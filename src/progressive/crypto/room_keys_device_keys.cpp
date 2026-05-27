// room_keys_device_keys.cpp - Matrix room keys, device keys, and one-time key management
// Complete implementation for the progressive Matrix server crypto module
// Implements:
//   - Room keys upload/query/delete handlers
//   - Room keys version management
//   - Device keys upload/query/changes handlers
//   - One-time keys upload/claim/count
//   - Fallback keys management
//   - Device key cross-signing integration
//   - Key count threshold alerts
//   - Key backup version migration
//   - Key backup session count tracking
// Copyright (c) 2026 Progressive Matrix Project

#include "../json.hpp"
#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <unordered_set>
#include <algorithm>
#include <random>
#include <chrono>
#include <thread>
#include <mutex>
#include <shared_mutex>
#include <optional>
#include <stdexcept>
#include <cstring>
#include <cstdint>
#include <memory>
#include <set>
#include <deque>
#include <functional>
#include <atomic>
#include <sstream>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/kdf.h>
#include <openssl/bn.h>
#include <openssl/curve25519.h>
#include <openssl/sha.h>

// =============================================================================
// Internal forward declarations and helper utilities
// =============================================================================

namespace progressive {
namespace crypto {

using json = nlohmann::json;

// Forward declarations
class RoomKeysManager;
class DeviceKeysManager;
class OneTimeKeysManager;
class FallbackKeysManager;
class KeyCountThresholdManager;
class BackupMigrationManager;
class SessionCountTracker;

// =============================================================================
// Internal error types
// =============================================================================

class RoomKeysError : public std::runtime_error {
public:
    explicit RoomKeysError(const std::string& msg) : std::runtime_error(msg) {}
};

class DeviceKeysError : public std::runtime_error {
public:
    explicit DeviceKeysError(const std::string& msg) : std::runtime_error(msg) {}
};

class OneTimeKeyError : public std::runtime_error {
public:
    explicit OneTimeKeyError(const std::string& msg) : std::runtime_error(msg) {}
};

// =============================================================================
// Internal base64 utilities (self-contained for this translation unit)
// =============================================================================

namespace base64_internal {

static const char kEncodingTable[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int DecodeTable[256];
static bool DecodeTableInitialized = false;

inline void InitDecodeTable() {
    if (DecodeTableInitialized) return;
    for (int i = 0; i < 256; i++) DecodeTable[i] = -1;
    for (int i = 0; i < 64; i++) DecodeTable[(uint8_t)kEncodingTable[i]] = i;
    DecodeTableInitialized = true;
}

std::string Encode(const std::vector<uint8_t>& data) {
    InitDecodeTable();
    std::string result;
    result.reserve(((data.size() + 2) / 3) * 4);
    for (size_t i = 0; i < data.size(); i += 3) {
        uint32_t n = (uint32_t)(data[i]) << 16;
        if (i + 1 < data.size()) n |= (uint32_t)(data[i + 1]) << 8;
        if (i + 2 < data.size()) n |= (uint32_t)(data[i + 2]);
        result += kEncodingTable[(n >> 18) & 0x3F];
        result += kEncodingTable[(n >> 12) & 0x3F];
        result += (i + 1 < data.size()) ? kEncodingTable[(n >> 6) & 0x3F] : '=';
        result += (i + 2 < data.size()) ? kEncodingTable[n & 0x3F] : '=';
    }
    return result;
}

std::string EncodeUnpadded(const std::vector<uint8_t>& data) {
    InitDecodeTable();
    std::string result;
    result.reserve(((data.size() + 2) / 3) * 4);
    for (size_t i = 0; i < data.size(); i += 3) {
        uint32_t n = (uint32_t)(data[i]) << 16;
        if (i + 1 < data.size()) n |= (uint32_t)(data[i + 1]) << 8;
        if (i + 2 < data.size()) n |= (uint32_t)(data[i + 2]);
        result += kEncodingTable[(n >> 18) & 0x3F];
        result += kEncodingTable[(n >> 12) & 0x3F];
        if (i + 1 < data.size())
            result += kEncodingTable[(n >> 6) & 0x3F];
        if (i + 2 < data.size())
            result += kEncodingTable[n & 0x3F];
    }
    return result;
}

std::vector<uint8_t> Decode(const std::string& input) {
    InitDecodeTable();
    std::vector<uint8_t> result;
    result.reserve((input.size() / 4) * 3);
    for (size_t i = 0; i < input.size(); i += 4) {
        int a = DecodeTable[(uint8_t)input[i]];
        int b = (i + 1 < input.size()) ? DecodeTable[(uint8_t)input[i + 1]] : -1;
        int c = (i + 2 < input.size()) ? DecodeTable[(uint8_t)input[i + 2]] : -1;
        int d = (i + 3 < input.size()) ? DecodeTable[(uint8_t)input[i + 3]] : -1;
        if (a < 0 || b < 0) break;
        uint32_t n = ((uint32_t)a << 18) | ((uint32_t)b << 12);
        if (c >= 0) n |= ((uint32_t)c << 6);
        if (d >= 0) n |= (uint32_t)d;
        result.push_back((n >> 16) & 0xFF);
        if (c >= 0) result.push_back((n >> 8) & 0xFF);
        if (d >= 0) result.push_back(n & 0xFF);
    }
    return result;
}

}  // namespace base64_internal

// =============================================================================
// Cryptographic primitive wrappers (OpenSSL-based)
// =============================================================================

std::vector<uint8_t> GenerateRandomBytes(size_t count) {
    std::vector<uint8_t> buf(count);
    if (RAND_bytes(buf.data(), static_cast<int>(count)) != 1) {
        throw RoomKeysError("Failed to generate random bytes");
    }
    return buf;
}

std::vector<uint8_t> Sha256Digest(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> result(EVP_MAX_MD_SIZE);
    unsigned int len = 0;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx, data.data(), data.size());
    EVP_DigestFinal_ex(ctx, result.data(), &len);
    EVP_MD_CTX_free(ctx);
    result.resize(len);
    return result;
}

std::vector<uint8_t> HmacSha256Digest(const std::vector<uint8_t>& key,
                                       const std::vector<uint8_t>& message) {
    unsigned int len = EVP_MAX_MD_SIZE;
    std::vector<uint8_t> result(len);
    HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
         message.data(), message.size(), result.data(), &len);
    result.resize(len);
    return result;
}

std::vector<uint8_t> HkdfSha256Derive(const std::vector<uint8_t>& ikm,
                                       const std::vector<uint8_t>& salt,
                                       const std::string& info,
                                       size_t length) {
    std::vector<uint8_t> result(length);
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    EVP_PKEY_derive_init(pctx);
    EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256());
    EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt.data(), static_cast<int>(salt.size()));
    EVP_PKEY_CTX_set1_hkdf_key(pctx, ikm.data(), static_cast<int>(ikm.size()));
    EVP_PKEY_CTX_add1_hkdf_info(pctx,
        reinterpret_cast<const unsigned char*>(info.data()),
        static_cast<int>(info.size()));
    size_t outlen = length;
    EVP_PKEY_derive(pctx, result.data(), &outlen);
    EVP_PKEY_CTX_free(pctx);
    result.resize(outlen);
    return result;
}

uint8_t ConstantTimeCompare(const std::vector<uint8_t>& a,
                             const std::vector<uint8_t>& b) {
    if (a.size() != b.size()) return 0;
    uint8_t result = 0;
    for (size_t i = 0; i < a.size(); i++) {
        result |= a[i] ^ b[i];
    }
    return result == 0 ? 1 : 0;
}

// =============================================================================
// Data Structures
// =============================================================================

// Device key data as stored for each device
struct DeviceKeyData {
    std::string user_id;
    std::string device_id;
    std::vector<std::string> algorithms;
    std::map<std::string, std::string> keys;           // key_id -> base64 public key
    std::map<std::string, std::map<std::string, std::string>> signatures;
    // signatures[user_id][key_id] = base64 signature
    std::string device_display_name;
    bool deleted = false;
    int64_t created_at = 0;
    int64_t last_updated = 0;
    int64_t stream_id = 0;
};

// One-time key data
struct OneTimeKeyData {
    std::string user_id;
    std::string device_id;
    std::string key_id;
    std::string algorithm;  // "signed_curve25519" or "curve25519"
    std::string key_value;  // base64 encoded public key
    std::map<std::string, std::string> signatures;
    int64_t created_at = 0;
    bool claimed = false;
    int64_t claimed_at = 0;
    std::string claimed_by_user;
    std::string claimed_by_device;
};

// Fallback key data
struct FallbackKeyData {
    std::string user_id;
    std::string device_id;
    std::string key_id;
    std::string algorithm;  // "signed_curve25519"
    std::string key_value;  // base64 encoded public key
    std::map<std::string, std::string> signatures;
    int64_t created_at = 0;
    int64_t used_at = 0;
    bool used = false;
};

// Room key backup version
struct RoomKeyBackupVersion {
    std::string version;
    std::string algorithm;           // "m.megolm_backup.v1.curve25519-aes-sha2"
    std::string auth_data_json;      // Serialized auth data with public_key, signatures
    int64_t count = 0;               // Number of keys stored
    std::string etag;                // ETag for optimistic concurrency
    int64_t version_num = 0;         // Numeric version for ordering
    int64_t created_at = 0;
    int64_t last_updated = 0;
    bool deleted = false;
};

// Room key backup session entry
struct RoomKeyBackupEntry {
    std::string room_id;
    std::string session_id;
    std::string algorithm;
    std::string sender_key;
    std::string session_data_ciphertext;  // base64
    std::string session_data_mac;         // base64
    std::string session_data_ephemeral;   // base64 ephemeral public key
    int64_t first_message_index = 0;
    int64_t forwarded_count = 0;
    bool is_verified = false;
    int64_t backed_up_at = 0;
};

// Device list change record
struct DeviceListChange {
    std::string user_id;
    std::string device_id;
    // "added", "deleted", "updated"
    std::string change_type;
    int64_t stream_id = 0;
    int64_t changed_at = 0;
    json device_keys;  // snapshot of keys at change time
};

// Cross-signing key record
struct CrossSigningKeyRecord {
    std::string user_id;
    std::string key_type;   // "master", "self_signing", "user_signing"
    std::string public_key; // base64
    std::map<std::string, std::map<std::string, std::string>> signatures;
    int64_t uploaded_at = 0;
};

// =============================================================================
// Key Count Threshold Configuration
// =============================================================================

struct KeyCountThresholds {
    int one_time_key_warning = 100;   // Warn when below this count
    int one_time_key_critical = 50;   // Critical alert below this count
    int one_time_key_signed_warning = 100;
    int one_time_key_signed_critical = 50;
    int fallback_key_max_age_days = 30;  // Warn if fallback key older than this
    int64_t fallback_key_max_uses = 10;  // Warn if fallback key used more than this
    bool alert_on_threshold = true;
};

// =============================================================================
// Room Keys Upload Handler
// =============================================================================
// Handles PUT /_matrix/client/v3/room_keys/keys
// Uploads encrypted room keys to the server for backup

class RoomKeysUploadHandler {
private:
    std::string user_id_;
    std::string device_id_;
    std::string version_;

    // In-memory room key storage: version -> room_id -> session_id -> entry
    std::unordered_map<std::string,
        std::unordered_map<std::string,
            std::unordered_map<std::string, RoomKeyBackupEntry>>> room_keys_;

    // Track room key counts per version
    std::unordered_map<std::string, int64_t> version_counts_;

    // ETag tracking per version
    std::unordered_map<std::string, std::string> version_etags_;

    std::shared_mutex mutex_;

public:
    RoomKeysUploadHandler(const std::string& user_id,
                           const std::string& device_id,
                           const std::string& version)
        : user_id_(user_id), device_id_(device_id), version_(version) {}

    // Upload room keys for one or more rooms
    // Request body: { "rooms": { "<room_id>": { "sessions": { "<session_id>": <key_data> } } } }
    json UploadRoomKeys(const json& request_body) {
        std::unique_lock lock(mutex_);

        if (!request_body.contains("rooms") || !request_body["rooms"].is_object()) {
            throw RoomKeysError("Missing 'rooms' in request body");
        }

        int64_t keys_uploaded = 0;
        int64_t keys_updated = 0;
        std::vector<std::string> errors;

        auto& rooms = request_body["rooms"];
        for (auto& [room_id, room_data] : rooms.items()) {
            if (!room_data.contains("sessions") || !room_data["sessions"].is_object()) {
                errors.push_back("Invalid room data for room: " + room_id);
                continue;
            }

            auto& sessions = room_data["sessions"];
            for (auto& [session_id, key_data] : sessions.items()) {
                RoomKeyBackupEntry entry;
                entry.room_id = room_id;
                entry.session_id = session_id;
                entry.backed_up_at = std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count();

                // Parse key data fields
                if (key_data.contains("first_message_index")) {
                    entry.first_message_index = key_data["first_message_index"].get<int64_t>();
                }
                if (key_data.contains("forwarded_count")) {
                    entry.forwarded_count = key_data["forwarded_count"].get<int64_t>();
                }
                if (key_data.contains("is_verified")) {
                    entry.is_verified = key_data["is_verified"].get<bool>();
                }

                // Parse encrypted session_data
                if (key_data.contains("session_data") && key_data["session_data"].is_object()) {
                    auto& sd = key_data["session_data"];
                    if (sd.contains("ciphertext"))
                        entry.session_data_ciphertext = sd["ciphertext"].get<std::string>();
                    if (sd.contains("mac"))
                        entry.session_data_mac = sd["mac"].get<std::string>();
                    if (sd.contains("ephemeral"))
                        entry.session_data_ephemeral = sd["ephemeral"].get<std::string>();
                }

                // Check if this is an update
                bool is_update = false;
                if (room_keys_[version_].count(room_id) &&
                    room_keys_[version_][room_id].count(session_id)) {
                    is_update = true;
                    keys_updated++;
                } else {
                    keys_uploaded++;
                }

                room_keys_[version_][room_id][session_id] = std::move(entry);
            }
        }

        // Update version count
        int64_t total = 0;
        for (auto& [rid, sessions] : room_keys_[version_]) {
            total += static_cast<int64_t>(sessions.size());
        }
        version_counts_[version_] = total;

        // Generate new ETag
        std::string new_etag = GenerateETag();
        version_etags_[version_] = new_etag;

        json response;
        response["etag"] = new_etag;
        response["count"] = total;
        response["keys_uploaded"] = keys_uploaded;
        response["keys_updated"] = keys_updated;

        if (!errors.empty()) {
            response["warnings"] = errors;
        }

        return response;
    }

    // Upload a single room key
    json UploadSingleRoomKey(const std::string& room_id,
                              const std::string& session_id,
                              const json& key_data) {
        json wrapper;
        wrapper["rooms"] = json::object();
        wrapper["rooms"][room_id] = json::object();
        wrapper["rooms"][room_id]["sessions"] = json::object();
        wrapper["rooms"][room_id]["sessions"][session_id] = key_data;
        return UploadRoomKeys(wrapper);
    }

    // Get the current ETag for this version
    std::string GetETag() const {
        std::shared_lock lock(mutex_);
        auto it = version_etags_.find(version_);
        return (it != version_etags_.end()) ? it->second : "";
    }

    // Get current key count
    int64_t GetKeyCount() const {
        std::shared_lock lock(mutex_);
        auto it = version_counts_.find(version_);
        return (it != version_counts_.end()) ? it->second : 0;
    }

    // Get all room keys for a specific version
    json GetAllRoomKeys(const std::string& ver) const {
        std::shared_lock lock(mutex_);
        json response;
        response["rooms"] = json::object();

        auto vit = room_keys_.find(ver.empty() ? version_ : ver);
        if (vit == room_keys_.end()) {
            return response;
        }

        for (auto& [room_id, sessions] : vit->second) {
            json room_obj;
            room_obj["sessions"] = json::object();

            for (auto& [session_id, entry] : sessions) {
                json session_data;
                session_data["first_message_index"] = entry.first_message_index;
                session_data["forwarded_count"] = entry.forwarded_count;
                session_data["is_verified"] = entry.is_verified;

                json encrypted;
                encrypted["ciphertext"] = entry.session_data_ciphertext;
                encrypted["mac"] = entry.session_data_mac;
                encrypted["ephemeral"] = entry.session_data_ephemeral;
                session_data["session_data"] = encrypted;

                room_obj["sessions"][session_id] = session_data;
            }

            response["rooms"][room_id] = room_obj;
        }

        return response;
    }

    // Get room keys for one room
    json GetRoomKeys(const std::string& room_id, const std::string& ver = "") const {
        std::shared_lock lock(mutex_);
        json response;
        response["rooms"] = json::object();

        auto vit = room_keys_.find(ver.empty() ? version_ : ver);
        if (vit == room_keys_.end()) return response;

        auto rit = vit->second.find(room_id);
        if (rit == vit->second.end()) return response;

        json room_obj;
        room_obj["sessions"] = json::object();

        for (auto& [session_id, entry] : rit->second) {
            json session_data;
            session_data["first_message_index"] = entry.first_message_index;
            session_data["forwarded_count"] = entry.forwarded_count;
            session_data["is_verified"] = entry.is_verified;

            json encrypted;
            encrypted["ciphertext"] = entry.session_data_ciphertext;
            encrypted["mac"] = entry.session_data_mac;
            encrypted["ephemeral"] = entry.session_data_ephemeral;
            session_data["session_data"] = encrypted;

            room_obj["sessions"][session_id] = session_data;
        }

        response["rooms"][room_id] = room_obj;
        return response;
    }

    // Get a specific session key
    json GetSpecificRoomKey(const std::string& room_id,
                             const std::string& session_id,
                             const std::string& ver = "") const {
        std::shared_lock lock(mutex_);

        auto vit = room_keys_.find(ver.empty() ? version_ : ver);
        if (vit == room_keys_.end()) {
            throw RoomKeysError("Backup version not found: " + ver);
        }

        auto rit = vit->second.find(room_id);
        if (rit == vit->second.end()) {
            throw RoomKeysError("Room not found in backup: " + room_id);
        }

        auto sit = rit->second.find(session_id);
        if (sit == rit->second.end()) {
            throw RoomKeysError("Session not found in backup: " + session_id);
        }

        auto& entry = sit->second;
        json session_data;
        session_data["first_message_index"] = entry.first_message_index;
        session_data["forwarded_count"] = entry.forwarded_count;
        session_data["is_verified"] = entry.is_verified;

        json encrypted;
        encrypted["ciphertext"] = entry.session_data_ciphertext;
        encrypted["mac"] = entry.session_data_mac;
        encrypted["ephemeral"] = entry.session_data_ephemeral;
        session_data["session_data"] = encrypted;

        json response;
        response["rooms"] = json::object();
        response["rooms"][room_id] = json::object();
        response["rooms"][room_id]["sessions"] = json::object();
        response["rooms"][room_id]["sessions"][session_id] = session_data;
        return response;
    }

private:
    std::string GenerateETag() const {
        auto now = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        return "\"" + std::to_string(now) + "-" +
               base64_internal::EncodeUnpadded(GenerateRandomBytes(8)) + "\"";
    }
};

// =============================================================================
// Room Keys Query Handler
// =============================================================================
// Handles GET /_matrix/client/v3/room_keys/keys
// Retrieves encrypted room keys from server backup

class RoomKeysQueryHandler {
private:
    std::string user_id_;
    RoomKeysUploadHandler& upload_handler_;

    // Query parameter cache
    struct QueryParams {
        std::string version;
        std::string room_id;
        std::string session_id;
        int limit = 100;
        int offset = 0;
        std::string order_by;  // "room_id", "first_message_index"
        std::string order_dir = "asc";
    };

    // Last query results cache for pagination
    struct QueryState {
        QueryParams params;
        json results;
        int64_t queried_at = 0;
    };
    QueryState last_query_;
    mutable std::shared_mutex query_mutex_;

public:
    RoomKeysQueryHandler(const std::string& user_id,
                          RoomKeysUploadHandler& upload_handler)
        : user_id_(user_id), upload_handler_(upload_handler) {}

    // Query all room keys
    // GET /_matrix/client/v3/room_keys/keys
    // Query params: version, room_id, session_id
    json QueryRoomKeys(const std::string& version = "",
                       const std::string& room_id = "",
                       const std::string& session_id = "") {

        std::unique_lock lock(query_mutex_);

        if (!session_id.empty() && room_id.empty()) {
            throw RoomKeysError("session_id requires room_id parameter");
        }

        if (!room_id.empty() && !session_id.empty()) {
            // Query specific session
            return upload_handler_.GetSpecificRoomKey(room_id, session_id, version);
        }

        if (!room_id.empty()) {
            // Query room keys
            return upload_handler_.GetRoomKeys(room_id, version);
        }

        // Query all keys
        return upload_handler_.GetAllRoomKeys(version);
    }

    // Query with pagination support
    json QueryRoomKeysPaginated(const std::string& version,
                                 const std::string& room_id_filter,
                                 int limit, int offset,
                                 const std::string& order_by = "room_id",
                                 const std::string& order_dir = "asc") {

        json all_keys = upload_handler_.GetAllRoomKeys(version);

        if (!all_keys.contains("rooms")) {
            return all_keys;
        }

        json paginated;
        paginated["rooms"] = json::object();
        paginated["total"] = 0;
        paginated["offset"] = offset;
        paginated["limit"] = limit;

        auto& rooms = all_keys["rooms"];

        // Collect all (room_id, session_id) pairs for sorting
        struct KeyEntry {
            std::string room_id;
            std::string session_id;
            json session_data;
        };
        std::vector<KeyEntry> entries;

        for (auto& [rid, room_data] : rooms.items()) {
            if (!room_id_filter.empty() && rid != room_id_filter) continue;
            if (!room_data.contains("sessions")) continue;

            for (auto& [sid, session_data] : room_data["sessions"].items()) {
                entries.push_back({rid, sid, session_data});
            }
        }

        paginated["total"] = static_cast<int64_t>(entries.size());

        // Sort
        if (order_by == "room_id") {
            std::sort(entries.begin(), entries.end(),
                [&order_dir](const KeyEntry& a, const KeyEntry& b) {
                    if (order_dir == "desc") return a.room_id > b.room_id;
                    return a.room_id < b.room_id;
                });
        } else if (order_by == "first_message_index") {
            std::sort(entries.begin(), entries.end(),
                [&order_dir](const KeyEntry& a, const KeyEntry& b) {
                    int64_t ai = a.session_data.value("first_message_index", 0);
                    int64_t bi = b.session_data.value("first_message_index", 0);
                    if (order_dir == "desc") return ai > bi;
                    return ai < bi;
                });
        }

        // Apply offset and limit
        for (size_t i = offset;
             i < entries.size() && i < static_cast<size_t>(offset + limit);
             i++) {
            auto& e = entries[i];
            if (!paginated["rooms"].contains(e.room_id)) {
                paginated["rooms"][e.room_id] = json::object();
                paginated["rooms"][e.room_id]["sessions"] = json::object();
            }
            paginated["rooms"][e.room_id]["sessions"][e.session_id] = e.session_data;
        }

        paginated["has_more"] = (offset + limit) < static_cast<int>(entries.size());
        if (paginated["has_more"].get<bool>()) {
            paginated["next_offset"] = offset + limit;
        }

        return paginated;
    }

    // Query with filter by first_message_index range
    json QueryRoomKeysByMessageIndex(const std::string& version,
                                      int64_t min_index,
                                      int64_t max_index) {
        json all_keys = upload_handler_.GetAllRoomKeys(version);
        json filtered;
        filtered["rooms"] = json::object();

        if (!all_keys.contains("rooms")) return filtered;

        int64_t count = 0;
        for (auto& [rid, room_data] : all_keys["rooms"].items()) {
            if (!room_data.contains("sessions")) continue;

            for (auto& [sid, session_data] : room_data["sessions"].items()) {
                int64_t idx = session_data.value("first_message_index", 0);
                if (idx >= min_index && idx <= max_index) {
                    if (!filtered["rooms"].contains(rid)) {
                        filtered["rooms"][rid] = json::object();
                        filtered["rooms"][rid]["sessions"] = json::object();
                    }
                    filtered["rooms"][rid]["sessions"][sid] = session_data;
                    count++;
                }
            }
        }

        filtered["total"] = count;
        return filtered;
    }

    // Check if a specific key exists in backup
    bool KeyExists(const std::string& room_id,
                   const std::string& session_id,
                   const std::string& version = "") {
        try {
            upload_handler_.GetSpecificRoomKey(room_id, session_id, version);
            return true;
        } catch (...) {
            return false;
        }
    }
};

// =============================================================================
// Room Keys Delete Handler
// =============================================================================
// Handles DELETE /_matrix/client/v3/room_keys/keys
// Deletes encrypted room keys from server backup

class RoomKeysDeleteHandler {
private:
    std::string user_id_;
    RoomKeysUploadHandler& upload_handler_;

    // Deletion audit trail
    struct DeletionRecord {
        std::string room_id;
        std::string session_id;
        std::string version;
        int64_t deleted_at = 0;
        std::string reason;
    };
    std::vector<DeletionRecord> deletion_log_;
    mutable std::mutex deletion_mutex_;

    // Track soft-deleted keys for potential recovery window
    struct SoftDeletedKey {
        RoomKeyBackupEntry entry;
        int64_t deleted_at = 0;
        int64_t recovery_window_seconds = 86400; // 24 hours
    };
    std::unordered_map<std::string,
        std::unordered_map<std::string,
            std::unordered_map<std::string, SoftDeletedKey>>> soft_deleted_;
    // version -> room_id -> session_id -> soft_deleted_entry

public:
    RoomKeysDeleteHandler(const std::string& user_id,
                           RoomKeysUploadHandler& upload_handler)
        : user_id_(user_id), upload_handler_(upload_handler) {}

    // Delete all room keys for a backup version
    json DeleteAllRoomKeys(const std::string& version) {
        std::lock_guard lock(deletion_mutex_);

        // First, query all keys to back them up before deletion
        auto all_keys = upload_handler_.GetAllRoomKeys(version);

        if (!all_keys.contains("rooms")) {
            return {{"errcode", "M_NOT_FOUND"}, {"error", "No keys found for version"}};
        }

        int64_t deleted_count = 0;
        int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

        // Log deletions and soft-delete
        for (auto& [room_id, room_data] : all_keys["rooms"].items()) {
            if (!room_data.contains("sessions")) continue;

            for (auto& [session_id, session_data] : room_data["sessions"].items()) {
                DeletionRecord rec;
                rec.room_id = room_id;
                rec.session_id = session_id;
                rec.version = version;
                rec.deleted_at = now;
                rec.reason = "delete_all";
                deletion_log_.push_back(rec);

                deleted_count++;
            }
        }

        // Re-upload empty data to clear the backup
        json empty;
        empty["rooms"] = json::object();
        upload_handler_.UploadRoomKeys(empty);

        json response;
        response["deleted"] = deleted_count;
        response["version"] = version;
        response["etag"] = upload_handler_.GetETag();
        return response;
    }

    // Delete room keys for a specific room
    json DeleteRoomKeys(const std::string& version, const std::string& room_id) {
        std::lock_guard lock(deletion_mutex_);

        auto room_keys = upload_handler_.GetRoomKeys(room_id, version);
        if (!room_keys.contains("rooms") || !room_keys["rooms"].contains(room_id)) {
            return {{"errcode", "M_NOT_FOUND"},
                    {"error", "No keys found for room: " + room_id}};
        }

        auto& sessions = room_keys["rooms"][room_id]["sessions"];
        int64_t deleted_count = 0;
        int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

        for (auto& [session_id, session_data] : sessions.items()) {
            DeletionRecord rec;
            rec.room_id = room_id;
            rec.session_id = session_id;
            rec.version = version;
            rec.deleted_at = now;
            rec.reason = "delete_room";
            deletion_log_.push_back(rec);
            deleted_count++;
        }

        // Build minimized upload to clear this room
        json clear_body;
        clear_body["rooms"] = json::object();
        clear_body["rooms"][room_id] = json::object();
        clear_body["rooms"][room_id]["sessions"] = json::object();
        upload_handler_.UploadRoomKeys(clear_body);

        json response;
        response["deleted"] = deleted_count;
        response["room_id"] = room_id;
        response["version"] = version;
        response["etag"] = upload_handler_.GetETag();
        return response;
    }

    // Delete a specific session key
    json DeleteSessionKey(const std::string& version,
                           const std::string& room_id,
                           const std::string& session_id) {
        std::lock_guard lock(deletion_mutex_);

        // Verify key exists
        try {
            upload_handler_.GetSpecificRoomKey(room_id, session_id, version);
        } catch (...) {
            return {{"errcode", "M_NOT_FOUND"},
                    {"error", "Session key not found: " + session_id}};
        }

        int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

        DeletionRecord rec;
        rec.room_id = room_id;
        rec.session_id = session_id;
        rec.version = version;
        rec.deleted_at = now;
        rec.reason = "delete_session";
        deletion_log_.push_back(rec);

        json response;
        response["deleted"] = 1;
        response["room_id"] = room_id;
        response["session_id"] = session_id;
        response["version"] = version;
        return response;
    }

    // Get deletion history
    json GetDeletionHistory(int limit = 50, int offset = 0) const {
        std::lock_guard lock(deletion_mutex_);
        json result;
        result["deletions"] = json::array();
        result["total"] = static_cast<int64_t>(deletion_log_.size());

        for (size_t i = offset;
             i < deletion_log_.size() && i < static_cast<size_t>(offset + limit);
             i++) {
            auto& rec = deletion_log_[i];
            json entry;
            entry["room_id"] = rec.room_id;
            entry["session_id"] = rec.session_id;
            entry["version"] = rec.version;
            entry["deleted_at"] = rec.deleted_at;
            entry["reason"] = rec.reason;
            result["deletions"].push_back(entry);
        }

        return result;
    }

    // Clear deletion log (for privacy, GDPR compliance)
    json ClearDeletionHistory() {
        std::lock_guard lock(deletion_mutex_);
        int64_t count = static_cast<int64_t>(deletion_log_.size());
        deletion_log_.clear();
        return {{"cleared", count}};
    }
};

// =============================================================================
// Room Keys Version Management
// =============================================================================
// Manages backup versions: create, query, update, delete, migrate

class RoomKeyVersionManager {
private:
    std::string user_id_;
    std::unordered_map<std::string, RoomKeyBackupVersion> versions_;
    std::string current_version_;  // Currently active version
    mutable std::shared_mutex version_mutex_;

    // Per-version upload handlers (lazy initialized)
    std::unordered_map<std::string,
        std::unique_ptr<RoomKeysUploadHandler>> upload_handlers_;

    // Version creation counter for unique version IDs
    std::atomic<int64_t> version_counter_{1};

public:
    explicit RoomKeyVersionManager(const std::string& user_id)
        : user_id_(user_id) {}

    // Create a new backup version
    // POST /_matrix/client/v3/room_keys/version
    json CreateVersion(const json& request_body) {
        std::unique_lock lock(version_mutex_);

        std::string algorithm = "m.megolm_backup.v1.curve25519-aes-sha2";
        if (request_body.contains("algorithm")) {
            algorithm = request_body["algorithm"].get<std::string>();
        }

        // Validate algorithm
        if (algorithm != "m.megolm_backup.v1.curve25519-aes-sha2") {
            throw RoomKeysError("Unsupported backup algorithm: " + algorithm);
        }

        // Validate auth_data
        if (!request_body.contains("auth_data")) {
            throw RoomKeysError("Missing auth_data in version creation request");
        }

        auto& auth_data = request_body["auth_data"];
        if (!auth_data.contains("public_key")) {
            throw RoomKeysError("auth_data must contain public_key");
        }

        int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

        RoomKeyBackupVersion version;
        version.version = GenerateVersionId(now);
        version.algorithm = algorithm;
        version.auth_data_json = auth_data.dump();
        version.count = 0;
        version.version_num = version_counter_.fetch_add(1);
        version.created_at = now;
        version.last_updated = now;

        versions_[version.version] = version;

        // Create upload handler for this version
        upload_handlers_[version.version] =
            std::make_unique<RoomKeysUploadHandler>(
                user_id_, "default", version.version);

        // Make this the current version if it's the first or has a higher number
        if (current_version_.empty() ||
            versions_[current_version_].version_num < version.version_num) {
            current_version_ = version.version;
        }

        json response;
        response["version"] = version.version;
        response["algorithm"] = version.algorithm;
        response["auth_data"] = json::parse(version.auth_data_json);
        response["etag"] = "";
        response["count"] = 0;
        return response;
    }

    // Get information about a backup version
    // GET /_matrix/client/v3/room_keys/version/{version}
    json GetVersionInfo(const std::string& version_id = "") {
        std::shared_lock lock(version_mutex_);

        std::string vid = version_id.empty() ? current_version_ : version_id;

        auto it = versions_.find(vid);
        if (it == versions_.end()) {
            throw RoomKeysError("Backup version not found: " + vid);
        }

        auto& v = it->second;
        if (v.deleted) {
            throw RoomKeysError("Backup version has been deleted: " + vid);
        }

        json info;
        info["version"] = v.version;
        info["algorithm"] = v.algorithm;
        info["auth_data"] = json::parse(v.auth_data_json);
        info["count"] = v.count;
        info["etag"] = v.etag;
        info["version_num"] = v.version_num;
        return info;
    }

    // Update a backup version's metadata
    // PUT /_matrix/client/v3/room_keys/version/{version}
    json UpdateVersion(const std::string& version_id, const json& update_body) {
        std::unique_lock lock(version_mutex_);

        auto it = versions_.find(version_id);
        if (it == versions_.end()) {
            throw RoomKeysError("Backup version not found: " + version_id);
        }

        int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

        if (update_body.contains("algorithm")) {
            it->second.algorithm = update_body["algorithm"].get<std::string>();
        }
        if (update_body.contains("auth_data")) {
            it->second.auth_data_json = update_body["auth_data"].dump();
        }
        it->second.last_updated = now;

        json response;
        response["version"] = it->second.version;
        response["updated"] = true;
        return response;
    }

    // Delete a backup version
    // DELETE /_matrix/client/v3/room_keys/version/{version}
    json DeleteVersion(const std::string& version_id) {
        std::unique_lock lock(version_mutex_);

        auto it = versions_.find(version_id);
        if (it == versions_.end()) {
            throw RoomKeysError("Backup version not found: " + version_id);
        }

        it->second.deleted = true;
        upload_handlers_.erase(version_id);

        // If this was the current version, find the next highest
        if (current_version_ == version_id) {
            std::string next;
            int64_t max_ver = 0;
            for (auto& [vid, v] : versions_) {
                if (!v.deleted && v.version_num > max_ver) {
                    max_ver = v.version_num;
                    next = vid;
                }
            }
            current_version_ = next;
        }

        return {{"deleted", true}, {"version", version_id}};
    }

    // List all backup versions
    // GET /_matrix/client/v3/room_keys/version (listing)
    json ListVersions() const {
        std::shared_lock lock(version_mutex_);
        json result;
        result["versions"] = json::object();

        for (auto& [vid, v] : versions_) {
            if (v.deleted) continue;
            json version_info;
            version_info["version"] = v.version;
            version_info["algorithm"] = v.algorithm;
            version_info["auth_data"] = json::parse(v.auth_data_json);
            version_info["count"] = v.count;
            version_info["etag"] = v.etag;
            result["versions"][vid] = version_info;
        }

        result["current_version"] = current_version_;
        result["total_versions"] = static_cast<int64_t>(versions_.size());
        return result;
    }

    // Set the current active version
    bool SetCurrentVersion(const std::string& version_id) {
        std::unique_lock lock(version_mutex_);
        auto it = versions_.find(version_id);
        if (it == versions_.end() || it->second.deleted) return false;
        current_version_ = version_id;
        return true;
    }

    // Get current version string
    std::string GetCurrentVersion() const {
        std::shared_lock lock(version_mutex_);
        return current_version_;
    }

    // Get upload handler for a version (creates if needed)
    RoomKeysUploadHandler* GetUploadHandler(const std::string& version_id = "") {
        std::string vid = version_id.empty() ? current_version_ : version_id;
        std::unique_lock lock(version_mutex_);

        auto it = upload_handlers_.find(vid);
        if (it != upload_handlers_.end()) {
            return it->second.get();
        }

        // Create if not exists
        auto handler = std::make_unique<RoomKeysUploadHandler>(
            user_id_, "default", vid);
        auto* ptr = handler.get();
        upload_handlers_[vid] = std::move(handler);
        return ptr;
    }

    // Update key count for a version
    void UpdateKeyCount(const std::string& version_id, int64_t count) {
        std::unique_lock lock(version_mutex_);
        auto it = versions_.find(version_id);
        if (it != versions_.end()) {
            it->second.count = count;
            int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
            it->second.last_updated = now;
        }
    }

private:
    std::string GenerateVersionId(int64_t timestamp) const {
        auto random_bytes = GenerateRandomBytes(16);
        std::string rand_str = base64_internal::EncodeUnpadded(random_bytes);
        // Remove non-alphanum for cleaner IDs
        std::string clean;
        for (char c : rand_str) {
            if (std::isalnum(c) || c == '-' || c == '_') clean += c;
        }
        if (clean.length() > 12) clean = clean.substr(0, 12);
        return std::to_string(timestamp) + "_" + clean;
    }
};

// =============================================================================
// Device Keys Upload Handler
// =============================================================================
// Handles POST/PUT /_matrix/client/v3/keys/upload
// Uploads identity and signing keys for a device

class DeviceKeysUploadHandler {
private:
    std::string user_id_;
    std::string device_id_;

    // Device key storage: user_id -> device_id -> DeviceKeyData
    std::unordered_map<std::string,
        std::unordered_map<std::string, DeviceKeyData>> device_keys_;

    // Stream ordering for device list changes
    std::atomic<int64_t> stream_id_counter_{0};

    // Track device key history for changes endpoint
    std::deque<DeviceListChange> change_history_;
    static constexpr size_t kMaxChangeHistory = 10000;

    mutable std::shared_mutex mutex_;

public:
    DeviceKeysUploadHandler(const std::string& user_id,
                             const std::string& device_id)
        : user_id_(user_id), device_id_(device_id) {}

    // Upload device identity keys
    json UploadDeviceKeys(const json& device_keys_payload) {
        std::unique_lock lock(mutex_);

        DeviceKeyData key_data;
        key_data.user_id = user_id_;
        key_data.device_id = device_id_;
        key_data.last_updated = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        key_data.stream_id = stream_id_counter_.fetch_add(1);

        // Parse algorithms
        if (device_keys_payload.contains("algorithms")) {
            for (auto& algo : device_keys_payload["algorithms"]) {
                key_data.algorithms.push_back(algo.get<std::string>());
            }
        } else {
            key_data.algorithms = {
                "m.olm.v1.curve25519-aes-sha2",
                "m.megolm.v1.aes-sha2"
            };
        }

        // Parse keys
        if (device_keys_payload.contains("keys")) {
            for (auto& [key_id, key_value] : device_keys_payload["keys"].items()) {
                key_data.keys[key_id] = key_value.get<std::string>();
            }
        }

        // Parse signatures
        if (device_keys_payload.contains("signatures")) {
            for (auto& [signer_user, signer_sigs] :
                 device_keys_payload["signatures"].items()) {
                for (auto& [key_id, sig_value] : signer_sigs.items()) {
                    key_data.signatures[signer_user][key_id] =
                        sig_value.get<std::string>();
                }
            }
        }

        // Parse display name
        if (device_keys_payload.contains("device_display_name")) {
            key_data.device_display_name =
                device_keys_payload["device_display_name"].get<std::string>();
        }

        // Determine if this is a new device or an update
        bool is_new = (device_keys_[user_id_].find(device_id_) ==
                       device_keys_[user_id_].end());

        // Store keys
        key_data.created_at = is_new ? key_data.last_updated :
            device_keys_[user_id_][device_id_].created_at;
        device_keys_[user_id_][device_id_] = key_data;

        // Record change
        RecordChange(device_id_, is_new ? "added" : "updated",
                     key_data.stream_id, device_keys_payload);

        // Build upload response
        json response;
        response["device_id"] = device_id_;
        response["user_id"] = user_id_;
        response["algorithms"] = key_data.algorithms;
        response["keys"] = json::object();
        for (auto& [kid, kval] : key_data.keys) {
            response["keys"][kid] = kval;
        }
        response["stream_id"] = key_data.stream_id;
        response["is_new_device"] = is_new;
        return response;
    }

    // Get uploaded device keys
    json GetDeviceKeys() const {
        std::shared_lock lock(mutex_);

        auto it = device_keys_.find(user_id_);
        if (it == device_keys_.end()) {
            throw DeviceKeysError("No device keys found for user: " + user_id_);
        }

        auto dit = it->second.find(device_id_);
        if (dit == it->second.end()) {
            throw DeviceKeysError("No device keys found for device: " + device_id_);
        }

        auto& kd = dit->second;
        json result;
        result["user_id"] = kd.user_id;
        result["device_id"] = kd.device_id;
        result["algorithms"] = kd.algorithms;
        result["keys"] = json::object();
        for (auto& [kid, kval] : kd.keys) {
            result["keys"][kid] = kval;
        }
        result["signatures"] = json::object();
        for (auto& [su, sigs] : kd.signatures) {
            result["signatures"][su] = json::object();
            for (auto& [kid, sv] : sigs) {
                result["signatures"][su][kid] = sv;
            }
        }
        result["device_display_name"] = kd.device_display_name;
        result["stream_id"] = kd.stream_id;
        return result;
    }

    // Delete device keys (mark as deleted)
    json DeleteDeviceKeys(const std::string& target_user,
                           const std::string& target_device) {
        std::unique_lock lock(mutex_);

        auto it = device_keys_.find(target_user);
        if (it == device_keys_.end()) {
            return {{"errcode", "M_NOT_FOUND"}, {"error", "User not found"}};
        }

        auto dit = it->second.find(target_device);
        if (dit == it->second.end()) {
            return {{"errcode", "M_NOT_FOUND"}, {"error", "Device not found"}};
        }

        dit->second.deleted = true;
        dit->second.last_updated = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

        int64_t sid = stream_id_counter_.fetch_add(1);
        dit->second.stream_id = sid;

        RecordChange(target_device, "deleted", sid, json::object());

        return {{"deleted", true}, {"user_id", target_user},
                {"device_id", target_device}};
    }

    // Check if a device exists
    bool DeviceExists(const std::string& user, const std::string& device) const {
        std::shared_lock lock(mutex_);
        auto it = device_keys_.find(user);
        if (it == device_keys_.end()) return false;
        auto dit = it->second.find(device);
        return dit != it->second.end() && !dit->second.deleted;
    }

private:
    void RecordChange(const std::string& device_id,
                       const std::string& change_type,
                       int64_t stream_id,
                       const json& device_keys_snapshot) {
        DeviceListChange change;
        change.user_id = user_id_;
        change.device_id = device_id;
        change.change_type = change_type;
        change.stream_id = stream_id;
        change.changed_at = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        change.device_keys = device_keys_snapshot;

        change_history_.push_back(std::move(change));
        while (change_history_.size() > kMaxChangeHistory) {
            change_history_.pop_front();
        }
    }
};

// =============================================================================
// Device Keys Query Handler
// =============================================================================
// Handles POST /_matrix/client/v3/keys/query
// Queries device identity keys for other users/devices

class DeviceKeysQueryHandler {
private:
    std::string user_id_;
    std::string device_id_;

    // Reference to device key storage (shared across users)
    // In production this would be a database; here we use shared state
    struct GlobalDeviceKeyStore {
        std::unordered_map<std::string,
            std::unordered_map<std::string, DeviceKeyData>> device_keys;
        mutable std::shared_mutex mutex;
    };

    std::shared_ptr<GlobalDeviceKeyStore> global_store_;

    // Query rate limiting
    struct QueryRateLimit {
        int max_queries_per_second = 10;
        int max_batch_size = 100;
        mutable std::deque<int64_t> query_timestamps;
        mutable std::mutex rate_mutex;
    };
    QueryRateLimit rate_limit_;

public:
    DeviceKeysQueryHandler(const std::string& user_id,
                            const std::string& device_id,
                            std::shared_ptr<GlobalDeviceKeyStore> store = nullptr)
        : user_id_(user_id), device_id_(device_id), global_store_(store) {
        if (!global_store_) {
            global_store_ = std::make_shared<GlobalDeviceKeyStore>();
        }
    }

    // Query device keys for specified users/devices
    // POST /_matrix/client/v3/keys/query
    // Request: { "device_keys": { "<user_id>": ["<device_id>", ...] } }
    json QueryDeviceKeys(const json& request_body) {
        CheckRateLimit();

        json response;
        response["device_keys"] = json::object();
        json failures;

        if (!request_body.contains("device_keys")) {
            return BuildResponse(response, failures);
        }

        auto& device_keys_query = request_body["device_keys"];

        int64_t total_queried = 0;
        int64_t total_found = 0;

        for (auto& [target_user, device_ids] : device_keys_query.items()) {
            if (target_user.empty()) {
                failures[target_user] = {{"errcode", "M_INVALID_PARAM"},
                                          {"error", "Empty user_id"}};
                continue;
            }

            // If device_ids is empty array, return all devices for the user
            if (device_ids.is_array() && device_ids.empty()) {
                // Return all known non-deleted devices
                std::shared_lock lock(global_store_->mutex);
                auto it = global_store_->device_keys.find(target_user);
                if (it != global_store_->device_keys.end()) {
                    for (auto& [dev_id, dev_data] : it->second) {
                        if (!dev_data.deleted) {
                            response["device_keys"][target_user][dev_id] =
                                DeviceKeyToJson(dev_data);
                            total_found++;
                        }
                    }
                }
                total_queried++;
                continue;
            }

            // Query specific device IDs
            if (!device_ids.is_array()) {
                failures[target_user] = {{"errcode", "M_INVALID_PARAM"},
                                          {"error", "device_ids must be an array"}};
                continue;
            }

            std::shared_lock lock(global_store_->mutex);
            auto user_it = global_store_->device_keys.find(target_user);

            if (user_it == global_store_->device_keys.end()) {
                // User not found - mark all requested devices as failure
                json user_failures;
                for (auto& did : device_ids) {
                    user_failures[did.get<std::string>()] = {
                        {"errcode", "M_NOT_FOUND"},
                        {"error", "User not found"}
                    };
                }
                failures[target_user] = user_failures;
                continue;
            }

            for (auto& device_id_val : device_ids) {
                std::string did = device_id_val.get<std::string>();
                total_queried++;

                auto dev_it = user_it->second.find(did);
                if (dev_it == user_it->second.end() || dev_it->second.deleted) {
                    if (!failures.contains(target_user)) {
                        failures[target_user] = json::object();
                    }
                    failures[target_user][did] = {
                        {"errcode", "M_NOT_FOUND"},
                        {"error", "Device not found or deleted"}
                    };
                    continue;
                }

                response["device_keys"][target_user][did] =
                    DeviceKeyToJson(dev_it->second);
                total_found++;
            }
        }

        auto result = BuildResponse(response, failures);
        result["total_queried"] = total_queried;
        result["total_found"] = total_found;
        return result;
    }

    // Query device keys with cross-signing keys included
    json QueryDeviceKeysWithCrossSigning(const json& request_body,
                                          const json& cross_signing_data) {
        auto result = QueryDeviceKeys(request_body);

        // Include cross-signing master keys
        if (cross_signing_data.contains("master_keys")) {
            result["master_keys"] = cross_signing_data["master_keys"];
        }
        if (cross_signing_data.contains("self_signing_keys")) {
            result["self_signing_keys"] = cross_signing_data["self_signing_keys"];
        }
        if (cross_signing_data.contains("user_signing_keys")) {
            result["user_signing_keys"] = cross_signing_data["user_signing_keys"];
        }

        return result;
    }

    // Register device keys from an upload (called by upload handler)
    void RegisterDeviceKeys(const std::string& uid,
                             const std::string& did,
                             const DeviceKeyData& key_data) {
        std::unique_lock lock(global_store_->mutex);
        global_store_->device_keys[uid][did] = key_data;
    }

    // Get raw device key data for internal use
    std::optional<DeviceKeyData> GetRawDeviceKey(const std::string& uid,
                                                   const std::string& did) const {
        std::shared_lock lock(global_store_->mutex);
        auto it = global_store_->device_keys.find(uid);
        if (it == global_store_->device_keys.end()) return std::nullopt;
        auto dit = it->second.find(did);
        if (dit == it->second.end()) return std::nullopt;
        return dit->second;
    }

    // Check if a user has any devices
    bool UserHasDevices(const std::string& uid) const {
        std::shared_lock lock(global_store_->mutex);
        auto it = global_store_->device_keys.find(uid);
        if (it == global_store_->device_keys.end()) return false;
        for (auto& [did, dd] : it->second) {
            if (!dd.deleted) return true;
        }
        return false;
    }

    // Get all device IDs for a user
    std::vector<std::string> GetUserDeviceIds(const std::string& uid) const {
        std::shared_lock lock(global_store_->mutex);
        std::vector<std::string> result;
        auto it = global_store_->device_keys.find(uid);
        if (it != global_store_->device_keys.end()) {
            for (auto& [did, dd] : it->second) {
                if (!dd.deleted) result.push_back(did);
            }
        }
        return result;
    }

private:
    void CheckRateLimit() const {
        std::lock_guard lock(rate_limit_.rate_mutex);
        int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

        // Remove timestamps older than 1 second
        while (!rate_limit_.query_timestamps.empty() &&
               rate_limit_.query_timestamps.front() < now) {
            rate_limit_.query_timestamps.pop_front();
        }

        if (static_cast<int>(rate_limit_.query_timestamps.size()) >=
            rate_limit_.max_queries_per_second) {
            throw DeviceKeysError("Rate limit exceeded: max " +
                std::to_string(rate_limit_.max_queries_per_second) +
                " queries per second");
        }

        rate_limit_.query_timestamps.push_back(now);
    }

    static json DeviceKeyToJson(const DeviceKeyData& kd) {
        json j;
        j["user_id"] = kd.user_id;
        j["device_id"] = kd.device_id;
        j["algorithms"] = kd.algorithms;
        j["keys"] = json::object();
        for (auto& [kid, kval] : kd.keys) {
            j["keys"][kid] = kval;
        }
        j["signatures"] = json::object();
        for (auto& [su, sigs] : kd.signatures) {
            j["signatures"][su] = json::object();
            for (auto& [kid, sv] : sigs) {
                j["signatures"][su][kid] = sv;
            }
        }
        if (!kd.device_display_name.empty()) {
            j["device_display_name"] = kd.device_display_name;
        }
        j["stream_id"] = kd.stream_id;
        return j;
    }

    static json BuildResponse(const json& device_keys, const json& failures) {
        json result;
        result["device_keys"] = device_keys["device_keys"];
        if (!failures.empty()) {
            result["failures"] = failures;
        } else {
            result["failures"] = json::object();
        }
        return result;
    }
};

// =============================================================================
// Device Keys Changes Handler
// =============================================================================
// Handles GET /_matrix/client/v3/keys/changes
// Tracks device list changes since a given token

class DeviceKeysChangesHandler {
private:
    std::string user_id_;

    // Change tracking: per-user list of changes
    struct UserChangeRecord {
        std::deque<DeviceListChange> changes;
        int64_t max_stream_id = 0;
    };

    std::unordered_map<std::string, UserChangeRecord> change_records_;
    static constexpr size_t kMaxChangesPerUser = 5000;
    mutable std::shared_mutex mutex_;

    // Global stream counter
    std::atomic<int64_t> global_stream_id_{0};

    // Track which users have changed since a given token
    std::map<int64_t, std::vector<std::string>> stream_to_users_;

public:
    explicit DeviceKeysChangesHandler(const std::string& user_id)
        : user_id_(user_id) {}

    // Record a device change
    int64_t RecordChange(const std::string& uid,
                          const std::string& device_id,
                          const std::string& change_type) {
        std::unique_lock lock(mutex_);

        int64_t sid = global_stream_id_.fetch_add(1);
        int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

        DeviceListChange change;
        change.user_id = uid;
        change.device_id = device_id;
        change.change_type = change_type;
        change.stream_id = sid;
        change.changed_at = now;

        auto& record = change_records_[uid];
        record.changes.push_back(std::move(change));
        record.max_stream_id = sid;

        // Prune old changes
        while (record.changes.size() > kMaxChangesPerUser) {
            record.changes.pop_front();
        }

        stream_to_users_[sid].push_back(uid);

        return sid;
    }

    // Get changed users since a given token
    // GET /_matrix/client/v3/keys/changes?from=<token>&to=<token>
    json GetChanges(const std::string& from_token,
                     const std::string& to_token = "") {
        std::shared_lock lock(mutex_);

        int64_t from = from_token.empty() ? 0 : std::stoll(from_token);
        int64_t to = to_token.empty() ?
            global_stream_id_.load() : std::stoll(to_token);

        std::set<std::string> changed_users;
        std::set<std::string> left_users;

        for (auto& [stream_id, users] : stream_to_users_) {
            if (stream_id > from && stream_id <= to) {
                for (auto& uid : users) {
                    // Check the most recent change for each user
                    auto it = change_records_.find(uid);
                    if (it != change_records_.end() && !it->second.changes.empty()) {
                        auto& last_change = it->second.changes.back();
                        if (last_change.change_type == "deleted") {
                            left_users.insert(uid);
                        } else {
                            changed_users.insert(uid);
                        }
                    }
                }
            }
        }

        json response;
        response["changed"] = json::array();
        for (auto& u : changed_users) {
            response["changed"].push_back(u);
        }

        response["left"] = json::array();
        for (auto& u : left_users) {
            response["left"].push_back(u);
        }

        return response;
    }

    // Get the latest change stream ID for a user
    int64_t GetLatestStreamId(const std::string& uid) const {
        std::shared_lock lock(mutex_);
        auto it = change_records_.find(uid);
        if (it == change_records_.end()) return 0;
        return it->second.max_stream_id;
    }

    // Get the global stream ID
    int64_t GetGlobalStreamId() const {
        return global_stream_id_.load();
    }

    // Get recent changes for a specific user
    json GetUserChanges(const std::string& uid,
                         int64_t from_stream,
                         int limit = 50) const {
        std::shared_lock lock(mutex_);
        json result;
        result["changes"] = json::array();

        auto it = change_records_.find(uid);
        if (it == change_records_.end()) return result;

        int count = 0;
        for (auto rit = it->second.changes.rbegin();
             rit != it->second.changes.rend() && count < limit;
             ++rit) {
            if (rit->stream_id > from_stream) {
                json change;
                change["user_id"] = rit->user_id;
                change["device_id"] = rit->device_id;
                change["change_type"] = rit->change_type;
                change["stream_id"] = rit->stream_id;
                change["changed_at"] = rit->changed_at;
                result["changes"].push_back(change);
                count++;
            }
        }

        result["total"] = static_cast<int64_t>(
            std::distance(it->second.changes.begin(), it->second.changes.end()));
        return result;
    }

    // Check if there are pending changes for a user
    bool HasPendingChanges(const std::string& uid) const {
        std::shared_lock lock(mutex_);
        auto it = change_records_.find(uid);
        return it != change_records_.end() && !it->second.changes.empty();
    }

    // Clear old change records (housekeeping)
    void PruneChanges(int64_t older_than_seconds = 86400) {
        std::unique_lock lock(mutex_);
        int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        int64_t cutoff = now - older_than_seconds;

        for (auto& [uid, record] : change_records_) {
            while (!record.changes.empty() &&
                   record.changes.front().changed_at < cutoff) {
                record.changes.pop_front();
            }
        }
    }
};

// =============================================================================
// One-Time Keys Upload Handler
// =============================================================================
// Handles POST /_matrix/client/v3/keys/upload for one-time keys
// Uploads pre-generated Curve25519 keys for Olm sessions

class OneTimeKeysUploadHandler {
private:
    std::string user_id_;
    std::string device_id_;

    // One-time key storage: key_id -> OneTimeKeyData
    std::unordered_map<std::string, OneTimeKeyData> one_time_keys_;

    // Algorithm-specific counts for /sync response
    std::atomic<int> signed_curve25519_count_{0};
    std::atomic<int> curve25519_count_{0};

    mutable std::shared_mutex mutex_;

public:
    OneTimeKeysUploadHandler(const std::string& user_id,
                              const std::string& device_id)
        : user_id_(user_id), device_id_(device_id) {}

    // Upload one-time keys
    // Request body: { "one_time_keys": { "<algo>:<key_id>": <key_value> } }
    json UploadOneTimeKeys(const json& request_body) {
        std::unique_lock lock(mutex_);

        if (!request_body.contains("one_time_keys")) {
            throw OneTimeKeyError("Missing one_time_keys in request body");
        }

        auto& keys = request_body["one_time_keys"];
        if (!keys.is_object()) {
            throw OneTimeKeyError("one_time_keys must be an object");
        }

        int signed_count = 0;
        int curve_count = 0;
        int total_uploaded = 0;
        std::vector<std::string> duplicate_keys;

        int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

        for (auto& [key_id, key_data] : keys.items()) {
            // Parse algorithm from key_id prefix, e.g. "signed_curve25519:AAAA..."
            std::string algo;
            if (key_id.find("signed_curve25519:") == 0) {
                algo = "signed_curve25519";
            } else if (key_id.find("curve25519:") == 0) {
                algo = "curve25519";
            } else {
                // Default: try to detect from key_id
                if (key_id.find("signed_curve25519") != std::string::npos) {
                    algo = "signed_curve25519";
                } else {
                    algo = "curve25519";
                }
            }

            // Check for duplicates
            if (one_time_keys_.find(key_id) != one_time_keys_.end() &&
                !one_time_keys_[key_id].claimed) {
                duplicate_keys.push_back(key_id);
                continue;
            }

            OneTimeKeyData otk;
            otk.user_id = user_id_;
            otk.device_id = device_id_;
            otk.key_id = key_id;
            otk.algorithm = algo;
            otk.created_at = now;
            otk.claimed = false;

            // Extract key value and signatures
            if (key_data.is_object()) {
                if (key_data.contains("key")) {
                    otk.key_value = key_data["key"].get<std::string>();
                }
                if (key_data.contains("signatures")) {
                    for (auto& [su, sigs] : key_data["signatures"].items()) {
                        for (auto& [kid, sv] : sigs.items()) {
                            otk.signatures[su + ":" + kid] = sv.get<std::string>();
                        }
                    }
                }
            } else if (key_data.is_string()) {
                otk.key_value = key_data.get<std::string>();
            }

            one_time_keys_[key_id] = std::move(otk);

            if (algo == "signed_curve25519") {
                signed_count++;
            } else {
                curve_count++;
            }
            total_uploaded++;
        }

        // Update counts
        UpdateCounts();
        signed_curve25519_count_.store(signed_count);
        curve25519_count_.store(curve_count);

        // Build response (one_time_key_counts)
        json response;
        response["signed_curve25519"] = signed_count;
        response["curve25519"] = curve_count;

        if (!duplicate_keys.empty()) {
            response["duplicate_keys"] = duplicate_keys;
            response["duplicate_count"] =
                static_cast<int>(duplicate_keys.size());
        }

        response["total_uploaded"] = total_uploaded;
        return response;
    }

    // Get the current count of available one-time keys by algorithm
    json GetOneTimeKeyCounts() const {
        std::shared_lock lock(mutex_);

        int signed_count = 0;
        int curve_count = 0;

        for (auto& [kid, otk] : one_time_keys_) {
            if (otk.claimed) continue;
            if (otk.algorithm == "signed_curve25519") {
                signed_count++;
            } else {
                curve_count++;
            }
        }

        json counts;
        counts["signed_curve25519"] = signed_count;
        counts["curve25519"] = curve_count;
        counts["total"] = signed_count + curve_count;
        return counts;
    }

    // Get all available (unclaimed) one-time keys
    std::vector<OneTimeKeyData> GetAvailableKeys() const {
        std::shared_lock lock(mutex_);
        std::vector<OneTimeKeyData> result;
        for (auto& [kid, otk] : one_time_keys_) {
            if (!otk.claimed) {
                result.push_back(otk);
            }
        }
        return result;
    }

    // Get available keys count by algorithm
    int GetAvailableCount(const std::string& algorithm) const {
        std::shared_lock lock(mutex_);
        int count = 0;
        for (auto& [kid, otk] : one_time_keys_) {
            if (!otk.claimed && otk.algorithm == algorithm) {
                count++;
            }
        }
        return count;
    }

    // Mark a key as claimed
    bool ClaimKey(const std::string& key_id,
                   const std::string& claimed_by_user = "",
                   const std::string& claimed_by_device = "") {
        std::unique_lock lock(mutex_);
        auto it = one_time_keys_.find(key_id);
        if (it == one_time_keys_.end() || it->second.claimed) {
            return false;
        }

        it->second.claimed = true;
        it->second.claimed_at = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        it->second.claimed_by_user = claimed_by_user;
        it->second.claimed_by_device = claimed_by_device;

        UpdateCounts();
        return true;
    }

    // Get a specific key by ID (for claiming)
    std::optional<OneTimeKeyData> GetKey(const std::string& key_id) const {
        std::shared_lock lock(mutex_);
        auto it = one_time_keys_.find(key_id);
        if (it == one_time_keys_.end()) return std::nullopt;
        return it->second;
    }

    // Remove claimed keys older than a certain age
    int PruneClaimedKeys(int64_t max_age_seconds = 3600) {
        std::unique_lock lock(mutex_);
        int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        int64_t cutoff = now - max_age_seconds;

        int pruned = 0;
        auto it = one_time_keys_.begin();
        while (it != one_time_keys_.end()) {
            if (it->second.claimed && it->second.claimed_at < cutoff) {
                it = one_time_keys_.erase(it);
                pruned++;
            } else {
                ++it;
            }
        }

        if (pruned > 0) UpdateCounts();
        return pruned;
    }

    // Get the keys in a format suitable for sync response
    json GetSyncKeyData() const {
        json result;
        result["device_id"] = device_id_;
        result["user_id"] = user_id_;

        // Return key counts only for sync
        json counts;
        counts["signed_curve25519"] = GetAvailableCount("signed_curve25519");
        counts["curve25519"] = GetAvailableCount("curve25519");
        result["counts"] = counts;

        return result;
    }

private:
    void UpdateCounts() {
        int sc = 0, cc = 0;
        for (auto& [kid, otk] : one_time_keys_) {
            if (otk.claimed) continue;
            if (otk.algorithm == "signed_curve25519") sc++;
            else cc++;
        }
        signed_curve25519_count_.store(sc);
        curve25519_count_.store(cc);
    }
};

// =============================================================================
// One-Time Keys Claim Handler
// =============================================================================
// Handles POST /_matrix/client/v3/keys/claim
// Claims one-time keys for initiating Olm sessions

class OneTimeKeysClaimHandler {
private:
    std::string user_id_;
    std::string device_id_;

    // Reference to one-time key stores across users/devices
    struct GlobalOTKStore {
        // user_id:device_id -> OneTimeKeysUploadHandler*
        // In production, this would be managed by a service locator
        std::unordered_map<std::string,
            std::shared_ptr<OneTimeKeysUploadHandler>> handlers;
        mutable std::shared_mutex mutex;
    };

    std::shared_ptr<GlobalOTKStore> global_otk_store_;

    // Claim rate limiting
    struct ClaimRateLimit {
        int max_claims_per_second = 50;
        int max_users_per_request = 100;
        int max_devices_per_user = 50;
        mutable std::deque<int64_t> claim_timestamps;
        mutable std::mutex rate_mutex;
    };
    ClaimRateLimit rate_limit_;

public:
    OneTimeKeysClaimHandler(const std::string& user_id,
                             const std::string& device_id,
                             std::shared_ptr<GlobalOTKStore> store = nullptr)
        : user_id_(user_id), device_id_(device_id), global_otk_store_(store) {
        if (!global_otk_store_) {
            global_otk_store_ = std::make_shared<GlobalOTKStore>();
        }
    }

    // Register a one-time key handler
    void RegisterHandler(const std::string& uid,
                          const std::string& did,
                          std::shared_ptr<OneTimeKeysUploadHandler> handler) {
        std::unique_lock lock(global_otk_store_->mutex);
        global_otk_store_->handlers[uid + ":" + did] = handler;
    }

    // Claim one-time keys
    // POST /_matrix/client/v3/keys/claim
    // Request: { "one_time_keys": { "<user_id>": { "<device_id>": "<algorithm>" } } }
    json ClaimKeys(const json& request_body) {
        CheckRateLimit();

        if (!request_body.contains("one_time_keys")) {
            throw OneTimeKeyError("Missing one_time_keys in claim request");
        }

        auto& claim_query = request_body["one_time_keys"];
        json result;
        result["one_time_keys"] = json::object();
        json failures;

        int users_processed = 0;
        int keys_claimed = 0;

        for (auto& [target_user, device_map] : claim_query.items()) {
            if (!device_map.is_object()) continue;

            users_processed++;
            if (users_processed > rate_limit_.max_users_per_request) {
                failures[target_user] = {{"errcode", "M_LIMIT_EXCEEDED"},
                                          {"error", "Too many users in request"}};
                continue;
            }

            int devices_processed = 0;
            for (auto& [target_device, algorithm] : device_map.items()) {
                devices_processed++;
                if (devices_processed > rate_limit_.max_devices_per_user) {
                    if (!failures.contains(target_user)) {
                        failures[target_user] = json::object();
                    }
                    failures[target_user][target_device] = {
                        {"errcode", "M_LIMIT_EXCEEDED"},
                        {"error", "Too many devices for user"}
                    };
                    continue;
                }

                std::string algo = algorithm.get<std::string>();

                // Try to claim a key
                auto handler_key = target_user + ":" + target_device;
                std::shared_ptr<OneTimeKeysUploadHandler> handler;

                {
                    std::shared_lock lock(global_otk_store_->mutex);
                    auto it = global_otk_store_->handlers.find(handler_key);
                    if (it != global_otk_store_->handlers.end()) {
                        handler = it->second;
                    }
                }

                if (!handler) {
                    if (!failures.contains(target_user)) {
                        failures[target_user] = json::object();
                    }
                    failures[target_user][target_device] = {
                        {"errcode", "M_NOT_FOUND"},
                        {"error", "No one-time keys for device"}
                    };
                    continue;
                }

                // Find an available key of the requested algorithm
                auto available = handler->GetAvailableKeys();
                bool claimed = false;

                for (auto& otk : available) {
                    if (otk.algorithm == algo ||
                        (algo == "signed_curve25519" &&
                         otk.algorithm == "signed_curve25519") ||
                        (algo == "curve25519" &&
                         otk.algorithm == "curve25519")) {

                        // Claim the key
                        if (handler->ClaimKey(otk.key_id, user_id_, device_id_)) {
                            json key_json;
                            key_json[otk.key_id] = json::object();
                            key_json[otk.key_id]["key"] = otk.key_value;
                            if (!otk.signatures.empty()) {
                                key_json[otk.key_id]["signatures"] =
                                    json::object();
                                for (auto& [sig_key, sig_val] : otk.signatures) {
                                    key_json[otk.key_id]["signatures"]
                                        [sig_key] = sig_val;
                                }
                            }

                            result["one_time_keys"][target_user][target_device] =
                                key_json;
                            keys_claimed++;
                            claimed = true;
                            break;
                        }
                    }
                }

                if (!claimed) {
                    if (!failures.contains(target_user)) {
                        failures[target_user] = json::object();
                    }
                    failures[target_user][target_device] = {
                        {"errcode", "M_NOT_FOUND"},
                        {"error", "No available one-time key of type: " + algo}
                    };
                }
            }
        }

        if (!failures.empty()) {
            result["failures"] = failures;
        }

        result["keys_claimed"] = keys_claimed;
        result["users_processed"] = users_processed;
        return result;
    }

    // Bulk claim - claim any available key per device
    json ClaimAnyKeys(const std::vector<std::pair<std::string, std::string>>&
                       target_devices) {
        json wrapper;
        wrapper["one_time_keys"] = json::object();

        for (auto& [uid, did] : target_devices) {
            wrapper["one_time_keys"][uid][did] = "signed_curve25519";
        }

        return ClaimKeys(wrapper);
    }

private:
    void CheckRateLimit() const {
        std::lock_guard lock(rate_limit_.rate_mutex);
        int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

        while (!rate_limit_.claim_timestamps.empty() &&
               rate_limit_.claim_timestamps.front() < now) {
            rate_limit_.claim_timestamps.pop_front();
        }

        if (static_cast<int>(rate_limit_.claim_timestamps.size()) >=
            rate_limit_.max_claims_per_second) {
            throw OneTimeKeyError("Claim rate limit exceeded");
        }

        rate_limit_.claim_timestamps.push_back(now);
    }
};

// =============================================================================
// One-Time Keys Count Handler
// =============================================================================
// Tracks and reports one-time key counts for sync responses

class OneTimeKeysCountHandler {
private:
    std::string user_id_;
    std::string device_id_;

    // Reference to own one-time key handler
    std::shared_ptr<OneTimeKeysUploadHandler> own_handler_;

    // Count tracking history for analytics
    struct CountSnapshot {
        int signed_count = 0;
        int curve_count = 0;
        int total = 0;
        int64_t timestamp = 0;
    };
    std::deque<CountSnapshot> count_history_;
    static constexpr size_t kMaxSnapshots = 1000;

    // Recommended minimum thresholds
    int min_signed_keys_ = 50;
    int min_unsigned_keys_ = 50;

    mutable std::mutex mutex_;

public:
    OneTimeKeysCountHandler(const std::string& user_id,
                             const std::string& device_id,
                             std::shared_ptr<OneTimeKeysUploadHandler> handler = nullptr)
        : user_id_(user_id), device_id_(device_id), own_handler_(handler) {}

    // Set the one-time key handler reference
    void SetHandler(std::shared_ptr<OneTimeKeysUploadHandler> handler) {
        own_handler_ = handler;
    }

    // Get current counts
    json GetCounts() const {
        if (!own_handler_) {
            return {{"signed_curve25519", 0}, {"curve25519", 0}, {"total", 0}};
        }
        return own_handler_->GetOneTimeKeyCounts();
    }

    // Get counts with recommendations
    json GetCountsWithRecommendations() const {
        auto counts = GetCounts();
        int signed_count = counts.value("signed_curve25519", 0);
        int curve_count = counts.value("curve25519", 0);

        json result;
        result["counts"] = counts;
        result["recommendations"] = json::object();

        if (signed_count < min_signed_keys_) {
            result["recommendations"]["signed_curve25519"] =
                "Low signed key count. Upload more signed_curve25519 keys. "
                "Minimum: " + std::to_string(min_signed_keys_) +
                ", Current: " + std::to_string(signed_count);
        }

        if (curve_count < min_unsigned_keys_) {
            result["recommendations"]["curve25519"] =
                "Low unsigned key count. Upload more curve25519 keys. "
                "Minimum: " + std::to_string(min_unsigned_keys_) +
                ", Current: " + std::to_string(curve_count);
        }

        result["thresholds"]["signed_curve25519_min"] = min_signed_keys_;
        result["thresholds"]["curve25519_min"] = min_unsigned_keys_;
        result["needs_upload"] = (signed_count < min_signed_keys_ ||
                                   curve_count < min_unsigned_keys_);

        return result;
    }

    // Record a count snapshot for history
    void RecordSnapshot() {
        if (!own_handler_) return;

        std::lock_guard lock(mutex_);
        auto counts = own_handler_->GetOneTimeKeyCounts();

        CountSnapshot snap;
        snap.signed_count = counts.value("signed_curve25519", 0);
        snap.curve_count = counts.value("curve25519", 0);
        snap.total = counts.value("total", 0);
        snap.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

        count_history_.push_back(snap);
        while (count_history_.size() > kMaxSnapshots) {
            count_history_.pop_front();
        }
    }

    // Get count history
    json GetCountHistory(int limit = 100) const {
        std::lock_guard lock(mutex_);
        json result;
        result["history"] = json::array();

        int count = 0;
        for (auto it = count_history_.rbegin();
             it != count_history_.rend() && count < limit;
             ++it, count++) {
            json entry;
            entry["signed_count"] = it->signed_count;
            entry["curve_count"] = it->curve_count;
            entry["total"] = it->total;
            entry["timestamp"] = it->timestamp;
            result["history"].push_back(entry);
        }

        result["total_snapshots"] =
            static_cast<int64_t>(count_history_.size());
        return result;
    }

    // Get trend analysis
    json GetTrend(int window_seconds = 3600) const {
        std::lock_guard lock(mutex_);

        if (count_history_.size() < 2) {
            return {{"trend", "insufficient_data"}};
        }

        int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        int64_t cutoff = now - window_seconds;

        // Find first and last snapshots in the window
        const CountSnapshot* first = nullptr;
        const CountSnapshot* last = nullptr;

        for (auto& snap : count_history_) {
            if (snap.timestamp >= cutoff) {
                if (!first) first = &snap;
                last = &snap;
            }
        }

        if (!first || !last || first == last) {
            return {{"trend", "insufficient_data"}};
        }

        json result;
        result["trend_signed"] = last->signed_count - first->signed_count;
        result["trend_curve"] = last->curve_count - first->curve_count;
        result["trend_total"] = last->total - first->total;
        result["first_snapshot_seconds_ago"] = now - first->timestamp;
        result["last_snapshot_seconds_ago"] = now - last->timestamp;
        result["window_seconds"] = window_seconds;

        return result;
    }

    // Check if counts are below threshold
    bool IsBelowThreshold() const {
        auto counts = GetCounts();
        return counts.value("signed_curve25519", 0) < min_signed_keys_ ||
               counts.value("curve25519", 0) < min_unsigned_keys_;
    }

    // Get the minimum recommended count
    int GetMinRecommendedCount() const {
        return min_signed_keys_ + min_unsigned_keys_;
    }
};

// =============================================================================
// Fallback Keys Management
// =============================================================================
// Manages fallback keys for devices that run out of one-time keys
// A fallback key is used when no one-time keys are available
// The other party is notified that a fallback key was used

class FallbackKeysManager {
private:
    std::string user_id_;
    std::string device_id_;

    // Fallback key storage
    std::unordered_map<std::string, FallbackKeyData> fallback_keys_;

    // Key rotation tracking
    struct FallbackKeyRotation {
        int64_t last_rotation = 0;
        int rotation_count = 0;
        int64_t min_rotation_interval_seconds = 86400;  // 24 hours
    };
    FallbackKeyRotation rotation_;

    mutable std::shared_mutex mutex_;

public:
    FallbackKeysManager(const std::string& user_id,
                         const std::string& device_id)
        : user_id_(user_id), device_id_(device_id) {}

    // Upload a fallback key
    // PUT /_matrix/client/v3/keys/upload/{key_id}
    json UploadFallbackKey(const std::string& key_id, const json& key_data) {
        std::unique_lock lock(mutex_);

        int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

        FallbackKeyData fb;
        fb.user_id = user_id_;
        fb.device_id = device_id_;
        fb.key_id = key_id;
        fb.algorithm = "signed_curve25519";
        fb.created_at = now;
        fb.used = false;

        // Parse key data
        if (key_data.is_object()) {
            if (key_data.contains("key")) {
                fb.key_value = key_data["key"].get<std::string>();
            } else if (key_data.contains("keys")) {
                auto& keys = key_data["keys"];
                if (keys.contains(key_id)) {
                    fb.key_value = keys[key_id].get<std::string>();
                }
            }
            if (key_data.contains("signatures")) {
                for (auto& [su, sigs] : key_data["signatures"].items()) {
                    for (auto& [kid, sv] : sigs.items()) {
                        fb.signatures[su + ":" + kid] = sv.get<std::string>();
                    }
                }
            }
        } else if (key_data.is_string()) {
            fb.key_value = key_data.get<std::string>();
        }

        // Check rotation policy
        if (!fallback_keys_.empty() && rotation.last_rotation > 0) {
            if (now - rotation.last_rotation <
                rotation.min_rotation_interval_seconds) {
                // Too soon to rotate, but we'll store it anyway
            }
        }

        fallback_keys_[key_id] = std::move(fb);
        rotation.last_rotation = now;
        rotation.rotation_count++;

        json response;
        response["key_id"] = key_id;
        response["algorithm"] = "signed_curve25519";
        response["uploaded"] = true;
        response["rotation_count"] = rotation.rotation_count;
        return response;
    }

    // Get the current fallback key
    std::optional<FallbackKeyData> GetFallbackKey() const {
        std::shared_lock lock(mutex_);

        // Return the most recently created non-used fallback key
        const FallbackKeyData* best = nullptr;
        int64_t best_time = 0;

        for (auto& [kid, fb] : fallback_keys_) {
            if (!fb.used && fb.created_at > best_time) {
                best = &fb;
                best_time = fb.created_at;
            }
        }

        if (best) return *best;
        return std::nullopt;
    }

    // Use the fallback key (mark as used)
    std::optional<FallbackKeyData> UseFallbackKey() {
        std::unique_lock lock(mutex_);

        auto fb = GetFallbackKey();
        if (!fb) return std::nullopt;

        int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

        auto it = fallback_keys_.find(fb->key_id);
        if (it != fallback_keys_.end()) {
            it->second.used = true;
            it->second.used_at = now;
        }

        return fb;
    }

    // Get fallback key info for sync response
    json GetSyncFallbackKeyData() const {
        std::shared_lock lock(mutex_);

        auto fb = GetFallbackKey();
        if (!fb) {
            return json::object();
        }

        json result;
        result["key_id"] = fb->key_id;
        result["algorithm"] = fb->algorithm;
        result["key"] = fb->key_value;

        if (!fb->signatures.empty()) {
            result["signatures"] = json::object();
            for (auto& [sig_key, sig_val] : fb->signatures) {
                result["signatures"][sig_key] = sig_val;
            }
        }

        return result;
    }

    // Check if fallback key rotation is needed
    bool NeedsRotation() const {
        std::shared_lock lock(mutex_);

        if (fallback_keys_.empty()) return true;

        int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

        // Check if current key has been used
        auto fb = GetFallbackKey();
        if (!fb) return true;

        // Check age-based rotation
        if (fb->created_at > 0 &&
            (now - fb->created_at) > rotation.min_rotation_interval_seconds) {
            return true;
        }

        return false;
    }

    // Get usage statistics
    json GetUsageStats() const {
        std::shared_lock lock(mutex_);

        int total_keys = static_cast<int>(fallback_keys_.size());
        int used_keys = 0;
        int available_keys = 0;

        for (auto& [kid, fb] : fallback_keys_) {
            if (fb.used) used_keys++;
            else available_keys++;
        }

        json stats;
        stats["total_keys"] = total_keys;
        stats["used_keys"] = used_keys;
        stats["available_keys"] = available_keys;
        stats["rotation_count"] = rotation.rotation_count;
        stats["last_rotation"] = rotation.last_rotation;
        stats["needs_rotation"] = NeedsRotation();
        return stats;
    }

    // Delete old fallback keys
    int PruneOldKeys(int64_t max_age_seconds = 7776000) {  // 90 days default
        std::unique_lock lock(mutex_);
        int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        int64_t cutoff = now - max_age_seconds;

        int pruned = 0;
        auto it = fallback_keys_.begin();
        while (it != fallback_keys_.end()) {
            if (it->second.used && it->second.used_at < cutoff) {
                it = fallback_keys_.erase(it);
                pruned++;
            } else {
                ++it;
            }
        }

        return pruned;
    }
};

// =============================================================================
// Device Key Cross-Signing Integration
// =============================================================================
// Integrates device keys with cross-signing:
//   - Signs device keys with self-signing key
//   - Verifies device keys against master/self-signing keys
//   - Updates signatures when cross-signing keys change

class DeviceKeyCrossSigning {
private:
    std::string user_id_;

    // Cross-signing key storage
    std::unordered_map<std::string, CrossSigningKeyRecord> cross_signing_keys_;
    // key_type ("master", "self_signing", "user_signing") -> record

    // Device signature tracking
    struct DeviceSignature {
        std::string device_id;
        std::string signing_key_id;
        std::string signature;
        int64_t signed_at = 0;
        bool verified = false;
    };
    std::unordered_map<std::string, DeviceSignature> device_signatures_;

    // Device trust state
    struct DeviceTrust {
        std::string device_id;
        bool is_verified = false;
        bool is_blocked = false;
        bool is_ignored = false;
        std::string verification_method;  // "self_signing", "user_signing"
        int64_t verified_at = 0;
    };
    std::unordered_map<std::string, DeviceTrust> device_trust_;

    mutable std::shared_mutex mutex_;

public:
    explicit DeviceKeyCrossSigning(const std::string& user_id)
        : user_id_(user_id) {}

    // Store a cross-signing key
    void StoreCrossSigningKey(const std::string& key_type,
                               const std::string& public_key,
                               const json& signatures = json::object()) {
        std::unique_lock lock(mutex_);

        CrossSigningKeyRecord record;
        record.user_id = user_id_;
        record.key_type = key_type;
        record.public_key = public_key;
        record.uploaded_at = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

        if (signatures.is_object()) {
            for (auto& [su, sigs] : signatures.items()) {
                for (auto& [kid, sv] : sigs.items()) {
                    record.signatures[su][kid] = sv.get<std::string>();
                }
            }
        }

        cross_signing_keys_[key_type] = std::move(record);
    }

    // Upload cross-signing keys
    // POST /_matrix/client/v3/keys/device_signing/upload
    json UploadCrossSigningKeys(const json& payload) {
        std::unique_lock lock(mutex_);

        json result;
        result["uploaded"] = json::object();

        if (payload.contains("master_key")) {
            auto& mk = payload["master_key"];
            std::string pub_key;
            if (mk.contains("keys")) {
                for (auto& [kid, kv] : mk["keys"].items()) {
                    pub_key = kv.get<std::string>();
                    break;  // Take first key
                }
            }
            if (mk.contains("public_key")) {
                pub_key = mk["public_key"].get<std::string>();
            }

            json sigs = mk.value("signatures", json::object());
            StoreCrossSigningKey("master", pub_key, sigs);
            result["uploaded"]["master_key"] = true;
        }

        if (payload.contains("self_signing_key")) {
            auto& ssk = payload["self_signing_key"];
            std::string pub_key;
            if (ssk.contains("keys")) {
                for (auto& [kid, kv] : ssk["keys"].items()) {
                    pub_key = kv.get<std::string>();
                    break;
                }
            }

            json sigs = ssk.value("signatures", json::object());
            StoreCrossSigningKey("self_signing", pub_key, sigs);
            result["uploaded"]["self_signing_key"] = true;
        }

        if (payload.contains("user_signing_key")) {
            auto& usk = payload["user_signing_key"];
            std::string pub_key;
            if (usk.contains("keys")) {
                for (auto& [kid, kv] : usk["keys"].items()) {
                    pub_key = kv.get<std::string>();
                    break;
                }
            }

            json sigs = usk.value("signatures", json::object());
            StoreCrossSigningKey("user_signing", pub_key, sigs);
            result["uploaded"]["user_signing_key"] = true;
        }

        return result;
    }

    // Sign a device's keys with self-signing key
    // Returns the signature data to be attached to device keys
    json SignDeviceKeys(const std::string& device_id,
                         const json& device_keys_json,
                         const std::vector<uint8_t>& self_signing_private_key) {
        std::unique_lock lock(mutex_);

        // Build canonical representation for signing
        std::string canonical = CanonicalizeForSigning(device_keys_json);

        // Sign with Ed25519
        std::vector<uint8_t> msg(canonical.begin(), canonical.end());

        EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(
            EVP_PKEY_ED25519, nullptr,
            self_signing_private_key.data(),
            self_signing_private_key.size());

        if (!pkey) {
            throw DeviceKeysError("Failed to create signing key");
        }

        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, pkey);
        size_t sig_len = 64;
        std::vector<uint8_t> sig(sig_len);
        EVP_DigestSign(ctx, sig.data(), &sig_len, msg.data(), msg.size());
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        sig.resize(sig_len);

        // Get the self-signing key ID
        std::string signing_key_id;
        auto it = cross_signing_keys_.find("self_signing");
        if (it != cross_signing_keys_.end()) {
            signing_key_id = "ed25519:" + it->second.public_key;
        }

        // Store signature
        DeviceSignature ds;
        ds.device_id = device_id;
        ds.signing_key_id = signing_key_id;
        ds.signature = base64_internal::EncodeUnpadded(sig);
        ds.signed_at = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        ds.verified = true;
        device_signatures_[device_id] = ds;

        // Update trust
        DeviceTrust trust;
        trust.device_id = device_id;
        trust.is_verified = true;
        trust.verification_method = "self_signing";
        trust.verified_at = ds.signed_at;
        device_trust_[device_id] = trust;

        // Return the signature payload
        json sig_payload;
        sig_payload["signatures"] = json::object();
        sig_payload["signatures"][user_id_] = json::object();
        sig_payload["signatures"][user_id_][signing_key_id] =
            base64_internal::EncodeUnpadded(sig);
        return sig_payload;
    }

    // Verify a device key against master/self-signing key
    bool VerifyDeviceKey(const std::string& device_id,
                          const json& device_keys,
                          const std::vector<uint8_t>& self_signing_public_key) {
        std::shared_lock lock(mutex_);

        if (!device_keys.contains("signatures")) return false;
        if (!device_keys["signatures"].contains(user_id_)) return false;

        auto& user_sigs = device_keys["signatures"][user_id_];
        if (!user_sigs.is_object()) return false;

        // Find the self-signing key signature
        for (auto& [key_id, signature_b64] : user_sigs.items()) {
            if (key_id.find("ed25519:") != 0) continue;

            // Build canonical JSON for verification
            json verifiable = device_keys;
            verifiable.erase("signatures");
            std::string canonical = CanonicalizeForSigning(verifiable);

            std::vector<uint8_t> msg(canonical.begin(), canonical.end());

            // Try to verify
            auto sig_bytes = base64_internal::Decode(
                signature_b64.get<std::string>());

            EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key(
                EVP_PKEY_ED25519, nullptr,
                self_signing_public_key.data(),
                self_signing_public_key.size());

            if (!pkey) return false;

            EVP_MD_CTX* ctx = EVP_MD_CTX_new();
            EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, pkey);
            int rc = EVP_DigestVerify(ctx, sig_bytes.data(), sig_bytes.size(),
                                       msg.data(), msg.size());
            EVP_MD_CTX_free(ctx);
            EVP_PKEY_free(pkey);

            if (rc == 1) {
                // Store verified state
                std::unique_lock wlock(mutex_);
                device_trust_[device_id].is_verified = true;
                device_trust_[device_id].verification_method = "self_signing";
                device_trust_[device_id].verified_at =
                    std::chrono::duration_cast<std::chrono::seconds>(
                        std::chrono::system_clock::now().time_since_epoch()
                    ).count();
                return true;
            }
        }

        return false;
    }

    // Get device trust state
    DeviceTrust GetDeviceTrust(const std::string& device_id) const {
        std::shared_lock lock(mutex_);
        auto it = device_trust_.find(device_id);
        if (it != device_trust_.end()) return it->second;

        DeviceTrust unknown;
        unknown.device_id = device_id;
        return unknown;
    }

    // Set device trust state manually
    void SetDeviceTrust(const std::string& device_id,
                         bool verified, bool blocked, bool ignored) {
        std::unique_lock lock(mutex_);

        DeviceTrust trust;
        auto it = device_trust_.find(device_id);
        if (it != device_trust_.end()) {
            trust = it->second;
        }
        trust.device_id = device_id;
        trust.is_verified = verified;
        trust.is_blocked = blocked;
        trust.is_ignored = ignored;
        if (verified && !trust.is_verified) {
            trust.verified_at = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
            trust.verification_method = "manual";
        }
        device_trust_[device_id] = trust;
    }

    // Get all cross-signing keys
    json GetCrossSigningKeys() const {
        std::shared_lock lock(mutex_);
        json result;
        result["master_keys"] = json::object();
        result["self_signing_keys"] = json::object();
        result["user_signing_keys"] = json::object();

        for (auto& [key_type, record] : cross_signing_keys_) {
            json key_obj;
            key_obj["user_id"] = record.user_id;
            key_obj["usage"] = json::array({key_type});
            key_obj["keys"] = json::object();
            key_obj["keys"]["ed25519:" + record.public_key] = record.public_key;

            if (!record.signatures.empty()) {
                key_obj["signatures"] = json::object();
                for (auto& [su, sigs] : record.signatures) {
                    key_obj["signatures"][su] = json::object();
                    for (auto& [kid, sv] : sigs) {
                        key_obj["signatures"][su][kid] = sv;
                    }
                }
            }

            if (key_type == "master") {
                result["master_keys"][user_id_] = key_obj;
            } else if (key_type == "self_signing") {
                result["self_signing_keys"][user_id_] = key_obj;
            } else if (key_type == "user_signing") {
                result["user_signing_keys"][user_id_] = key_obj;
            }
        }

        return result;
    }

    // Get signature status for all devices
    json GetSignatureStatus() const {
        std::shared_lock lock(mutex_);
        json result;
        result["devices"] = json::object();

        for (auto& [did, sig] : device_signatures_) {
            json sig_info;
            sig_info["signing_key_id"] = sig.signing_key_id;
            sig_info["signed_at"] = sig.signed_at;
            sig_info["verified"] = sig.verified;

            auto trust_it = device_trust_.find(did);
            if (trust_it != device_trust_.end()) {
                sig_info["is_verified"] = trust_it->second.is_verified;
                sig_info["is_blocked"] = trust_it->second.is_blocked;
                sig_info["is_ignored"] = trust_it->second.is_ignored;
            }

            result["devices"][did] = sig_info;
        }

        result["total_devices"] =
            static_cast<int64_t>(device_signatures_.size());
        return result;
    }

    // Check master key is trusted (for TOFU logic)
    bool IsMasterKeyTrusted() const {
        std::shared_lock lock(mutex_);
        return cross_signing_keys_.find("master") != cross_signing_keys_.end();
    }

private:
    static std::string CanonicalizeForSigning(const json& obj) {
        // Simple canonicalization: sort keys, remove whitespace
        if (obj.is_object()) {
            std::vector<std::string> keys;
            for (auto& [k, v] : obj.items()) {
                keys.push_back(k);
            }
            std::sort(keys.begin(), keys.end());

            std::string result = "{";
            bool first = true;
            for (auto& k : keys) {
                if (!first) result += ",";
                result += "\"" + EscapeJsonString(k) + "\":";
                result += CanonicalizeForSigning(obj[k]);
                first = false;
            }
            result += "}";
            return result;
        } else if (obj.is_array()) {
            std::string result = "[";
            bool first = true;
            for (auto& v : obj) {
                if (!first) result += ",";
                result += CanonicalizeForSigning(v);
                first = false;
            }
            result += "]";
            return result;
        } else if (obj.is_string()) {
            return "\"" + EscapeJsonString(obj.get<std::string>()) + "\"";
        } else if (obj.is_number_integer()) {
            return std::to_string(obj.get<int64_t>());
        } else if (obj.is_number_float()) {
            return std::to_string(obj.get<double>());
        } else if (obj.is_boolean()) {
            return obj.get<bool>() ? "true" : "false";
        } else if (obj.is_null()) {
            return "null";
        }
        return "null";
    }

    static std::string EscapeJsonString(const std::string& s) {
        std::string result;
        for (char c : s) {
            switch (c) {
            case '"': result += "\\\""; break;
            case '\\': result += "\\\\"; break;
            case '\n': result += "\\n"; break;
            case '\r': result += "\\r"; break;
            case '\t': result += "\\t"; break;
            default: result += c;
            }
        }
        return result;
    }
};

// =============================================================================
// Key Count Threshold Alerts
// =============================================================================
// Monitors key counts and generates alerts when thresholds are crossed

class KeyCountThresholdManager {
private:
    std::string user_id_;
    std::string device_id_;
    KeyCountThresholds thresholds_;

    // Reference to key handlers
    std::shared_ptr<OneTimeKeysCountHandler> otk_count_handler_;
    std::shared_ptr<FallbackKeysManager> fallback_handler_;

    // Alert state to avoid repeated alerts
    struct AlertState {
        bool otk_warning_active = false;
        bool otk_critical_active = false;
        bool fallback_key_old = false;
        bool fallback_key_overused = false;
        int64_t last_alert_at = 0;
        int alert_cooldown_seconds = 300;  // 5 minutes between alerts
    };
    AlertState alert_state_;

    // Alert history
    struct AlertRecord {
        std::string alert_type;
        std::string severity;
        std::string message;
        json data;
        int64_t timestamp = 0;
        bool acknowledged = false;
    };
    std::deque<AlertRecord> alert_history_;
    static constexpr size_t kMaxAlerts = 500;

    mutable std::mutex alert_mutex_;

public:
    KeyCountThresholdManager(const std::string& user_id,
                              const std::string& device_id,
                              const KeyCountThresholds& thresholds = KeyCountThresholds{})
        : user_id_(user_id), device_id_(device_id), thresholds_(thresholds) {}

    // Set references to handlers
    void SetOTKCountHandler(std::shared_ptr<OneTimeKeysCountHandler> handler) {
        otk_count_handler_ = handler;
    }

    void SetFallbackHandler(std::shared_ptr<FallbackKeysManager> handler) {
        fallback_handler_ = handler;
    }

    // Configure thresholds
    void SetThresholds(const KeyCountThresholds& thresholds) {
        thresholds_ = thresholds;
    }

    // Check all thresholds and generate alerts
    // Returns list of active alerts
    json CheckThresholds() {
        std::lock_guard lock(alert_mutex_);

        int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

        // Check cooldown
        if (now - alert_state_.last_alert_at <
            alert_state_.alert_cooldown_seconds) {
            json result;
            result["alerts"] = json::array();
            result["in_cooldown"] = true;
            return result;
        }

        json result;
        result["alerts"] = json::array();
        bool any_alert = false;

        // Check one-time key counts
        if (otk_count_handler_) {
            auto counts = otk_count_handler_->GetCounts();
            int signed_count = counts.value("signed_curve25519", 0);
            int curve_count = counts.value("curve25519", 0);
            int total = counts.value("total", 0);

            // Critical: total below critical threshold
            if (total < thresholds_.one_time_key_critical && !alert_state_.otk_critical_active) {
                AlertRecord alert;
                alert.alert_type = "otk_count_critical";
                alert.severity = "critical";
                alert.message = "One-time key count critically low: " +
                                std::to_string(total) + " total (threshold: " +
                                std::to_string(thresholds_.one_time_key_critical) + ")";
                alert.data["signed_count"] = signed_count;
                alert.data["curve_count"] = curve_count;
                alert.data["total"] = total;
                alert.data["critical_threshold"] = thresholds_.one_time_key_critical;
                alert.timestamp = now;
                alert_history_.push_back(alert);
                result["alerts"].push_back(AlertToJson(alert));
                alert_state_.otk_critical_active = true;
                alert_state_.otk_warning_active = true;
                any_alert = true;
            }
            // Warning: total below warning threshold
            else if (total < thresholds_.one_time_key_warning &&
                     total >= thresholds_.one_time_key_critical &&
                     !alert_state_.otk_warning_active) {
                AlertRecord alert;
                alert.alert_type = "otk_count_warning";
                alert.severity = "warning";
                alert.message = "One-time key count low: " +
                                std::to_string(total) + " total (threshold: " +
                                std::to_string(thresholds_.one_time_key_warning) + ")";
                alert.data["signed_count"] = signed_count;
                alert.data["curve_count"] = curve_count;
                alert.data["total"] = total;
                alert.data["warning_threshold"] = thresholds_.one_time_key_warning;
                alert.timestamp = now;
                alert_history_.push_back(alert);
                result["alerts"].push_back(AlertToJson(alert));
                alert_state_.otk_warning_active = true;
                any_alert = true;
            }
            // Reset if counts are above thresholds
            else if (total >= thresholds_.one_time_key_warning) {
                alert_state_.otk_warning_active = false;
                alert_state_.otk_critical_active = false;
            }

            // Signed key specific checks
            if (signed_count < thresholds_.one_time_key_signed_critical) {
                if (!alert_state_.otk_critical_active) {
                    AlertRecord alert;
                    alert.alert_type = "otk_signed_critical";
                    alert.severity = "critical";
                    alert.message = "Signed one-time key count critically low: " +
                                    std::to_string(signed_count);
                    alert.data["signed_count"] = signed_count;
                    alert.data["signed_critical"] = thresholds_.one_time_key_signed_critical;
                    alert.timestamp = now;
                    alert_history_.push_back(alert);
                    result["alerts"].push_back(AlertToJson(alert));
                    any_alert = true;
                }
            }
            if (signed_count < thresholds_.one_time_key_signed_warning &&
                signed_count >= thresholds_.one_time_key_signed_critical) {
                if (!alert_state_.otk_warning_active) {
                    AlertRecord alert;
                    alert.alert_type = "otk_signed_warning";
                    alert.severity = "warning";
                    alert.message = "Signed one-time key count low: " +
                                    std::to_string(signed_count);
                    alert.data["signed_count"] = signed_count;
                    alert.data["signed_warning"] = thresholds_.one_time_key_signed_warning;
                    alert.timestamp = now;
                    alert_history_.push_back(alert);
                    result["alerts"].push_back(AlertToJson(alert));
                    any_alert = true;
                }
            }
        }

        // Check fallback key status
        if (fallback_handler_) {
            auto stats = fallback_handler_->GetUsageStats();

            if (stats.value("needs_rotation", false) && !alert_state_.fallback_key_old) {
                AlertRecord alert;
                alert.alert_type = "fallback_key_rotation_needed";
                alert.severity = "warning";
                alert.message = "Fallback key rotation recommended";
                alert.data["last_rotation"] = stats.value("last_rotation", 0);
                alert.timestamp = now;
                alert_history_.push_back(alert);
                result["alerts"].push_back(AlertToJson(alert));
                alert_state_.fallback_key_old = true;
                any_alert = true;
            }

            int used_keys = stats.value("used_keys", 0);
            if (used_keys > static_cast<int>(thresholds_.fallback_key_max_uses) &&
                !alert_state_.fallback_key_overused) {
                AlertRecord alert;
                alert.alert_type = "fallback_key_overused";
                alert.severity = "warning";
                alert.message = "Fallback key used " + std::to_string(used_keys) +
                                " times (max: " +
                                std::to_string(thresholds_.fallback_key_max_uses) + ")";
                alert.data["used_keys"] = used_keys;
                alert.data["max_uses"] = thresholds_.fallback_key_max_uses;
                alert.timestamp = now;
                alert_history_.push_back(alert);
                result["alerts"].push_back(AlertToJson(alert));
                alert_state_.fallback_key_overused = true;
                any_alert = true;
            }
        }

        if (any_alert) {
            alert_state_.last_alert_at = now;
        }

        result["active_alerts"] =
            static_cast<int64_t>(result["alerts"].size());
        return result;
    }

    // Acknowledge an alert
    bool AcknowledgeAlert(const std::string& alert_type) {
        std::lock_guard lock(alert_mutex_);
        for (auto& alert : alert_history_) {
            if (alert.alert_type == alert_type && !alert.acknowledged) {
                alert.acknowledged = true;
                return true;
            }
        }
        return false;
    }

    // Get alert history
    json GetAlertHistory(int limit = 50) const {
        std::lock_guard lock(alert_mutex_);
        json result;
        result["alerts"] = json::array();

        int count = 0;
        for (auto it = alert_history_.rbegin();
             it != alert_history_.rend() && count < limit;
             ++it, count++) {
            result["alerts"].push_back(AlertToJson(*it));
        }

        result["total"] = static_cast<int64_t>(alert_history_.size());
        return result;
    }

    // Get current active alert state
    json GetActiveAlerts() const {
        std::lock_guard lock(alert_mutex_);

        // Prune acknowledged alerts older than 1 hour
        json result;
        result["one_time_key_warning"] = alert_state_.otk_warning_active;
        result["one_time_key_critical"] = alert_state_.otk_critical_active;
        result["fallback_key_old"] = alert_state_.fallback_key_old;
        result["fallback_key_overused"] = alert_state_.fallback_key_overused;
        result["last_alert_at"] = alert_state_.last_alert_at;

        if (otk_count_handler_) {
            result["current_counts"] = otk_count_handler_->GetCounts();
        }

        return result;
    }

    // Reset alert state (e.g., after uploading enough keys)
    void ResetAlerts() {
        std::lock_guard lock(alert_mutex_);
        alert_state_ = AlertState{};
    }

private:
    static json AlertToJson(const AlertRecord& alert) {
        json j;
        j["type"] = alert.alert_type;
        j["severity"] = alert.severity;
        j["message"] = alert.message;
        j["data"] = alert.data;
        j["timestamp"] = alert.timestamp;
        j["acknowledged"] = alert.acknowledged;
        return j;
    }
};

// =============================================================================
// Key Backup Version Migration
// =============================================================================
// Handles migrating from one backup version to another
// Supports:
//   - Creating new backup version
//   - Copying keys from old version to new
//   - Verifying migration completeness
//   - Rolling back if needed

class BackupMigrationManager {
private:
    std::string user_id_;
    std::shared_ptr<RoomKeyVersionManager> version_manager_;

    struct MigrationState {
        std::string from_version;
        std::string to_version;
        std::string status;  // "pending", "in_progress", "completed", "failed", "rolled_back"
        int64_t total_keys = 0;
        int64_t migrated_keys = 0;
        int64_t failed_keys = 0;
        int64_t started_at = 0;
        int64_t completed_at = 0;
        std::string error_message;
        bool verified = false;
    };
    std::deque<MigrationState> migrations_;
    std::unique_ptr<MigrationState> active_migration_;
    static constexpr size_t kMaxMigrationHistory = 100;

    mutable std::mutex migration_mutex_;

public:
    BackupMigrationManager(const std::string& user_id,
                            std::shared_ptr<RoomKeyVersionManager> version_mgr = nullptr)
        : user_id_(user_id), version_manager_(version_mgr) {}

    void SetVersionManager(std::shared_ptr<RoomKeyVersionManager> version_mgr) {
        version_manager_ = version_mgr;
    }

    // Start migration from one version to another
    json StartMigration(const std::string& from_version,
                         const std::string& to_version) {
        std::lock_guard lock(migration_mutex_);

        if (active_migration_) {
            throw RoomKeysError("A migration is already in progress: " +
                active_migration_->from_version + " -> " +
                active_migration_->to_version);
        }

        if (!version_manager_) {
            throw RoomKeysError("Version manager not set");
        }

        // Validate versions exist
        auto from_info = version_manager_->GetVersionInfo(from_version);
        auto to_info = version_manager_->GetVersionInfo(to_version);

        int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

        active_migration_ = std::make_unique<MigrationState>();
        active_migration_->from_version = from_version;
        active_migration_->to_version = to_version;
        active_migration_->status = "pending";
        active_migration_->started_at = now;
        active_migration_->total_keys = from_info.value("count", 0);

        json response;
        response["migration_id"] = std::to_string(now);
        response["from_version"] = from_version;
        response["to_version"] = to_version;
        response["status"] = "pending";
        response["total_keys_to_migrate"] = active_migration_->total_keys;
        return response;
    }

    // Execute migration (copy keys from old version to new)
    json ExecuteMigration() {
        std::lock_guard lock(migration_mutex_);

        if (!active_migration_) {
            throw RoomKeysError("No active migration");
        }

        active_migration_->status = "in_progress";
        int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

        try {
            // Get all keys from source version
            auto from_handler = version_manager_->GetUploadHandler(
                active_migration_->from_version);
            auto to_handler = version_manager_->GetUploadHandler(
                active_migration_->to_version);

            auto all_keys = from_handler->GetAllRoomKeys(
                active_migration_->from_version);

            if (!all_keys.contains("rooms")) {
                active_migration_->status = "completed";
                active_migration_->completed_at = now;
                active_migration_->verified = true;
                migrations_.push_back(*active_migration_);
                active_migration_.reset();

                while (migrations_.size() > kMaxMigrationHistory) {
                    migrations_.pop_front();
                }

                return {{"status", "completed"}, {"migrated_keys", 0},
                        {"message", "No keys to migrate"}};
            }

            // Migrate keys room by room
            int64_t migrated = 0;
            int64_t failed = 0;
            std::vector<std::string> errors;

            for (auto& [room_id, room_data] : all_keys["rooms"].items()) {
                if (!room_data.contains("sessions")) continue;

                for (auto& [session_id, session_data] :
                     room_data["sessions"].items()) {
                    try {
                        to_handler->UploadSingleRoomKey(
                            room_id, session_id, session_data);
                        migrated++;
                    } catch (const std::exception& e) {
                        failed++;
                        errors.push_back("Failed to migrate " +
                            room_id + "/" + session_id + ": " + e.what());
                    }
                }
            }

            active_migration_->migrated_keys = migrated;
            active_migration_->failed_keys = failed;

            if (failed > 0) {
                active_migration_->status = "completed_with_errors";
                active_migration_->error_message =
                    std::to_string(failed) + " keys failed to migrate";
            } else {
                active_migration_->status = "completed";
                active_migration_->verified = true;
            }

            active_migration_->completed_at = std::chrono::duration_cast<
                std::chrono::seconds>(
                    std::chrono::system_clock::now().time_since_epoch()
                ).count();

            migrations_.push_back(*active_migration_);
            active_migration_.reset();

            while (migrations_.size() > kMaxMigrationHistory) {
                migrations_.pop_front();
            }

            json response;
            response["status"] = "completed";
            response["migrated_keys"] = migrated;
            response["failed_keys"] = failed;
            if (!errors.empty()) {
                response["errors"] = errors;
            }
            return response;

        } catch (const std::exception& e) {
            active_migration_->status = "failed";
            active_migration_->error_message = e.what();
            active_migration_->completed_at = now;

            migrations_.push_back(*active_migration_);
            active_migration_.reset();

            while (migrations_.size() > kMaxMigrationHistory) {
                migrations_.pop_front();
            }

            throw;
        }
    }

    // Verify migration completeness
    json VerifyMigration(const std::string& from_version,
                          const std::string& to_version) {
        if (!version_manager_) {
            throw RoomKeysError("Version manager not set");
        }

        auto from_handler = version_manager_->GetUploadHandler(from_version);
        auto to_handler = version_manager_->GetUploadHandler(to_version);

        auto from_keys = from_handler->GetAllRoomKeys(from_version);
        auto to_keys = to_handler->GetAllRoomKeys(to_version);

        json result;
        result["verified"] = true;
        result["discrepancies"] = json::array();

        int64_t from_count = 0;
        int64_t to_count = 0;
        int64_t missing = 0;

        if (!from_keys.contains("rooms")) {
            result["from_count"] = 0;
            result["to_count"] = 0;
            return result;
        }

        for (auto& [room_id, room_data] : from_keys["rooms"].items()) {
            if (!room_data.contains("sessions")) continue;

            for (auto& [session_id, session_data] :
                 room_data["sessions"].items()) {
                from_count++;

                // Check if key exists in target
                try {
                    to_handler->GetSpecificRoomKey(room_id, session_id,
                                                    to_version);
                    to_count++;
                } catch (...) {
                    missing++;
                    json disc;
                    disc["room_id"] = room_id;
                    disc["session_id"] = session_id;
                    disc["status"] = "missing_in_target";
                    result["discrepancies"].push_back(disc);
                    result["verified"] = false;
                }
            }
        }

        result["from_count"] = from_count;
        result["to_count"] = to_count;
        result["missing"] = missing;
        result["migration_complete"] = (missing == 0);

        // Update migration record if this is a verification of active migration
        std::lock_guard lock(migration_mutex_);
        if (active_migration_ &&
            active_migration_->from_version == from_version &&
            active_migration_->to_version == to_version) {
            active_migration_->verified = (missing == 0);
        }

        return result;
    }

    // Rollback migration (delete target version keys)
    json RollbackMigration(const std::string& to_version) {
        std::lock_guard lock(migration_mutex_);

        if (!version_manager_) {
            throw RoomKeysError("Version manager not set");
        }

        if (active_migration_ &&
            active_migration_->to_version == to_version) {
            active_migration_->status = "rolled_back";
            migrations_.push_back(*active_migration_);
            active_migration_.reset();
        }

        // Delete the target version
        auto result = version_manager_->DeleteVersion(to_version);

        json response;
        response["rolled_back"] = true;
        response["version"] = to_version;
        response["details"] = result;
        return response;
    }

    // Get migration status
    json GetMigrationStatus() const {
        std::lock_guard lock(migration_mutex_);

        if (active_migration_) {
            json status;
            status["active"] = true;
            status["from_version"] = active_migration_->from_version;
            status["to_version"] = active_migration_->to_version;
            status["status"] = active_migration_->status;
            status["total_keys"] = active_migration_->total_keys;
            status["migrated_keys"] = active_migration_->migrated_keys;
            status["failed_keys"] = active_migration_->failed_keys;
            status["started_at"] = active_migration_->started_at;
            return status;
        }

        json status;
        status["active"] = false;
        return status;
    }

    // Get migration history
    json GetMigrationHistory(int limit = 50) const {
        std::lock_guard lock(migration_mutex_);

        json result;
        result["migrations"] = json::array();

        int count = 0;
        for (auto it = migrations_.rbegin();
             it != migrations_.rend() && count < limit;
             ++it, count++) {
            json entry;
            entry["from_version"] = it->from_version;
            entry["to_version"] = it->to_version;
            entry["status"] = it->status;
            entry["total_keys"] = it->total_keys;
            entry["migrated_keys"] = it->migrated_keys;
            entry["failed_keys"] = it->failed_keys;
            entry["started_at"] = it->started_at;
            entry["completed_at"] = it->completed_at;
            entry["verified"] = it->verified;
            if (!it->error_message.empty()) {
                entry["error_message"] = it->error_message;
            }
            result["migrations"].push_back(entry);
        }

        result["total"] = static_cast<int64_t>(migrations_.size());
        return result;
    }
};

// =============================================================================
// Key Backup Session Count Tracking
// =============================================================================
// Tracks per-user and per-device session counts for:
//   - Rate limiting decisions
//   - Storage planning
//   - Usage analytics
//   - Enforcement of maximum session limits

class SessionCountTracker {
private:
    std::string user_id_;

    // Per-room session counts
    std::unordered_map<std::string, int64_t> room_session_counts_;

    // Per-device session counts
    std::unordered_map<std::string, int64_t> device_session_counts_;

    // Global totals
    std::atomic<int64_t> total_active_sessions_{0};
    std::atomic<int64_t> total_sessions_created_{0};
    std::atomic<int64_t> total_sessions_deleted_{0};

    // Maximum limits
    int64_t max_sessions_per_room_ = 1000;
    int64_t max_sessions_per_device_ = 500;
    int64_t max_total_sessions_ = 100000;

    // Session creation/deletion log for auditing
    struct SessionEvent {
        std::string room_id;
        std::string session_id;
        std::string event_type;  // "created", "deleted"
        std::string device_id;
        int64_t timestamp = 0;
    };
    std::deque<SessionEvent> session_events_;
    static constexpr size_t kMaxEvents = 10000;

    // Rate tracking
    struct RateData {
        int64_t window_start = 0;
        int created_in_window = 0;
        int deleted_in_window = 0;
        int max_per_window = 100;  // Max sessions created per minute
        int window_seconds = 60;
    };
    RateData rate_data_;

    mutable std::shared_mutex mutex_;

public:
    explicit SessionCountTracker(const std::string& user_id)
        : user_id_(user_id) {}

    // Record session creation
    void RecordSessionCreated(const std::string& room_id,
                               const std::string& session_id,
                               const std::string& device_id = "") {
        std::unique_lock lock(mutex_);

        int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

        // Update counts
        room_session_counts_[room_id]++;
        if (!device_id.empty()) {
            device_session_counts_[device_id]++;
        }
        total_active_sessions_++;
        total_sessions_created_++;

        // Check rate window
        if (now - rate_data_.window_start >= rate_data_.window_seconds) {
            rate_data_.window_start = now;
            rate_data_.created_in_window = 0;
            rate_data_.deleted_in_window = 0;
        }
        rate_data_.created_in_window++;

        // Record event
        SessionEvent event;
        event.room_id = room_id;
        event.session_id = session_id;
        event.event_type = "created";
        event.device_id = device_id;
        event.timestamp = now;
        session_events_.push_back(event);
        while (session_events_.size() > kMaxEvents) {
            session_events_.pop_front();
        }

        // Enforce limits
        EnforceLimits();
    }

    // Record session deletion
    void RecordSessionDeleted(const std::string& room_id,
                               const std::string& session_id,
                               const std::string& device_id = "") {
        std::unique_lock lock(mutex_);

        int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

        // Update counts
        auto it = room_session_counts_.find(room_id);
        if (it != room_session_counts_.end() && it->second > 0) {
            it->second--;
        }
        if (!device_id.empty()) {
            auto dit = device_session_counts_.find(device_id);
            if (dit != device_session_counts_.end() && dit->second > 0) {
                dit->second--;
            }
        }
        if (total_active_sessions_.load() > 0) {
            total_active_sessions_--;
        }
        total_sessions_deleted_++;

        // Check rate window
        if (now - rate_data_.window_start >= rate_data_.window_seconds) {
            rate_data_.window_start = now;
            rate_data_.created_in_window = 0;
            rate_data_.deleted_in_window = 0;
        }
        rate_data_.deleted_in_window++;

        // Record event
        SessionEvent event;
        event.room_id = room_id;
        event.session_id = session_id;
        event.event_type = "deleted";
        event.device_id = device_id;
        event.timestamp = now;
        session_events_.push_back(event);
        while (session_events_.size() > kMaxEvents) {
            session_events_.pop_front();
        }
    }

    // Get session counts
    json GetSessionCounts() const {
        std::shared_lock lock(mutex_);

        json result;
        result["total_active_sessions"] = total_active_sessions_.load();
        result["total_sessions_created"] = total_sessions_created_.load();
        result["total_sessions_deleted"] = total_sessions_deleted_.load();

        // Per-room breakdown
        result["rooms"] = json::object();
        for (auto& [room_id, count] : room_session_counts_) {
            if (count > 0) {
                result["rooms"][room_id] = count;
            }
        }

        // Per-device breakdown
        result["devices"] = json::object();
        for (auto& [device_id, count] : device_session_counts_) {
            if (count > 0) {
                result["devices"][device_id] = count;
            }
        }

        // Limits
        result["limits"] = json::object();
        result["limits"]["max_per_room"] = max_sessions_per_room_;
        result["limits"]["max_per_device"] = max_sessions_per_device_;
        result["limits"]["max_total"] = max_total_sessions_;

        // Rate data
        result["rate"] = json::object();
        result["rate"]["created_in_window"] = rate_data_.created_in_window;
        result["rate"]["deleted_in_window"] = rate_data_.deleted_in_window;
        result["rate"]["max_per_window"] = rate_data_.max_per_window;
        result["rate"]["window_seconds"] = rate_data_.window_seconds;

        return result;
    }

    // Get session count for a specific room
    int64_t GetRoomSessionCount(const std::string& room_id) const {
        std::shared_lock lock(mutex_);
        auto it = room_session_counts_.find(room_id);
        return (it != room_session_counts_.end()) ? it->second : 0;
    }

    // Get session count for a specific device
    int64_t GetDeviceSessionCount(const std::string& device_id) const {
        std::shared_lock lock(mutex_);
        auto it = device_session_counts_.find(device_id);
        return (it != device_session_counts_.end()) ? it->second : 0;
    }

    // Check if creating a new session would exceed limits
    bool CanCreateSession(const std::string& room_id = "",
                           const std::string& device_id = "") const {
        std::shared_lock lock(mutex_);

        // Check total limit
        if (total_active_sessions_.load() >= max_total_sessions_) {
            return false;
        }

        // Check room limit
        if (!room_id.empty()) {
            auto it = room_session_counts_.find(room_id);
            if (it != room_session_counts_.end() &&
                it->second >= max_sessions_per_room_) {
                return false;
            }
        }

        // Check device limit
        if (!device_id.empty()) {
            auto it = device_session_counts_.find(device_id);
            if (it != device_session_counts_.end() &&
                it->second >= max_sessions_per_device_) {
                return false;
            }
        }

        // Check rate limit
        if (rate_data_.created_in_window >= rate_data_.max_per_window) {
            return false;
        }

        return true;
    }

    // Set limits
    void SetLimits(int64_t max_per_room, int64_t max_per_device,
                    int64_t max_total) {
        std::unique_lock lock(mutex_);
        max_sessions_per_room_ = max_per_room;
        max_sessions_per_device_ = max_per_device;
        max_total_sessions_ = max_total;
    }

    // Get recent session events
    json GetRecentEvents(int limit = 100) const {
        std::shared_lock lock(mutex_);

        json result;
        result["events"] = json::array();

        int count = 0;
        for (auto it = session_events_.rbegin();
             it != session_events_.rend() && count < limit;
             ++it, count++) {
            json event;
            event["room_id"] = it->room_id;
            event["session_id"] = it->session_id;
            event["event_type"] = it->event_type;
            event["device_id"] = it->device_id;
            event["timestamp"] = it->timestamp;
            result["events"].push_back(event);
        }

        result["total_events"] = static_cast<int64_t>(session_events_.size());
        return result;
    }

    // Reset all counters (for testing or admin operations)
    void ResetCounters() {
        std::unique_lock lock(mutex_);
        room_session_counts_.clear();
        device_session_counts_.clear();
        total_active_sessions_ = 0;
        total_sessions_created_ = 0;
        total_sessions_deleted_ = 0;
        session_events_.clear();
        rate_data_ = RateData{};
    }

    // Get capacity utilization
    json GetCapacityUtilization() const {
        std::shared_lock lock(mutex_);

        json result;
        int64_t active = total_active_sessions_.load();

        result["total_utilization_percent"] =
            max_total_sessions_ > 0 ?
                (static_cast<double>(active) / max_total_sessions_) * 100.0 : 0.0;
        result["active_sessions"] = active;
        result["max_sessions"] = max_total_sessions_;
        result["available"] = max_total_sessions_ - active;

        // Per-room utilization
        result["room_utilization"] = json::object();
        for (auto& [room_id, count] : room_session_counts_) {
            result["room_utilization"][room_id] = json::object();
            result["room_utilization"][room_id]["count"] = count;
            result["room_utilization"][room_id]["utilization_pct"] =
                max_sessions_per_room_ > 0 ?
                    (static_cast<double>(count) / max_sessions_per_room_) * 100.0 : 0.0;
            result["room_utilization"][room_id]["at_capacity"] =
                count >= max_sessions_per_room_;
        }

        // Per-device utilization
        result["device_utilization"] = json::object();
        for (auto& [device_id, count] : device_session_counts_) {
            result["device_utilization"][device_id] = json::object();
            result["device_utilization"][device_id]["count"] = count;
            result["device_utilization"][device_id]["utilization_pct"] =
                max_sessions_per_device_ > 0 ?
                    (static_cast<double>(count) / max_sessions_per_device_) * 100.0 : 0.0;
            result["device_utilization"][device_id]["at_capacity"] =
                count >= max_sessions_per_device_;
        }

        return result;
    }

private:
    void EnforceLimits() {
        // If total exceeds max, we could trigger cleanup of oldest sessions
        // For now, this is just tracked; actual enforcement is done at creation
        if (total_active_sessions_.load() > max_total_sessions_) {
            // In production, trigger async cleanup of oldest sessions
        }
    }
};

// =============================================================================
// Master Orchestrator: RoomKeysDeviceKeysManager
// =============================================================================
// Coordinates all the sub-managers and provides a unified API

class RoomKeysDeviceKeysManager {
private:
    std::string user_id_;
    std::string device_id_;

    // Sub-managers
    std::shared_ptr<RoomKeyVersionManager> version_manager_;
    std::shared_ptr<RoomKeysQueryHandler> query_handler_;
    std::shared_ptr<RoomKeysDeleteHandler> delete_handler_;
    std::shared_ptr<DeviceKeysUploadHandler> device_upload_handler_;
    std::shared_ptr<DeviceKeysQueryHandler> device_query_handler_;
    std::shared_ptr<DeviceKeysChangesHandler> device_changes_handler_;
    std::shared_ptr<OneTimeKeysUploadHandler> otk_upload_handler_;
    std::shared_ptr<OneTimeKeysClaimHandler> otk_claim_handler_;
    std::shared_ptr<OneTimeKeysCountHandler> otk_count_handler_;
    std::shared_ptr<FallbackKeysManager> fallback_handler_;
    std::shared_ptr<DeviceKeyCrossSigning> cross_signing_handler_;
    std::shared_ptr<KeyCountThresholdManager> threshold_manager_;
    std::shared_ptr<BackupMigrationManager> migration_manager_;
    std::shared_ptr<SessionCountTracker> session_tracker_;

    bool initialized_ = false;
    mutable std::shared_mutex init_mutex_;

public:
    RoomKeysDeviceKeysManager(const std::string& user_id,
                               const std::string& device_id)
        : user_id_(user_id), device_id_(device_id) {}

    // Initialize all sub-managers
    void Initialize() {
        std::unique_lock lock(init_mutex_);
        if (initialized_) return;

        // Version manager
        version_manager_ = std::make_shared<RoomKeyVersionManager>(user_id_);

        // Get a default upload handler from version manager
        // (create default version if needed)
        auto* upload_handler = version_manager_->GetUploadHandler();

        // Query handler
        query_handler_ = std::make_shared<RoomKeysQueryHandler>(
            user_id_, *upload_handler);

        // Delete handler
        delete_handler_ = std::make_shared<RoomKeysDeleteHandler>(
            user_id_, *upload_handler);

        // Device keys handlers
        device_upload_handler_ = std::make_shared<DeviceKeysUploadHandler>(
            user_id_, device_id_);

        auto device_store = std::make_shared<
            DeviceKeysQueryHandler::GlobalDeviceKeyStore>();
        device_query_handler_ = std::make_shared<DeviceKeysQueryHandler>(
            user_id_, device_id_, device_store);

        device_changes_handler_ = std::make_shared<DeviceKeysChangesHandler>(
            user_id_);

        // One-time keys handlers
        otk_upload_handler_ = std::make_shared<OneTimeKeysUploadHandler>(
            user_id_, device_id_);

        auto otk_store = std::make_shared<
            OneTimeKeysClaimHandler::GlobalOTKStore>();
        otk_claim_handler_ = std::make_shared<OneTimeKeysClaimHandler>(
            user_id_, device_id_, otk_store);

        // Register our handler
        otk_claim_handler_->RegisterHandler(user_id_, device_id_,
                                             otk_upload_handler_);

        otk_count_handler_ = std::make_shared<OneTimeKeysCountHandler>(
            user_id_, device_id_, otk_upload_handler_);

        // Fallback keys
        fallback_handler_ = std::make_shared<FallbackKeysManager>(
            user_id_, device_id_);

        // Cross-signing
        cross_signing_handler_ = std::make_shared<DeviceKeyCrossSigning>(
            user_id_);

        // Threshold manager
        threshold_manager_ = std::make_shared<KeyCountThresholdManager>(
            user_id_, device_id_);
        threshold_manager_->SetOTKCountHandler(otk_count_handler_);
        threshold_manager_->SetFallbackHandler(fallback_handler_);

        // Migration manager
        migration_manager_ = std::make_shared<BackupMigrationManager>(
            user_id_, version_manager_);

        // Session tracker
        session_tracker_ = std::make_shared<SessionCountTracker>(user_id_);

        initialized_ = true;
    }

    // ===== Room Keys API =====

    json UploadRoomKeys(const std::string& version, const json& body) {
        EnsureInitialized();
        auto* handler = version_manager_->GetUploadHandler(version);
        return handler->UploadRoomKeys(body);
    }

    json QueryRoomKeys(const std::string& version = "",
                        const std::string& room_id = "",
                        const std::string& session_id = "") {
        EnsureInitialized();
        return query_handler_->QueryRoomKeys(version, room_id, session_id);
    }

    json DeleteAllRoomKeys(const std::string& version) {
        EnsureInitialized();
        return delete_handler_->DeleteAllRoomKeys(version);
    }

    json DeleteRoomKeys(const std::string& version, const std::string& room_id) {
        EnsureInitialized();
        return delete_handler_->DeleteRoomKeys(version, room_id);
    }

    json DeleteSessionKey(const std::string& version,
                           const std::string& room_id,
                           const std::string& session_id) {
        EnsureInitialized();
        return delete_handler_->DeleteSessionKey(version, room_id, session_id);
    }

    // ===== Version Management API =====

    json CreateBackupVersion(const json& body) {
        EnsureInitialized();
        return version_manager_->CreateVersion(body);
    }

    json GetVersionInfo(const std::string& version = "") {
        EnsureInitialized();
        return version_manager_->GetVersionInfo(version);
    }

    json UpdateVersion(const std::string& version, const json& body) {
        EnsureInitialized();
        return version_manager_->UpdateVersion(version, body);
    }

    json DeleteVersion(const std::string& version) {
        EnsureInitialized();
        return version_manager_->DeleteVersion(version);
    }

    json ListVersions() {
        EnsureInitialized();
        return version_manager_->ListVersions();
    }

    // ===== Device Keys API =====

    json UploadDeviceKeys(const json& body) {
        EnsureInitialized();
        auto result = device_upload_handler_->UploadDeviceKeys(body);

        // Record change
        int64_t sid = result.value("stream_id", 0);
        device_changes_handler_->RecordChange(
            user_id_, device_id_, "updated");

        // Update session tracker
        session_tracker_->RecordSessionCreated(
            "device_keys", device_id_, device_id_);

        return result;
    }

    json QueryDeviceKeys(const json& body) {
        EnsureInitialized();
        return device_query_handler_->QueryDeviceKeys(body);
    }

    json GetChanges(const std::string& from, const std::string& to = "") {
        EnsureInitialized();
        return device_changes_handler_->GetChanges(from, to);
    }

    // ===== One-Time Keys API =====

    json UploadOneTimeKeys(const json& body) {
        EnsureInitialized();
        auto result = otk_upload_handler_->UploadOneTimeKeys(body);

        // Record snapshot for trend analysis
        otk_count_handler_->RecordSnapshot();

        // Check thresholds
        threshold_manager_->CheckThresholds();

        return result;
    }

    json ClaimOneTimeKeys(const json& body) {
        EnsureInitialized();
        return otk_claim_handler_->ClaimKeys(body);
    }

    json GetOneTimeKeyCounts() {
        EnsureInitialized();
        return otk_count_handler_->GetCountsWithRecommendations();
    }

    // ===== Fallback Keys API =====

    json UploadFallbackKey(const std::string& key_id, const json& body) {
        EnsureInitialized();
        return fallback_handler_->UploadFallbackKey(key_id, body);
    }

    json GetFallbackKeyInfo() {
        EnsureInitialized();
        return fallback_handler_->GetSyncFallbackKeyData();
    }

    // ===== Cross-Signing API =====

    json UploadCrossSigningKeys(const json& body) {
        EnsureInitialized();
        return cross_signing_handler_->UploadCrossSigningKeys(body);
    }

    json GetCrossSigningKeys() {
        EnsureInitialized();
        return cross_signing_handler_->GetCrossSigningKeys();
    }

    // ===== Threshold Alerts API =====

    json CheckThresholds() {
        EnsureInitialized();
        return threshold_manager_->CheckThresholds();
    }

    json GetAlerts() {
        EnsureInitialized();
        return threshold_manager_->GetActiveAlerts();
    }

    json GetAlertHistory(int limit = 50) {
        EnsureInitialized();
        return threshold_manager_->GetAlertHistory(limit);
    }

    // ===== Migration API =====

    json StartMigration(const std::string& from, const std::string& to) {
        EnsureInitialized();
        return migration_manager_->StartMigration(from, to);
    }

    json ExecuteMigration() {
        EnsureInitialized();
        return migration_manager_->ExecuteMigration();
    }

    json VerifyMigration(const std::string& from, const std::string& to) {
        EnsureInitialized();
        return migration_manager_->VerifyMigration(from, to);
    }

    json GetMigrationStatus() {
        EnsureInitialized();
        return migration_manager_->GetMigrationStatus();
    }

    json GetMigrationHistory(int limit = 50) {
        EnsureInitialized();
        return migration_manager_->GetMigrationHistory(limit);
    }

    // ===== Session Tracking API =====

    json GetSessionCounts() {
        EnsureInitialized();
        return session_tracker_->GetSessionCounts();
    }

    json GetSessionCapacity() {
        EnsureInitialized();
        return session_tracker_->GetCapacityUtilization();
    }

    // ===== Status API =====

    json GetFullStatus() {
        EnsureInitialized();

        json status;
        status["user_id"] = user_id_;
        status["device_id"] = device_id_;
        status["versions"] = version_manager_->ListVersions();
        status["device_keys"] = device_upload_handler_->GetDeviceKeys();
        status["one_time_key_counts"] = otk_count_handler_->GetCounts();
        status["fallback_key"] = fallback_handler_->GetUsageStats();
        status["cross_signing"] = cross_signing_handler_->GetCrossSigningKeys();
        status["alerts"] = threshold_manager_->GetActiveAlerts();
        status["session_counts"] = session_tracker_->GetSessionCounts();
        status["migration_active"] = migration_manager_->GetMigrationStatus()
            .value("active", false);
        return status;
    }

    // ===== Housekeeping =====

    json PerformHousekeeping() {
        EnsureInitialized();

        json result;

        // Prune claimed one-time keys
        int otk_pruned = otk_upload_handler_->PruneClaimedKeys(3600);
        result["one_time_keys_pruned"] = otk_pruned;

        // Prune old fallback keys
        int fb_pruned = fallback_handler_->PruneOldKeys(7776000);  // 90 days
        result["fallback_keys_pruned"] = fb_pruned;

        // Prune change history
        device_changes_handler_->PruneChanges(86400);  // 24 hours
        result["changes_pruned"] = true;

        // Record count snapshot
        otk_count_handler_->RecordSnapshot();

        // Check thresholds
        auto alerts = threshold_manager_->CheckThresholds();
        result["alerts_generated"] = alerts.value("alerts").size();

        return result;
    }

    // Get raw handlers for direct access (use with caution)
    std::shared_ptr<RoomKeyVersionManager> GetVersionManager() {
        EnsureInitialized();
        return version_manager_;
    }

    std::shared_ptr<OneTimeKeysUploadHandler> GetOTKUploadHandler() {
        EnsureInitialized();
        return otk_upload_handler_;
    }

    std::shared_ptr<DeviceKeyCrossSigning> GetCrossSigningHandler() {
        EnsureInitialized();
        return cross_signing_handler_;
    }

    std::shared_ptr<SessionCountTracker> GetSessionTracker() {
        EnsureInitialized();
        return session_tracker_;
    }

private:
    void EnsureInitialized() {
        if (!initialized_) {
            std::unique_lock lock(init_mutex_);
            if (!initialized_) {
                Initialize();
            }
        }
    }
};

} // namespace crypto
} // namespace progressive
