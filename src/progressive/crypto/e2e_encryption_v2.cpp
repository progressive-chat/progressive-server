// progressive-server: Matrix End-to-End Encryption (Olm/Megolm)
// Reference: Synapse e2e_room_keys.py, synapse/crypto/event_signing.py (4,200+ lines)

#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <memory>
#include <optional>
#include <ctime>
#include <algorithm>
#include <sstream>
#include <atomic>
#include <mutex>
#include <functional>
#include <deque>
#include <cstring>
#include "../json.hpp"

namespace progressive {
namespace crypto {

using json = nlohmann::json;

// =============================================================================
// Olm and Megolm session types
// =============================================================================
struct OlmSessionData {
    std::string session_id;
    std::string sender_key;
    std::string chain_index;
    std::string message_index;
    bool shared = false;
    time_t created_at = 0;
    time_t last_used = 0;
};

struct MegolmSessionData {
    std::string session_id;
    std::string room_id;
    std::string sender_key;
    std::string algorithm = "m.megolm.v1.aes-sha2";
    std::string session_key;
    int message_index = 0;
    bool shared = false;
    bool verified = false;
    time_t created_at = 0;
    time_t last_used = 0;
    std::vector<std::string> devices; // devices this session is shared with
    int rotation_period_ms = 604800000;
    int rotation_period_msgs = 100;
};

struct DeviceKeys {
    std::string user_id;
    std::string device_id;
    std::string algorithm;
    std::string curve25519_key;  // identity key
    std::string ed25519_key;     // signing key
    std::string signed_json;
};

struct OneTimeKey {
    std::string user_id;
    std::string device_id;
    std::string key_id;
    std::string key;
    std::string signature;
};

// =============================================================================
// Key store
// =============================================================================
class CryptoStore {
public:
    // Device keys
    void store_device_keys(const std::string& user_id, const std::string& device_id,
                           const DeviceKeys& keys) {
        std::lock_guard lock(mutex_);
        device_keys_[user_id][device_id] = keys;
    }

    std::optional<DeviceKeys> get_device_keys(const std::string& user_id,
                                               const std::string& device_id) {
        auto it = device_keys_.find(user_id);
        if (it == device_keys_.end()) return std::nullopt;
        auto dit = it->second.find(device_id);
        if (dit == it->second.end()) return std::nullopt;
        return dit->second;
    }

    void mark_device_deleted(const std::string& user_id, const std::string& device_id) {
        std::lock_guard lock(mutex_);
        deleted_devices_.insert(user_id + ":" + device_id);
    }

    bool is_device_deleted(const std::string& user_id, const std::string& device_id) {
        return deleted_devices_.count(user_id + ":" + device_id) > 0;
    }

    // One-time keys
    void store_one_time_key(const std::string& user_id, const std::string& device_id,
                            const OneTimeKey& key) {
        std::lock_guard lock(mutex_);
        one_time_keys_[user_id + ":" + device_id][key.key_id] = key;
    }

    std::optional<OneTimeKey> claim_one_time_key(const std::string& user_id,
                                                  const std::string& device_id) {
        std::lock_guard lock(mutex_);
        auto it = one_time_keys_.find(user_id + ":" + device_id);
        if (it == one_time_keys_.end() || it->second.empty()) return std::nullopt;
        // Take the first available key
        auto key = it->second.begin()->second;
        it->second.erase(it->second.begin());
        return key;
    }

    int count_one_time_keys(const std::string& user_id, const std::string& device_id) {
        auto it = one_time_keys_.find(user_id + ":" + device_id);
        if (it == one_time_keys_.end()) return 0;
        return (int)it->second.size();
    }

    // Olm sessions
    void store_olm_session(const OlmSessionData& session) {
        std::lock_guard lock(mutex_);
        olm_sessions_[session.session_id] = session;
    }

    std::optional<OlmSessionData> get_olm_session(const std::string& session_id) {
        auto it = olm_sessions_.find(session_id);
        return (it != olm_sessions_.end()) ? std::optional(it->second) : std::nullopt;
    }

    // Megolm sessions (inbound)
    void store_megolm_inbound(const MegolmSessionData& session) {
        std::lock_guard lock(mutex_);
        megolm_inbound_[session.session_id] = session;
        room_sessions_[session.room_id].push_back(session.session_id);
    }

    std::optional<MegolmSessionData> get_megolm_inbound(const std::string& session_id) {
        auto it = megolm_inbound_.find(session_id);
        return (it != megolm_inbound_.end()) ? std::optional(it->second) : std::nullopt;
    }

    std::vector<MegolmSessionData> get_room_sessions(const std::string& room_id) {
        std::vector<MegolmSessionData> result;
        auto it = room_sessions_.find(room_id);
        if (it == room_sessions_.end()) return result;
        for (auto& sid : it->second) {
            auto sit = megolm_inbound_.find(sid);
            if (sit != megolm_inbound_.end()) result.push_back(sit->second);
        }
        return result;
    }

    // Megolm sessions (outbound) - sessions WE created
    void store_megolm_outbound(const std::string& room_id, const MegolmSessionData& session) {
        std::lock_guard lock(mutex_);
        megolm_outbound_[room_id] = session;
    }

    std::optional<MegolmSessionData> get_megolm_outbound(const std::string& room_id) {
        auto it = megolm_outbound_.find(room_id);
        return (it != megolm_outbound_.end()) ? std::optional(it->second) : std::nullopt;
    }

    // Room key backup
    void store_room_key_backup(const std::string& room_id, const std::string& session_id,
                                const json& key_data) {
        std::lock_guard lock(mutex_);
        key_backup_[room_id][session_id] = key_data;
    }

    json get_key_backup(const std::string& room_id, const std::string& session_id,
                        const std::string& version = "") {
        auto it = key_backup_.find(room_id);
        if (it == key_backup_.end()) return json();
        auto sit = it->second.find(session_id);
        return (sit != it->second.end()) ? sit->second : json();
    }

    std::unordered_map<std::string, json> get_all_key_backups(const std::string& room_id) {
        auto it = key_backup_.find(room_id);
        return (it != key_backup_.end()) ? it->second : std::unordered_map<std::string, json>{};
    }

private:
    std::unordered_map<std::string, std::unordered_map<std::string, DeviceKeys>> device_keys_;
    std::unordered_set<std::string> deleted_devices_;
    std::unordered_map<std::string, std::unordered_map<std::string, OneTimeKey>> one_time_keys_;
    std::unordered_map<std::string, OlmSessionData> olm_sessions_;
    std::unordered_map<std::string, MegolmSessionData> megolm_inbound_;
    std::unordered_map<std::string, std::vector<std::string>> room_sessions_; // room_id -> [session_id]
    std::unordered_map<std::string, MegolmSessionData> megolm_outbound_;
    std::unordered_map<std::string, std::unordered_map<std::string, json>> key_backup_;
    std::mutex mutex_;
};

// =============================================================================
// Key upload and query
// =============================================================================
class KeyUploadManager {
public:
    KeyUploadManager(CryptoStore& store) : store_(store) {}

    json upload_device_keys(const std::string& user_id, const std::string& device_id,
                             const DeviceKeys& keys) {
        store_.store_device_keys(user_id, device_id, keys);

        json result;
        result["device_id"] = device_id;
        result["user_id"] = user_id;
        result["algorithms"] = json::array({
            "m.olm.v1.curve25519-aes-sha2",
            "m.megolm.v1.aes-sha2"
        });
        result["keys"]["curve25519:" + device_id] = keys.curve25519_key;
        result["keys"]["ed25519:" + device_id] = keys.ed25519_key;
        result["signatures"][user_id]["ed25519:" + device_id] = "signature_placeholder";
        return result;
    }

    json upload_one_time_keys(const std::string& user_id, const std::string& device_id,
                               const std::unordered_map<std::string, std::string>& keys) {
        json counts;
        for (auto& [key_id, key_value] : keys) {
            OneTimeKey otk;
            otk.user_id = user_id;
            otk.device_id = device_id;
            otk.key_id = key_id;
            otk.key = key_value;
            store_.store_one_time_key(user_id, device_id, otk);

            std::string algo = key_id.find("signed_curve25519") != std::string::npos
                             ? "signed_curve25519" : "curve25519";
            if (counts.contains(algo)) {
                counts[algo] = counts[algo].get<int>() + 1;
            } else {
                counts[algo] = 1;
            }
        }
        return counts; // one_time_key_counts
    }

    json query_device_keys(const std::string& user_id,
                            const std::unordered_map<std::string, std::vector<std::string>>& query) {
        json result;
        for (auto& [target_user, device_ids] : query) {
            if (device_ids.empty()) {
                // Return all known devices for this user
                // but actually we should discover devices via device_lists
            }
            for (auto& device_id : device_ids) {
                auto keys = store_.get_device_keys(target_user, device_id);
                if (keys) {
                    result[target_user][device_id] = keys_to_json(*keys);
                }
            }
        }
        // Store failures for users we couldn't reach
        json failures;
        result["failures"] = failures;
        return result;
    }

    json claim_one_time_keys(const std::unordered_map<std::string,
                              std::unordered_map<std::string, std::string>>& query) {
        json result;
        for (auto& [user_id, device_keys] : query) {
            for (auto& [device_id, algorithm] : device_keys) {
                auto key = store_.claim_one_time_key(user_id, device_id);
                if (key) {
                    json key_json;
                    key_json[key->key_id] = key->key;
                    result[user_id][device_id] = key_json;
                }
            }
        }
        return result;
    }

private:
    CryptoStore& store_;

    static json keys_to_json(const DeviceKeys& keys) {
        json j;
        j["user_id"] = keys.user_id;
        j["device_id"] = keys.device_id;
        j["algorithms"] = json::array({
            "m.olm.v1.curve25519-aes-sha2",
            "m.megolm.v1.aes-sha2"
        });
        j["keys"]["curve25519:" + keys.device_id] = keys.curve25519_key;
        j["keys"]["ed25519:" + keys.device_id] = keys.ed25519_key;
        j["signatures"][keys.user_id]["ed25519:" + keys.device_id] = keys.signed_json;
        return j;
    }
};

// =============================================================================
// Megolm group session manager
// =============================================================================
class MegolmManager {
public:
    MegolmManager(CryptoStore& store) : store_(store) {}

    MegolmSessionData create_outbound_session(const std::string& room_id,
                                               const std::string& sender_key) {
        MegolmSessionData session;
        session.session_id = generate_session_id();
        session.room_id = room_id;
        session.sender_key = sender_key;
        session.message_index = 0;
        session.shared = false;
        session.created_at = std::time(nullptr);

        store_.store_megolm_outbound(room_id, session);
        return session;
    }

    void share_session(const std::string& room_id, const std::string& session_id,
                       const std::vector<std::string>& device_list) {
        auto session = store_.get_megolm_outbound(room_id);
        if (!session) return;

        // Create m.room_key to_device event for each device
        json content;
        content["room_id"] = room_id;
        content["session_id"] = session_id;
        content["session_key"] = session->session_key;
        content["algorithm"] = session->algorithm;
        content["chain_index"] = 0;

        for (auto& device_id : device_list) {
            json key_event;
            key_event["type"] = "m.room_key";
            key_event["content"] = content;
            // These would be encrypted with Olm and sent via /sendToDevice
        }

        session->shared = true;
        session->devices = device_list;
        store_.store_megolm_outbound(room_id, *session);
    }

    // Rotate session when it expires
    void maybe_rotate_session(const std::string& room_id, const std::string& sender_key) {
        auto session = store_.get_megolm_outbound(room_id);
        if (!session) return;

        bool should_rotate = false;
        if (session->rotation_period_msgs > 0 &&
            session->message_index >= session->rotation_period_msgs) {
            should_rotate = true;
        }
        if (session->rotation_period_ms > 0) {
            time_t now = std::time(nullptr);
            time_t created = session->created_at;
            if ((now - created) * 1000 > session->rotation_period_ms) {
                should_rotate = true;
            }
        }

        if (should_rotate) {
            create_outbound_session(room_id, sender_key);
        }
    }

    void receive_room_key(const std::string& room_id, const std::string& session_id,
                          const std::string& session_key, const std::string& sender_key) {
        MegolmSessionData session;
        session.session_id = session_id;
        session.room_id = room_id;
        session.sender_key = sender_key;
        session.session_key = session_key;
        session.created_at = std::time(nullptr);
        session.shared = true;

        store_.store_megolm_inbound(session);
    }

    int get_message_index(const std::string& room_id) {
        auto session = store_.get_megolm_outbound(room_id);
        if (!session) return 0;
        return session->message_index++;
    }

private:
    CryptoStore& store_;

    static std::string generate_session_id() {
        static std::atomic<uint64_t> c{0};
        return "megolm_" + std::to_string(c.fetch_add(1));
    }
};

// =============================================================================
// Device list tracking
// =============================================================================
class DeviceListTracker {
public:
    void mark_device_changed(const std::string& user_id) {
        std::lock_guard lock(mutex_);
        changed_users_.insert(user_id);
        change_timestamps_[user_id] = std::time(nullptr);
    }

    void mark_device_left(const std::string& user_id) {
        std::lock_guard lock(mutex_);
        left_users_.insert(user_id);
        left_timestamps_[user_id] = std::time(nullptr);
    }

    std::vector<std::string> get_changed_since(const std::string& user_id, int64_t since_token) {
        std::vector<std::string> result;
        for (auto& [changed_user, ts] : change_timestamps_) {
            if (ts > since_token) result.push_back(changed_user);
        }
        return result;
    }

    std::vector<std::string> get_left_since(const std::string& user_id, int64_t since_token) {
        std::vector<std::string> result;
        for (auto& [left_user, ts] : left_timestamps_) {
            if (ts > since_token) result.push_back(left_user);
        }
        return result;
    }

    bool has_pending_changes(const std::string& user_id) {
        return changed_users_.count(user_id) > 0 || left_users_.count(user_id) > 0;
    }

private:
    std::unordered_set<std::string> changed_users_;
    std::unordered_set<std::string> left_users_;
    std::unordered_map<std::string, time_t> change_timestamps_;
    std::unordered_map<std::string, time_t> left_timestamps_;
    std::mutex mutex_;
};

// =============================================================================
// Key verification (to_device, SAS, QR)
// =============================================================================
enum class VerificationMethod : uint8_t {
    SAS,        // Short Authentication String
    QR_CODE,    // QR code scan
    QR_SHOW,    // QR code display
    RECIPROCATE,
};

struct VerificationRequest {
    std::string transaction_id;
    std::string from_device;
    std::string to_user;
    std::string to_device;
    VerificationMethod method = VerificationMethod::SAS;
    time_t created_at = 0;
    bool accepted = false;
    bool done = false;
    bool cancelled = false;
    std::string cancel_reason;
};

class KeyVerification {
public:
    std::string start_verification(const std::string& from_device,
                                    const std::string& to_user,
                                    const std::string& to_device,
                                    const std::vector<std::string>& methods) {
        std::string txn_id = generate_transaction_id();
        VerificationRequest req;
        req.transaction_id = txn_id;
        req.from_device = from_device;
        req.to_user = to_user;
        req.to_device = to_device;
        req.created_at = std::time(nullptr);

        // Determine best method
        for (auto& m : methods) {
            if (m == "m.sas.v1") req.method = VerificationMethod::SAS;
            if (m == "m.qr_code.scan.v1") req.method = VerificationMethod::QR_CODE;
            if (m == "m.qr_code.show.v1") req.method = VerificationMethod::QR_SHOW;
        }

        std::lock_guard lock(mutex_);
        pending_[txn_id] = req;

        // Build verification start event
        json content;
        content["from_device"] = from_device;
        content["transaction_id"] = txn_id;
        content["method"] = method_to_string(req.method);
        if (!methods.empty()) content["methods"] = methods;

        return txn_id;
    }

    bool accept_verification(const std::string& txn_id) {
        std::lock_guard lock(mutex_);
        auto it = pending_.find(txn_id);
        if (it == pending_.end()) return false;
        it->second.accepted = true;

        // Build key_verification_accept event
        return true;
    }

    bool cancel_verification(const std::string& txn_id, const std::string& reason) {
        std::lock_guard lock(mutex_);
        auto it = pending_.find(txn_id);
        if (it == pending_.end()) return false;
        it->second.cancelled = true;
        it->second.cancel_reason = reason;
        return true;
    }

    bool complete_verification(const std::string& txn_id) {
        std::lock_guard lock(mutex_);
        auto it = pending_.find(txn_id);
        if (it == pending_.end()) return false;
        it->second.done = true;
        pending_.erase(it);
        return true;
    }

    const VerificationRequest* get_request(const std::string& txn_id) {
        auto it = pending_.find(txn_id);
        return (it != pending_.end()) ? &it->second : nullptr;
    }

    // SAS decimal or emoji comparison
    std::string compute_sas_decimal(const std::string& shared_secret) {
        // Compute 3 decimal SAS codes
        // In real implementation: HKDF then compare
        return "123 456 789";
    }

    std::vector<std::string> compute_sas_emoji(const std::string& shared_secret) {
        return {"🐶", "🐱", "🐭", "🐹", "🐰", "🦊", "🐻"};
    }

private:
    std::unordered_map<std::string, VerificationRequest> pending_;
    std::mutex mutex_;

    static std::string generate_transaction_id() {
        return "verify_" + std::to_string(std::time(nullptr));
    }

    static std::string method_to_string(VerificationMethod m) {
        switch (m) {
        case VerificationMethod::SAS: return "m.sas.v1";
        case VerificationMethod::QR_CODE: return "m.qr_code.scan.v1";
        case VerificationMethod::QR_SHOW: return "m.qr_code.show.v1";
        case VerificationMethod::RECIPROCATE: return "m.reciprocate.v1";
        default: return "m.sas.v1";
        }
    }
};

// =============================================================================
// Room key backup (server-side key backup)
// =============================================================================
struct KeyBackupVersion {
    std::string version;
    std::string algorithm = "m.megolm_backup.v1.curve25519-aes-sha2";
    std::string auth_data; // JSON: public_key, signatures, etc.
    int count = 0;
    std::string etag;
    time_t created_at = 0;
};

class KeyBackupManager {
public:
    KeyBackupManager(CryptoStore& store) : store_(store) {}

    KeyBackupVersion create_backup_version(const std::string& algorithm,
                                            const json& auth_data) {
        KeyBackupVersion version;
        version.version = std::to_string(std::time(nullptr));
        version.algorithm = algorithm;
        version.auth_data = auth_data.dump();
        version.created_at = std::time(nullptr);

        std::lock_guard lock(mutex_);
        backup_versions_[version.version] = version;
        current_version_ = version.version;

        return version;
    }

    json get_backup_info(const std::string& version = "") {
        std::string ver = version.empty() ? current_version_ : version;
        auto it = backup_versions_.find(ver);
        if (it == backup_versions_.end()) {
            return {{"errcode", "M_NOT_FOUND"}, {"error", "No backup version"}};
        }
        return {
            {"algorithm", it->second.algorithm},
            {"auth_data", json::parse(it->second.auth_data)},
            {"count", it->second.count},
            {"etag", it->second.etag},
            {"version", it->second.version}
        };
    }

    json backup_room_keys(const std::string& version,
                           const std::unordered_map<std::string, json>& rooms) {
        for (auto& [room_id, sessions] : rooms) {
            for (auto& [session_id, key_data] : sessions.items()) {
                store_.store_room_key_backup(room_id, session_id, key_data);
                auto it = backup_versions_.find(version);
                if (it != backup_versions_.end()) it->second.count++;
            }
        }
        return {{"etag", "etag_" + std::to_string(std::time(nullptr))}, {"count", 0}};
    }

    json get_room_keys(const std::string& version, const std::string& room_id = "",
                        const std::string& session_id = "") {
        if (room_id.empty()) {
            json result;
            // Return all rooms
            return {{"rooms", json::object()}};
        }
        if (session_id.empty()) {
            json result;
            result[room_id] = json::object();
            auto backups = store_.get_all_key_backups(room_id);
            for (auto& [sid, data] : backups) {
                result[room_id][sid] = data;
            }
            return {{"rooms", result}};
        }
        auto key = store_.get_key_backup(room_id, session_id);
        json result;
        result[room_id] = json::object();
        result[room_id][session_id] = key;
        return {{"rooms", result}};
    }

    bool delete_backup(const std::string& version) {
        return backup_versions_.erase(version) > 0;
    }

private:
    CryptoStore& store_;
    std::unordered_map<std::string, KeyBackupVersion> backup_versions_;
    std::string current_version_;
    std::mutex mutex_;
};

// =============================================================================
// Cross-signing keys (master, self-signing, user-signing)
// =============================================================================
struct CrossSigningKey {
    std::string user_id;
    std::string key_type; // "master", "self_signing", "user_signing"
    std::string public_key;
    std::string signature;
    json signatures;
};

class CrossSigningManager {
public:
    void store_master_key(const std::string& user_id, const json& key_data) {
        std::lock_guard lock(mutex_);
        master_keys_[user_id] = key_data.dump();
    }

    void store_self_signing_key(const std::string& user_id, const json& key_data) {
        std::lock_guard lock(mutex_);
        self_signing_keys_[user_id] = key_data.dump();
    }

    void store_user_signing_key(const std::string& user_id, const json& key_data) {
        std::lock_guard lock(mutex_);
        user_signing_keys_[user_id] = key_data.dump();
    }

    json get_master_key(const std::string& user_id) {
        auto it = master_keys_.find(user_id);
        return (it != master_keys_.end()) ? json::parse(it->second) : json();
    }

    json get_self_signing_key(const std::string& user_id) {
        auto it = self_signing_keys_.find(user_id);
        return (it != self_signing_keys_.end()) ? json::parse(it->second) : json();
    }

    json get_user_signing_key(const std::string& user_id) {
        auto it = user_signing_keys_.find(user_id);
        return (it != user_signing_keys_.end()) ? json::parse(it->second) : json();
    }

private:
    std::unordered_map<std::string, std::string> master_keys_;
    std::unordered_map<std::string, std::string> self_signing_keys_;
    std::unordered_map<std::string, std::string> user_signing_keys_;
    std::mutex mutex_;
};

// =============================================================================
// Secrets handling (cross-signing key sharing via SSSS)
// =============================================================================
struct Secret {
    std::string name;   // "m.cross_signing.master", etc.
    std::string content;
    std::string key_id;
};

class SecretsManager {
public:
    void store_secret(const std::string& user_id, const Secret& secret) {
        std::lock_guard lock(mutex_);
        secrets_[user_id][secret.name] = secret.content;
    }

    std::optional<std::string> get_secret(const std::string& user_id,
                                           const std::string& name) {
        auto it = secrets_.find(user_id);
        if (it == secrets_.end()) return std::nullopt;
        auto sit = it->second.find(name);
        if (sit == it->second.end()) return std::nullopt;
        return sit->second;
    }

    void delete_secret(const std::string& user_id, const std::string& name) {
        auto it = secrets_.find(user_id);
        if (it != secrets_.end()) it->second.erase(name);
    }

    // Send secret to a device
    json send_secret(const std::string& user_id, const std::string& device_id,
                     const std::string& secret_name) {
        auto secret = get_secret(user_id, secret_name);
        if (!secret) return json();
        // Build m.secret.send to_device event
        json event;
        event["type"] = "m.secret.send";
        event["content"]["name"] = secret_name;
        event["content"]["secret"] = *secret;
        return event;
    }

private:
    std::unordered_map<std::string, std::unordered_map<std::string, std::string>> secrets_;
    std::mutex mutex_;
};

} // namespace crypto
} // namespace progressive
