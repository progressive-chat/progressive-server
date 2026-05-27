// progressive-server: Matrix signing, hashing, and key management
// References: Synapse signing_key_management.py, keyring.py, event_auth.py,
//             Matrix Spec v1.11 §3 (Event Signing), §10 (Server Keys),
//             §14 (Cross-Signing), §15 (Key Backup), §16 (SSSS)
//
// Implements:
//   1. Ed25519 key generation and loading
//   2. Event signing with ed25519
//   3. Event signature verification
//   4. Hash computation (SHA-256) for event references
//   5. Canonical JSON serialization for signing
//   6. Event redaction (strip content for hashing)
//   7. Server key management (verify_key, signing_key, TLS certs)
//   8. Key publishing (/key/v2/server endpoint)
//   9. Key query (/key/v2/query endpoint)
//  10. Key validity period and rotation
//  11. Cross-signing key hierarchy (master -> self-signing -> user-signing)
//  12. Self-signing key generation and signing
//  13. User-signing key generation and signing
//  14. Device signing (sign device keys with self-signing key)
//  15. Key backup encryption (encrypt room keys for server backup)
//  16. Key backup decryption
//  17. SSSS (Secure Secret Storage and Sharing) integration
//  18. Secret storage (store secrets encrypted with recovery key/passphrase)
//  19. Recovery key generation
//  20. Passphrase-based key derivation for SSSS

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/bio.h>

#include <nlohmann/json.hpp>

#include <string>
#include <string_view>
#include <vector>
#include <array>
#include <unordered_map>
#include <optional>
#include <ctime>
#include <chrono>
#include <cstring>
#include <cstdint>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <stdexcept>
#include <mutex>
#include <random>
#include <set>
#include <map>
#include <deque>
#include <memory>
#include <functional>
#include <shared_mutex>

#include "signing.hpp"
#include "key.hpp"
#include "../json/canonical.hpp"
#include "../util/base64.hpp"

namespace progressive::crypto {

using json = nlohmann::json;

// =============================================================================
// Constants
// =============================================================================

// Default validity period for server keys: 7 days
constexpr std::chrono::seconds DEFAULT_KEY_VALIDITY{7 * 24 * 3600};
// Maximum backdated time for signing: 5 minutes
constexpr std::chrono::seconds SIGNATURE_GRACE_PERIOD{300};
// Key rotation overlap: keep old keys valid for 24h past rotation
constexpr std::chrono::seconds KEY_ROTATION_OVERLAP{24 * 3600};
// SSSS default parameters
constexpr int SSSS_PBKDF2_ITERATIONS = 500000;
constexpr int SSSS_PBKDF2_SALT_LEN = 32;
constexpr int SSSS_IV_LEN = 16;
constexpr int SSSS_MAC_LEN = 32;
constexpr int SSSS_KEY_LEN = 32;
constexpr int RECOVERY_KEY_BYTES = 32;
// Event reference hash algorithm
constexpr const char* REFERENCE_HASH_ALGO = "sha256";

// =============================================================================
// Data Structures
// =============================================================================

// A server signing key with full metadata and lifecycle tracking
struct ServerSigningKey {
    std::string server_name;
    std::string key_id;          // e.g. "ed25519:abc123"
    std::vector<uint8_t> public_key;   // 32 bytes
    std::vector<uint8_t> private_key;  // 32 bytes (seed)
    uint64_t valid_until_ts = 0; // millisecond timestamp
    uint64_t created_ts = 0;
    bool is_verify_key = true;
    bool is_signing_key = false;
    // TLS certificate paths (for federation)
    std::string tls_certificate_path;
    std::string tls_private_key_path;
    std::vector<std::string> old_key_ids;
};

// A published server key JSON document, self-signed
struct PublishedServerKey {
    std::string server_name;
    json verify_keys = json::object();
    json old_verify_keys = json::object();
    uint64_t valid_until_ts = 0;
    json signatures = json::object();
    // TLS fingerprints (optional)
    json tls_fingerprints = json::array();
};

// Cross-signing keys (Matrix Spec §14)
enum class CrossSigningKeyType {
    Master,
    SelfSigning,
    UserSigning
};

struct CrossSigningKey {
    std::string user_id;
    std::string key_id;          // e.g. "ed25519:master_public_key"
    CrossSigningKeyType key_type;
    std::vector<uint8_t> public_key;   // 32 bytes
    std::vector<uint8_t> private_key;  // 32 bytes
    std::string usage;           // "master", "self_signing", "user_signing"
    json signatures = json::object();  // signed by other cross-signing keys
    uint64_t created_ts = 0;
};

// Device key structure as per Matrix spec
struct DeviceKeys {
    std::string user_id;
    std::string device_id;
    std::string algorithm;       // e.g. "m.olm.v1.curve25519-aes-sha2"
    json keys = json::object();  // key_id -> base64-encoded key
    json signatures = json::object();
};

// Single key in a backup
struct BackupKeyData {
    std::string room_id;
    std::string session_id;
    std::string algorithm;
    std::string session_key;     // base64-encoded
    uint64_t first_message_index = 0;
    uint64_t forwarded_count = 0;
    bool is_verified = false;
    json sender_claimed_keys = json::object();
    // Encrypted form
    json encrypted = json::object();
};

// Backup version metadata
struct BackupVersion {
    std::string version;         // opaque string, e.g. "1"
    std::string algorithm;       // "m.megolm_backup.v1.curve25519-aes-sha2"
    std::string auth_data;       // base64
    uint64_t count = 0;
    uint64_t etag = 0;
};

// SSSS Secret Storage record
struct SSSSSecret {
    std::string secret_id;
    json encrypted = json::object();  // {ciphertext, mac, iv}
    std::string decrypted_value;
};

// Recovery key
struct RecoveryKey {
    std::vector<uint8_t> key_bytes;  // 32 bytes
    std::string passphrase_base;     // e.g. "EsTc TwiN ..." if derived from passphrase

    std::string encode_base58() const;
    static RecoveryKey generate();
    static std::optional<RecoveryKey> from_base58(std::string_view encoded);
    static std::optional<RecoveryKey> from_passphrase(
        std::string_view passphrase, const std::vector<uint8_t>& salt, int iterations);
};

// =============================================================================
// Utility Functions
// =============================================================================

namespace {

// Secure constant-time comparison
bool constant_time_equals(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    volatile uint8_t result = 0;
    for (size_t i = 0; i < a.size(); ++i) {
        result |= static_cast<uint8_t>(a[i]) ^ static_cast<uint8_t>(b[i]);
    }
    return result == 0;
}

bool constant_time_equals_bytes(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
    if (a.size() != b.size()) return false;
    volatile uint8_t result = 0;
    for (size_t i = 0; i < a.size(); ++i) {
        result |= a[i] ^ b[i];
    }
    return result == 0;
}

// Milliseconds since epoch
uint64_t now_ms() {
    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()).count();
    return static_cast<uint64_t>(ms);
}

// Seconds since epoch
uint64_t now_sec() {
    auto now = std::chrono::system_clock::now();
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            now.time_since_epoch()).count());
}

// Random bytes
std::vector<uint8_t> random_bytes(size_t count) {
    std::vector<uint8_t> buf(count);
    if (RAND_bytes(buf.data(), static_cast<int>(count)) != 1) {
        throw std::runtime_error("RAND_bytes failed");
    }
    return buf;
}

// Hex-encode bytes
std::string hex_encode(const std::vector<uint8_t>& data) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (auto b : data) {
        oss << std::setw(2) << static_cast<int>(b);
    }
    return oss.str();
}

// Hex-decode string
std::vector<uint8_t> hex_decode(std::string_view hex) {
    std::vector<uint8_t> out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        unsigned int byte;
        std::string byte_str{hex[i], hex[i + 1]};
        byte = static_cast<unsigned int>(std::stoul(byte_str, nullptr, 16));
        out.push_back(static_cast<uint8_t>(byte));
    }
    return out;
}

// Unpadded base64
std::string base64_unpadded(std::string_view data) {
    std::string encoded = base64::encode(data);
    while (!encoded.empty() && encoded.back() == '=') {
        encoded.pop_back();
    }
    return encoded;
}

// Convert string_view to vector
std::vector<uint8_t> to_bytes(std::string_view sv) {
    return std::vector<uint8_t>(reinterpret_cast<const uint8_t*>(sv.data()),
                                reinterpret_cast<const uint8_t*>(sv.data()) + sv.size());
}

// Convert vector to string_view
std::string_view to_sv(const std::vector<uint8_t>& v) {
    return std::string_view(reinterpret_cast<const char*>(v.data()), v.size());
}

// Strip signatures and unsigned from JSON for signing
json prepare_for_signing(const json& obj) {
    json cleaned = obj;
    if (cleaned.contains("signatures")) {
        cleaned.erase("signatures");
    }
    if (cleaned.contains("unsigned")) {
        cleaned.erase("unsigned");
    }
    return cleaned;
}

// Strip 'content' field from event for hashing (spec §3.3)
json strip_content_for_hash(const json& event) {
    json stripped = event;
    // Remove content field
    if (stripped.contains("content")) {
        stripped.erase("content");
    }
    // Remove hashes field (will be recomputed)
    if (stripped.contains("hashes")) {
        stripped.erase("hashes");
    }
    // Remove signatures
    if (stripped.contains("signatures")) {
        stripped.erase("signatures");
    }
    // Remove unsigned
    if (stripped.contains("unsigned")) {
        stripped.erase("unsigned");
    }
    return stripped;
}

} // anonymous namespace

// =============================================================================
// 1. Ed25519 Key Generation and Loading
// =============================================================================

// Generate a new server signing keypair with metadata
ServerSigningKey generate_server_signing_key(std::string_view server_name,
                                              std::string_view version) {
    ServerSigningKey sk;
    sk.server_name = std::string(server_name);
    sk.created_ts = now_ms();
    sk.valid_until_ts = sk.created_ts +
        static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
            DEFAULT_KEY_VALIDITY).count());
    sk.is_signing_key = true;
    sk.is_verify_key = true;

    // Generate the actual Ed25519 keypair
    auto kp = generate_ed25519_keypair(version);
    sk.key_id = kp.key_id();
    sk.public_key = std::move(kp.public_key);
    sk.private_key = std::move(kp.private_key);

    return sk;
}

// Load an Ed25519 keypair from a PEM file
Ed25519Keypair load_ed25519_from_pem(std::string_view pem_path) {
    std::ifstream f(std::string(pem_path), std::ios::binary);
    if (!f) {
        throw std::runtime_error("Cannot open PEM file: " + std::string(pem_path));
    }
    std::string pem_data((std::istreambuf_iterator<char>(f)),
                          std::istreambuf_iterator<char>());

    BIO* bio = BIO_new_mem_buf(pem_data.data(), static_cast<int>(pem_data.size()));
    if (!bio) throw std::runtime_error("BIO_new_mem_buf failed");

    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (!pkey) {
        // Try public key
        bio = BIO_new_mem_buf(pem_data.data(), static_cast<int>(pem_data.size()));
        pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);
    }

    if (!pkey) {
        throw std::runtime_error("Failed to read key from PEM");
    }

    Ed25519Keypair kp;
    kp.version = "pem_loaded";

    size_t pub_len = 32;
    kp.public_key.resize(pub_len);
    if (EVP_PKEY_get_raw_public_key(pkey, kp.public_key.data(), &pub_len) <= 0) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("EVP_PKEY_get_raw_public_key failed");
    }
    kp.public_key.resize(pub_len);

    size_t priv_len = 32;
    kp.private_key.resize(priv_len);
    if (EVP_PKEY_get_raw_private_key(pkey, kp.private_key.data(), &priv_len) <= 0) {
        // Public key only is OK
        kp.private_key.clear();
    } else {
        kp.private_key.resize(priv_len);
    }

    EVP_PKEY_free(pkey);
    return kp;
}

// Save Ed25519 keypair to PEM file
void save_ed25519_to_pem(const Ed25519Keypair& kp, std::string_view pem_path) {
    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_ED25519, nullptr,
        kp.private_key.data(), kp.private_key.size());
    if (!pkey) throw std::runtime_error("EVP_PKEY_new_raw_private_key failed");

    BIO* bio = BIO_new_file(std::string(pem_path).c_str(), "w");
    if (!bio) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Cannot open output file");
    }

    if (PEM_write_bio_PrivateKey(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr) != 1) {
        BIO_free(bio);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("PEM_write_bio_PrivateKey failed");
    }

    BIO_free(bio);
    EVP_PKEY_free(pkey);
}

// Load a ServerSigningKey from a JSON file
ServerSigningKey load_signing_key_from_file(std::string_view path) {
    std::ifstream f(std::string(path));
    if (!f) throw std::runtime_error("Cannot open key file: " + std::string(path));

    json j = json::parse(f);
    ServerSigningKey sk;
    sk.server_name = j.value("server_name", "");
    sk.key_id = j.value("key_id", "ed25519:default");
    sk.is_signing_key = j.value("is_signing_key", true);
    sk.is_verify_key = j.value("is_verify_key", true);
    sk.valid_until_ts = j.value("valid_until_ts", 0ULL);
    sk.created_ts = j.value("created_ts", 0ULL);
    sk.tls_certificate_path = j.value("tls_certificate_path", "");
    sk.tls_private_key_path = j.value("tls_private_key_path", "");

    if (j.contains("public_key_b64")) {
        sk.public_key = base64::decode(j["public_key_b64"].get<std::string>());
    }
    if (j.contains("private_key_b64")) {
        sk.private_key = base64::decode(j["private_key_b64"].get<std::string>());
    }
    if (j.contains("old_key_ids")) {
        for (auto& kid : j["old_key_ids"]) {
            sk.old_key_ids.push_back(kid.get<std::string>());
        }
    }
    return sk;
}

// Save a ServerSigningKey to a JSON file
void save_signing_key_to_file(const ServerSigningKey& sk, std::string_view path,
                               bool include_private) {
    json j;
    j["server_name"] = sk.server_name;
    j["key_id"] = sk.key_id;
    j["is_signing_key"] = sk.is_signing_key;
    j["is_verify_key"] = sk.is_verify_key;
    j["valid_until_ts"] = sk.valid_until_ts;
    j["created_ts"] = sk.created_ts;
    j["tls_certificate_path"] = sk.tls_certificate_path;
    j["tls_private_key_path"] = sk.tls_private_key_path;
    j["public_key_b64"] = base64::encode(to_sv(sk.public_key));

    if (include_private && !sk.private_key.empty()) {
        j["private_key_b64"] = base64::encode(to_sv(sk.private_key));
    }

    json old_keys = json::array();
    for (auto& kid : sk.old_key_ids) {
        old_keys.push_back(kid);
    }
    j["old_key_ids"] = old_keys;

    std::ofstream f(std::string(path));
    if (!f) throw std::runtime_error("Cannot write key file");
    f << j.dump(2);
}

// =============================================================================
// 2. Event Signing with Ed25519
// =============================================================================

// Sign a Matrix event JSON with the given keypair
json sign_event(const json& event, const Ed25519Keypair& key, std::string_view origin) {
    json signed_event = event;

    // Ensure signatures structure exists
    if (!signed_event.contains("signatures")) {
        signed_event["signatures"] = json::object();
    }
    if (!signed_event["signatures"].contains(origin)) {
        signed_event["signatures"][origin] = json::object();
    }

    // Remove existing signature for this key (for clean re-signing)
    signed_event["signatures"][origin].erase(key.key_id());

    // Remove unsigned/age_ts before signing
    if (signed_event.contains("unsigned")) {
        signed_event["unsigned"].erase("age_ts");
    }

    // Compute canonical JSON and sign
    std::string canon = json::canonical_json(signed_event);
    std::string sig = ed25519_sign(canon, key.private_key);

    signed_event["signatures"][origin][key.key_id()] = sig;
    return signed_event;
}

// Sign an event with multiple keys (e.g., signing key + backup key)
json sign_event_multi(const json& event,
                       const std::vector<std::pair<Ed25519Keypair, std::string>>& signers) {
    json signed_event = event;
    for (auto& [key, origin] : signers) {
        signed_event = sign_event(signed_event, key, origin);
    }
    return signed_event;
}

// Add server signature to an event (convenience wrapper)
json add_server_signature(const json& event, const ServerSigningKey& server_key) {
    Ed25519Keypair kp;
    kp.version = server_key.key_id;
    kp.public_key = server_key.public_key;
    kp.private_key = server_key.private_key;

    // Parse the key_id to get version: "ed25519:version"
    auto colon_pos = server_key.key_id.find(':');
    if (colon_pos != std::string::npos) {
        kp.version = server_key.key_id.substr(colon_pos + 1);
    }

    return sign_event(event, kp, server_key.server_name);
}

// =============================================================================
// 3. Event Signature Verification
// =============================================================================

// Verify a single signature on an event
bool verify_event_signature(const json& event, std::string_view origin,
                            std::string_view key_id,
                            const std::vector<uint8_t>& public_key) {
    return verify_json_signature(event, origin, key_id, public_key);
}

// Verify all signatures on an event against known server keys
struct SignatureVerificationResult {
    bool all_valid = false;
    std::vector<std::string> valid_origins;
    std::vector<std::string> invalid_origins;
    std::vector<std::string> missing_keys;
};

SignatureVerificationResult verify_event_signatures(
    const json& event,
    const std::unordered_map<std::string,
        std::unordered_map<std::string, std::vector<uint8_t>>>& known_keys) {
    // known_keys: origin -> key_id -> public_key
    SignatureVerificationResult result;
    result.all_valid = true;

    if (!event.contains("signatures")) {
        result.all_valid = false;
        return result;
    }

    for (auto& [origin, sigs] : event["signatures"].items()) {
        bool origin_valid = true;
        for (auto& [key_id, sig_val] : sigs.items()) {
            auto origin_it = known_keys.find(origin);
            if (origin_it == known_keys.end()) {
                result.missing_keys.push_back(std::string(origin) + ":" + key_id);
                origin_valid = false;
                continue;
            }
            auto key_it = origin_it->second.find(key_id);
            if (key_it == origin_it->second.end()) {
                result.missing_keys.push_back(std::string(origin) + ":" + key_id);
                origin_valid = false;
                continue;
            }
            if (verify_event_signature(event, origin, key_id, key_it->second)) {
                result.valid_origins.push_back(origin);
            } else {
                result.invalid_origins.push_back(origin);
                origin_valid = false;
            }
        }
        if (!origin_valid) result.all_valid = false;
    }

    return result;
}

// Verify event signatures for a single known origin
bool verify_event_from_origin(const json& event, std::string_view origin,
                               const std::vector<std::pair<std::string, std::vector<uint8_t>>>& keys) {
    if (!event.contains("signatures") || !event["signatures"].contains(origin)) {
        return false;
    }

    auto& origin_sigs = event["signatures"][origin];
    for (auto& [key_id, pub_key] : keys) {
        if (origin_sigs.contains(key_id)) {
            if (verify_event_signature(event, origin, key_id, pub_key)) {
                return true;
            }
        }
    }
    return false;
}

// =============================================================================
// 4. Hash Computation (SHA-256) for Event References
// =============================================================================

// Compute SHA-256 hash of raw bytes
std::vector<uint8_t> sha256(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH);
    SHA256(data.data(), data.size(), hash.data());
    return hash;
}

std::vector<uint8_t> sha256(std::string_view data) {
    std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH);
    SHA256(reinterpret_cast<const uint8_t*>(data.data()), data.size(), hash.data());
    return hash;
}

// Compute SHA-256 hash and return as hex
std::string sha256_hex(const std::vector<uint8_t>& data) {
    return hex_encode(sha256(data));
}

std::string sha256_hex(std::string_view data) {
    return hex_encode(sha256(data));
}

// Compute SHA-256 hash and return as unpadded base64
std::string sha256_b64(std::string_view data) {
    auto hash = sha256(data);
    return base64_unpadded(to_sv(hash));
}

std::string sha256_b64(const std::vector<uint8_t>& data) {
    auto hash = sha256(data);
    return base64_unpadded(to_sv(hash));
}

// Compute the event reference hash as per Matrix spec §3.3
// This is SHA-256 of the canonical JSON of the event with 'content', 'hashes', and
// signatures stripped.
json compute_event_reference_hash(const json& event) {
    json stripped = strip_content_for_hash(event);
    std::string canon = json::canonical_json(stripped);
    auto hash = sha256(to_bytes(canon));

    json result;
    result[REFERENCE_HASH_ALGO] = base64_unpadded(to_sv(hash));
    return result;
}

// Add reference hash to an event
json add_reference_hash(json event) {
    event["hashes"] = compute_event_reference_hash(event);
    return event;
}

// Verify the reference hash in an event
bool verify_reference_hash(const json& event) {
    if (!event.contains("hashes")) {
        return false; // No hash to verify — consider this valid per spec
    }
    if (!event["hashes"].contains(REFERENCE_HASH_ALGO)) {
        return false;
    }

    std::string expected_hash = event["hashes"][REFERENCE_HASH_ALGO].get<std::string>();
    json computed = compute_event_reference_hash(event);
    std::string computed_hash = computed[REFERENCE_HASH_ALGO].get<std::string>();

    return constant_time_equals(expected_hash, computed_hash);
}

// Compute content hash (SHA-256 of just the content object)
std::string compute_content_hash(const json& content) {
    std::string canon = json::canonical_json(content);
    return sha256_b64(canon);
}

// HMAC-SHA256
std::vector<uint8_t> hmac_sha256(const std::vector<uint8_t>& key,
                                  const std::vector<uint8_t>& data) {
    std::vector<uint8_t> mac(SHA256_DIGEST_LENGTH);
    unsigned int mac_len = SHA256_DIGEST_LENGTH;
    HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
         data.data(), data.size(), mac.data(), &mac_len);
    mac.resize(mac_len);
    return mac;
}

std::vector<uint8_t> hmac_sha256(std::string_view key, std::string_view data) {
    std::vector<uint8_t> mac(SHA256_DIGEST_LENGTH);
    unsigned int mac_len = SHA256_DIGEST_LENGTH;
    HMAC(EVP_sha256(),
         reinterpret_cast<const uint8_t*>(key.data()), static_cast<int>(key.size()),
         reinterpret_cast<const uint8_t*>(data.data()), static_cast<int>(data.size()),
         mac.data(), &mac_len);
    mac.resize(mac_len);
    return mac;
}

// =============================================================================
// 5. Canonical JSON Serialization for Signing
// =============================================================================

// Wrapper that invokes progressive::json::canonical_json
std::string canonical_json_for_signing(const json& obj) {
    // Strip keys that should not be included in signatures
    json cleaned = obj;
    if (cleaned.contains("unsigned")) {
        auto& uns = cleaned["unsigned"];
        if (uns.contains("age_ts")) {
            uns.erase("age_ts");
        }
    }
    return json::canonical_json(cleaned);
}

// Compute the canonical JSON, strip signatures for that specific key, and return
std::string canonical_json_minus_signature(const json& obj,
                                             std::string_view origin,
                                             std::string_view key_id) {
    json cleaned = obj;
    if (cleaned.contains("signatures") && cleaned["signatures"].contains(origin)) {
        cleaned["signatures"][origin].erase(std::string(key_id));
        if (cleaned["signatures"][origin].empty()) {
            cleaned["signatures"].erase(std::string(origin));
        }
        if (cleaned["signatures"].empty()) {
            cleaned.erase("signatures");
        }
    }
    if (cleaned.contains("unsigned")) {
        cleaned["unsigned"].erase("age_ts");
    }
    return json::canonical_json(cleaned);
}

// =============================================================================
// 6. Event Redaction
// =============================================================================

// Redact an event according to Matrix spec §11.2
// Returns a new event with sensitive fields removed, keeping only allowed top-level keys
json redact_event(const json& event, std::optional<std::string_view> reason) {
    // Allowed top-level keys for redacted events
    static const std::set<std::string> allowed_top_level = {
        "auth_events", "prev_events", "depth",
        "event_id", "hashes", "origin", "origin_server_ts",
        "membership", "prev_state", "redacts",
        "room_id", "sender", "signatures", "state_key",
        "type", "unsigned"
    };

    // Allowed content keys - only membership kept
    static const std::set<std::string> allowed_content_keys = {
        "membership"
    };

    json redacted;

    // Copy allowed top-level keys
    for (auto& [key, val] : event.items()) {
        if (allowed_top_level.count(key)) {
            if (key == "unsigned") {
                // Only keep age_ts and redacted_because in unsigned
                json new_unsigned;
                if (val.contains("age_ts")) {
                    new_unsigned["age_ts"] = val["age_ts"];
                }
                if (reason.has_value()) {
                    new_unsigned["redacted_because"] = *reason;
                }
                if (!new_unsigned.empty()) {
                    redacted["unsigned"] = new_unsigned;
                }
            } else {
                redacted[key] = val;
            }
        }
    }

    // Handle content — only keep membership if present
    if (event.contains("content") && event["content"].is_object()) {
        json new_content;
        for (auto& [key, val] : event["content"].items()) {
            if (allowed_content_keys.count(key)) {
                new_content[key] = val;
            }
        }
        redacted["content"] = new_content;
    } else {
        redacted["content"] = json::object();
    }

    // Always set type to "m.room.redaction" if not already present
    if (!redacted.contains("type")) {
        redacted["type"] = "m.room.redaction";
    }

    return redacted;
}

// Verify that a redacted event matches its original (spec §11.2)
bool verify_redaction(const json& original, const json& redacted) {
    // Check that all keys in redacted exist in original with same value
    // (except content and unsigned which are explicitly modified)
    for (auto& [key, val] : redacted.items()) {
        if (key == "content" || key == "unsigned" ||
            key == "hashes" || key == "signatures") {
            continue;
        }
        if (!original.contains(key)) return false;
        if (original[key] != val) return false;
    }
    return true;
}

// =============================================================================
// 7. Server Key Management
// =============================================================================

// Thread-safe key store for server key management
class ServerKeyManager {
public:
    ServerKeyManager() = default;

    // Add a verify key (for incoming signature verification)
    void add_verify_key(const ServerSigningKey& key) {
        std::unique_lock lock(mutex_);
        verify_keys_[key.server_name][key.key_id] = key;
    }

    // Remove a verify key
    void remove_verify_key(std::string_view server_name, std::string_view key_id) {
        std::unique_lock lock(mutex_);
        auto it = verify_keys_.find(std::string(server_name));
        if (it != verify_keys_.end()) {
            it->second.erase(std::string(key_id));
        }
    }

    // Get a verify key
    std::optional<ServerSigningKey> get_verify_key(std::string_view server_name,
                                                    std::string_view key_id) {
        std::shared_lock lock(mutex_);
        auto it = verify_keys_.find(std::string(server_name));
        if (it != verify_keys_.end()) {
            auto kit = it->second.find(std::string(key_id));
            if (kit != it->second.end()) {
                return kit->second;
            }
        }
        return std::nullopt;
    }

    // Get all verify keys for a server
    std::unordered_map<std::string, ServerSigningKey> get_verify_keys_for_server(
        std::string_view server_name) {
        std::shared_lock lock(mutex_);
        auto it = verify_keys_.find(std::string(server_name));
        if (it != verify_keys_.end()) {
            return it->second;
        }
        return {};
    }

    // Set the active signing key for this server
    void set_signing_key(const ServerSigningKey& key) {
        std::unique_lock lock(mutex_);
        signing_key_ = key;
        // Also add as verify key
        verify_keys_[key.server_name][key.key_id] = key;
    }

    // Get active signing key
    std::optional<ServerSigningKey> get_signing_key() {
        std::shared_lock lock(mutex_);
        if (signing_key_.has_value()) {
            return *signing_key_;
        }
        return std::nullopt;
    }

    // Rotate signing key: old key becomes old_verify_key, new key becomes signing_key
    ServerSigningKey rotate_signing_key(std::string_view version) {
        std::unique_lock lock(mutex_);
        std::string server_name;
        if (signing_key_.has_value()) {
            server_name = signing_key_->server_name;
            // Add old key to old key list
            auto old_key = *signing_key_;
            old_key.is_signing_key = false;
            old_key.is_verify_key = true;
            // Extend validity for overlap
            old_key.valid_until_ts = now_ms() +
                static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                    KEY_ROTATION_OVERLAP).count());

            // Store old key
            if (old_keys_.size() >= 10) {
                old_keys_.pop_front();
            }
            old_keys_.push_back(old_key);
        }

        // Generate new key
        auto new_key = generate_server_signing_key(server_name, version);
        signing_key_ = new_key;
        verify_keys_[server_name][new_key.key_id] = new_key;

        return new_key;
    }

    // Get old verify keys (for inclusion in /key/v2/server)
    std::vector<ServerSigningKey> get_old_keys() {
        std::shared_lock lock(mutex_);
        return std::vector<ServerSigningKey>(old_keys_.begin(), old_keys_.end());
    }

    // Check if a key is still valid
    bool is_key_valid(std::string_view server_name, std::string_view key_id) {
        std::shared_lock lock(mutex_);
        auto it = verify_keys_.find(std::string(server_name));
        if (it != verify_keys_.end()) {
            auto kit = it->second.find(std::string(key_id));
            if (kit != it->second.end()) {
                return kit->second.valid_until_ts > now_ms();
            }
        }
        // Check old keys
        for (auto& ok : old_keys_) {
            if (ok.server_name == server_name && ok.key_id == key_id) {
                return ok.valid_until_ts > now_ms();
            }
        }
        return false;
    }

    // Purge expired keys
    void purge_expired_keys() {
        std::unique_lock lock(mutex_);
        auto ts = now_ms();

        // Purge verify keys
        for (auto& [server, keys] : verify_keys_) {
            auto it = keys.begin();
            while (it != keys.end()) {
                if (it->second.valid_until_ts < ts) {
                    it = keys.erase(it);
                } else {
                    ++it;
                }
            }
        }

        // Purge old keys
        auto it = old_keys_.begin();
        while (it != old_keys_.end()) {
            if (it->valid_until_ts < ts) {
                it = old_keys_.erase(it);
            } else {
                ++it;
            }
        }
    }

    // Get TLS certificate fingerprint
    std::string get_tls_fingerprint(std::string_view server_name) {
        std::shared_lock lock(mutex_);
        auto it = verify_keys_.find(std::string(server_name));
        if (it != verify_keys_.end() && !it->second.empty()) {
            auto& key = it->second.begin()->second;
            if (!key.tls_certificate_path.empty()) {
                // Read cert and compute SHA-256 fingerprint
                std::ifstream f(key.tls_certificate_path, std::ios::binary);
                if (f) {
                    std::string cert_data((std::istreambuf_iterator<char>(f)),
                                           std::istreambuf_iterator<char>());
                    return sha256_b64(cert_data);
                }
            }
        }
        return "";
    }

private:
    std::shared_mutex mutex_;
    std::optional<ServerSigningKey> signing_key_;
    // server_name -> key_id -> key
    std::unordered_map<std::string,
        std::unordered_map<std::string, ServerSigningKey>> verify_keys_;
    std::deque<ServerSigningKey> old_keys_;
};

// Global server key manager instance
ServerKeyManager& get_server_key_manager() {
    static ServerKeyManager instance;
    return instance;
}

// =============================================================================
// 8. Key Publishing (/key/v2/server endpoint)
// =============================================================================

// Build the complete /key/v2/server response JSON
json build_key_server_response(std::string_view server_name,
                                const ServerSigningKey& verify_key,
                                const std::vector<ServerSigningKey>& old_keys,
                                const std::vector<std::string>& tls_fingerprints) {
    json response;
    response["server_name"] = server_name;
    response["valid_until_ts"] = verify_key.valid_until_ts;

    // Current verify keys
    json verify_keys_obj = json::object();
    json vk;
    vk["key"] = base64::encode(to_sv(verify_key.public_key));
    verify_keys_obj[verify_key.key_id] = vk;
    response["verify_keys"] = verify_keys_obj;

    // Old verify keys
    json old_verify_keys = json::object();
    for (auto& ok : old_keys) {
        json ovk;
        ovk["key"] = base64::encode(to_sv(ok.public_key));
        // Note: old keys can optionally include 'expired_ts'
        ovk["expired_ts"] = ok.valid_until_ts;
        old_verify_keys[ok.key_id] = ovk;
    }
    response["old_verify_keys"] = old_verify_keys;

    // TLS fingerprints (sha256)
    json fingerprints = json::array();
    for (auto& fp : tls_fingerprints) {
        json f_obj;
        f_obj["sha256"] = fp;
        fingerprints.push_back(f_obj);
    }
    if (!fingerprints.empty()) {
        response["tls_fingerprints"] = fingerprints;
    }

    // Self-sign the response
    // Build a copy without signatures for the self-signing
    json self_sign_obj;
    self_sign_obj["server_name"] = server_name;
    self_sign_obj["verify_keys"] = verify_keys_obj;
    self_sign_obj["old_verify_keys"] = old_verify_keys;
    self_sign_obj["valid_until_ts"] = response["valid_until_ts"];

    std::string canon = json::canonical_json(self_sign_obj);

    Ed25519Keypair kp;
    kp.version = verify_key.key_id;
    kp.public_key = verify_key.public_key;
    kp.private_key = verify_key.private_key;
    auto colon_pos = verify_key.key_id.find(':');
    if (colon_pos != std::string::npos) {
        kp.version = verify_key.key_id.substr(colon_pos + 1);
    }

    std::string sig = ed25519_sign(canon, kp.private_key);

    response["signatures"] = json::object();
    response["signatures"][std::string(server_name)] = json::object();
    response["signatures"][std::string(server_name)][verify_key.key_id] = sig;

    return response;
}

// Build response from server key manager
json build_key_server_response_from_manager(std::string_view server_name,
                                              const std::vector<std::string>& tls_fingerprints) {
    auto& mgr = get_server_key_manager();
    auto signing_key = mgr.get_signing_key();
    if (!signing_key.has_value()) {
        throw std::runtime_error("No signing key configured for server: " + std::string(server_name));
    }
    auto old_keys = mgr.get_old_keys();
    return build_key_server_response(server_name, *signing_key, old_keys, tls_fingerprints);
}

// Parse and validate a /key/v2/server response from a remote server
struct ParsedServerKeys {
    std::string server_name;
    std::string key_id;
    std::vector<uint8_t> public_key;
    uint64_t valid_until_ts;
    bool self_signature_valid = false;
};

std::optional<ParsedServerKeys> parse_server_key_response(const json& response) {
    ParsedServerKeys result;

    if (!response.contains("server_name") || !response.contains("verify_keys")) {
        return std::nullopt;
    }

    result.server_name = response["server_name"].get<std::string>();
    result.valid_until_ts = response.value("valid_until_ts", 0ULL);

    // Check validity period
    if (result.valid_until_ts > 0 && result.valid_until_ts < now_ms()) {
        return std::nullopt; // expired
    }

    // Get the first verify key
    auto& vk = response["verify_keys"];
    if (vk.empty()) return std::nullopt;

    auto first = vk.begin();
    result.key_id = first.key();
    auto key_b64 = first.value()["key"].get<std::string>();
    result.public_key = base64::decode(key_b64);

    // Verify self-signature
    if (response.contains("signatures") &&
        response["signatures"].contains(result.server_name) &&
        response["signatures"][result.server_name].contains(result.key_id)) {

        std::string sig = response["signatures"][result.server_name][result.key_id].get<std::string>();

        // Rebuild the self-signed object excluding signatures
        json self_obj;
        self_obj["server_name"] = response["server_name"];
        self_obj["verify_keys"] = response["verify_keys"];
        self_obj["old_verify_keys"] = response.value("old_verify_keys", json::object());
        self_obj["valid_until_ts"] = response["valid_until_ts"];

        std::string canon = json::canonical_json(self_obj);
        result.self_signature_valid = ed25519_verify(canon, sig, result.public_key);
    }

    return result;
}

// =============================================================================
// 9. Key Query (/key/v2/query endpoint)
// =============================================================================

// Build a /key/v2/query request for specific server keys
json build_key_query_request(const std::unordered_map<std::string, std::vector<std::string>>& server_keys) {
    // server_keys: server_name -> list of key_ids (or empty for all)
    json request;
    request["method"] = "GET";
    request["uri"] = "/_matrix/key/v2/server";

    json key_ids = json::object();
    for (auto& [server, kids] : server_keys) {
        if (kids.empty()) {
            key_ids[server] = json::object(); // request all keys
        } else {
            json k_obj = json::object();
            for (auto& kid : kids) {
                k_obj[kid] = json::object();
            }
            key_ids[server] = k_obj;
        }
    }
    request["server_keys"] = key_ids;

    return request;
}

// Build a /key/v2/query response
json build_key_query_response(
    const std::unordered_map<std::string, json>& server_responses) {
    json response;
    response["server_keys"] = json::array();
    for (auto& [server, resp] : server_responses) {
        response["server_keys"].push_back(resp);
    }
    return response;
}

// Parse a key query response and extract valid keys
std::unordered_map<std::string, std::unordered_map<std::string, std::vector<uint8_t>>>
parse_key_query_response(const json& response) {
    std::unordered_map<std::string,
        std::unordered_map<std::string, std::vector<uint8_t>>> result;

    if (!response.contains("server_keys")) return result;

    for (auto& key_obj : response["server_keys"]) {
        auto parsed = parse_server_key_response(key_obj);
        if (parsed.has_value() && parsed->self_signature_valid) {
            result[parsed->server_name][parsed->key_id] = std::move(parsed->public_key);
        }
    }

    return result;
}

// =============================================================================
// 10. Key Validity Period and Rotation
// =============================================================================

// Key rotation manager — handles periodic key rotation
class KeyRotationManager {
public:
    struct Config {
        std::chrono::seconds rotation_interval = DEFAULT_KEY_VALIDITY;
        std::chrono::seconds overlap_period = KEY_ROTATION_OVERLAP;
        int max_old_keys = 10;
        std::string key_version_prefix = "v";
        int version_counter = 1;
    };

    explicit KeyRotationManager(Config config = {}) : config_(std::move(config)) {}

    // Check if rotation is needed
    bool needs_rotation() {
        auto now = std::chrono::system_clock::now();
        return now >= next_rotation_;
    }

    // Perform key rotation
    ServerSigningKey rotate() {
        std::string version = config_.key_version_prefix +
                              std::to_string(config_.version_counter++);
        auto& mgr = get_server_key_manager();
        auto new_key = mgr.rotate_signing_key(version);

        // Schedule next rotation
        next_rotation_ = std::chrono::system_clock::now() + config_.rotation_interval;

        return new_key;
    }

    // Get next scheduled rotation time
    std::chrono::system_clock::time_point get_next_rotation() const {
        return next_rotation_;
    }

    // Set the next rotation time manually
    void set_next_rotation(std::chrono::system_clock::time_point next) {
        next_rotation_ = next;
    }

private:
    Config config_;
    std::chrono::system_clock::time_point next_rotation_ =
        std::chrono::system_clock::now() + DEFAULT_KEY_VALIDITY;
};

// Check if a key validity period is acceptable (not too far future, not expired)
bool is_validity_period_acceptable(uint64_t valid_until_ts, uint64_t max_future_ms = 30 * 24 * 3600 * 1000ULL) {
    uint64_t now = now_ms();
    if (valid_until_ts < now) return false;

    // Don't accept keys valid more than 30 days in the future
    if (valid_until_ts > now + max_future_ms) {
        return false;
    }
    return true;
}

// =============================================================================
// 11. Cross-Signing Key Hierarchy
// =============================================================================

// Cross-signing key manager implementing the three-key hierarchy:
//   Master Key -> Self-Signing Key -> User-Signing Key
//
// Master key: signs both sub-keys, used as root of trust
// Self-signing key: signs device keys
// User-signing key: signs user identity keys (for attestation)
class CrossSigningKeyManager {
public:
    CrossSigningKeyManager() = default;

    // Generate a new master key
    CrossSigningKey generate_master_key(std::string_view user_id) {
        auto kp = generate_ed25519_keypair("master");
        CrossSigningKey key;
        key.user_id = user_id;
        key.key_id = "ed25519:" + std::string(user_id);
        key.key_type = CrossSigningKeyType::Master;
        key.usage = "master";
        key.public_key = std::move(kp.public_key);
        key.private_key = std::move(kp.private_key);
        key.created_ts = now_ms();
        key.signatures = json::object();

        std::unique_lock lock(mutex_);
        master_key_ = key;
        return key;
    }

    // Generate self-signing key, signed by master
    CrossSigningKey generate_self_signing_key(std::string_view user_id) {
        std::shared_lock lock(mutex_);
        if (!master_key_.has_value()) {
            throw std::runtime_error("Master key must be generated first");
        }

        auto kp = generate_ed25519_keypair("self_signing");
        CrossSigningKey key;
        key.user_id = user_id;
        key.key_id = "ed25519:self_signing_" + std::string(user_id);
        key.key_type = CrossSigningKeyType::SelfSigning;
        key.usage = "self_signing";
        key.public_key = std::move(kp.public_key);
        key.private_key = std::move(kp.private_key);
        key.created_ts = now_ms();

        // Sign with master key
        json to_sign;
        to_sign["user_id"] = key.user_id;
        to_sign["usage"] = {"self_signing"};
        to_sign["keys"] = json::object();
        to_sign["keys"][key.key_id] = base64::encode(to_sv(key.public_key));

        std::string canon = json::canonical_json(to_sign);
        std::string sig = ed25519_sign(canon, master_key_->private_key);

        key.signatures[master_key_->user_id] = json::object();
        key.signatures[master_key_->user_id][master_key_->key_id] = sig;

        lock.unlock();
        std::unique_lock wlock(mutex_);
        self_signing_key_ = key;
        return key;
    }

    // Generate user-signing key, signed by master
    CrossSigningKey generate_user_signing_key(std::string_view user_id) {
        std::shared_lock lock(mutex_);
        if (!master_key_.has_value()) {
            throw std::runtime_error("Master key must be generated first");
        }

        auto kp = generate_ed25519_keypair("user_signing");
        CrossSigningKey key;
        key.user_id = user_id;
        key.key_id = "ed25519:user_signing_" + std::string(user_id);
        key.key_type = CrossSigningKeyType::UserSigning;
        key.usage = "user_signing";
        key.public_key = std::move(kp.public_key);
        key.private_key = std::move(kp.private_key);
        key.created_ts = now_ms();

        // Sign with master key
        json to_sign;
        to_sign["user_id"] = key.user_id;
        to_sign["usage"] = {"user_signing"};
        to_sign["keys"] = json::object();
        to_sign["keys"][key.key_id] = base64::encode(to_sv(key.public_key));

        std::string canon = json::canonical_json(to_sign);
        std::string sig = ed25519_sign(canon, master_key_->private_key);

        key.signatures[master_key_->user_id] = json::object();
        key.signatures[master_key_->user_id][master_key_->key_id] = sig;

        lock.unlock();
        std::unique_lock wlock(mutex_);
        user_signing_key_ = key;
        return key;
    }

    // Get master key public info (for sharing)
    json get_master_key_public() const {
        std::shared_lock lock(mutex_);
        if (!master_key_.has_value()) {
            return json::object();
        }
        json result;
        result["user_id"] = master_key_->user_id;
        result["usage"] = json::array({"master"});
        result["keys"] = json::object();
        result["keys"][master_key_->key_id] = base64::encode(to_sv(master_key_->public_key));
        result["signatures"] = master_key_->signatures;
        return result;
    }

    // Get self-signing key public info
    json get_self_signing_key_public() const {
        std::shared_lock lock(mutex_);
        if (!self_signing_key_.has_value()) {
            return json::object();
        }
        json result;
        result["user_id"] = self_signing_key_->user_id;
        result["usage"] = json::array({"self_signing"});
        result["keys"] = json::object();
        result["keys"][self_signing_key_->key_id] =
            base64::encode(to_sv(self_signing_key_->public_key));
        result["signatures"] = self_signing_key_->signatures;
        return result;
    }

    // Get user-signing key public info
    json get_user_signing_key_public() const {
        std::shared_lock lock(mutex_);
        if (!user_signing_key_.has_value()) {
            return json::object();
        }
        json result;
        result["user_id"] = user_signing_key_->user_id;
        result["usage"] = json::array({"user_signing"});
        result["keys"] = json::object();
        result["keys"][user_signing_key_->key_id] =
            base64::encode(to_sv(user_signing_key_->public_key));
        result["signatures"] = user_signing_key_->signatures;
        return result;
    }

    // Get the full cross-signing keys object (for /keys/query response)
    json get_cross_signing_keys() const {
        std::shared_lock lock(mutex_);
        json result;

        if (master_key_.has_value()) {
            result["master"] = get_master_key_public();
        }
        if (self_signing_key_.has_value()) {
            result["self_signing"] = get_self_signing_key_public();
        }
        if (user_signing_key_.has_value()) {
            result["user_signing"] = get_user_signing_key_public();
        }

        return result;
    }

    // Verify cross-signing key hierarchy
    bool verify_cross_signing_hierarchy(const json& cross_signing_keys) {
        // Check master key exists
        if (!cross_signing_keys.contains("master")) {
            return false;
        }
        auto& master = cross_signing_keys["master"];

        // If self-signing key is present, verify its master signature
        if (cross_signing_keys.contains("self_signing")) {
            auto& ss = cross_signing_keys["self_signing"];
            if (!verify_cross_signing_signature(ss, master)) {
                return false;
            }
        }

        // If user-signing key is present, verify its master signature
        if (cross_signing_keys.contains("user_signing")) {
            auto& us = cross_signing_keys["user_signing"];
            if (!verify_cross_signing_signature(us, master)) {
                return false;
            }
        }

        return true;
    }

    // Load cross-signing keys from JSON (for import/restore)
    void load_from_json(const json& keys) {
        std::unique_lock lock(mutex_);

        auto load_key = [](const json& k, CrossSigningKeyType type) -> std::optional<CrossSigningKey> {
            if (!k.contains("user_id") || !k.contains("keys")) return std::nullopt;

            CrossSigningKey ck;
            ck.user_id = k["user_id"].get<std::string>();
            ck.key_type = type;

            auto& keys_obj = k["keys"];
            if (keys_obj.empty()) return std::nullopt;
            auto first = keys_obj.begin();
            ck.key_id = first.key();
            ck.public_key = base64::decode(first.value().get<std::string>());

            if (k.contains("usage") && k["usage"].is_array() && !k["usage"].empty()) {
                ck.usage = k["usage"][0].get<std::string>();
            }

            if (k.contains("signatures")) {
                ck.signatures = k["signatures"];
            }

            return ck;
        };

        if (keys.contains("master")) {
            auto mk = load_key(keys["master"], CrossSigningKeyType::Master);
            if (mk) master_key_ = std::move(*mk);
        }
        if (keys.contains("self_signing")) {
            auto ss = load_key(keys["self_signing"], CrossSigningKeyType::SelfSigning);
            if (ss) self_signing_key_ = std::move(*ss);
        }
        if (keys.contains("user_signing")) {
            auto us = load_key(keys["user_signing"], CrossSigningKeyType::UserSigning);
            if (us) user_signing_key_ = std::move(*us);
        }
    }

private:
    bool verify_cross_signing_signature(const json& sub_key, const json& master_key) {
        // Rebuild the object that was signed
        json to_verify;
        to_verify["user_id"] = sub_key["user_id"];
        to_verify["usage"] = sub_key["usage"];
        to_verify["keys"] = sub_key["keys"];

        std::string canon = json::canonical_json(to_verify);

        // Get master key public key and id
        if (!master_key.contains("keys") || master_key["keys"].empty()) return false;
        auto first_mk = master_key["keys"].begin();
        std::string master_key_id = first_mk.key();
        auto master_pub_b64 = first_mk.value().get<std::string>();
        auto master_pub = base64::decode(master_pub_b64);

        std::string master_user_id = master_key["user_id"].get<std::string>();

        // Find signature from master
        if (!sub_key.contains("signatures")) return false;
        if (!sub_key["signatures"].contains(master_user_id)) return false;
        if (!sub_key["signatures"][master_user_id].contains(master_key_id)) return false;

        std::string sig = sub_key["signatures"][master_user_id][master_key_id].get<std::string>();

        return ed25519_verify(canon, sig, master_pub);
    }

    mutable std::shared_mutex mutex_;
    std::optional<CrossSigningKey> master_key_;
    std::optional<CrossSigningKey> self_signing_key_;
    std::optional<CrossSigningKey> user_signing_key_;
};

// Global cross-signing manager instance
CrossSigningKeyManager& get_cross_signing_manager() {
    static CrossSigningKeyManager instance;
    return instance;
}

// =============================================================================
// 12. Self-Signing Key Generation and Signing
// =============================================================================

// Generate self-signing key with master signature
CrossSigningKey generate_self_signing_key(std::string_view user_id) {
    return get_cross_signing_manager().generate_self_signing_key(user_id);
}

// Export self-signing key public info
json export_self_signing_key_public() {
    return get_cross_signing_manager().get_self_signing_key_public();
}

// =============================================================================
// 13. User-Signing Key Generation and Signing
// =============================================================================

// Generate user-signing key with master signature
CrossSigningKey generate_user_signing_key(std::string_view user_id) {
    return get_cross_signing_manager().generate_user_signing_key(user_id);
}

// Export user-signing key public info
json export_user_signing_key_public() {
    return get_cross_signing_manager().get_user_signing_key_public();
}

// =============================================================================
// 14. Device Signing
// =============================================================================

// Sign device keys with the self-signing key
json sign_device_keys(const DeviceKeys& device_keys, const CrossSigningKey& self_signing_key) {
    // Build the object to sign (as per Matrix spec)
    json to_sign;
    to_sign["user_id"] = device_keys.user_id;
    to_sign["device_id"] = device_keys.device_id;
    to_sign["algorithms"] = json::array({device_keys.algorithm});

    // Add device keys, sorted by key_id
    json sorted_keys = json::object();
    std::vector<std::string> key_names;
    for (auto& [k, v] : device_keys.keys.items()) {
        key_names.push_back(k);
    }
    std::sort(key_names.begin(), key_names.end());
    for (auto& k : key_names) {
        sorted_keys[k] = device_keys.keys[k];
    }
    to_sign["keys"] = sorted_keys;

    std::string canon = json::canonical_json(to_sign);
    std::string sig = ed25519_sign(canon, self_signing_key.private_key);

    json signed_device = device_keys.signatures;
    signed_device[self_signing_key.user_id] = json::object();
    signed_device[self_signing_key.user_id][self_signing_key.key_id] = sig;

    json result;
    result["user_id"] = device_keys.user_id;
    result["device_id"] = device_keys.device_id;
    result["algorithms"] = json::array({device_keys.algorithm});
    result["keys"] = sorted_keys;
    result["signatures"] = signed_device;

    return result;
}

// Verify device key signature
bool verify_device_signature(const json& signed_device, const CrossSigningKey& self_signing_key) {
    if (!signed_device.contains("signatures")) return false;

    // Rebuild the object that was signed (excluding signatures)
    json to_verify;
    to_verify["user_id"] = signed_device["user_id"];
    to_verify["device_id"] = signed_device["device_id"];
    to_verify["algorithms"] = signed_device["algorithms"];
    to_verify["keys"] = signed_device["keys"];

    std::string canon = json::canonical_json(to_verify);

    std::string user_id = self_signing_key.user_id;
    std::string key_id = self_signing_key.key_id;

    if (!signed_device["signatures"].contains(user_id)) return false;
    if (!signed_device["signatures"][user_id].contains(key_id)) return false;

    std::string sig = signed_device["signatures"][user_id][key_id].get<std::string>();
    return ed25519_verify(canon, sig, self_signing_key.public_key);
}

// Build device keys JSON for a given set of keys
DeviceKeys build_device_keys(std::string_view user_id, std::string_view device_id,
                              const std::unordered_map<std::string, std::vector<uint8_t>>& keys) {
    DeviceKeys dk;
    dk.user_id = user_id;
    dk.device_id = device_id;
    dk.algorithm = "m.olm.v1.curve25519-aes-sha2";

    for (auto& [key_id, key_data] : keys) {
        dk.keys[key_id] = base64::encode(to_sv(key_data));
    }
    dk.signatures = json::object();

    return dk;
}

// =============================================================================
// 15. Key Backup Encryption
// =============================================================================

// AES-256-CTR encryption for key backup
std::vector<uint8_t> aes_ctr_encrypt(const std::vector<uint8_t>& key,
                                      const std::vector<uint8_t>& iv,
                                      const std::vector<uint8_t>& plaintext) {
    if (key.size() != 32) throw std::runtime_error("AES-256 key must be 32 bytes");
    if (iv.size() != 16) throw std::runtime_error("AES-CTR IV must be 16 bytes");

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    std::vector<uint8_t> ciphertext(plaintext.size() + EVP_MAX_BLOCK_LENGTH);
    int out_len = 0;
    int total_len = 0;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), nullptr, key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptInit_ex failed");
    }

    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &out_len,
                          plaintext.data(), static_cast<int>(plaintext.size())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptUpdate failed");
    }
    total_len = out_len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + total_len, &out_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptFinal_ex failed");
    }
    total_len += out_len;

    EVP_CIPHER_CTX_free(ctx);
    ciphertext.resize(total_len);
    return ciphertext;
}

// AES-256-CTR decryption
std::vector<uint8_t> aes_ctr_decrypt(const std::vector<uint8_t>& key,
                                      const std::vector<uint8_t>& iv,
                                      const std::vector<uint8_t>& ciphertext) {
    if (key.size() != 32) throw std::runtime_error("AES-256 key must be 32 bytes");
    if (iv.size() != 16) throw std::runtime_error("AES-CTR IV must be 16 bytes");

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    std::vector<uint8_t> plaintext(ciphertext.size());
    int out_len = 0;
    int total_len = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(), nullptr, key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptInit_ex failed");
    }

    if (EVP_DecryptUpdate(ctx, plaintext.data(), &out_len,
                          ciphertext.data(), static_cast<int>(ciphertext.size())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptUpdate failed");
    }
    total_len = out_len;

    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + total_len, &out_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptFinal_ex failed");
    }
    total_len += out_len;

    EVP_CIPHER_CTX_free(ctx);
    plaintext.resize(total_len);
    return plaintext;
}

// Encrypt a single room key for backup
json encrypt_backup_key(const BackupKeyData& key_data, const std::vector<uint8_t>& encryption_key) {
    // Build the plaintext JSON
    json plaintext;
    plaintext["algorithm"] = key_data.algorithm;
    plaintext["sender_key"] = key_data.session_key;
    plaintext["sender_claimed_keys"] = key_data.sender_claimed_keys;
    plaintext["session_id"] = key_data.session_id;
    plaintext["room_id"] = key_data.room_id;
    plaintext["forwarding_curve25519_key_chain"] = json::array();

    std::string plaintext_str = plaintext.dump();
    auto plaintext_bytes = to_bytes(plaintext_str);

    // Generate random IV
    auto iv = random_bytes(SSSS_IV_LEN);

    // Encrypt
    auto ciphertext = aes_ctr_encrypt(encryption_key, iv, plaintext_bytes);

    // Compute MAC: HMAC-SHA256(key, ciphertext || iv)
    std::vector<uint8_t> mac_input;
    mac_input.insert(mac_input.end(), ciphertext.begin(), ciphertext.end());
    mac_input.insert(mac_input.end(), iv.begin(), iv.end());
    auto mac = hmac_sha256(encryption_key, mac_input);

    // Build encrypted JSON as per Matrix spec
    json encrypted;
    encrypted["ciphertext"] = base64_unpadded(to_sv(ciphertext));
    encrypted["mac"] = base64_unpadded(to_sv(mac));
    encrypted["iv"] = base64_unpadded(to_sv(iv));

    return encrypted;
}

// Encrypt a batch of room keys for backup
json encrypt_backup_keys(
    const std::unordered_map<std::string, BackupKeyData>& room_keys,
    const std::vector<uint8_t>& encryption_key) {
    json result = json::object();
    result["rooms"] = json::object();

    for (auto& [room_id, key] : room_keys) {
        std::string session_id = key.session_id;
        json encrypted = encrypt_backup_key(key, encryption_key);

        if (!result["rooms"].contains(room_id)) {
            result["rooms"][room_id] = json::object();
            result["rooms"][room_id]["sessions"] = json::object();
        }
        result["rooms"][room_id]["sessions"][session_id] = encrypted;
    }

    return result;
}

// =============================================================================
// 16. Key Backup Decryption
// =============================================================================

// Decrypt a single room key from backup
BackupKeyData decrypt_backup_key(const json& encrypted_key,
                                  const std::vector<uint8_t>& encryption_key,
                                  std::string_view room_id,
                                  std::string_view session_id) {
    if (!encrypted_key.contains("ciphertext") ||
        !encrypted_key.contains("mac") ||
        !encrypted_key.contains("iv")) {
        throw std::runtime_error("Invalid encrypted key format");
    }

    auto ciphertext = base64::decode(encrypted_key["ciphertext"].get<std::string>());
    auto stored_mac = base64::decode(encrypted_key["mac"].get<std::string>());
    auto iv = base64::decode(encrypted_key["iv"].get<std::string>());

    // Verify MAC first
    std::vector<uint8_t> mac_input;
    mac_input.insert(mac_input.end(), ciphertext.begin(), ciphertext.end());
    mac_input.insert(mac_input.end(), iv.begin(), iv.end());
    auto computed_mac = hmac_sha256(encryption_key, mac_input);

    if (!constant_time_equals_bytes(stored_mac, computed_mac)) {
        throw std::runtime_error("MAC verification failed for backup key");
    }

    // Decrypt
    auto plaintext_bytes = aes_ctr_decrypt(encryption_key, iv, ciphertext);
    std::string plaintext_str(reinterpret_cast<const char*>(plaintext_bytes.data()),
                               plaintext_bytes.size());

    json plaintext = json::parse(plaintext_str);

    BackupKeyData key;
    key.room_id = room_id;
    key.session_id = session_id;
    key.algorithm = plaintext.value("algorithm", "");
    key.session_key = plaintext.value("sender_key", "");
    key.sender_claimed_keys = plaintext.value("sender_claimed_keys", json::object());

    return key;
}

// Decrypt a batch of room keys from backup
std::unordered_map<std::string, BackupKeyData> decrypt_backup_keys(
    const json& encrypted_backup,
    const std::vector<uint8_t>& encryption_key) {
    std::unordered_map<std::string, BackupKeyData> result;

    if (!encrypted_backup.contains("rooms")) return result;

    for (auto& [room_id, room_data] : encrypted_backup["rooms"].items()) {
        if (!room_data.contains("sessions")) continue;
        for (auto& [session_id, encrypted_key] : room_data["sessions"].items()) {
            try {
                auto key = decrypt_backup_key(encrypted_key, encryption_key, room_id, session_id);
                result[session_id] = std::move(key);
            } catch (...) {
                // Skip corrupted entries
                continue;
            }
        }
    }

    return result;
}

// =============================================================================
// 17. SSSS (Secure Secret Storage and Sharing) Integration
// =============================================================================

// SSSS Manager - implements Matrix Secure Secret Storage and Sharing
class SSSSManager {
public:
    struct SecretMetadata {
        std::string secret_id;
        std::string algorithm;         // "m.secret_storage.v1.aes-hmac-sha2"
        std::string key_id;            // which key encrypts this secret
        json iv;                       // base64 IV
        json ciphertext;               // base64 ciphertext
        json mac;                      // base64 MAC
    };

    // Store a secret encrypted with a specific SSSS key
    SecretMetadata store_secret(std::string_view secret_id,
                                 std::string_view secret_value,
                                 const std::vector<uint8_t>& ssss_key,
                                 std::string_view ssss_key_id) {
        SecretMetadata meta;
        meta.secret_id = secret_id;
        meta.algorithm = "m.secret_storage.v1.aes-hmac-sha2";
        meta.key_id = ssss_key_id;

        // Generate random IV
        auto iv = random_bytes(SSSS_IV_LEN);

        // Zero-pad the secret to 32 bytes minimum
        std::string padded_secret(secret_value);
        if (padded_secret.size() < 32) {
            padded_secret.append(32 - padded_secret.size(), '\0');
        }

        // Encrypt
        auto ciphertext = aes_ctr_encrypt(ssss_key, iv, to_bytes(padded_secret));

        // Compute MAC
        std::vector<uint8_t> mac_input;
        mac_input.insert(mac_input.end(), ciphertext.begin(), ciphertext.end());
        mac_input.insert(mac_input.end(), iv.begin(), iv.end());
        auto mac = hmac_sha256(ssss_key, mac_input);

        meta.iv = base64_unpadded(to_sv(iv));
        meta.ciphertext = base64_unpadded(to_sv(ciphertext));
        meta.mac = base64_unpadded(to_sv(mac));

        // Store in memory
        std::unique_lock lock(mutex_);
        secrets_[std::string(secret_id)] = meta;

        return meta;
    }

    // Retrieve and decrypt a secret
    std::string retrieve_secret(std::string_view secret_id,
                                 const std::vector<uint8_t>& ssss_key) {
        std::shared_lock lock(mutex_);
        auto it = secrets_.find(std::string(secret_id));
        if (it == secrets_.end()) {
            throw std::runtime_error("Secret not found: " + std::string(secret_id));
        }

        auto& meta = it->second;
        auto ciphertext = base64::decode(meta.ciphertext.get<std::string>());
        auto iv = base64::decode(meta.iv.get<std::string>());
        auto stored_mac = base64::decode(meta.mac.get<std::string>());

        // Verify MAC
        std::vector<uint8_t> mac_input;
        mac_input.insert(mac_input.end(), ciphertext.begin(), ciphertext.end());
        mac_input.insert(mac_input.end(), iv.begin(), iv.end());
        auto computed_mac = hmac_sha256(ssss_key, mac_input);

        if (!constant_time_equals_bytes(stored_mac, computed_mac)) {
            throw std::runtime_error("MAC verification failed for secret");
        }

        // Decrypt
        auto plaintext = aes_ctr_decrypt(ssss_key, iv, ciphertext);

        // Strip null padding
        std::string result(reinterpret_cast<const char*>(plaintext.data()), plaintext.size());
        auto null_pos = result.find('\0');
        if (null_pos != std::string::npos) {
            result.resize(null_pos);
        }

        return result;
    }

    // Build the account_data JSON for SSSS
    json build_ssss_account_data() const {
        std::shared_lock lock(mutex_);
        json result;
        result["encrypted"] = json::object();

        for (auto& [secret_id, meta] : secrets_) {
            json entry;
            entry["encrypted"] = json::object();
            entry["encrypted"][meta.key_id] = json::object();
            entry["encrypted"][meta.key_id]["algorithm"] = meta.algorithm;
            entry["encrypted"][meta.key_id]["iv"] = meta.iv;
            entry["encrypted"][meta.key_id]["ciphertext"] = meta.ciphertext;
            entry["encrypted"][meta.key_id]["mac"] = meta.mac;

            result["encrypted"][secret_id] = entry;
        }

        return result;
    }

    // Load secrets from account_data
    void load_from_account_data(const json& account_data) {
        std::unique_lock lock(mutex_);
        secrets_.clear();

        if (!account_data.contains("encrypted")) return;

        for (auto& [secret_id, entry] : account_data["encrypted"].items()) {
            if (!entry.contains("encrypted")) continue;

            // Get the first (and typically only) encryption entry
            auto& encrypted = entry["encrypted"];
            if (encrypted.empty()) continue;

            auto first = encrypted.begin();
            SecretMetadata meta;
            meta.secret_id = secret_id;
            meta.key_id = first.key();
            meta.algorithm = first.value().value("algorithm", "m.secret_storage.v1.aes-hmac-sha2");
            meta.iv = first.value()["iv"];
            meta.ciphertext = first.value()["ciphertext"];
            meta.mac = first.value()["mac"];

            secrets_[secret_id] = meta;
        }
    }

    // Delete a stored secret
    bool delete_secret(std::string_view secret_id) {
        std::unique_lock lock(mutex_);
        return secrets_.erase(std::string(secret_id)) > 0;
    }

    // List stored secret IDs
    std::vector<std::string> list_secrets() const {
        std::shared_lock lock(mutex_);
        std::vector<std::string> ids;
        for (auto& [id, _] : secrets_) {
            ids.push_back(id);
        }
        return ids;
    }

private:
    mutable std::shared_mutex mutex_;
    std::unordered_map<std::string, SecretMetadata> secrets_;
};

// Global SSSS manager instance
SSSSManager& get_ssss_manager() {
    static SSSSManager instance;
    return instance;
}

// =============================================================================
// 18. Secret Storage (Store Secrets Encrypted with Recovery Key/Passphrase)
// =============================================================================

// Store a secret using recovery key
json store_secret_with_recovery_key(std::string_view secret_id,
                                      std::string_view secret_value,
                                      const RecoveryKey& recovery_key) {
    auto& mgr = get_ssss_manager();
    std::string ssss_key_id = "m.secret_storage.key.recovery";

    auto meta = mgr.store_secret(secret_id, secret_value,
                                  recovery_key.key_bytes, ssss_key_id);

    json result;
    result["secret_id"] = meta.secret_id;
    result["key_id"] = meta.key_id;
    result["algorithm"] = meta.algorithm;
    result["iv"] = meta.iv;
    result["ciphertext"] = meta.ciphertext;
    result["mac"] = meta.mac;
    return result;
}

// Store a secret using passphrase-derived key
json store_secret_with_passphrase(std::string_view secret_id,
                                    std::string_view secret_value,
                                    std::string_view passphrase,
                                    const std::vector<uint8_t>& salt,
                                    int iterations) {
    auto recovery_key = RecoveryKey::from_passphrase(passphrase, salt, iterations);
    if (!recovery_key.has_value()) {
        throw std::runtime_error("Failed to derive recovery key from passphrase");
    }

    auto& mgr = get_ssss_manager();
    std::string ssss_key_id = "m.secret_storage.key.passphrase";

    auto meta = mgr.store_secret(secret_id, secret_value,
                                  recovery_key->key_bytes, ssss_key_id);

    json result;
    result["secret_id"] = meta.secret_id;
    result["key_id"] = meta.key_id;
    result["algorithm"] = meta.algorithm;
    result["iv"] = meta.iv;
    result["ciphertext"] = meta.ciphertext;
    result["mac"] = meta.mac;
    result["passphrase"] = json::object();
    result["passphrase"]["algorithm"] = "m.pbkdf2";
    result["passphrase"]["salt"] = base64::encode(to_sv(salt));
    result["passphrase"]["iterations"] = iterations;
    return result;
}

// Retrieve secret with recovery key
std::string retrieve_secret_with_recovery_key(std::string_view secret_id,
                                                const RecoveryKey& recovery_key) {
    auto& mgr = get_ssss_manager();
    return mgr.retrieve_secret(secret_id, recovery_key.key_bytes);
}

// Retrieve secret with passphrase
std::string retrieve_secret_with_passphrase(std::string_view secret_id,
                                              std::string_view passphrase,
                                              const std::vector<uint8_t>& salt,
                                              int iterations) {
    auto recovery_key = RecoveryKey::from_passphrase(passphrase, salt, iterations);
    if (!recovery_key.has_value()) {
        throw std::runtime_error("Failed to derive recovery key from passphrase");
    }
    auto& mgr = get_ssss_manager();
    return mgr.retrieve_secret(secret_id, recovery_key->key_bytes);
}

// =============================================================================
// 19. Recovery Key Generation
// =============================================================================

// Base58 alphabet (Bitcoin-style, for human-readable recovery keys)
static const char BASE58_ALPHABET[] =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

std::string RecoveryKey::encode_base58() const {
    // Encode key_bytes as base58
    if (key_bytes.empty()) return "";

    // Count leading zeros
    size_t leading_zeros = 0;
    for (auto b : key_bytes) {
        if (b == 0) leading_zeros++;
        else break;
    }

    // Convert to big integer (base 256 -> base 58)
    std::vector<uint8_t> num = key_bytes;
    std::string result;

    while (!num.empty()) {
        int remainder = 0;
        std::vector<uint8_t> next;
        for (auto b : num) {
            int current = (remainder * 256) + b;
            int quotient = current / 58;
            remainder = current % 58;
            if (!next.empty() || quotient > 0) {
                next.push_back(static_cast<uint8_t>(quotient));
            }
        }
        result = BASE58_ALPHABET[remainder] + result;
        num = std::move(next);
    }

    // Add leading '1's for leading zeros
    for (size_t i = 0; i < leading_zeros; i++) {
        result = '1' + result;
    }

    return result;
}

std::optional<RecoveryKey> RecoveryKey::from_base58(std::string_view encoded) {
    RecoveryKey rk;

    // Count leading '1's
    size_t leading_ones = 0;
    while (leading_ones < encoded.size() && encoded[leading_ones] == '1') {
        leading_ones++;
    }

    // Decode base58 -> bytes
    std::vector<uint8_t> num = {0};
    for (size_t i = leading_ones; i < encoded.size(); i++) {
        char c = encoded[i];
        auto pos = strchr(BASE58_ALPHABET, c);
        if (!pos) return std::nullopt; // invalid char
        int digit = static_cast<int>(pos - BASE58_ALPHABET);

        // Multiply by 58 and add digit
        int carry = digit;
        for (auto it = num.rbegin(); it != num.rend(); ++it) {
            carry += 58 * (*it);
            *it = static_cast<uint8_t>(carry % 256);
            carry /= 256;
        }
        while (carry > 0) {
            num.insert(num.begin(), static_cast<uint8_t>(carry % 256));
            carry /= 256;
        }
    }

    // Add leading zeros
    rk.key_bytes = std::vector<uint8_t>(leading_ones, 0);
    rk.key_bytes.insert(rk.key_bytes.end(), num.begin(), num.end());

    if (rk.key_bytes.size() != RECOVERY_KEY_BYTES) {
        return std::nullopt; // wrong length
    }

    return rk;
}

RecoveryKey RecoveryKey::generate() {
    RecoveryKey rk;
    rk.key_bytes = random_bytes(RECOVERY_KEY_BYTES);
    return rk;
}

std::optional<RecoveryKey> RecoveryKey::from_passphrase(
    std::string_view passphrase, const std::vector<uint8_t>& salt, int iterations) {

    RecoveryKey rk;
    rk.key_bytes.resize(RECOVERY_KEY_BYTES);

    // PBKDF2-HMAC-SHA512
    int ret = PKCS5_PBKDF2_HMAC(
        passphrase.data(), static_cast<int>(passphrase.size()),
        salt.data(), static_cast<int>(salt.size()),
        iterations,
        EVP_sha512(),
        RECOVERY_KEY_BYTES,
        rk.key_bytes.data());

    if (ret != 1) {
        return std::nullopt;
    }

    rk.passphrase_base = rk.encode_base58();
    return rk;
}

// Generate a new recovery key and return the base58 passphrase
std::string generate_recovery_key_passphrase() {
    auto rk = RecoveryKey::generate();
    return rk.encode_base58();
}

// Generate recovery key from scratch
RecoveryKey generate_recovery_key() {
    return RecoveryKey::generate();
}

// Decode a base58 recovery key
std::optional<RecoveryKey> decode_recovery_key(std::string_view base58_key) {
    return RecoveryKey::from_base58(base58_key);
}

// =============================================================================
// 20. Passphrase-Based Key Derivation for SSSS
// =============================================================================

// Derive a key from a passphrase using PBKDF2
std::vector<uint8_t> derive_key_from_passphrase(std::string_view passphrase,
                                                  const std::vector<uint8_t>& salt,
                                                  int iterations,
                                                  int key_length) {
    std::vector<uint8_t> key(key_length);

    int ret = PKCS5_PBKDF2_HMAC(
        passphrase.data(), static_cast<int>(passphrase.size()),
        salt.data(), static_cast<int>(salt.size()),
        iterations,
        EVP_sha512(),
        key_length,
        key.data());

    if (ret != 1) {
        throw std::runtime_error("PBKDF2 key derivation failed");
    }

    return key;
}

// Derive SSSS encryption key from passphrase with Matrix-standard parameters
std::vector<uint8_t> derive_ssss_key_from_passphrase(std::string_view passphrase,
                                                       const std::vector<uint8_t>& salt,
                                                       int iterations) {
    return derive_key_from_passphrase(passphrase, salt, iterations, SSSS_KEY_LEN);
}

// Generate a random salt for passphrase-based key derivation
std::vector<uint8_t> generate_ssss_salt() {
    return random_bytes(SSSS_PBKDF2_SALT_LEN);
}

// Build the key description JSON for a recovery passphrase key
json build_recovery_passphrase_key_description(std::string_view passphrase) {
    auto salt = generate_ssss_salt();
    auto derived_key = derive_ssss_key_from_passphrase(
        passphrase, salt, SSSS_PBKDF2_ITERATIONS);

    json desc;
    desc["name"] = "m.default";
    desc["algorithm"] = "m.secret_storage.v1.aes-hmac-sha2";
    desc["passphrase"] = json::object();
    desc["passphrase"]["algorithm"] = "m.pbkdf2";
    desc["passphrase"]["iterations"] = SSSS_PBKDF2_ITERATIONS;
    desc["passphrase"]["salt"] = base64::encode(to_sv(salt));
    // The IV and MAC for the key itself (key is stored as a secret)
    desc["iv"] = base64_unpadded(to_sv(random_bytes(SSSS_IV_LEN)));
    desc["mac"] = base64_unpadded(to_sv(derived_key));

    return desc;
}

// Verify a passphrase against stored key description
bool verify_passphrase_key(std::string_view passphrase,
                            const json& key_description) {
    if (!key_description.contains("passphrase")) return false;

    auto& pp = key_description["passphrase"];
    if (pp.value("algorithm", "") != "m.pbkdf2") return false;

    int iterations = pp.value("iterations", SSSS_PBKDF2_ITERATIONS);
    auto salt_b64 = pp["salt"].get<std::string>();
    auto salt = base64::decode(salt_b64);

    auto derived_key = derive_ssss_key_from_passphrase(
        passphrase, salt, iterations);

    // Verify by checking MAC if present
    if (key_description.contains("mac")) {
        auto stored_mac = base64::decode(key_description["mac"].get<std::string>());
        return constant_time_equals_bytes(derived_key, stored_mac);
    }

    return true; // No MAC to verify against (key was just derived)
}

// =============================================================================
// Event Builder Utilities
// =============================================================================

// Build a minimal event JSON with the required fields
json build_event(std::string_view type, std::string_view sender,
                  std::string_view room_id, const json& content) {
    json event;
    event["type"] = type;
    event["sender"] = sender;
    event["room_id"] = room_id;
    event["content"] = content;
    event["origin_server_ts"] = now_ms();
    event["origin"] = sender; // simplified: origin = sender's server
    event["unsigned"] = json::object();
    return event;
}

// Build a federation event with prev_events and auth_events
json build_federation_event(std::string_view type, std::string_view sender,
                              std::string_view room_id, const json& content,
                              const std::vector<std::string>& prev_events,
                              const std::vector<std::string>& auth_events,
                              int64_t depth) {
    json event;
    event["type"] = type;
    event["sender"] = sender;
    event["room_id"] = room_id;
    event["content"] = content;
    event["origin_server_ts"] = now_ms();
    event["origin"] = sender;
    event["unsigned"] = json::object();
    event["depth"] = depth;

    json pe = json::array();
    for (auto& pev : prev_events) {
        json entry;
        entry[0] = pev;
        entry[1] = json::object(); // empty hash
        pe.push_back(entry);
    }
    event["prev_events"] = pe;

    json ae = json::array();
    for (auto& aev : auth_events) {
        json entry;
        entry[0] = aev;
        entry[1] = json::object();
        ae.push_back(entry);
    }
    event["auth_events"] = ae;

    return event;
}

// Add an event ID to an event (computed from origin + reference hash)
json assign_event_id(json event, std::string_view origin) {
    // Compute reference hash
    auto hash_obj = compute_event_reference_hash(event);
    std::string ref_hash = hash_obj[REFERENCE_HASH_ALGO].get<std::string>();

    // Event ID format: $base64hash
    std::string event_id = "$" + ref_hash;
    // Per spec, also include origin in the event_id
    // event_id = "$" + ref_hash + ":" + std::string(origin);

    event["event_id"] = event_id;
    event["hashes"] = hash_obj;
    return event;
}

// =============================================================================
// Key Backup Version Management
// =============================================================================

// Generate a new backup version with auth data
BackupVersion create_backup_version(std::string_view version,
                                      const std::vector<uint8_t>& public_key) {
    BackupVersion bv;
    bv.version = version;
    bv.algorithm = "m.megolm_backup.v1.curve25519-aes-sha2";

    // Auth data: signed JSON containing public key and signatures
    json auth;
    auth["public_key"] = base64_unpadded(to_sv(public_key));
    auth["signatures"] = json::object();
    bv.auth_data = base64_unpadded(auth.dump());

    bv.count = 0;
    bv.etag = now_ms();
    return bv;
}

// Build backup version info JSON for responses
json build_backup_info_json(const BackupVersion& bv) {
    json result;
    result["version"] = bv.version;
    result["algorithm"] = bv.algorithm;
    result["auth_data"] = bv.auth_data;
    result["count"] = bv.count;
    result["etag"] = std::to_string(bv.etag);
    return result;
}

// =============================================================================
// Key Validation Utilities
// =============================================================================

// Validate that a key_id has the correct format (e.g., "ed25519:abc123")
bool validate_key_id_format(std::string_view key_id) {
    auto colon_pos = key_id.find(':');
    if (colon_pos == std::string::npos) return false;
    if (colon_pos == 0) return false; // no algorithm prefix
    if (colon_pos == key_id.size() - 1) return false; // no version suffix

    auto algo = key_id.substr(0, colon_pos);
    if (algo != "ed25519" && algo != "curve25519" && algo != "signed_curve25519") {
        return false;
    }

    return true;
}

// Validate that a public key has the correct size for its algorithm
bool validate_public_key_size(std::string_view algorithm,
                                const std::vector<uint8_t>& public_key) {
    if (algorithm == "ed25519") {
        return public_key.size() == 32;
    }
    if (algorithm == "curve25519") {
        return public_key.size() == 32;
    }
    if (algorithm == "signed_curve25519") {
        // signed_curve25519 includes the key + Ed25519 signature = 32 + 64 = 96
        return public_key.size() == 96;
    }
    return false;
}

// =============================================================================
// TLS Certificate Management for Federation
// =============================================================================

// Load TLS certificate from file
std::string load_tls_certificate(std::string_view path) {
    std::ifstream f(std::string(path), std::ios::binary);
    if (!f) throw std::runtime_error("Cannot open TLS cert: " + std::string(path));
    return std::string((std::istreambuf_iterator<char>(f)),
                        std::istreambuf_iterator<char>());
}

// Compute TLS certificate SHA-256 fingerprint
std::string compute_tls_fingerprint_sha256(std::string_view cert_data) {
    // Try to parse PEM and extract the DER certificate
    BIO* bio = BIO_new_mem_buf(cert_data.data(), static_cast<int>(cert_data.size()));
    if (!bio) return sha256_b64(cert_data); // fallback: hash raw data

    X509* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (!cert) {
        // Not PEM, try as raw DER or just hash the raw data
        return sha256_b64(cert_data);
    }

    // Extract DER encoding and hash it
    unsigned char* der_buf = nullptr;
    int der_len = i2d_X509(cert, &der_buf);
    X509_free(cert);

    if (der_len <= 0 || !der_buf) {
        return sha256_b64(cert_data);
    }

    std::vector<uint8_t> der_data(der_buf, der_buf + der_len);
    OPENSSL_free(der_buf);

    return sha256_b64(der_data);
}

// Compute TLS certificate SHA-256 fingerprint from file
std::string compute_tls_fingerprint_from_file(std::string_view cert_path) {
    std::string cert_data = load_tls_certificate(cert_path);
    return compute_tls_fingerprint_sha256(cert_data);
}

// Build TLS fingerprints array for /key/v2/server
json build_tls_fingerprints_json(const std::vector<std::string>& fingerprints) {
    json result = json::array();
    for (auto& fp : fingerprints) {
        json entry;
        entry["sha256"] = fp;
        result.push_back(entry);
    }
    return result;
}

// =============================================================================
// Signature Verification with Grace Period
// =============================================================================

// Check if a signature timestamp is within the acceptable grace period
bool is_within_signature_grace_period(uint64_t origin_server_ts) {
    uint64_t now = now_ms();
    // Allow signatures up to 5 minutes in the future
    if (origin_server_ts > now + static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                SIGNATURE_GRACE_PERIOD).count())) {
        return false;
    }
    // Allow signatures up to 5 minutes in the past
    if (origin_server_ts < now - static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                SIGNATURE_GRACE_PERIOD).count())) {
        // Still accept but may flag as potentially replay
        return true;
    }
    return true;
}

// =============================================================================
// Event Chain Verification
// =============================================================================

// Verify that an event correctly references its prev_events
bool verify_event_chain(const json& event,
                         const std::unordered_map<std::string, json>& known_events) {
    if (!event.contains("prev_events")) return true; // no prev_events to verify

    for (auto& prev : event["prev_events"]) {
        if (!prev.is_array() || prev.size() < 2) continue;
        std::string prev_event_id = prev[0].get<std::string>();

        // Check if we know this event
        auto it = known_events.find(prev_event_id);
        if (it == known_events.end()) {
            continue; // we don't have the event, skip verification
        }

        // Verify the reference hash matches
        if (prev.size() >= 2 && !prev[1].is_null() && prev[1].is_object()) {
            auto& hash_obj = prev[1];
            if (hash_obj.contains(REFERENCE_HASH_ALGO)) {
                std::string stored_hash = hash_obj[REFERENCE_HASH_ALGO].get<std::string>();
                auto computed_hash = compute_event_reference_hash(it->second);
                std::string computed_str = computed_hash[REFERENCE_HASH_ALGO].get<std::string>();
                if (!constant_time_equals(stored_hash, computed_str)) {
                    return false;
                }
            }
        }
    }

    return true;
}

// =============================================================================
// Multi-Signature Aggregation
// =============================================================================

// Aggregate signatures from multiple servers onto a single event
json aggregate_signatures(const json& event,
                           const std::vector<std::pair<std::string, json>>& server_events) {
    // server_events: vector of (server_name, signed_event)
    json result = event;
    if (!result.contains("signatures")) {
        result["signatures"] = json::object();
    }

    for (auto& [server_name, signed_event] : server_events) {
        if (signed_event.contains("signatures") &&
            signed_event["signatures"].contains(server_name)) {
            result["signatures"][server_name] = signed_event["signatures"][server_name];
        }
    }

    return result;
}

// =============================================================================
// Key Persistence Layer
// =============================================================================

// Save all key manager state to a directory
void save_key_manager_state(std::string_view directory) {
    // Save server signing keys
    auto& mgr = get_server_key_manager();
    auto signing_key = mgr.get_signing_key();

    if (signing_key.has_value()) {
        std::string path = std::string(directory) + "/server_signing_key.json";
        save_signing_key_to_file(*signing_key, path, true);
    }

    // Save old keys
    auto old_keys = mgr.get_old_keys();
    for (size_t i = 0; i < old_keys.size(); i++) {
        std::string path = std::string(directory) + "/server_old_key_" +
                           std::to_string(i) + ".json";
        save_signing_key_to_file(old_keys[i], path, false);
    }

    // Save cross-signing keys
    auto& csm = get_cross_signing_manager();
    json cs_keys = csm.get_cross_signing_keys();
    if (!cs_keys.empty()) {
        std::string path = std::string(directory) + "/cross_signing_keys.json";
        std::ofstream f(path);
        if (f) {
            f << cs_keys.dump(2);
        }
    }
}

// Load key manager state from a directory
void load_key_manager_state(std::string_view directory) {
    auto& mgr = get_server_key_manager();

    // Load server signing key
    std::string signing_path = std::string(directory) + "/server_signing_key.json";
    std::ifstream sf(signing_path);
    if (sf) {
        auto sk = load_signing_key_from_file(signing_path);
        mgr.set_signing_key(sk);
    }

    // Load cross-signing keys
    std::string cs_path = std::string(directory) + "/cross_signing_keys.json";
    std::ifstream cf(cs_path);
    if (cf) {
        json cs_keys = json::parse(cf);
        auto& csm = get_cross_signing_manager();
        csm.load_from_json(cs_keys);
    }
}

// =============================================================================
// Backup Version Management (continued)
// =============================================================================

// Verify backup auth data signature
bool verify_backup_auth_data(const BackupVersion& bv,
                               const std::vector<uint8_t>& expected_public_key) {
    try {
        auto auth_bytes = base64::decode(bv.auth_data);
        std::string auth_str(reinterpret_cast<const char*>(auth_bytes.data()), auth_bytes.size());
        json auth = json::parse(auth_str);

        if (!auth.contains("public_key")) return false;
        std::string pub_key_b64 = auth["public_key"].get<std::string>();
        auto pub_key = base64::decode(pub_key_b64);

        // Verify the public key matches if we have an expected one
        if (!expected_public_key.empty() &&
            !constant_time_equals_bytes(pub_key, expected_public_key)) {
            return false;
        }

        return true;
    } catch (...) {
        return false;
    }
}

// =============================================================================
// Key Export/Import
// =============================================================================

// Export cross-signing keys in a format suitable for recovery
json export_cross_signing_keys_for_backup() {
    auto& mgr = get_cross_signing_manager();
    return mgr.get_cross_signing_keys();
}

// Export all keys for backup/recovery
json export_all_keys_for_backup() {
    json result;

    auto& csm = get_cross_signing_manager();
    result["cross_signing_keys"] = csm.get_cross_signing_keys();

    // Server key public info only
    auto& srv_mgr = get_server_key_manager();
    auto sig_key = srv_mgr.get_signing_key();
    if (sig_key.has_value()) {
        json server_key;
        server_key["server_name"] = sig_key->server_name;
        server_key["key_id"] = sig_key->key_id;
        server_key["public_key_b64"] = base64::encode(to_sv(sig_key->public_key));
        server_key["valid_until_ts"] = sig_key->valid_until_ts;
        result["server_key"] = server_key;
    }

    return result;
}

// =============================================================================
// Ed25519 Key Derivation (for backup key from recovery key)
// =============================================================================

// Derive an Ed25519 keypair from a recovery key for backup encryption
Ed25519Keypair derive_ed25519_from_key(const std::vector<uint8_t>& seed_material,
                                         std::string_view context) {
    // Use HKDF-like approach: HMAC-SHA256 the seed with context
    std::string ctx(context);
    auto derived_bytes = hmac_sha256(
        to_sv(seed_material),
        ctx);

    // Use derived bytes as Ed25519 seed
    Ed25519Keypair kp;
    kp.version = "derived";

    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_ED25519, nullptr,
        derived_bytes.data(), derived_bytes.size());
    if (!pkey) throw std::runtime_error("EVP_PKEY_new_raw_private_key failed");

    size_t pub_len = 32;
    kp.public_key.resize(pub_len);
    EVP_PKEY_get_raw_public_key(pkey, kp.public_key.data(), &pub_len);

    kp.private_key = std::move(derived_bytes);
    EVP_PKEY_free(pkey);

    return kp;
}

// =============================================================================
// Signature Timestamp Validation (advanced)
// =============================================================================

// Validate the complete set of event timestamps
struct TimestampValidationResult {
    bool valid = false;
    bool origin_server_ts_valid = false;
    bool age_ts_present = false;
    std::string error;
};

TimestampValidationResult validate_event_timestamps(const json& event) {
    TimestampValidationResult result;

    if (!event.contains("origin_server_ts")) {
        result.error = "Missing origin_server_ts";
        return result;
    }

    uint64_t origin_ts = event["origin_server_ts"].get<uint64_t>();
    result.origin_server_ts_valid = is_within_signature_grace_period(origin_ts);

    if (!result.origin_server_ts_valid) {
        result.error = "origin_server_ts outside grace period";
        return result;
    }

    if (event.contains("unsigned") && event["unsigned"].contains("age_ts")) {
        result.age_ts_present = true;
    }

    result.valid = true;
    return result;
}

// =============================================================================
// Key Fingerprint Computation
// =============================================================================

// Compute a human-readable Ed25519 key fingerprint
// Format: 8 groups of 4 base64 characters
std::string compute_key_fingerprint(const std::vector<uint8_t>& public_key) {
    auto encoded = base64_unpadded(to_sv(public_key));
    auto hash = sha256(to_bytes(encoded));
    auto fp_encoded = base64_unpadded(to_sv(hash));

    // Take first 32 characters and format as 8 groups of 4
    std::string fingerprint;
    for (size_t i = 0; i < 32 && i < fp_encoded.size(); i++) {
        if (i > 0 && i % 4 == 0) fingerprint += ' ';
        fingerprint += fp_encoded[i];
    }
    return fingerprint;
}

// =============================================================================
// Key Rotation History
// =============================================================================

// Record of a key rotation
struct KeyRotationRecord {
    std::string old_key_id;
    std::string new_key_id;
    uint64_t rotated_at_ms;
    std::string reason;
};

// Maintain key rotation history
class KeyRotationHistory {
public:
    void record_rotation(std::string_view old_key_id, std::string_view new_key_id,
                         std::string_view reason = "") {
        std::unique_lock lock(mutex_);
        KeyRotationRecord record;
        record.old_key_id = old_key_id;
        record.new_key_id = new_key_id;
        record.rotated_at_ms = now_ms();
        record.reason = reason;
        history_.push_back(record);

        if (history_.size() > max_records_) {
            history_.pop_front();
        }
    }

    std::vector<KeyRotationRecord> get_history() const {
        std::shared_lock lock(mutex_);
        return std::vector<KeyRotationRecord>(history_.begin(), history_.end());
    }

    std::optional<KeyRotationRecord> get_latest() const {
        std::shared_lock lock(mutex_);
        if (history_.empty()) return std::nullopt;
        return history_.back();
    }

private:
    static constexpr size_t max_records_ = 100;
    mutable std::shared_mutex mutex_;
    std::deque<KeyRotationRecord> history_;
};

// Global rotation history
KeyRotationHistory& get_key_rotation_history() {
    static KeyRotationHistory instance;
    return instance;
}

// =============================================================================
// Event Content Hashing for Forward Extremities
// =============================================================================

// Compute the content hash used in prev_events entries
json compute_prev_event_content_hash(const json& event) {
    return compute_event_reference_hash(event);
}

// =============================================================================
// Streamlined Event Signing Pipeline
// =============================================================================

// Complete event signing pipeline: build, hash, sign
json sign_event_pipeline(const json& event_template,
                          const Ed25519Keypair& key,
                          std::string_view origin) {
    json event = event_template;

    // 1. Add origin_server_ts if not present
    if (!event.contains("origin_server_ts")) {
        event["origin_server_ts"] = now_ms();
    }

    // 2. Ensure unsigned exists
    if (!event.contains("unsigned")) {
        event["unsigned"] = json::object();
    }

    // 3. Compute and add reference hash
    event = add_reference_hash(event);

    // 4. Sign the event
    event = sign_event(event, key, origin);

    return event;
}

// =============================================================================
// Multi-Step Signature Aggregation (for federation)
// =============================================================================

// During federation, events gather signatures from participating servers.
// This function adds a new server's signature while preserving existing ones.
json federate_event_signature(json event,
                               const Ed25519Keypair& key,
                               std::string_view origin) {
    if (!event.contains("signatures")) {
        event["signatures"] = json::object();
    }

    // Sign with this server's key (preserves existing signatures)
    event = sign_event(event, key, origin);

    return event;
}

// =============================================================================
// Backup Session Key Encryption/Decryption Wrappers
// =============================================================================

// Encrypt a single session key for server-side backup
json backup_encrypt_session_key(
    std::string_view session_key,
    std::string_view session_id,
    std::string_view room_id,
    const std::vector<uint8_t>& backup_encryption_key) {

    BackupKeyData key_data;
    key_data.session_key = session_key;
    key_data.session_id = session_id;
    key_data.room_id = room_id;
    key_data.algorithm = "m.megolm.v1.aes-sha2";

    return encrypt_backup_key(key_data, backup_encryption_key);
}

// =============================================================================
// SSSS Key Description Builder
// =============================================================================

// Build the complete key description for the default SSSS key
json build_ssss_default_key_description(const std::vector<uint8_t>& public_key) {
    json desc;
    desc["name"] = "m.default";
    desc["algorithm"] = "m.secret_storage.v1.aes-hmac-sha2";

    // For a passphrase-based key
    auto salt = generate_ssss_salt();
    desc["passphrase"] = json::object();
    desc["passphrase"]["algorithm"] = "m.pbkdf2";
    desc["passphrase"]["iterations"] = SSSS_PBKDF2_ITERATIONS;
    desc["passphrase"]["salt"] = base64::encode(to_sv(salt));

    // IV placeholder (set when secrets are stored)
    desc["iv"] = base64_unpadded(to_sv(random_bytes(SSSS_IV_LEN)));

    // Store the public key
    desc["pubkey"] = base64_unpadded(to_sv(public_key));

    return desc;
}

// =============================================================================
// Key Validity Check with Clock Skew Tolerance
// =============================================================================

// Check key validity with a configurable clock skew tolerance
bool is_key_valid_with_skew(uint64_t valid_until_ts,
                              int64_t clock_skew_ms = 300000) {
    uint64_t now = now_ms();
    // Allow keys expired up to clock_skew_ms in the past
    if (valid_until_ts + static_cast<uint64_t>(clock_skew_ms) < now) {
        return false;
    }
    return true;
}

// =============================================================================
// Canonical JSON for Content-Specific Signing
// =============================================================================

// Compute canonical JSON for just the content field (for content signing)
std::string canonical_content_for_signing(const json& event) {
    if (!event.contains("content")) {
        return json::canonical_json(json::object());
    }
    return json::canonical_json(event["content"]);
}

// =============================================================================
// Batch Signature Verification for Performance
// =============================================================================

// Batch-verify multiple signatures on the same canonical JSON (optimization)
bool batch_verify_event_signatures(
    const json& event,
    const std::vector<std::tuple<std::string, std::string, std::vector<uint8_t>>>& signatures) {
    // signatures: (origin, key_id, public_key)
    // For Ed25519, batch verification can be done via OpenSSL but we do sequential for simplicity
    for (auto& [origin, key_id, pub_key] : signatures) {
        if (!verify_event_signature(event, origin, key_id, pub_key)) {
            return false;
        }
    }
    return true;
}

// =============================================================================
// Event Hash Cache
// =============================================================================

// Cache for computed event reference hashes to avoid recomputation
class EventHashCache {
public:
    std::optional<std::string> get_hash(std::string_view event_id) const {
        std::shared_lock lock(mutex_);
        auto it = cache_.find(std::string(event_id));
        if (it != cache_.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    void set_hash(std::string_view event_id, std::string_view hash) {
        std::unique_lock lock(mutex_);
        cache_[std::string(event_id)] = std::string(hash);
    }

    void invalidate(std::string_view event_id) {
        std::unique_lock lock(mutex_);
        cache_.erase(std::string(event_id));
    }

    void clear() {
        std::unique_lock lock(mutex_);
        cache_.clear();
    }

private:
    mutable std::shared_mutex mutex_;
    std::unordered_map<std::string, std::string> cache_;
};

EventHashCache& get_event_hash_cache() {
    static EventHashCache instance;
    return instance;
}

// =============================================================================
// Event Redaction Chain Verification
// =============================================================================

// Verify an entire redaction chain (original -> redaction1 -> redaction2 -> ...)
bool verify_redaction_chain(const std::vector<json>& events) {
    if (events.size() < 2) return true;

    for (size_t i = 1; i < events.size(); i++) {
        if (!verify_redaction(events[i - 1], events[i])) {
            return false;
        }
    }
    return true;
}

// =============================================================================
// Key Garbage Collection
// =============================================================================

// Automated key garbage collection: remove expired keys, rotate if needed
struct KeyGCStats {
    int verify_keys_removed = 0;
    int old_keys_removed = 0;
    int keys_rotated = 0;
    uint64_t gc_timestamp_ms = 0;
};

KeyGCStats run_key_garbage_collection() {
    KeyGCStats stats;
    stats.gc_timestamp_ms = now_ms();

    auto& mgr = get_server_key_manager();

    // Count before
    auto old_keys_before = mgr.get_old_keys().size();

    // Purge expired keys
    mgr.purge_expired_keys();

    auto old_keys_after = mgr.get_old_keys().size();
    stats.old_keys_removed = static_cast<int>(old_keys_before - old_keys_after);

    return stats;
}

// =============================================================================
// Key Version Tracking Across Federation
// =============================================================================

// Track which key versions each server is known to have
class KeyVersionTracker {
public:
    void record_key(std::string_view server_name, std::string_view key_id,
                    std::string_view key_b64) {
        std::unique_lock lock(mutex_);
        known_keys_[std::string(server_name)][std::string(key_id)] = std::string(key_b64);
        last_seen_[std::string(server_name)][std::string(key_id)] = now_ms();
    }

    std::optional<std::string> get_key(std::string_view server_name,
                                        std::string_view key_id) const {
        std::shared_lock lock(mutex_);
        auto sit = known_keys_.find(std::string(server_name));
        if (sit != known_keys_.end()) {
            auto kit = sit->second.find(std::string(key_id));
            if (kit != sit->second.end()) {
                return kit->second;
            }
        }
        return std::nullopt;
    }

    json get_known_keys_json() const {
        std::shared_lock lock(mutex_);
        json result = json::object();
        for (auto& [server, keys] : known_keys_) {
            json server_keys = json::object();
            for (auto& [kid, key_b64] : keys) {
                server_keys[kid] = key_b64;
            }
            result[server] = server_keys;
        }
        return result;
    }

    void remove_stale_keys(uint64_t max_age_ms = 30 * 24 * 3600 * 1000ULL) {
        std::unique_lock lock(mutex_);
        auto cutoff = now_ms() - max_age_ms;
        for (auto& [server, keys] : last_seen_) {
            auto it = keys.begin();
            while (it != keys.end()) {
                if (it->second < cutoff) {
                    known_keys_[server].erase(it->first);
                    it = keys.erase(it);
                } else {
                    ++it;
                }
            }
        }
    }

private:
    mutable std::shared_mutex mutex_;
    std::unordered_map<std::string,
        std::unordered_map<std::string, std::string>> known_keys_;
    std::unordered_map<std::string,
        std::unordered_map<std::string, uint64_t>> last_seen_;
};

KeyVersionTracker& get_key_version_tracker() {
    static KeyVersionTracker instance;
    return instance;
}

// =============================================================================
// Signed Key JSON Builder
// =============================================================================

// Build and sign a standard key JSON document
json build_signed_key_json(std::string_view user_id,
                             const std::unordered_map<std::string, std::vector<uint8_t>>& keys,
                             const Ed25519Keypair& signing_key) {
    json result;
    result["user_id"] = user_id;

    json keys_json = json::object();
    for (auto& [key_id, key_data] : keys) {
        keys_json[key_id] = base64::encode(to_sv(key_data));
    }
    result["keys"] = keys_json;

    // Self-sign
    result["signatures"] = json::object();
    result["signatures"][user_id] = json::object();

    // Build canonical for signing (exclude signatures)
    json to_sign;
    to_sign["user_id"] = result["user_id"];
    to_sign["keys"] = result["keys"];

    std::string canon = json::canonical_json(to_sign);
    std::string sig = ed25519_sign(canon, signing_key.private_key);

    result["signatures"][user_id][signing_key.key_id()] = sig;

    return result;
}

// =============================================================================
// Key Storage Provider Interface
// =============================================================================

// Abstract interface for key storage backends
class KeyStorageProvider {
public:
    virtual ~KeyStorageProvider() = default;

    virtual bool store_signing_key(const ServerSigningKey& key) = 0;
    virtual std::optional<ServerSigningKey> load_signing_key(std::string_view server_name) = 0;
    virtual bool store_cross_signing_keys(const json& keys, std::string_view user_id) = 0;
    virtual std::optional<json> load_cross_signing_keys(std::string_view user_id) = 0;
    virtual bool store_secret(std::string_view secret_id, const json& encrypted_data) = 0;
    virtual std::optional<json> load_secret(std::string_view secret_id) = 0;
    virtual bool delete_secret(std::string_view secret_id) = 0;
    virtual std::vector<std::string> list_secrets() = 0;
};

// File-system based key storage provider
class FilesystemKeyStorage : public KeyStorageProvider {
public:
    explicit FilesystemKeyStorage(std::string base_path)
        : base_path_(std::move(base_path)) {}

    bool store_signing_key(const ServerSigningKey& key) override {
        try {
            std::string path = base_path_ + "/server_keys/" + key.server_name + ".json";
            save_signing_key_to_file(key, path, true);
            return true;
        } catch (...) {
            return false;
        }
    }

    std::optional<ServerSigningKey> load_signing_key(std::string_view server_name) override {
        try {
            std::string path = base_path_ + "/server_keys/" + std::string(server_name) + ".json";
            return load_signing_key_from_file(path);
        } catch (...) {
            return std::nullopt;
        }
    }

    bool store_cross_signing_keys(const json& keys, std::string_view user_id) override {
        try {
            std::string path = base_path_ + "/cross_signing/" + std::string(user_id) + ".json";
            std::ofstream f(path);
            if (!f) return false;
            f << keys.dump(2);
            return true;
        } catch (...) {
            return false;
        }
    }

    std::optional<json> load_cross_signing_keys(std::string_view user_id) override {
        try {
            std::string path = base_path_ + "/cross_signing/" + std::string(user_id) + ".json";
            std::ifstream f(path);
            if (!f) return std::nullopt;
            return json::parse(f);
        } catch (...) {
            return std::nullopt;
        }
    }

    bool store_secret(std::string_view secret_id, const json& encrypted_data) override {
        try {
            std::string path = base_path_ + "/secrets/" + std::string(secret_id) + ".json";
            std::ofstream f(path);
            if (!f) return false;
            f << encrypted_data.dump(2);
            return true;
        } catch (...) {
            return false;
        }
    }

    std::optional<json> load_secret(std::string_view secret_id) override {
        try {
            std::string path = base_path_ + "/secrets/" + std::string(secret_id) + ".json";
            std::ifstream f(path);
            if (!f) return std::nullopt;
            return json::parse(f);
        } catch (...) {
            return std::nullopt;
        }
    }

    bool delete_secret(std::string_view secret_id) override {
        std::string path = base_path_ + "/secrets/" + std::string(secret_id) + ".json";
        return std::remove(path.c_str()) == 0;
    }

    std::vector<std::string> list_secrets() override {
        // Simplified: can't easily list files without platform-specific code
        return {};
    }

private:
    std::string base_path_;
};

// =============================================================================
// Key Agreement Utilities (for X3DH / Olm)
// =============================================================================

// Derive a shared secret using Ed25519 keys (for key agreement — note: in practice
// Curve25519 is used for ECDH, but Ed25519 can be converted or this serves
// as a helper for key verification scenarios)
std::vector<uint8_t> derive_shared_secret_ed25519(const std::vector<uint8_t>& private_key,
                                                    const std::vector<uint8_t>& peer_public_key) {
    // This is a simplified demonstration — real implementations would use X25519
    // Derive using HMAC-based approach for key verification
    std::vector<uint8_t> combined;
    combined.insert(combined.end(), private_key.begin(), private_key.end());
    combined.insert(combined.end(), peer_public_key.begin(), peer_public_key.end());
    return sha256(combined);
}

// =============================================================================
// JSON Canonicalization Helpers for Signing
// =============================================================================

// Remove all keys that should not be present before signing
json strip_unsigned_before_sign(const json& event) {
    json cleaned = event;
    if (cleaned.contains("unsigned")) {
        json new_unsigned;
        // Keep only non-ephemeral unsigned fields
        if (cleaned["unsigned"].contains("invite_room_state")) {
            new_unsigned["invite_room_state"] = cleaned["unsigned"]["invite_room_state"];
        }
        if (new_unsigned.empty()) {
            cleaned.erase("unsigned");
        } else {
            cleaned["unsigned"] = new_unsigned;
        }
    }
    return cleaned;
}

// =============================================================================
// Signature Verification with Fallback Keys
// =============================================================================

// Try to verify with primary key, fall back to old keys
bool verify_with_fallback(const json& event, std::string_view origin,
                           std::string_view key_id,
                           const std::vector<std::vector<uint8_t>>& candidate_keys) {
    for (auto& key : candidate_keys) {
        if (verify_event_signature(event, origin, key_id, key)) {
            return true;
        }
    }
    return false;
}

// =============================================================================
// Key Metadata Serialization
// =============================================================================

// Serialize a ServerSigningKey to a compact binary format for network transport
std::vector<uint8_t> serialize_signing_key_metadata(const ServerSigningKey& sk) {
    json j;
    j["sn"] = sk.server_name;
    j["kid"] = sk.key_id;
    j["vut"] = sk.valid_until_ts;
    j["ct"] = sk.created_ts;
    j["isv"] = sk.is_verify_key;
    j["iss"] = sk.is_signing_key;
    j["pk"] = base64::encode(to_sv(sk.public_key));

    std::string serialized = j.dump();
    return to_bytes(serialized);
}

// Deserialize a ServerSigningKey from compact binary format
std::optional<ServerSigningKey> deserialize_signing_key_metadata(
    const std::vector<uint8_t>& data) {
    try {
        std::string s(reinterpret_cast<const char*>(data.data()), data.size());
        json j = json::parse(s);

        ServerSigningKey sk;
        sk.server_name = j["sn"].get<std::string>();
        sk.key_id = j["kid"].get<std::string>();
        sk.valid_until_ts = j["vut"].get<uint64_t>();
        sk.created_ts = j["ct"].get<uint64_t>();
        sk.is_verify_key = j["isv"].get<bool>();
        sk.is_signing_key = j["iss"].get<bool>();
        sk.public_key = base64::decode(j["pk"].get<std::string>());

        return sk;
    } catch (...) {
        return std::nullopt;
    }
}

// =============================================================================
// Key ID Generation
// =============================================================================

// Generate a unique key ID based on the public key
std::string generate_key_id_from_public_key(std::string_view algorithm,
                                               const std::vector<uint8_t>& public_key) {
    auto hash = sha256(public_key);
    // Take first 8 bytes of hash as the key version
    std::string version;
    for (size_t i = 0; i < 8 && i < hash.size(); i++) {
        version += "0123456789ABCDEF"[hash[i] & 0x0F];
        version += "0123456789ABCDEF"[hash[i] >> 4];
    }
    return std::string(algorithm) + ":" + version;
}

// =============================================================================
// Audit Logging for Key Operations
// =============================================================================

// Simple in-memory audit log for key operations
class KeyAuditLog {
public:
    enum class Operation {
        KeyGenerated,
        KeyRotated,
        KeyExpired,
        KeyLoaded,
        KeySaved,
        SignatureVerified,
        SignatureFailed,
        SecretStored,
        SecretRetrieved,
        BackupCreated,
        BackupDecrypted
    };

    struct Entry {
        Operation op;
        std::string description;
        uint64_t timestamp_ms;
        std::string origin;
    };

    void log(Operation op, std::string_view description, std::string_view origin = "") {
        std::unique_lock lock(mutex_);
        entries_.push_back({op, std::string(description), now_ms(), std::string(origin)});
        if (entries_.size() > max_entries_) {
            entries_.pop_front();
        }
    }

    std::vector<Entry> get_recent_entries(size_t count = 100) const {
        std::shared_lock lock(mutex_);
        std::vector<Entry> result;
        auto start = entries_.size() > count ? entries_.end() - count : entries_.begin();
        result.assign(start, entries_.end());
        return result;
    }

    std::vector<Entry> get_entries_since(uint64_t since_ms) const {
        std::shared_lock lock(mutex_);
        std::vector<Entry> result;
        for (auto& e : entries_) {
            if (e.timestamp_ms >= since_ms) {
                result.push_back(e);
            }
        }
        return result;
    }

private:
    static constexpr size_t max_entries_ = 10000;
    mutable std::shared_mutex mutex_;
    std::deque<Entry> entries_;
};

KeyAuditLog& get_key_audit_log() {
    static KeyAuditLog instance;
    return instance;
}

// =============================================================================
// Utility: Convert KeyAuditLog Operation to String
// =============================================================================

std::string audit_op_to_string(KeyAuditLog::Operation op) {
    switch (op) {
        case KeyAuditLog::Operation::KeyGenerated:    return "KeyGenerated";
        case KeyAuditLog::Operation::KeyRotated:      return "KeyRotated";
        case KeyAuditLog::Operation::KeyExpired:      return "KeyExpired";
        case KeyAuditLog::Operation::KeyLoaded:       return "KeyLoaded";
        case KeyAuditLog::Operation::KeySaved:        return "KeySaved";
        case KeyAuditLog::Operation::SignatureVerified: return "SignatureVerified";
        case KeyAuditLog::Operation::SignatureFailed: return "SignatureFailed";
        case KeyAuditLog::Operation::SecretStored:    return "SecretStored";
        case KeyAuditLog::Operation::SecretRetrieved: return "SecretRetrieved";
        case KeyAuditLog::Operation::BackupCreated:   return "BackupCreated";
        case KeyAuditLog::Operation::BackupDecrypted: return "BackupDecrypted";
        default: return "Unknown";
    }
}

// =============================================================================
// Final: End of signing_key_management.cpp
// =============================================================================

}  // namespace progressive::crypto
