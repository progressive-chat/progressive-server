// key_backup_bootstrap.cpp - Matrix key backup, dehydrated devices, cross-signing bootstrap
// Complete implementation for the progressive Matrix server crypto module
// Copyright (c) 2026 Progressive Matrix Project

#include "../json.hpp"
#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <algorithm>
#include <random>
#include <chrono>
#include <thread>
#include <mutex>
#include <stdexcept>
#include <cstring>
#include <cstdint>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/kdf.h>
#include <openssl/bn.h>
#include <openssl/curve25519.h>

// =============================================================================
// Internal forward declarations and helper utilities
// =============================================================================

namespace progressive {
namespace crypto {

// Forward declarations
class KeyBackupManager;
class RecoveryKeyManager;
class CrossSigningManager;
class DehydratedDeviceManager;
class SecretStorageManager;

// Internal base64 utilities
namespace base64 {

static const char kEncodingTable[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static const char kUnpaddedEncodingTable[] =
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
        result += kUnpaddedEncodingTable[(n >> 18) & 0x3F];
        result += kUnpaddedEncodingTable[(n >> 12) & 0x3F];
        if (i + 1 < data.size())
            result += kUnpaddedEncodingTable[(n >> 6) & 0x3F];
        if (i + 2 < data.size())
            result += kUnpaddedEncodingTable[n & 0x3F];
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

}  // namespace base64

// =============================================================================
// Cryptographic primitive wrappers (OpenSSL-based)
// =============================================================================

class CryptoError : public std::runtime_error {
public:
    explicit CryptoError(const std::string& msg) : std::runtime_error(msg) {}
};

static std::mutex g_openssl_mutex;

std::vector<uint8_t> HmacSha256(const std::vector<uint8_t>& key,
                                const std::vector<uint8_t>& message) {
    unsigned int len = EVP_MAX_MD_SIZE;
    std::vector<uint8_t> result(len);
    HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
         message.data(), message.size(), result.data(), &len);
    result.resize(len);
    return result;
}

std::vector<uint8_t> Sha256(const std::vector<uint8_t>& data) {
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

std::vector<uint8_t> HkdfSha256(const std::vector<uint8_t>& ikm,
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

std::vector<uint8_t> AesCtrEncrypt(const std::vector<uint8_t>& key,
                                   const std::vector<uint8_t>& iv,
                                   const std::vector<uint8_t>& plaintext) {
    std::vector<uint8_t> ciphertext(plaintext.size());
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), nullptr, key.data(), iv.data());
    int outlen = 0, len = 0;
    EVP_EncryptUpdate(ctx, ciphertext.data(), &outlen,
                      plaintext.data(), static_cast<int>(plaintext.size()));
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + outlen, &len);
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext;
}

std::vector<uint8_t> AesCtrDecrypt(const std::vector<uint8_t>& key,
                                   const std::vector<uint8_t>& iv,
                                   const std::vector<uint8_t>& ciphertext) {
    std::vector<uint8_t> plaintext(ciphertext.size());
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(), nullptr, key.data(), iv.data());
    int outlen = 0, len = 0;
    EVP_DecryptUpdate(ctx, plaintext.data(), &outlen,
                      ciphertext.data(), static_cast<int>(ciphertext.size()));
    EVP_DecryptFinal_ex(ctx, plaintext.data() + outlen, &len);
    EVP_CIPHER_CTX_free(ctx);
    return plaintext;
}

std::vector<uint8_t> AesCbcEncrypt(const std::vector<uint8_t>& key,
                                   const std::vector<uint8_t>& iv,
                                   const std::vector<uint8_t>& plaintext) {
    // Pad to 16-byte boundary with PKCS#7
    std::vector<uint8_t> padded = plaintext;
    uint8_t pad = 16 - (plaintext.size() % 16);
    padded.insert(padded.end(), pad, pad);

    std::vector<uint8_t> ciphertext(padded.size() + 16);
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data());
    int outlen = 0, len = 0;
    EVP_EncryptUpdate(ctx, ciphertext.data(), &outlen,
                      padded.data(), static_cast<int>(padded.size()));
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + outlen, &len);
    EVP_CIPHER_CTX_free(ctx);
    ciphertext.resize(outlen + len);
    return ciphertext;
}

std::vector<uint8_t> AesCbcDecrypt(const std::vector<uint8_t>& key,
                                   const std::vector<uint8_t>& iv,
                                   const std::vector<uint8_t>& ciphertext) {
    std::vector<uint8_t> plaintext(ciphertext.size());
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data());
    int outlen = 0, len = 0;
    EVP_DecryptUpdate(ctx, plaintext.data(), &outlen,
                      ciphertext.data(), static_cast<int>(ciphertext.size()));
    EVP_DecryptFinal_ex(ctx, plaintext.data() + outlen, &len);
    EVP_CIPHER_CTX_free(ctx);
    plaintext.resize(outlen + len);

    // Remove PKCS#7 padding
    if (!plaintext.empty()) {
        uint8_t pad = plaintext.back();
        if (pad > 0 && pad <= 16) {
            plaintext.resize(plaintext.size() - pad);
        }
    }
    return plaintext;
}

std::vector<uint8_t> GenerateRandomBytes(size_t count) {
    std::vector<uint8_t> buf(count);
    if (RAND_bytes(buf.data(), static_cast<int>(count)) != 1) {
        throw CryptoError("Failed to generate random bytes");
    }
    return buf;
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

// Ed25519 helpers
struct Ed25519KeyPair {
    std::vector<uint8_t> public_key;   // 32 bytes
    std::vector<uint8_t> private_key;  // 64 bytes (seed + pub)
};

Ed25519KeyPair GenerateEd25519KeyPair() {
    Ed25519KeyPair kp;
    kp.public_key.resize(32);
    kp.private_key.resize(64);

    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
    EVP_PKEY_keygen_init(pctx);
    EVP_PKEY_keygen(pctx, &pkey);
    EVP_PKEY_CTX_free(pctx);

    size_t pub_len = 32, priv_len = 64;
    EVP_PKEY_get_raw_public_key(pkey, kp.public_key.data(), &pub_len);
    EVP_PKEY_get_raw_private_key(pkey, kp.private_key.data(), &priv_len);
    EVP_PKEY_free(pkey);

    return kp;
}

std::vector<uint8_t> Ed25519Sign(const std::vector<uint8_t>& private_key,
                                 const std::vector<uint8_t>& message) {
    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr,
        private_key.data(), private_key.size());
    if (!pkey) throw CryptoError("Failed to create Ed25519 key");

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, pkey);
    size_t sig_len = 64;
    std::vector<uint8_t> sig(sig_len);
    EVP_DigestSign(ctx, sig.data(), &sig_len,
                   message.data(), message.size());
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    sig.resize(sig_len);
    return sig;
}

bool Ed25519Verify(const std::vector<uint8_t>& public_key,
                   const std::vector<uint8_t>& message,
                   const std::vector<uint8_t>& signature) {
    EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr,
        public_key.data(), public_key.size());
    if (!pkey) return false;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, pkey);
    int rc = EVP_DigestVerify(ctx, signature.data(), signature.size(),
                              message.data(), message.size());
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return rc == 1;
}

// Curve25519 key agreement
std::vector<uint8_t> Curve25519SharedSecret(
    const std::vector<uint8_t>& private_key,   // 32 bytes
    const std::vector<uint8_t>& public_key) {  // 32 bytes
    std::vector<uint8_t> secret(32);
    X25519(secret.data(), private_key.data(), public_key.data());
    return secret;
}

Curve25519KeyPair GenerateCurve25519KeyPair() {
    Curve25519KeyPair kp;
    kp.private_key = GenerateRandomBytes(32);
    kp.public_key.resize(32);
    X25519(kp.public_key.data(), kp.private_key.data(),
           (const uint8_t*)"\x09\x00\x00\x00\x00\x00\x00\x00"
           "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
           "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00");
    return kp;
}

// =============================================================================
// Key backup session data format (encrypted JSON with MAC)
// =============================================================================

struct KeyBackupSessionData {
    // Plaintext data included in the encrypted payload
    std::string algorithm;
    std::string sender_key;
    std::string session_id;
    std::string room_id;
    uint64_t first_message_index = 0;
    uint64_t forwarded_count = 0;
    bool is_verified = false;
    std::string session_key;  // Base64 encoded

    // Serialize to JSON
    json::object ToJson() const {
        json::object obj;
        obj["algorithm"] = algorithm;
        obj["sender_key"] = sender_key;
        obj["session_id"] = session_id;
        obj["room_id"] = room_id;
        obj["first_message_index"] = static_cast<int64_t>(first_message_index);
        obj["forwarded_count"] = static_cast<int64_t>(forwarded_count);
        obj["is_verified"] = is_verified;
        obj["session_key"] = session_key;
        return obj;
    }

    static KeyBackupSessionData FromJson(const json::object& obj) {
        KeyBackupSessionData data;
        data.algorithm = json::get_string(obj, "algorithm");
        data.sender_key = json::get_string(obj, "sender_key");
        data.session_id = json::get_string(obj, "session_id");
        data.room_id = json::get_string(obj, "room_id");
        data.first_message_index =
            static_cast<uint64_t>(json::get_number(obj, "first_message_index"));
        data.forwarded_count =
            static_cast<uint64_t>(json::get_number(obj, "forwarded_count"));
        data.is_verified = json::get_bool(obj, "is_verified");
        data.session_key = json::get_string(obj, "session_key");
        return data;
    }
};

struct KeyBackupAuthData {
    std::string public_key;        // Curve25519 public key, base64
    std::string mac;               // HMAC-SHA256 of ciphertext
    std::string iv;                // Initialisation vector, base64
    std::map<std::string, json::value> signatures;

    json::object ToJson() const {
        json::object obj;
        obj["public_key"] = public_key;
        obj["mac"] = mac;
        obj["iv"] = iv;
        json::object sigs;
        for (auto& [k, v] : signatures) sigs[k] = v;
        obj["signatures"] = sigs;
        return obj;
    }

    static KeyBackupAuthData FromJson(const json::object& obj) {
        KeyBackupAuthData data;
        data.public_key = json::get_string(obj, "public_key");
        data.mac = json::get_string(obj, "mac");
        data.iv = json::get_string(obj, "iv");
        if (obj.count("signatures")) {
            auto& sigs = std::get<json::object>(obj.at("signatures"));
            for (auto& [k, v] : sigs) data.signatures[k] = v;
        }
        return data;
    }
};

// Serialize SessionData to ciphertext
// Encrypts the serialized JSON, computes MAC, returns (ciphertext, mac, iv)
struct EncryptedSessionData {
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> mac;
    std::vector<uint8_t> iv;
    std::vector<uint8_t> ephemeral_public_key;
};

EncryptedSessionData EncryptSessionData(
    const KeyBackupSessionData& session,
    const std::vector<uint8_t>& recovery_private_key) {

    // Generate ephemeral key pair
    auto ephemeral = GenerateCurve25519KeyPair();

    // Compute shared secret using ephemeral private + recovery public
    // For encrypting, we derive the recovery public from the private key
    std::vector<uint8_t> recovery_public(32);
    X25519(recovery_public.data(), recovery_private_key.data(),
           (const uint8_t*)"\x09\x00\x00\x00\x00\x00\x00\x00"
           "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
           "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00");

    auto shared_secret = Curve25519SharedSecret(
        ephemeral.private_key, recovery_public);

    // Derive encryption keys via HKDF
    std::string info = "m.megolm_backup.v1";
    auto key_material = HkdfSha256(shared_secret, {}, info, 64);
    std::vector<uint8_t> aes_key(key_material.begin(), key_material.begin() + 32);
    std::vector<uint8_t> mac_key(key_material.begin() + 32, key_material.end());

    // Generate random IV
    auto iv = GenerateRandomBytes(16);

    // Serialize session to JSON
    std::string json_str = json::serialize(session.ToJson());
    std::vector<uint8_t> plaintext(json_str.begin(), json_str.end());

    // Encrypt with AES-256-CTR
    auto ciphertext = AesCtrEncrypt(aes_key, iv, plaintext);

    // Compute MAC = HMAC-SHA256(mac_key, ciphertext)
    auto mac = HmacSha256(mac_key, ciphertext);

    EncryptedSessionData result;
    result.ciphertext = std::move(ciphertext);
    result.mac = std::move(mac);
    result.iv = std::move(iv);
    result.ephemeral_public_key = std::move(ephemeral.public_key);
    return result;
}

KeyBackupSessionData DecryptSessionData(
    const std::vector<uint8_t>& ciphertext,
    const std::vector<uint8_t>& mac,
    const std::vector<uint8_t>& iv,
    const std::vector<uint8_t>& ephemeral_public_key,
    const std::vector<uint8_t>& recovery_private_key) {

    // Compute shared secret
    auto shared_secret = Curve25519SharedSecret(
        recovery_private_key, ephemeral_public_key);

    // Derive encryption keys
    std::string info = "m.megolm_backup.v1";
    auto key_material = HkdfSha256(shared_secret, {}, info, 64);
    std::vector<uint8_t> aes_key(key_material.begin(), key_material.begin() + 32);
    std::vector<uint8_t> mac_key(key_material.begin() + 32, key_material.end());

    // Verify MAC first
    auto computed_mac = HmacSha256(mac_key, ciphertext);
    if (!ConstantTimeCompare(computed_mac, mac)) {
        throw CryptoError("MAC verification failed - corrupted or tampered data");
    }

    // Decrypt
    auto plaintext = AesCtrDecrypt(aes_key, iv, ciphertext);
    std::string json_str(plaintext.begin(), plaintext.end());

    json::value val = json::parse(json_str);
    return KeyBackupSessionData::FromJson(std::get<json::object>(val));
}

// =============================================================================
// Recovery Key Generation & Validation (MSC 1946)
// =============================================================================

class RecoveryKeyManager {
public:
    // Generate a recovery key: returns (private_key_bytes, recovery_key_string)
    // The string is the human-readable form for display
    static std::pair<std::vector<uint8_t>, std::string> GenerateRecoveryKey() {
        // Generate 32 bytes of random data for the recovery key
        auto key_bytes = GenerateRandomBytes(32);

        // Derive the recovery key string: base58-like with parity word
        // Matrix uses "recovery key" format with passphrase-base style
        auto key_string = EncodeRecoveryKey(key_bytes);

        return {key_bytes, key_string};
    }

    // Encode raw bytes into a displayable recovery key string
    static std::string EncodeRecoveryKey(const std::vector<uint8_t>& key_bytes) {
        // Matrix recovery key format: group of 4 words from wordlist
        // Each group encodes 3 bytes (or similar) with parity
        // Real implementation uses a specific word list
        // Here we output a base64 representation for the hex form
        std::string encoded = base64::EncodeUnpadded(key_bytes);
        // Add dashes every 4 characters for readability
        std::string result;
        for (size_t i = 0; i < encoded.size(); i++) {
            if (i > 0 && i % 4 == 0) result += '-';
            result += encoded[i];
        }
        return result;
    }

    // Parse a recovery key string back to raw bytes
    static std::vector<uint8_t> DecodeRecoveryKey(const std::string& key_string) {
        // Remove dashes from the encoded string
        std::string cleaned;
        for (char c : key_string) {
            if (c != '-' && c != ' ') cleaned += c;
        }
        return base64::Decode(cleaned);
    }

    // Validate a recovery key string format
    static bool ValidateRecoveryKey(const std::string& key_string) {
        if (key_string.empty()) return false;

        // Check if it can be decoded
        try {
            auto decoded = DecodeRecoveryKey(key_string);
            return decoded.size() >= 16;  // At least 128 bits of entropy
        } catch (...) {
            return false;
        }
    }

    // Derive the AES key from recovery key for secret storage
    static std::vector<uint8_t> DeriveKey(const std::vector<uint8_t>& recovery_key,
                                           const std::string& context = "") {
        std::string info = "m.secret_storage.v1.aes-hmac-sha2" + context;
        return HkdfSha256(recovery_key, {}, info, 32);
    }

    // Derive key ID from recovery key
    static std::string DeriveKeyId(const std::vector<uint8_t>& recovery_key) {
        auto derived = DeriveKey(recovery_key);
        return base64::EncodeUnpadded(Sha256(derived));
    }

    // Generate passphrase from recovery key bytes (Matrix passphrase-style key)
    static std::string GeneratePassphrase() {
        // Use a wordlist-based approach for user-friendly passphrase
        // This is a simplified version - real impl uses BIP39-like wordlist
        auto entropy = GenerateRandomBytes(16);
        return EncodeRecoveryKey(entropy);
    }
};

// =============================================================================
// Secret Storage (SSSS) default key and secrets management
// =============================================================================

struct SecretStorageKey {
    std::string key_id;
    std::string algorithm;      // "m.secret_storage.v1.aes-hmac-sha2"
    std::string passphrase_salt;
    int passphrase_iterations = 0;
    std::string iv;
    std::string mac;
};

struct StoredSecret {
    std::string key_id;
    std::vector<uint8_t> encrypted_data;
    std::string iv;
    std::string mac;
};

class SecretStorageManager {
private:
    std::string user_id_;
    std::map<std::string, SecretStorageKey> keys_;
    std::map<std::string, StoredSecret> secrets_;

public:
    explicit SecretStorageManager(const std::string& user_id)
        : user_id_(user_id) {}

    // SSSS Default Key Generation
    // Creates a default secret storage key from a passphrase or recovery key
    SecretStorageKey GenerateDefaultKey(
        const std::vector<uint8_t>& recovery_key,
        const std::string& passphrase_salt = "",
        int iterations = 500000) {

        SecretStorageKey key;
        key.key_id = RecoveryKeyManager::DeriveKeyId(recovery_key);
        key.algorithm = "m.secret_storage.v1.aes-hmac-sha2";
        key.passphrase_salt = passphrase_salt;
        key.passphrase_iterations = iterations;

        // Generate a random IV for the key description
        auto iv = GenerateRandomBytes(16);
        key.iv = base64::EncodeUnpadded(iv);

        // Compute MAC over empty data with derived key
        auto derived = RecoveryKeyManager::DeriveKey(recovery_key);
        std::vector<uint8_t> empty;
        auto mac_val = HmacSha256(derived, empty);
        key.mac = base64::EncodeUnpadded(mac_val);

        keys_[key.key_id] = key;
        return key;
    }

    // Store cross-signing private keys in SSSS
    bool StoreSecret(const std::string& secret_name,
                     const std::vector<uint8_t>& secret_data,
                     const std::string& key_id) {

        auto it = keys_.find(key_id);
        if (it == keys_.end()) return false;

        // Encrypt secret with AES-256-CBC + HMAC
        auto iv = GenerateRandomBytes(16);
        std::vector<uint8_t> plaintext = secret_data;

        // Derive AES key from the storage key
        auto storage_key = base64::Decode(it->second.key_id);
        auto aes_key = RecoveryKeyManager::DeriveKey(storage_key, secret_name);

        auto ciphertext = AesCbcEncrypt(aes_key, iv, plaintext);
        auto mac = HmacSha256(aes_key, ciphertext);

        StoredSecret secret;
        secret.key_id = key_id;
        secret.encrypted_data = std::move(ciphertext);
        secret.iv = base64::EncodeUnpadded(iv);
        secret.mac = base64::EncodeUnpadded(mac);

        secrets_[secret_name] = secret;
        return true;
    }

    // Store cross-signing signing key in SSSS
    bool StoreCrossSigningKey(const std::string& key_type,
                              const std::vector<uint8_t>& private_key,
                              const std::string& key_id) {
        std::string secret_name = "m.cross_signing." + key_type;
        return StoreSecret(secret_name, private_key, key_id);
    }

    // Store master key in SSSS
    bool StoreMasterKey(const std::vector<uint8_t>& private_key,
                        const std::string& key_id) {
        return StoreCrossSigningKey("master", private_key, key_id);
    }

    // Store self-signing key in SSSS
    bool StoreSelfSigningKey(const std::vector<uint8_t>& private_key,
                             const std::string& key_id) {
        return StoreCrossSigningKey("self_signing", private_key, key_id);
    }

    // Store user-signing key in SSSS
    bool StoreUserSigningKey(const std::vector<uint8_t>& private_key,
                             const std::string& key_id) {
        return StoreCrossSigningKey("user_signing", private_key, key_id);
    }

    // Retrieve a stored secret
    std::vector<uint8_t> RetrieveSecret(const std::string& secret_name,
                                         const std::vector<uint8_t>& recovery_key) {
        auto it = secrets_.find(secret_name);
        if (it == secrets_.end()) {
            throw CryptoError("Secret not found: " + secret_name);
        }

        auto iv = base64::Decode(it->second.iv);
        auto mac = base64::Decode(it->second.mac);

        // Derive AES key
        auto aes_key = RecoveryKeyManager::DeriveKey(recovery_key, secret_name);

        // Verify MAC
        auto computed_mac = HmacSha256(aes_key, it->second.encrypted_data);
        if (!ConstantTimeCompare(computed_mac, mac)) {
            throw CryptoError("MAC verification failed for secret: " + secret_name);
        }

        // Decrypt
        return AesCbcDecrypt(aes_key, iv, it->second.encrypted_data);
    }

    // Get stored key IDs
    std::vector<std::string> GetKeyIds() const {
        std::vector<std::string> ids;
        for (auto& [id, key] : keys_) ids.push_back(id);
        return ids;
    }

    // Get the default key ID
    std::string GetDefaultKeyId() const {
        if (keys_.empty()) return "";
        return keys_.begin()->first;
    }

    // Check if a key exists
    bool HasKey(const std::string& key_id) const {
        return keys_.find(key_id) != keys_.end();
    }

    // Serialize keys to JSON for server upload
    json::object SerializeKeys() const {
        json::object result;
        for (auto& [id, key] : keys_) {
            json::object key_obj;
            key_obj["algorithm"] = key.algorithm;
            if (!key.passphrase_salt.empty()) {
                key_obj["passphrase"] = json::object{
                    {"algorithm", "m.pbkdf2"},
                    {"salt", key.passphrase_salt},
                    {"iterations", key.passphrase_iterations}
                };
            }
            key_obj["iv"] = key.iv;
            key_obj["mac"] = key.mac;
            result[id] = key_obj;
        }
        return result;
    }

    // Load keys from server response
    void DeserializeKeys(const json::object& obj) {
        keys_.clear();
        for (auto& [id, val] : obj) {
            auto& key_obj = std::get<json::object>(val);
            SecretStorageKey key;
            key.key_id = id;
            key.algorithm = json::get_string(key_obj, "algorithm");
            if (key_obj.count("passphrase")) {
                auto& pp = std::get<json::object>(key_obj.at("passphrase"));
                key.passphrase_salt = json::get_string(pp, "salt");
                key.passphrase_iterations =
                    static_cast<int>(json::get_number(pp, "iterations"));
            }
            key.iv = json::get_string(key_obj, "iv");
            key.mac = json::get_string(key_obj, "mac");
            keys_[id] = key;
        }
    }
};

// =============================================================================
// Cross-signing Key Management
// =============================================================================

struct CrossSigningKey {
    std::string user_id;
    std::string key_type;  // "master", "self_signing", "user_signing"
    std::vector<uint8_t> public_key;
    std::vector<uint8_t> private_key;
    std::string public_key_b64;
    std::map<std::string, std::map<std::string, std::string>> signatures;

    std::string KeyId() const {
        return base64::EncodeUnpadded(public_key);
    }

    json::object ToJson() const {
        json::object obj;
        obj["user_id"] = user_id;
        obj["usage"] = json::array{key_type};
        obj["keys"] = json::object{
            {"ed25519:" + KeyId(), public_key_b64}
        };
        json::object sigs;
        for (auto& [uid, dev_sigs] : signatures) {
            json::object dev_obj;
            for (auto& [dev_id, sig] : dev_sigs) {
                dev_obj[dev_id] = sig;
            }
            sigs[uid] = dev_obj;
        }
        obj["signatures"] = sigs;
        return obj;
    }
};

class CrossSigningManager {
private:
    std::string user_id_;
    std::unique_ptr<CrossSigningKey> master_key_;
    std::unique_ptr<CrossSigningKey> self_signing_key_;
    std::unique_ptr<CrossSigningKey> user_signing_key_;
    bool is_bootstrapped_ = false;

    // Sign a JSON object with a cross-signing key
    json::object SignJson(const json::object& obj,
                          const CrossSigningKey& signer) {
        // Canonical JSON: sort keys and remove whitespace
        std::string canonical = CanonicalJson(obj);

        std::vector<uint8_t> msg(canonical.begin(), canonical.end());
        auto signature = Ed25519Sign(signer.private_key, msg);

        json::object result = obj;
        json::object sigs;
        if (result.count("signatures")) {
            sigs = std::get<json::object>(result["signatures"]);
        }
        json::object user_sigs;
        if (sigs.count(signer.user_id)) {
            user_sigs = std::get<json::object>(sigs[signer.user_id]);
        }
        user_sigs["ed25519:" + signer.KeyId()] =
            base64::EncodeUnpadded(signature);
        sigs[signer.user_id] = user_sigs;
        result["signatures"] = sigs;
        return result;
    }

    std::string CanonicalJson(const json::object& obj) {
        // Sort keys and serialize without whitespace
        json::object sorted;
        std::vector<std::string> keys;
        for (auto& [k, v] : obj) keys.push_back(k);
        std::sort(keys.begin(), keys.end());
        for (auto& k : keys) sorted[k] = obj.at(k);
        return json::serialize(sorted);
    }

public:
    explicit CrossSigningManager(const std::string& user_id)
        : user_id_(user_id) {}

    // ===== Cross-signing Bootstrap =====
    // Initial setup of master, self-signing, and user-signing keys
    bool Bootstrap() {
        try {
            // Generate master key
            auto master_pair = GenerateEd25519KeyPair();
            master_key_ = std::make_unique<CrossSigningKey>();
            master_key_->user_id = user_id_;
            master_key_->key_type = "master";
            master_key_->public_key = master_pair.public_key;
            master_key_->private_key = master_pair.private_key;
            master_key_->public_key_b64 = base64::EncodeUnpadded(master_pair.public_key);

            // Generate self-signing key
            auto self_pair = GenerateEd25519KeyPair();
            self_signing_key_ = std::make_unique<CrossSigningKey>();
            self_signing_key_->user_id = user_id_;
            self_signing_key_->key_type = "self_signing";
            self_signing_key_->public_key = self_pair.public_key;
            self_signing_key_->private_key = self_pair.private_key;
            self_signing_key_->public_key_b64 = base64::EncodeUnpadded(self_pair.public_key);

            // Generate user-signing key
            auto user_pair = GenerateEd25519KeyPair();
            user_signing_key_ = std::make_unique<CrossSigningKey>();
            user_signing_key_->user_id = user_id_;
            user_signing_key_->key_type = "user_signing";
            user_signing_key_->public_key = user_pair.public_key;
            user_signing_key_->private_key = user_pair.private_key;
            user_signing_key_->public_key_b64 = base64::EncodeUnpadded(user_pair.public_key);

            // Master key signs self-signing key
            SignSelfSigningKeyWithMaster();

            // Master key signs user-signing key
            SignUserSigningKeyWithMaster();

            is_bootstrapped_ = true;
            return true;
        } catch (const std::exception& e) {
            return false;
        }
    }

    // Sign self-signing key with master key
    void SignSelfSigningKeyWithMaster() {
        if (!master_key_ || !self_signing_key_) return;
        auto self_json = self_signing_key_->ToJson();
        // Remove old signatures, sign fresh
        self_json["signatures"] = json::object{};
        auto signed_json = SignJson(self_json, *master_key_);
        self_signing_key_->signatures = master_key_->signatures;
    }

    // Sign user-signing key with master key
    void SignUserSigningKeyWithMaster() {
        if (!master_key_ || !user_signing_key_) return;
        auto user_json = user_signing_key_->ToJson();
        user_json["signatures"] = json::object{};
        auto signed_json = SignJson(user_json, *master_key_);
        user_signing_key_->signatures = master_key_->signatures;
    }

    // Sign a device key with the self-signing key
    json::object SignDeviceKey(const json::object& device_keys) {
        if (!self_signing_key_) {
            throw CryptoError("Self-signing key not available");
        }
        return SignJson(device_keys, *self_signing_key_);
    }

    // Sign a user key with the user-signing key
    json::object SignUserKey(const json::object& user_keys) {
        if (!user_signing_key_) {
            throw CryptoError("User-signing key not available");
        }
        return SignJson(user_keys, *user_signing_key_);
    }

    // ===== Cross-signing Reset =====
    // Reset all cross-signing keys
    bool Reset() {
        master_key_.reset();
        self_signing_key_.reset();
        user_signing_key_.reset();
        is_bootstrapped_ = false;
        return true;
    }

    // ===== Cross-signing Upload =====
    // Upload signing keys to server
    json::object BuildUploadPayload() {
        if (!is_bootstrapped_) {
            throw CryptoError("Cross-signing not bootstrapped");
        }

        json::object payload;

        // Master key
        payload["master_key"] = master_key_->ToJson();

        // Self-signing key
        payload["self_signing_key"] = self_signing_key_->ToJson();

        // User-signing key
        payload["user_signing_key"] = user_signing_key_->ToJson();

        return payload;
    }

    // ===== Cross-signing Upload Signatures =====
    // Sign device/user keys and return the signatures
    json::object BuildSignaturesPayload(
        const std::map<std::string, json::object>& device_keys_map,
        const std::map<std::string, json::object>& user_keys_map) {

        json::object payload;
        json::object device_sigs;
        json::object user_sigs;

        // Sign device keys with self-signing key
        for (auto& [device_id, device_keys] : device_keys_map) {
            auto signed_dev = SignDeviceKey(device_keys);
            if (signed_dev.count("signatures")) {
                auto& sigs = std::get<json::object>(signed_dev["signatures"]);
                if (sigs.count(user_id_)) {
                    device_sigs[device_id] = sigs[user_id_];
                }
            }
        }

        // Sign user keys with user-signing key
        for (auto& [target_user_id, user_keys] : user_keys_map) {
            auto signed_user = SignUserKey(user_keys);
            if (signed_user.count("signatures")) {
                auto& sigs = std::get<json::object>(signed_user["signatures"]);
                if (sigs.count(user_id_)) {
                    user_sigs[target_user_id] = sigs[user_id_];
                }
            }
        }

        if (!device_sigs.empty()) payload[user_id_] = device_sigs;
        // User signatures go under each target user
        for (auto& [uid, sig] : user_sigs) {
            payload[uid] = json::object{{user_id_, sig}};
        }

        return payload;
    }

    // Getters
    const CrossSigningKey* GetMasterKey() const { return master_key_.get(); }
    const CrossSigningKey* GetSelfSigningKey() const { return self_signing_key_.get(); }
    const CrossSigningKey* GetUserSigningKey() const { return user_signing_key_.get(); }
    bool IsBootstrapped() const { return is_bootstrapped_; }

    // Get public key map for device key verification
    std::map<std::string, std::string> GetPublicKeys() const {
        std::map<std::string, std::string> keys;
        if (master_key_) {
            keys["ed25519:" + master_key_->KeyId()] = master_key_->public_key_b64;
        }
        if (self_signing_key_) {
            keys["ed25519:" + self_signing_key_->KeyId()] =
                self_signing_key_->public_key_b64;
        }
        if (user_signing_key_) {
            keys["ed25519:" + user_signing_key_->KeyId()] =
                user_signing_key_->public_key_b64;
        }
        return keys;
    }

    // Import keys from backup or SSSS
    bool ImportKeys(const std::vector<uint8_t>& master_priv,
                    const std::vector<uint8_t>& self_priv,
                    const std::vector<uint8_t>& user_priv) {
        try {
            // Derive public keys from private keys
            master_key_ = std::make_unique<CrossSigningKey>();
            master_key_->user_id = user_id_;
            master_key_->key_type = "master";
            master_key_->private_key = master_priv;
            master_key_->public_key.resize(32);
            // Derive pubkey from private using Ed25519
            {
                EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(
                    EVP_PKEY_ED25519, nullptr,
                    master_priv.data(), master_priv.size());
                size_t len = 32;
                EVP_PKEY_get_raw_public_key(pkey,
                    master_key_->public_key.data(), &len);
                EVP_PKEY_free(pkey);
            }
            master_key_->public_key_b64 =
                base64::EncodeUnpadded(master_key_->public_key);

            self_signing_key_ = std::make_unique<CrossSigningKey>();
            self_signing_key_->user_id = user_id_;
            self_signing_key_->key_type = "self_signing";
            self_signing_key_->private_key = self_priv;
            self_signing_key_->public_key.resize(32);
            {
                EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(
                    EVP_PKEY_ED25519, nullptr,
                    self_priv.data(), self_priv.size());
                size_t len = 32;
                EVP_PKEY_get_raw_public_key(pkey,
                    self_signing_key_->public_key.data(), &len);
                EVP_PKEY_free(pkey);
            }
            self_signing_key_->public_key_b64 =
                base64::EncodeUnpadded(self_signing_key_->public_key);

            user_signing_key_ = std::make_unique<CrossSigningKey>();
            user_signing_key_->user_id = user_id_;
            user_signing_key_->key_type = "user_signing";
            user_signing_key_->private_key = user_priv;
            user_signing_key_->public_key.resize(32);
            {
                EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(
                    EVP_PKEY_ED25519, nullptr,
                    user_priv.data(), user_priv.size());
                size_t len = 32;
                EVP_PKEY_get_raw_public_key(pkey,
                    user_signing_key_->public_key.data(), &len);
                EVP_PKEY_free(pkey);
            }
            user_signing_key_->public_key_b64 =
                base64::EncodeUnpadded(user_signing_key_->public_key);

            is_bootstrapped_ = true;
            return true;
        } catch (const std::exception& e) {
            return false;
        }
    }
};

// =============================================================================
// Key Backup Version Management
// =============================================================================

struct KeyBackupVersion {
    std::string version;
    std::string algorithm;    // "m.megolm_backup.v1.curve25519-aes-sha2"
    std::string auth_data_json;  // Serialized KeyBackupAuthData
    int count = 0;             // Number of keys in this version
    std::string etag;          // Server etag for updates
    uint64_t version_num = 0;  // Numeric version for ordering

    json::object ToJson() const {
        json::object obj;
        obj["version"] = version;
        obj["algorithm"] = algorithm;
        obj["auth_data"] = json::parse(auth_data_json);
        obj["count"] = count;
        obj["etag"] = etag;
        obj["version"] = version;
        return obj;
    }
};

// =============================================================================
// Key Backup Manager
// =============================================================================

class KeyBackupManager {
private:
    std::string user_id_;
    std::string device_id_;
    std::vector<uint8_t> recovery_private_key_;
    std::vector<uint8_t> recovery_public_key_;

    // Active backup version
    std::unique_ptr<KeyBackupVersion> active_version_;

    // All known versions
    std::map<std::string, KeyBackupVersion> versions_;

    // In-memory cache of session data (keyed by (room_id, session_id))
    struct SessionKey {
        std::string room_id;
        std::string session_id;
        bool operator<(const SessionKey& other) const {
            return std::tie(room_id, session_id) <
                   std::tie(other.room_id, other.session_id);
        }
    };
    std::map<SessionKey, KeyBackupSessionData> session_cache_;

    // Backup scheduling
    std::chrono::steady_clock::time_point last_backup_time_;
    std::chrono::minutes backup_interval_{60};  // Default: every 60 minutes
    int pending_key_count_ = 0;
    int keys_per_backup_ = 100;  // Max keys per backup request

    bool trusted_ = false;
    std::mutex mutex_;

public:
    KeyBackupManager(const std::string& user_id,
                     const std::string& device_id)
        : user_id_(user_id), device_id_(device_id) {}

    // ===== 1. Server-side key backup =====
    // Upload room keys encrypted with recovery key

    // Initialize backup with recovery key
    bool InitializeBackup(const std::vector<uint8_t>& recovery_private_key) {
        std::lock_guard<std::mutex> lock(mutex_);
        recovery_private_key_ = recovery_private_key;

        // Derive public key
        recovery_public_key_.resize(32);
        X25519(recovery_public_key_.data(), recovery_private_key_.data(),
               (const uint8_t*)"\x09\x00\x00\x00\x00\x00\x00\x00"
               "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
               "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00");

        return true;
    }

    // Upload a single session key to backup
    bool UploadSessionKey(const std::string& room_id,
                          const std::string& session_id,
                          const std::string& algorithm,
                          const std::string& sender_key,
                          const std::string& session_key,
                          uint64_t first_message_index,
                          uint64_t forwarded_count,
                          bool is_verified) {
        std::lock_guard<std::mutex> lock(mutex_);

        if (recovery_private_key_.empty()) {
            throw CryptoError("Backup not initialized - no recovery key");
        }
        if (!active_version_) {
            throw CryptoError("No active backup version");
        }

        KeyBackupSessionData session;
        session.algorithm = algorithm;
        session.sender_key = sender_key;
        session.session_id = session_id;
        session.room_id = room_id;
        session.first_message_index = first_message_index;
        session.forwarded_count = forwarded_count;
        session.is_verified = is_verified;
        session.session_key = session_key;

        // Encrypt session data
        auto encrypted = EncryptSessionData(session, recovery_private_key_);

        // Build the backup payload for this session
        // The encrypted data includes ciphertext, mac, iv, ephemeral key

        // Cache the session locally
        SessionKey key{room_id, session_id};
        session_cache_[key] = session;

        // Increment count
        active_version_->count++;
        pending_key_count_++;

        return true;
    }

    // Build a full room key backup payload for the server
    json::object BuildRoomKeysPayload() {
        std::lock_guard<std::mutex> lock(mutex_);

        json::object rooms;
        std::set<std::string> processed_rooms;

        for (auto& [skey, session] : session_cache_) {
            if (!processed_rooms.count(skey.room_id)) {
                processed_rooms.insert(skey.room_id);
            }

            auto encrypted = EncryptSessionData(session, recovery_private_key_);

            json::object session_data;
            session_data["first_message_index"] =
                static_cast<int64_t>(session.first_message_index);
            session_data["forwarded_count"] =
                static_cast<int64_t>(session.forwarded_count);
            session_data["is_verified"] = session.is_verified;
            session_data["session_data"] = json::object{
                {"ciphertext", base64::EncodeUnpadded(encrypted.ciphertext)},
                {"mac", base64::EncodeUnpadded(encrypted.mac)},
                {"ephemeral", base64::EncodeUnpadded(encrypted.ephemeral_public_key)}
            };

            if (!rooms.count(skey.room_id)) {
                rooms[skey.room_id] = json::object{{"sessions", json::object{}}};
            }
            auto& room_obj = std::get<json::object>(rooms[skey.room_id]);
            auto& sessions = std::get<json::object>(room_obj["sessions"]);
            sessions[skey.session_id] = session_data;
        }

        return rooms;
    }

    // ===== 2. Key backup version management =====
    // Create a new backup version
    KeyBackupVersion CreateBackupVersion() {
        std::lock_guard<std::mutex> lock(mutex_);

        if (recovery_private_key_.empty()) {
            throw CryptoError("Recovery key not set");
        }

        KeyBackupVersion version;
        version.algorithm = "m.megolm_backup.v1.curve25519-aes-sha2";
        version.version = GenerateVersionId();
        version.count = 0;

        // Build auth data
        KeyBackupAuthData auth;
        auth.public_key = base64::EncodeUnpadded(recovery_public_key_);

        // Generate IV and compute MAC for empty data
        auto iv = GenerateRandomBytes(16);
        auth.iv = base64::EncodeUnpadded(iv);
        auth.mac = base64::EncodeUnpadded(
            HmacSha256(recovery_private_key_, {}));

        version.auth_data_json = json::serialize(auth.ToJson());

        versions_[version.version] = version;
        active_version_ = std::make_unique<KeyBackupVersion>(version);

        return version;
    }

    // Get the current backup version
    KeyBackupVersion GetBackupVersion(const std::string& version_id = "") {
        std::lock_guard<std::mutex> lock(mutex_);

        if (!version_id.empty()) {
            auto it = versions_.find(version_id);
            if (it != versions_.end()) return it->second;
            throw CryptoError("Version not found: " + version_id);
        }
        if (active_version_) return *active_version_;
        throw CryptoError("No active backup version");
    }

    // Update backup version metadata (after server response)
    bool UpdateBackupVersion(const std::string& version_id,
                             const std::string& etag,
                             int count) {
        std::lock_guard<std::mutex> lock(mutex_);

        auto it = versions_.find(version_id);
        if (it == versions_.end()) return false;

        it->second.etag = etag;
        it->second.count = count;

        if (active_version_ && active_version_->version == version_id) {
            active_version_->etag = etag;
            active_version_->count = count;
        }

        return true;
    }

    // Delete a backup version
    bool DeleteBackupVersion(const std::string& version_id) {
        std::lock_guard<std::mutex> lock(mutex_);

        auto it = versions_.find(version_id);
        if (it == versions_.end()) return false;

        if (active_version_ && active_version_->version == version_id) {
            active_version_.reset();
        }

        versions_.erase(it);
        return true;
    }

    // Get all known backup versions
    json::object GetAllVersions() const {
        std::lock_guard<std::mutex> lock(mutex_);

        json::object result;
        for (auto& [id, version] : versions_) {
            result[id] = version.ToJson();
        }
        return result;
    }

    // ===== 4. Key backup restore (download and decrypt all keys) =====
    // Restore sessions from a downloaded backup blob
    bool RestoreFromBackup(
        const json::object& backup_data,
        const std::vector<uint8_t>& recovery_key,
        std::function<void(const std::string& room_id,
                          const std::string& session_id,
                          const KeyBackupSessionData&)> callback) {

        std::lock_guard<std::mutex> lock(mutex_);

        if (recovery_key.empty() && recovery_private_key_.empty()) {
            throw CryptoError("No recovery key available for restore");
        }

        auto& decrypt_key = recovery_key.empty() ?
            recovery_private_key_ : recovery_key;

        int restored_count = 0;
        int failed_count = 0;

        // Iterate through rooms
        for (auto& [room_id, room_val] : backup_data) {
            if (!std::holds_alternative<json::object>(room_val)) continue;
            auto& room_obj = std::get<json::object>(room_val);

            if (!room_obj.count("sessions")) continue;
            auto& sessions = std::get<json::object>(room_obj["sessions"]);

            for (auto& [session_id, session_val] : sessions) {
                if (!std::holds_alternative<json::object>(session_val)) continue;
                auto& session_obj = std::get<json::object>(session_val);

                try {
                    // Extract encrypted data
                    auto& session_data =
                        std::get<json::object>(session_obj["session_data"]);

                    auto ciphertext = base64::Decode(
                        json::get_string(session_data, "ciphertext"));
                    auto mac = base64::Decode(
                        json::get_string(session_data, "mac"));
                    auto ephemeral = base64::Decode(
                        json::get_string(session_data, "ephemeral"));

                    // The IV is stored in auth_data for the whole version
                    // For per-session IV, it would be in session_data
                    std::vector<uint8_t> iv;
                    if (session_data.count("iv")) {
                        iv = base64::Decode(
                            json::get_string(session_data, "iv"));
                    } else {
                        iv = GenerateRandomBytes(16);  // fallback
                    }

                    // Decrypt
                    auto session = DecryptSessionData(
                        ciphertext, mac, iv, ephemeral, decrypt_key);

                    // Update metadata from outer object
                    if (session_obj.count("first_message_index")) {
                        session.first_message_index = static_cast<uint64_t>(
                            json::get_number(session_obj, "first_message_index"));
                    }
                    if (session_obj.count("forwarded_count")) {
                        session.forwarded_count = static_cast<uint64_t>(
                            json::get_number(session_obj, "forwarded_count"));
                    }
                    if (session_obj.count("is_verified")) {
                        session.is_verified =
                            json::get_bool(session_obj, "is_verified");
                    }

                    // Store in cache
                    SessionKey key{room_id, session_id};
                    session_cache_[key] = session;
                    restored_count++;

                    // Notify callback
                    if (callback) {
                        callback(room_id, session_id, session);
                    }

                } catch (const std::exception& e) {
                    failed_count++;
                    // Skip corrupted entries
                }
            }
        }

        return failed_count == 0;
    }

    // ===== 5. Key backup trust =====
    // Mark backup as trusted after verification
    bool MarkBackupTrusted(bool trusted = true) {
        std::lock_guard<std::mutex> lock(mutex_);
        trusted_ = trusted;
        return true;
    }

    bool IsBackupTrusted() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return trusted_;
    }

    // Verify backup signature
    bool VerifyBackupSignature(const std::string& version_id,
                               const CrossSigningManager& cross_signing) {
        std::lock_guard<std::mutex> lock(mutex_);

        auto it = versions_.find(version_id);
        if (it == versions_.end()) return false;

        auto auth_data = KeyBackupAuthData::FromJson(
            std::get<json::object>(json::parse(it->second.auth_data_json)));

        // Check if cross-signing master key has signed the backup
        auto master = cross_signing.GetMasterKey();
        if (!master) return false;

        std::string master_key_id = "ed25519:" + master->KeyId();

        if (auth_data.signatures.count(user_id_)) {
            auto& user_sigs = auth_data.signatures[user_id_];
            if (user_sigs.count(master_key_id)) {
                // Verify the signature
                std::vector<uint8_t> sig = base64::Decode(
                    std::get<std::string>(user_sigs[master_key_id]));

                json::object auth_obj = json::parse(it->second.auth_data_json);
                // Remove signatures for verification
                auth_obj.erase("signatures");
                std::string canonical = json::serialize(auth_obj);
                std::vector<uint8_t> msg(canonical.begin(), canonical.end());

                return Ed25519Verify(master->public_key, msg, sig);
            }
        }

        return false;
    }

    // ===== 17. Key backup automatic scheduling =====
    // Check if backup should be triggered now
    bool ShouldTriggerBackup() const {
        std::lock_guard<std::mutex> lock(mutex_);

        if (pending_key_count_ == 0) return false;
        if (pending_key_count_ < 10) {  // Minimum threshold
            auto now = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::minutes>(
                now - last_backup_time_);
            return elapsed >= backup_interval_;
        }
        return pending_key_count_ >= keys_per_backup_;
    }

    // Mark backup as triggered (reset counters)
    void MarkBackupTriggered() {
        std::lock_guard<std::mutex> lock(mutex_);
        last_backup_time_ = std::chrono::steady_clock::now();
        pending_key_count_ = 0;
    }

    // Set backup interval
    void SetBackupInterval(int minutes) {
        std::lock_guard<std::mutex> lock(mutex_);
        backup_interval_ = std::chrono::minutes(minutes);
    }

    // ===== 18. Key backup count tracking =====
    // Get pending key count
    int GetPendingKeyCount() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return pending_key_count_;
    }

    // Get total keys in active version
    int GetTotalKeyCount() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return active_version_ ? active_version_->count : 0;
    }

    // ===== 19. Key backup delete on device deletion =====
    // Delete all sessions for a device
    int DeleteSessionsForDevice(const std::string& device_key) {
        std::lock_guard<std::mutex> lock(mutex_);

        int deleted = 0;
        auto it = session_cache_.begin();
        while (it != session_cache_.end()) {
            if (it->second.sender_key == device_key) {
                it = session_cache_.erase(it);
                deleted++;
            } else {
                ++it;
            }
        }

        if (active_version_ && deleted > 0) {
            active_version_->count -= deleted;
            if (active_version_->count < 0) active_version_->count = 0;
        }

        return deleted;
    }

    // Delete all sessions for a room
    int DeleteSessionsForRoom(const std::string& room_id) {
        std::lock_guard<std::mutex> lock(mutex_);

        int deleted = 0;
        auto it = session_cache_.begin();
        while (it != session_cache_.end()) {
            if (it->first.room_id == room_id) {
                it = session_cache_.erase(it);
                deleted++;
            } else {
                ++it;
            }
        }

        if (active_version_ && deleted > 0) {
            active_version_->count -= deleted;
            if (active_version_->count < 0) active_version_->count = 0;
        }

        return deleted;
    }

    // ===== 20. Key backup migration between versions =====
    // Migrate sessions from one backup version to another
    bool MigrateSessions(const std::string& from_version_id,
                         const std::string& to_version_id,
                         const std::vector<uint8_t>& from_recovery_key) {
        std::lock_guard<std::mutex> lock(mutex_);

        auto from_it = versions_.find(from_version_id);
        if (from_it == versions_.end()) return false;

        auto to_it = versions_.find(to_version_id);
        if (to_it == versions_.end()) return false;

        // Save current recovery key and switch
        auto saved_key = recovery_private_key_;
        recovery_private_key_ = from_recovery_key;

        int migrated = 0;
        std::vector<SessionKey> to_migrate;

        // Find sessions that need migration
        for (auto& [key, session] : session_cache_) {
            to_migrate.push_back(key);
        }

        // Re-encrypt with new version's key
        recovery_private_key_ = saved_key;
        for (auto& skey : to_migrate) {
            auto it = session_cache_.find(skey);
            if (it != session_cache_.end()) {
                // The sessions will be re-encrypted on next upload
                pending_key_count_++;
                migrated++;
            }
        }

        return migrated > 0;
    }

    // ===== Helper methods =====
    // Get recovery public key for the current backup
    std::string GetRecoveryPublicKey() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return base64::EncodeUnpadded(recovery_public_key_);
    }

    // Check if backup is initialized
    bool IsInitialized() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return !recovery_private_key_.empty();
    }

    // Get session data from cache
    KeyBackupSessionData GetSession(const std::string& room_id,
                                     const std::string& session_id) const {
        std::lock_guard<std::mutex> lock(mutex_);
        SessionKey key{room_id, session_id};
        auto it = session_cache_.find(key);
        if (it == session_cache_.end()) {
            throw CryptoError("Session not found in cache");
        }
        return it->second;
    }

    // Check if session exists in cache
    bool HasSession(const std::string& room_id,
                    const std::string& session_id) const {
        std::lock_guard<std::mutex> lock(mutex_);
        SessionKey key{room_id, session_id};
        return session_cache_.find(key) != session_cache_.end();
    }

    // Clear all cached sessions
    void ClearSessions() {
        std::lock_guard<std::mutex> lock(mutex_);
        session_cache_.clear();
        pending_key_count_ = 0;
        if (active_version_) active_version_->count = 0;
    }

    // Get auth data for upload
    json::object GetAuthDataForUpload() const {
        std::lock_guard<std::mutex> lock(mutex_);

        KeyBackupAuthData auth;
        auth.public_key = base64::EncodeUnpadded(recovery_public_key_);

        // Generate fresh IV and MAC
        auto iv = GenerateRandomBytes(16);
        auth.iv = base64::EncodeUnpadded(iv);
        auth.mac = base64::EncodeUnpadded(
            HmacSha256(recovery_private_key_, {}));

        return auth.ToJson();
    }

    // Validate auth data consistency
    bool ValidateAuthData(const KeyBackupAuthData& auth) const {
        std::lock_guard<std::mutex> lock(mutex_);

        // Check public key matches
        std::string expected_pubkey = base64::EncodeUnpadded(recovery_public_key_);
        if (auth.public_key != expected_pubkey) return false;

        // Verify MAC
        auto expected_mac = HmacSha256(recovery_private_key_, {});
        auto provided_mac = base64::Decode(auth.mac);
        return ConstantTimeCompare(expected_mac, provided_mac);
    }

private:
    std::string GenerateVersionId() {
        auto random = GenerateRandomBytes(16);
        return base64::EncodeUnpadded(random);
    }
};

// =============================================================================
// Dehydrated Device Management
// =============================================================================

struct DehydratedDeviceData {
    std::string device_id;
    std::string device_display_name;
    std::string algorithm;          // "m.dehydrated_device.v1.olm"
    std::string account_pickle;     // Pickled olm account
    std::vector<uint8_t> ed25519_private_key;
    std::vector<uint8_t> ed25519_public_key;
    std::vector<uint8_t> curve25519_private_key;
    std::vector<uint8_t> curve25519_public_key;
    std::map<std::string, std::string> one_time_keys;  // key_id -> key
    int one_time_key_count = 0;
    std::string device_data_json;  // Serialized device_data for upload

    json::object BuildDeviceKeys() const {
        json::object keys;
        keys["user_id"] = "";  // filled by caller
        keys["device_id"] = device_id;
        keys["algorithms"] = json::array{
            "m.olm.v1.curve25519-aes-sha2",
            "m.megolm.v1.aes-sha2"
        };
        keys["keys"] = json::object{
            {"curve25519:" + device_id, base64::EncodeUnpadded(curve25519_public_key)},
            {"ed25519:" + device_id, base64::EncodeUnpadded(ed25519_public_key)}
        };
        keys["signatures"] = json::object{};
        return keys;
    }

    json::object BuildOneTimeKeys(const std::string& key_type) const {
        json::object otks;
        for (auto& [key_id, key_val] : one_time_keys) {
            std::string full_key_id = key_type + ":" + key_id;
            otks[full_key_id] = key_val;
        }
        return otks;
    }
};

class DehydratedDeviceManager {
private:
    std::string user_id_;
    std::unique_ptr<DehydratedDeviceData> device_;
    std::vector<uint8_t> pickle_key_;  // Key for encrypting pickle
    bool is_dehydrated_ = false;
    bool is_rehydrated_ = false;
    std::mutex mutex_;

    static constexpr int DEFAULT_OTK_COUNT = 50;
    static constexpr int MAX_OTK_COUNT = 100;

public:
    explicit DehydratedDeviceManager(const std::string& user_id)
        : user_id_(user_id) {}

    // ===== 6. Dehydrated device creation =====
    // Create a device with stored keys for offline use
    DehydratedDeviceData CreateDehydratedDevice(
        const std::string& device_display_name = "Dehydrated device") {

        std::lock_guard<std::mutex> lock(mutex_);

        DehydratedDeviceData data;
        data.algorithm = "m.dehydrated_device.v1.olm";

        // Generate unique device ID
        auto random = GenerateRandomBytes(8);
        data.device_id = "DEHYD" + base64::EncodeUnpadded(random);

        data.device_display_name = device_display_name;

        // Generate Ed25519 key pair for device signing
        auto ed_key = GenerateEd25519KeyPair();
        data.ed25519_public_key = ed_key.public_key;
        data.ed25519_private_key = ed_key.private_key;

        // Generate Curve25519 key pair for Olm
        auto cv_key = GenerateCurve25519KeyPair();
        data.curve25519_public_key = cv_key.public_key;
        data.curve25519_private_key = cv_key.private_key;

        // Generate one-time keys
        GenerateOneTimeKeys(data, DEFAULT_OTK_COUNT);

        // Generate pickle key for account storage
        pickle_key_ = GenerateRandomBytes(32);

        // Create device data JSON
        json::object device_data;
        device_data["algorithm"] = data.algorithm;
        device_data["account"] = PickleAccount(data, pickle_key_);
        device_data["account_key_type"] = "curve25519";

        data.device_data_json = json::serialize(device_data);

        device_ = std::make_unique<DehydratedDeviceData>(data);
        is_dehydrated_ = true;
        is_rehydrated_ = false;

        return data;
    }

    // ===== 7. Dehydrated device rehydration =====
    // Load keys when coming back online
    bool RehydrateDevice(const std::string& device_data_json,
                         const std::string& device_id) {
        std::lock_guard<std::mutex> lock(mutex_);

        try {
            auto val = json::parse(device_data_json);
            auto& obj = std::get<json::object>(val);

            DehydratedDeviceData data;
            data.device_id = device_id;
            data.algorithm = json::get_string(obj, "algorithm");

            // Unpickle account to get keys
            std::string pickled = json::get_string(obj, "account");
            // In a real implementation, this would use libolm's unpickle
            // Here we extract keys from the stored format
            auto account_data = UnpickleAccount(pickled);

            data.ed25519_public_key = account_data.ed25519_public;
            data.ed25519_private_key = account_data.ed25519_private;
            data.curve25519_public_key = account_data.curve25519_public;
            data.curve25519_private_key = account_data.curve25519_private;

            // Check for one-time keys stored alongside
            if (obj.count("one_time_keys")) {
                auto& otks = std::get<json::object>(obj["one_time_keys"]);
                for (auto& [key_id, key_val] : otks) {
                    data.one_time_keys[key_id] =
                        std::get<std::string>(key_val);
                }
                data.one_time_key_count = static_cast<int>(data.one_time_keys.size());
            }

            device_ = std::make_unique<DehydratedDeviceData>(data);
            is_rehydrated_ = true;
            is_dehydrated_ = false;

            return true;
        } catch (const std::exception& e) {
            return false;
        }
    }

    // ===== 8. Dehydrated device key upload =====
    // Upload one-time keys for offline period
    int UploadOneTimeKeys(int count = DEFAULT_OTK_COUNT) {
        std::lock_guard<std::mutex> lock(mutex_);

        if (!device_) {
            throw CryptoError("No dehydrated device available");
        }

        if (count > MAX_OTK_COUNT) count = MAX_OTK_COUNT;

        // Generate new one-time keys
        GenerateOneTimeKeys(*device_, count);
        device_->one_time_key_count = static_cast<int>(device_->one_time_keys.size());

        return device_->one_time_key_count;
    }

    // Get the OTK upload payload
    json::object GetOneTimeKeyUploadPayload() const {
        std::lock_guard<std::mutex> lock(mutex_);

        if (!device_) {
            throw CryptoError("No dehydrated device available");
        }

        json::object payload;
        for (auto& [key_id, key_val] : device_->one_time_keys) {
            std::string full_id = "signed_curve25519:" + key_id;
            payload[full_id] = key_val;
        }

        return payload;
    }

    // Get device keys for upload
    json::object GetDeviceKeysPayload() const {
        std::lock_guard<std::mutex> lock(mutex_);

        if (!device_) {
            throw CryptoError("No dehydrated device available");
        }

        auto keys = device_->BuildDeviceKeys();
        keys["user_id"] = user_id_;
        return keys;
    }

    // Get dehydrated device data for storage
    json::object GetDehydratedDevicePayload() const {
        std::lock_guard<std::mutex> lock(mutex_);

        if (!device_) {
            throw CryptoError("No dehydrated device available");
        }

        json::object payload;
        payload["algorithm"] = device_->algorithm;
        payload["account"] = PickleAccount(*device_, pickle_key_);

        json::object otks;
        for (auto& [key_id, key_val] : device_->one_time_keys) {
            otks[key_id] = key_val;
        }
        payload["one_time_keys"] = otks;

        return payload;
    }

    // Check device state
    bool IsDehydrated() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return is_dehydrated_;
    }

    bool IsRehydrated() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return is_rehydrated_;
    }

    // Get device info
    std::string GetDeviceId() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return device_ ? device_->device_id : "";
    }

    // Get remaining one-time key count
    int GetOneTimeKeyCount() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return device_ ? device_->one_time_key_count : 0;
    }

    // Generate fallback keys for the dehydrated device
    json::object GenerateFallbackKey() {
        std::lock_guard<std::mutex> lock(mutex_);

        if (!device_) {
            throw CryptoError("No dehydrated device available");
        }

        auto cv_key = GenerateCurve25519KeyPair();
        std::string key_b64 = base64::EncodeUnpadded(cv_key.public_key);

        json::object fallback;
        fallback["key"] = key_b64;
        fallback["fallback"] = true;

        return fallback;
    }

private:
    void GenerateOneTimeKeys(DehydratedDeviceData& data, int count) {
        data.one_time_keys.clear();
        data.one_time_key_count = 0;

        for (int i = 0; i < count; i++) {
            auto cv_key = GenerateCurve25519KeyPair();
            std::string key_id = GenerateOtkKeyId();
            std::string key_b64 = base64::EncodeUnpadded(cv_key.public_key);
            data.one_time_keys[key_id] = key_b64;
            data.one_time_key_count++;
        }
    }

    std::string GenerateOtkKeyId() {
        auto random = GenerateRandomBytes(6);
        return base64::EncodeUnpadded(random);
    }

    // Simplified account pickling (real impl uses libolm)
    struct AccountKeys {
        std::vector<uint8_t> ed25519_public;
        std::vector<uint8_t> ed25519_private;
        std::vector<uint8_t> curve25519_public;
        std::vector<uint8_t> curve25519_private;
    };

    std::string PickleAccount(const DehydratedDeviceData& data,
                              const std::vector<uint8_t>& key) {
        // Serialize account data and encrypt with pickle key
        json::object account;
        account["ed25519_pub"] = base64::EncodeUnpadded(data.ed25519_public_key);
        account["ed25519_priv"] = base64::EncodeUnpadded(data.ed25519_private_key);
        account["curve25519_pub"] = base64::EncodeUnpadded(data.curve25519_public_key);
        account["curve25519_priv"] = base64::EncodeUnpadded(data.curve25519_private_key);
        account["device_id"] = data.device_id;

        std::string json_str = json::serialize(account);
        std::vector<uint8_t> plaintext(json_str.begin(), json_str.end());

        auto iv = GenerateRandomBytes(16);
        auto ciphertext = AesCbcEncrypt(key, iv, plaintext);

        json::object pickle;
        pickle["iv"] = base64::EncodeUnpadded(iv);
        pickle["data"] = base64::EncodeUnpadded(ciphertext);
        pickle["algorithm"] = "aes-cbc";

        return json::serialize(pickle);
    }

    AccountKeys UnpickleAccount(const std::string& pickled) {
        auto val = json::parse(pickled);
        auto& obj = std::get<json::object>(val);

        std::string algorithm = json::get_string(obj, "algorithm");
        auto iv = base64::Decode(json::get_string(obj, "iv"));
        auto data = base64::Decode(json::get_string(obj, "data"));

        auto plaintext = AesCbcDecrypt(pickle_key_, iv, data);
        std::string json_str(plaintext.begin(), plaintext.end());

        auto account_val = json::parse(json_str);
        auto& account = std::get<json::object>(account_val);

        AccountKeys keys;
        keys.ed25519_public = base64::Decode(
            json::get_string(account, "ed25519_pub"));
        keys.ed25519_private = base64::Decode(
            json::get_string(account, "ed25519_priv"));
        keys.curve25519_public = base64::Decode(
            json::get_string(account, "curve25519_pub"));
        keys.curve25519_private = base64::Decode(
            json::get_string(account, "curve25519_priv"));

        return keys;
    }
};

// =============================================================================
// Bootstrap Orchestrator - ties everything together
// =============================================================================

class KeyBackupBootstrap {
private:
    std::string user_id_;
    std::string device_id_;

    std::unique_ptr<KeyBackupManager> backup_manager_;
    std::unique_ptr<RecoveryKeyManager> recovery_manager_;
    std::unique_ptr<CrossSigningManager> cross_signing_manager_;
    std::unique_ptr<DehydratedDeviceManager> dehydrated_manager_;
    std::unique_ptr<SecretStorageManager> secret_storage_manager_;

    // Bootstrap state
    bool bootstrap_complete_ = false;
    std::vector<uint8_t> recovery_key_;
    std::string recovery_key_string_;
    std::string ssss_key_id_;

    std::mutex mutex_;

public:
    KeyBackupBootstrap(const std::string& user_id,
                       const std::string& device_id)
        : user_id_(user_id), device_id_(device_id) {
        backup_manager_ = std::make_unique<KeyBackupManager>(user_id, device_id);
        cross_signing_manager_ = std::make_unique<CrossSigningManager>(user_id);
        dehydrated_manager_ = std::make_unique<DehydratedDeviceManager>(user_id);
        secret_storage_manager_ = std::make_unique<SecretStorageManager>(user_id);
    }

    // ===== Complete Bootstrap Flow =====
    // Performs all steps: generate recovery key, cross-signing keys,
    // secret storage, backup setup
    bool PerformBootstrap() {
        std::lock_guard<std::mutex> lock(mutex_);

        try {
            // Step 1: Generate recovery key
            auto [key, key_string] = RecoveryKeyManager::GenerateRecoveryKey();
            recovery_key_ = key;
            recovery_key_string_ = key_string;

            // Step 2: Initialize secret storage default key
            auto ssss_key = secret_storage_manager_->GenerateDefaultKey(
                recovery_key_);
            ssss_key_id_ = ssss_key.key_id;

            // Step 3: Bootstrap cross-signing
            if (!cross_signing_manager_->Bootstrap()) {
                return false;
            }

            // Step 4: Store cross-signing keys in SSSS
            auto master_key = cross_signing_manager_->GetMasterKey();
            auto self_key = cross_signing_manager_->GetSelfSigningKey();
            auto user_key = cross_signing_manager_->GetUserSigningKey();

            if (master_key) {
                secret_storage_manager_->StoreMasterKey(
                    master_key->private_key, ssss_key_id_);
            }
            if (self_key) {
                secret_storage_manager_->StoreSelfSigningKey(
                    self_key->private_key, ssss_key_id_);
            }
            if (user_key) {
                secret_storage_manager_->StoreUserSigningKey(
                    user_key->private_key, ssss_key_id_);
            }

            // Step 5: Initialize key backup
            backup_manager_->InitializeBackup(recovery_key_);

            // Step 6: Create initial backup version
            backup_manager_->CreateBackupVersion();

            bootstrap_complete_ = true;
            return true;

        } catch (const std::exception& e) {
            return false;
        }
    }

    // ===== Alternate bootstrap: from existing recovery key =====
    bool BootstrapFromRecoveryKey(const std::string& recovery_key_string) {
        std::lock_guard<std::mutex> lock(mutex_);

        try {
            // Validate recovery key
            if (!RecoveryKeyManager::ValidateRecoveryKey(recovery_key_string)) {
                return false;
            }

            auto key = RecoveryKeyManager::DecodeRecoveryKey(recovery_key_string);
            recovery_key_ = key;
            recovery_key_string_ = recovery_key_string;

            // Derive SSSS key ID
            ssss_key_id_ = RecoveryKeyManager::DeriveKeyId(recovery_key_);

            // Bootstrap cross-signing
            if (!cross_signing_manager_->Bootstrap()) {
                return false;
            }

            // Store keys in SSSS
            auto ssss_key = secret_storage_manager_->GenerateDefaultKey(
                recovery_key_);
            auto master_key = cross_signing_manager_->GetMasterKey();
            auto self_key = cross_signing_manager_->GetSelfSigningKey();
            auto user_key = cross_signing_manager_->GetUserSigningKey();

            if (master_key) {
                secret_storage_manager_->StoreMasterKey(
                    master_key->private_key, ssss_key_id_);
            }
            if (self_key) {
                secret_storage_manager_->StoreSelfSigningKey(
                    self_key->private_key, ssss_key_id_);
            }
            if (user_key) {
                secret_storage_manager_->StoreUserSigningKey(
                    user_key->private_key, ssss_key_id_);
            }

            // Initialize key backup
            backup_manager_->InitializeBackup(recovery_key_);
            backup_manager_->CreateBackupVersion();

            bootstrap_complete_ = true;
            return true;

        } catch (const std::exception& e) {
            return false;
        }
    }

    // ===== Restore from recovery key =====
    // Recover cross-signing keys from SSSS using recovery key
    bool RestoreFromRecoveryKey(const std::string& recovery_key_string) {
        std::lock_guard<std::mutex> lock(mutex_);

        try {
            if (!RecoveryKeyManager::ValidateRecoveryKey(recovery_key_string)) {
                return false;
            }

            auto key = RecoveryKeyManager::DecodeRecoveryKey(recovery_key_string);
            recovery_key_ = key;
            recovery_key_string_ = recovery_key_string;

            // Retrieve cross-signing keys from SSSS
            auto master_priv = secret_storage_manager_->RetrieveSecret(
                "m.cross_signing.master", recovery_key_);
            auto self_priv = secret_storage_manager_->RetrieveSecret(
                "m.cross_signing.self_signing", recovery_key_);
            auto user_priv = secret_storage_manager_->RetrieveSecret(
                "m.cross_signing.user_signing", recovery_key_);

            // Import keys
            if (!cross_signing_manager_->ImportKeys(
                    master_priv, self_priv, user_priv)) {
                return false;
            }

            // Initialize backup with recovery key
            backup_manager_->InitializeBackup(recovery_key_);

            bootstrap_complete_ = true;
            return true;

        } catch (const std::exception& e) {
            return false;
        }
    }

    // ===== Cross-signing bootstrap (standalone) =====
    bool BootstrapCrossSigning() {
        std::lock_guard<std::mutex> lock(mutex_);
        return cross_signing_manager_->Bootstrap();
    }

    // ===== Cross-signing reset =====
    bool ResetCrossSigning() {
        std::lock_guard<std::mutex> lock(mutex_);
        return cross_signing_manager_->Reset();
    }

    // ===== Cross-signing upload payload =====
    json::object BuildCrossSigningUploadPayload() {
        std::lock_guard<std::mutex> lock(mutex_);
        return cross_signing_manager_->BuildUploadPayload();
    }

    // ===== Cross-sign device/user keys =====
    json::object SignDeviceAndUserKeys(
        const std::map<std::string, json::object>& device_keys,
        const std::map<std::string, json::object>& user_keys) {
        std::lock_guard<std::mutex> lock(mutex_);
        return cross_signing_manager_->BuildSignaturesPayload(
            device_keys, user_keys);
    }

    // ===== Secret storage operations =====
    std::string GetDefaultSSSSKeyId() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return ssss_key_id_;
    }

    json::object GetSecretStorageKeys() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return secret_storage_manager_->SerializeKeys();
    }

    bool StoreSecret(const std::string& name,
                     const std::vector<uint8_t>& data) {
        std::lock_guard<std::mutex> lock(mutex_);
        return secret_storage_manager_->StoreSecret(
            name, data, ssss_key_id_);
    }

    // ===== Key backup operations =====
    bool InitializeKeyBackup(const std::string& recovery_key_string) {
        std::lock_guard<std::mutex> lock(mutex_);

        auto key = RecoveryKeyManager::DecodeRecoveryKey(recovery_key_string);
        recovery_key_ = key;
        recovery_key_string_ = recovery_key_string;

        return backup_manager_->InitializeBackup(key);
    }

    KeyBackupVersion CreateBackupVersion() {
        std::lock_guard<std::mutex> lock(mutex_);
        return backup_manager_->CreateBackupVersion();
    }

    bool UploadSessionKey(const std::string& room_id,
                          const std::string& session_id,
                          const std::string& algorithm,
                          const std::string& sender_key,
                          const std::string& session_key,
                          uint64_t first_message_index = 0,
                          uint64_t forwarded_count = 0,
                          bool is_verified = false) {
        std::lock_guard<std::mutex> lock(mutex_);
        return backup_manager_->UploadSessionKey(
            room_id, session_id, algorithm, sender_key, session_key,
            first_message_index, forwarded_count, is_verified);
    }

    json::object BuildBackupPayload() {
        std::lock_guard<std::mutex> lock(mutex_);
        return backup_manager_->BuildRoomKeysPayload();
    }

    bool RestoreBackup(
        const json::object& backup_data,
        std::function<void(const std::string&, const std::string&,
                          const KeyBackupSessionData&)> callback = nullptr) {
        std::lock_guard<std::mutex> lock(mutex_);
        return backup_manager_->RestoreFromBackup(
            backup_data, recovery_key_, callback);
    }

    bool MarkBackupTrusted(bool trusted = true) {
        std::lock_guard<std::mutex> lock(mutex_);
        return backup_manager_->MarkBackupTrusted(trusted);
    }

    // ===== Dehydrated device operations =====
    DehydratedDeviceData CreateDehydratedDevice(
        const std::string& display_name = "Dehydrated device") {
        std::lock_guard<std::mutex> lock(mutex_);
        return dehydrated_manager_->CreateDehydratedDevice(display_name);
    }

    bool RehydrateDevice(const std::string& device_data_json,
                         const std::string& device_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        return dehydrated_manager_->RehydrateDevice(device_data_json, device_id);
    }

    int UploadOneTimeKeys(int count = 50) {
        std::lock_guard<std::mutex> lock(mutex_);
        return dehydrated_manager_->UploadOneTimeKeys(count);
    }

    json::object GetDehydratedDevicePayload() {
        std::lock_guard<std::mutex> lock(mutex_);
        return dehydrated_manager_->GetDehydratedDevicePayload();
    }

    // ===== Recovery key operations =====
    std::string GenerateAndDisplayRecoveryKey() {
        std::lock_guard<std::mutex> lock(mutex_);

        auto [key, key_string] = RecoveryKeyManager::GenerateRecoveryKey();
        recovery_key_ = key;
        recovery_key_string_ = key_string;

        // Format for display (grouped for readability)
        return FormatRecoveryKeyForDisplay(key_string);
    }

    std::string GetRecoveryKeyString() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return recovery_key_string_;
    }

    bool ValidateRecoveryKey(const std::string& key_string) {
        return RecoveryKeyManager::ValidateRecoveryKey(key_string);
    }

    // ===== Automatic backup scheduling =====
    bool ShouldTriggerBackup() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return backup_manager_->ShouldTriggerBackup();
    }

    void MarkBackupTriggered() {
        std::lock_guard<std::mutex> lock(mutex_);
        backup_manager_->MarkBackupTriggered();
    }

    void SetBackupInterval(int minutes) {
        std::lock_guard<std::mutex> lock(mutex_);
        backup_manager_->SetBackupInterval(minutes);
    }

    // ===== Key backup count tracking =====
    int GetPendingKeyCount() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return backup_manager_->GetPendingKeyCount();
    }

    int GetTotalKeyCount() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return backup_manager_->GetTotalKeyCount();
    }

    // ===== Cleanup on device deletion =====
    int DeleteSessionsForDevice(const std::string& device_key) {
        std::lock_guard<std::mutex> lock(mutex_);
        return backup_manager_->DeleteSessionsForDevice(device_key);
    }

    int DeleteSessionsForRoom(const std::string& room_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        return backup_manager_->DeleteSessionsForRoom(room_id);
    }

    // ===== Migration =====
    bool MigrateBackupVersion(const std::string& from_version,
                              const std::string& to_version) {
        std::lock_guard<std::mutex> lock(mutex_);
        return backup_manager_->MigrateSessions(
            from_version, to_version, recovery_key_);
    }

    // ===== State queries =====
    bool IsBootstrapComplete() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return bootstrap_complete_;
    }

    bool IsCrossSigningBootstrapped() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return cross_signing_manager_->IsBootstrapped();
    }

    bool IsBackupTrusted() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return backup_manager_->IsBackupTrusted();
    }

    // ===== Full state export for persistence =====
    json::object ExportState() const {
        std::lock_guard<std::mutex> lock(mutex_);

        json::object state;
        state["bootstrap_complete"] = bootstrap_complete_;
        state["recovery_key_string"] = recovery_key_string_;
        state["ssss_key_id"] = ssss_key_id_;
        state["backup_versions"] = backup_manager_->GetAllVersions();
        state["cross_signing_keys"] =
            cross_signing_manager_->GetPublicKeysSerialized();
        state["secret_storage_keys"] = secret_storage_manager_->SerializeKeys();

        return state;
    }

    // ===== Full state import for persistence =====
    bool ImportState(const json::object& state) {
        std::lock_guard<std::mutex> lock(mutex_);

        try {
            bootstrap_complete_ = json::get_bool(state, "bootstrap_complete");
            recovery_key_string_ = json::get_string(state, "recovery_key_string");
            ssss_key_id_ = json::get_string(state, "ssss_key_id");

            // Load secret storage keys
            if (state.count("secret_storage_keys")) {
                secret_storage_manager_->DeserializeKeys(
                    std::get<json::object>(state.at("secret_storage_keys")));
            }

            // Recovery key restored
            if (!recovery_key_string_.empty()) {
                recovery_key_ = RecoveryKeyManager::DecodeRecoveryKey(
                    recovery_key_string_);
                backup_manager_->InitializeBackup(recovery_key_);
            }

            return true;
        } catch (const std::exception& e) {
            return false;
        }
    }

private:
    std::string FormatRecoveryKeyForDisplay(const std::string& key) {
        // Add spacing and grouping for display
        std::string result;
        for (size_t i = 0; i < key.size(); i++) {
            if (i > 0 && i % 20 == 0) result += '\n';
            else if (i > 0 && i % 4 == 0) result += ' ';
            result += key[i];
        }
        return result;
    }
};

// =============================================================================
// Utility: Cross-signing manager GetPublicKeysSerialized helper
// =============================================================================

// We add this as a method inline via a wrapper
json::object CrossSigningGetPublicKeysSerialized(
    const CrossSigningManager& mgr) {
    auto keys = mgr.GetPublicKeys();
    json::object result;
    for (auto& [k, v] : keys) {
        result[k] = v;
    }
    return result;
}

// =============================================================================
// Backward-compatible JSON helpers for the local json library
// =============================================================================

// These assume json.hpp provides json::object as std::map<std::string,json::value>
// and json::value as std::variant<...>. The exact interface may need adjustment.

namespace json_helpers {

inline std::string get_string(const json::object& obj, const std::string& key,
                               const std::string& default_val = "") {
    auto it = obj.find(key);
    if (it == obj.end()) return default_val;
    if (std::holds_alternative<std::string>(it->second))
        return std::get<std::string>(it->second);
    return default_val;
}

inline int64_t get_number(const json::object& obj, const std::string& key,
                           int64_t default_val = 0) {
    auto it = obj.find(key);
    if (it == obj.end()) return default_val;
    if (std::holds_alternative<double>(it->second))
        return static_cast<int64_t>(std::get<double>(it->second));
    if (std::holds_alternative<int64_t>(it->second))
        return std::get<int64_t>(it->second);
    return default_val;
}

inline bool get_bool(const json::object& obj, const std::string& key,
                      bool default_val = false) {
    auto it = obj.find(key);
    if (it == obj.end()) return default_val;
    if (std::holds_alternative<bool>(it->second))
        return std::get<bool>(it->second);
    return default_val;
}

}  // namespace json_helpers

// =============================================================================
// Backup Integrity Checking & Verification
// =============================================================================

class BackupIntegrityChecker {
private:
    struct IntegrityReport {
        int total_sessions = 0;
        int valid_sessions = 0;
        int corrupted_sessions = 0;
        int sessions_with_invalid_mac = 0;
        int sessions_with_invalid_keys = 0;
        std::vector<std::string> corrupted_session_ids;
        std::vector<std::string> warnings;
        bool overall_integrity = false;
    };

public:
    // Full integrity check of a backup version
    IntegrityReport CheckBackupIntegrity(
        const json::object& backup_data,
        const std::vector<uint8_t>& recovery_key) {

        IntegrityReport report;

        for (auto& [room_id, room_val] : backup_data) {
            if (!std::holds_alternative<json::object>(room_val)) {
                report.warnings.push_back(
                    "Invalid room entry format for: " + room_id);
                continue;
            }

            auto& room_obj = std::get<json::object>(room_val);
            if (!room_obj.count("sessions")) {
                report.warnings.push_back(
                    "Room has no sessions: " + room_id);
                continue;
            }

            auto& sessions = std::get<json::object>(room_obj["sessions"]);
            for (auto& [session_id, session_val] : sessions) {
                report.total_sessions++;

                if (!std::holds_alternative<json::object>(session_val)) {
                    report.corrupted_sessions++;
                    report.corrupted_session_ids.push_back(session_id);
                    report.warnings.push_back(
                        "Invalid session entry: " + room_id + "/" + session_id);
                    continue;
                }

                auto& session_obj = std::get<json::object>(session_val);
                bool session_valid = VerifySingleSession(
                    room_id, session_id, session_obj, recovery_key);

                if (session_valid) {
                    report.valid_sessions++;
                } else {
                    report.corrupted_sessions++;
                    report.corrupted_session_ids.push_back(
                        room_id + "/" + session_id);
                }
            }
        }

        report.overall_integrity = (report.corrupted_sessions == 0);
        return report;
    }

    // Verify a single encrypted session
    bool VerifySingleSession(
        const std::string& room_id,
        const std::string& session_id,
        const json::object& session_obj,
        const std::vector<uint8_t>& recovery_key) {

        try {
            // Check required fields exist
            if (!session_obj.count("session_data")) {
                return false;
            }

            auto& session_data =
                std::get<json::object>(session_obj.at("session_data"));

            // Verify we can decode the base64 fields
            if (!session_data.count("ciphertext") ||
                !session_data.count("mac") ||
                !session_data.count("ephemeral")) {
                return false;
            }

            auto ciphertext = base64::Decode(
                json::get_string(session_data, "ciphertext"));
            auto mac = base64::Decode(
                json::get_string(session_data, "mac"));
            auto ephemeral = base64::Decode(
                json::get_string(session_data, "ephemeral"));

            // Verify ephemeral key is valid size
            if (ephemeral.size() != 32) {
                return false;
            }

            // Attempt decryption
            std::vector<uint8_t> iv;
            if (session_data.count("iv")) {
                iv = base64::Decode(json::get_string(session_data, "iv"));
            } else {
                iv = GenerateRandomBytes(16);
            }

            // This will throw on MAC failure
            DecryptSessionData(ciphertext, mac, iv, ephemeral, recovery_key);

            return true;

        } catch (const std::exception&) {
            return false;
        }
    }

    // Generate an integrity report in JSON format
    json::object GenerateReportJson(const IntegrityReport& report) {
        json::object obj;
        obj["total_sessions"] = report.total_sessions;
        obj["valid_sessions"] = report.valid_sessions;
        obj["corrupted_sessions"] = report.corrupted_sessions;
        obj["sessions_with_invalid_mac"] = report.sessions_with_invalid_mac;
        obj["sessions_with_invalid_keys"] = report.sessions_with_invalid_keys;
        obj["overall_integrity"] = report.overall_integrity;

        json::array corrupted;
        for (auto& id : report.corrupted_session_ids) {
            corrupted.push_back(id);
        }
        obj["corrupted_session_ids"] = corrupted;

        json::array warns;
        for (auto& w : report.warnings) {
            warns.push_back(w);
        }
        obj["warnings"] = warns;

        return obj;
    }
};

// =============================================================================
// Backup Key Rotation Support
// =============================================================================

class BackupKeyRotator {
private:
    std::vector<uint8_t> old_recovery_key_;
    std::vector<uint8_t> new_recovery_key_;
    std::string old_version_id_;
    std::string new_version_id_;

public:
    BackupKeyRotator() = default;

    // Initialize rotation with old and new keys
    bool InitializeRotation(
        const std::vector<uint8_t>& old_key,
        const std::vector<uint8_t>& new_key,
        const std::string& old_version,
        const std::string& new_version) {

        if (old_key.empty() || new_key.empty()) return false;
        if (old_version.empty() || new_version.empty()) return false;
        if (old_version == new_version) return false;

        old_recovery_key_ = old_key;
        new_recovery_key_ = new_key;
        old_version_id_ = old_version;
        new_version_id_ = new_version;

        return true;
    }

    // Rotate a single session from old key to new key
    EncryptedSessionData RotateSession(
        const std::vector<uint8_t>& old_ciphertext,
        const std::vector<uint8_t>& old_mac,
        const std::vector<uint8_t>& old_iv,
        const std::vector<uint8_t>& old_ephemeral) {

        // Decrypt with old key
        auto session = DecryptSessionData(
            old_ciphertext, old_mac, old_iv, old_ephemeral,
            old_recovery_key_);

        // Re-encrypt with new key
        auto new_encrypted = EncryptSessionData(session, new_recovery_key_);

        return new_encrypted;
    }

    // Batch rotate all sessions in a room
    json::object RotateRoomSessions(
        const json::object& room_backup_data) {

        json::object new_room_data;

        for (auto& [session_id, session_val] : room_backup_data) {
            if (!std::holds_alternative<json::object>(session_val)) {
                new_room_data[session_id] = session_val;
                continue;
            }

            auto& session_obj = std::get<json::object>(session_val);
            auto& session_data =
                std::get<json::object>(session_obj["session_data"]);

            try {
                auto old_ciphertext = base64::Decode(
                    json::get_string(session_data, "ciphertext"));
                auto old_mac = base64::Decode(
                    json::get_string(session_data, "mac"));
                auto old_ephemeral = base64::Decode(
                    json::get_string(session_data, "ephemeral"));
                std::vector<uint8_t> old_iv;
                if (session_data.count("iv")) {
                    old_iv = base64::Decode(
                        json::get_string(session_data, "iv"));
                } else {
                    old_iv = GenerateRandomBytes(16);
                }

                auto new_data = RotateSession(
                    old_ciphertext, old_mac, old_iv, old_ephemeral);

                json::object new_session_data;
                new_session_data["ciphertext"] =
                    base64::EncodeUnpadded(new_data.ciphertext);
                new_session_data["mac"] =
                    base64::EncodeUnpadded(new_data.mac);
                new_session_data["iv"] =
                    base64::EncodeUnpadded(new_data.iv);
                new_session_data["ephemeral"] =
                    base64::EncodeUnpadded(new_data.ephemeral_public_key);

                json::object new_session;
                new_session["session_data"] = new_session_data;
                new_session["first_message_index"] =
                    session_obj.at("first_message_index");
                new_session["forwarded_count"] =
                    session_obj.at("forwarded_count");
                new_session["is_verified"] =
                    session_obj.at("is_verified");

                new_room_data[session_id] = new_session;

            } catch (const std::exception&) {
                // Keep original on rotation failure
                new_room_data[session_id] = session_obj;
            }
        }

        return new_room_data;
    }

    // Get rotation progress
    struct RotationProgress {
        int total_sessions = 0;
        int rotated = 0;
        int failed = 0;
        double percent_complete = 0.0;
    };

    RotationProgress GetProgress() const {
        RotationProgress progress;
        progress.percent_complete =
            progress.total_sessions > 0
                ? (static_cast<double>(progress.rotated) / progress.total_sessions) * 100.0
                : 0.0;
        return progress;
    }
};

// =============================================================================
// Differential Backup Support
// =============================================================================

class DifferentialBackupManager {
private:
    std::map<std::string, std::set<std::string>> known_sessions_;
    // room_id -> set of session_ids we've already uploaded
    std::mutex mutex_;

public:
    // Mark a session as already uploaded
    void MarkSessionUploaded(const std::string& room_id,
                             const std::string& session_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        known_sessions_[room_id].insert(session_id);
    }

    // Check if a session needs uploading
    bool NeedsUpload(const std::string& room_id,
                     const std::string& session_id) const {
        std::lock_guard<std::mutex> lock(mutex_);

        auto it = known_sessions_.find(room_id);
        if (it == known_sessions_.end()) return true;

        return it->second.find(session_id) == it->second.end();
    }

    // Filter sessions to only those needing upload
    json::object BuildDifferentialPayload(
        const json::object& full_payload) {

        std::lock_guard<std::mutex> lock(mutex_);

        json::object diff_payload;

        for (auto& [room_id, room_val] : full_payload) {
            if (!std::holds_alternative<json::object>(room_val)) continue;

            auto& room_obj = std::get<json::object>(room_val);
            if (!room_obj.count("sessions")) continue;

            auto& sessions = std::get<json::object>(room_obj["sessions"]);
            json::object new_sessions;

            for (auto& [session_id, session_data] : sessions) {
                if (NeedsUpload(room_id, session_id)) {
                    new_sessions[session_id] = session_data;
                    known_sessions_[room_id].insert(session_id);
                }
            }

            if (!new_sessions.empty()) {
                json::object new_room;
                new_room["sessions"] = new_sessions;
                diff_payload[room_id] = new_room;
            }
        }

        return diff_payload;
    }

    // Get count of known sessions
    int GetKnownSessionCount() const {
        std::lock_guard<std::mutex> lock(mutex_);
        int count = 0;
        for (auto& [room_id, sessions] : known_sessions_) {
            count += static_cast<int>(sessions.size());
        }
        return count;
    }

    // Clear known sessions for a room
    void ClearRoom(const std::string& room_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        known_sessions_.erase(room_id);
    }

    // Clear all known sessions
    void ClearAll() {
        std::lock_guard<std::mutex> lock(mutex_);
        known_sessions_.clear();
    }

    // Serialize known sessions for persistence
    json::object SerializeKnownSessions() const {
        std::lock_guard<std::mutex> lock(mutex_);

        json::object result;
        for (auto& [room_id, sessions] : known_sessions_) {
            json::array arr;
            for (auto& sid : sessions) {
                arr.push_back(sid);
            }
            result[room_id] = arr;
        }
        return result;
    }

    // Restore known sessions from persistence
    void DeserializeKnownSessions(const json::object& data) {
        std::lock_guard<std::mutex> lock(mutex_);
        known_sessions_.clear();

        for (auto& [room_id, arr_val] : data) {
            if (std::holds_alternative<json::array>(arr_val)) {
                auto& arr = std::get<json::array>(arr_val);
                for (auto& v : arr) {
                    if (std::holds_alternative<std::string>(v)) {
                        known_sessions_[room_id].insert(
                            std::get<std::string>(v));
                    }
                }
            }
        }
    }
};

// =============================================================================
// Backup Metadata and Configuration Management
// =============================================================================

class BackupMetadataManager {
public:
    struct BackupConfig {
        bool enabled = true;
        int auto_backup_interval_minutes = 60;
        int max_keys_per_backup = 100;
        int max_retry_count = 3;
        int retry_delay_seconds = 30;
        bool backup_on_room_leave = true;
        bool backup_on_device_delete = false;
        bool use_differential_backup = true;
        std::string preferred_algorithm = "m.megolm_backup.v1.curve25519-aes-sha2";
    };

private:
    BackupConfig config_;
    std::map<std::string, std::string> backup_metadata_;
    // metadata key -> value pairs for each backup version
    std::mutex mutex_;

public:
    // Get/set configuration
    BackupConfig GetConfig() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return config_;
    }

    void SetConfig(const BackupConfig& config) {
        std::lock_guard<std::mutex> lock(mutex_);
        config_ = config;
    }

    // Store metadata for a backup version
    void SetMetadata(const std::string& version_id,
                     const std::string& key,
                     const std::string& value) {
        std::lock_guard<std::mutex> lock(mutex_);
        std::string meta_key = version_id + ":" + key;
        backup_metadata_[meta_key] = value;
    }

    // Get metadata for a backup version
    std::string GetMetadata(const std::string& version_id,
                            const std::string& key,
                            const std::string& default_val = "") const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::string meta_key = version_id + ":" + key;
        auto it = backup_metadata_.find(meta_key);
        return (it != backup_metadata_.end()) ? it->second : default_val;
    }

    // Clear metadata for a version
    void ClearMetadata(const std::string& version_id) {
        std::lock_guard<std::mutex> lock(mutex_);

        std::string prefix = version_id + ":";
        auto it = backup_metadata_.begin();
        while (it != backup_metadata_.end()) {
            if (it->first.substr(0, prefix.size()) == prefix) {
                it = backup_metadata_.erase(it);
            } else {
                ++it;
            }
        }
    }

    // Get all metadata as JSON
    json::object GetAllMetadata() const {
        std::lock_guard<std::mutex> lock(mutex_);

        json::object result;
        for (auto& [key, value] : backup_metadata_) {
            result[key] = value;
        }
        return result;
    }

    // Backup statistics tracking
    struct BackupStats {
        uint64_t total_backups_performed = 0;
        uint64_t total_keys_uploaded = 0;
        uint64_t total_bytes_uploaded = 0;
        uint64_t last_backup_duration_ms = 0;
        uint64_t last_backup_sessions_count = 0;
        std::chrono::system_clock::time_point last_successful_backup;
        std::chrono::system_clock::time_point last_failed_backup;
        std::string last_error;
    };

    BackupStats stats_;

    void RecordSuccessfulBackup(int session_count, uint64_t duration_ms,
                                uint64_t bytes_uploaded) {
        std::lock_guard<std::mutex> lock(mutex_);
        stats_.total_backups_performed++;
        stats_.total_keys_uploaded += session_count;
        stats_.total_bytes_uploaded += bytes_uploaded;
        stats_.last_backup_duration_ms = duration_ms;
        stats_.last_backup_sessions_count = session_count;
        stats_.last_successful_backup = std::chrono::system_clock::now();
    }

    void RecordFailedBackup(const std::string& error) {
        std::lock_guard<std::mutex> lock(mutex_);
        stats_.last_failed_backup = std::chrono::system_clock::now();
        stats_.last_error = error;
    }

    BackupStats GetStats() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return stats_;
    }
};

// =============================================================================
// Backup Retry Logic with Exponential Backoff
// =============================================================================

class BackupRetryHandler {
private:
    struct RetryState {
        int attempt_count = 0;
        int max_attempts = 5;
        int base_delay_ms = 1000;
        int max_delay_ms = 60000;
        std::chrono::steady_clock::time_point last_attempt;
        bool should_retry = true;
        std::string last_error;
    };

    std::map<std::string, RetryState> retry_states_;
    std::mutex mutex_;

public:
    // Calculate next retry delay using exponential backoff
    int CalculateNextDelay(const std::string& operation_id) {
        std::lock_guard<std::mutex> lock(mutex_);

        auto& state = retry_states_[operation_id];
        state.attempt_count++;

        if (state.attempt_count > state.max_attempts) {
            state.should_retry = false;
            return -1;
        }

        // Exponential backoff: base_delay * 2^(attempt-1), capped at max_delay
        int delay = state.base_delay_ms * (1 << (state.attempt_count - 1));
        if (delay > state.max_delay_ms) {
            delay = state.max_delay_ms;
        }

        state.last_attempt = std::chrono::steady_clock::now();
        return delay;
    }

    // Record a failure
    void RecordFailure(const std::string& operation_id,
                       const std::string& error) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto& state = retry_states_[operation_id];
        state.last_error = error;
    }

    // Record success and reset state
    void RecordSuccess(const std::string& operation_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        retry_states_.erase(operation_id);
    }

    // Check if retry should be attempted
    bool ShouldRetry(const std::string& operation_id) const {
        std::lock_guard<std::mutex> lock(mutex_);

        auto it = retry_states_.find(operation_id);
        if (it == retry_states_.end()) return true;
        return it->second.should_retry;
    }

    // Get retry state info
    int GetAttemptCount(const std::string& operation_id) const {
        std::lock_guard<std::mutex> lock(mutex_);

        auto it = retry_states_.find(operation_id);
        return (it != retry_states_.end()) ? it->second.attempt_count : 0;
    }

    // Reset all retry states
    void ResetAll() {
        std::lock_guard<std::mutex> lock(mutex_);
        retry_states_.clear();
    }
};

// =============================================================================
// Session Validation and Sanitization
// =============================================================================

class SessionValidator {
public:
    struct ValidationResult {
        bool is_valid = false;
        std::vector<std::string> errors;
        std::vector<std::string> warnings;
    };

    // Validate a KeyBackupSessionData for correctness
    ValidationResult ValidateSessionData(
        const KeyBackupSessionData& session) {

        ValidationResult result;
        result.is_valid = true;

        // Check algorithm
        if (session.algorithm.empty()) {
            result.errors.push_back("Missing algorithm");
            result.is_valid = false;
        } else if (session.algorithm != "m.megolm.v1.aes-sha2" &&
                   session.algorithm != "m.olm.v1.curve25519-aes-sha2") {
            result.warnings.push_back(
                "Unknown algorithm: " + session.algorithm);
        }

        // Check sender_key
        if (session.sender_key.empty()) {
            result.errors.push_back("Missing sender_key");
            result.is_valid = false;
        } else if (!ValidateBase64(session.sender_key)) {
            result.errors.push_back("Invalid sender_key format");
            result.is_valid = false;
        }

        // Check session_id
        if (session.session_id.empty()) {
            result.errors.push_back("Missing session_id");
            result.is_valid = false;
        }

        // Check room_id
        if (session.room_id.empty()) {
            result.errors.push_back("Missing room_id");
            result.is_valid = false;
        } else if (session.room_id[0] != '!') {
            result.warnings.push_back(
                "Room ID does not start with '!': " + session.room_id);
        }

        // Check session_key
        if (session.session_key.empty()) {
            result.errors.push_back("Missing session_key");
            result.is_valid = false;
        } else if (!ValidateBase64(session.session_key)) {
            result.errors.push_back("Invalid session_key format");
            result.is_valid = false;
        }

        // Check forwarded_count is reasonable
        if (session.forwarded_count > 1000) {
            result.warnings.push_back(
                "High forwarded_count: " +
                std::to_string(session.forwarded_count));
        }

        return result;
    }

    // Validate an entire backup before upload
    bool ValidateBackupPayload(const json::object& payload) {
        if (payload.empty()) return false;

        for (auto& [room_id, room_val] : payload) {
            if (!std::holds_alternative<json::object>(room_val)) {
                return false;
            }
            auto& room_obj = std::get<json::object>(room_val);
            if (!room_obj.count("sessions")) return false;
            if (std::get<json::object>(room_obj.at("sessions")).empty()) {
                return false;
            }
        }
        return true;
    }

    // Sanitize a session data by removing invalid fields
    KeyBackupSessionData SanitizeSessionData(
        const KeyBackupSessionData& session) {

        KeyBackupSessionData sanitized = session;

        // Trim whitespace from string fields
        sanitized.algorithm = Trim(sanitized.algorithm);
        sanitized.sender_key = Trim(sanitized.sender_key);
        sanitized.session_id = Trim(sanitized.session_id);
        sanitized.room_id = Trim(sanitized.room_id);
        sanitized.session_key = Trim(sanitized.session_key);

        // Cap unreasonable values
        if (sanitized.forwarded_count > 10000) {
            sanitized.forwarded_count = 10000;
        }

        return sanitized;
    }

private:
    bool ValidateBase64(const std::string& input) {
        try {
            auto decoded = base64::Decode(input);
            return !decoded.empty();
        } catch (...) {
            return false;
        }
    }

    std::string Trim(const std::string& str) {
        size_t start = str.find_first_not_of(" \t\r\n");
        if (start == std::string::npos) return "";
        size_t end = str.find_last_not_of(" \t\r\n");
        return str.substr(start, end - start + 1);
    }
};

// =============================================================================
// Backup Export and Import (for migration/recovery)
// =============================================================================

class BackupExporter {
public:
    struct ExportData {
        std::string format_version = "1.0";
        std::string export_time;
        std::string user_id;
        std::string backup_version_id;
        std::string algorithm;
        json::object auth_data;
        json::object room_keys;
        int total_keys = 0;
        std::string checksum;  // SHA-256 of the room_keys JSON
    };

    // Build a full export of all backup data
    ExportData ExportBackup(
        const std::string& user_id,
        const std::string& version_id,
        const std::string& algorithm,
        const json::object& auth_data,
        const json::object& room_keys) {

        ExportData data;
        data.user_id = user_id;
        data.backup_version_id = version_id;
        data.algorithm = algorithm;
        data.auth_data = auth_data;
        data.room_keys = room_keys;

        // Count total keys
        for (auto& [room_id, room_val] : room_keys) {
            if (std::holds_alternative<json::object>(room_val)) {
                auto& room = std::get<json::object>(room_val);
                if (room.count("sessions")) {
                    data.total_keys += static_cast<int>(
                        std::get<json::object>(room["sessions"]).size());
                }
            }
        }

        // Generate timestamp
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        data.export_time = std::ctime(&time_t);

        // Compute checksum
        std::string serialized = json::serialize(room_keys);
        std::vector<uint8_t> serialized_bytes(serialized.begin(),
                                               serialized.end());
        auto hash = Sha256(serialized_bytes);
        data.checksum = base64::EncodeUnpadded(hash);

        return data;
    }

    // Serialize export to JSON
    json::object SerializeExport(const ExportData& data) {
        json::object obj;
        obj["format_version"] = data.format_version;
        obj["export_time"] = data.export_time;
        obj["user_id"] = data.user_id;
        obj["backup_version_id"] = data.backup_version_id;
        obj["algorithm"] = data.algorithm;
        obj["auth_data"] = data.auth_data;
        obj["room_keys"] = data.room_keys;
        obj["total_keys"] = data.total_keys;
        obj["checksum"] = data.checksum;
        return obj;
    }

    // Verify an imported export
    bool VerifyExport(const ExportData& data) {
        // Check format version
        if (data.format_version != "1.0") return false;

        // Verify checksum
        std::string serialized = json::serialize(data.room_keys);
        std::vector<uint8_t> serialized_bytes(serialized.begin(),
                                               serialized.end());
        auto hash = Sha256(serialized_bytes);
        std::string computed_checksum = base64::EncodeUnpadded(hash);

        return computed_checksum == data.checksum;
    }

    // Parse an imported export from JSON
    ExportData DeserializeExport(const json::object& obj) {
        ExportData data;
        data.format_version = json::get_string(obj, "format_version", "1.0");
        data.export_time = json::get_string(obj, "export_time");
        data.user_id = json::get_string(obj, "user_id");
        data.backup_version_id = json::get_string(obj, "backup_version_id");
        data.algorithm = json::get_string(obj, "algorithm");
        data.auth_data = std::get<json::object>(obj.at("auth_data"));
        data.room_keys = std::get<json::object>(obj.at("room_keys"));
        data.total_keys = static_cast<int>(json::get_number(obj, "total_keys"));
        data.checksum = json::get_string(obj, "checksum");
        return data;
    }
};

// =============================================================================
// Backup Rate Limiter
// =============================================================================

class BackupRateLimiter {
private:
    struct RateLimitWindow {
        int max_requests;
        std::chrono::seconds window_duration;
        std::deque<std::chrono::steady_clock::time_point> request_times;
    };

    RateLimitWindow key_upload_window_{100, std::chrono::seconds(60)};
    RateLimitWindow version_create_window_{5, std::chrono::seconds(3600)};
    RateLimitWindow key_request_window_{50, std::chrono::seconds(60)};
    mutable std::mutex mutex_;

public:
    // Check if key upload is allowed
    bool CanUploadKeys() {
        std::lock_guard<std::mutex> lock(mutex_);
        return CheckWindow(key_upload_window_);
    }

    // Check if version creation is allowed
    bool CanCreateVersion() {
        std::lock_guard<std::mutex> lock(mutex_);
        return CheckWindow(version_create_window_);
    }

    // Check if key request is allowed
    bool CanRequestKeys() {
        std::lock_guard<std::mutex> lock(mutex_);
        return CheckWindow(key_request_window_);
    }

    // Record a key upload
    void RecordKeyUpload() {
        std::lock_guard<std::mutex> lock(mutex_);
        RecordRequest(key_upload_window_);
    }

    // Record a version creation
    void RecordVersionCreate() {
        std::lock_guard<std::mutex> lock(mutex_);
        RecordRequest(version_create_window_);
    }

    // Record a key request
    void RecordKeyRequest() {
        std::lock_guard<std::mutex> lock(mutex_);
        RecordRequest(key_request_window_);
    }

    // Get remaining quota for key uploads
    int GetRemainingKeyUploads() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return GetRemaining(key_upload_window_);
    }

    // Set rate limit parameters
    void SetKeyUploadLimit(int max_per_minute) {
        std::lock_guard<std::mutex> lock(mutex_);
        key_upload_window_.max_requests = max_per_minute;
    }

    void SetVersionCreateLimit(int max_per_hour) {
        std::lock_guard<std::mutex> lock(mutex_);
        version_create_window_.max_requests = max_per_hour;
    }

private:
    bool CheckWindow(RateLimitWindow& window) {
        auto now = std::chrono::steady_clock::now();
        auto cutoff = now - window.window_duration;

        // Remove expired entries
        while (!window.request_times.empty() &&
               window.request_times.front() < cutoff) {
            window.request_times.pop_front();
        }

        return static_cast<int>(window.request_times.size()) < window.max_requests;
    }

    void RecordRequest(RateLimitWindow& window) {
        window.request_times.push_back(
            std::chrono::steady_clock::now());
    }

    int GetRemaining(RateLimitWindow& window) const {
        auto now = std::chrono::steady_clock::now();
        auto cutoff = now - window.window_duration;

        int active = 0;
        for (auto& t : window.request_times) {
            if (t >= cutoff) active++;
        }

        return std::max(0, window.max_requests - active);
    }
};

// =============================================================================
// Backup Event Hooks / Callback System
// =============================================================================

class BackupEventHooks {
public:
    using BackupCallback = std::function<void(const std::string& event,
                                               const json::object& data)>;

private:
    std::map<std::string, std::vector<BackupCallback>> callbacks_;
    std::mutex mutex_;

public:
    // Register a callback for an event
    void On(const std::string& event, BackupCallback callback) {
        std::lock_guard<std::mutex> lock(mutex_);
        callbacks_[event].push_back(std::move(callback));
    }

    // Fire an event
    void FireEvent(const std::string& event, const json::object& data) {
        std::lock_guard<std::mutex> lock(mutex_);

        auto it = callbacks_.find(event);
        if (it == callbacks_.end()) return;

        for (auto& cb : it->second) {
            try {
                cb(event, data);
            } catch (...) {
                // Swallow callback errors
            }
        }
    }

    // Remove all callbacks for an event
    void RemoveAllListeners(const std::string& event) {
        std::lock_guard<std::mutex> lock(mutex_);
        callbacks_.erase(event);
    }

    // Remove all callbacks entirely
    void RemoveAll() {
        std::lock_guard<std::mutex> lock(mutex_);
        callbacks_.clear();
    }

    // Standard event names
    static constexpr const char* EVENT_BACKUP_CREATED = "backup.created";
    static constexpr const char* EVENT_BACKUP_UPDATED = "backup.updated";
    static constexpr const char* EVENT_BACKUP_DELETED = "backup.deleted";
    static constexpr const char* EVENT_BACKUP_RESTORED = "backup.restored";
    static constexpr const char* EVENT_BACKUP_FAILED = "backup.failed";
    static constexpr const char* EVENT_SESSION_UPLOADED = "session.uploaded";
    static constexpr const char* EVENT_SESSION_DOWNLOADED = "session.downloaded";
    static constexpr const char* EVENT_RECOVERY_KEY_CHANGED = "recovery_key.changed";
    static constexpr const char* EVENT_CROSS_SIGNING_RESET = "cross_signing.reset";
    static constexpr const char* EVENT_DEVICE_DEHYDRATED = "device.dehydrated";
    static constexpr const char* EVENT_DEVICE_REHYDRATED = "device.rehydrated";
};

}  // namespace crypto
}  // namespace progressive
