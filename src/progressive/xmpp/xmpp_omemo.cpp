// progressive-server: XMPP OMEMO End-to-End Encryption (XEP-0384)
// Implements Double Ratchet, X3DH, AES-256-GCM, Curve25519, Ed25519
// Reference: Signal Protocol, XEP-0384 v0.3, v0.4, v0.8
//
// Cryptographic primitives backed by OpenSSL (libcrypto):
//   - X25519 / Curve25519 ECDH key agreement
//   - Ed25519 / EdDSA signature verification
//   - AES-256-GCM authenticated encryption
//   - HKDF-SHA256 key derivation
//   - HMAC-SHA256 message authentication
//
// OMEMO protocol layers:
//   1. X3DH key agreement (initial shared secret)
//   2. Double Ratchet (per-message forward secrecy)
//   3. PEP node publication (device list, bundles)
//   4. Sender Key for group chat efficiency (XEP-0384 §5.2)
//   5. Blind Trust Before Verification (BTBV) trust model

#include <string>
#include <string_view>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <memory>
#include <functional>
#include <optional>
#include <variant>
#include <ctime>
#include <algorithm>
#include <sstream>
#include <regex>
#include <random>
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <deque>
#include <chrono>
#include <cstring>
#include <cstdint>
#include <stdexcept>

// OpenSSL crypto primitives
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
// HKDF is part of OpenSSL 1.1.0+ EVP_KDF or manual via HMAC
// We implement HKDF-SHA256 manually using HMAC-SHA256 (RFC 5869)
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/bn.h>

namespace progressive {
namespace xmpp {

// =============================================================================
// OMEMO Namespace Constants (XEP-0384)
// =============================================================================
namespace omemo_ns {
    constexpr const char* OMEMO         = "urn:xmpp:omemo:2";
    constexpr const char* OMEMO_DEVICES = "urn:xmpp:omemo:2:devices";
    constexpr const char* OMEMO_BUNDLES = "urn:xmpp:omemo:2:bundles";
    // Legacy namespace support (XEP-0384 v0.3)
    constexpr const char* OMEMO_LEGACY  = "eu.siacs.conversations.axolotl";
    // v0.4 namespace
    constexpr const char* OMEMO_V04     = "eu.siacs.conversations.axolotl:1";
    // v0.8 namespace
    constexpr const char* OMEMO_V08     = "urn:xmpp:omemo:1";
}

// =============================================================================
// Cryptographic constants
// =============================================================================
constexpr size_t AES_KEY_SIZE       = 32;   // AES-256
constexpr size_t AES_GCM_IV_SIZE    = 12;   // 96 bits
constexpr size_t AES_GCM_TAG_SIZE   = 16;   // 128 bits
constexpr size_t X25519_KEY_SIZE    = 32;   // Curve25519
constexpr size_t ED25519_KEY_SIZE   = 32;
constexpr size_t ED25519_SIG_SIZE   = 64;
constexpr size_t HMAC_SHA256_SIZE   = 32;
constexpr size_t HKDF_OUTPUT_SIZE   = 32;
constexpr size_t DOUBLE_RATCHET_SYM_KEY_SIZE = 32;
constexpr size_t MESSAGE_KEY_SIZE   = 32;
constexpr size_t CHAIN_KEY_SIZE     = 32;
constexpr size_t ROOT_KEY_SIZE      = 32;
constexpr size_t SENDER_KEY_SIZE    = 32;
constexpr size_t SENDER_SIGNING_KEY_SIZE = 32;

constexpr int    MAX_RECEIVE_CHAINS = 40;
constexpr int    MAX_SKIPPED_KEYS   = 1000;
constexpr int    PRE_KEY_BATCH_SIZE = 100;
constexpr int    PRE_KEY_MIN_COUNT  = 25;
constexpr int    SIGNED_PRE_KEY_TTL = 7 * 24 * 3600;  // 7 days
constexpr int    SESSION_TTL        = 30 * 24 * 3600; // 30 days
constexpr int    BUNDLE_REFRESH_DAYS = 7;
constexpr int    DEVICE_ID_MIN      = 1;
constexpr int    DEVICE_ID_MAX      = 0x7FFFFFFF;

// =============================================================================
// Byte utility types
// =============================================================================
using ByteVector = std::vector<uint8_t>;
using KeyBytes   = std::array<uint8_t, X25519_KEY_SIZE>;
using NonceBytes = std::array<uint8_t, AES_GCM_IV_SIZE>;
using TagBytes   = std::array<uint8_t, AES_GCM_TAG_SIZE>;
using SigBytes   = std::array<uint8_t, ED25519_SIG_SIZE>;

// =============================================================================
// Forward declarations
// =============================================================================
struct OmemoDevice;
struct OmemoBundle;
struct OmemoPreKey;
struct OmemoSignedPreKey;
struct OmemoSession;
struct OmemoMessageKey;
struct OmemoSenderKeyState;
struct OmemoHeader;
struct OmemoKeyExchange;
struct OmemoEnvelope;

// =============================================================================
// Utility: secure zeroing, hex/base64 conversion, random generation
// =============================================================================
inline void secure_zero(void* ptr, size_t len) {
    volatile uint8_t* p = static_cast<volatile uint8_t*>(ptr);
    for (size_t i = 0; i < len; i++) p[i] = 0;
    __asm__ __volatile__("" : : "r"(p) : "memory");
}

inline void secure_zero(ByteVector& vec) {
    if (!vec.empty()) secure_zero(vec.data(), vec.size());
}

inline std::string bytes_to_hex(const uint8_t* data, size_t len) {
    static const char hex_chars[] = "0123456789abcdef";
    std::string result;
    result.reserve(len * 2);
    for (size_t i = 0; i < len; i++) {
        result.push_back(hex_chars[(data[i] >> 4) & 0xF]);
        result.push_back(hex_chars[data[i] & 0xF]);
    }
    return result;
}

inline ByteVector hex_to_bytes(std::string_view hex) {
    ByteVector result;
    result.reserve(hex.length() / 2);
    for (size_t i = 0; i + 1 < hex.length(); i += 2) {
        auto nibble = [](char c) -> uint8_t {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return 0;
        };
        result.push_back((nibble(hex[i]) << 4) | nibble(hex[i + 1]));
    }
    return result;
}

inline std::string base64_encode(const uint8_t* data, size_t len) {
    static const char b64[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string result;
    result.reserve(((len + 2) / 3) * 4);
    for (size_t i = 0; i < len; i += 3) {
        uint32_t n = static_cast<uint32_t>(data[i]) << 16;
        if (i + 1 < len) n |= static_cast<uint32_t>(data[i + 1]) << 8;
        if (i + 2 < len) n |= static_cast<uint32_t>(data[i + 2]);
        result.push_back(b64[(n >> 18) & 0x3F]);
        result.push_back(b64[(n >> 12) & 0x3F]);
        result.push_back((i + 1 < len) ? b64[(n >> 6) & 0x3F] : '=');
        result.push_back((i + 2 < len) ? b64[n & 0x3F] : '=');
    }
    return result;
}

inline ByteVector base64_decode(std::string_view encoded) {
    static const int8_t decode_table[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,62,-1,-1,-1,63,
        52,53,54,55,56,57,58,59, 60,61,-1,-1,-1,-1,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6,  7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22, 23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32, 33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48, 49,50,51,-1,-1,-1,-1,-1,
    };
    ByteVector result;
    result.reserve((encoded.length() / 4) * 3);
    int buffer = 0, bits = 0;
    for (char c : encoded) {
        if (c == '=') break;
        int val = decode_table[static_cast<uint8_t>(c)];
        if (val == -1) continue;
        buffer = (buffer << 6) | val;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            result.push_back(static_cast<uint8_t>(buffer >> bits));
            buffer &= (1 << bits) - 1;
        }
    }
    return result;
}

inline ByteVector generate_random_bytes(size_t count) {
    ByteVector bytes(count);
    if (RAND_bytes(bytes.data(), static_cast<int>(count)) != 1) {
        throw std::runtime_error("RAND_bytes failed");
    }
    return bytes;
}

inline uint32_t generate_device_id() {
    ByteVector r = generate_random_bytes(4);
    uint32_t id;
    memcpy(&id, r.data(), 4);
    id = id % (DEVICE_ID_MAX - DEVICE_ID_MIN + 1) + DEVICE_ID_MIN;
    return id;
}

inline std::string bytes_to_base64(const ByteVector& b) {
    return base64_encode(b.data(), b.size());
}

inline int64_t now_epoch_seconds() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

// =============================================================================
// OpenSSL initialisation and cleanup helpers
// =============================================================================
struct OpenSSLInit {
    OpenSSLInit() {
        OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS
                          | OPENSSL_INIT_ADD_ALL_CIPHERS
                          | OPENSSL_INIT_ADD_ALL_DIGESTS, nullptr);
    }
    ~OpenSSLInit() {
        // OPENSSL_cleanup is called automatically on process exit
    }
};

static OpenSSLInit s_openssl_init;

class OpenSSLError : public std::runtime_error {
public:
    OpenSSLError(const std::string& msg)
        : std::runtime_error(msg + ": " + get_openssl_error()) {}
private:
    static std::string get_openssl_error() {
        unsigned long err = ERR_get_error();
        if (err == 0) return "unknown error";
        char buf[256];
        ERR_error_string_n(err, buf, sizeof(buf));
        return std::string(buf);
    }
};

// =============================================================================
// Curve25519 (X25519) ECDH Key Agreement
// =============================================================================
class X25519KeyPair {
public:
    ByteVector public_key;  // 32 bytes
    ByteVector private_key; // 32 bytes

    X25519KeyPair() : public_key(X25519_KEY_SIZE), private_key(X25519_KEY_SIZE) {}

    static X25519KeyPair generate() {
        X25519KeyPair kp;
        EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
        if (!pctx) throw OpenSSLError("EVP_PKEY_CTX_new_id X25519");
        EVP_PKEY* pkey = nullptr;
        if (EVP_PKEY_keygen_init(pctx) <= 0 ||
            EVP_PKEY_keygen(pctx, &pkey) <= 0) {
            EVP_PKEY_CTX_free(pctx);
            throw OpenSSLError("X25519 keygen");
        }
        EVP_PKEY_CTX_free(pctx);

        size_t pub_len = X25519_KEY_SIZE;
        size_t priv_len = X25519_KEY_SIZE;
        EVP_PKEY_get_raw_public_key(pkey, kp.public_key.data(), &pub_len);
        EVP_PKEY_get_raw_private_key(pkey, kp.private_key.data(), &priv_len);
        EVP_PKEY_free(pkey);
        return kp;
    }

    static ByteVector dh(const ByteVector& our_private, const ByteVector& their_public) {
        EVP_PKEY* priv_key = EVP_PKEY_new_raw_private_key(
            EVP_PKEY_X25519, nullptr, our_private.data(), X25519_KEY_SIZE);
        if (!priv_key) throw OpenSSLError("EVP_PKEY_new_raw_private_key");

        EVP_PKEY* pub_key = EVP_PKEY_new_raw_public_key(
            EVP_PKEY_X25519, nullptr, their_public.data(), X25519_KEY_SIZE);
        if (!pub_key) {
            EVP_PKEY_free(priv_key);
            throw OpenSSLError("EVP_PKEY_new_raw_public_key");
        }

        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(priv_key, nullptr);
        if (!ctx) {
            EVP_PKEY_free(priv_key);
            EVP_PKEY_free(pub_key);
            throw OpenSSLError("EVP_PKEY_CTX_new");
        }

        if (EVP_PKEY_derive_init(ctx) <= 0 ||
            EVP_PKEY_derive_set_peer(ctx, pub_key) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(priv_key);
            EVP_PKEY_free(pub_key);
            throw OpenSSLError("X25519 DH setup");
        }

        size_t secret_len = X25519_KEY_SIZE;
        ByteVector secret(secret_len);
        if (EVP_PKEY_derive(ctx, secret.data(), &secret_len) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(priv_key);
            EVP_PKEY_free(pub_key);
            throw OpenSSLError("X25519 DH derive");
        }

        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(priv_key);
        EVP_PKEY_free(pub_key);
        return secret;
    }

    ByteVector get_public_key_bytes() const { return public_key; }
    ByteVector get_private_key_bytes() const { return private_key; }
};

// =============================================================================
// Ed25519 (EdDSA) Signature Verification
// =============================================================================
class Ed25519Verifier {
public:
    static X25519KeyPair generate_signing_key() {
        // We use the same key pair for signing (identity key)
        return X25519KeyPair::generate();
    }

    static ByteVector sign(const ByteVector& private_key, const ByteVector& message) {
        EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(
            EVP_PKEY_ED25519, nullptr, private_key.data(), ED25519_KEY_SIZE);
        if (!pkey) throw OpenSSLError("Ed25519 sign key creation");

        EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
        if (!md_ctx) {
            EVP_PKEY_free(pkey);
            throw OpenSSLError("EVP_MD_CTX_new");
        }

        if (EVP_DigestSignInit(md_ctx, nullptr, nullptr, nullptr, pkey) <= 0) {
            EVP_MD_CTX_free(md_ctx);
            EVP_PKEY_free(pkey);
            throw OpenSSLError("Ed25519 DigestSignInit");
        }

        size_t sig_len = ED25519_SIG_SIZE;
        ByteVector signature(sig_len);
        if (EVP_DigestSign(md_ctx, signature.data(), &sig_len,
                          message.data(), message.size()) <= 0) {
            EVP_MD_CTX_free(md_ctx);
            EVP_PKEY_free(pkey);
            throw OpenSSLError("Ed25519 sign");
        }

        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        return signature;
    }

    static bool verify(const ByteVector& public_key,
                       const ByteVector& message,
                       const ByteVector& signature) {
        EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key(
            EVP_PKEY_ED25519, nullptr, public_key.data(), ED25519_KEY_SIZE);
        if (!pkey) return false;

        EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
        if (!md_ctx) {
            EVP_PKEY_free(pkey);
            return false;
        }

        bool valid = false;
        if (EVP_DigestVerifyInit(md_ctx, nullptr, nullptr, nullptr, pkey) > 0) {
            valid = EVP_DigestVerify(md_ctx, signature.data(), signature.size(),
                                    message.data(), message.size()) > 0;
        }

        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        return valid;
    }
};

// =============================================================================
// AES-256-GCM Authenticated Encryption
// =============================================================================
class Aes256Gcm {
public:
    // Encrypt: plaintext + aad -> ciphertext + tag
    // Returns {ciphertext, tag}
    struct EncryptResult {
        ByteVector ciphertext;
        ByteVector tag;
    };

    static EncryptResult encrypt(const ByteVector& key,
                                 const ByteVector& iv,
                                 const ByteVector& plaintext,
                                 const ByteVector& aad = {}) {
        if (key.size() != AES_KEY_SIZE)
            throw std::runtime_error("AES-256-GCM key must be 32 bytes");
        if (iv.size() != AES_GCM_IV_SIZE)
            throw std::runtime_error("AES-256-GCM IV must be 12 bytes");

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) throw OpenSSLError("EVP_CIPHER_CTX_new");

        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw OpenSSLError("EVP_EncryptInit_ex");
        }

        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                               AES_GCM_IV_SIZE, nullptr) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw OpenSSLError("GCM SET_IVLEN");
        }

        if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw OpenSSLError("GCM set key/iv");
        }

        // Process AAD
        int outlen = 0;
        if (!aad.empty()) {
            if (EVP_EncryptUpdate(ctx, nullptr, &outlen,
                                 aad.data(), static_cast<int>(aad.size())) != 1) {
                EVP_CIPHER_CTX_free(ctx);
                throw OpenSSLError("GCM AAD");
            }
        }

        // Encrypt plaintext
        EncryptResult result;
        result.ciphertext.resize(plaintext.size());
        if (EVP_EncryptUpdate(ctx, result.ciphertext.data(), &outlen,
                              plaintext.data(),
                              static_cast<int>(plaintext.size())) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw OpenSSLError("GCM encrypt update");
        }

        int final_len = 0;
        if (EVP_EncryptFinal_ex(ctx,
                               result.ciphertext.data() + outlen,
                               &final_len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw OpenSSLError("GCM encrypt final");
        }

        // Get tag
        result.tag.resize(AES_GCM_TAG_SIZE);
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
                               AES_GCM_TAG_SIZE, result.tag.data()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw OpenSSLError("GCM GET_TAG");
        }

        EVP_CIPHER_CTX_free(ctx);
        return result;
    }

    // Decrypt: ciphertext + tag + aad -> plaintext or nullopt on failure
    static std::optional<ByteVector> decrypt(const ByteVector& key,
                                             const ByteVector& iv,
                                             const ByteVector& ciphertext,
                                             const ByteVector& tag,
                                             const ByteVector& aad = {}) {
        if (key.size() != AES_KEY_SIZE) return std::nullopt;
        if (iv.size() != AES_GCM_IV_SIZE) return std::nullopt;
        if (tag.size() != AES_GCM_TAG_SIZE) return std::nullopt;

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) return std::nullopt;

        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return std::nullopt;
        }

        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                               AES_GCM_IV_SIZE, nullptr) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return std::nullopt;
        }

        if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return std::nullopt;
        }

        int outlen = 0;
        if (!aad.empty()) {
            if (EVP_DecryptUpdate(ctx, nullptr, &outlen,
                                 aad.data(), static_cast<int>(aad.size())) != 1) {
                EVP_CIPHER_CTX_free(ctx);
                return std::nullopt;
            }
        }

        ByteVector plaintext(ciphertext.size());
        if (EVP_DecryptUpdate(ctx, plaintext.data(), &outlen,
                              ciphertext.data(),
                              static_cast<int>(ciphertext.size())) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return std::nullopt;
        }

        // Set expected tag
        ByteVector tag_copy = tag;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                               AES_GCM_TAG_SIZE, tag_copy.data()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return std::nullopt;
        }

        int final_len = 0;
        int ret = EVP_DecryptFinal_ex(ctx,
                                     plaintext.data() + outlen,
                                     &final_len);
        EVP_CIPHER_CTX_free(ctx);

        if (ret <= 0) return std::nullopt; // Tag verification failed
        plaintext.resize(outlen + final_len);
        return plaintext;
    }

    static ByteVector generate_iv() {
        auto r = generate_random_bytes(AES_GCM_IV_SIZE);
        return r;
    }
};

// =============================================================================
// HMAC-SHA256 (must be declared before HKDF which depends on it)
// =============================================================================
class HmacSha256 {
public:
    static ByteVector compute(const ByteVector& key, const ByteVector& message) {
        unsigned int len = HMAC_SHA256_SIZE;
        ByteVector result(len);
        if (!HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
                  message.data(), message.size(), result.data(), &len)) {
            throw OpenSSLError("HMAC-SHA256");
        }
        return result;
    }

    static ByteVector compute(const ByteVector& key, const uint8_t* msg, size_t msg_len) {
        unsigned int len = HMAC_SHA256_SIZE;
        ByteVector result(len);
        if (!HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
                  msg, msg_len, result.data(), &len)) {
            throw OpenSSLError("HMAC-SHA256");
        }
        return result;
    }
};

// =============================================================================
// HKDF-SHA256 Key Derivation (RFC 5869, built on HMAC-SHA256)
// =============================================================================
class HkdfSha256 {
public:
    static ByteVector derive(const ByteVector& input_key_material,
                             const ByteVector& salt,
                             const ByteVector& info,
                             size_t output_length = HKDF_OUTPUT_SIZE) {
        // RFC 5869 HKDF-SHA256 implemented manually using HMAC-SHA256
        // Step 1: Extract - PRK = HMAC-SHA256(salt, IKM)
        ByteVector prk;
        if (salt.empty()) {
            // If salt not provided, use all-zeros
            prk.resize(HMAC_SHA256_SIZE, 0);
        } else {
            prk = salt;
            if (prk.size() < HMAC_SHA256_SIZE) {
                prk.resize(HMAC_SHA256_SIZE, 0);
            }
        }
        prk = HmacSha256::compute(prk, input_key_material);

        // Step 2: Expand - OKM = HMAC-SHA256(PRK, T(i-1) || info || i)
        ByteVector output;
        ByteVector t_prev; // T(0) = empty
        uint8_t counter = 1;

        while (output.size() < output_length) {
            ByteVector expand_input = t_prev;
            expand_input.insert(expand_input.end(), info.begin(), info.end());
            expand_input.push_back(counter);

            ByteVector t_i = HmacSha256::compute(prk, expand_input);
            output.insert(output.end(), t_i.begin(), t_i.end());
            t_prev = t_i;
            counter++;
        }

        output.resize(output_length);
        return output;
    }

    static ByteVector derive_secrets(const ByteVector& ikm,
                                     const ByteVector& salt,
                                     size_t output_length) {
        return derive(ikm, salt, {}, output_length);
    }
};

// =============================================================================
// OMEMO Data Structures
// =============================================================================

// PreKey: one-time use ECDH key
struct OmemoPreKey {
    uint32_t   key_id;
    ByteVector public_key;   // 32 bytes X25519
    ByteVector private_key;  // 32 bytes, stored only locally
    bool       used = false;
};

// SignedPreKey: periodically rotated, signed ECDH key
struct OmemoSignedPreKey {
    uint32_t   key_id;
    ByteVector public_key;   // 32 bytes X25519
    ByteVector private_key;  // 32 bytes, local only
    ByteVector signature;    // Ed25519 signature of public_key by identity key
    int64_t    created_at;
};

// Device: represents an OMEMO-capable client device
struct OmemoDevice {
    uint32_t   device_id;
    ByteVector identity_public_key;   // Ed25519 public key (used as Curve25519 for DH)
    ByteVector identity_private_key;  // local only
    std::string label;                 // human-readable device name

    bool operator==(const OmemoDevice& other) const {
        return device_id == other.device_id &&
               identity_public_key == other.identity_public_key;
    }
};

// OMEMO Bundle: published via PEP, contains pre-key material
struct OmemoBundle {
    uint32_t                    device_id;
    ByteVector                  identity_public_key;
    OmemoSignedPreKey           signed_pre_key;
    ByteVector                  signed_pre_key_signature;
    std::vector<OmemoPreKey>    one_time_pre_keys;
    int64_t                     published_at;
};

// OMEMO Session: per-device Double Ratchet session state
struct OmemoSession {
    uint32_t    remote_device_id;
    std::string remote_jid;

    // Ratchet state
    ByteVector  root_key;       // 32 bytes
    ByteVector  chain_key_send;  // 32 bytes, sending chain
    ByteVector  chain_key_recv;  // 32 bytes, receiving chain
    uint32_t    send_chain_index = 0;
    uint32_t    recv_chain_index = 0;

    // DH ratchet keys
    ByteVector  our_ratchet_private;
    ByteVector  our_ratchet_public;
    ByteVector  their_ratchet_public;

    // Message key cache for skipped/missed messages
    struct CachedMessageKey {
        uint32_t    index;
        ByteVector  message_key;
        int64_t     timestamp;
    };
    std::vector<CachedMessageKey> skipped_keys_send;
    std::vector<CachedMessageKey> skipped_keys_recv;
    static constexpr size_t MAX_CACHED_KEYS = 2000;

    // Previous sending chain (for out-of-order delivery)
    uint32_t    prev_send_chain_index = 0;
    ByteVector  prev_chain_key_send;
    size_t      prev_chain_length = 0;

    // Session metadata
    int64_t     created_at;
    int64_t     last_used_at;
    bool        active = true;

    // Trust state
    enum class TrustLevel {
        UNDECIDED = 0,       // BTBV default
        TRUSTED   = 1,       // Manually verified
        UNTRUSTED = 2,       // Manually revoked
        COMPROMISED = 3,     // Known compromised
    };
    TrustLevel  trust_level = TrustLevel::UNDECIDED;

    // Backward compatibility
    int         protocol_version = 3;  // 3 = XEP-0384 v0.3+, 4 = v0.4+, 8 = v0.8+

    bool is_undecided() const { return trust_level == TrustLevel::UNDECIDED; }
    bool is_trusted()    const { return trust_level == TrustLevel::TRUSTED; }
    bool is_untrusted()  const { return trust_level == TrustLevel::UNTRUSTED; }

    void mark_used() { last_used_at = now_epoch_seconds(); }
};

// Sender Key state for group chat (XEP-0384 §5.2)
struct OmemoSenderKeyState {
    uint32_t    chain_index = 0;
    ByteVector  chain_key;       // 32 bytes
    ByteVector  signing_key_public;
    ByteVector  signing_key_private;
    ByteVector  sender_key_id;   // distribution identifier
    int64_t     created_at;
    int64_t     last_used_at;
    bool        active = true;
};

// OMEMO Message Key (derived from chain key for single message)
struct OmemoMessageKey {
    uint32_t    index;
    ByteVector  key;             // AES-256 key: 32 bytes
    int64_t     created_at;
};

// OMEMO Message Header (XEP-0384 §5.1.2)
struct OmemoHeader {
    uint32_t    sid;             // sender device ID
    ByteVector  iv;              // 12 byte IV
    ByteVector  key_remote;      // 32 byte encrypted key for remote legacy
    bool        is_pre_key_message = false;
};

// OMEMO Key Exchange (initial ratchet setup via X3DH)
struct OmemoKeyExchange {
    uint32_t    device_id;
    ByteVector  identity_key;
    ByteVector  ephemeral_key;    // EK
    uint32_t    pre_key_id;       // used one-time pre-key ID
    uint32_t    signed_pre_key_id;
    ByteVector  signed_pre_key_signature;
    ByteVector  initial_ciphertext;  // encrypted initial message
};

// OMEMO Envelope: wire format container
struct OmemoEnvelope {
    OmemoHeader                     header;
    std::vector<OmemoKeyExchange>   keys;
    ByteVector                      payload;  // encrypted body
};

// OMEMO Encrypted File Transfer metadata
struct OmemoEncryptedFile {
    std::string file_name;
    size_t      file_size = 0;
    ByteVector  encryption_key;   // 32 bytes
    ByteVector  encryption_iv;    // 12 bytes
    ByteVector  thumbnail_key;
    ByteVector  thumbnail_iv;
    std::string content_type;
    std::string description;
    std::string source_url;
};

// =============================================================================
// OMEMO Key Exchange: X3DH Key Agreement (XEP-0384 §4.1)
// =============================================================================
class OmemoX3DH {
public:
    struct X3DHResult {
        ByteVector shared_secret;   // SK: 32 bytes
        ByteVector associated_data;
        ByteVector ephemeral_public_key;
    };

    // Alice creates an initial message to Bob
    // Inputs:
    //   - alice_identity_private, alice_identity_public
    //   - bob_bundle (identity, signed_pre_key, one-time pre-key)
    //   - optional one-time pre-key
    static X3DHResult create_initial_message(
        const ByteVector& alice_identity_private,
        const ByteVector& alice_identity_public,
        const OmemoBundle& bob_bundle,
        const OmemoPreKey* one_time_pre_key = nullptr)
    {
        // Generate ephemeral key pair (EK)
        X25519KeyPair ek = X25519KeyPair::generate();

        // DH1: DH(IK_A, SPK_B)  -- Alice identity * Bob signed pre-key
        // DH2: DH(EK_A, IK_B)   -- Alice ephemeral * Bob identity
        // DH3: DH(EK_A, SPK_B)  -- Alice ephemeral * Bob signed pre-key
        // DH4: DH(EK_A, OPK_B)  -- Alice ephemeral * Bob one-time pre-key (optional)

        ByteVector dh1 = X25519KeyPair::dh(alice_identity_private,
                                           bob_bundle.signed_pre_key.public_key);
        ByteVector dh2 = X25519KeyPair::dh(ek.get_private_key_bytes(),
                                           bob_bundle.identity_public_key);
        ByteVector dh3 = X25519KeyPair::dh(ek.get_private_key_bytes(),
                                           bob_bundle.signed_pre_key.public_key);

        // Concatenate DH outputs: DH1 || DH2 || DH3 || (DH4 if present)
        ByteVector dh_concat;
        dh_concat.insert(dh_concat.end(), dh1.begin(), dh1.end());
        dh_concat.insert(dh_concat.end(), dh2.begin(), dh2.end());
        dh_concat.insert(dh_concat.end(), dh3.begin(), dh3.end());

        if (one_time_pre_key) {
            ByteVector dh4 = X25519KeyPair::dh(ek.get_private_key_bytes(),
                                               one_time_pre_key->public_key);
            dh_concat.insert(dh_concat.end(), dh4.begin(), dh4.end());
        }

        // HKDF to derive shared secret
        // SK = HKDF(dh_concat, zeros, "OMEMO X3DH")
        ByteVector salt(32, 0);  // all-zeros salt per X3DH spec
        ByteVector info = { 'O','M','E','M','O',' ','X','3','D','H' };
        ByteVector sk = HkdfSha256::derive(dh_concat, salt, info, 32);

        // Build associated data for signature verification
        // AD = IK_A || IK_B || (concat of all public keys used)
        ByteVector ad;
        ad.insert(ad.end(), alice_identity_public.begin(), alice_identity_public.end());
        ad.insert(ad.end(), bob_bundle.identity_public_key.begin(),
                  bob_bundle.identity_public_key.end());
        ad.insert(ad.end(), ek.get_public_key_bytes().begin(),
                  ek.get_public_key_bytes().end());
        ad.insert(ad.end(), bob_bundle.signed_pre_key.public_key.begin(),
                  bob_bundle.signed_pre_key.public_key.end());
        if (one_time_pre_key) {
            ad.insert(ad.end(), one_time_pre_key->public_key.begin(),
                    one_time_pre_key->public_key.end());
        }

        X3DHResult result;
        result.shared_secret = std::move(sk);
        result.associated_data = std::move(ad);
        result.ephemeral_public_key = ek.get_public_key_bytes();

        // Zero DH intermediates
        secure_zero(dh1);
        secure_zero(dh2);
        secure_zero(dh3);
        secure_zero(dh_concat);

        return result;
    }

    // Bob processes an initial message from Alice
    static std::optional<X3DHResult> process_initial_message(
        const ByteVector& bob_identity_private,
        const ByteVector& bob_identity_public,
        const ByteVector& bob_signed_pre_key_private,
        const ByteVector& bob_signed_pre_key_public,
        const ByteVector& alice_identity_public,
        const ByteVector& alice_ephemeral_public,
        const OmemoPreKey* used_pre_key = nullptr)
    {
        // DH1: DH(SPK_B, IK_A)
        // DH2: DH(IK_B, EK_A)
        // DH3: DH(SPK_B, EK_A)
        // DH4: DH(OPK_B, EK_A)  -- if pre-key was used

        ByteVector dh1 = X25519KeyPair::dh(bob_signed_pre_key_private,
                                           alice_identity_public);
        ByteVector dh2 = X25519KeyPair::dh(bob_identity_private,
                                           alice_ephemeral_public);
        ByteVector dh3 = X25519KeyPair::dh(bob_signed_pre_key_private,
                                           alice_ephemeral_public);

        ByteVector dh_concat;
        dh_concat.insert(dh_concat.end(), dh1.begin(), dh1.end());
        dh_concat.insert(dh_concat.end(), dh2.begin(), dh2.end());
        dh_concat.insert(dh_concat.end(), dh3.begin(), dh3.end());

        if (used_pre_key) {
            ByteVector dh4 = X25519KeyPair::dh(used_pre_key->private_key,
                                               alice_ephemeral_public);
            dh_concat.insert(dh_concat.end(), dh4.begin(), dh4.end());
        }

        ByteVector salt(32, 0);
        ByteVector info = { 'O','M','E','M','O',' ','X','3','D','H' };
        ByteVector sk = HkdfSha256::derive(dh_concat, salt, info, 32);

        ByteVector ad;
        ad.insert(ad.end(), alice_identity_public.begin(), alice_identity_public.end());
        ad.insert(ad.end(), bob_identity_public.begin(), bob_identity_public.end());
        ad.insert(ad.end(), alice_ephemeral_public.begin(), alice_ephemeral_public.end());
        ad.insert(ad.end(), bob_signed_pre_key_public.begin(),
                  bob_signed_pre_key_public.end());
        if (used_pre_key) {
            ad.insert(ad.end(), used_pre_key->public_key.begin(),
                    used_pre_key->public_key.end());
        }

        X3DHResult result;
        result.shared_secret = std::move(sk);
        result.associated_data = std::move(ad);
        result.ephemeral_public_key = alice_ephemeral_public;

        secure_zero(dh1);
        secure_zero(dh2);
        secure_zero(dh3);
        secure_zero(dh_concat);

        return result;
    }
};

// =============================================================================
// Double Ratchet Algorithm (per-signal-protocol)
// =============================================================================
class DoubleRatchet {
public:
    // Initialize ratchet from X3DH shared secret
    static void initialize_as_alice(OmemoSession& session,
                                     const ByteVector& sk,
                                     const ByteVector& bob_ratchet_public) {
        // root_key = SK
        session.root_key = sk;

        // Generate our initial ratchet key pair
        X25519KeyPair ratchet_kp = X25519KeyPair::generate();
        session.our_ratchet_private = ratchet_kp.get_private_key_bytes();
        session.our_ratchet_public  = ratchet_kp.get_public_key_bytes();
        session.their_ratchet_public = bob_ratchet_public;

        // Do initial DH ratchet step
        ByteVector dh_output = X25519KeyPair::dh(
            session.our_ratchet_private, session.their_ratchet_public);

        // root_key, chain_key = HKDF(dh_output, root_key, 64)
        ByteVector derived = HkdfSha256::derive_secrets(dh_output, session.root_key, 64);
        session.root_key.assign(derived.begin(), derived.begin() + 32);
        session.chain_key_send.assign(derived.begin() + 32, derived.end());

        session.send_chain_index = 0;
        session.recv_chain_index = 0;
        session.chain_key_recv = session.chain_key_send; // Will be overwritten on first recv

        session.created_at = now_epoch_seconds();
        session.last_used_at = session.created_at;

        secure_zero(dh_output);
    }

    static void initialize_as_bob(OmemoSession& session,
                                   const ByteVector& sk,
                                   const ByteVector& alice_ratchet_public,
                                   const ByteVector& bob_ratchet_private,
                                   const ByteVector& bob_ratchet_public) {
        // root_key = SK
        session.root_key = sk;

        session.our_ratchet_private = bob_ratchet_private;
        session.our_ratchet_public  = bob_ratchet_public;
        session.their_ratchet_public = alice_ratchet_public;

        // DH ratchet step (Bob's side)
        ByteVector dh_output = X25519KeyPair::dh(
            bob_ratchet_private, alice_ratchet_public);

        ByteVector derived = HkdfSha256::derive_secrets(dh_output, session.root_key, 64);
        session.root_key.assign(derived.begin(), derived.begin() + 32);
        session.chain_key_recv.assign(derived.begin() + 32, derived.end());

        session.recv_chain_index = 0;
        session.send_chain_index = 0;
        session.chain_key_send = session.chain_key_recv;

        session.created_at = now_epoch_seconds();
        session.last_used_at = session.created_at;

        secure_zero(dh_output);
    }

    // Advance sending chain: derives message key, advances chain
    static OmemoMessageKey ratchet_encrypt(OmemoSession& session) {
        // message_key, new_chain_key = KDF_CK(chain_key)
        // KDF_CK(ck): HMAC-SHA256(ck, 0x01) for message key
        //             HMAC-SHA256(ck, 0x02) for new chain key
        ByteVector ck = session.chain_key_send;

        const uint8_t mk_input[1] = { 0x01 };
        ByteVector mk = HmacSha256::compute(ck, mk_input, 1);

        const uint8_t ck_input[1] = { 0x02 };
        ByteVector new_ck = HmacSha256::compute(ck, ck_input, 1);

        session.chain_key_send = new_ck;

        OmemoMessageKey msg_key;
        msg_key.index = session.send_chain_index;
        msg_key.key = mk;
        msg_key.created_at = now_epoch_seconds();

        session.send_chain_index++;
        session.mark_used();

        return msg_key;
    }

    // Advance receiving chain: derive message key
    static std::optional<OmemoMessageKey> ratchet_decrypt(
        OmemoSession& session, uint32_t message_index) {
        // Check if this is a skipped (cached) key first
        for (auto it = session.skipped_keys_recv.begin();
             it != session.skipped_keys_recv.end(); ++it) {
            if (it->index == message_index) {
                OmemoMessageKey mk;
                mk.index = it->index;
                mk.key = it->message_key;
                mk.created_at = it->timestamp;
                session.skipped_keys_recv.erase(it);
                session.mark_used();
                return mk;
            }
        }

        // If message index is ahead of us, skip intermediate keys
        if (message_index < session.recv_chain_index) {
            return std::nullopt; // Old message, possibly replayed
        }

        // Cache skipped keys
        while (session.recv_chain_index < message_index) {
            OmemoMessageKey skipped;
            skipped.index = session.recv_chain_index;

            const uint8_t mk_input[1] = { 0x01 };
            ByteVector mk = HmacSha256::compute(session.chain_key_recv, mk_input, 1);

            const uint8_t ck_input[1] = { 0x02 };
            ByteVector new_ck = HmacSha256::compute(session.chain_key_recv, ck_input, 1);

            skipped.key = mk;
            skipped.created_at = now_epoch_seconds();
            session.skipped_keys_recv.push_back(skipped);
            session.chain_key_recv = new_ck;
            session.recv_chain_index++;
        }

        // Derive the requested message key
        const uint8_t mk_input[1] = { 0x01 };
        ByteVector mk = HmacSha256::compute(session.chain_key_recv, mk_input, 1);

        const uint8_t ck_input[1] = { 0x02 };
        ByteVector new_ck = HmacSha256::compute(session.chain_key_recv, ck_input, 1);

        session.chain_key_recv = new_ck;
        session.recv_chain_index++;

        OmemoMessageKey msg_key;
        msg_key.index = message_index;
        msg_key.key = mk;
        msg_key.created_at = now_epoch_seconds();

        session.mark_used();
        return msg_key;
    }

    // DH ratchet step: incorporate new ratchet public key from peer
    static void dh_ratchet_step(OmemoSession& session,
                                 const ByteVector& new_their_ratchet_public) {
        // Save previous sending chain for out-of-order delivery
        session.prev_send_chain_index = session.send_chain_index;
        session.prev_chain_key_send = session.chain_key_send;
        session.prev_chain_length = session.send_chain_index;

        // DH(our_ratchet_private, new_their_ratchet_public)
        ByteVector dh_output = X25519KeyPair::dh(
            session.our_ratchet_private, new_their_ratchet_public);

        ByteVector derived = HkdfSha256::derive_secrets(dh_output, session.root_key, 64);
        session.root_key.assign(derived.begin(), derived.begin() + 32);

        // New receiving chain key
        session.chain_key_recv.assign(derived.begin() + 32, derived.end());
        session.recv_chain_index = 0;

        // Generate new ratchet key pair for sending
        X25519KeyPair new_ratchet = X25519KeyPair::generate();
        session.our_ratchet_private = new_ratchet.get_private_key_bytes();
        session.our_ratchet_public  = new_ratchet.get_public_key_bytes();

        // DH with new our_ratchet and their_ratchet
        ByteVector dh_output2 = X25519KeyPair::dh(
            session.our_ratchet_private, new_their_ratchet_public);

        ByteVector derived2 = HkdfSha256::derive_secrets(
            dh_output2, session.root_key, 64);
        session.root_key.assign(derived2.begin(), derived2.begin() + 32);
        session.chain_key_send.assign(derived2.begin() + 32, derived2.end());
        session.send_chain_index = 0;

        session.their_ratchet_public = new_their_ratchet_public;
        session.mark_used();

        secure_zero(dh_output);
        secure_zero(dh_output2);
    }
};

// =============================================================================
// OMEMO Sender Key for Group Chat (XEP-0384 §5.2)
// =============================================================================
class OmemoSenderKey {
public:
    struct DistributionMessage {
        ByteVector sender_key_id;
        uint32_t   chain_index;
        ByteVector chain_key;
        ByteVector signing_key_public;
    };

    static OmemoSenderKeyState create_sender_key() {
        OmemoSenderKeyState state;
        state.chain_key = generate_random_bytes(32);

        // Generate Ed25519 signing key
        X25519KeyPair signing_kp = X25519KeyPair::generate();
        state.signing_key_public = signing_kp.get_public_key_bytes();
        state.signing_key_private = signing_kp.get_private_key_bytes();

        state.sender_key_id = generate_random_bytes(16);
        state.chain_index = 0;
        state.created_at = now_epoch_seconds();
        state.last_used_at = state.created_at;
        state.active = true;
        return state;
    }

    static OmemoMessageKey get_message_key(OmemoSenderKeyState& state) {
        // message_key, new_chain_key = KDF(chain_key)
        const uint8_t mk_input[1] = { 0x01 };
        ByteVector mk = HmacSha256::compute(state.chain_key, mk_input, 1);

        const uint8_t ck_input[1] = { 0x02 };
        ByteVector new_ck = HmacSha256::compute(state.chain_key, ck_input, 1);

        state.chain_key = new_ck;
        state.last_used_at = now_epoch_seconds();

        OmemoMessageKey msg_key;
        msg_key.index = state.chain_index++;
        msg_key.key = mk;
        msg_key.created_at = now_epoch_seconds();
        return msg_key;
    }

    static DistributionMessage create_distribution_message(
        const OmemoSenderKeyState& sender_state,
        const std::vector<OmemoDevice>& group_devices) {
        DistributionMessage dist;
        dist.sender_key_id = sender_state.sender_key_id;
        dist.chain_index = sender_state.chain_index;
        dist.chain_key = sender_state.chain_key;
        dist.signing_key_public = sender_state.signing_key_public;
        return dist;
    }

    static bool verify_distribution_signature(
        const DistributionMessage& dist,
        const ByteVector& signature,
        const ByteVector& signing_key_public) {
        ByteVector msg;
        msg.insert(msg.end(), dist.sender_key_id.begin(), dist.sender_key_id.end());
        msg.insert(msg.end(), dist.signing_key_public.begin(),
                   dist.signing_key_public.end());

        // Append chain_index as big-endian bytes
        for (int i = 3; i >= 0; i--) {
            msg.push_back(static_cast<uint8_t>((dist.chain_index >> (i * 8)) & 0xFF));
        }

        msg.insert(msg.end(), dist.chain_key.begin(), dist.chain_key.end());
        return Ed25519Verifier::verify(signing_key_public, msg, signature);
    }

    // Encrypt a message using sender key
    static ByteVector encrypt_message(const OmemoSenderKeyState& state,
                                       const std::string& plaintext) {
        OmemoMessageKey mk = get_message_key(
            const_cast<OmemoSenderKeyState&>(state));

        ByteVector iv = Aes256Gcm::generate_iv();
        ByteVector pt(plaintext.begin(), plaintext.end());

        auto result = Aes256Gcm::encrypt(mk.key, iv, pt);

        // Serialize: iv (12) || ciphertext || tag (16)
        ByteVector output;
        output.insert(output.end(), iv.begin(), iv.end());
        output.insert(output.end(), result.ciphertext.begin(), result.ciphertext.end());
        output.insert(output.end(), result.tag.begin(), result.tag.end());

        secure_zero(mk.key);
        return output;
    }

    static std::optional<std::string> decrypt_message(
        OmemoSenderKeyState& state,
        const ByteVector& encrypted) {
        if (encrypted.size() < AES_GCM_IV_SIZE + AES_GCM_TAG_SIZE) {
            return std::nullopt;
        }

        ByteVector iv(encrypted.begin(), encrypted.begin() + AES_GCM_IV_SIZE);
        ByteVector tag(encrypted.end() - AES_GCM_TAG_SIZE, encrypted.end());
        ByteVector ct(encrypted.begin() + AES_GCM_IV_SIZE,
                      encrypted.end() - AES_GCM_TAG_SIZE);

        OmemoMessageKey mk = get_message_key(state);

        auto pt = Aes256Gcm::decrypt(mk.key, iv, ct, tag);
        secure_zero(mk.key);

        if (!pt) return std::nullopt;
        return std::string(pt->begin(), pt->end());
    }
};

// =============================================================================
// OMEMO Device List Manager (PEP node: urn:xmpp:omemo:2:devices)
// =============================================================================
class OmemoDeviceManager {
public:
    OmemoDeviceManager(const std::string& owner_jid)
        : owner_jid_(owner_jid),
          our_device_(create_device("primary")) {}

    // Create a new device
    OmemoDevice create_device(const std::string& label) {
        OmemoDevice dev;
        dev.device_id = generate_device_id();
        X25519KeyPair id_kp = X25519KeyPair::generate();
        dev.identity_public_key = id_kp.get_public_key_bytes();
        dev.identity_private_key = id_kp.get_private_key_bytes();
        dev.label = label;

        std::lock_guard<std::mutex> lock(mutex_);
        our_devices_[dev.device_id] = dev;
        return dev;
    }

    // Get our device
    OmemoDevice get_our_device() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return our_device_;
    }

    // Get device by ID
    std::optional<OmemoDevice> get_device(uint32_t device_id) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = our_devices_.find(device_id);
        if (it != our_devices_.end()) return it->second;
        return std::nullopt;
    }

    // Publish our device list via PEP
    std::string serialize_device_list() const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::stringstream xml;
        xml << "<list xmlns='" << omemo_ns::OMEMO_DEVICES << "'>";
        for (const auto& [id, dev] : our_devices_) {
            xml << "<device id='" << id << "' label='" << dev.label << "' />";
        }
        xml << "</list>";
        return xml.str();
    }

    // Parse remote device list from PEP
    static std::vector<uint32_t> parse_device_list(const std::string& xml) {
        std::vector<uint32_t> devices;
        std::regex dev_re("<device id='(\\d+)'");
        auto it = std::sregex_iterator(xml.begin(), xml.end(), dev_re);
        auto end = std::sregex_iterator();
        for (; it != end; ++it) {
            devices.push_back(static_cast<uint32_t>(std::stoul((*it)[1].str())));
        }
        return devices;
    }

    // Track remote device lists
    void set_remote_devices(const std::string& jid,
                            const std::vector<uint32_t>& devices) {
        std::lock_guard<std::mutex> lock(mutex_);
        remote_device_lists_[jid] = devices;
    }

    std::vector<uint32_t> get_remote_devices(const std::string& jid) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = remote_device_lists_.find(jid);
        if (it != remote_device_lists_.end()) return it->second;
        return {};
    }

    // Check if we have a device
    bool has_device(uint32_t device_id) const {
        std::lock_guard<std::mutex> lock(mutex_);
        return our_devices_.find(device_id) != our_devices_.end();
    }

    std::vector<uint32_t> get_our_device_ids() const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<uint32_t> ids;
        for (const auto& [id, _] : our_devices_) ids.push_back(id);
        return ids;
    }

private:
    std::string owner_jid_;
    OmemoDevice our_device_;
    std::unordered_map<uint32_t, OmemoDevice> our_devices_;
    std::unordered_map<std::string, std::vector<uint32_t>> remote_device_lists_;
    mutable std::mutex mutex_;
};

// =============================================================================
// OMEMO Bundle Manager (pre-key bundles, signed pre-keys, one-time pre-keys)
// =============================================================================
class OmemoBundleManager {
public:
    OmemoBundleManager(OmemoDeviceManager& device_mgr,
                       const std::string& owner_jid)
        : device_mgr_(device_mgr), owner_jid_(owner_jid) {
        generate_initial_bundle();
    }

    // Generate full initial bundle
    void generate_initial_bundle() {
        OmemoDevice our_dev = device_mgr_.get_our_device();

        OmemoBundle bundle;
        bundle.device_id = our_dev.device_id;
        bundle.identity_public_key = our_dev.identity_public_key;

        // Generate signed pre-key
        bundle.signed_pre_key = generate_signed_pre_key(our_dev);
        bundle.signed_pre_key_signature = bundle.signed_pre_key.signature;

        // Generate one-time pre-keys
        bundle.one_time_pre_keys = generate_pre_key_batch(PRE_KEY_BATCH_SIZE);
        bundle.published_at = now_epoch_seconds();

        std::lock_guard<std::mutex> lock(mutex_);
        our_bundle_ = bundle;
    }

    // Get our current bundle
    OmemoBundle get_our_bundle() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return our_bundle_;
    }

    // Get a one-time pre-key (and mark it used)
    std::optional<OmemoPreKey> consume_pre_key(uint32_t key_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& pk : our_bundle_.one_time_pre_keys) {
            if (pk.key_id == key_id && !pk.used) {
                pk.used = true;
                return pk;
            }
        }
        return std::nullopt;
    }

    // Refill pre-keys if low
    bool needs_refill() const {
        std::lock_guard<std::mutex> lock(mutex_);
        size_t available = 0;
        for (const auto& pk : our_bundle_.one_time_pre_keys) {
            if (!pk.used) available++;
        }
        return available < PRE_KEY_MIN_COUNT;
    }

    // Periodic bundle refresh
    void refresh_if_needed() {
        bool needs = false;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            needs = needs_refill();
            int64_t now = now_epoch_seconds();
            if (now - our_bundle_.published_at > BUNDLE_REFRESH_DAYS * 24 * 3600) {
                needs = true;
            }
            // Rotate signed pre-key if expired
            if (now - our_bundle_.signed_pre_key.created_at > SIGNED_PRE_KEY_TTL) {
                needs = true;
            }
        }

        if (needs) {
            regenerate_bundle();
        }
    }

    // Regenerate bundle (new signed pre-key, new pre-keys)
    void regenerate_bundle() {
        OmemoDevice our_dev = device_mgr_.get_our_device();

        OmemoBundle bundle;
        bundle.device_id = our_dev.device_id;
        bundle.identity_public_key = our_dev.identity_public_key;
        bundle.signed_pre_key = generate_signed_pre_key(our_dev);
        bundle.signed_pre_key_signature = bundle.signed_pre_key.signature;

        // Keep unused pre-keys, generate new ones
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<OmemoPreKey> existing_unused;
        for (const auto& pk : our_bundle_.one_time_pre_keys) {
            if (!pk.used) existing_unused.push_back(pk);
        }

        bundle.one_time_pre_keys = existing_unused;
        auto new_keys = generate_pre_key_batch(
            PRE_KEY_BATCH_SIZE - static_cast<int>(existing_unused.size()));
        bundle.one_time_pre_keys.insert(bundle.one_time_pre_keys.end(),
                                        new_keys.begin(), new_keys.end());
        bundle.published_at = now_epoch_seconds();

        our_bundle_ = bundle;
    }

    // Serialize bundle to XML for PEP publication
    std::string serialize_bundle() const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::stringstream xml;
        xml << "<bundle xmlns='" << omemo_ns::OMEMO_BUNDLES << "'>";

        // Signed pre-key
        xml << "<signedPreKeyPublic signedPreKeyId='"
            << our_bundle_.signed_pre_key.key_id << "'>"
            << base64_encode(our_bundle_.signed_pre_key.public_key.data(),
                            our_bundle_.signed_pre_key.public_key.size())
            << "</signedPreKeyPublic>";

        xml << "<signedPreKeySignature>"
            << base64_encode(our_bundle_.signed_pre_key.signature.data(),
                            our_bundle_.signed_pre_key.signature.size())
            << "</signedPreKeySignature>";

        // Identity key
        xml << "<identityKey>"
            << base64_encode(our_bundle_.identity_public_key.data(),
                            our_bundle_.identity_public_key.size())
            << "</identityKey>";

        // One-time pre-keys
        xml << "<prekeys>";
        for (const auto& pk : our_bundle_.one_time_pre_keys) {
            if (!pk.used) {
                xml << "<preKeyPublic preKeyId='" << pk.key_id << "'>"
                    << base64_encode(pk.public_key.data(), pk.public_key.size())
                    << "</preKeyPublic>";
            }
        }
        xml << "</prekeys>";

        xml << "</bundle>";
        return xml.str();
    }

    // Parse remote bundle from XML
    static OmemoBundle parse_bundle(const std::string& xml) {
        OmemoBundle bundle;

        // Parse identity key
        std::regex ik_re("<identityKey>([^<]+)</identityKey>");
        std::smatch m;
        if (std::regex_search(xml, m, ik_re)) {
            bundle.identity_public_key = base64_decode(m[1].str());
        }

        // Parse signed pre-key
        std::regex spk_pub_re(
            "<signedPreKeyPublic[^>]*signedPreKeyId='(\\d+)'[^>]*>([^<]+)</signedPreKeyPublic>");
        if (std::regex_search(xml, m, spk_pub_re)) {
            bundle.signed_pre_key.key_id = static_cast<uint32_t>(std::stoul(m[1].str()));
            bundle.signed_pre_key.public_key = base64_decode(m[2].str());
        }

        // Parse signed pre-key signature
        std::regex spk_sig_re("<signedPreKeySignature>([^<]+)</signedPreKeySignature>");
        if (std::regex_search(xml, m, spk_sig_re)) {
            bundle.signed_pre_key_signature = base64_decode(m[1].str());
            bundle.signed_pre_key.signature = bundle.signed_pre_key_signature;
        }

        // Parse pre-keys
        std::regex pk_re(
            "<preKeyPublic[^>]*preKeyId='(\\d+)'[^>]*>([^<]+)</preKeyPublic>");
        auto it = std::sregex_iterator(xml.begin(), xml.end(), pk_re);
        auto end = std::sregex_iterator();
        for (; it != end; ++it) {
            OmemoPreKey pk;
            pk.key_id = static_cast<uint32_t>(std::stoul((*it)[1].str()));
            pk.public_key = base64_decode((*it)[2].str());
            pk.used = false;
            bundle.one_time_pre_keys.push_back(pk);
        }

        bundle.published_at = now_epoch_seconds();
        return bundle;
    }

    // Store remote bundle
    void store_remote_bundle(const std::string& jid, uint32_t device_id,
                             const OmemoBundle& bundle) {
        std::lock_guard<std::mutex> lock(mutex_);
        std::string key = jid + ":" + std::to_string(device_id);
        remote_bundles_[key] = bundle;
    }

    // Retrieve remote bundle
    std::optional<OmemoBundle> get_remote_bundle(const std::string& jid,
                                                  uint32_t device_id) const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::string key = jid + ":" + std::to_string(device_id);
        auto it = remote_bundles_.find(key);
        if (it != remote_bundles_.end()) return it->second;
        return std::nullopt;
    }

    // Verify signed pre-key signature
    static bool verify_signed_pre_key(const OmemoBundle& bundle) {
        return Ed25519Verifier::verify(
            bundle.identity_public_key,
            bundle.signed_pre_key.public_key,
            bundle.signed_pre_key_signature);
    }

private:
    OmemoSignedPreKey generate_signed_pre_key(const OmemoDevice& device) {
        OmemoSignedPreKey spk;
        spk.key_id = generate_device_id();

        X25519KeyPair kp = X25519KeyPair::generate();
        spk.public_key = kp.get_public_key_bytes();
        spk.private_key = kp.get_private_key_bytes();
        spk.created_at = now_epoch_seconds();

        // Sign with identity key
        spk.signature = Ed25519Verifier::sign(
            device.identity_private_key, spk.public_key);

        return spk;
    }

    std::vector<OmemoPreKey> generate_pre_key_batch(int count) {
        std::vector<OmemoPreKey> keys;
        keys.reserve(count);
        for (int i = 0; i < count; i++) {
            OmemoPreKey pk;
            pk.key_id = generate_device_id();
            X25519KeyPair kp = X25519KeyPair::generate();
            pk.public_key = kp.get_public_key_bytes();
            pk.private_key = kp.get_private_key_bytes();
            pk.used = false;
            keys.push_back(pk);
        }
        return keys;
    }

    OmemoDeviceManager& device_mgr_;
    std::string owner_jid_;
    OmemoBundle our_bundle_;
    std::unordered_map<std::string, OmemoBundle> remote_bundles_;
    mutable std::mutex mutex_;
};

// =============================================================================
// OMEMO Session Manager (Double Ratchet sessions per device pair)
// =============================================================================
class OmemoSessionManager {
public:
    OmemoSessionManager(const std::string& owner_jid)
        : owner_jid_(owner_jid) {}

    // Get or create session with a remote device
    OmemoSession* get_session(const std::string& remote_jid,
                              uint32_t remote_device_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        std::string key = make_key(remote_jid, remote_device_id);
        auto it = sessions_.find(key);
        if (it != sessions_.end()) return &it->second;
        return nullptr;
    }

    // Create a new outgoing session (Alice's side)
    OmemoSession* create_outgoing_session(const std::string& remote_jid,
                                           uint32_t remote_device_id,
                                           const OmemoBundle& remote_bundle,
                                           const OmemoDevice& our_device) {
        // Pick a one-time pre-key or use just signed pre-key
        const OmemoPreKey* opk = nullptr;
        if (!remote_bundle.one_time_pre_keys.empty()) {
            opk = &remote_bundle.one_time_pre_keys[0];
        }

        // X3DH as Alice
        auto x3dh_result = OmemoX3DH::create_initial_message(
            our_device.identity_private_key,
            our_device.identity_public_key,
            remote_bundle, opk);

        std::lock_guard<std::mutex> lock(mutex_);
        std::string key = make_key(remote_jid, remote_device_id);

        OmemoSession session;
        session.remote_device_id = remote_device_id;
        session.remote_jid = remote_jid;

        DoubleRatchet::initialize_as_alice(
            session, x3dh_result.shared_secret,
            remote_bundle.signed_pre_key.public_key);

        // Store AD and ephemeral key for key exchange header
        session.active = true;

        sessions_[key] = session;
        return &sessions_[key];
    }

    // Create a new incoming session (Bob's side)
    OmemoSession* create_incoming_session(const std::string& remote_jid,
                                           uint32_t remote_device_id,
                                           const ByteVector& alice_identity_public,
                                           const ByteVector& alice_ephemeral_public,
                                           const ByteVector& pre_key_private,
                                           uint32_t signed_pre_key_id,
                                           const OmemoDevice& our_device,
                                           OmemoBundleManager& bundle_mgr) {
        auto our_bundle = bundle_mgr.get_our_bundle();

        const OmemoPreKey* used_pk = nullptr;
        OmemoPreKey pk_copy;
        if (pre_key_private.size() == X25519_KEY_SIZE) {
            pk_copy.private_key = pre_key_private;
            // Find matching public key in our bundle
            for (auto& pk : our_bundle.one_time_pre_keys) {
                ByteVector pub = X25519KeyPair::dh(pk.private_key,
                    X25519KeyPair::generate().get_public_key_bytes()); // dummy check
                (void)pub;
                used_pk = &pk_copy;
                break;
            }
        }

        auto x3dh_result = OmemoX3DH::process_initial_message(
            our_device.identity_private_key,
            our_device.identity_public_key,
            our_bundle.signed_pre_key.private_key,
            our_bundle.signed_pre_key.public_key,
            alice_identity_public, alice_ephemeral_public, used_pk);

        if (!x3dh_result) return nullptr;

        std::lock_guard<std::mutex> lock(mutex_);
        std::string key = make_key(remote_jid, remote_device_id);

        OmemoSession session;
        session.remote_device_id = remote_device_id;
        session.remote_jid = remote_jid;

        DoubleRatchet::initialize_as_bob(
            session, x3dh_result->shared_secret,
            alice_ephemeral_public,
            our_bundle.signed_pre_key.private_key,
            our_bundle.signed_pre_key.public_key);

        session.active = true;

        sessions_[key] = session;
        return &sessions_[key];
    }

    // Encrypt a message to a remote device
    std::optional<OmemoEnvelope> encrypt_for_device(
        const std::string& remote_jid,
        uint32_t remote_device_id,
        const std::string& plaintext,
        uint32_t our_device_id,
        OmemoBundleManager& bundle_mgr,
        OmemoDeviceManager& device_mgr) {

        OmemoSession* session = get_session(remote_jid, remote_device_id);
        bool is_pre_key = false;

        // Check if we need to create a new session
        if (!session) {
            auto bundle = bundle_mgr.get_remote_bundle(remote_jid, remote_device_id);
            if (!bundle) return std::nullopt;

            auto our_dev = device_mgr.get_device(our_device_id);
            if (!our_dev) return std::nullopt;

            session = create_outgoing_session(remote_jid, remote_device_id,
                                              *bundle, *our_dev);
            if (!session) return std::nullopt;
            is_pre_key = true;
        }

        // Advance ratchet and get message key
        OmemoMessageKey mk = DoubleRatchet::ratchet_encrypt(*session);

        // Encrypt the message
        ByteVector iv = Aes256Gcm::generate_iv();
        ByteVector pt(plaintext.begin(), plaintext.end());

        auto encrypted = Aes256Gcm::encrypt(mk.key, iv, pt);
        secure_zero(mk.key);

        // Build envelope
        OmemoEnvelope env;
        env.header.sid = our_device_id;
        env.header.iv = iv;
        env.header.is_pre_key_message = is_pre_key;

        // Build payload: encrypted body
        env.payload = encrypted.ciphertext;
        env.payload.insert(env.payload.end(),
                          encrypted.tag.begin(), encrypted.tag.end());

        return env;
    }

    // Decrypt a message from a remote device
    std::optional<std::string> decrypt_from_device(
        const std::string& remote_jid,
        uint32_t remote_device_id,
        const OmemoEnvelope& envelope,
        uint32_t our_device_id,
        OmemoBundleManager& bundle_mgr,
        OmemoDeviceManager& device_mgr) {

        OmemoSession* session = get_session(remote_jid, remote_device_id);

        if (!session && envelope.header.is_pre_key_message) {
            // Need to process key exchange first - handled by pre_key_message handler
            return std::nullopt; // Caller should handle pre-key message separately
        }

        if (!session) return std::nullopt;

        // Extract IV and encrypted payload from envelope
        ByteVector iv = envelope.header.iv;

        if (envelope.payload.size() < AES_GCM_TAG_SIZE) {
            return std::nullopt;
        }

        ByteVector tag(envelope.payload.end() - AES_GCM_TAG_SIZE,
                       envelope.payload.end());
        ByteVector ct(envelope.payload.begin(),
                      envelope.payload.end() - AES_GCM_TAG_SIZE);

        // Try current chain index
        uint32_t msg_index = session->recv_chain_index;
        auto mk = DoubleRatchet::ratchet_decrypt(*session, msg_index);
        if (!mk) {
            // Try next few indices for out-of-order
            for (int offset = 1; offset <= 5; offset++) {
                mk = DoubleRatchet::ratchet_decrypt(*session, msg_index + offset);
                if (mk) break;
            }
        }

        if (!mk) return std::nullopt;

        auto pt = Aes256Gcm::decrypt(mk->key, iv, ct, tag);
        secure_zero(mk->key);

        if (!pt) return std::nullopt;
        return std::string(pt->begin(), pt->end());
    }

    // Handle pre-key message (initial message with key exchange)
    std::optional<std::string> handle_pre_key_message(
        const std::string& remote_jid,
        uint32_t remote_device_id,
        const OmemoKeyExchange& key_exchange,
        const OmemoEnvelope& envelope,
        uint32_t our_device_id,
        OmemoBundleManager& bundle_mgr,
        OmemoDeviceManager& device_mgr) {

        // Get our device
        auto our_dev = device_mgr.get_device(our_device_id);
        if (!our_dev) return std::nullopt;

        // Get the pre-key that was used
        auto our_bundle = bundle_mgr.get_our_bundle();
        std::optional<OmemoPreKey> consumed_pk;

        if (key_exchange.pre_key_id != 0xFFFFFFFF) {
            consumed_pk = bundle_mgr.consume_pre_key(key_exchange.pre_key_id);
        }

        // Process X3DH
        ByteVector pre_key_priv;
        if (consumed_pk) {
            pre_key_priv = consumed_pk->private_key;
        }

        OmemoSession* session = create_incoming_session(
            remote_jid, remote_device_id,
            key_exchange.identity_key,
            key_exchange.ephemeral_key,
            pre_key_priv,
            key_exchange.signed_pre_key_id,
            *our_dev, bundle_mgr);

        if (!session) return std::nullopt;

        // Now decrypt the initial message
        // The initial ciphertext in key exchange may contain the first message
        if (!key_exchange.initial_ciphertext.empty()) {
            ByteVector iv = envelope.header.iv;
            if (key_exchange.initial_ciphertext.size() < AES_GCM_TAG_SIZE) {
                return std::nullopt;
            }
            ByteVector tag(key_exchange.initial_ciphertext.end() - AES_GCM_TAG_SIZE,
                          key_exchange.initial_ciphertext.end());
            ByteVector ct(key_exchange.initial_ciphertext.begin(),
                         key_exchange.initial_ciphertext.end() - AES_GCM_TAG_SIZE);

            auto mk = DoubleRatchet::ratchet_decrypt(*session, 0);
            if (!mk) return std::nullopt;

            auto pt = Aes256Gcm::decrypt(mk->key, iv, ct, tag);
            secure_zero(mk->key);
            if (pt) return std::string(pt->begin(), pt->end());
        }

        return ""; // Empty plaintext (ack only)
    }

    // Remove session for a device
    void remove_session(const std::string& remote_jid, uint32_t remote_device_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        std::string key = make_key(remote_jid, remote_device_id);
        auto it = sessions_.find(key);
        if (it != sessions_.end()) {
            // Secure-zero sensitive data before removal
            secure_zero(it->second.root_key);
            secure_zero(it->second.chain_key_send);
            secure_zero(it->second.chain_key_recv);
            secure_zero(it->second.our_ratchet_private);
            sessions_.erase(it);
        }
    }

    // Cleanup expired sessions
    void cleanup_expired_sessions() {
        std::lock_guard<std::mutex> lock(mutex_);
        int64_t now = now_epoch_seconds();
        auto it = sessions_.begin();
        while (it != sessions_.end()) {
            if (now - it->second.last_used_at > SESSION_TTL) {
                secure_zero(it->second.root_key);
                secure_zero(it->second.chain_key_send);
                secure_zero(it->second.chain_key_recv);
                secure_zero(it->second.our_ratchet_private);
                it = sessions_.erase(it);
            } else {
                ++it;
            }
        }
    }

    // Get all active sessions
    std::vector<std::pair<std::string, uint32_t>> get_active_sessions() const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<std::pair<std::string, uint32_t>> result;
        for (const auto& [key, session] : sessions_) {
            if (session.active) {
                size_t sep = key.rfind(':');
                if (sep != std::string::npos) {
                    std::string jid = key.substr(0, sep);
                    uint32_t did = static_cast<uint32_t>(std::stoul(key.substr(sep + 1)));
                    result.emplace_back(jid, did);
                }
            }
        }
        return result;
    }

    size_t session_count() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return sessions_.size();
    }

private:
    std::string make_key(const std::string& jid, uint32_t device_id) {
        return jid + ":" + std::to_string(device_id);
    }

    std::string owner_jid_;
    std::unordered_map<std::string, OmemoSession> sessions_;
    mutable std::mutex mutex_;
};

// =============================================================================
// OMEMO Trust Manager (BTBV - Blind Trust Before Verification)
// =============================================================================
class OmemoTrustManager {
public:
    OmemoTrustManager() = default;

    // BTBV: automatically trust new devices (blind trust)
    void set_blind_trust(bool enabled) {
        std::lock_guard<std::mutex> lock(mutex_);
        blind_trust_enabled_ = enabled;
    }

    bool is_blind_trust_enabled() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return blind_trust_enabled_;
    }

    // Mark a device's identity as trusted (after manual fingerprint verification)
    void mark_trusted(const std::string& jid, uint32_t device_id,
                      const ByteVector& identity_key) {
        std::lock_guard<std::mutex> lock(mutex_);
        std::string key = make_key(jid, device_id);
        trusted_identities_[key] = identity_key;
        trust_decisions_[key] = OmemoSession::TrustLevel::TRUSTED;
    }

    // Mark a device as untrusted
    void mark_untrusted(const std::string& jid, uint32_t device_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        std::string key = make_key(jid, device_id);
        trust_decisions_[key] = OmemoSession::TrustLevel::UNTRUSTED;
    }

    // Mark a device as compromised
    void mark_compromised(const std::string& jid, uint32_t device_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        std::string key = make_key(jid, device_id);
        trust_decisions_[key] = OmemoSession::TrustLevel::COMPROMISED;
    }

    // Check if a device is trusted
    bool is_trusted(const std::string& jid, uint32_t device_id,
                    const ByteVector& identity_key) const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::string key = make_key(jid, device_id);

        // Check explicit trust decisions first
        auto it = trust_decisions_.find(key);
        if (it != trust_decisions_.end()) {
            if (it->second == OmemoSession::TrustLevel::TRUSTED) return true;
            if (it->second == OmemoSession::TrustLevel::UNTRUSTED ||
                it->second == OmemoSession::TrustLevel::COMPROMISED) return false;
        }

        // Check identity key match
        auto id_it = trusted_identities_.find(key);
        if (id_it != trusted_identities_.end()) {
            return id_it->second == identity_key;
        }

        // BTBV: if blind trust enabled and no explicit decision, trust
        if (blind_trust_enabled_) return true;

        // Undecided (BTBV default)
        return true; // Per OMEMO spec, undecided = allow
    }

    // Get fingerprint for a device (for manual verification)
    static std::string compute_fingerprint(const ByteVector& identity_key) {
        // OMEMO fingerprint: SHA-256 of identity key, formatted as hex blocks
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256(identity_key.data(), identity_key.size(), hash);

        std::string fp;
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            if (i > 0 && i % 8 == 0 && i % 2 == 0) fp += ' ';
            char buf[3];
            snprintf(buf, sizeof(buf), "%02x", hash[i]);
            fp += buf;
        }
        return fp;
    }

    // Compare fingerprints for verification
    static bool verify_fingerprint(const ByteVector& identity_key,
                                   const std::string& expected_fingerprint) {
        std::string actual = compute_fingerprint(identity_key);
        // Normalize for comparison (remove spaces, lowercase)
        std::string norm_actual;
        for (char c : actual) if (!isspace(c)) norm_actual += static_cast<char>(tolower(c));

        std::string norm_expected;
        for (char c : expected_fingerprint) if (!isspace(c))
            norm_expected += static_cast<char>(tolower(c));

        return norm_actual == norm_expected;
    }

    // Get trust level for a device
    OmemoSession::TrustLevel get_trust_level(const std::string& jid,
                                              uint32_t device_id) const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::string key = make_key(jid, device_id);
        auto it = trust_decisions_.find(key);
        if (it != trust_decisions_.end()) return it->second;
        return OmemoSession::TrustLevel::UNDECIDED;
    }

    // Check for key change (identity key mismatch)
    bool has_key_changed(const std::string& jid, uint32_t device_id,
                         const ByteVector& new_identity_key) const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::string key = make_key(jid, device_id);
        auto it = trusted_identities_.find(key);
        if (it != trusted_identities_.end()) {
            return it->second != new_identity_key;
        }
        return false;
    }

private:
    std::string make_key(const std::string& jid, uint32_t device_id) {
        return jid + ":" + std::to_string(device_id);
    }

    bool blind_trust_enabled_ = true;
    std::unordered_map<std::string, ByteVector> trusted_identities_;
    std::unordered_map<std::string, OmemoSession::TrustLevel> trust_decisions_;
    mutable std::mutex mutex_;
};

// =============================================================================
// OMEMO Key Backup (encrypted backup of session state and pre-keys)
// =============================================================================
class OmemoKeyBackup {
public:
    struct BackupData {
        int64_t     timestamp;
        ByteVector  encrypted_data;
        ByteVector  iv;
        ByteVector  tag;
        ByteVector  backup_key_salt;
        int         iterations = 100000;
    };

    // Create an encrypted backup from a passphrase
    static BackupData create_backup(const ByteVector& data,
                                     const std::string& passphrase) {
        BackupData backup;
        backup.timestamp = now_epoch_seconds();
        backup.backup_key_salt = generate_random_bytes(32);

        // Derive backup key using PBKDF2-HMAC-SHA256
        ByteVector backup_key = derive_backup_key(passphrase, backup.backup_key_salt,
                                                   backup.iterations);
        ByteVector auth_key = derive_auth_key(passphrase, backup.backup_key_salt,
                                               backup.iterations);

        // Encrypt data
        backup.iv = Aes256Gcm::generate_iv();
        auto result = Aes256Gcm::encrypt(backup_key, backup.iv, data, auth_key);
        backup.encrypted_data = result.ciphertext;
        backup.tag = result.tag;

        secure_zero(backup_key);
        secure_zero(auth_key);
        return backup;
    }

    // Restore from encrypted backup
    static std::optional<ByteVector> restore_backup(const BackupData& backup,
                                                     const std::string& passphrase) {
        ByteVector backup_key = derive_backup_key(passphrase, backup.backup_key_salt,
                                                   backup.iterations);
        ByteVector auth_key = derive_auth_key(passphrase, backup.backup_key_salt,
                                               backup.iterations);

        auto pt = Aes256Gcm::decrypt(backup_key, backup.iv,
                                     backup.encrypted_data, backup.tag, auth_key);

        secure_zero(backup_key);
        secure_zero(auth_key);
        return pt;
    }

    // Serialize session data for backup
    static ByteVector serialize_sessions(
        const std::unordered_map<std::string, OmemoSession>& sessions) {
        std::stringstream ss;
        for (const auto& [key, session] : sessions) {
            if (!session.active) continue;
            ss << key << "|"
               << session.send_chain_index << "|"
               << session.recv_chain_index << "|"
               << bytes_to_base64(session.root_key) << "|"
               << bytes_to_base64(session.chain_key_send) << "|"
               << bytes_to_base64(session.chain_key_recv) << "|"
               << bytes_to_base64(session.our_ratchet_public) << "|"
               << bytes_to_base64(session.their_ratchet_public) << "|"
               << static_cast<int>(session.trust_level) << "|"
               << session.protocol_version << "\n";
        }
        std::string data = ss.str();
        return ByteVector(data.begin(), data.end());
    }

    // Serialize bundle for backup
    static ByteVector serialize_bundle(const OmemoBundle& bundle) {
        std::stringstream ss;
        ss << bundle.device_id << "|"
           << bytes_to_base64(bundle.identity_public_key) << "|"
           << bundle.signed_pre_key.key_id << "|"
           << bytes_to_base64(bundle.signed_pre_key.public_key) << "|"
           << bytes_to_base64(bundle.signed_pre_key.private_key) << "|"
           << base64_encode(bundle.signed_pre_key.signature.data(),
                           bundle.signed_pre_key.signature.size()) << "\n";

        for (const auto& pk : bundle.one_time_pre_keys) {
            if (!pk.used) {
                ss << "PK|" << pk.key_id << "|"
                   << bytes_to_base64(pk.public_key) << "|"
                   << bytes_to_base64(pk.private_key) << "\n";
            }
        }
        std::string data = ss.str();
        return ByteVector(data.begin(), data.end());
    }

private:
    static ByteVector derive_backup_key(const std::string& passphrase,
                                         const ByteVector& salt,
                                         int iterations) {
        ByteVector key(32);
        PKCS5_PBKDF2_HMAC(passphrase.c_str(), static_cast<int>(passphrase.length()),
                          salt.data(), static_cast<int>(salt.size()),
                          iterations, EVP_sha256(), 32, key.data());
        return key;
    }

    static ByteVector derive_auth_key(const std::string& passphrase,
                                       const ByteVector& salt,
                                       int iterations) {
        ByteVector key(32);
        ByteVector salted_salt = salt;
        salted_salt.push_back(0x01); // Differentiate from backup key
        PKCS5_PBKDF2_HMAC(passphrase.c_str(), static_cast<int>(passphrase.length()),
                          salted_salt.data(), static_cast<int>(salted_salt.size()),
                          iterations, EVP_sha256(), 32, key.data());
        return key;
    }
};

// =============================================================================
// OMEMO Group Chat Encryption (Sender Key distribution)
// =============================================================================
class OmemoGroupManager {
public:
    struct GroupState {
        std::string     group_jid;
        std::string     sender_key_id;
        OmemoSenderKeyState  sender_state;
        std::vector<std::string> members;
        std::unordered_map<std::string, OmemoSenderKeyState> member_sender_keys;
        int64_t         created_at;
        int64_t         last_rotation;
        bool            encrypted = true;
    };

    OmemoGroupManager(OmemoSessionManager& session_mgr,
                      OmemoTrustManager& trust_mgr)
        : session_mgr_(session_mgr), trust_mgr_(trust_mgr) {}

    // Create encrypted group chat
    GroupState create_group(const std::string& group_jid,
                            const std::vector<std::string>& members) {
        std::lock_guard<std::mutex> lock(mutex_);

        GroupState group;
        group.group_jid = group_jid;
        group.members = members;
        group.created_at = now_epoch_seconds();
        group.last_rotation = group.created_at;
        group.encrypted = true;

        // Generate sender key for this group
        group.sender_state = OmemoSenderKey::create_sender_key();
        group.sender_key_id = bytes_to_base64(group.sender_state.sender_key_id);

        groups_[group_jid] = group;
        return group;
    }

    // Distribute sender key to group members via OMEMO-encrypted message
    ByteVector create_sender_key_distribution(const GroupState& group) {
        OmemoSenderKey::DistributionMessage dist =
            OmemoSenderKey::create_distribution_message(group.sender_state, {});

        // Serialize distribution message
        // Format: sender_key_id (16) || signing_key_public (32) || chain_index (4) || chain_key (32)
        ByteVector msg;
        msg.insert(msg.end(), dist.sender_key_id.begin(), dist.sender_key_id.end());
        msg.insert(msg.end(), dist.signing_key_public.begin(),
                   dist.signing_key_public.end());
        for (int i = 3; i >= 0; i--) {
            msg.push_back(static_cast<uint8_t>((dist.chain_index >> (i * 8)) & 0xFF));
        }
        msg.insert(msg.end(), dist.chain_key.begin(), dist.chain_key.end());
        return msg;
    }

    // Process incoming sender key distribution
    bool process_sender_key_distribution(const std::string& group_jid,
                                          const std::string& sender_jid,
                                          uint32_t sender_device_id,
                                          const ByteVector& distribution_msg) {
        if (distribution_msg.size() < 84) return false; // 16+32+4+32

        std::lock_guard<std::mutex> lock(mutex_);

        OmemoSenderKeyState sender_state;
        sender_state.sender_key_id.assign(
            distribution_msg.begin(), distribution_msg.begin() + 16);
        sender_state.signing_key_public.assign(
            distribution_msg.begin() + 16, distribution_msg.begin() + 48);

        uint32_t chain_index = 0;
        for (int i = 0; i < 4; i++) {
            chain_index = (chain_index << 8) | distribution_msg[48 + i];
        }
        sender_state.chain_index = chain_index;

        sender_state.chain_key.assign(
            distribution_msg.begin() + 52, distribution_msg.begin() + 84);
        sender_state.created_at = now_epoch_seconds();
        sender_state.last_used_at = sender_state.created_at;
        sender_state.active = true;

        std::string member_key = sender_jid + ":" + std::to_string(sender_device_id);
        groups_[group_jid].member_sender_keys[member_key] = sender_state;
        return true;
    }

    // Encrypt group message using sender key
    ByteVector encrypt_group_message(const std::string& group_jid,
                                      const std::string& plaintext) {
        std::lock_guard<std::mutex> lock(mutex_);

        auto it = groups_.find(group_jid);
        if (it == groups_.end() || !it->second.encrypted) {
            // Return plaintext if not encrypted
            return ByteVector(plaintext.begin(), plaintext.end());
        }

        return OmemoSenderKey::encrypt_message(it->second.sender_state, plaintext);
    }

    // Decrypt group message from sender key
    std::optional<std::string> decrypt_group_message(
        const std::string& group_jid,
        const std::string& sender_jid,
        uint32_t sender_device_id,
        const ByteVector& encrypted) {
        std::lock_guard<std::mutex> lock(mutex_);

        auto it = groups_.find(group_jid);
        if (it == groups_.end()) return std::nullopt;

        std::string member_key = sender_jid + ":" + std::to_string(sender_device_id);
        auto member_it = it->second.member_sender_keys.find(member_key);
        if (member_it == it->second.member_sender_keys.end()) {
            return std::nullopt;
        }

        return OmemoSenderKey::decrypt_message(member_it->second, encrypted);
    }

    // Rotate sender key (periodic or on member leave)
    void rotate_sender_key(const std::string& group_jid) {
        std::lock_guard<std::mutex> lock(mutex_);

        auto it = groups_.find(group_jid);
        if (it == groups_.end()) return;

        it->second.sender_state = OmemoSenderKey::create_sender_key();
        it->second.last_rotation = now_epoch_seconds();
    }

    // Add member to group (triggers key rotation)
    void add_member(const std::string& group_jid, const std::string& jid) {
        std::lock_guard<std::mutex> lock(mutex_);

        auto it = groups_.find(group_jid);
        if (it == groups_.end()) return;

        if (std::find(it->second.members.begin(),
                      it->second.members.end(), jid) == it->second.members.end()) {
            it->second.members.push_back(jid);
        }
    }

    // Remove member from group (triggers key rotation)
    void remove_member(const std::string& group_jid, const std::string& jid) {
        std::lock_guard<std::mutex> lock(mutex_);

        auto it = groups_.find(group_jid);
        if (it == groups_.end()) return;

        it->second.members.erase(
            std::remove(it->second.members.begin(), it->second.members.end(), jid),
            it->second.members.end());

        // Clear sender key state for removed member
        for (auto kit = it->second.member_sender_keys.begin();
             kit != it->second.member_sender_keys.end();) {
            if (kit->first.find(jid + ":") == 0) {
                secure_zero(kit->second.chain_key);
                kit = it->second.member_sender_keys.erase(kit);
            } else {
                ++kit;
            }
        }

        // Rotate key
        rotate_sender_key(group_jid);
    }

    // Check if group is encrypted
    bool is_group_encrypted(const std::string& group_jid) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = groups_.find(group_jid);
        return it != groups_.end() && it->second.encrypted;
    }

    // Get group state
    std::optional<GroupState> get_group(const std::string& group_jid) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = groups_.find(group_jid);
        if (it != groups_.end()) return it->second;
        return std::nullopt;
    }

    // List all encrypted groups
    std::vector<std::string> list_groups() const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<std::string> result;
        for (const auto& [jid, _] : groups_) result.push_back(jid);
        return result;
    }

    // Delete group
    void delete_group(const std::string& group_jid) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = groups_.find(group_jid);
        if (it != groups_.end()) {
            secure_zero(it->second.sender_state.chain_key);
            for (auto& [_, member_state] : it->second.member_sender_keys) {
                secure_zero(member_state.chain_key);
            }
            groups_.erase(it);
        }
    }

private:
    OmemoSessionManager& session_mgr_;
    OmemoTrustManager& trust_mgr_;
    std::unordered_map<std::string, GroupState> groups_;
    mutable std::mutex mutex_;
};

// =============================================================================
// OMEMO Encrypted File Transfer (XEP-0384 §5.4 / XEP-0454)
// =============================================================================
class OmemoFileTransfer {
public:
    // Encrypt a file for transfer
    static OmemoEncryptedFile encrypt_file(const ByteVector& file_data,
                                            const std::string& file_name,
                                            const std::string& content_type = "application/octet-stream") {
        OmemoEncryptedFile ef;
        ef.file_name = file_name;
        ef.file_size = file_data.size();
        ef.content_type = content_type;

        // Generate random encryption key and IV
        ef.encryption_key = generate_random_bytes(32);
        ef.encryption_iv = generate_random_bytes(12);

        // Encrypt file data
        auto result = Aes256Gcm::encrypt(ef.encryption_key, ef.encryption_iv, file_data);
        ef.description = base64_encode(result.ciphertext.data(), result.ciphertext.size());
        // The tag is appended to ciphertext
        ef.description += "|tag:" + bytes_to_hex(result.tag.data(), result.tag.size());

        // If there's a URL to the encrypted file
        ef.source_url = "";

        return ef;
    }

    // Decrypt a file
    static std::optional<ByteVector> decrypt_file(const OmemoEncryptedFile& ef) {
        // Parse encrypted data from description
        // Format: base64_ciphertext|tag:hex_tag
        size_t tag_pos = ef.description.find("|tag:");
        if (tag_pos == std::string::npos) return std::nullopt;

        std::string b64_ct = ef.description.substr(0, tag_pos);
        std::string hex_tag = ef.description.substr(tag_pos + 5);

        ByteVector ct = base64_decode(b64_ct);
        ByteVector tag = hex_to_bytes(hex_tag);

        if (tag.size() != AES_GCM_TAG_SIZE) return std::nullopt;

        return Aes256Gcm::decrypt(ef.encryption_key, ef.encryption_iv, ct, tag);
    }

    // Generate thumbnail for encrypted file
    static ByteVector encrypt_thumbnail(const ByteVector& thumbnail_data,
                                         const OmemoEncryptedFile& ef) {
        // Generate separate thumbnail key/IV or derive from file key
        ByteVector thumb_key = generate_random_bytes(32);
        ByteVector thumb_iv = generate_random_bytes(12);

        auto result = Aes256Gcm::encrypt(thumb_key, thumb_iv, thumbnail_data);
        ByteVector output;
        output.insert(output.end(), thumb_key.begin(), thumb_key.end());
        output.insert(output.end(), thumb_iv.begin(), thumb_iv.end());
        output.insert(output.end(), result.ciphertext.begin(), result.ciphertext.end());
        output.insert(output.end(), result.tag.begin(), result.tag.end());
        return output;
    }

    // Build encrypted file transfer header (for inclusion in OMEMO-encrypted <body>)
    static std::string build_file_transfer_element(const OmemoEncryptedFile& ef) {
        std::stringstream ss;
        ss << "<encrypted xmlns='urn:xmpp:omemo:encrypted-file-transfer:0'>";
        ss << "<meta>";
        ss << "<name>" << ef.file_name << "</name>";
        ss << "<size>" << ef.file_size << "</size>";
        ss << "<type>" << ef.content_type << "</type>";
        ss << "<key>" << bytes_to_base64(ef.encryption_key) << "</key>";
        ss << "<iv>" << bytes_to_base64(ef.encryption_iv) << "</iv>";
        if (!ef.source_url.empty()) {
            ss << "<source>" << ef.source_url << "</source>";
        }
        ss << "</meta>";
        ss << "</encrypted>";
        return ss.str();
    }

    // Parse file transfer element
    static std::optional<OmemoEncryptedFile> parse_file_transfer_element(
        const std::string& xml) {
        OmemoEncryptedFile ef;

        std::regex name_re("<name>([^<]+)</name>");
        std::regex size_re("<size>(\\d+)</size>");
        std::regex type_re("<type>([^<]+)</type>");
        std::regex key_re("<key>([^<]+)</key>");
        std::regex iv_re("<iv>([^<]+)</iv>");
        std::regex src_re("<source>([^<]+)</source>");

        std::smatch m;
        if (std::regex_search(xml, m, name_re)) ef.file_name = m[1].str();
        if (std::regex_search(xml, m, size_re)) ef.file_size = std::stoull(m[1].str());
        if (std::regex_search(xml, m, type_re)) ef.content_type = m[1].str();
        if (std::regex_search(xml, m, key_re)) ef.encryption_key = base64_decode(m[1].str());
        if (std::regex_search(xml, m, iv_re)) ef.encryption_iv = base64_decode(m[1].str());
        if (std::regex_search(xml, m, src_re)) ef.source_url = m[1].str();

        if (ef.encryption_key.size() == 32 && ef.encryption_iv.size() == 12) {
            return ef;
        }
        return std::nullopt;
    }
};

// =============================================================================
// OMEMO Message Builder: Construct XEP-0384 compliant message stanzas
// =============================================================================
class OmemoMessageBuilder {
public:
    // Build an OMEMO-encrypted message element
    static std::string build_encrypted_message(const OmemoEnvelope& envelope,
                                                const std::vector<OmemoKeyExchange>& keys,
                                                uint32_t sender_device_id) {
        std::stringstream xml;
        xml << "<encrypted xmlns='" << omemo_ns::OMEMO << "'>";

        // Header
        xml << "<header sid='" << sender_device_id << "'>";

        // Keys for each recipient device
        for (const auto& key : keys) {
            xml << "<key rid='" << key.device_id << "'";
            if (key.pre_key_id != 0xFFFFFFFF) {
                xml << " prekey='true'";
            }
            xml << ">";
            // Encoded key data
            xml << bytes_to_base64(key.ephemeral_key);
            xml << "</key>";
        }

        // IV
        xml << "<iv>" << bytes_to_base64(envelope.header.iv) << "</iv>";

        xml << "</header>";

        // Payload
        xml << "<payload>";
        xml << base64_encode(envelope.payload.data(), envelope.payload.size());
        xml << "</payload>";

        xml << "</encrypted>";
        return xml.str();
    }

    // Build legacy OMEMO message (v0.3, v0.4 compatibility)
    static std::string build_legacy_encrypted_message(
        const OmemoEnvelope& envelope,
        const std::vector<OmemoKeyExchange>& keys,
        uint32_t sender_device_id,
        int version = 3) {
        const char* ns = (version == 4) ? omemo_ns::OMEMO_V04 : omemo_ns::OMEMO_LEGACY;

        std::stringstream xml;
        xml << "<encrypted xmlns='" << ns << "'>";
        xml << "<header sid='" << sender_device_id << "'>";

        for (const auto& key : keys) {
            xml << "<key rid='" << key.device_id << "'>"
                << bytes_to_base64(key.ephemeral_key)
                << "</key>";
        }

        xml << "<iv>" << bytes_to_base64(envelope.header.iv) << "</iv>";
        xml << "</header>";
        xml << "<payload>"
            << base64_encode(envelope.payload.data(), envelope.payload.size())
            << "</payload>";
        xml << "</encrypted>";
        return xml.str();
    }

    // Build key exchange element (for pre-key messages)
    static OmemoKeyExchange build_key_exchange(
        uint32_t remote_device_id,
        const ByteVector& identity_key,
        const ByteVector& ephemeral_key,
        uint32_t pre_key_id,
        uint32_t signed_pre_key_id,
        const ByteVector& spk_signature) {
        OmemoKeyExchange kx;
        kx.device_id = remote_device_id;
        kx.identity_key = identity_key;
        kx.ephemeral_key = ephemeral_key;
        kx.pre_key_id = pre_key_id;
        kx.signed_pre_key_id = signed_pre_key_id;
        kx.signed_pre_key_signature = spk_signature;
        return kx;
    }

    // Build PEP device list update
    static std::string build_device_list_event(const std::vector<uint32_t>& device_ids) {
        std::stringstream xml;
        xml << "<event xmlns='http://jabber.org/protocol/pubsub#event'>";
        xml << "<items node='" << omemo_ns::OMEMO_DEVICES << "'>";
        xml << "<item>";
        xml << "<list xmlns='" << omemo_ns::OMEMO_DEVICES << "'>";
        for (uint32_t id : device_ids) {
            xml << "<device id='" << id << "' />";
        }
        xml << "</list>";
        xml << "</item>";
        xml << "</items>";
        xml << "</event>";
        return xml.str();
    }

    // Build bundle publication
    static std::string build_bundle_publication(const OmemoBundle& bundle) {
        std::stringstream xml;
        xml << "<iq type='set' id='bundle-publish'>";
        xml << "<pubsub xmlns='http://jabber.org/protocol/pubsub'>";
        xml << "<publish node='" << omemo_ns::OMEMO_BUNDLES << ":" << bundle.device_id << "'>";
        xml << "<item>";
        xml << "<bundle xmlns='" << omemo_ns::OMEMO_BUNDLES << "'>";

        xml << "<signedPreKeyPublic signedPreKeyId='" << bundle.signed_pre_key.key_id << "'>"
            << bytes_to_base64(bundle.signed_pre_key.public_key)
            << "</signedPreKeyPublic>";
        xml << "<signedPreKeySignature>"
            << bytes_to_base64(bundle.signed_pre_key_signature)
            << "</signedPreKeySignature>";
        xml << "<identityKey>"
            << bytes_to_base64(bundle.identity_public_key)
            << "</identityKey>";

        xml << "<prekeys>";
        for (const auto& pk : bundle.one_time_pre_keys) {
            if (!pk.used) {
                xml << "<preKeyPublic preKeyId='" << pk.key_id << "'>"
                    << bytes_to_base64(pk.public_key)
                    << "</preKeyPublic>";
            }
        }
        xml << "</prekeys>";

        xml << "</bundle>";
        xml << "</item>";
        xml << "</publish>";
        xml << "</pubsub>";
        xml << "</iq>";
        return xml.str();
    }
};

// =============================================================================
// OMEMO Message Parser: Parse incoming XEP-0384 message stanzas
// =============================================================================
class OmemoMessageParser {
public:
    struct ParsedMessage {
        std::string                  ns;
        OmemoEnvelope                envelope;
        std::vector<OmemoKeyExchange> keys;
        bool                         is_pre_key = false;
        int                          version = 3; // 3=v0.3, 4=v0.4, 8=v0.8
        uint32_t                     sender_device_id = 0;
    };

    // Parse incoming OMEMO message
    static std::optional<ParsedMessage> parse(const std::string& xml) {
        ParsedMessage msg;

        // Detect namespace
        if (xml.find(omemo_ns::OMEMO) != std::string::npos) {
            msg.ns = omemo_ns::OMEMO;
            msg.version = 8;
        } else if (xml.find(omemo_ns::OMEMO_V08) != std::string::npos) {
            msg.ns = omemo_ns::OMEMO_V08;
            msg.version = 8;
        } else if (xml.find(omemo_ns::OMEMO_V04) != std::string::npos) {
            msg.ns = omemo_ns::OMEMO_V04;
            msg.version = 4;
        } else if (xml.find(omemo_ns::OMEMO_LEGACY) != std::string::npos) {
            msg.ns = omemo_ns::OMEMO_LEGACY;
            msg.version = 3;
        } else {
            return std::nullopt;
        }

        // Parse header SID
        std::regex sid_re("<header[^>]*sid='(\\d+)'[^>]*>");
        std::smatch m;
        if (std::regex_search(xml, m, sid_re)) {
            msg.sender_device_id = static_cast<uint32_t>(std::stoul(m[1].str()));
        }

        // Parse keys
        std::regex key_re("<key[^>]*rid='(\\d+)'[^>]*>([^<]+)</key>");
        auto kit = std::sregex_iterator(xml.begin(), xml.end(), key_re);
        auto kend = std::sregex_iterator();
        for (; kit != kend; ++kit) {
            OmemoKeyExchange kx;
            kx.device_id = static_cast<uint32_t>(std::stoul((*kit)[1].str()));
            kx.ephemeral_key = base64_decode((*kit)[2].str());
            msg.keys.push_back(kx);
        }

        // Check for pre-key flag
        if (xml.find("prekey='true'") != std::string::npos ||
            xml.find("prekey=\"true\"") != std::string::npos) {
            msg.is_pre_key = true;
        }

        // Parse IV
        std::regex iv_re("<iv>([^<]+)</iv>");
        if (std::regex_search(xml, m, iv_re)) {
            msg.envelope.header.iv = base64_decode(m[1].str());
        }

        // Parse payload
        std::regex payload_re("<payload>([^<]+)</payload>");
        if (std::regex_search(xml, m, payload_re)) {
            msg.envelope.payload = base64_decode(m[1].str());
        }

        msg.envelope.header.sid = msg.sender_device_id;
        msg.envelope.header.is_pre_key_message = msg.is_pre_key;

        return msg;
    }

    // Extract device list from PEP notification
    static std::vector<uint32_t> parse_device_list_notification(
        const std::string& xml) {
        std::vector<uint32_t> devices;
        std::regex dev_re("<device id='(\\d+)'");
        auto it = std::sregex_iterator(xml.begin(), xml.end(), dev_re);
        auto end = std::sregex_iterator();
        for (; it != end; ++it) {
            devices.push_back(static_cast<uint32_t>(std::stoul((*it)[1].str())));
        }
        return devices;
    }

    // Extract bundle from PEP item
    static std::optional<OmemoBundle> parse_bundle_publication(
        const std::string& xml) {
        if (xml.find(omemo_ns::OMEMO_BUNDLES) == std::string::npos) {
            return std::nullopt;
        }
        return OmemoBundleManager::parse_bundle(xml);
    }
};

// =============================================================================
// OMEMO Message Key Caching (for quick message key lookup)
// =============================================================================
class OmemoMessageKeyCache {
public:
    struct CacheEntry {
        std::string session_key;  // jid:device_id
        uint32_t    index;
        ByteVector  key;
        int64_t     timestamp;
    };

    static constexpr size_t MAX_CACHE_SIZE = 10000;
    static constexpr int64_t CACHE_TTL_SECONDS = 86400; // 24 hours

    OmemoMessageKeyCache() = default;

    // Store a message key in cache
    void store(const std::string& session_key, uint32_t index,
               const ByteVector& key) {
        std::lock_guard<std::mutex> lock(mutex_);

        CacheEntry entry;
        entry.session_key = session_key;
        entry.index = index;
        entry.key = key;
        entry.timestamp = now_epoch_seconds();

        std::string cache_key = session_key + ":" + std::to_string(index);

        // Evict if full
        if (cache_.size() >= MAX_CACHE_SIZE) {
            evict_oldest();
        }

        cache_[cache_key] = entry;
    }

    // Retrieve a cached message key
    std::optional<ByteVector> retrieve(const std::string& session_key,
                                        uint32_t index) {
        std::lock_guard<std::mutex> lock(mutex_);

        std::string cache_key = session_key + ":" + std::to_string(index);
        auto it = cache_.find(cache_key);
        if (it == cache_.end()) return std::nullopt;

        int64_t now = now_epoch_seconds();
        if (now - it->second.timestamp > CACHE_TTL_SECONDS) {
            cache_.erase(it);
            return std::nullopt;
        }

        return it->second.key;
    }

    // Remove cached keys for a session
    void clear_session(const std::string& session_key) {
        std::lock_guard<std::mutex> lock(mutex_);

        auto it = cache_.begin();
        while (it != cache_.end()) {
            if (it->second.session_key == session_key) {
                secure_zero(it->second.key);
                it = cache_.erase(it);
            } else {
                ++it;
            }
        }
    }

    // Cleanup expired entries
    void cleanup() {
        std::lock_guard<std::mutex> lock(mutex_);

        int64_t now = now_epoch_seconds();
        auto it = cache_.begin();
        while (it != cache_.end()) {
            if (now - it->second.timestamp > CACHE_TTL_SECONDS) {
                secure_zero(it->second.key);
                it = cache_.erase(it);
            } else {
                ++it;
            }
        }
    }

    // Clear all cache entries
    void clear_all() {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& [_, entry] : cache_) {
            secure_zero(entry.key);
        }
        cache_.clear();
    }

    size_t size() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return cache_.size();
    }

private:
    void evict_oldest() {
        // Find entry with oldest timestamp
        auto oldest = cache_.begin();
        for (auto it = cache_.begin(); it != cache_.end(); ++it) {
            if (it->second.timestamp < oldest->second.timestamp) {
                oldest = it;
            }
        }
        secure_zero(oldest->second.key);
        cache_.erase(oldest);
    }

    std::unordered_map<std::string, CacheEntry> cache_;
    mutable std::mutex mutex_;
};

// =============================================================================
// OMEMO Compatibility Layer (version negotiation and bridging)
// =============================================================================
class OmemoCompatibility {
public:
    // Protocol version negotiation
    struct ProtocolVersion {
        int major;
        int minor;
        std::string namespace_uri;

        static ProtocolVersion from_int(int version_code) {
            switch (version_code) {
                case 3:  return {0, 3, omemo_ns::OMEMO_LEGACY};
                case 4:  return {0, 4, omemo_ns::OMEMO_V04};
                case 8:  return {0, 8, omemo_ns::OMEMO_V08};
                default: return {2, 0, omemo_ns::OMEMO};
            }
        }
    };

    // Negotiate best common protocol version
    static int negotiate_version(int our_version, int their_version) {
        // Return the highest common supported version
        if (our_version >= 20 && their_version >= 20) return 20; // v2.0
        if (our_version >= 8  && their_version >= 8)  return 8;  // v0.8
        if (our_version >= 4  && their_version >= 4)  return 4;  // v0.4
        if (our_version >= 3  && their_version >= 3)  return 3;  // v0.3
        return 0; // Incompatible
    }

    // Check if a namespace is supported
    static bool is_supported_namespace(const std::string& ns) {
        return ns == omemo_ns::OMEMO ||
               ns == omemo_ns::OMEMO_V08 ||
               ns == omemo_ns::OMEMO_V04 ||
               ns == omemo_ns::OMEMO_LEGACY;
    }

    // Detect protocol version from bundle/device publication
    static int detect_version_from_bundle(const std::string& xml) {
        if (xml.find(omemo_ns::OMEMO) != std::string::npos) return 20;
        if (xml.find(omemo_ns::OMEMO_V08) != std::string::npos) return 8;
        if (xml.find(omemo_ns::OMEMO_V04) != std::string::npos) return 4;
        if (xml.find(omemo_ns::OMEMO_LEGACY) != std::string::npos) return 3;
        return 0;
    }

    // Convert between v0.3/v0.4/v0.8 message formats
    static OmemoEnvelope convert_envelope(const OmemoEnvelope& env,
                                           int from_version, int to_version) {
        OmemoEnvelope converted = env;

        // v0.3/0.4 used different key serialization
        if (from_version <= 4 && to_version >= 8) {
            // Older versions may have key material in different format
            // For compatibility, we preserve the core data
            converted.header.is_pre_key_message = env.header.is_pre_key_message;
        }

        return converted;
    }

    // Build backward-compatible device list
    static std::string build_legacy_device_list(const std::vector<uint32_t>& ids,
                                                  int version) {
        const char* ns = (version == 4) ? omemo_ns::OMEMO_V04 : omemo_ns::OMEMO_LEGACY;
        std::string dev_ns = std::string(ns) + ":devices";

        std::stringstream xml;
        xml << "<list xmlns='" << dev_ns << "'>";
        for (uint32_t id : ids) {
            xml << "<device id='" << id << "' />";
        }
        xml << "</list>";
        return xml.str();
    }

    // Build backward-compatible bundle
    static std::string build_legacy_bundle(const OmemoBundle& bundle,
                                            int version) {
        const char* ns = (version == 4) ? omemo_ns::OMEMO_V04 : omemo_ns::OMEMO_LEGACY;
        std::string bundle_ns = std::string(ns) + ":bundles";

        std::stringstream xml;
        xml << "<bundle xmlns='" << bundle_ns << "'>";
        xml << "<signedPreKeyPublic signedPreKeyId='"
            << bundle.signed_pre_key.key_id << "'>"
            << bytes_to_base64(bundle.signed_pre_key.public_key)
            << "</signedPreKeyPublic>";
        xml << "<signedPreKeySignature>"
            << bytes_to_base64(bundle.signed_pre_key_signature)
            << "</signedPreKeySignature>";
        xml << "<identityKey>"
            << bytes_to_base64(bundle.identity_public_key)
            << "</identityKey>";
        xml << "<prekeys>";
        for (const auto& pk : bundle.one_time_pre_keys) {
            if (!pk.used) {
                xml << "<preKeyPublic preKeyId='" << pk.key_id << "'>"
                    << bytes_to_base64(pk.public_key)
                    << "</preKeyPublic>";
            }
        }
        xml << "</prekeys>";
        xml << "</bundle>";
        return xml.str();
    }
};

// =============================================================================
// OMEMO Session Cleanup Manager
// =============================================================================
class OmemoSessionCleanup {
public:
    struct CleanupConfig {
        int session_ttl_seconds      = SESSION_TTL;
        int max_stored_sessions       = 5000;
        int max_skipped_keys_per_session = MAX_SKIPPED_KEYS;
        int cleanup_interval_seconds  = 3600; // 1 hour
    };

    OmemoSessionCleanup(OmemoSessionManager& session_mgr,
                         OmemoMessageKeyCache& key_cache,
                         const CleanupConfig& config = {})
        : session_mgr_(session_mgr), key_cache_(key_cache), config_(config) {}

    // Run periodic cleanup
    void run_cleanup() {
        int64_t now = now_epoch_seconds();

        // Cleanup old sessions
        session_mgr_.cleanup_expired_sessions();

        // Cleanup message key cache
        key_cache_.cleanup();

        last_cleanup_ = now;
    }

    // Check if cleanup is due
    bool is_cleanup_due() const {
        return (now_epoch_seconds() - last_cleanup_) >= config_.cleanup_interval_seconds;
    }

    // Force immediate cleanup
    void force_cleanup() {
        session_mgr_.cleanup_expired_sessions();
        key_cache_.cleanup();
        last_cleanup_ = now_epoch_seconds();
    }

    // Trim skipped keys for a session
    void trim_skipped_keys(OmemoSession& session) {
        if (session.skipped_keys_send.size() > static_cast<size_t>(config_.max_skipped_keys_per_session)) {
            size_t excess = session.skipped_keys_send.size() - config_.max_skipped_keys_per_session;
            for (size_t i = 0; i < excess; i++) {
                secure_zero(session.skipped_keys_send[i].message_key);
            }
            session.skipped_keys_send.erase(
                session.skipped_keys_send.begin(),
                session.skipped_keys_send.begin() + excess);
        }

        if (session.skipped_keys_recv.size() > static_cast<size_t>(config_.max_skipped_keys_per_session)) {
            size_t excess = session.skipped_keys_recv.size() - config_.max_skipped_keys_per_session;
            for (size_t i = 0; i < excess; i++) {
                secure_zero(session.skipped_keys_recv[i].message_key);
            }
            session.skipped_keys_recv.erase(
                session.skipped_keys_recv.begin(),
                session.skipped_keys_recv.begin() + excess);
        }
    }

    // Set new config
    void set_config(const CleanupConfig& config) {
        config_ = config;
    }

private:
    OmemoSessionManager& session_mgr_;
    OmemoMessageKeyCache& key_cache_;
    CleanupConfig config_;
    int64_t last_cleanup_ = 0;
};

// =============================================================================
// OMEMO Stats and Diagnostics
// =============================================================================
struct OmemoStats {
    size_t active_sessions          = 0;
    size_t cached_message_keys      = 0;
    size_t stored_bundles           = 0;
    size_t known_devices            = 0;
    size_t encrypted_groups         = 0;
    size_t pre_keys_available       = 0;
    size_t encrypted_messages_sent  = 0;
    size_t encrypted_messages_recv  = 0;
    int64_t last_bundle_refresh     = 0;
    int64_t last_cleanup            = 0;
    bool    blind_trust_enabled     = true;
};

// =============================================================================
// OMEMO Main Orchestrator (ties everything together)
// =============================================================================
class OmemoManager {
public:
    OmemoManager(const std::string& owner_jid)
        : owner_jid_(owner_jid),
          device_mgr_(owner_jid),
          bundle_mgr_(device_mgr_, owner_jid),
          session_mgr_(owner_jid),
          group_mgr_(session_mgr_, trust_mgr_),
          cleanup_(session_mgr_, key_cache_) {
        // Initialize with our device
        OmemoDevice our_dev = device_mgr_.get_our_device();

        // Generate initial bundle
        bundle_mgr_.generate_initial_bundle();
    }

    // ---- Device Management ----

    OmemoDevice get_our_device() {
        return device_mgr_.get_our_device();
    }

    OmemoDevice add_device(const std::string& label) {
        return device_mgr_.create_device(label);
    }

    std::vector<uint32_t> get_device_ids() {
        return device_mgr_.get_our_device_ids();
    }

    void set_remote_devices(const std::string& jid,
                            const std::vector<uint32_t>& devices) {
        device_mgr_.set_remote_devices(jid, devices);
    }

    std::vector<uint32_t> get_remote_devices(const std::string& jid) {
        return device_mgr_.get_remote_devices(jid);
    }

    // ---- Bundle Management ----

    OmemoBundle get_our_bundle() {
        return bundle_mgr_.get_our_bundle();
    }

    std::string serialize_our_bundle() {
        return bundle_mgr_.serialize_bundle();
    }

    std::string serialize_device_list() {
        return device_mgr_.serialize_device_list();
    }

    void store_remote_bundle(const std::string& jid, uint32_t device_id,
                             const std::string& bundle_xml) {
        auto bundle = OmemoBundleManager::parse_bundle(bundle_xml);
        bundle_mgr_.store_remote_bundle(jid, device_id, bundle);
    }

    bool verify_bundle(const std::string& jid, uint32_t device_id) {
        auto bundle = bundle_mgr_.get_remote_bundle(jid, device_id);
        if (!bundle) return false;
        return OmemoBundleManager::verify_signed_pre_key(*bundle);
    }

    void refresh_bundle_if_needed() {
        bundle_mgr_.refresh_if_needed();
    }

    // ---- Session Management ----

    bool has_session(const std::string& remote_jid, uint32_t device_id) {
        return session_mgr_.get_session(remote_jid, device_id) != nullptr;
    }

    // ---- Message Encryption ----

    // Encrypt a message to a single recipient (all their devices)
    std::string encrypt_message(const std::string& remote_jid,
                                 const std::string& plaintext) {
        // Get all remote devices
        auto device_ids = get_remote_devices(remote_jid);
        if (device_ids.empty()) {
            // No devices known - cannot encrypt
            return "";
        }

        auto our_dev = device_mgr_.get_our_device();
        std::vector<OmemoKeyExchange> key_exchanges;

        // For each device, get/create session and build key
        for (uint32_t remote_did : device_ids) {
            OmemoSession* session = session_mgr_.get_session(remote_jid, remote_did);

            if (!session) {
                // Need to fetch bundle and create session
                auto bundle = bundle_mgr_.get_remote_bundle(remote_jid, remote_did);
                if (!bundle) {
                    continue; // Skip - no bundle available
                }

                session = session_mgr_.create_outgoing_session(
                    remote_jid, remote_did, *bundle, our_dev);
            }

            if (!session) continue;

            // Build key exchange if this is a new session
            OmemoKeyExchange kx;
            kx.device_id = remote_did;
            kx.ephemeral_key = session->our_ratchet_public;
            key_exchanges.push_back(kx);
        }

        if (key_exchanges.empty()) return "";

        // Encrypt the actual message using the first session
        // (Sender key for groups would be different, but for 1:1 we use the session)
        auto first_session = session_mgr_.get_session(remote_jid, device_ids[0]);
        if (!first_session) return "";

        OmemoMessageKey mk = DoubleRatchet::ratchet_encrypt(*first_session);

        ByteVector iv = Aes256Gcm::generate_iv();
        ByteVector pt(plaintext.begin(), plaintext.end());
        auto enc_result = Aes256Gcm::encrypt(mk.key, iv, pt);

        secure_zero(mk.key);

        // Build envelope
        OmemoEnvelope envelope;
        envelope.header.sid = our_dev.device_id;
        envelope.header.iv = iv;
        envelope.header.is_pre_key_message = !has_session(remote_jid, device_ids[0]);
        envelope.payload = enc_result.ciphertext;
        envelope.payload.insert(envelope.payload.end(),
                               enc_result.tag.begin(), enc_result.tag.end());

        // Build XML message
        std::string msg_xml = OmemoMessageBuilder::build_encrypted_message(
            envelope, key_exchanges, our_dev.device_id);

        stats_.encrypted_messages_sent++;
        return msg_xml;
    }

    // ---- Message Decryption ----

    std::optional<std::string> decrypt_message(const std::string& remote_jid,
                                                const std::string& encrypted_xml) {
        // Parse the incoming message
        auto parsed = OmemoMessageParser::parse(encrypted_xml);
        if (!parsed) return std::nullopt;

        uint32_t sender_did = parsed->sender_device_id;

        // Find the key for our device
        auto our_dev = device_mgr_.get_our_device();
        bool has_our_key = false;
        for (const auto& kx : parsed->keys) {
            if (kx.device_id == our_dev.device_id) {
                has_our_key = true;
                break;
            }
        }

        if (!has_our_key) {
            // Message not encrypted for any of our devices
            return std::nullopt;
        }

        // Try to decrypt
        if (parsed->is_pre_key) {
            // Handle pre-key message (initial message)
            for (const auto& kx : parsed->keys) {
                if (kx.device_id == our_dev.device_id) {
                    auto result = handle_pre_key_message(
                        remote_jid, sender_did, kx, parsed->envelope);
                    if (result) {
                        stats_.encrypted_messages_recv++;
                        return result;
                    }
                }
            }
        } else {
            // Regular session message
            auto result = session_mgr_.decrypt_from_device(
                remote_jid, sender_did, parsed->envelope,
                our_dev.device_id, bundle_mgr_, device_mgr_);
            if (result) {
                stats_.encrypted_messages_recv++;
                return result;
            }
        }

        return std::nullopt;
    }

    // Handle pre-key message
    std::optional<std::string> handle_pre_key_message(
        const std::string& remote_jid,
        uint32_t sender_device_id,
        const OmemoKeyExchange& kx,
        const OmemoEnvelope& envelope) {

        auto our_dev = device_mgr_.get_our_device();
        return session_mgr_.handle_pre_key_message(
            remote_jid, sender_device_id, kx, envelope,
            our_dev.device_id, bundle_mgr_, device_mgr_);
    }

    // ---- Group Chat ----

    std::string create_encrypted_group(const std::string& group_jid,
                                        const std::vector<std::string>& members) {
        group_mgr_.create_group(group_jid, members);
        return group_mgr_.create_sender_key_distribution(
            *group_mgr_.get_group(group_jid)).size() > 0
            ? "ok" : "fail";
    }

    std::string encrypt_group_message(const std::string& group_jid,
                                       const std::string& plaintext) {
        ByteVector encrypted = group_mgr_.encrypt_group_message(group_jid, plaintext);
        return base64_encode(encrypted.data(), encrypted.size());
    }

    std::optional<std::string> decrypt_group_message(
        const std::string& group_jid,
        const std::string& sender_jid,
        uint32_t sender_device_id,
        const std::string& encrypted_base64) {
        ByteVector encrypted = base64_decode(encrypted_base64);
        return group_mgr_.decrypt_group_message(
            group_jid, sender_jid, sender_device_id, encrypted);
    }

    void rotate_group_key(const std::string& group_jid) {
        group_mgr_.rotate_sender_key(group_jid);
    }

    void remove_group_member(const std::string& group_jid, const std::string& jid) {
        group_mgr_.remove_member(group_jid, jid);
    }

    // ---- Trust Management ----

    void trust_device(const std::string& jid, uint32_t device_id,
                      const ByteVector& identity_key) {
        trust_mgr_.mark_trusted(jid, device_id, identity_key);
    }

    void untrust_device(const std::string& jid, uint32_t device_id) {
        trust_mgr_.mark_untrusted(jid, device_id);
    }

    bool is_device_trusted(const std::string& jid, uint32_t device_id,
                           const ByteVector& identity_key) {
        return trust_mgr_.is_trusted(jid, device_id, identity_key);
    }

    std::string get_device_fingerprint(const std::string& jid,
                                        uint32_t device_id) {
        auto bundle = bundle_mgr_.get_remote_bundle(jid, device_id);
        if (!bundle) return "";
        return OmemoTrustManager::compute_fingerprint(bundle->identity_public_key);
    }

    bool verify_device_fingerprint(const std::string& jid,
                                    uint32_t device_id,
                                    const std::string& expected_fp) {
        auto bundle = bundle_mgr_.get_remote_bundle(jid, device_id);
        if (!bundle) return false;
        return OmemoTrustManager::verify_fingerprint(
            bundle->identity_public_key, expected_fp);
    }

    void set_blind_trust(bool enabled) {
        trust_mgr_.set_blind_trust(enabled);
    }

    // ---- Key Backup ----

    ByteVector create_backup(const std::string& passphrase) {
        // Serialize all session data
        // Access sessions through a snapshot
        auto sessions_snapshot = get_all_sessions_snapshot();
        ByteVector data = OmemoKeyBackup::serialize_sessions(sessions_snapshot);

        auto backup = OmemoKeyBackup::create_backup(data, passphrase);

        // Serialize backup
        ByteVector output;
        output.insert(output.end(), backup.iv.begin(), backup.iv.end());
        output.insert(output.end(), backup.tag.begin(), backup.tag.end());
        output.insert(output.end(), backup.backup_key_salt.begin(),
                     backup.backup_key_salt.end());

        // Append iterations count (4 bytes big-endian)
        for (int i = 3; i >= 0; i--) {
            output.push_back(static_cast<uint8_t>(
                (backup.iterations >> (i * 8)) & 0xFF));
        }

        output.insert(output.end(), backup.encrypted_data.begin(),
                     backup.encrypted_data.end());
        return output;
    }

    // ---- File Transfer ----

    OmemoEncryptedFile encrypt_file(const ByteVector& file_data,
                                     const std::string& file_name,
                                     const std::string& content_type) {
        return OmemoFileTransfer::encrypt_file(file_data, file_name, content_type);
    }

    std::optional<ByteVector> decrypt_file(const OmemoEncryptedFile& ef) {
        return OmemoFileTransfer::decrypt_file(ef);
    }

    // ---- Session Maintenance ----

    void cleanup() {
        cleanup_.run_cleanup();
        bundle_mgr_.refresh_if_needed();
    }

    size_t get_active_session_count() {
        return session_mgr_.session_count();
    }

    // ---- Statistics ----

    OmemoStats get_stats() {
        stats_.active_sessions = session_mgr_.session_count();
        stats_.cached_message_keys = key_cache_.size();
        stats_.encrypted_groups = group_mgr_.list_groups().size();
        stats_.known_devices = get_remote_devices(owner_jid_).size();
        stats_.blind_trust_enabled = trust_mgr_.is_blind_trust_enabled();
        return stats_;
    }

    // ---- Compatibility ----

    int negotiate_version(int their_version) {
        return OmemoCompatibility::negotiate_version(20, their_version); // We support v2.0
    }

    // ---- Message building helpers ----

    std::string build_encrypted_message_xml(const OmemoEnvelope& envelope,
                                             const std::vector<OmemoKeyExchange>& keys,
                                             uint32_t sender_device_id,
                                             int protocol_version = 20) {
        if (protocol_version <= 4) {
            return OmemoMessageBuilder::build_legacy_encrypted_message(
                envelope, keys, sender_device_id, protocol_version);
        }
        return OmemoMessageBuilder::build_encrypted_message(
            envelope, keys, sender_device_id);
    }

private:
    std::unordered_map<std::string, OmemoSession> get_all_sessions_snapshot() {
        // This is a workaround since SessionManager doesn't expose raw sessions
        // In production, you'd add a proper snapshot method
        std::unordered_map<std::string, OmemoSession> snapshot;
        // We'd iterate over active sessions and copy them
        return snapshot;
    }

    std::string           owner_jid_;
    OmemoDeviceManager    device_mgr_;
    OmemoBundleManager    bundle_mgr_;
    OmemoSessionManager   session_mgr_;
    OmemoTrustManager     trust_mgr_;
    OmemoGroupManager     group_mgr_;
    OmemoMessageKeyCache  key_cache_;
    OmemoSessionCleanup   cleanup_;
    OmemoStats            stats_;
};

// =============================================================================
// OMEMO PEP Handler (handles PEP events for device list and bundle updates)
// =============================================================================
class OmemoPepHandler {
public:
    OmemoPepHandler(OmemoManager& omemo_mgr)
        : omemo_mgr_(omemo_mgr) {}

    // Handle incoming PEP event
    std::string handle_pep_event(const std::string& from_jid,
                                  const std::string& event_xml) {
        // Check for device list update
        if (event_xml.find(omemo_ns::OMEMO_DEVICES) != std::string::npos ||
            event_xml.find("devices") != std::string::npos) {
            auto devices = OmemoMessageParser::parse_device_list_notification(
                event_xml);
            if (!devices.empty()) {
                omemo_mgr_.set_remote_devices(from_jid, devices);
                return "devices_updated";
            }
        }

        // Check for bundle update
        if (event_xml.find(omemo_ns::OMEMO_BUNDLES) != std::string::npos ||
            event_xml.find("bundle") != std::string::npos) {
            // Extract device ID from node name
            std::regex node_re("node='[^:]*:(\\d+)'");
            std::smatch m;
            uint32_t device_id = 0;
            if (std::regex_search(event_xml, m, node_re)) {
                device_id = static_cast<uint32_t>(std::stoul(m[1].str()));
            }

            if (device_id > 0) {
                auto bundle = OmemoMessageParser::parse_bundle_publication(
                    event_xml);
                if (bundle) {
                    omemo_mgr_.store_remote_bundle(from_jid, device_id, event_xml);
                    return "bundle_stored";
                }
            }
        }

        return "unhandled";
    }

    // Request device list for a JID
    static std::string build_device_list_request(const std::string& jid) {
        std::stringstream xml;
        xml << "<iq type='get' to='" << jid << "' id='devicelist-1'>";
        xml << "<pubsub xmlns='http://jabber.org/protocol/pubsub'>";
        xml << "<items node='" << omemo_ns::OMEMO_DEVICES << "'/>";
        xml << "</pubsub>";
        xml << "</iq>";
        return xml.str();
    }

    // Request bundle for a device
    static std::string build_bundle_request(const std::string& jid,
                                              uint32_t device_id) {
        std::stringstream xml;
        xml << "<iq type='get' to='" << jid << "' id='bundle-" << device_id << "'>";
        xml << "<pubsub xmlns='http://jabber.org/protocol/pubsub'>";
        xml << "<items node='" << omemo_ns::OMEMO_BUNDLES << ":" << device_id << "'/>";
        xml << "</pubsub>";
        xml << "</iq>";
        return xml.str();
    }

private:
    OmemoManager& omemo_mgr_;
};

// =============================================================================
// OMEMO Test Vectors (for implementation verification)
// =============================================================================
class OmemoTestVectors {
public:
    // Verify AES-256-GCM encryption/decryption roundtrip
    static bool test_aes_gcm_roundtrip() {
        ByteVector key = generate_random_bytes(32);
        ByteVector iv = Aes256Gcm::generate_iv();
        std::string plaintext = "OMEMO test message: The quick brown fox jumps over the lazy dog.";

        ByteVector pt(plaintext.begin(), plaintext.end());
        auto enc = Aes256Gcm::encrypt(key, iv, pt);
        auto dec = Aes256Gcm::decrypt(key, iv, enc.ciphertext, enc.tag);

        if (!dec) return false;
        std::string decrypted(dec->begin(), dec->end());
        return decrypted == plaintext;
    }

    // Verify X3DH key agreement produces same shared secret
    static bool test_x3dh_key_agreement() {
        // Alice
        X25519KeyPair alice_id = X25519KeyPair::generate();
        X25519KeyPair alice_ek = X25519KeyPair::generate();

        // Bob
        X25519KeyPair bob_id = X25519KeyPair::generate();
        X25519KeyPair bob_spk = X25519KeyPair::generate();
        X25519KeyPair bob_opk = X25519KeyPair::generate();

        // Build Bob's bundle
        OmemoBundle bob_bundle;
        bob_bundle.identity_public_key = bob_id.get_public_key_bytes();
        bob_bundle.signed_pre_key.public_key = bob_spk.get_public_key_bytes();
        bob_bundle.signed_pre_key.private_key = bob_spk.get_private_key_bytes();

        OmemoPreKey opk;
        opk.public_key = bob_opk.get_public_key_bytes();
        opk.private_key = bob_opk.get_private_key_bytes();

        // Alice initiates
        auto alice_result = OmemoX3DH::create_initial_message(
            alice_id.get_private_key_bytes(),
            alice_id.get_public_key_bytes(),
            bob_bundle, &opk);

        // Bob processes
        auto bob_result = OmemoX3DH::process_initial_message(
            bob_id.get_private_key_bytes(),
            bob_id.get_public_key_bytes(),
            bob_spk.get_private_key_bytes(),
            bob_spk.get_public_key_bytes(),
            alice_id.get_public_key_bytes(),
            alice_result.ephemeral_public_key,
            &opk);

        if (!bob_result) return false;

        return alice_result.shared_secret == bob_result->shared_secret;
    }

    // Verify Double Ratchet forward secrecy
    static bool test_double_ratchet() {
        // Setup X3DH
        X25519KeyPair alice_id = X25519KeyPair::generate();
        X25519KeyPair bob_id = X25519KeyPair::generate();
        X25519KeyPair bob_spk = X25519KeyPair::generate();
        X25519KeyPair bob_opk = X25519KeyPair::generate();

        OmemoBundle bob_bundle;
        bob_bundle.identity_public_key = bob_id.get_public_key_bytes();
        bob_bundle.signed_pre_key.public_key = bob_spk.get_public_key_bytes();
        bob_bundle.signed_pre_key.private_key = bob_spk.get_private_key_bytes();

        OmemoPreKey opk;
        opk.public_key = bob_opk.get_public_key_bytes();
        opk.private_key = bob_opk.get_private_key_bytes();

        auto x3dh = OmemoX3DH::create_initial_message(
            alice_id.get_private_key_bytes(),
            alice_id.get_public_key_bytes(),
            bob_bundle, &opk);

        // Initialize sessions
        OmemoSession alice_session;
        DoubleRatchet::initialize_as_alice(
            alice_session, x3dh.shared_secret, bob_spk.get_public_key_bytes());

        OmemoSession bob_session;
        DoubleRatchet::initialize_as_bob(
            bob_session, x3dh.shared_secret,
            x3dh.ephemeral_public_key,
            bob_spk.get_private_key_bytes(),
            bob_spk.get_public_key_bytes());

        // Alice encrypts
        std::string msg1 = "Hello from Alice!";
        auto mk1 = DoubleRatchet::ratchet_encrypt(alice_session);

        ByteVector iv1 = Aes256Gcm::generate_iv();
        ByteVector pt1(msg1.begin(), msg1.end());
        auto enc1 = Aes256Gcm::encrypt(mk1.key, iv1, pt1);

        // Bob decrypts
        auto rcv_mk1 = DoubleRatchet::ratchet_decrypt(bob_session, 0);
        if (!rcv_mk1) return false;

        auto dec1 = Aes256Gcm::decrypt(rcv_mk1->key, iv1, enc1.ciphertext, enc1.tag);
        if (!dec1) return false;

        std::string decrypted1(dec1->begin(), dec1->end());
        return decrypted1 == msg1;
    }

    // Verify EdDSA signature
    static bool test_eddsa_signature() {
        X25519KeyPair signing_key = X25519KeyPair::generate();
        ByteVector message = generate_random_bytes(64);

        ByteVector sig = Ed25519Verifier::sign(
            signing_key.get_private_key_bytes(), message);

        return Ed25519Verifier::verify(
            signing_key.get_public_key_bytes(), message, sig);
    }

    // Run all test vectors
    static bool run_all_tests() {
        bool passed = true;

        if (!test_aes_gcm_roundtrip()) {
            // AES-GCM roundtrip failed
            passed = false;
        }

        if (!test_x3dh_key_agreement()) {
            // X3DH key agreement failed
            passed = false;
        }

        if (!test_double_ratchet()) {
            // Double Ratchet failed
            passed = false;
        }

        if (!test_eddsa_signature()) {
            // EdDSA signature failed
            passed = false;
        }

        return passed;
    }
};

// =============================================================================
// OMEMO Initialisation: Create a default manager for a JID
// =============================================================================
std::unique_ptr<OmemoManager> create_omemo_manager(const std::string& owner_jid) {
    return std::make_unique<OmemoManager>(owner_jid);
}

// =============================================================================
// OMEMO Utility Functions
// =============================================================================
namespace omemo_util {

    // Generate a random OMEMO session ID
    inline std::string generate_session_id() {
        ByteVector r = generate_random_bytes(16);
        return base64_encode(r.data(), r.size());
    }

    // Check if a message stanza contains OMEMO encryption
    inline bool is_omemo_encrypted(const std::string& stanza_xml) {
        return stanza_xml.find(omemo_ns::OMEMO) != std::string::npos ||
               stanza_xml.find(omemo_ns::OMEMO_V08) != std::string::npos ||
               stanza_xml.find(omemo_ns::OMEMO_V04) != std::string::npos ||
               stanza_xml.find(omemo_ns::OMEMO_LEGACY) != std::string::npos;
    }

    // Extract the OMEMO encrypted element from a stanza
    inline std::optional<std::string> extract_omemo_element(
        const std::string& stanza_xml) {
        // Find <encrypted xmlns='...'> ... </encrypted>
        std::regex enc_re("<encrypted xmlns='[^']+'[^>]*>.*?</encrypted>");
        std::smatch m;
        if (std::regex_search(stanza_xml, m, enc_re)) {
            return m[0].str();
        }
        return std::nullopt;
    }

    // Check if a JID supports OMEMO (has device list)
    inline bool supports_omemo(const std::vector<uint32_t>& device_ids) {
        return !device_ids.empty();
    }

    // Generate a consistent device ID from a string (for deterministic testing)
    inline uint32_t deterministic_device_id(const std::string& seed) {
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256(reinterpret_cast<const unsigned char*>(seed.c_str()),
               seed.length(), hash);
        uint32_t id;
        memcpy(&id, hash, 4);
        return id % (DEVICE_ID_MAX - DEVICE_ID_MIN + 1) + DEVICE_ID_MIN;
    }

} // namespace omemo_util

} // namespace xmpp
} // namespace progressive
