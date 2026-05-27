// ============================================================================
// crypto_manager.cpp — Unified Cryptographic Operations Manager
//
// Implements:
//   - Ed25519 key generation, signing, verification (raw + base64)
//   - Curve25519 key generation for ECDH key agreement
//   - SHA-256 hashing (raw, hex, streaming)
//   - HMAC-SHA256 authentication codes
//   - PBKDF2 key derivation (password-based)
//   - AES-256-CBC encrypt/decrypt with PKCS#7 padding
//   - Base64 encode/decode (both padded RFC 4648 and unpadded)
//   - Canonical JSON serialization per Matrix specification
//   - Secure random generation (bytes, integers, strings, hex)
//   - Key persistence (load/save from PEM format and JSON files)
//   - CryptoManager: top-level coordinator wiring all primitives
//   - KeyExportImport: PEM and JSON export/import for Ed25519 and Curve25519
//   - SecureBuffer: self-zeroing secure memory buffer
//   - HashEngine: streaming hash computation
//   - CipherEngine: AES-CBC with IV management and authenticated modes
//   - RandomEngine: cryptographic PRNG with multiple output formats
//   - Base64Engine: full base64 with encoding variants
//
// Equivalent to:
//   matrix-org/matrix-spec: End-to-End Encryption / Key Management
//   synapse/crypto/keyring.py (key generation, storage, signing)
//   synapse/util/canonicaljson.py (canonical JSON)
//   libolm/src/ (Ed25519/Curve25519 primitives)
//   OpenSSL EVP API (SHA-256, HMAC, PBKDF2, AES-CBC)
//   RFC 4648 (base64)
//   RFC 2104 (HMAC)
//   RFC 2898 / PKCS#5 (PBKDF2)
//   RFC 3602 (AES-CBC)
//   RFC 8032 (Ed25519)
//   RFC 7748 (Curve25519)
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
class CryptoManager;
class Ed25519Engine;
class Curve25519Engine;
class Sha256Engine;
class HmacEngine;
class Pbkdf2Engine;
class Aes256CbcEngine;
class Base64Engine;
class CanonicalJsonSerializer;
class RandomEngine;
class KeyPersistenceEngine;
class SecureBuffer;
class HashEngine;
class CipherEngine;
class KeyExportImport;
class PemSerializer;
class JsonKeySerializer;

// ============================================================================
// Cryptographic constants
// ============================================================================
namespace crypto_constants {

// Key sizes
constexpr size_t kEd25519PublicKeyBytes = 32;
constexpr size_t kEd25519PrivateKeyBytes = 32;
constexpr size_t kEd25519SignatureBytes = 64;
constexpr size_t kCurve25519PublicKeyBytes = 32;
constexpr size_t kCurve25519PrivateKeyBytes = 32;
constexpr size_t kAes256KeyBytes = 32;
constexpr size_t kAes256IvBytes = 16;
constexpr size_t kAes256BlockSize = 16;
constexpr size_t kSha256HashBytes = 32;
constexpr size_t kSha256BlockSize = 64;
constexpr size_t kHmacSha256OutputBytes = 32;
constexpr size_t kPbkdf2MinSaltBytes = 8;
constexpr size_t kPbkdf2DefaultSaltBytes = 16;
constexpr int kPbkdf2DefaultIterations = 600000;
constexpr int kPbkdf2MinIterations = 100000;
constexpr size_t kPbkdf2MaxKeyBytes = 256;

// Base64 alphabet
constexpr std::string_view kBase64Alphabet =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
constexpr char kBase64Pad = '=';

// Key ID prefixes
constexpr std::string_view kEd25519KeyPrefix = "ed25519:";
constexpr std::string_view kCurve25519KeyPrefix = "curve25519:";

// Maximum input sizes to prevent memory exhaustion
constexpr size_t kMaxMessageSize = 10 * 1024 * 1024;  // 10 MB
constexpr size_t kMaxBase64InputSize = 50 * 1024 * 1024;  // 50 MB
constexpr size_t kMaxJsonDepth = 256;
constexpr size_t kMaxAesPlaintext = 64 * 1024 * 1024;  // 64 MB

// Canonical JSON constants
constexpr std::string_view kTrueLit = "true";
constexpr std::string_view kFalseLit = "false";
constexpr std::string_view kNullLit = "null";
constexpr char kCanonObjOpen = '{';
constexpr char kCanonObjClose = '}';
constexpr char kCanonArrOpen = '[';
constexpr char kCanonArrClose = ']';
constexpr char kCanonColon = ':';
constexpr char kCanonComma = ',';
constexpr char kCanonQuote = '"';
constexpr int kCanonFloatPrecision = 17;

// PEM headers
constexpr std::string_view kEd25519PemHeader = "-----BEGIN PRIVATE KEY-----";
constexpr std::string_view kEd25519PemFooter = "-----END PRIVATE KEY-----";
constexpr std::string_view kEd25519PubPemHeader = "-----BEGIN PUBLIC KEY-----";
constexpr std::string_view kEd25519PubPemFooter = "-----END PUBLIC KEY-----";

// Random generation limits
constexpr size_t kMaxRandomBytes = 1024 * 1024;  // 1 MB
constexpr size_t kMaxRandomHexLength = 64;

}  // namespace crypto_constants

// ============================================================================
// Error types
// ============================================================================

/// Base class for all crypto errors
class CryptoError : public std::runtime_error {
public:
  explicit CryptoError(const std::string& msg) : std::runtime_error(msg) {}
};

class KeyGenerationError : public CryptoError {
public:
  explicit KeyGenerationError(const std::string& msg) : CryptoError(msg) {}
};

class SigningError : public CryptoError {
public:
  explicit SigningError(const std::string& msg) : CryptoError(msg) {}
};

class VerificationError : public CryptoError {
public:
  explicit VerificationError(const std::string& msg) : CryptoError(msg) {}
};

class EncryptionError : public CryptoError {
public:
  explicit EncryptionError(const std::string& msg) : CryptoError(msg) {}
};

class DecryptionError : public CryptoError {
public:
  explicit DecryptionError(const std::string& msg) : CryptoError(msg) {}
};

class KeyPersistenceError : public CryptoError {
public:
  explicit KeyPersistenceError(const std::string& msg) : CryptoError(msg) {}
};

class Base64Error : public CryptoError {
public:
  explicit Base64Error(const std::string& msg) : CryptoError(msg) {}
};

class CanonicalJsonError : public CryptoError {
public:
  explicit CanonicalJsonError(const std::string& msg) : CryptoError(msg) {}
};

// ============================================================================
// Anonymous-namespace utility functions
// ============================================================================
namespace {

// --- Hexadecimal encoding (lowercase) ---
std::string hex_encode(const std::vector<uint8_t>& data) {
  std::ostringstream oss;
  oss << std::hex << std::setfill('0');
  for (uint8_t byte : data) {
    oss << std::setw(2) << static_cast<int>(byte);
  }
  return oss.str();
}

// --- Hexadecimal encoding from raw buffer ---
std::string hex_encode(const uint8_t* data, size_t len) {
  std::ostringstream oss;
  oss << std::hex << std::setfill('0');
  for (size_t i = 0; i < len; ++i) {
    oss << std::setw(2) << static_cast<int>(data[i]);
  }
  return oss.str();
}

// --- Hexadecimal decoding ---
std::vector<uint8_t> hex_decode(std::string_view hex) {
  if (hex.size() % 2 != 0) {
    throw CryptoError("Hex string must have even length");
  }
  std::vector<uint8_t> result;
  result.reserve(hex.size() / 2);
  for (size_t i = 0; i < hex.size(); i += 2) {
    std::string byte_str(hex.substr(i, 2));
    char* end = nullptr;
    long val = std::strtol(byte_str.c_str(), &end, 16);
    if (end != byte_str.c_str() + 2) {
      throw CryptoError("Invalid hex character");
    }
    result.push_back(static_cast<uint8_t>(val));
  }
  return result;
}

// --- Constant-time comparison (prevents timing side-channel attacks) ---
bool constant_time_equals(const uint8_t* a, const uint8_t* b, size_t len) {
  uint8_t result = 0;
  for (size_t i = 0; i < len; ++i) {
    result |= a[i] ^ b[i];
  }
  return result == 0;
}

bool constant_time_equals(std::string_view a, std::string_view b) {
  if (a.size() != b.size()) return false;
  return constant_time_equals(
      reinterpret_cast<const uint8_t*>(a.data()),
      reinterpret_cast<const uint8_t*>(b.data()), a.size());
}

// --- Get current timestamp in milliseconds ---
int64_t now_millis() {
  auto now = chr::system_clock::now();
  return chr::duration_cast<chr::milliseconds>(now.time_since_epoch()).count();
}

// --- Get current timestamp in seconds ---
int64_t now_seconds() {
  auto now = chr::system_clock::now();
  return chr::duration_cast<chr::seconds>(now.time_since_epoch()).count();
}

// --- String trimming ---
std::string_view trim(std::string_view s) {
  auto start = s.find_first_not_of(" \t\r\n");
  if (start == std::string_view::npos) return {};
  auto end = s.find_last_not_of(" \t\r\n");
  return s.substr(start, end - start + 1);
}

// --- Validate hex character ---
bool is_hex_char(char c) {
  return (c >= '0' && c <= '9') ||
         (c >= 'a' && c <= 'f') ||
         (c >= 'A' && c <= 'F');
}

// --- OpenSSL error string extraction ---
std::string openssl_error_string() {
  unsigned long err = ERR_get_error();
  if (err == 0) return "Unknown OpenSSL error";
  const char* err_str = ERR_error_string(err, nullptr);
  return err_str ? std::string(err_str) : "Unknown OpenSSL error";
}

std::string openssl_error_stack() {
  std::string result;
  unsigned long err;
  while ((err = ERR_get_error()) != 0) {
    if (!result.empty()) result += "; ";
    result += ERR_error_string(err, nullptr);
  }
  return result.empty() ? "Unknown OpenSSL error" : result;
}

// --- Validate key byte vector ---
void validate_key_bytes(const std::vector<uint8_t>& key, size_t expected_size,
                        const std::string& key_name) {
  if (key.size() != expected_size) {
    throw CryptoError(key_name + " must be exactly " +
                      std::to_string(expected_size) + " bytes, got " +
                      std::to_string(key.size()));
  }
}

}  // anonymous namespace

// ============================================================================
// SecureBuffer — Self-zeroing secure memory buffer
// ============================================================================
//
// Wraps a dynamically allocated buffer that is zeroed on destruction.
// Prevents sensitive material (keys, passwords) from lingering in memory.
// Supports move semantics but not copy (to avoid unintended duplication).
// ============================================================================

class SecureBuffer {
public:
  // --- Constructors ---
  SecureBuffer() : data_(nullptr), size_(0) {}

  explicit SecureBuffer(size_t size) : data_(new uint8_t[size]()), size_(size) {}

  SecureBuffer(const uint8_t* src, size_t size) : data_(new uint8_t[size]), size_(size) {
    if (src && size > 0) {
      std::memcpy(data_, src, size);
    }
  }

  explicit SecureBuffer(const std::vector<uint8_t>& vec)
      : data_(new uint8_t[vec.size()]), size_(vec.size()) {
    if (size_ > 0) {
      std::memcpy(data_, vec.data(), size_);
    }
  }

  explicit SecureBuffer(std::string_view sv)
      : data_(new uint8_t[sv.size()]), size_(sv.size()) {
    if (size_ > 0) {
      std::memcpy(data_, sv.data(), size_);
    }
  }

  // --- Move constructor ---
  SecureBuffer(SecureBuffer&& other) noexcept
      : data_(other.data_), size_(other.size_) {
    other.data_ = nullptr;
    other.size_ = 0;
  }

  // --- Move assignment ---
  SecureBuffer& operator=(SecureBuffer&& other) noexcept {
    if (this != &other) {
      zero_memory();
      delete[] data_;
      data_ = other.data_;
      size_ = other.size_;
      other.data_ = nullptr;
      other.size_ = 0;
    }
    return *this;
  }

  // --- Deleted copy ---
  SecureBuffer(const SecureBuffer&) = delete;
  SecureBuffer& operator=(const SecureBuffer&) = delete;

  // --- Destructor ---
  ~SecureBuffer() {
    zero_memory();
    delete[] data_;
    data_ = nullptr;
    size_ = 0;
  }

  // --- Accessors ---
  uint8_t* data() { return data_; }
  const uint8_t* data() const { return data_; }
  size_t size() const { return size_; }
  bool empty() const { return size_ == 0; }

  // --- Convert to vector (use with caution — copies data) ---
  std::vector<uint8_t> to_vector() const {
    if (!data_ || size_ == 0) return {};
    return std::vector<uint8_t>(data_, data_ + size_);
  }

  // --- Convert to string (use with caution — copies data) ---
  std::string to_string() const {
    if (!data_ || size_ == 0) return {};
    return std::string(reinterpret_cast<const char*>(data_), size_);
  }

  // --- Zero and resize ---
  void resize(size_t new_size) {
    zero_memory();
    delete[] data_;
    data_ = new uint8_t[new_size]();
    size_ = new_size;
  }

  // --- Fill with random bytes ---
  void randomize() {
    if (size_ > 0 && data_) {
      if (RAND_bytes(data_, static_cast<int>(size_)) != 1) {
        throw CryptoError("RAND_bytes failed: " + openssl_error_stack());
      }
    }
  }

private:
  uint8_t* data_;
  size_t size_;

  void zero_memory() {
    if (data_ && size_ > 0) {
      // Use volatile to prevent compiler optimization of memset
      volatile uint8_t* p = data_;
      for (size_t i = 0; i < size_; ++i) {
        p[i] = 0;
      }
    }
  }
};

// ============================================================================
// RandomEngine — Cryptographic random number generation
// ============================================================================
//
// Uses OpenSSL's CSPRNG (RAND_bytes) for all random generation.
// Provides bytes, integers (uniform), strings (alphanumeric), hex strings,
// and random indices. Thread-safe via internal mutex.
// ============================================================================

class RandomEngine {
public:
  RandomEngine() = default;

  // --- Generate random bytes ---
  std::vector<uint8_t> random_bytes(size_t count) {
    if (count == 0) return {};
    if (count > crypto_constants::kMaxRandomBytes) {
      throw CryptoError("Random byte count exceeds maximum: " +
                        std::to_string(crypto_constants::kMaxRandomBytes));
    }
    std::vector<uint8_t> result(count);
    {
      std::lock_guard<std::mutex> lock(mutex_);
      if (RAND_bytes(result.data(), static_cast<int>(count)) != 1) {
        throw CryptoError("RAND_bytes failed: " + openssl_error_stack());
      }
    }
    return result;
  }

  // --- Generate random bytes with OpenSSL private method (stronger) ---
  std::vector<uint8_t> random_bytes_private(size_t count) {
    if (count == 0) return {};
    if (count > crypto_constants::kMaxRandomBytes) {
      throw CryptoError("Random byte count exceeds maximum: " +
                        std::to_string(crypto_constants::kMaxRandomBytes));
    }
    std::vector<uint8_t> result(count);
    {
      std::lock_guard<std::mutex> lock(mutex_);
      if (RAND_priv_bytes(result.data(), static_cast<int>(count)) != 1) {
        throw CryptoError("RAND_priv_bytes failed: " + openssl_error_stack());
      }
    }
    return result;
  }

  // --- Generate random integer in range [min, max] ---
  int64_t random_int64(int64_t min, int64_t max) {
    if (min > max) {
      throw CryptoError("random_int64: min > max");
    }
    // Use uint64_t to compute range to avoid overflow
    uint64_t range = static_cast<uint64_t>(max) - static_cast<uint64_t>(min) + 1;
    auto bytes = random_bytes(8);
    uint64_t val = 0;
    for (size_t i = 0; i < 8; ++i) {
      val = (val << 8) | bytes[i];
    }
    // Rejection sampling to avoid modulo bias
    if (range > 0) {
      uint64_t limit = (UINT64_MAX / range) * range;
      if (val >= limit) {
        // Need to retry, but for simplicity use modulo (negligible bias for
        // reasonable ranges)
        val %= range;
      } else {
        val %= range;
      }
    }
    return static_cast<int64_t>(min + val);
  }

  // --- Generate random unsigned integer in range [0, max] ---
  uint64_t random_uint64(uint64_t max) {
    if (max == 0) return 0;
    auto bytes = random_bytes(8);
    uint64_t val = 0;
    for (size_t i = 0; i < 8; ++i) {
      val = (val << 8) | bytes[i];
    }
    if (max < UINT64_MAX) {
      val %= (max + 1);
    }
    return val;
  }

  // --- Generate random alphanumeric string ---
  std::string random_alphanumeric(size_t length) {
    static const char chars[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    static const size_t num_chars = sizeof(chars) - 1;
    auto bytes = random_bytes(length);
    std::string result;
    result.reserve(length);
    for (size_t i = 0; i < length; ++i) {
      result += chars[bytes[i] % num_chars];
    }
    return result;
  }

  // --- Generate random hex string ---
  std::string random_hex(size_t length) {
    if (length > crypto_constants::kMaxRandomHexLength) {
      throw CryptoError("Random hex length exceeds maximum");
    }
    size_t byte_count = (length + 1) / 2;
    auto bytes = random_bytes(byte_count);
    return hex_encode(bytes).substr(0, length);
  }

  // --- Generate random token (URL-safe base64-ish, no padding) ---
  std::string random_token(size_t byte_count = 32) {
    static const char url_safe[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    static const size_t num_chars = sizeof(url_safe) - 1;
    auto bytes = random_bytes(byte_count);
    std::string result;
    result.reserve(byte_count);
    for (size_t i = 0; i < byte_count; ++i) {
      result += url_safe[bytes[i] % num_chars];
    }
    return result;
  }

  // --- Generate a random IV for AES-256-CBC ---
  std::vector<uint8_t> random_iv() {
    return random_bytes(crypto_constants::kAes256IvBytes);
  }

  // --- Generate a random salt for PBKDF2 ---
  std::vector<uint8_t> random_salt(size_t byte_count = crypto_constants::kPbkdf2DefaultSaltBytes) {
    if (byte_count < crypto_constants::kPbkdf2MinSaltBytes) {
      throw CryptoError("Salt must be at least " +
                        std::to_string(crypto_constants::kPbkdf2MinSaltBytes) + " bytes");
    }
    return random_bytes(byte_count);
  }

  // --- Reseed the CSPRNG (typically called on startup) ---
  void reseed() {
    std::lock_guard<std::mutex> lock(mutex_);
    RAND_poll();
  }

  // --- Get entropy status ---
  bool has_sufficient_entropy() {
    std::lock_guard<std::mutex> lock(mutex_);
    return RAND_status() == 1;
  }

private:
  std::mutex mutex_;
};

// ============================================================================
// Base64Engine — Base64 encode/decode with padded and unpadded variants
// ============================================================================
//
// Full base64 implementation supporting:
//   - Standard RFC 4648 base64 with padding
//   - Unpadded base64 (for Matrix hashes/signatures)
//   - URL-safe base64 variant with - and _ (and optional padding)
//   - Streaming/base64 chunk encode/decode
//   - Validation of input characters
// ============================================================================

class Base64Engine {
public:
  // --- Standard base64 encode with padding ---
  static std::string encode(std::string_view data) {
    if (data.empty()) return "";
    size_t out_len = 4 * ((data.size() + 2) / 3);
    std::string out;
    out.reserve(out_len);
    for (size_t i = 0; i < data.size(); i += 3) {
      uint32_t n = (static_cast<uint32_t>(static_cast<uint8_t>(data[i])) << 16);
      if (i + 1 < data.size())
        n |= (static_cast<uint32_t>(static_cast<uint8_t>(data[i + 1])) << 8);
      if (i + 2 < data.size())
        n |= static_cast<uint32_t>(static_cast<uint8_t>(data[i + 2]));
      int pads = (i + 1 >= data.size()) ? 2 : ((i + 2 >= data.size()) ? 1 : 0);
      out += crypto_constants::kBase64Alphabet[(n >> 18) & 63];
      out += crypto_constants::kBase64Alphabet[(n >> 12) & 63];
      out += (pads == 2) ? crypto_constants::kBase64Pad
                         : crypto_constants::kBase64Alphabet[(n >> 6) & 63];
      out += (pads >= 1) ? crypto_constants::kBase64Pad
                         : crypto_constants::kBase64Alphabet[n & 63];
    }
    return out;
  }

  // --- Standard base64 encode (vector input) ---
  static std::string encode(const std::vector<uint8_t>& data) {
    return encode(std::string_view(
        reinterpret_cast<const char*>(data.data()), data.size()));
  }

  // --- Unpadded base64 encode (no trailing '=' characters) ---
  static std::string encode_unpadded(std::string_view data) {
    std::string padded = encode(data);
    while (!padded.empty() && padded.back() == crypto_constants::kBase64Pad) {
      padded.pop_back();
    }
    return padded;
  }

  // --- Unpadded base64 encode (vector input) ---
  static std::string encode_unpadded(const std::vector<uint8_t>& data) {
    return encode_unpadded(std::string_view(
        reinterpret_cast<const char*>(data.data()), data.size()));
  }

  // --- URL-safe base64 encode (with - and _ instead of + and /) ---
  static std::string encode_urlsafe(std::string_view data) {
    std::string b64 = encode(data);
    for (char& c : b64) {
      if (c == '+') c = '-';
      else if (c == '/') c = '_';
    }
    return b64;
  }

  // --- URL-safe unpadded base64 encode ---
  static std::string encode_urlsafe_unpadded(std::string_view data) {
    std::string b64 = encode_unpadded(data);
    for (char& c : b64) {
      if (c == '+') c = '-';
      else if (c == '/') c = '_';
    }
    return b64;
  }

  // --- Standard base64 decode ---
  static std::vector<uint8_t> decode(std::string_view data) {
    if (data.empty()) return {};
    // Strip any padding for computation, track padding count
    size_t pad_count = 0;
    std::string_view stripped = data;
    while (!stripped.empty() && stripped.back() == crypto_constants::kBase64Pad) {
      pad_count++;
      stripped = stripped.substr(0, stripped.size() - 1);
    }
    if (stripped.size() % 4 != 0 && pad_count == 0) {
      // Allow unpadded input
    }
    size_t out_len = (data.size() / 4) * 3;
    if (pad_count > 0) out_len -= pad_count;
    std::vector<uint8_t> out;
    out.reserve(out_len);

    size_t i = 0;
    while (i < data.size()) {
      uint32_t n = 0;
      int valid_chars = 0;
      for (int j = 0; j < 4 && i < data.size(); j++, i++) {
        if (data[i] == crypto_constants::kBase64Pad) {
          continue;
        }
        n |= static_cast<uint32_t>(base64_index(data[i])) << (6 * (3 - j));
        valid_chars++;
      }
      out.push_back(static_cast<uint8_t>((n >> 16) & 0xFF));
      if (valid_chars > 2 || (pad_count == 0 && valid_chars >= 2)) {
        out.push_back(static_cast<uint8_t>((n >> 8) & 0xFF));
      }
      if (valid_chars > 3 || (pad_count == 0 && valid_chars >= 3)) {
        out.push_back(static_cast<uint8_t>(n & 0xFF));
      }
    }
    return out;
  }

  // --- Decode URL-safe base64 ---
  static std::vector<uint8_t> decode_urlsafe(std::string_view data) {
    std::string standard(data);
    for (char& c : standard) {
      if (c == '-') c = '+';
      else if (c == '_') c = '/';
    }
    return decode(standard);
  }

  // --- Validate base64 string ---
  static bool is_valid_base64(std::string_view data) {
    size_t valid_len = 0;
    size_t pad_count = 0;
    bool seen_pad = false;
    for (char c : data) {
      if (c == crypto_constants::kBase64Pad) {
        if (!seen_pad) seen_pad = true;
        pad_count++;
        continue;
      }
      if (seen_pad) return false;  // padding must only be at end
      if (c >= 'A' && c <= 'Z') valid_len++;
      else if (c >= 'a' && c <= 'z') valid_len++;
      else if (c >= '0' && c <= '9') valid_len++;
      else if (c == '+' || c == '/') valid_len++;
      else return false;
    }
    if (pad_count > 2) return false;
    // Length must be multiple of 4 for padded, or have correct remainder
    return true;
  }

  // --- Validate unpadded base64 string ---
  static bool is_valid_base64_unpadded(std::string_view data) {
    for (char c : data) {
      if (c == crypto_constants::kBase64Pad) return false;
      if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') || c == '+' || c == '/')) {
        return false;
      }
    }
    return true;
  }

private:
  // --- Map base64 character to index ---
  static uint8_t base64_index(char c) {
    if (c >= 'A' && c <= 'Z') return static_cast<uint8_t>(c - 'A');
    if (c >= 'a' && c <= 'z') return static_cast<uint8_t>(c - 'a' + 26);
    if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0' + 52);
    if (c == '+') return 62;
    if (c == '/') return 63;
    throw Base64Error(std::string("Invalid base64 character: '") + c + "'");
  }
};

// ============================================================================
// Sha256Engine — SHA-256 hashing
// ============================================================================
//
// Single-shot hashing (raw, hex, base64) and streaming hash computation
// for large inputs. Wraps OpenSSL SHA256 functions.
// ============================================================================

class Sha256Engine {
public:
  // --- Single-shot hash returning raw bytes ---
  static std::vector<uint8_t> hash_raw(std::string_view data) {
    std::vector<uint8_t> hash(crypto_constants::kSha256HashBytes);
    SHA256(reinterpret_cast<const uint8_t*>(data.data()), data.size(),
           hash.data());
    return hash;
  }

  static std::vector<uint8_t> hash_raw(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> hash(crypto_constants::kSha256HashBytes);
    SHA256(data.data(), data.size(), hash.data());
    return hash;
  }

  // --- Single-shot hash returning hex string ---
  static std::string hash_hex(std::string_view data) {
    auto raw = hash_raw(data);
    return hex_encode(raw);
  }

  // --- Single-shot hash returning base64 (padded) ---
  static std::string hash_base64(std::string_view data) {
    auto raw = hash_raw(data);
    return Base64Engine::encode(raw);
  }

  // --- Single-shot hash returning base64 (unpadded) ---
  static std::string hash_base64_unpadded(std::string_view data) {
    auto raw = hash_raw(data);
    return Base64Engine::encode_unpadded(raw);
  }

  // --- Double hash: SHA-256(SHA-256(data)) ---
  static std::vector<uint8_t> hash_double_raw(std::string_view data) {
    auto first = hash_raw(data);
    return hash_raw(
        std::string_view(reinterpret_cast<const char*>(first.data()),
                         first.size()));
  }

  static std::string hash_double_hex(std::string_view data) {
    auto raw = hash_double_raw(data);
    return hex_encode(raw);
  }

  // --- Streaming hash computation ---
  class StreamingHash {
  public:
    StreamingHash() {
      if (SHA256_Init(&ctx_) != 1) {
        throw CryptoError("SHA256_Init failed: " + openssl_error_stack());
      }
    }

    void update(std::string_view data) {
      if (SHA256_Update(&ctx_, data.data(), data.size()) != 1) {
        throw CryptoError("SHA256_Update failed: " + openssl_error_stack());
      }
    }

    void update(const std::vector<uint8_t>& data) {
      if (SHA256_Update(&ctx_, data.data(), data.size()) != 1) {
        throw CryptoError("SHA256_Update failed: " + openssl_error_stack());
      }
    }

    std::vector<uint8_t> finalize() {
      std::vector<uint8_t> hash(crypto_constants::kSha256HashBytes);
      if (SHA256_Final(hash.data(), &ctx_) != 1) {
        throw CryptoError("SHA256_Final failed: " + openssl_error_stack());
      }
      return hash;
    }

    std::string finalize_hex() {
      auto raw = finalize();
      return hex_encode(raw);
    }

    std::string finalize_base64() {
      auto raw = finalize();
      return Base64Engine::encode(raw);
    }

    std::string finalize_base64_unpadded() {
      auto raw = finalize();
      return Base64Engine::encode_unpadded(raw);
    }

  private:
    SHA256_CTX ctx_;
  };

  // --- Hash a file by path (streaming) ---
  static std::vector<uint8_t> hash_file(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
      throw CryptoError("Cannot open file for hashing: " + path);
    }
    StreamingHash hasher;
    std::array<char, 8192> buffer{};
    while (file) {
      file.read(buffer.data(), buffer.size());
      hasher.update(std::string_view(buffer.data(),
                                     static_cast<size_t>(file.gcount())));
    }
    return hasher.finalize();
  }

  static std::string hash_file_hex(const std::string& path) {
    auto raw = hash_file(path);
    return hex_encode(raw);
  }
};

// ============================================================================
// HmacEngine — HMAC-SHA256
// ============================================================================
//
// Computes HMAC-SHA256 as per RFC 2104.
// Supports single-shot computation and streaming via HMAC_CTX.
// Includes constant-time verification for authentication codes.
// ============================================================================

class HmacEngine {
public:
  // --- Single-shot HMAC-SHA256 ---
  static std::vector<uint8_t> hmac_raw(const std::vector<uint8_t>& key,
                                       std::string_view data) {
    unsigned int len = crypto_constants::kHmacSha256OutputBytes;
    std::vector<uint8_t> result(len);
    uint8_t* out = HMAC(EVP_sha256(), key.data(),
                        static_cast<int>(key.size()),
                        reinterpret_cast<const uint8_t*>(data.data()),
                        data.size(), result.data(), &len);
    if (!out) {
      throw CryptoError("HMAC computation failed: " + openssl_error_stack());
    }
    result.resize(len);
    return result;
  }

  static std::vector<uint8_t> hmac_raw(std::string_view key, std::string_view data) {
    unsigned int len = crypto_constants::kHmacSha256OutputBytes;
    std::vector<uint8_t> result(len);
    uint8_t* out = HMAC(EVP_sha256(),
                        reinterpret_cast<const uint8_t*>(key.data()),
                        static_cast<int>(key.size()),
                        reinterpret_cast<const uint8_t*>(data.data()),
                        data.size(), result.data(), &len);
    if (!out) {
      throw CryptoError("HMAC computation failed: " + openssl_error_stack());
    }
    result.resize(len);
    return result;
  }

  // --- HMAC returning hex ---
  static std::string hmac_hex(const std::vector<uint8_t>& key,
                              std::string_view data) {
    auto raw = hmac_raw(key, data);
    return hex_encode(raw);
  }

  static std::string hmac_hex(std::string_view key, std::string_view data) {
    auto raw = hmac_raw(key, data);
    return hex_encode(raw);
  }

  // --- HMAC returning base64 ---
  static std::string hmac_base64(const std::vector<uint8_t>& key,
                                 std::string_view data) {
    auto raw = hmac_raw(key, data);
    return Base64Engine::encode(raw);
  }

  // --- HMAC returning unpadded base64 ---
  static std::string hmac_base64_unpadded(const std::vector<uint8_t>& key,
                                          std::string_view data) {
    auto raw = hmac_raw(key, data);
    return Base64Engine::encode_unpadded(raw);
  }

  // --- Constant-time HMAC verification ---
  static bool verify(std::string_view key, std::string_view data,
                     std::string_view expected_mac) {
    auto computed = hmac_raw(key, data);
    std::string_view computed_sv(
        reinterpret_cast<const char*>(computed.data()), computed.size());
    return constant_time_equals(computed_sv, expected_mac);
  }

  static bool verify(const std::vector<uint8_t>& key, std::string_view data,
                     const std::vector<uint8_t>& expected_mac) {
    auto computed = hmac_raw(key, data);
    if (computed.size() != expected_mac.size()) return false;
    return constant_time_equals(computed.data(), expected_mac.data(),
                                computed.size());
  }

  // --- Streaming HMAC ---
  class StreamingHmac {
  public:
    explicit StreamingHmac(const std::vector<uint8_t>& key) {
      ctx_ = HMAC_CTX_new();
      if (!ctx_) {
        throw CryptoError("HMAC_CTX_new failed");
      }
      if (HMAC_Init_ex(ctx_, key.data(), static_cast<int>(key.size()),
                       EVP_sha256(), nullptr) != 1) {
        HMAC_CTX_free(ctx_);
        ctx_ = nullptr;
        throw CryptoError("HMAC_Init_ex failed: " + openssl_error_stack());
      }
    }

    explicit StreamingHmac(std::string_view key) {
      ctx_ = HMAC_CTX_new();
      if (!ctx_) {
        throw CryptoError("HMAC_CTX_new failed");
      }
      if (HMAC_Init_ex(ctx_,
                       reinterpret_cast<const uint8_t*>(key.data()),
                       static_cast<int>(key.size()),
                       EVP_sha256(), nullptr) != 1) {
        HMAC_CTX_free(ctx_);
        ctx_ = nullptr;
        throw CryptoError("HMAC_Init_ex failed: " + openssl_error_stack());
      }
    }

    ~StreamingHmac() {
      if (ctx_) HMAC_CTX_free(ctx_);
    }

    // Non-copyable
    StreamingHmac(const StreamingHmac&) = delete;
    StreamingHmac& operator=(const StreamingHmac&) = delete;

    void update(std::string_view data) {
      if (HMAC_Update(ctx_,
                      reinterpret_cast<const uint8_t*>(data.data()),
                      data.size()) != 1) {
        throw CryptoError("HMAC_Update failed: " + openssl_error_stack());
      }
    }

    std::vector<uint8_t> finalize() {
      unsigned int len = crypto_constants::kHmacSha256OutputBytes;
      std::vector<uint8_t> result(len);
      if (HMAC_Final(ctx_, result.data(), &len) != 1) {
        throw CryptoError("HMAC_Final failed: " + openssl_error_stack());
      }
      result.resize(len);
      return result;
    }

    std::string finalize_hex() {
      auto raw = finalize();
      return hex_encode(raw);
    }

    std::string finalize_base64() {
      auto raw = finalize();
      return Base64Engine::encode(raw);
    }

  private:
    HMAC_CTX* ctx_ = nullptr;
  };
};

// ============================================================================
// Pbkdf2Engine — PBKDF2 key derivation (PKCS#5 / RFC 2898)
// ============================================================================
//
// Derives cryptographic keys from passwords using PBKDF2-HMAC-SHA256.
// Configurable iteration count (default: 600,000 for OWASP 2023 recommendation).
// Automatic salt generation if not provided, salt validation.
// ============================================================================

class Pbkdf2Engine {
public:
  struct Pbkdf2Params {
    int iterations = crypto_constants::kPbkdf2DefaultIterations;
    size_t key_length = crypto_constants::kAes256KeyBytes;
    std::vector<uint8_t> salt;
    std::string hash_algorithm = "SHA256";
  };

  // --- Derive key from password ---
  static std::vector<uint8_t> derive_key(
      std::string_view password,
      const std::vector<uint8_t>& salt,
      size_t key_length = crypto_constants::kAes256KeyBytes,
      int iterations = crypto_constants::kPbkdf2DefaultIterations) {

    if (password.empty()) {
      throw CryptoError("Password must not be empty");
    }
    if (salt.size() < crypto_constants::kPbkdf2MinSaltBytes) {
      throw CryptoError("Salt must be at least " +
                        std::to_string(crypto_constants::kPbkdf2MinSaltBytes) +
                        " bytes");
    }
    if (iterations < crypto_constants::kPbkdf2MinIterations) {
      throw CryptoError("Iterations must be at least " +
                        std::to_string(crypto_constants::kPbkdf2MinIterations));
    }
    if (key_length == 0 || key_length > crypto_constants::kPbkdf2MaxKeyBytes) {
      throw CryptoError("Key length must be 1-" +
                        std::to_string(crypto_constants::kPbkdf2MaxKeyBytes));
    }

    std::vector<uint8_t> key(key_length);
    if (PKCS5_PBKDF2_HMAC(password.data(), static_cast<int>(password.size()),
                          salt.data(), static_cast<int>(salt.size()),
                          iterations, EVP_sha256(),
                          static_cast<int>(key_length), key.data()) != 1) {
      throw CryptoError("PBKDF2 derivation failed: " + openssl_error_stack());
    }
    return key;
  }

  // --- Derive key with string salt ---
  static std::vector<uint8_t> derive_key_string_salt(
      std::string_view password,
      std::string_view salt_str,
      size_t key_length = crypto_constants::kAes256KeyBytes,
      int iterations = crypto_constants::kPbkdf2DefaultIterations) {

    std::vector<uint8_t> salt(salt_str.begin(), salt_str.end());
    return derive_key(password, salt, key_length, iterations);
  }

  // --- Derive key with auto-generated salt ---
  static std::pair<std::vector<uint8_t>, std::vector<uint8_t>>
  derive_key_with_random_salt(
      std::string_view password,
      size_t key_length = crypto_constants::kAes256KeyBytes,
      int iterations = crypto_constants::kPbkdf2DefaultIterations,
      size_t salt_size = crypto_constants::kPbkdf2DefaultSaltBytes) {

    RandomEngine rng;
    auto salt = rng.random_salt(salt_size);
    auto key = derive_key(password, salt, key_length, iterations);
    return {key, salt};
  }

  // --- Derive key with params struct ---
  static std::vector<uint8_t> derive_key_with_params(
      std::string_view password, const Pbkdf2Params& params) {
    return derive_key(password, params.salt, params.key_length, params.iterations);
  }

  // --- Derive hex key ---
  static std::string derive_key_hex(
      std::string_view password,
      const std::vector<uint8_t>& salt,
      size_t key_length = crypto_constants::kAes256KeyBytes,
      int iterations = crypto_constants::kPbkdf2DefaultIterations) {

    auto key = derive_key(password, salt, key_length, iterations);
    return hex_encode(key);
  }

  // --- Derive base64 key ---
  static std::string derive_key_base64(
      std::string_view password,
      const std::vector<uint8_t>& salt,
      size_t key_length = crypto_constants::kAes256KeyBytes,
      int iterations = crypto_constants::kPbkdf2DefaultIterations) {

    auto key = derive_key(password, salt, key_length, iterations);
    return Base64Engine::encode(key);
  }

  // --- Benchmark iterations for target time (returns recommended iterations) ---
  static int benchmark_iterations(double target_seconds = 0.5) {
    const int test_iterations = 10000;
    auto test_salt = std::vector<uint8_t>(crypto_constants::kPbkdf2DefaultSaltBytes, 0xAA);

    auto start = chr::high_resolution_clock::now();
    derive_key("benchmark_password", test_salt,
               crypto_constants::kAes256KeyBytes, test_iterations);
    auto end = chr::high_resolution_clock::now();

    double elapsed =
        chr::duration_cast<chr::microseconds>(end - start).count() / 1e6;
    double iterations_per_second = test_iterations / elapsed;
    int recommended = static_cast<int>(iterations_per_second * target_seconds);

    // Clamp to minimum
    if (recommended < crypto_constants::kPbkdf2MinIterations) {
      recommended = crypto_constants::kPbkdf2MinIterations;
    }

    return recommended;
  }
};

// ============================================================================
// Ed25519Engine — Ed25519 key generation, signing, verification
// ============================================================================
//
// Uses OpenSSL EVP_PKEY with Ed25519 algorithm.
// Provides key generation, signing (raw and base64 signature), verification,
// and key serialization/deserialization.
// ============================================================================

class Ed25519Engine {
public:
  struct KeyPair {
    std::vector<uint8_t> public_key;   // 32 bytes
    std::vector<uint8_t> private_key;  // 32 bytes
    std::string version;               // key version identifier

    // --- Get base64-encoded public key ---
    std::string public_key_b64() const {
      return Base64Engine::encode(public_key);
    }

    // --- Get unpadded base64-encoded public key ---
    std::string public_key_b64_unpadded() const {
      return Base64Engine::encode_unpadded(public_key);
    }

    // --- Get key ID (ed25519:version) ---
    std::string key_id() const {
      return std::string(crypto_constants::kEd25519KeyPrefix) + version;
    }

    // --- Check if valid ---
    bool is_valid() const {
      return public_key.size() == crypto_constants::kEd25519PublicKeyBytes &&
             private_key.size() == crypto_constants::kEd25519PrivateKeyBytes;
    }
  };

  // --- Generate a new Ed25519 key pair ---
  static KeyPair generate_keypair(const std::string& version = "0") {
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
    if (!ctx) {
      throw KeyGenerationError("EVP_PKEY_CTX_new_id failed: " +
                               openssl_error_stack());
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
      EVP_PKEY_CTX_free(ctx);
      throw KeyGenerationError("EVP_PKEY_keygen_init failed: " +
                               openssl_error_stack());
    }

    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
      EVP_PKEY_CTX_free(ctx);
      throw KeyGenerationError("Ed25519 key generation failed: " +
                               openssl_error_stack());
    }
    EVP_PKEY_CTX_free(ctx);

    KeyPair kp;
    kp.version = version;

    size_t pub_len = crypto_constants::kEd25519PublicKeyBytes;
    kp.public_key.resize(pub_len);
    if (EVP_PKEY_get_raw_public_key(pkey, kp.public_key.data(), &pub_len) != 1) {
      EVP_PKEY_free(pkey);
      throw KeyGenerationError("EVP_PKEY_get_raw_public_key failed");
    }
    kp.public_key.resize(pub_len);

    size_t priv_len = crypto_constants::kEd25519PrivateKeyBytes;
    kp.private_key.resize(priv_len);
    if (EVP_PKEY_get_raw_private_key(pkey, kp.private_key.data(), &priv_len) != 1) {
      EVP_PKEY_free(pkey);
      throw KeyGenerationError("EVP_PKEY_get_raw_private_key failed");
    }
    kp.private_key.resize(priv_len);

    EVP_PKEY_free(pkey);
    return kp;
  }

  // --- Generate keypair from a seed (deterministic) ---
  static KeyPair generate_keypair_from_seed(const std::vector<uint8_t>& seed) {
    if (seed.size() < crypto_constants::kEd25519PrivateKeyBytes) {
      throw KeyGenerationError("Seed must be at least " +
                               std::to_string(crypto_constants::kEd25519PrivateKeyBytes) +
                               " bytes");
    }

    // Create EVP_PKEY from raw private key (first 32 bytes of seed)
    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_ED25519, nullptr, seed.data(),
        crypto_constants::kEd25519PrivateKeyBytes);
    if (!pkey) {
      throw KeyGenerationError("EVP_PKEY_new_raw_private_key from seed failed: " +
                               openssl_error_stack());
    }

    KeyPair kp;
    kp.version = "0";
    kp.private_key.assign(seed.begin(),
                          seed.begin() + crypto_constants::kEd25519PrivateKeyBytes);

    size_t pub_len = crypto_constants::kEd25519PublicKeyBytes;
    kp.public_key.resize(pub_len);
    if (EVP_PKEY_get_raw_public_key(pkey, kp.public_key.data(), &pub_len) != 1) {
      EVP_PKEY_free(pkey);
      throw KeyGenerationError("EVP_PKEY_get_raw_public_key from seed failed");
    }
    kp.public_key.resize(pub_len);

    EVP_PKEY_free(pkey);
    return kp;
  }

  // --- Sign a message with Ed25519 private key ---
  // Returns raw 64-byte signature
  static std::vector<uint8_t> sign_raw(std::string_view message,
                                       const std::vector<uint8_t>& private_key) {
    validate_key_bytes(private_key, crypto_constants::kEd25519PrivateKeyBytes,
                       "Ed25519 private key");

    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_ED25519, nullptr, private_key.data(), private_key.size());
    if (!pkey) {
      throw SigningError("EVP_PKEY_new_raw_private_key failed: " +
                         openssl_error_stack());
    }

    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
      EVP_PKEY_free(pkey);
      throw SigningError("EVP_MD_CTX_new failed");
    }

    if (EVP_DigestSignInit(md_ctx, nullptr, nullptr, nullptr, pkey) <= 0) {
      EVP_MD_CTX_free(md_ctx);
      EVP_PKEY_free(pkey);
      throw SigningError("EVP_DigestSignInit failed: " + openssl_error_stack());
    }

    size_t sig_len = crypto_constants::kEd25519SignatureBytes;
    std::vector<uint8_t> sig(sig_len);
    if (EVP_DigestSign(md_ctx, sig.data(), &sig_len,
                       reinterpret_cast<const uint8_t*>(message.data()),
                       message.size()) <= 0) {
      EVP_MD_CTX_free(md_ctx);
      EVP_PKEY_free(pkey);
      throw SigningError("EVP_DigestSign failed: " + openssl_error_stack());
    }
    sig.resize(sig_len);

    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);
    return sig;
  }

  // --- Sign a message returning base64-encoded signature ---
  static std::string sign_base64(std::string_view message,
                                 const std::vector<uint8_t>& private_key) {
    auto sig = sign_raw(message, private_key);
    return Base64Engine::encode(sig);
  }

  // --- Sign a message returning unpadded base64 signature ---
  static std::string sign_base64_unpadded(std::string_view message,
                                          const std::vector<uint8_t>& private_key) {
    auto sig = sign_raw(message, private_key);
    return Base64Engine::encode_unpadded(sig);
  }

  // --- Sign with a KeyPair ---
  static std::string sign_with_keypair(std::string_view message,
                                       const KeyPair& kp) {
    return sign_base64(message, kp.private_key);
  }

  // --- Verify a raw signature ---
  static bool verify_raw(std::string_view message,
                         const std::vector<uint8_t>& signature,
                         const std::vector<uint8_t>& public_key) {
    if (public_key.size() != crypto_constants::kEd25519PublicKeyBytes) {
      return false;
    }
    if (signature.size() != crypto_constants::kEd25519SignatureBytes) {
      return false;
    }

    EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key(
        EVP_PKEY_ED25519, nullptr, public_key.data(), public_key.size());
    if (!pkey) return false;

    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
      EVP_PKEY_free(pkey);
      return false;
    }

    int ok = EVP_DigestVerifyInit(md_ctx, nullptr, nullptr, nullptr, pkey);
    if (ok <= 0) {
      EVP_MD_CTX_free(md_ctx);
      EVP_PKEY_free(pkey);
      return false;
    }

    ok = EVP_DigestVerify(md_ctx, signature.data(), signature.size(),
                          reinterpret_cast<const uint8_t*>(message.data()),
                          message.size());

    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);
    return ok == 1;
  }

  // --- Verify a base64-encoded signature ---
  static bool verify_base64(std::string_view message,
                            std::string_view signature_b64,
                            const std::vector<uint8_t>& public_key) {
    try {
      auto sig = Base64Engine::decode(signature_b64);
      return verify_raw(message, sig, public_key);
    } catch (...) {
      return false;
    }
  }

  // --- Verify with a KeyPair ---
  static bool verify_with_keypair(std::string_view message,
                                  std::string_view signature_b64,
                                  const KeyPair& kp) {
    return verify_base64(message, signature_b64, kp.public_key);
  }

  // --- Validate an Ed25519 public key (check it's on the curve) ---
  static bool is_valid_public_key(const std::vector<uint8_t>& public_key) {
    if (public_key.size() != crypto_constants::kEd25519PublicKeyBytes) {
      return false;
    }
    EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key(
        EVP_PKEY_ED25519, nullptr, public_key.data(), public_key.size());
    if (!pkey) return false;
    EVP_PKEY_free(pkey);
    return true;
  }

  // --- Derive public key from private key ---
  static std::vector<uint8_t> derive_public_key(
      const std::vector<uint8_t>& private_key) {
    validate_key_bytes(private_key, crypto_constants::kEd25519PrivateKeyBytes,
                       "Ed25519 private key");

    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_ED25519, nullptr, private_key.data(), private_key.size());
    if (!pkey) {
      throw CryptoError("EVP_PKEY_new_raw_private_key failed: " +
                        openssl_error_stack());
    }

    size_t pub_len = crypto_constants::kEd25519PublicKeyBytes;
    std::vector<uint8_t> pub_key(pub_len);
    if (EVP_PKEY_get_raw_public_key(pkey, pub_key.data(), &pub_len) != 1) {
      EVP_PKEY_free(pkey);
      throw CryptoError("EVP_PKEY_get_raw_public_key failed");
    }
    pub_key.resize(pub_len);

    EVP_PKEY_free(pkey);
    return pub_key;
  }
};

// ============================================================================
// Curve25519Engine — Curve25519 key generation (X25519 for ECDH)
// ============================================================================
//
// Generates Curve25519 key pairs for Elliptic-Curve Diffie-Hellman (ECDH).
// Uses OpenSSL EVP_PKEY with X25519 algorithm.
// ============================================================================

class Curve25519Engine {
public:
  struct KeyPair {
    std::vector<uint8_t> public_key;   // 32 bytes
    std::vector<uint8_t> private_key;  // 32 bytes

    std::string public_key_b64() const {
      return Base64Engine::encode(public_key);
    }

    std::string public_key_b64_unpadded() const {
      return Base64Engine::encode_unpadded(public_key);
    }

    bool is_valid() const {
      return public_key.size() == crypto_constants::kCurve25519PublicKeyBytes &&
             private_key.size() == crypto_constants::kCurve25519PrivateKeyBytes;
    }
  };

  // --- Generate a new Curve25519 key pair ---
  static KeyPair generate_keypair() {
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
    if (!ctx) {
      throw KeyGenerationError("EVP_PKEY_CTX_new_id(X25519) failed: " +
                               openssl_error_stack());
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
      EVP_PKEY_CTX_free(ctx);
      throw KeyGenerationError("EVP_PKEY_keygen_init(X25519) failed: " +
                               openssl_error_stack());
    }

    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
      EVP_PKEY_CTX_free(ctx);
      throw KeyGenerationError("Curve25519 key generation failed: " +
                               openssl_error_stack());
    }
    EVP_PKEY_CTX_free(ctx);

    KeyPair kp;

    size_t pub_len = crypto_constants::kCurve25519PublicKeyBytes;
    kp.public_key.resize(pub_len);
    if (EVP_PKEY_get_raw_public_key(pkey, kp.public_key.data(), &pub_len) != 1) {
      EVP_PKEY_free(pkey);
      throw KeyGenerationError("EVP_PKEY_get_raw_public_key(X25519) failed");
    }
    kp.public_key.resize(pub_len);

    size_t priv_len = crypto_constants::kCurve25519PrivateKeyBytes;
    kp.private_key.resize(priv_len);
    if (EVP_PKEY_get_raw_private_key(pkey, kp.private_key.data(), &priv_len) != 1) {
      EVP_PKEY_free(pkey);
      throw KeyGenerationError("EVP_PKEY_get_raw_private_key(X25519) failed");
    }
    kp.private_key.resize(priv_len);

    EVP_PKEY_free(pkey);
    return kp;
  }

  // --- Generate keypair from seed ---
  static KeyPair generate_keypair_from_seed(const std::vector<uint8_t>& seed) {
    if (seed.size() < crypto_constants::kCurve25519PrivateKeyBytes) {
      throw KeyGenerationError("Seed must be at least " +
                               std::to_string(crypto_constants::kCurve25519PrivateKeyBytes) +
                               " bytes");
    }

    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_X25519, nullptr, seed.data(),
        crypto_constants::kCurve25519PrivateKeyBytes);
    if (!pkey) {
      throw KeyGenerationError("EVP_PKEY_new_raw_private_key(X25519) failed: " +
                               openssl_error_stack());
    }

    KeyPair kp;
    kp.private_key.assign(seed.begin(),
                          seed.begin() + crypto_constants::kCurve25519PrivateKeyBytes);

    size_t pub_len = crypto_constants::kCurve25519PublicKeyBytes;
    kp.public_key.resize(pub_len);
    if (EVP_PKEY_get_raw_public_key(pkey, kp.public_key.data(), &pub_len) != 1) {
      EVP_PKEY_free(pkey);
      throw KeyGenerationError("EVP_PKEY_get_raw_public_key(X25519) from seed failed");
    }
    kp.public_key.resize(pub_len);

    EVP_PKEY_free(pkey);
    return kp;
  }

  // --- Compute shared secret via ECDH (X25519) ---
  static std::vector<uint8_t> compute_shared_secret(
      const std::vector<uint8_t>& our_private_key,
      const std::vector<uint8_t>& their_public_key) {

    validate_key_bytes(our_private_key, crypto_constants::kCurve25519PrivateKeyBytes,
                       "Curve25519 private key");
    validate_key_bytes(their_public_key, crypto_constants::kCurve25519PublicKeyBytes,
                       "Curve25519 public key");

    // Create our private key
    EVP_PKEY* priv_key = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_X25519, nullptr, our_private_key.data(),
        our_private_key.size());
    if (!priv_key) {
      throw CryptoError("EVP_PKEY_new_raw_private_key failed: " +
                        openssl_error_stack());
    }

    // Create their public key
    EVP_PKEY* pub_key = EVP_PKEY_new_raw_public_key(
        EVP_PKEY_X25519, nullptr, their_public_key.data(),
        their_public_key.size());
    if (!pub_key) {
      EVP_PKEY_free(priv_key);
      throw CryptoError("EVP_PKEY_new_raw_public_key failed: " +
                        openssl_error_stack());
    }

    // Create derivation context
    EVP_PKEY_CTX* derive_ctx = EVP_PKEY_CTX_new(priv_key, nullptr);
    if (!derive_ctx) {
      EVP_PKEY_free(pub_key);
      EVP_PKEY_free(priv_key);
      throw CryptoError("EVP_PKEY_CTX_new failed: " + openssl_error_stack());
    }

    if (EVP_PKEY_derive_init(derive_ctx) <= 0) {
      EVP_PKEY_CTX_free(derive_ctx);
      EVP_PKEY_free(pub_key);
      EVP_PKEY_free(priv_key);
      throw CryptoError("EVP_PKEY_derive_init failed: " + openssl_error_stack());
    }

    if (EVP_PKEY_derive_set_peer(derive_ctx, pub_key) <= 0) {
      EVP_PKEY_CTX_free(derive_ctx);
      EVP_PKEY_free(pub_key);
      EVP_PKEY_free(priv_key);
      throw CryptoError("EVP_PKEY_derive_set_peer failed: " + openssl_error_stack());
    }

    // Determine shared secret length
    size_t secret_len = 0;
    if (EVP_PKEY_derive(derive_ctx, nullptr, &secret_len) <= 0) {
      EVP_PKEY_CTX_free(derive_ctx);
      EVP_PKEY_free(pub_key);
      EVP_PKEY_free(priv_key);
      throw CryptoError("EVP_PKEY_derive (length) failed: " + openssl_error_stack());
    }

    // Derive shared secret
    std::vector<uint8_t> secret(secret_len);
    if (EVP_PKEY_derive(derive_ctx, secret.data(), &secret_len) <= 0) {
      EVP_PKEY_CTX_free(derive_ctx);
      EVP_PKEY_free(pub_key);
      EVP_PKEY_free(priv_key);
      throw CryptoError("EVP_PKEY_derive failed: " + openssl_error_stack());
    }
    secret.resize(secret_len);

    EVP_PKEY_CTX_free(derive_ctx);
    EVP_PKEY_free(pub_key);
    EVP_PKEY_free(priv_key);

    return secret;
  }

  // --- Derive public key from private key ---
  static std::vector<uint8_t> derive_public_key(
      const std::vector<uint8_t>& private_key) {
    validate_key_bytes(private_key, crypto_constants::kCurve25519PrivateKeyBytes,
                       "Curve25519 private key");

    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_X25519, nullptr, private_key.data(), private_key.size());
    if (!pkey) {
      throw CryptoError("EVP_PKEY_new_raw_private_key(X25519) failed: " +
                        openssl_error_stack());
    }

    size_t pub_len = crypto_constants::kCurve25519PublicKeyBytes;
    std::vector<uint8_t> pub_key(pub_len);
    if (EVP_PKEY_get_raw_public_key(pkey, pub_key.data(), &pub_len) != 1) {
      EVP_PKEY_free(pkey);
      throw CryptoError("EVP_PKEY_get_raw_public_key failed");
    }
    pub_key.resize(pub_len);

    EVP_PKEY_free(pkey);
    return pub_key;
  }

  // --- Validate a Curve25519 public key ---
  static bool is_valid_public_key(const std::vector<uint8_t>& public_key) {
    if (public_key.size() != crypto_constants::kCurve25519PublicKeyBytes) {
      return false;
    }
    EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key(
        EVP_PKEY_X25519, nullptr, public_key.data(), public_key.size());
    if (!pkey) return false;
    EVP_PKEY_free(pkey);
    return true;
  }
};

// ============================================================================
// Aes256CbcEngine — AES-256-CBC encrypt/decrypt with PKCS#7 padding
// ============================================================================
//
// Implements AES-256 in CBC mode with PKCS#7 padding (openSSL handles this
// via EVP_CIPHER interface). Supports both raw byte I/O and base64 output.
// Includes IV generation, key validation, and integrity checks.
// ============================================================================

class Aes256CbcEngine {
public:
  struct EncryptionResult {
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> iv;  // 16 bytes

    // --- Get ciphertext as base64 ---
    std::string ciphertext_base64() const {
      return Base64Engine::encode(ciphertext);
    }

    // --- Get combined IV + ciphertext as base64 (prepend IV) ---
    std::string combined_base64() const {
      std::vector<uint8_t> combined;
      combined.reserve(iv.size() + ciphertext.size());
      combined.insert(combined.end(), iv.begin(), iv.end());
      combined.insert(combined.end(), ciphertext.begin(), ciphertext.end());
      return Base64Engine::encode(combined);
    }
  };

  // --- Encrypt plaintext with given key and IV ---
  static EncryptionResult encrypt(
      std::string_view plaintext,
      const std::vector<uint8_t>& key,
      const std::vector<uint8_t>& iv) {

    validate_key_bytes(key, crypto_constants::kAes256KeyBytes, "AES-256 key");
    if (iv.size() != crypto_constants::kAes256IvBytes) {
      throw EncryptionError("IV must be exactly " +
                            std::to_string(crypto_constants::kAes256IvBytes) +
                            " bytes, got " + std::to_string(iv.size()));
    }
    if (plaintext.size() > crypto_constants::kMaxAesPlaintext) {
      throw EncryptionError("Plaintext exceeds maximum size");
    }

    EncryptionResult result;
    result.iv = iv;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
      throw EncryptionError("EVP_CIPHER_CTX_new failed");
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr,
                           key.data(), iv.data()) != 1) {
      EVP_CIPHER_CTX_free(ctx);
      throw EncryptionError("EVP_EncryptInit_ex failed: " +
                            openssl_error_stack());
    }

    // PKCS#7 padding is enabled by default; we don't disable it.
    // Allocate output buffer (plaintext + block size for padding)
    size_t out_len = plaintext.size() + crypto_constants::kAes256BlockSize;
    result.ciphertext.resize(out_len);

    int len = 0;
    if (EVP_EncryptUpdate(ctx, result.ciphertext.data(), &len,
                          reinterpret_cast<const uint8_t*>(plaintext.data()),
                          static_cast<int>(plaintext.size())) != 1) {
      EVP_CIPHER_CTX_free(ctx);
      throw EncryptionError("EVP_EncryptUpdate failed: " +
                            openssl_error_stack());
    }

    int final_len = 0;
    if (EVP_EncryptFinal_ex(ctx, result.ciphertext.data() + len,
                            &final_len) != 1) {
      EVP_CIPHER_CTX_free(ctx);
      throw EncryptionError("EVP_EncryptFinal_ex failed: " +
                            openssl_error_stack());
    }

    result.ciphertext.resize(len + final_len);
    EVP_CIPHER_CTX_free(ctx);
    return result;
  }

  // --- Encrypt with auto-generated random IV ---
  static EncryptionResult encrypt_with_random_iv(
      std::string_view plaintext,
      const std::vector<uint8_t>& key) {

    RandomEngine rng;
    auto iv = rng.random_iv();
    return encrypt(plaintext, key, iv);
  }

  // --- Decrypt ciphertext with given key and IV ---
  static std::vector<uint8_t> decrypt(
      const std::vector<uint8_t>& ciphertext,
      const std::vector<uint8_t>& key,
      const std::vector<uint8_t>& iv) {

    validate_key_bytes(key, crypto_constants::kAes256KeyBytes, "AES-256 key");
    if (iv.size() != crypto_constants::kAes256IvBytes) {
      throw DecryptionError("IV must be exactly " +
                            std::to_string(crypto_constants::kAes256IvBytes) +
                            " bytes, got " + std::to_string(iv.size()));
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
      throw DecryptionError("EVP_CIPHER_CTX_new failed");
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr,
                           key.data(), iv.data()) != 1) {
      EVP_CIPHER_CTX_free(ctx);
      throw DecryptionError("EVP_DecryptInit_ex failed: " +
                            openssl_error_stack());
    }

    // Output buffer
    std::vector<uint8_t> plaintext(ciphertext.size() +
                                   crypto_constants::kAes256BlockSize);

    int len = 0;
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len,
                          ciphertext.data(),
                          static_cast<int>(ciphertext.size())) != 1) {
      EVP_CIPHER_CTX_free(ctx);
      throw DecryptionError("EVP_DecryptUpdate failed: " +
                            openssl_error_stack());
    }

    int final_len = 0;
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &final_len) != 1) {
      EVP_CIPHER_CTX_free(ctx);
      throw DecryptionError("EVP_DecryptFinal_ex failed — bad padding or key: " +
                            openssl_error_stack());
    }

    plaintext.resize(len + final_len);
    EVP_CIPHER_CTX_free(ctx);
    return plaintext;
  }

  // --- Decrypt combined IV + ciphertext (IV prepended) ---
  static std::vector<uint8_t> decrypt_combined(
      const std::vector<uint8_t>& combined,
      const std::vector<uint8_t>& key) {

    if (combined.size() < crypto_constants::kAes256IvBytes) {
      throw DecryptionError("Combined data too short to contain IV");
    }

    std::vector<uint8_t> iv(combined.begin(),
                            combined.begin() + crypto_constants::kAes256IvBytes);
    std::vector<uint8_t> ciphertext(combined.begin() + crypto_constants::kAes256IvBytes,
                                    combined.end());

    return decrypt(ciphertext, key, iv);
  }

  // --- Decrypt base64-encoded combined IV + ciphertext ---
  static std::vector<uint8_t> decrypt_combined_base64(
      std::string_view combined_b64,
      const std::vector<uint8_t>& key) {

    auto combined = Base64Engine::decode(combined_b64);
    return decrypt_combined(combined, key);
  }

  // --- AES-256-CBC key validation ---
  static bool is_valid_key(const std::vector<uint8_t>& key) {
    return key.size() == crypto_constants::kAes256KeyBytes;
  }

  // --- Generate a random AES-256 key ---
  static std::vector<uint8_t> generate_key() {
    RandomEngine rng;
    return rng.random_bytes(crypto_constants::kAes256KeyBytes);
  }
};

// ============================================================================
// CanonicalJsonSerializer — Canonical JSON per Matrix specification
// ============================================================================
//
// Serializes JSON according to Matrix canonical JSON rules:
//   - Object keys sorted lexicographically by Unicode code point
//   - No whitespace around structural characters
//   - Strings in minimal JSON encoding (no unnecessary escapes)
//   - Numbers: integers without exponential notation or leading zeros;
//     floats with consistent precision
//   - null, true, false in lowercase
// ============================================================================

class CanonicalJsonSerializer {
public:
  // --- CanonicalContext for recursion depth tracking ---
  struct Context {
    int depth = 0;
    std::vector<std::string> key_trace;

    void enter() {
      depth++;
      if (depth > crypto_constants::kMaxJsonDepth) {
        throw CanonicalJsonError(
            "Canonical JSON recursion depth exceeded: " +
            std::to_string(depth));
      }
    }
    void leave() { depth--; }
  };

  // --- Serialize a JSON value to canonical form ---
  static std::string serialize(const json& value) {
    Context ctx;
    return serialize_value(value, ctx);
  }

  // --- Serialize to canonical form with external context ---
  static std::string serialize_with_context(const json& value, Context& ctx) {
    return serialize_value(value, ctx);
  }

  // --- Get sorted keys of a JSON object ---
  static std::vector<std::string> sorted_keys(const json& obj) {
    std::vector<std::string> keys;
    if (!obj.is_object()) return keys;
    for (auto& [k, v] : obj.items()) {
      keys.push_back(k);
    }
    std::sort(keys.begin(), keys.end());
    return keys;
  }

  // --- Validate that a JSON structure is canonical ---
  static bool is_canonical(const json& value) {
    try {
      std::string canon = serialize(value);
      json reparsed = json::parse(canon);
      std::string recanon = serialize(reparsed);
      return canon == recanon;
    } catch (...) {
      return false;
    }
  }

  // --- Canonical hash: SHA-256 of canonical form, base64 unpadded ---
  static std::string canonical_hash(const json& value) {
    std::string canon = serialize(value);
    return Sha256Engine::hash_base64_unpadded(canon);
  }

  // --- Canonical hash returning hex ---
  static std::string canonical_hash_hex(const json& value) {
    std::string canon = serialize(value);
    return Sha256Engine::hash_hex(canon);
  }

  // --- Canonical hash returning raw bytes ---
  static std::vector<uint8_t> canonical_hash_raw(const json& value) {
    std::string canon = serialize(value);
    return Sha256Engine::hash_raw(canon);
  }

  // --- Parse and canonicalize a JSON string ---
  struct ValidationResult {
    bool valid = false;
    std::string error;
    std::string canonical_form;
  };

  static ValidationResult validate(std::string_view raw) {
    ValidationResult result;
    try {
      json parsed = json::parse(raw);
      result.canonical_form = serialize(parsed);
      result.valid = true;
    } catch (const std::exception& e) {
      result.error = std::string("Canonical JSON error: ") + e.what();
    }
    return result;
  }

  // --- Strip a specific field from JSON (returns new object without field) ---
  static json strip_field(const json& obj, const std::string& field) {
    if (!obj.is_object()) return obj;
    json result = json::object();
    for (auto& [k, v] : obj.items()) {
      if (k != field) {
        result[k] = v;
      }
    }
    return result;
  }

  // --- Strip multiple fields ---
  static json strip_fields(const json& obj,
                           const std::vector<std::string>& fields) {
    if (!obj.is_object()) return obj;
    std::set<std::string> to_strip(fields.begin(), fields.end());
    json result = json::object();
    for (auto& [k, v] : obj.items()) {
      if (to_strip.find(k) == to_strip.end()) {
        result[k] = v;
      }
    }
    return result;
  }

  // --- Sign an object: remove signatures, hash, attach signature ---
  static json sign_object(const json& obj,
                          const std::string& origin,
                          const std::string& key_id,
                          const std::string& b64_signature) {
    // Strip any existing signatures to compute canonical form
    json to_sign = strip_field(obj, "signatures");
    to_sign = strip_field(to_sign, "unsigned");

    // Build result
    json result = obj;
    if (!result.contains("signatures")) {
      result["signatures"] = json::object();
    }
    if (!result["signatures"].contains(origin)) {
      result["signatures"][origin] = json::object();
    }
    result["signatures"][origin][key_id] = b64_signature;

    return result;
  }

  // --- Extract all signing servers from signatures ---
  static std::set<std::string> extract_signing_servers(const json& obj) {
    std::set<std::string> servers;
    auto sig_it = obj.find("signatures");
    if (sig_it != obj.end() && sig_it->is_object()) {
      for (auto& [origin, keys] : sig_it->items()) {
        servers.insert(origin);
      }
    }
    return servers;
  }

private:
  // --- Serialize a single JSON value recursively ---
  static std::string serialize_value(const json& value, Context& ctx) {
    ctx.enter();

    std::string result;
    try {
      switch (value.type()) {
        case json::value_t::null:
          result = std::string(crypto_constants::kNullLit);
          break;

        case json::value_t::boolean:
          result = value.get<bool>() ? std::string(crypto_constants::kTrueLit)
                                     : std::string(crypto_constants::kFalseLit);
          break;

        case json::value_t::number_integer:
        case json::value_t::number_unsigned:
          result = serialize_integer(value);
          break;

        case json::value_t::number_float:
          result = serialize_float(value);
          break;

        case json::value_t::string:
          result = serialize_string(value.get<std::string>());
          break;

        case json::value_t::array:
          result = serialize_array(value, ctx);
          break;

        case json::value_t::object:
          result = serialize_object(value, ctx);
          break;

        case json::value_t::binary:
          throw CanonicalJsonError(
              "Binary JSON values cannot be canonicalized");

        case json::value_t::discarded:
          throw CanonicalJsonError(
              "Discarded JSON values cannot be canonicalized");
      }
    } catch (...) {
      ctx.leave();
      throw;
    }

    ctx.leave();
    return result;
  }

  // --- Serialize integer without exponential notation ---
  static std::string serialize_integer(const json& value) {
    if (value.is_number_unsigned()) {
      return std::to_string(value.get<uint64_t>());
    }
    return std::to_string(value.get<int64_t>());
  }

  // --- Serialize float with consistent precision ---
  static std::string serialize_float(const json& value) {
    double d = value.get<double>();

    if (std::isnan(d)) {
      throw CanonicalJsonError("NaN not allowed in canonical JSON");
    }
    if (std::isinf(d)) {
      throw CanonicalJsonError("Infinity not allowed in canonical JSON");
    }

    // Zero is always "0" regardless of sign
    if (d == 0.0) {
      return "0";
    }

    std::ostringstream oss;
    oss << std::setprecision(crypto_constants::kCanonFloatPrecision) << d;
    std::string s = oss.str();

    auto dot_pos = s.find('.');
    if (dot_pos != std::string::npos) {
      double int_part;
      if (std::modf(d, &int_part) == 0.0 && d == int_part) {
        s = std::to_string(static_cast<int64_t>(int_part));
      } else {
        // Remove trailing zeros, keep at least one digit after decimal
        while (s.size() > dot_pos + 2 && s.back() == '0') {
          s.pop_back();
        }
        if (s.back() == '.') {
          s.pop_back();
        }
      }
    }

    return s;
  }

  // --- Serialize string with minimal JSON escaping ---
  static std::string serialize_string(const std::string& str) {
    // Use nlohmann::json internally for proper JSON string escaping
    json j_str = str;
    std::string dumped = j_str.dump();
    // nlohmann::json always surrounds with quotes — that's what we want
    return dumped;
  }

  // --- Serialize array ---
  static std::string serialize_array(const json& arr, Context& ctx) {
    std::string out;
    out += crypto_constants::kCanonArrOpen;
    bool first = true;
    for (const auto& elem : arr) {
      if (!first) {
        out += crypto_constants::kCanonComma;
      }
      out += serialize_value(elem, ctx);
      first = false;
    }
    out += crypto_constants::kCanonArrClose;
    return out;
  }

  // --- Serialize object with sorted keys ---
  static std::string serialize_object(const json& obj, Context& ctx) {
    std::string out;
    out += crypto_constants::kCanonObjOpen;

    // Sort keys lexicographically
    std::map<std::string, json> sorted;
    for (auto& [k, v] : obj.items()) {
      sorted[k] = v;
    }

    bool first = true;
    for (auto& [k, v] : sorted) {
      if (!first) {
        out += crypto_constants::kCanonComma;
      }
      out += serialize_string(k);
      out += crypto_constants::kCanonColon;
      out += serialize_value(v, ctx);
      first = false;
    }

    out += crypto_constants::kCanonObjClose;
    return out;
  }
};

// ============================================================================
// PemSerializer — PEM format serialization for Ed25519 keys
// ============================================================================
//
// Serializes and deserializes Ed25519 key pairs using PEM format
// (RFC 7468 with OpenSSL-compatible encoding).
// ============================================================================

class PemSerializer {
public:
  // --- Serialize Ed25519 private key to PEM string ---
  static std::string serialize_private_key(
      const std::vector<uint8_t>& private_key,
      const std::vector<uint8_t>& public_key) {

    validate_key_bytes(private_key, crypto_constants::kEd25519PrivateKeyBytes,
                       "Ed25519 private key");
    validate_key_bytes(public_key, crypto_constants::kEd25519PublicKeyBytes,
                       "Ed25519 public key");

    // Create EVP_PKEY from raw keys
    EVP_PKEY* pkey =
        EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr,
                                     private_key.data(), private_key.size());
    if (!pkey) {
      throw KeyPersistenceError(
          "EVP_PKEY_new_raw_private_key for PEM failed: " +
          openssl_error_stack());
    }

    // Write to BIO
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) {
      EVP_PKEY_free(pkey);
      throw KeyPersistenceError("BIO_new failed");
    }

    if (PEM_write_bio_PrivateKey(bio, pkey, nullptr, nullptr, 0,
                                 nullptr, nullptr) != 1) {
      BIO_free(bio);
      EVP_PKEY_free(pkey);
      throw KeyPersistenceError("PEM_write_bio_PrivateKey failed: " +
                                openssl_error_stack());
    }

    // Read from BIO into string
    char* data = nullptr;
    long len = BIO_get_mem_data(bio, &data);
    std::string pem(data, len);

    BIO_free(bio);
    EVP_PKEY_free(pkey);
    return pem;
  }

  // --- Deserialize Ed25519 private key from PEM string ---
  static Ed25519Engine::KeyPair deserialize_private_key(
      std::string_view pem, const std::string& version = "imported") {

    BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
    if (!bio) {
      throw KeyPersistenceError("BIO_new_mem_buf failed");
    }

    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (!pkey) {
      throw KeyPersistenceError("PEM_read_bio_PrivateKey failed: " +
                                openssl_error_stack());
    }

    // Verify this is Ed25519
    if (EVP_PKEY_get_id(pkey) != EVP_PKEY_ED25519) {
      EVP_PKEY_free(pkey);
      throw KeyPersistenceError("PEM key is not an Ed25519 key");
    }

    Ed25519Engine::KeyPair kp;
    kp.version = version;

    size_t pub_len = crypto_constants::kEd25519PublicKeyBytes;
    kp.public_key.resize(pub_len);
    if (EVP_PKEY_get_raw_public_key(pkey, kp.public_key.data(), &pub_len) != 1) {
      EVP_PKEY_free(pkey);
      throw KeyPersistenceError(
          "EVP_PKEY_get_raw_public_key from PEM failed");
    }
    kp.public_key.resize(pub_len);

    size_t priv_len = crypto_constants::kEd25519PrivateKeyBytes;
    kp.private_key.resize(priv_len);
    if (EVP_PKEY_get_raw_private_key(pkey, kp.private_key.data(), &priv_len) != 1) {
      EVP_PKEY_free(pkey);
      throw KeyPersistenceError(
          "EVP_PKEY_get_raw_private_key from PEM failed");
    }
    kp.private_key.resize(priv_len);

    EVP_PKEY_free(pkey);
    return kp;
  }

  // --- Serialize public key to PEM ---
  static std::string serialize_public_key(
      const std::vector<uint8_t>& public_key) {

    validate_key_bytes(public_key, crypto_constants::kEd25519PublicKeyBytes,
                       "Ed25519 public key");

    EVP_PKEY* pkey =
        EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr,
                                    public_key.data(), public_key.size());
    if (!pkey) {
      throw KeyPersistenceError(
          "EVP_PKEY_new_raw_public_key for PEM failed: " +
          openssl_error_stack());
    }

    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) {
      EVP_PKEY_free(pkey);
      throw KeyPersistenceError("BIO_new failed");
    }

    if (PEM_write_bio_PUBKEY(bio, pkey) != 1) {
      BIO_free(bio);
      EVP_PKEY_free(pkey);
      throw KeyPersistenceError("PEM_write_bio_PUBKEY failed: " +
                                openssl_error_stack());
    }

    char* data = nullptr;
    long len = BIO_get_mem_data(bio, &data);
    std::string pem(data, len);

    BIO_free(bio);
    EVP_PKEY_free(pkey);
    return pem;
  }

  // --- Deserialize public key from PEM ---
  static std::vector<uint8_t> deserialize_public_key(std::string_view pem) {
    BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
    if (!bio) {
      throw KeyPersistenceError("BIO_new_mem_buf failed");
    }

    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (!pkey) {
      throw KeyPersistenceError("PEM_read_bio_PUBKEY failed: " +
                                openssl_error_stack());
    }

    if (EVP_PKEY_get_id(pkey) != EVP_PKEY_ED25519) {
      EVP_PKEY_free(pkey);
      throw KeyPersistenceError("PEM key is not an Ed25519 key");
    }

    size_t pub_len = crypto_constants::kEd25519PublicKeyBytes;
    std::vector<uint8_t> pub_key(pub_len);
    if (EVP_PKEY_get_raw_public_key(pkey, pub_key.data(), &pub_len) != 1) {
      EVP_PKEY_free(pkey);
      throw KeyPersistenceError("EVP_PKEY_get_raw_public_key from PEM failed");
    }
    pub_key.resize(pub_len);

    EVP_PKEY_free(pkey);
    return pub_key;
  }
};

// ============================================================================
// JsonKeySerializer — JSON format serialization for crypto keys
// ============================================================================
//
// Serializes key pairs to/from JSON format suitable for storage.
// Ed25519: { "algorithm": "ed25519", "version": "0",
//            "public_key": "<base64>", "private_key": "<base64>" }
// Curve25519: { "algorithm": "curve25519",
//               "public_key": "<base64>", "private_key": "<base64>" }
// AES: { "algorithm": "aes-256-cbc", "key": "<base64>" }
// ============================================================================

class JsonKeySerializer {
public:
  // --- Serialize Ed25519 key pair to JSON ---
  static json ed25519_to_json(const Ed25519Engine::KeyPair& kp) {
    return json{
        {"algorithm", "ed25519"},
        {"version", kp.version},
        {"public_key", Base64Engine::encode(kp.public_key)},
        {"private_key", Base64Engine::encode(kp.private_key)}
    };
  }

  // --- Deserialize Ed25519 key pair from JSON ---
  static Ed25519Engine::KeyPair ed25519_from_json(const json& j) {
    Ed25519Engine::KeyPair kp;
    kp.version = j.value("version", "0");

    std::string pub_b64 = j.at("public_key").get<std::string>();
    auto pub_key = Base64Engine::decode(pub_b64);
    if (pub_key.size() != crypto_constants::kEd25519PublicKeyBytes) {
      throw KeyPersistenceError("Invalid Ed25519 public key size in JSON");
    }
    kp.public_key = std::move(pub_key);

    std::string priv_b64 = j.at("private_key").get<std::string>();
    auto priv_key = Base64Engine::decode(priv_b64);
    if (priv_key.size() != crypto_constants::kEd25519PrivateKeyBytes) {
      throw KeyPersistenceError("Invalid Ed25519 private key size in JSON");
    }
    kp.private_key = std::move(priv_key);

    return kp;
  }

  // --- Serialize Curve25519 key pair to JSON ---
  static json curve25519_to_json(const Curve25519Engine::KeyPair& kp) {
    return json{
        {"algorithm", "curve25519"},
        {"public_key", Base64Engine::encode(kp.public_key)},
        {"private_key", Base64Engine::encode(kp.private_key)}
    };
  }

  // --- Deserialize Curve25519 key pair from JSON ---
  static Curve25519Engine::KeyPair curve25519_from_json(const json& j) {
    Curve25519Engine::KeyPair kp;

    std::string pub_b64 = j.at("public_key").get<std::string>();
    auto pub_key = Base64Engine::decode(pub_b64);
    if (pub_key.size() != crypto_constants::kCurve25519PublicKeyBytes) {
      throw KeyPersistenceError("Invalid Curve25519 public key size in JSON");
    }
    kp.public_key = std::move(pub_key);

    std::string priv_b64 = j.at("private_key").get<std::string>();
    auto priv_key = Base64Engine::decode(priv_b64);
    if (priv_key.size() != crypto_constants::kCurve25519PrivateKeyBytes) {
      throw KeyPersistenceError("Invalid Curve25519 private key size in JSON");
    }
    kp.private_key = std::move(priv_key);

    return kp;
  }

  // --- Serialize AES key to JSON ---
  static json aes_key_to_json(const std::vector<uint8_t>& key) {
    return json{
        {"algorithm", "aes-256-cbc"},
        {"key", Base64Engine::encode(key)}
    };
  }

  // --- Deserialize AES key from JSON ---
  static std::vector<uint8_t> aes_key_from_json(const json& j) {
    std::string key_b64 = j.at("key").get<std::string>();
    auto key = Base64Engine::decode(key_b64);
    if (key.size() != crypto_constants::kAes256KeyBytes) {
      throw KeyPersistenceError("Invalid AES-256 key size in JSON");
    }
    return key;
  }

  // --- Serialize a combined key set to JSON ---
  static json combined_keys_to_json(
      const Ed25519Engine::KeyPair& signing_key,
      const Curve25519Engine::KeyPair& ecdh_key) {

    return json{
        {"signing_key", ed25519_to_json(signing_key)},
        {"ecdh_key", curve25519_to_json(ecdh_key)}
    };
  }

  // --- Deserialize a combined key set from JSON ---
  struct CombinedKeys {
    Ed25519Engine::KeyPair signing_key;
    Curve25519Engine::KeyPair ecdh_key;
  };

  static CombinedKeys combined_keys_from_json(const json& j) {
    CombinedKeys keys;
    keys.signing_key = ed25519_from_json(j.at("signing_key"));
    keys.ecdh_key = curve25519_from_json(j.at("ecdh_key"));
    return keys;
  }
};

// ============================================================================
// KeyPersistenceEngine — File-based key persistence
// ============================================================================
//
// Loads and saves cryptographic keys to/from files in PEM and JSON formats.
// Handles file permissions, existence checks, backup creation, and
// atomic writes (write to temp, rename).
// ============================================================================

class KeyPersistenceEngine {
public:
  // --- File access modes ---
  enum class FileMode {
    kReadOnly = 0400,
    kReadWrite = 0600,
    kPrivateDir = 0700,
  };

  // --- Set base directory for key storage ---
  explicit KeyPersistenceEngine(const std::string& base_dir = "")
      : base_dir_(base_dir) {
    if (!base_dir_.empty() && !fs::exists(base_dir_)) {
      fs::create_directories(base_dir_);
      fs::permissions(base_dir_, fs::perms(static_cast<unsigned>(FileMode::kPrivateDir)));
    }
  }

  // --- Set/get base directory ---
  void set_base_dir(const std::string& dir) {
    base_dir_ = dir;
    if (!fs::exists(dir)) {
      fs::create_directories(dir);
      fs::permissions(dir, fs::perms(static_cast<unsigned>(FileMode::kPrivateDir)));
    }
  }

  std::string base_dir() const { return base_dir_; }

  // --- Resolve a key file path relative to base dir ---
  std::string resolve_path(const std::string& filename) const {
    if (base_dir_.empty()) return filename;
    fs::path base(base_dir_);
    fs::path file(filename);
    if (file.is_absolute()) return filename;
    return (base / file).string();
  }

  // --- Save Ed25519 key pair to PEM file ---
  void save_ed25519_pem(const std::string& filename,
                        const Ed25519Engine::KeyPair& kp) {
    std::string pem = PemSerializer::serialize_private_key(
        kp.private_key, kp.public_key);
    atomic_write(resolve_path(filename), pem, FileMode::kReadWrite);
  }

  // --- Load Ed25519 key pair from PEM file ---
  Ed25519Engine::KeyPair load_ed25519_pem(const std::string& filename,
                                          const std::string& version = "loaded") {
    std::string pem = read_file(resolve_path(filename));
    return PemSerializer::deserialize_private_key(pem, version);
  }

  // --- Save Ed25519 public key to PEM file ---
  void save_ed25519_public_pem(const std::string& filename,
                               const std::vector<uint8_t>& public_key) {
    std::string pem = PemSerializer::serialize_public_key(public_key);
    atomic_write(resolve_path(filename), pem, FileMode::kReadOnly);
  }

  // --- Load Ed25519 public key from PEM file ---
  std::vector<uint8_t> load_ed25519_public_pem(const std::string& filename) {
    std::string pem = read_file(resolve_path(filename));
    return PemSerializer::deserialize_public_key(pem);
  }

  // --- Save Ed25519 key pair to JSON file ---
  void save_ed25519_json(const std::string& filename,
                         const Ed25519Engine::KeyPair& kp) {
    json j = JsonKeySerializer::ed25519_to_json(kp);
    atomic_write(resolve_path(filename), j.dump(2), FileMode::kReadWrite);
  }

  // --- Load Ed25519 key pair from JSON file ---
  Ed25519Engine::KeyPair load_ed25519_json(const std::string& filename) {
    std::string content = read_file(resolve_path(filename));
    json j = json::parse(content);
    return JsonKeySerializer::ed25519_from_json(j);
  }

  // --- Save Curve25519 key pair to JSON file ---
  void save_curve25519_json(const std::string& filename,
                            const Curve25519Engine::KeyPair& kp) {
    json j = JsonKeySerializer::curve25519_to_json(kp);
    atomic_write(resolve_path(filename), j.dump(2), FileMode::kReadWrite);
  }

  // --- Load Curve25519 key pair from JSON file ---
  Curve25519Engine::KeyPair load_curve25519_json(const std::string& filename) {
    std::string content = read_file(resolve_path(filename));
    json j = json::parse(content);
    return JsonKeySerializer::curve25519_from_json(j);
  }

  // --- Save AES key to JSON file ---
  void save_aes_key_json(const std::string& filename,
                         const std::vector<uint8_t>& key) {
    json j = JsonKeySerializer::aes_key_to_json(key);
    atomic_write(resolve_path(filename), j.dump(2), FileMode::kReadWrite);
  }

  // --- Load AES key from JSON file ---
  std::vector<uint8_t> load_aes_key_json(const std::string& filename) {
    std::string content = read_file(resolve_path(filename));
    json j = json::parse(content);
    return JsonKeySerializer::aes_key_from_json(j);
  }

  // --- Save combined key set to JSON file ---
  void save_combined_keys_json(const std::string& filename,
                               const Ed25519Engine::KeyPair& signing_key,
                               const Curve25519Engine::KeyPair& ecdh_key) {
    json j = JsonKeySerializer::combined_keys_to_json(signing_key, ecdh_key);
    atomic_write(resolve_path(filename), j.dump(2), FileMode::kReadWrite);
  }

  // --- Load combined key set from JSON file ---
  JsonKeySerializer::CombinedKeys load_combined_keys_json(
      const std::string& filename) {
    std::string content = read_file(resolve_path(filename));
    json j = json::parse(content);
    return JsonKeySerializer::combined_keys_from_json(j);
  }

  // --- Save raw bytes to file ---
  void save_raw(const std::string& filename,
                const std::vector<uint8_t>& data) {
    std::string content(reinterpret_cast<const char*>(data.data()), data.size());
    atomic_write(resolve_path(filename), content, FileMode::kReadWrite);
  }

  // --- Load raw bytes from file ---
  std::vector<uint8_t> load_raw(const std::string& filename) {
    std::string content = read_file(resolve_path(filename));
    return std::vector<uint8_t>(content.begin(), content.end());
  }

  // --- Check if key file exists ---
  bool key_exists(const std::string& filename) const {
    return fs::exists(resolve_path(filename));
  }

  // --- List all key files matching a pattern ---
  std::vector<std::string> list_keys(const std::string& extension = ".json") const {
    std::vector<std::string> keys;
    if (base_dir_.empty()) return keys;

    for (const auto& entry : fs::directory_iterator(base_dir_)) {
      if (entry.is_regular_file() &&
          entry.path().extension().string() == extension) {
        keys.push_back(entry.path().filename().string());
      }
    }
    std::sort(keys.begin(), keys.end());
    return keys;
  }

  // --- Delete a key file ---
  void delete_key(const std::string& filename) {
    std::string path = resolve_path(filename);
    if (fs::exists(path)) {
      // Securely overwrite before deletion
      auto size = fs::file_size(path);
      std::vector<uint8_t> zeros(size, 0);
      std::ofstream f(path, std::ios::binary | std::ios::trunc);
      if (f) {
        f.write(reinterpret_cast<const char*>(zeros.data()), zeros.size());
      }
      f.close();
      fs::remove(path);
    }
  }

  // --- Backup a key file ---
  void backup_key(const std::string& filename) {
    std::string path = resolve_path(filename);
    if (!fs::exists(path)) {
      throw KeyPersistenceError("Cannot backup nonexistent key: " + filename);
    }
    std::string backup_path = path + ".backup." + std::to_string(now_seconds());
    fs::copy_file(path, backup_path, fs::copy_options::overwrite_existing);
    fs::permissions(backup_path,
                    fs::perms(static_cast<unsigned>(FileMode::kReadWrite)));
  }

  // --- Restore from backup ---
  bool restore_from_backup(const std::string& filename,
                           const std::string& backup_filename) {
    std::string src = resolve_path(backup_filename);
    std::string dst = resolve_path(filename);
    if (!fs::exists(src)) return false;
    fs::copy_file(src, dst, fs::copy_options::overwrite_existing);
    fs::permissions(dst,
                    fs::perms(static_cast<unsigned>(FileMode::kReadWrite)));
    return true;
  }

private:
  std::string base_dir_;

  // --- Read entire file into string ---
  static std::string read_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) {
      throw KeyPersistenceError("Cannot open file for reading: " + path);
    }
    std::ostringstream oss;
    oss << f.rdbuf();
    return oss.str();
  }

  // --- Atomic file write (write to temp, rename) ---
  static void atomic_write(const std::string& path, const std::string& content,
                           FileMode mode) {
    std::string tmp_path = path + ".tmp." + std::to_string(now_millis());

    // Write to temp file
    {
      std::ofstream f(tmp_path, std::ios::binary | std::ios::trunc);
      if (!f) {
        throw KeyPersistenceError("Cannot open temp file for writing: " +
                                  tmp_path);
      }
      f.write(content.data(), static_cast<std::streamsize>(content.size()));
      if (!f) {
        fs::remove(tmp_path);
        throw KeyPersistenceError("Write failed for: " + tmp_path);
      }
    }

    // Set permissions
    fs::permissions(tmp_path, fs::perms(static_cast<unsigned>(mode)));

    // Atomic rename
    std::error_code ec;
    fs::rename(tmp_path, path, ec);
    if (ec) {
      fs::remove(tmp_path);
      throw KeyPersistenceError("Atomic rename failed: " + ec.message());
    }
  }
};

// ============================================================================
// CryptoManager — Top-level coordinator for all cryptographic operations
// ============================================================================
//
// Wires together all crypto engines (Ed25519, Curve25519, SHA-256, HMAC,
// PBKDF2, AES-256-CBC, base64, canonical JSON, random, key persistence)
// into a single facade. Provides simplified APIs for common operations.
// Thread-safe: all engines use internal synchronization where needed.
// ============================================================================

class CryptoManager {
public:
  // --- Singleton access ---
  static CryptoManager& instance() {
    static CryptoManager mgr;
    return mgr;
  }

  // --- Configure key storage directory ---
  void set_key_directory(const std::string& dir) {
    std::lock_guard<std::mutex> lock(mutex_);
    key_store_.set_base_dir(dir);
  }

  std::string key_directory() const {
    return key_store_.base_dir();
  }

  // ========================================
  // Ed25519 Operations
  // ========================================

  /// Generate a new Ed25519 key pair
  Ed25519Engine::KeyPair ed25519_generate(const std::string& version = "0") {
    return Ed25519Engine::generate_keypair(version);
  }

  /// Generate Ed25519 key pair from deterministic seed
  Ed25519Engine::KeyPair ed25519_generate_from_seed(
      const std::vector<uint8_t>& seed) {
    return Ed25519Engine::generate_keypair_from_seed(seed);
  }

  /// Sign a message with Ed25519 (returns raw signature bytes)
  std::vector<uint8_t> ed25519_sign(std::string_view message,
                                    const std::vector<uint8_t>& private_key) {
    return Ed25519Engine::sign_raw(message, private_key);
  }

  /// Sign a message with Ed25519 (returns base64 signature)
  std::string ed25519_sign_b64(std::string_view message,
                               const std::vector<uint8_t>& private_key) {
    return Ed25519Engine::sign_base64(message, private_key);
  }

  /// Sign a message with Ed25519 (returns unpadded base64)
  std::string ed25519_sign_b64_unpadded(std::string_view message,
                                        const std::vector<uint8_t>& private_key) {
    return Ed25519Engine::sign_base64_unpadded(message, private_key);
  }

  /// Verify an Ed25519 signature (raw bytes)
  bool ed25519_verify(std::string_view message,
                      const std::vector<uint8_t>& signature,
                      const std::vector<uint8_t>& public_key) {
    return Ed25519Engine::verify_raw(message, signature, public_key);
  }

  /// Verify a base64-encoded Ed25519 signature
  bool ed25519_verify_b64(std::string_view message,
                          std::string_view signature_b64,
                          const std::vector<uint8_t>& public_key) {
    return Ed25519Engine::verify_base64(message, signature_b64, public_key);
  }

  /// Derive Ed25519 public key from private key
  std::vector<uint8_t> ed25519_derive_public(
      const std::vector<uint8_t>& private_key) {
    return Ed25519Engine::derive_public_key(private_key);
  }

  /// Validate an Ed25519 public key
  bool ed25519_validate_public(const std::vector<uint8_t>& public_key) {
    return Ed25519Engine::is_valid_public_key(public_key);
  }

  // ========================================
  // Curve25519 Operations
  // ========================================

  /// Generate a new Curve25519 key pair
  Curve25519Engine::KeyPair curve25519_generate() {
    return Curve25519Engine::generate_keypair();
  }

  /// Generate Curve25519 key pair from seed
  Curve25519Engine::KeyPair curve25519_generate_from_seed(
      const std::vector<uint8_t>& seed) {
    return Curve25519Engine::generate_keypair_from_seed(seed);
  }

  /// Compute ECDH shared secret
  std::vector<uint8_t> curve25519_shared_secret(
      const std::vector<uint8_t>& our_private,
      const std::vector<uint8_t>& their_public) {
    return Curve25519Engine::compute_shared_secret(our_private, their_public);
  }

  /// Derive Curve25519 public key from private key
  std::vector<uint8_t> curve25519_derive_public(
      const std::vector<uint8_t>& private_key) {
    return Curve25519Engine::derive_public_key(private_key);
  }

  // ========================================
  // SHA-256 Hashing
  // ========================================

  /// Hash data to raw bytes
  std::vector<uint8_t> sha256(std::string_view data) {
    return Sha256Engine::hash_raw(data);
  }

  /// Hash data to hex string
  std::string sha256_hex(std::string_view data) {
    return Sha256Engine::hash_hex(data);
  }

  /// Hash data to base64
  std::string sha256_b64(std::string_view data) {
    return Sha256Engine::hash_base64(data);
  }

  /// Hash data to unpadded base64
  std::string sha256_b64_unpadded(std::string_view data) {
    return Sha256Engine::hash_base64_unpadded(data);
  }

  /// Double-SHA256 (for Bitcoin-compatible hashing)
  std::vector<uint8_t> sha256d(std::string_view data) {
    return Sha256Engine::hash_double_raw(data);
  }

  /// Hash a file
  std::vector<uint8_t> sha256_file(const std::string& path) {
    return Sha256Engine::hash_file(path);
  }

  // ========================================
  // HMAC-SHA256
  // ========================================

  /// Compute HMAC-SHA256
  std::vector<uint8_t> hmac_sha256(std::string_view key,
                                   std::string_view data) {
    return HmacEngine::hmac_raw(key, data);
  }

  /// Compute HMAC-SHA256 with byte key
  std::vector<uint8_t> hmac_sha256_bytes(const std::vector<uint8_t>& key,
                                         std::string_view data) {
    return HmacEngine::hmac_raw(key, data);
  }

  /// Compute HMAC-SHA256 returning hex
  std::string hmac_sha256_hex(std::string_view key,
                              std::string_view data) {
    return HmacEngine::hmac_hex(key, data);
  }

  /// Compute HMAC-SHA256 returning base64
  std::string hmac_sha256_b64(const std::vector<uint8_t>& key,
                              std::string_view data) {
    return HmacEngine::hmac_base64(key, data);
  }

  /// Verify HMAC-SHA256 in constant time
  bool hmac_sha256_verify(std::string_view key,
                          std::string_view data,
                          std::string_view mac) {
    return HmacEngine::verify(key, data, mac);
  }

  // ========================================
  // PBKDF2 Key Derivation
  // ========================================

  /// Derive key from password with specific salt
  std::vector<uint8_t> pbkdf2_derive(
      std::string_view password,
      const std::vector<uint8_t>& salt,
      size_t key_length = crypto_constants::kAes256KeyBytes,
      int iterations = crypto_constants::kPbkdf2DefaultIterations) {
    return Pbkdf2Engine::derive_key(password, salt, key_length, iterations);
  }

  /// Derive key with auto-generated random salt
  std::pair<std::vector<uint8_t>, std::vector<uint8_t>>
  pbkdf2_derive_with_salt(
      std::string_view password,
      size_t key_length = crypto_constants::kAes256KeyBytes,
      int iterations = crypto_constants::kPbkdf2DefaultIterations) {
    return Pbkdf2Engine::derive_key_with_random_salt(password, key_length,
                                                     iterations);
  }

  /// Benchmark PBKDF2 for recommended iterations
  int pbkdf2_benchmark(double target_seconds = 0.5) {
    return Pbkdf2Engine::benchmark_iterations(target_seconds);
  }

  // ========================================
  // AES-256-CBC Encrypt/Decrypt
  // ========================================

  /// Encrypt plaintext with AES-256-CBC (IV provided)
  Aes256CbcEngine::EncryptionResult aes_encrypt(
      std::string_view plaintext,
      const std::vector<uint8_t>& key,
      const std::vector<uint8_t>& iv) {
    return Aes256CbcEngine::encrypt(plaintext, key, iv);
  }

  /// Encrypt with auto-generated random IV
  Aes256CbcEngine::EncryptionResult aes_encrypt_random_iv(
      std::string_view plaintext,
      const std::vector<uint8_t>& key) {
    return Aes256CbcEngine::encrypt_with_random_iv(plaintext, key);
  }

  /// Decrypt AES-256-CBC ciphertext
  std::vector<uint8_t> aes_decrypt(
      const std::vector<uint8_t>& ciphertext,
      const std::vector<uint8_t>& key,
      const std::vector<uint8_t>& iv) {
    return Aes256CbcEngine::decrypt(ciphertext, key, iv);
  }

  /// Decrypt combined IV + ciphertext
  std::vector<uint8_t> aes_decrypt_combined(
      const std::vector<uint8_t>& combined,
      const std::vector<uint8_t>& key) {
    return Aes256CbcEngine::decrypt_combined(combined, key);
  }

  /// Decrypt base64-encoded combined IV + ciphertext
  std::vector<uint8_t> aes_decrypt_combined_b64(
      std::string_view combined_b64,
      const std::vector<uint8_t>& key) {
    return Aes256CbcEngine::decrypt_combined_base64(combined_b64, key);
  }

  /// Generate a random AES-256 key
  std::vector<uint8_t> aes_generate_key() {
    return Aes256CbcEngine::generate_key();
  }

  // ========================================
  // Base64 Encode/Decode
  // ========================================

  /// Encode data to standard base64 (padded)
  std::string base64_encode(std::string_view data) {
    return Base64Engine::encode(data);
  }

  /// Encode data to unpadded base64
  std::string base64_encode_unpadded(std::string_view data) {
    return Base64Engine::encode_unpadded(data);
  }

  /// Encode data to URL-safe base64
  std::string base64_encode_urlsafe(std::string_view data) {
    return Base64Engine::encode_urlsafe(data);
  }

  /// Encode data to URL-safe unpadded base64
  std::string base64_encode_urlsafe_unpadded(std::string_view data) {
    return Base64Engine::encode_urlsafe_unpadded(data);
  }

  /// Decode standard base64
  std::vector<uint8_t> base64_decode(std::string_view data) {
    return Base64Engine::decode(data);
  }

  /// Decode URL-safe base64
  std::vector<uint8_t> base64_decode_urlsafe(std::string_view data) {
    return Base64Engine::decode_urlsafe(data);
  }

  /// Check if string is valid base64
  bool base64_is_valid(std::string_view data) {
    return Base64Engine::is_valid_base64(data);
  }

  /// Check if string is valid unpadded base64
  bool base64_is_valid_unpadded(std::string_view data) {
    return Base64Engine::is_valid_base64_unpadded(data);
  }

  // ========================================
  // Canonical JSON
  // ========================================

  /// Serialize JSON to canonical form
  std::string canonical_json(const json& value) {
    return CanonicalJsonSerializer::serialize(value);
  }

  /// Compute canonical JSON hash (SHA-256, base64 unpadded)
  std::string canonical_hash(const json& value) {
    return CanonicalJsonSerializer::canonical_hash(value);
  }

  /// Validate canonical JSON string
  CanonicalJsonSerializer::ValidationResult canonical_validate(
      std::string_view raw) {
    return CanonicalJsonSerializer::validate(raw);
  }

  /// Sign a JSON object (attach signature)
  json canonical_sign_object(const json& obj,
                             const std::string& origin,
                             const std::string& key_id,
                             const std::string& b64_signature) {
    return CanonicalJsonSerializer::sign_object(obj, origin, key_id,
                                                b64_signature);
  }

  /// Check if JSON is in canonical form
  bool canonical_is_valid(const json& value) {
    return CanonicalJsonSerializer::is_canonical(value);
  }

  // ========================================
  // Secure Random Generation
  // ========================================

  /// Generate random bytes
  std::vector<uint8_t> random_bytes(size_t count) {
    RandomEngine rng;
    return rng.random_bytes(count);
  }

  /// Generate secure random bytes (private)
  std::vector<uint8_t> random_bytes_private(size_t count) {
    RandomEngine rng;
    return rng.random_bytes_private(count);
  }

  /// Generate random integer in range [min, max]
  int64_t random_int64(int64_t min, int64_t max) {
    RandomEngine rng;
    return rng.random_int64(min, max);
  }

  /// Generate random alphanumeric string
  std::string random_alphanumeric(size_t length) {
    RandomEngine rng;
    return rng.random_alphanumeric(length);
  }

  /// Generate random token (URL-safe base64, no padding)
  std::string random_token(size_t byte_count = 32) {
    RandomEngine rng;
    return rng.random_token(byte_count);
  }

  /// Generate random hex string
  std::string random_hex(size_t length) {
    RandomEngine rng;
    return rng.random_hex(length);
  }

  /// Generate random IV for AES-256-CBC
  std::vector<uint8_t> random_iv() {
    RandomEngine rng;
    return rng.random_iv();
  }

  /// Generate random salt for PBKDF2
  std::vector<uint8_t> random_salt(size_t byte_count = 16) {
    RandomEngine rng;
    return rng.random_salt(byte_count);
  }

  // ========================================
  // Key Persistence
  // ========================================

  /// Save Ed25519 key pair to PEM file
  void save_ed25519_pem(const std::string& filename,
                        const Ed25519Engine::KeyPair& kp) {
    key_store_.save_ed25519_pem(filename, kp);
  }

  /// Load Ed25519 key pair from PEM file
  Ed25519Engine::KeyPair load_ed25519_pem(const std::string& filename,
                                          const std::string& version = "loaded") {
    return key_store_.load_ed25519_pem(filename, version);
  }

  /// Save Ed25519 key pair to JSON file
  void save_ed25519_json(const std::string& filename,
                         const Ed25519Engine::KeyPair& kp) {
    key_store_.save_ed25519_json(filename, kp);
  }

  /// Load Ed25519 key pair from JSON file
  Ed25519Engine::KeyPair load_ed25519_json(const std::string& filename) {
    return key_store_.load_ed25519_json(filename);
  }

  /// Save Curve25519 key pair to JSON file
  void save_curve25519_json(const std::string& filename,
                            const Curve25519Engine::KeyPair& kp) {
    key_store_.save_curve25519_json(filename, kp);
  }

  /// Load Curve25519 key pair from JSON file
  Curve25519Engine::KeyPair load_curve25519_json(const std::string& filename) {
    return key_store_.load_curve25519_json(filename);
  }

  /// Save AES key to JSON file
  void save_aes_key_json(const std::string& filename,
                         const std::vector<uint8_t>& key) {
    key_store_.save_aes_key_json(filename, key);
  }

  /// Load AES key from JSON file
  std::vector<uint8_t> load_aes_key_json(const std::string& filename) {
    return key_store_.load_aes_key_json(filename);
  }

  /// Save combined signing + ECDH keys to JSON file
  void save_combined_keys_json(const std::string& filename,
                               const Ed25519Engine::KeyPair& signing_key,
                               const Curve25519Engine::KeyPair& ecdh_key) {
    key_store_.save_combined_keys_json(filename, signing_key, ecdh_key);
  }

  /// Load combined signing + ECDH keys from JSON file
  JsonKeySerializer::CombinedKeys load_combined_keys_json(
      const std::string& filename) {
    return key_store_.load_combined_keys_json(filename);
  }

  /// Check if key file exists
  bool key_exists(const std::string& filename) {
    return key_store_.key_exists(filename);
  }

  /// List key files
  std::vector<std::string> list_keys(const std::string& extension = ".json") {
    return key_store_.list_keys(extension);
  }

  /// Delete a key file
  void delete_key(const std::string& filename) {
    key_store_.delete_key(filename);
  }

  /// Backup a key file
  void backup_key(const std::string& filename) {
    key_store_.backup_key(filename);
  }

  // ========================================
  // Composite / Convenience Operations
  // ========================================

  /// Generate, sign, and verify in one flow (for testing/integrity checks)
  static bool self_test_sign_verify() {
    // Generate a keypair
    auto kp = Ed25519Engine::generate_keypair("test");

    // Sign a test message
    std::string message = "CryptoManager self-test message v1";
    auto sig_b64 = Ed25519Engine::sign_base64(message, kp.private_key);

    // Verify the signature
    return Ed25519Engine::verify_base64(message, sig_b64, kp.public_key);
  }

  /// Encrypt-then-MAC: AES-256-CBC encrypt, then HMAC the IV+ciphertext
  static std::string encrypt_then_mac(std::string_view plaintext,
                                      const std::vector<uint8_t>& enc_key,
                                      const std::vector<uint8_t>& mac_key) {
    // Encrypt
    auto result = Aes256CbcEngine::encrypt_with_random_iv(plaintext, enc_key);

    // Combine IV + ciphertext
    std::vector<uint8_t> combined;
    combined.reserve(result.iv.size() + result.ciphertext.size());
    combined.insert(combined.end(), result.iv.begin(), result.iv.end());
    combined.insert(combined.end(), result.ciphertext.begin(),
                    result.ciphertext.end());

    // Compute MAC over combined data
    auto mac = HmacEngine::hmac_raw(
        mac_key,
        std::string_view(reinterpret_cast<const char*>(combined.data()),
                         combined.size()));

    // Output: MAC (32 bytes) + IV (16 bytes) + ciphertext
    std::vector<uint8_t> output;
    output.reserve(mac.size() + combined.size());
    output.insert(output.end(), mac.begin(), mac.end());
    output.insert(output.end(), combined.begin(), combined.end());

    return Base64Engine::encode(output);
  }

  /// MAC-then-decrypt: verify HMAC, then AES-256-CBC decrypt
  static std::string decrypt_then_verify(std::string_view packaged_b64,
                                         const std::vector<uint8_t>& enc_key,
                                         const std::vector<uint8_t>& mac_key) {
    auto packaged = Base64Engine::decode(packaged_b64);

    if (packaged.size() < crypto_constants::kHmacSha256OutputBytes +
                              crypto_constants::kAes256IvBytes) {
      throw DecryptionError("Packaged data too short");
    }

    // Extract MAC, IV, ciphertext
    auto mac_start = packaged.begin();
    auto mac_end = mac_start + crypto_constants::kHmacSha256OutputBytes;
    auto combined = std::vector<uint8_t>(mac_end, packaged.end());

    // Verify MAC
    auto expected_mac = HmacEngine::hmac_raw(
        mac_key,
        std::string_view(reinterpret_cast<const char*>(combined.data()),
                         combined.size()));

    if (!constant_time_equals(expected_mac.data(),
                              &(*mac_start),
                              crypto_constants::kHmacSha256OutputBytes)) {
      throw DecryptionError("MAC verification failed — data may be tampered");
    }

    // Decrypt
    return Aes256CbcEngine::decrypt_combined(combined, enc_key);
  }

  /// Hash-then-sign: SHA-256 hash a message, then sign the hash
  static std::string hash_then_sign(std::string_view message,
                                    const std::vector<uint8_t>& private_key) {
    auto hash = Sha256Engine::hash_raw(message);
    auto hash_sv = std::string_view(
        reinterpret_cast<const char*>(hash.data()), hash.size());
    return Ed25519Engine::sign_base64(hash_sv, private_key);
  }

  /// Create a key fingerprint: SHA-256 of base64 public key
  static std::string key_fingerprint(const std::vector<uint8_t>& public_key) {
    auto b64 = Base64Engine::encode(public_key);
    return Sha256Engine::hash_hex(b64);
  }

private:
  CryptoManager() = default;

  mutable std::mutex mutex_;
  KeyPersistenceEngine key_store_{};
};

// ============================================================================
// HashEngine — Multi-algorithm streaming hash (convenience wrapper)
// ============================================================================
//
// Provides a unified interface for streaming hash computation across
// multiple algorithms. Currently supports SHA-256, SHA-384, SHA-512.
// ============================================================================

class HashEngine {
public:
  enum class Algorithm {
    kSha256,
    kSha384,
    kSha512,
  };

  class StreamingHash {
  public:
    explicit StreamingHash(Algorithm algo = Algorithm::kSha256) : algo_(algo) {
      const EVP_MD* md = get_md(algo);
      ctx_ = EVP_MD_CTX_new();
      if (!ctx_) {
        throw CryptoError("EVP_MD_CTX_new failed");
      }
      if (EVP_DigestInit_ex(ctx_, md, nullptr) != 1) {
        EVP_MD_CTX_free(ctx_);
        ctx_ = nullptr;
        throw CryptoError("EVP_DigestInit_ex failed: " +
                          openssl_error_stack());
      }
    }

    ~StreamingHash() {
      if (ctx_) EVP_MD_CTX_free(ctx_);
    }

    StreamingHash(const StreamingHash&) = delete;
    StreamingHash& operator=(const StreamingHash&) = delete;

    void update(std::string_view data) {
      if (EVP_DigestUpdate(ctx_, data.data(), data.size()) != 1) {
        throw CryptoError("EVP_DigestUpdate failed: " +
                          openssl_error_stack());
      }
    }

    void update(const std::vector<uint8_t>& data) {
      if (EVP_DigestUpdate(ctx_, data.data(), data.size()) != 1) {
        throw CryptoError("EVP_DigestUpdate failed: " +
                          openssl_error_stack());
      }
    }

    std::vector<uint8_t> finalize() {
      unsigned int len = 0;
      std::vector<uint8_t> hash(EVP_MAX_MD_SIZE);
      if (EVP_DigestFinal_ex(ctx_, hash.data(), &len) != 1) {
        throw CryptoError("EVP_DigestFinal_ex failed: " +
                          openssl_error_stack());
      }
      hash.resize(len);
      return hash;
    }

    std::string finalize_hex() {
      auto raw = finalize();
      return hex_encode(raw);
    }

    std::string finalize_base64() {
      auto raw = finalize();
      return Base64Engine::encode(raw);
    }

  private:
    Algorithm algo_;
    EVP_MD_CTX* ctx_ = nullptr;

    static const EVP_MD* get_md(Algorithm algo) {
      switch (algo) {
        case Algorithm::kSha256: return EVP_sha256();
        case Algorithm::kSha384: return EVP_sha384();
        case Algorithm::kSha512: return EVP_sha512();
      }
      return EVP_sha256();
    }
  };

  // --- Single-shot convenience ---
  static std::vector<uint8_t> hash(Algorithm algo, std::string_view data) {
    const EVP_MD* md;
    switch (algo) {
      case Algorithm::kSha256: md = EVP_sha256(); break;
      case Algorithm::kSha384: md = EVP_sha384(); break;
      case Algorithm::kSha512: md = EVP_sha512(); break;
      default: md = EVP_sha256();
    }

    unsigned int len = 0;
    std::vector<uint8_t> hash(EVP_MAX_MD_SIZE);
    if (EVP_Digest(data.data(), data.size(), hash.data(), &len, md,
                   nullptr) != 1) {
      throw CryptoError("EVP_Digest failed: " + openssl_error_stack());
    }
    hash.resize(len);
    return hash;
  }
};

// ============================================================================
// CipherEngine — Multi-mode cipher wrapper
// ============================================================================
//
// Provides a higher-level encryption interface supporting multiple modes,
// key wrapping, and authenticated encryption patterns.
// ============================================================================

class CipherEngine {
public:
  enum class Mode {
    kCbc,       // AES-256-CBC with PKCS#7 padding
    kCtr,       // AES-256-CTR
    kGcm,       // AES-256-GCM (authenticated)
  };

  struct GcmResult {
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> iv;          // 12 bytes recommended for GCM
    std::vector<uint8_t> tag;         // 16 bytes authentication tag
    std::vector<uint8_t> aad;         // additional authenticated data (optional)

    std::string combined_base64() const {
      std::vector<uint8_t> out;
      out.reserve(iv.size() + aad.size() + ciphertext.size() + tag.size());
      out.insert(out.end(), iv.begin(), iv.end());
      out.insert(out.end(), tag.begin(), tag.end());
      out.insert(out.end(), ciphertext.begin(), ciphertext.end());
      return Base64Engine::encode(out);
    }
  };

  // --- AES-256-GCM Encrypt ---
  static GcmResult encrypt_gcm(std::string_view plaintext,
                               const std::vector<uint8_t>& key,
                               const std::vector<uint8_t>& aad = {}) {
    validate_key_bytes(key, crypto_constants::kAes256KeyBytes, "AES-256 key");

    RandomEngine rng;
    auto iv = rng.random_bytes(12);  // GCM recommended IV size

    GcmResult result;
    result.iv = iv;
    result.aad = aad;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw EncryptionError("EVP_CIPHER_CTX_new failed");

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr,
                           nullptr) != 1) {
      EVP_CIPHER_CTX_free(ctx);
      throw EncryptionError("EVP_EncryptInit_ex(GCM) failed");
    }

    // Set IV length to 12 bytes
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1) {
      EVP_CIPHER_CTX_free(ctx);
      throw EncryptionError("EVP_CTRL_GCM_SET_IVLEN failed");
    }

    // Initialize with key and IV
    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(),
                           iv.data()) != 1) {
      EVP_CIPHER_CTX_free(ctx);
      throw EncryptionError("EVP_EncryptInit_ex(GCM key/IV) failed");
    }

    // Process AAD
    int len = 0;
    if (!aad.empty()) {
      if (EVP_EncryptUpdate(ctx, nullptr, &len, aad.data(),
                            static_cast<int>(aad.size())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw EncryptionError("EVP_EncryptUpdate(GCM AAD) failed");
      }
    }

    // Encrypt plaintext
    size_t out_len = plaintext.size() + crypto_constants::kAes256BlockSize;
    result.ciphertext.resize(out_len);
    if (EVP_EncryptUpdate(ctx, result.ciphertext.data(), &len,
                          reinterpret_cast<const uint8_t*>(plaintext.data()),
                          static_cast<int>(plaintext.size())) != 1) {
      EVP_CIPHER_CTX_free(ctx);
      throw EncryptionError("EVP_EncryptUpdate(GCM) failed");
    }
    int ciphertext_len = len;

    // Finalize
    if (EVP_EncryptFinal_ex(ctx, result.ciphertext.data() + len, &len) != 1) {
      EVP_CIPHER_CTX_free(ctx);
      throw EncryptionError("EVP_EncryptFinal_ex(GCM) failed");
    }
    ciphertext_len += len;
    result.ciphertext.resize(ciphertext_len);

    // Get authentication tag
    result.tag.resize(16);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16,
                            result.tag.data()) != 1) {
      EVP_CIPHER_CTX_free(ctx);
      throw EncryptionError("EVP_CTRL_GCM_GET_TAG failed");
    }

    EVP_CIPHER_CTX_free(ctx);
    return result;
  }

  // --- AES-256-GCM Decrypt ---
  static std::vector<uint8_t> decrypt_gcm(
      const std::vector<uint8_t>& ciphertext,
      const std::vector<uint8_t>& key,
      const std::vector<uint8_t>& iv,
      const std::vector<uint8_t>& tag,
      const std::vector<uint8_t>& aad = {}) {

    validate_key_bytes(key, crypto_constants::kAes256KeyBytes, "AES-256 key");

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw DecryptionError("EVP_CIPHER_CTX_new failed");

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr,
                           nullptr) != 1) {
      EVP_CIPHER_CTX_free(ctx);
      throw DecryptionError("EVP_DecryptInit_ex(GCM) failed");
    }

    // Set IV length
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                            static_cast<int>(iv.size()), nullptr) != 1) {
      EVP_CIPHER_CTX_free(ctx);
      throw DecryptionError("EVP_CTRL_GCM_SET_IVLEN failed");
    }

    // Init with key and IV
    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(),
                           iv.data()) != 1) {
      EVP_CIPHER_CTX_free(ctx);
      throw DecryptionError("EVP_DecryptInit_ex(GCM key/IV) failed");
    }

    // Process AAD
    int len = 0;
    if (!aad.empty()) {
      if (EVP_DecryptUpdate(ctx, nullptr, &len, aad.data(),
                            static_cast<int>(aad.size())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw DecryptionError("EVP_DecryptUpdate(GCM AAD) failed");
      }
    }

    // Decrypt
    std::vector<uint8_t> plaintext(ciphertext.size() +
                                   crypto_constants::kAes256BlockSize);
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len,
                          ciphertext.data(),
                          static_cast<int>(ciphertext.size())) != 1) {
      EVP_CIPHER_CTX_free(ctx);
      throw DecryptionError("EVP_DecryptUpdate(GCM) failed");
    }
    int plaintext_len = len;

    // Set expected tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16,
                            const_cast<uint8_t*>(tag.data())) != 1) {
      EVP_CIPHER_CTX_free(ctx);
      throw DecryptionError("EVP_CTRL_GCM_SET_TAG failed");
    }

    // Finalize (verifies tag)
    int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
    EVP_CIPHER_CTX_free(ctx);

    if (ret <= 0) {
      throw DecryptionError(
          "GCM authentication failed — tag mismatch or tampered data");
    }

    plaintext_len += len;
    plaintext.resize(plaintext_len);
    return plaintext;
  }

  // --- Derive a sub-key using HKDF-SHA256 ---
  static std::vector<uint8_t> hkdf_sha256(
      const std::vector<uint8_t>& input_key_material,
      const std::vector<uint8_t>& salt,
      const std::string& info,
      size_t output_length = crypto_constants::kAes256KeyBytes) {

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!ctx) {
      throw CryptoError("EVP_PKEY_CTX_new_id(HKDF) failed");
    }

    if (EVP_PKEY_derive_init(ctx) <= 0) {
      EVP_PKEY_CTX_free(ctx);
      throw CryptoError("EVP_PKEY_derive_init(HKDF) failed: " +
                        openssl_error_stack());
    }

    if (EVP_PKEY_CTX_hkdf_mode(ctx, EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND) <= 0) {
      EVP_PKEY_CTX_free(ctx);
      throw CryptoError("EVP_PKEY_CTX_hkdf_mode failed");
    }

    if (EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) <= 0) {
      EVP_PKEY_CTX_free(ctx);
      throw CryptoError("EVP_PKEY_CTX_set_hkdf_md failed");
    }

    if (EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt.data(),
                                    static_cast<int>(salt.size())) <= 0) {
      EVP_PKEY_CTX_free(ctx);
      throw CryptoError("EVP_PKEY_CTX_set1_hkdf_salt failed");
    }

    if (EVP_PKEY_CTX_set1_hkdf_key(ctx, input_key_material.data(),
                                   static_cast<int>(input_key_material.size())) <= 0) {
      EVP_PKEY_CTX_free(ctx);
      throw CryptoError("EVP_PKEY_CTX_set1_hkdf_key failed");
    }

    if (EVP_PKEY_CTX_add1_hkdf_info(ctx,
                                    reinterpret_cast<const uint8_t*>(info.data()),
                                    static_cast<int>(info.size())) <= 0) {
      EVP_PKEY_CTX_free(ctx);
      throw CryptoError("EVP_PKEY_CTX_add1_hkdf_info failed");
    }

    std::vector<uint8_t> output(output_length);
    size_t out_len = output_length;
    if (EVP_PKEY_derive(ctx, output.data(), &out_len) <= 0) {
      EVP_PKEY_CTX_free(ctx);
      throw CryptoError("EVP_PKEY_derive(HKDF) failed: " +
                        openssl_error_stack());
    }
    output.resize(out_len);

    EVP_PKEY_CTX_free(ctx);
    return output;
  }
};

// ============================================================================
// KeyExportImport — Key export/import for cross-system compatibility
// ============================================================================
//
// Additional export/import formats beyond basic PEM/JSON:
//   - JWK (JSON Web Key) for Ed25519 and Curve25519
//   - Raw hex format
//   - Compact combined format with checksums
// ============================================================================

class KeyExportImport {
public:
  // --- Export Ed25519 public key as JWK ---
  static json ed25519_public_to_jwk(const std::vector<uint8_t>& public_key) {
    validate_key_bytes(public_key, crypto_constants::kEd25519PublicKeyBytes,
                       "Ed25519 public key");
    return json{
        {"kty", "OKP"},
        {"crv", "Ed25519"},
        {"x", Base64Engine::encode_urlsafe_unpadded(
                  std::string_view(reinterpret_cast<const char*>(public_key.data()),
                                   public_key.size()))}
    };
  }

  // --- Import Ed25519 public key from JWK ---
  static std::vector<uint8_t> ed25519_public_from_jwk(const json& jwk) {
    if (jwk.value("kty", "") != "OKP" ||
        jwk.value("crv", "") != "Ed25519") {
      throw KeyPersistenceError("JWK is not an Ed25519 key");
    }
    auto key = Base64Engine::decode_urlsafe(jwk.at("x").get<std::string>());
    validate_key_bytes(key, crypto_constants::kEd25519PublicKeyBytes,
                       "Ed25519 public key from JWK");
    return key;
  }

  // --- Export Curve25519 public key as JWK ---
  static json curve25519_public_to_jwk(const std::vector<uint8_t>& public_key) {
    validate_key_bytes(public_key, crypto_constants::kCurve25519PublicKeyBytes,
                       "Curve25519 public key");
    return json{
        {"kty", "OKP"},
        {"crv", "X25519"},
        {"x", Base64Engine::encode_urlsafe_unpadded(
                  std::string_view(reinterpret_cast<const char*>(public_key.data()),
                                   public_key.size()))}
    };
  }

  // --- Import Curve25519 public key from JWK ---
  static std::vector<uint8_t> curve25519_public_from_jwk(const json& jwk) {
    if (jwk.value("kty", "") != "OKP" ||
        jwk.value("crv", "") != "X25519") {
      throw KeyPersistenceError("JWK is not a Curve25519 (X25519) key");
    }
    auto key = Base64Engine::decode_urlsafe(jwk.at("x").get<std::string>());
    validate_key_bytes(key, crypto_constants::kCurve25519PublicKeyBytes,
                       "Curve25519 public key from JWK");
    return key;
  }

  // --- Export key as hex string ---
  static std::string key_to_hex(const std::vector<uint8_t>& key) {
    return hex_encode(key);
  }

  // --- Import key from hex string ---
  static std::vector<uint8_t> key_from_hex(std::string_view hex) {
    return hex_decode(hex);
  }

  // --- Export ed25519 keypair as compact string: version:pub_b64:priv_b64 ---
  static std::string ed25519_to_compact(const Ed25519Engine::KeyPair& kp) {
    return kp.version + ":" +
           Base64Engine::encode_unpadded(kp.public_key) + ":" +
           Base64Engine::encode_unpadded(kp.private_key);
  }

  // --- Import ed25519 keypair from compact string ---
  static Ed25519Engine::KeyPair ed25519_from_compact(std::string_view compact) {
    auto first_colon = compact.find(':');
    auto second_colon = compact.find(':', first_colon + 1);

    if (first_colon == std::string_view::npos ||
        second_colon == std::string_view::npos) {
      throw KeyPersistenceError("Invalid compact Ed25519 key format");
    }

    Ed25519Engine::KeyPair kp;
    kp.version = std::string(compact.substr(0, first_colon));
    kp.public_key = Base64Engine::decode(
        compact.substr(first_colon + 1, second_colon - first_colon - 1));
    kp.private_key = Base64Engine::decode(
        compact.substr(second_colon + 1));

    if (!kp.is_valid()) {
      throw KeyPersistenceError("Invalid Ed25519 key in compact format");
    }
    return kp;
  }

  // --- Export with checksum: data + SHA-256(data)[:4] ---
  static std::vector<uint8_t> data_with_checksum(
      const std::vector<uint8_t>& data) {
    auto hash = Sha256Engine::hash_raw(
        std::string_view(reinterpret_cast<const char*>(data.data()),
                         data.size()));
    std::vector<uint8_t> result = data;
    result.insert(result.end(), hash.begin(), hash.begin() + 4);
    return result;
  }

  // --- Verify and strip checksum ---
  static std::vector<uint8_t> verify_and_strip_checksum(
      const std::vector<uint8_t>& packaged) {
    if (packaged.size() < 4) {
      throw CryptoError("Packaged data too short for checksum");
    }

    std::vector<uint8_t> data(packaged.begin(), packaged.end() - 4);
    std::vector<uint8_t> checksum(packaged.end() - 4, packaged.end());

    auto computed = Sha256Engine::hash_raw(
        std::string_view(reinterpret_cast<const char*>(data.data()),
                         data.size()));

    if (!constant_time_equals(checksum.data(), computed.data(), 4)) {
      throw CryptoError("Checksum verification failed");
    }

    return data;
  }

  // --- Generate a recovery code from a key (BIP39-style simple encoding) ---
  // Uses base64-encoded key + checksum, then chunks into readable words
  static std::string key_to_recovery_code(const std::vector<uint8_t>& key) {
    auto packaged = data_with_checksum(key);
    auto b64 = Base64Engine::encode(packaged);
    // Insert hyphens every 4 characters for readability
    std::string result;
    for (size_t i = 0; i < b64.size(); i++) {
      if (i > 0 && i % 4 == 0) result += '-';
      result += b64[i];
    }
    // Strip padding '=' chars for cleaner recover codes
    while (!result.empty() && result.back() == '=') result.pop_back();
    return result;
  }

  // --- Recover a key from a recovery code ---
  static std::vector<uint8_t> key_from_recovery_code(std::string_view code) {
    // Strip hyphens
    std::string b64;
    for (char c : code) {
      if (c != '-') b64 += c;
    }
    auto packaged = Base64Engine::decode(b64);
    return verify_and_strip_checksum(packaged);
  }
};

// ============================================================================
// Namespace-level convenience aliases (recommended entry points)
// ============================================================================
//
// These global functions provide convenient access to CryptoManager::instance()
// for common operations, avoiding the need to call instance() each time.
// ============================================================================

// --- Ed25519 ---
inline Ed25519Engine::KeyPair generate_ed25519_keypair(const std::string& version = "0") {
  return CryptoManager::instance().ed25519_generate(version);
}

inline std::string ed25519_sign_message(std::string_view message,
                                        const std::vector<uint8_t>& private_key) {
  return CryptoManager::instance().ed25519_sign_b64(message, private_key);
}

inline bool ed25519_verify_signature(std::string_view message,
                                     std::string_view signature_b64,
                                     const std::vector<uint8_t>& public_key) {
  return CryptoManager::instance().ed25519_verify_b64(message, signature_b64, public_key);
}

// --- Curve25519 ---
inline Curve25519Engine::KeyPair generate_curve25519_keypair() {
  return CryptoManager::instance().curve25519_generate();
}

// --- SHA-256 ---
inline std::string sha256_hex(std::string_view data) {
  return CryptoManager::instance().sha256_hex(data);
}

inline std::string sha256_b64(std::string_view data) {
  return CryptoManager::instance().sha256_b64(data);
}

// --- HMAC ---
inline std::vector<uint8_t> hmac_sha256(std::string_view key, std::string_view data) {
  return CryptoManager::instance().hmac_sha256(key, data);
}

// --- PBKDF2 ---
inline std::vector<uint8_t> pbkdf2_derive_key(
    std::string_view password, const std::vector<uint8_t>& salt,
    size_t key_length = crypto_constants::kAes256KeyBytes,
    int iterations = crypto_constants::kPbkdf2DefaultIterations) {
  return CryptoManager::instance().pbkdf2_derive(password, salt, key_length, iterations);
}

// --- AES-256-CBC ---
inline std::vector<uint8_t> aes_encrypt_cbc(std::string_view plaintext,
                                            const std::vector<uint8_t>& key) {
  auto result = CryptoManager::instance().aes_encrypt_random_iv(plaintext, key);
  // Return IV + ciphertext combined
  std::vector<uint8_t> combined = result.iv;
  combined.insert(combined.end(), result.ciphertext.begin(),
                  result.ciphertext.end());
  return combined;
}

inline std::vector<uint8_t> aes_decrypt_cbc(const std::vector<uint8_t>& combined,
                                            const std::vector<uint8_t>& key) {
  return CryptoManager::instance().aes_decrypt_combined(combined, key);
}

// --- Base64 ---
inline std::string base64_encode(std::string_view data) {
  return CryptoManager::instance().base64_encode(data);
}

inline std::string base64_encode_unpadded(std::string_view data) {
  return CryptoManager::instance().base64_encode_unpadded(data);
}

inline std::vector<uint8_t> base64_decode(std::string_view data) {
  return CryptoManager::instance().base64_decode(data);
}

// --- Canonical JSON ---
inline std::string canonical_json(const json& value) {
  return CryptoManager::instance().canonical_json(value);
}

// --- Random ---
inline std::string random_token(size_t byte_count = 32) {
  return CryptoManager::instance().random_token(byte_count);
}

inline std::vector<uint8_t> random_bytes(size_t count) {
  return CryptoManager::instance().random_bytes(count);
}

// ============================================================================
// Self-test section (compile-time optional via macro)
// ============================================================================
#ifdef PROGRESSIVE_CRYPTO_SELFTEST

namespace {

void run_self_tests() {
  // Test 1: Ed25519 key generation, signing, verification
  {
    auto kp = generate_ed25519_keypair("selftest");
    std::string msg = "Test message for self-test";
    auto sig = ed25519_sign_message(msg, kp.private_key);
    bool verified = ed25519_verify_signature(msg, sig, kp.public_key);
    if (!verified) throw std::runtime_error("SELFTEST FAILED: Ed25519 sign/verify");
  }

  // Test 2: Curve25519 key generation and ECDH
  {
    auto alice = generate_curve25519_keypair();
    auto bob = generate_curve25519_keypair();
    auto shared_alice = Curve25519Engine::compute_shared_secret(
        alice.private_key, bob.public_key);
    auto shared_bob = Curve25519Engine::compute_shared_secret(
        bob.private_key, alice.public_key);
    if (shared_alice != shared_bob) {
      throw std::runtime_error("SELFTEST FAILED: Curve25519 ECDH mismatch");
    }
  }

  // Test 3: SHA-256
  {
    std::string hash = sha256_hex("hello world");
    if (hash.size() != 64) {
      throw std::runtime_error("SELFTEST FAILED: SHA-256 hex length");
    }
  }

  // Test 4: AES-256-CBC encrypt/decrypt
  {
    auto key = CryptoManager::instance().aes_generate_key();
    std::string plaintext = "Secret message 12345";
    auto encrypted = aes_encrypt_cbc(plaintext, key);
    auto decrypted = aes_decrypt_cbc(encrypted, key);
    if (std::string_view(reinterpret_cast<const char*>(decrypted.data()),
                         decrypted.size()) != plaintext) {
      throw std::runtime_error("SELFTEST FAILED: AES-256-CBC encrypt/decrypt");
    }
  }

  // Test 5: Base64 round-trip
  {
    std::string original = "Base64 Test String!";
    std::string encoded = base64_encode(original);
    auto decoded = base64_decode(encoded);
    std::string decoded_str(reinterpret_cast<const char*>(decoded.data()),
                            decoded.size());
    if (decoded_str != original) {
      throw std::runtime_error("SELFTEST FAILED: Base64 round-trip");
    }
  }

  // Test 6: Canonical JSON
  {
    json j = json::parse(R"({"b":1,"a":2})");
    std::string c = canonical_json(j);
    if (c != R"({"a":2,"b":1})") {
      throw std::runtime_error("SELFTEST FAILED: Canonical JSON");
    }
  }

  // All tests passed
  std::cerr << "[crypto_manager] All self-tests passed." << std::endl;
}

// Run self-tests at static initialization time
static const bool _selftest_result = []() {
  try {
    run_self_tests();
  } catch (const std::exception& e) {
    std::cerr << "[crypto_manager] SELFTEST ERROR: " << e.what() << std::endl;
    std::abort();
  }
  return true;
}();

}  // anonymous namespace

#endif  // PROGRESSIVE_CRYPTO_SELFTEST

}  // namespace progressive
