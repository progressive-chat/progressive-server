#include "../json.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <deque>
#include <functional>
#include <iomanip>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <queue>
#include <random>
#include <regex>
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

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

/* ============================================================================
 * progressive::auth - Login Token Manager
 *
 * Comprehensive Matrix authentication token lifecycle management:
 *
 *   Password Management:
 *     - bcrypt-style multi-round salted SHA-512 hashing
 *     - argon2id-emulated memory-hard password hashing
 *     - Password verification against stored hashes
 *     - Password strength validation
 *
 *   Token Generation & Lifecycle:
 *     - Login tokens (short-lived, single-use, Matrix SSO/login flow)
 *     - Access tokens (syt_ format, 14-day default TTL)
 *     - Refresh tokens (30-day TTL, rotation support)
 *     - Password reset tokens (time-limited, single-use)
 *     - Email verification tokens
 *
 *   Token Operations:
 *     - Verification with expiry checking
 *     - Revocation (single, per-user, per-device, bulk)
 *     - Rotation (token refresh with old token invalidation)
 *     - Device tracking (device_id association)
 *     - Session tracking (IP, user-agent, geo metadata)
 *     - Last-used timestamp updates with debouncing
 *
 *   Security:
 *     - Brute force protection (sliding-window rate limiting)
 *     - Account lockout after threshold failures
 *     - IP-based tracking and anomaly detection
 *     - Concurrent login throttling
 *     - Graduated backoff on repeated failures
 *
 *   Admin Functions:
 *     - Token listing by user, device, or global scope
 *     - Bulk revocation for users/devices
 *     - Lockout status inspection and override
 *     - Rate-limit status inspection
 *
 * All state held in memory with shared_mutex for reader-writer safety.
 * ========================================================================== */

namespace progressive {
namespace auth {

using json = nlohmann::json;

/* ============================================================================
 * Internal Constants
 * ========================================================================== */

// --- Token Format & Length ---
static constexpr size_t   ACCESS_TOKEN_RAW_BYTES   = 32;
static constexpr size_t   REFRESH_TOKEN_RAW_BYTES  = 48;
static constexpr size_t   LOGIN_TOKEN_RAW_BYTES    = 32;
static constexpr size_t   PASSWORD_RESET_TOKEN_LEN  = 64;
static constexpr size_t   EMAIL_VERIFY_TOKEN_LEN    = 48;
static constexpr size_t   TOKEN_PREFIX_LEN          = 4;     // "syt_"
static constexpr size_t   DEVICE_ID_LENGTH          = 10;

// --- Token TTLs (seconds) ---
static constexpr int64_t  ACCESS_TOKEN_TTL_SEC      = 1209600L;   // 14 days
static constexpr int64_t  REFRESH_TOKEN_TTL_SEC      = 2592000L;   // 30 days
static constexpr int64_t  LOGIN_TOKEN_TTL_SEC        = 3600L;      // 1 hour
static constexpr int64_t  PASSWORD_RESET_TTL_SEC     = 3600L;      // 1 hour
static constexpr int64_t  EMAIL_VERIFY_TTL_SEC       = 86400L;     // 24 hours
static constexpr int64_t  ABSOLUTE_MAX_TOKEN_TTL     = 31536000L;  // 1 year cap

// --- Password Hashing ---
static constexpr int      BCRYPT_ROUNDS_DEFAULT     = 12;
static constexpr int      BCRYPT_ROUNDS_MIN         = 4;
static constexpr int      BCRYPT_ROUNDS_MAX         = 31;
static constexpr size_t   BCRYPT_SALT_BYTES         = 16;
static constexpr size_t   BCRYPT_HASH_OUTPUT_BYTES  = 32;

// --- Argon2id Emulation ---
static constexpr size_t   ARGON2_SALT_BYTES         = 16;
static constexpr size_t   ARGON2_HASH_LEN            = 32;
static constexpr int      ARGON2_TIME_COST           = 3;
static constexpr int      ARGON2_MEM_COST_KB         = 65536;   // 64 MB
static constexpr int      ARGON2_PARALLELISM         = 1;
static constexpr int      ARGON2_INNER_ITERATIONS    = 4096;

// --- Rate Limiting ---
static constexpr int64_t  RATE_LIMIT_WINDOW_SEC      = 300;      // 5 minutes
static constexpr int      RATE_LIMIT_MAX_LOGIN       = 30;
static constexpr int      RATE_LIMIT_MAX_FAILED      = 10;
static constexpr int      RATE_LIMIT_MAX_PW_RESET    = 5;
static constexpr int      RATE_LIMIT_MAX_EMAIL_VERIFY = 10;

// --- Account Lockout ---
static constexpr int      LOCKOUT_THRESHOLD_FAILURES  = 10;
static constexpr int64_t  LOCKOUT_DURATION_SEC        = 900;     // 15 minutes
static constexpr int64_t  LOCKOUT_ESCALATION_MULT     = 2;       // doubles each time
static constexpr int64_t  LOCKOUT_MAX_DURATION_SEC    = 86400;   // 24 hours max

// --- Token Rotation ---
static constexpr int64_t  TOKEN_ROTATION_GRACE_SEC    = 300;     // 5 min grace for old token after rotation

// --- Last-Used Debounce ---
static constexpr int64_t  LAST_USED_DEBOUNCE_SEC      = 60;      // update at most every 60s

// --- Cleanup ---
static constexpr int64_t  TOKEN_CLEANUP_INTERVAL_SEC  = 3600;    // hourly expired token sweep
static constexpr int64_t  RATELIMIT_CLEANUP_INTERVAL  = 600;     // 10-minute rate limit entry sweep

/* ============================================================================
 * Internal Structures
 * ========================================================================== */

/// Hashed password representation with algorithm identifier
struct HashedPassword {
  enum class Algorithm : uint8_t {
    BCRYPT_SHA512  = 0x01,
    ARGON2ID_EMU   = 0x02,
    SHA256_SIMPLE  = 0x03,  // legacy
  };

  Algorithm  algo;
  int        rounds;         // for bcrypt
  int        time_cost;      // for argon2
  int        mem_cost_kb;    // for argon2
  int        parallelism;    // for argon2
  std::string salt;          // raw salt bytes
  std::string hash;          // raw hash output
  std::string serialized;    // stored format: "$algo$params$salt$hash"
};

/// An access token record
struct AccessTokenRecord {
  std::string token;           // full syt_ token
  std::string token_hash;      // SHA-256 of token for lookups
  std::string user_id;
  std::string device_id;
  std::string refresh_token;
  std::string refresh_token_hash;
  int64_t     created_at_ms;
  int64_t     expires_at_ms;
  int64_t     last_used_ms;
  int64_t     rotated_at_ms;       // when this token was rotated out
  std::string rotated_by_token;    // token hash that replaced this one
  bool        is_revoked;
  int64_t     revoked_at_ms;
  std::string revoked_reason;
  // Session metadata
  std::string ip_address;
  std::string user_agent;
  std::string initial_ip;
  std::string initial_user_agent;
};

/// A login token (used in Matrix SSO/login token flow)
struct LoginTokenRecord {
  std::string token;
  std::string token_hash;
  std::string user_id;
  int64_t     created_at_ms;
  int64_t     expires_at_ms;
  bool        used;
  int64_t     used_at_ms;
  bool        is_revoked;
};

/// A password reset token
struct PasswordResetToken {
  std::string token;
  std::string token_hash;
  std::string user_id;
  int64_t     created_at_ms;
  int64_t     expires_at_ms;
  bool        used;
  int64_t     used_at_ms;
};

/// An email verification token
struct EmailVerificationToken {
  std::string token;
  std::string token_hash;
  std::string email;
  std::string user_id;          // may be empty for pre-registration
  std::string client_secret;
  int         send_attempt;
  int64_t     created_at_ms;
  int64_t     expires_at_ms;
  bool        used;
  int64_t     used_at_ms;
  bool        validated;
  int64_t     validated_at_ms;
};

/// Rate-limit tracking entry
struct RateLimitEntry {
  std::string key;              // "login:<user>", "login:<ip>", "failed:<user>", etc.
  int64_t     timestamp_ms;
};

/// Account lockout record
struct LockoutRecord {
  std::string user_id;
  int         consecutive_failures;
  int         total_lockouts;
  int64_t     first_failure_ms;
  int64_t     last_failure_ms;
  int64_t     locked_until_ms;
  int64_t     current_lockout_duration_sec;
};

/// Session tracking aggregated data
struct SessionStats {
  std::string user_id;
  int         active_sessions;
  int         active_devices;
  std::vector<std::string> recent_ips;
  int64_t     last_active_ms;
};

/// IP tracking entry for anomaly detection
struct IPTrackingEntry {
  std::string user_id;
  std::string ip_address;
  int64_t     first_seen_ms;
  int64_t     last_seen_ms;
  int         count;
};

/// Authentication event for audit trail
struct AuthAuditEntry {
  int64_t     timestamp_ms;
  std::string event_type;       // "login", "logout", "token_refresh", "revoke", etc.
  std::string user_id;
  std::string device_id;
  std::string ip_address;
  std::string detail;
};

/* ============================================================================
 * Global State (all guarded by mutexes)
 * ========================================================================== */

// --- Password hashes: user_id -> HashedPassword ---
static std::shared_mutex g_password_mutex;
static std::unordered_map<std::string, HashedPassword> g_passwords;

// --- Access tokens ---
static std::shared_mutex g_access_token_mutex;
static std::unordered_map<std::string /*token_hash*/, AccessTokenRecord> g_access_tokens;
static std::unordered_map<std::string /*user_id*/,
    std::unordered_set<std::string /*token_hash*/>> g_access_tokens_by_user;
static std::unordered_map<std::string /*device_id*/,
    std::unordered_set<std::string /*token_hash*/>> g_access_tokens_by_device;
static std::unordered_map<std::string /*refresh_token_hash*/,
    std::string /*access_token_hash*/> g_refresh_to_access;

// --- Login tokens ---
static std::shared_mutex g_login_token_mutex;
static std::unordered_map<std::string /*token_hash*/, LoginTokenRecord> g_login_tokens;

// --- Password reset tokens ---
static std::shared_mutex g_pw_reset_mutex;
static std::unordered_map<std::string /*token_hash*/, PasswordResetToken> g_pw_reset_tokens;

// --- Email verification tokens ---
static std::shared_mutex g_email_verify_mutex;
static std::unordered_map<std::string /*token_hash*/, EmailVerificationToken> g_email_verify_tokens;

// --- Rate limiting ---
static std::shared_mutex g_ratelimit_mutex;
static std::deque<RateLimitEntry> g_ratelimit_entries;

// --- Account lockouts ---
static std::shared_mutex g_lockout_mutex;
static std::unordered_map<std::string, LockoutRecord> g_lockouts;

// --- IP tracking ---
static std::shared_mutex g_ip_track_mutex;
static std::unordered_map<std::string /*user_id*/,
    std::vector<IPTrackingEntry>> g_ip_tracking;

// --- Audit log (ring buffer) ---
static std::shared_mutex g_audit_mutex;
static constexpr size_t AUDIT_RING_SIZE = 10000;
static std::deque<AuthAuditEntry> g_audit_log;
static size_t g_audit_sequence = 0;

// --- Random generators (thread-local would be better, but per-instance is fine) ---
static std::mutex g_rng_mutex;
static std::mt19937_64 g_rng(std::random_device{}());

// --- Cleanup tracking ---
static std::atomic<int64_t> g_last_token_cleanup_ms{0};
static std::atomic<int64_t> g_last_ratelimit_cleanup_ms{0};

/* ============================================================================
 * Internal Helpers — Cryptography
 * ========================================================================== */

/// Generate cryptographically secure random bytes
static std::string secure_random_bytes(size_t n) {
  std::string buf(n, '\0');
  if (RAND_bytes(reinterpret_cast<unsigned char*>(buf.data()), static_cast<int>(n)) != 1) {
    // Fallback to mt19937 if OpenSSL RAND fails (unlikely)
    std::lock_guard<std::mutex> lock(g_rng_mutex);
    std::uniform_int_distribution<int> dist(0, 255);
    for (size_t i = 0; i < n; ++i) buf[i] = static_cast<char>(dist(g_rng));
  }
  return buf;
}

/// SHA-256 digest of input, returns raw bytes
static std::string sha256_raw(std::string_view input) {
  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256(reinterpret_cast<const unsigned char*>(input.data()), input.size(), hash);
  return std::string(reinterpret_cast<char*>(hash), SHA256_DIGEST_LENGTH);
}

/// SHA-512 digest of input, returns raw bytes
static std::string sha512_raw(std::string_view input) {
  unsigned char hash[SHA512_DIGEST_LENGTH];
  SHA512(reinterpret_cast<const unsigned char*>(input.data()), input.size(), hash);
  return std::string(reinterpret_cast<char*>(hash), SHA512_DIGEST_LENGTH);
}

/// HMAC-SHA256
static std::string hmac_sha256(std::string_view key, std::string_view data) {
  unsigned char result[EVP_MAX_MD_SIZE];
  unsigned int result_len = 0;
  HMAC(EVP_sha256(),
       key.data(), static_cast<int>(key.size()),
       reinterpret_cast<const unsigned char*>(data.data()), data.size(),
       result, &result_len);
  return std::string(reinterpret_cast<char*>(result), result_len);
}

/// PBKDF2-HMAC-SHA512 for key stretching
static std::string pbkdf2_sha512(std::string_view password, std::string_view salt,
                                  int iterations, size_t key_len) {
  std::string key(key_len, '\0');
  PKCS5_PBKDF2_HMAC(password.data(), static_cast<int>(password.size()),
                     reinterpret_cast<const unsigned char*>(salt.data()),
                     static_cast<int>(salt.size()),
                     iterations,
                     EVP_sha512(),
                     static_cast<int>(key_len),
                     reinterpret_cast<unsigned char*>(key.data()));
  return key;
}

/// Base64 encode (URL-safe, no padding) — inline since util may not be available
static std::string base64url_encode(std::string_view data) {
  static const char kChars[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  std::string out;
  out.reserve(((data.size() + 2) / 3) * 4);
  size_t i = 0;
  unsigned char buf3[3];
  while (i < data.size()) {
    int len = 0;
    uint32_t val = 0;
    for (int j = 0; j < 3; ++j) {
      if (i < data.size()) {
        buf3[j] = static_cast<unsigned char>(data[i++]);
        len++;
      } else {
        buf3[j] = 0;
      }
      val = (val << 8) | buf3[j];
    }
    if (len > 0) {
      for (int j = 0; j < len + 1; ++j) {
        out += kChars[(val >> ((3 - j) * 6)) & 0x3F];
      }
    }
  }
  // No padding in URL-safe mode
  return out;
}

/// Base64 decode (URL-safe, no padding)
static std::optional<std::string> base64url_decode(std::string_view input) {
  static const int kDecodeTable[256] = {
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,  // '+'=62, '/'=63 but we use '-','_'
    52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
    15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,  // '-' = 62
    -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
    41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,  // '_' = 63
    // rest are -1
  };
  // Build proper table
  int table[256];
  for (int i = 0; i < 256; ++i) table[i] = -1;
  table['A']=0; table['B']=1; table['C']=2; table['D']=3; table['E']=4;
  table['F']=5; table['G']=6; table['H']=7; table['I']=8; table['J']=9;
  table['K']=10; table['L']=11; table['M']=12; table['N']=13; table['O']=14;
  table['P']=15; table['Q']=16; table['R']=17; table['S']=18; table['T']=19;
  table['U']=20; table['V']=21; table['W']=22; table['X']=23; table['Y']=24;
  table['Z']=25; table['a']=26; table['b']=27; table['c']=28; table['d']=29;
  table['e']=30; table['f']=31; table['g']=32; table['h']=33; table['i']=34;
  table['j']=35; table['k']=36; table['l']=37; table['m']=38; table['n']=39;
  table['o']=40; table['p']=41; table['q']=42; table['r']=43; table['s']=44;
  table['t']=45; table['u']=46; table['v']=47; table['w']=48; table['x']=49;
  table['y']=50; table['z']=51; table['0']=52; table['1']=53; table['2']=54;
  table['3']=55; table['4']=56; table['5']=57; table['6']=58; table['7']=59;
  table['8']=60; table['9']=61; table['-']=62; table['_']=63;

  std::string out;
  int val = 0, valb = -8;
  for (unsigned char c : input) {
    int idx = table[c];
    if (idx == -1) continue;
    val = (val << 6) + idx;
    valb += 6;
    if (valb >= 0) {
      out += static_cast<char>((val >> valb) & 0xFF);
      valb -= 8;
    }
  }
  return out;
}

/// Hex encode raw bytes
static std::string hex_encode(std::string_view data) {
  std::ostringstream oss;
  oss << std::hex << std::setfill('0');
  for (unsigned char c : data) {
    oss << std::setw(2) << static_cast<int>(c);
  }
  return oss.str();
}

/// Hex decode
static std::optional<std::string> hex_decode(std::string_view hex) {
  if (hex.size() % 2 != 0) return std::nullopt;
  std::string out;
  out.reserve(hex.size() / 2);
  for (size_t i = 0; i < hex.size(); i += 2) {
    unsigned int byte;
    std::stringstream ss;
    ss << std::hex << hex.substr(i, 2);
    ss >> byte;
    if (ss.fail()) return std::nullopt;
    out += static_cast<char>(byte);
  }
  return out;
}

/* ============================================================================
 * Internal Helpers — Time
 * ========================================================================== */

/// Current time in milliseconds since epoch
static int64_t now_ms() {
  auto now = std::chrono::system_clock::now();
  return std::chrono::duration_cast<std::chrono::milliseconds>(
      now.time_since_epoch()).count();
}

/// Current time in seconds since epoch
static int64_t now_sec() {
  return now_ms() / 1000;
}

/* ============================================================================
 * Internal Helpers — Token Generation
 * ========================================================================== */

/// Generate a syt_ format access token:
/// "syt_" + base64url(server_seed || random || timestamp || user_hash || counter)
static std::string generate_syt_token(std::string_view user_id,
                                       std::string_view device_id) {
  static std::atomic<uint64_t> g_token_counter{0};
  uint64_t counter = g_token_counter.fetch_add(1, std::memory_order_relaxed);

  // Build token payload
  std::string payload;
  payload.reserve(64);

  // 8 bytes: server random seed
  std::string seed = secure_random_bytes(8);
  payload += seed;

  // 8 bytes: random nonce
  std::string nonce = secure_random_bytes(8);
  payload += nonce;

  // 8 bytes: timestamp (big-endian)
  uint64_t ts = static_cast<uint64_t>(now_ms());
  for (int i = 7; i >= 0; --i)
    payload += static_cast<char>((ts >> (i * 8)) & 0xFF);

  // 8 bytes: user hash prefix
  std::string user_hash = sha256_raw(user_id);
  payload += user_hash.substr(0, 8);

  // 8 bytes: counter
  for (int i = 7; i >= 0; --i)
    payload += static_cast<char>((counter >> (i * 8)) & 0xFF);

  // Sign with HMAC
  std::string mac = hmac_sha256(seed, payload);
  payload += mac.substr(0, 8);  // truncate MAC to 8 bytes

  return "syt_" + base64url_encode(payload);
}

/// Generate a refresh token
static std::string generate_refresh_token() {
  // Format: "rft_" + base64url(48 random bytes)
  return "rft_" + base64url_encode(secure_random_bytes(REFRESH_TOKEN_RAW_BYTES));
}

/// Generate a login token (for Matrix login token flow)
static std::string generate_login_token() {
  return "mlt_" + base64url_encode(secure_random_bytes(LOGIN_TOKEN_RAW_BYTES));
}

/// Generate a password reset token
static std::string generate_password_reset_token() {
  return "prt_" + base64url_encode(secure_random_bytes(PASSWORD_RESET_TOKEN_LEN / 4 * 3));
  // base64 expands ~4/3, so 48 random bytes → ~64 chars
}

/// Generate an email verification token
static std::string generate_email_verification_token() {
  return "evt_" + base64url_encode(secure_random_bytes(EMAIL_VERIFY_TOKEN_LEN));
}

/// Token-based lookup using SHA-256 of the token
static std::string hash_token(std::string_view token) {
  return hex_encode(sha256_raw(token));
}

/* ============================================================================
 * Internal Helpers — Rate Limiting
 * ========================================================================== */

/// Prune expired rate-limit entries from the deque
static void prune_ratelimit_entries(int64_t window_ms) {
  int64_t cutoff = now_ms() - window_ms;
  while (!g_ratelimit_entries.empty() && g_ratelimit_entries.front().timestamp_ms < cutoff) {
    g_ratelimit_entries.pop_front();
  }
}

/// Count rate-limit entries for a given key within the window
static int count_ratelimit_entries(const std::string& key, int64_t window_ms) {
  int64_t cutoff = now_ms() - window_ms;
  int count = 0;
  // Scan backwards since entries are ordered by time
  for (auto it = g_ratelimit_entries.rbegin();
       it != g_ratelimit_entries.rend() && it->timestamp_ms >= cutoff;
       ++it) {
    if (it->key == key) ++count;
  }
  return count;
}

/// Check if a rate-limited action is allowed. Returns true if allowed.
static bool check_rate_limit(const std::string& key, int max_allowed, int64_t window_sec) {
  std::unique_lock<std::shared_mutex> lock(g_ratelimit_mutex);

  int64_t window_ms = window_sec * 1000LL;
  prune_ratelimit_entries(window_ms);
  int count = count_ratelimit_entries(key, window_ms);

  if (count >= max_allowed) return false;

  // Record this attempt
  g_ratelimit_entries.push_back({key, now_ms()});
  return true;
}

/// Record a rate-limit entry without checking (for auditing)
static void record_ratelimit_entry(const std::string& key) {
  std::unique_lock<std::shared_mutex> lock(g_ratelimit_mutex);
  g_ratelimit_entries.push_back({key, now_ms()});
}

/// Periodic cleanup of rate-limit entries
static void maybe_cleanup_ratelimits() {
  int64_t last = g_last_ratelimit_cleanup_ms.load(std::memory_order_relaxed);
  int64_t now = now_ms();
  if (now - last < RATELIMIT_CLEANUP_INTERVAL * 1000LL) return;

  // Try to CAS — only one thread does cleanup
  if (!g_last_ratelimit_cleanup_ms.compare_exchange_strong(last, now,
        std::memory_order_relaxed)) {
    return;
  }

  std::unique_lock<std::shared_mutex> lock(g_ratelimit_mutex);
  int64_t window_ms = RATE_LIMIT_WINDOW_SEC * 1000LL * 2; // generous window
  prune_ratelimit_entries(window_ms);
}

/* ============================================================================
 * Internal Helpers — Account Lockout
 * ========================================================================== */

/// Apply graduated lockout: each lockout doubles the duration, up to a max
static int64_t compute_lockout_duration(int total_lockouts) {
  int64_t dur = LOCKOUT_DURATION_SEC;
  for (int i = 1; i < total_lockouts; ++i) {
    dur *= LOCKOUT_ESCALATION_MULT;
    if (dur > LOCKOUT_MAX_DURATION_SEC) return LOCKOUT_MAX_DURATION_SEC;
  }
  return dur;
}

/// Record a failed login attempt and handle lockout logic
/// Returns true if the account is currently locked out
static bool record_failed_login(const std::string& user_id) {
  std::unique_lock<std::shared_mutex> lock(g_lockout_mutex);
  auto& rec = g_lockouts[user_id];
  rec.user_id = user_id;
  int64_t now = now_ms();

  // Check if currently locked out
  if (rec.locked_until_ms > now) {
    // Still locked — don't increment, just return true
    return true;
  }

  // Not currently locked — record failure
  if (rec.consecutive_failures == 0) {
    rec.first_failure_ms = now;
  }
  rec.consecutive_failures++;
  rec.last_failure_ms = now;

  // Check if threshold crossed
  if (rec.consecutive_failures >= LOCKOUT_THRESHOLD_FAILURES) {
    rec.total_lockouts++;
    rec.current_lockout_duration_sec = compute_lockout_duration(rec.total_lockouts);
    rec.locked_until_ms = now + rec.current_lockout_duration_sec * 1000LL;
    return true;
  }

  return false;
}

/// Clear lockout on successful login
static void clear_lockout(const std::string& user_id) {
  std::unique_lock<std::shared_mutex> lock(g_lockout_mutex);
  auto it = g_lockouts.find(user_id);
  if (it != g_lockouts.end()) {
    it->second.consecutive_failures = 0;
    it->second.first_failure_ms = 0;
    it->second.locked_until_ms = 0;
  }
}

/// Check if a user is locked out without modifying state
static bool is_locked_out(const std::string& user_id) {
  std::shared_lock<std::shared_mutex> lock(g_lockout_mutex);
  auto it = g_lockouts.find(user_id);
  if (it == g_lockouts.end()) return false;
  return it->second.locked_until_ms > now_ms();
}

/// Get remaining lockout time in seconds, 0 if not locked
static int64_t lockout_remaining_sec(const std::string& user_id) {
  std::shared_lock<std::shared_mutex> lock(g_lockout_mutex);
  auto it = g_lockouts.find(user_id);
  if (it == g_lockouts.end()) return 0;
  int64_t rem = it->second.locked_until_ms - now_ms();
  return rem > 0 ? (rem / 1000) : 0;
}

/* ============================================================================
 * Internal Helpers — Audit Logging
 * ========================================================================== */

static void audit_log(const std::string& event_type, const std::string& user_id,
                      const std::string& device_id, const std::string& ip,
                      const std::string& detail) {
  std::unique_lock<std::shared_mutex> lock(g_audit_mutex);
  g_audit_log.push_back({now_ms(), event_type, user_id, device_id, ip, detail});
  if (g_audit_log.size() > AUDIT_RING_SIZE) {
    g_audit_log.pop_front();
  }
  g_audit_sequence++;
}

/* ============================================================================
 * Internal Helpers — IP Tracking
 * ========================================================================== */

static void track_ip(const std::string& user_id, const std::string& ip_address) {
  if (ip_address.empty()) return;
  std::unique_lock<std::shared_mutex> lock(g_ip_track_mutex);
  auto& entries = g_ip_tracking[user_id];
  int64_t now = now_ms();

  // Look for existing entry for this IP
  for (auto& e : entries) {
    if (e.ip_address == ip_address) {
      e.last_seen_ms = now;
      e.count++;
      return;
    }
  }

  // New IP
  entries.push_back({user_id, ip_address, now, now, 1});

  // Keep at most 50 IPs per user
  if (entries.size() > 50) {
    // Remove least recently seen
    auto oldest = std::min_element(entries.begin(), entries.end(),
        [](const IPTrackingEntry& a, const IPTrackingEntry& b) {
          return a.last_seen_ms < b.last_seen_ms;
        });
    entries.erase(oldest);
  }
}

/// Check for suspicious IP changes — many different IPs in short time
static bool detect_anomalous_ip_activity(const std::string& user_id,
                                          const std::string& current_ip) {
  if (current_ip.empty()) return false;
  std::shared_lock<std::shared_mutex> lock(g_ip_track_mutex);
  auto it = g_ip_tracking.find(user_id);
  if (it == g_ip_tracking.end()) return false;

  const auto& entries = it->second;
  if (entries.size() < 5) return false;

  int64_t now = now_ms();
  int64_t one_hour = 3600000LL;
  int recent_distinct = 0;
  for (const auto& e : entries) {
    if (now - e.first_seen_ms < one_hour) {
      recent_distinct++;
    }
  }
  // Flag if >8 different IPs in an hour
  return recent_distinct > 8;
}

/* ============================================================================
 * Password Hashing — bcrypt-style Multi-Round Salted SHA-512
 * ============================================================================
 *
 * Format:  $2b$<rounds>$<salt-base64>$<hash-base64>
 *
 * Algorithm:
 *   1. Generate random salt (16 bytes)
 *   2. PBKDF2-HMAC-SHA512 with the given rounds
 *   3. XOR-fold to 32 bytes for bcrypt compatibility
 */

static HashedPassword hash_password_bcrypt(std::string_view password, int rounds) {
  if (rounds < BCRYPT_ROUNDS_MIN) rounds = BCRYPT_ROUNDS_MIN;
  if (rounds > BCRYPT_ROUNDS_MAX) rounds = BCRYPT_ROUNDS_MAX;

  HashedPassword hp;
  hp.algo = HashedPassword::Algorithm::BCRYPT_SHA512;
  hp.rounds = rounds;
  hp.salt = secure_random_bytes(BCRYPT_SALT_BYTES);

  // Use PBKDF2 with 2^rounds iterations
  int iterations = 1 << rounds;
  std::string derived = pbkdf2_sha512(password, hp.salt, iterations, 64);

  // XOR-fold 64 bytes → 32 bytes
  hp.hash.resize(BCRYPT_HASH_OUTPUT_BYTES);
  for (size_t i = 0; i < BCRYPT_HASH_OUTPUT_BYTES; ++i) {
    hp.hash[i] = derived[i] ^ derived[i + BCRYPT_HASH_OUTPUT_BYTES];
  }

  // Serialize: $2b$<rounds>$<salt-b64>$<hash-b64>
  std::ostringstream oss;
  oss << "$2b$" << std::setfill('0') << std::setw(2) << rounds << "$";
  oss << base64url_encode(hp.salt) << "$";
  oss << base64url_encode(hp.hash);
  hp.serialized = oss.str();

  return hp;
}

/* ============================================================================
 * Password Hashing — Argon2id Emulation
 * ============================================================================
 *
 * Emulates Argon2id memory-hardness using iterative PBKDF2 + SHA-256 mixing:
 *
 *   1. Generate salt (16 bytes)
 *   2. Derive initial block via PBKDF2-HMAC-SHA512(password, salt, 1, block_size)
 *   3. Fill memory blocks using H(prev_block || counter)
 *   4. Perform t_cost passes of mixing
 *   5. Extract final hash
 *
 * Format: $argon2id$v=19$m=<mem>,t=<time>,p=<parallelism>$<salt-b64>$<hash-b64>
 */

static HashedPassword hash_password_argon2id(std::string_view password,
                                              int time_cost, int mem_cost_kb,
                                              int parallelism) {
  HashedPassword hp;
  hp.algo = HashedPassword::Algorithm::ARGON2ID_EMU;
  hp.time_cost = time_cost;
  hp.mem_cost_kb = mem_cost_kb;
  hp.parallelism = parallelism;
  hp.salt = secure_random_bytes(ARGON2_SALT_BYTES);

  // Memory block size: 1 KB per block
  size_t block_size = 1024;
  size_t num_blocks = static_cast<size_t>(mem_cost_kb);

  // Step 1: Derive initial seed block
  std::string seed = pbkdf2_sha512(password, hp.salt, 1, block_size);

  // Step 2: Fill memory
  std::vector<std::string> memory;
  memory.reserve(num_blocks);
  memory.push_back(seed);

  for (size_t i = 1; i < num_blocks; ++i) {
    // Build input: prev_block || counter
    std::string input = memory[i - 1];
    // Append counter in big-endian
    for (int j = 3; j >= 0; --j) input += static_cast<char>((i >> (j * 8)) & 0xFF);

    // Hash with SHA-256 for speed, mix with salt every 64 blocks
    std::string block = sha256_raw(input);
    if (i % 64 == 0) {
      block = sha256_raw(block + hp.salt);
    }
    // Pad/truncate to block_size
    if (block.size() < block_size) {
      // Expand by repeated hashing
      std::string expanded = block;
      while (expanded.size() < block_size) {
        expanded += sha256_raw(expanded);
      }
      block = expanded.substr(0, block_size);
    }
    memory.push_back(block);
  }

  // Step 3: Mixing passes (time_cost)
  for (int pass = 0; pass < time_cost; ++pass) {
    for (size_t i = 0; i < num_blocks; ++i) {
      // Mix with a pseudo-randomly selected previous block
      std::string block_hash = sha256_raw(memory[i]);
      uint64_t ref_idx = 0;
      for (size_t j = 0; j < 8 && j < block_hash.size(); ++j) {
        ref_idx = (ref_idx << 8) | static_cast<unsigned char>(block_hash[j]);
      }
      ref_idx %= num_blocks;

      // Mix: H(current || reference || pass_num || salt)
      std::string mix_input = memory[i] + memory[ref_idx];
      mix_input += static_cast<char>(pass);
      mix_input += hp.salt;
      memory[i] = sha256_raw(mix_input);
      if (memory[i].size() < block_size) {
        std::string expanded = memory[i];
        while (expanded.size() < block_size) {
          expanded += sha256_raw(expanded);
        }
        memory[i] = expanded.substr(0, block_size);
      }
    }
  }

  // Step 4: Extract final hash from the first block
  hp.hash = sha256_raw(memory[0] + hp.salt);
  hp.hash = hp.hash.substr(0, ARGON2_HASH_LEN);

  // Serialize
  std::ostringstream oss;
  oss << "$argon2id$v=19$m=" << mem_cost_kb
      << ",t=" << time_cost
      << ",p=" << parallelism << "$";
  oss << base64url_encode(hp.salt) << "$";
  oss << base64url_encode(hp.hash);
  hp.serialized = oss.str();

  return hp;
}

/* ============================================================================
 * Password Hashing — Legacy SHA-256 (for migration)
 * ============================================================================
 *
 * Format: $sha256$<salt-b64>$<hash-b64>
 */

static HashedPassword hash_password_sha256_legacy(std::string_view password) {
  HashedPassword hp;
  hp.algo = HashedPassword::Algorithm::SHA256_SIMPLE;
  hp.rounds = 0;
  hp.salt = secure_random_bytes(BCRYPT_SALT_BYTES);
  hp.hash = sha256_raw(std::string(password) + hp.salt);

  std::ostringstream oss;
  oss << "$sha256$" << base64url_encode(hp.salt) << "$" << base64url_encode(hp.hash);
  hp.serialized = oss.str();

  return hp;
}

/* ============================================================================
 * Password Hashing — Deserialization & Verification
 * ========================================================================== */

/// Parse a serialized password hash
static std::optional<HashedPassword> deserialize_password_hash(
    std::string_view serialized) {
  HashedPassword hp;
  hp.serialized = std::string(serialized);

  // Split by '$'
  std::vector<std::string_view> parts;
  size_t pos = 0;
  if (!serialized.empty() && serialized[0] == '$') pos = 1;

  size_t next;
  while ((next = serialized.find('$', pos)) != std::string_view::npos) {
    parts.push_back(serialized.substr(pos, next - pos));
    pos = next + 1;
  }
  if (pos < serialized.size()) {
    parts.push_back(serialized.substr(pos));
  }

  if (parts.size() < 2) return std::nullopt;

  std::string_view algo_str = parts[0];

  if (algo_str == "2b") {
    // $2b$<rounds>$<salt>$<hash>
    if (parts.size() < 4) return std::nullopt;
    hp.algo = HashedPassword::Algorithm::BCRYPT_SHA512;
    hp.rounds = std::stoi(std::string(parts[1]));
    auto salt = base64url_decode(parts[2]);
    auto hash = base64url_decode(parts[3]);
    if (!salt || !hash) return std::nullopt;
    hp.salt = *salt;
    hp.hash = *hash;
    return hp;

  } else if (algo_str == "argon2id") {
    // $argon2id$v=19$m=<mem>,t=<time>,p=<p>$<salt>$<hash>
    if (parts.size() < 4) return std::nullopt;

    // Parse parameters from parts[1]: "v=19" — skip version
    // parts[2]: "m=<mem>,t=<time>,p=<p>"
    std::string params_str(parts[2]);
    hp.algo = HashedPassword::Algorithm::ARGON2ID_EMU;
    hp.time_cost = ARGON2_TIME_COST;
    hp.mem_cost_kb = ARGON2_MEM_COST_KB;
    hp.parallelism = ARGON2_PARALLELISM;

    // Parse comma-separated key=value
    size_t start = 0;
    while (start < params_str.size()) {
      size_t eq = params_str.find('=', start);
      if (eq == std::string::npos) break;
      size_t comma = params_str.find(',', eq);
      if (comma == std::string::npos) comma = params_str.size();
      std::string key = params_str.substr(start, eq - start);
      std::string val = params_str.substr(eq + 1, comma - eq - 1);
      if (key == "m") hp.mem_cost_kb = std::stoi(val);
      else if (key == "t") hp.time_cost = std::stoi(val);
      else if (key == "p") hp.parallelism = std::stoi(val);
      start = comma + 1;
    }

    auto salt = base64url_decode(parts[parts.size() - 2]);
    auto hash = base64url_decode(parts[parts.size() - 1]);
    if (!salt || !hash) return std::nullopt;
    hp.salt = *salt;
    hp.hash = *hash;
    return hp;

  } else if (algo_str == "sha256") {
    // $sha256$<salt>$<hash>
    if (parts.size() < 3) return std::nullopt;
    hp.algo = HashedPassword::Algorithm::SHA256_SIMPLE;
    auto salt = base64url_decode(parts[1]);
    auto hash = base64url_decode(parts[2]);
    if (!salt || !hash) return std::nullopt;
    hp.salt = *salt;
    hp.hash = *hash;
    return hp;
  }

  return std::nullopt;
}

/// Verify a password against a stored hash
static bool verify_password_against_hash(std::string_view password,
                                          const HashedPassword& stored) {
  switch (stored.algo) {
    case HashedPassword::Algorithm::BCRYPT_SHA512: {
      if (stored.rounds < BCRYPT_ROUNDS_MIN || stored.rounds > BCRYPT_ROUNDS_MAX)
        return false;
      int iterations = 1 << stored.rounds;
      std::string derived = pbkdf2_sha512(password, stored.salt, iterations, 64);
      std::string computed_hash(BCRYPT_HASH_OUTPUT_BYTES, '\0');
      for (size_t i = 0; i < BCRYPT_HASH_OUTPUT_BYTES; ++i) {
        computed_hash[i] = derived[i] ^ derived[i + BCRYPT_HASH_OUTPUT_BYTES];
      }
      // Constant-time comparison
      if (computed_hash.size() != stored.hash.size()) return false;
      int diff = 0;
      for (size_t i = 0; i < computed_hash.size(); ++i) {
        diff |= static_cast<unsigned char>(computed_hash[i]) ^
                static_cast<unsigned char>(stored.hash[i]);
      }
      return diff == 0;
    }

    case HashedPassword::Algorithm::ARGON2ID_EMU: {
      // Re-run the emulated argon2id with stored parameters
      HashedPassword recomputed = hash_password_argon2id(
          password, stored.time_cost, stored.mem_cost_kb, stored.parallelism);
      recomputed.salt = stored.salt;

      // Re-do the computation manually with stored salt
      size_t block_size = 1024;
      size_t num_blocks = static_cast<size_t>(stored.mem_cost_kb);

      std::string seed = pbkdf2_sha512(password, stored.salt, 1, block_size);
      std::vector<std::string> memory;
      memory.reserve(num_blocks);
      memory.push_back(seed);

      for (size_t i = 1; i < num_blocks; ++i) {
        std::string input = memory[i - 1];
        for (int j = 3; j >= 0; --j) input += static_cast<char>((i >> (j * 8)) & 0xFF);
        std::string block = sha256_raw(input);
        if (i % 64 == 0) {
          block = sha256_raw(block + stored.salt);
        }
        if (block.size() < block_size) {
          std::string expanded = block;
          while (expanded.size() < block_size) {
            expanded += sha256_raw(expanded);
          }
          block = expanded.substr(0, block_size);
        }
        memory.push_back(block);
      }

      for (int pass = 0; pass < stored.time_cost; ++pass) {
        for (size_t i = 0; i < num_blocks; ++i) {
          std::string block_hash = sha256_raw(memory[i]);
          uint64_t ref_idx = 0;
          for (size_t j = 0; j < 8 && j < block_hash.size(); ++j) {
            ref_idx = (ref_idx << 8) | static_cast<unsigned char>(block_hash[j]);
          }
          ref_idx %= num_blocks;
          std::string mix_input = memory[i] + memory[ref_idx];
          mix_input += static_cast<char>(pass);
          mix_input += stored.salt;
          memory[i] = sha256_raw(mix_input);
          if (memory[i].size() < block_size) {
            std::string expanded = memory[i];
            while (expanded.size() < block_size) {
              expanded += sha256_raw(expanded);
            }
            memory[i] = expanded.substr(0, block_size);
          }
        }
      }

      std::string computed_hash = sha256_raw(memory[0] + stored.salt);
      computed_hash = computed_hash.substr(0, ARGON2_HASH_LEN);

      if (computed_hash.size() != stored.hash.size()) return false;
      int diff = 0;
      for (size_t i = 0; i < computed_hash.size(); ++i) {
        diff |= static_cast<unsigned char>(computed_hash[i]) ^
                static_cast<unsigned char>(stored.hash[i]);
      }
      return diff == 0;
    }

    case HashedPassword::Algorithm::SHA256_SIMPLE: {
      std::string computed = sha256_raw(std::string(password) + stored.salt);
      if (computed.size() != stored.hash.size()) return false;
      int diff = 0;
      for (size_t i = 0; i < computed.size(); ++i) {
        diff |= static_cast<unsigned char>(computed[i]) ^
                static_cast<unsigned char>(stored.hash[i]);
      }
      return diff == 0;
    }
  }

  return false;
}

/* ============================================================================
 * Token Cleanup — Expired Token Sweep
 * ========================================================================== */

static void cleanup_expired_tokens() {
  int64_t last = g_last_token_cleanup_ms.load(std::memory_order_relaxed);
  int64_t now = now_ms();
  if (now - last < TOKEN_CLEANUP_INTERVAL_SEC * 1000LL) return;

  if (!g_last_token_cleanup_ms.compare_exchange_strong(last, now,
        std::memory_order_relaxed)) {
    return;
  }

  // Cleanup access tokens
  {
    std::unique_lock<std::shared_mutex> lock(g_access_token_mutex);
    std::vector<std::string> to_remove;
    for (const auto& [thash, rec] : g_access_tokens) {
      if (rec.is_revoked && now - rec.revoked_at_ms > 86400000LL) {
        // Remove tokens revoked >24h ago
        to_remove.push_back(thash);
      } else if (!rec.is_revoked && rec.expires_at_ms < now) {
        to_remove.push_back(thash);
      }
    }
    for (const auto& thash : to_remove) {
      auto it = g_access_tokens.find(thash);
      if (it == g_access_tokens.end()) continue;
      const auto& rec = it->second;

      // Remove from user index
      auto uit = g_access_tokens_by_user.find(rec.user_id);
      if (uit != g_access_tokens_by_user.end()) {
        uit->second.erase(thash);
        if (uit->second.empty()) g_access_tokens_by_user.erase(uit);
      }

      // Remove from device index
      if (!rec.device_id.empty()) {
        auto dit = g_access_tokens_by_device.find(rec.device_id);
        if (dit != g_access_tokens_by_device.end()) {
          dit->second.erase(thash);
          if (dit->second.empty()) g_access_tokens_by_device.erase(dit);
        }
      }

      // Remove refresh mapping
      if (!rec.refresh_token_hash.empty()) {
        g_refresh_to_access.erase(rec.refresh_token_hash);
      }

      g_access_tokens.erase(it);
    }
  }

  // Cleanup login tokens
  {
    std::unique_lock<std::shared_mutex> lock(g_login_token_mutex);
    std::vector<std::string> to_remove;
    for (const auto& [thash, rec] : g_login_tokens) {
      if (rec.expires_at_ms < now || rec.used) {
        to_remove.push_back(thash);
      }
    }
    for (const auto& thash : to_remove) {
      g_login_tokens.erase(thash);
    }
  }

  // Cleanup password reset tokens
  {
    std::unique_lock<std::shared_mutex> lock(g_pw_reset_mutex);
    std::vector<std::string> to_remove;
    for (const auto& [thash, rec] : g_pw_reset_tokens) {
      if (rec.expires_at_ms < now || rec.used) {
        to_remove.push_back(thash);
      }
    }
    for (const auto& thash : to_remove) {
      g_pw_reset_tokens.erase(thash);
    }
  }

  // Cleanup email verification tokens
  {
    std::unique_lock<std::shared_mutex> lock(g_email_verify_mutex);
    std::vector<std::string> to_remove;
    for (const auto& [thash, rec] : g_email_verify_tokens) {
      if (rec.expires_at_ms < now || rec.used) {
        to_remove.push_back(thash);
      }
    }
    for (const auto& thash : to_remove) {
      g_email_verify_tokens.erase(thash);
    }
  }
}

/* ============================================================================
 * PUBLIC API — LoginTokenManager Class
 * ========================================================================== */

class LoginTokenManager {
public:
  LoginTokenManager() {
    // Seed the RNG
    std::lock_guard<std::mutex> lock(g_rng_mutex);
    g_rng.seed(std::random_device{}());
  }

  ~LoginTokenManager() = default;

  // ==========================================================================
  // Password Hashing
  // ==========================================================================

  /// Hash a password using bcrypt-style hashing (default algorithm)
  std::string hash_password(std::string_view password) {
    return hash_password_bcrypt(password, BCRYPT_ROUNDS_DEFAULT).serialized;
  }

  /// Hash a password with specified algorithm
  std::string hash_password_with_algo(std::string_view password,
                                       const std::string& algo) {
    if (algo == "argon2id") {
      return hash_password_argon2id(password, ARGON2_TIME_COST,
                                     ARGON2_MEM_COST_KB,
                                     ARGON2_PARALLELISM).serialized;
    } else if (algo == "bcrypt") {
      return hash_password_bcrypt(password, BCRYPT_ROUNDS_DEFAULT).serialized;
    } else {
      // Default to bcrypt
      return hash_password_bcrypt(password, BCRYPT_ROUNDS_DEFAULT).serialized;
    }
  }

  /// Hash a password with custom bcrypt rounds
  std::string hash_password_bcrypt_rounds(std::string_view password, int rounds) {
    return hash_password_bcrypt(password, rounds).serialized;
  }

  /// Store a user's password hash
  void store_password(const std::string& user_id, const std::string& hashed) {
    auto parsed = deserialize_password_hash(hashed);
    if (!parsed) {
      // Store as-is for legacy, but try to parse first for future verifications
      HashedPassword hp;
      hp.serialized = hashed;
      hp.algo = HashedPassword::Algorithm::SHA256_SIMPLE;
      std::unique_lock<std::shared_mutex> lock(g_password_mutex);
      g_passwords[user_id] = hp;
      return;
    }
    std::unique_lock<std::shared_mutex> lock(g_password_mutex);
    g_passwords[user_id] = *parsed;
  }

  /// Hash and store in one call
  std::string hash_and_store_password(const std::string& user_id,
                                       std::string_view password) {
    auto hp = hash_password_bcrypt(password, BCRYPT_ROUNDS_DEFAULT);
    std::unique_lock<std::shared_mutex> lock(g_password_mutex);
    g_passwords[user_id] = hp;
    return hp.serialized;
  }

  // ==========================================================================
  // Password Verification
  // ==========================================================================

  /// Verify a password against the stored hash for a user
  bool verify_password(const std::string& user_id, std::string_view password) {
    HashedPassword stored;
    {
      std::shared_lock<std::shared_mutex> lock(g_password_mutex);
      auto it = g_passwords.find(user_id);
      if (it == g_passwords.end()) return false;
      stored = it->second;
    }
    return verify_password_against_hash(password, stored);
  }

  /// Verify a password against an explicit hash string
  bool verify_password_static(std::string_view password,
                               std::string_view hash_str) {
    auto parsed = deserialize_password_hash(hash_str);
    if (!parsed) return false;
    return verify_password_against_hash(password, *parsed);
  }

  /// Check if a user has a stored password
  bool has_password(const std::string& user_id) {
    std::shared_lock<std::shared_mutex> lock(g_password_mutex);
    return g_passwords.find(user_id) != g_passwords.end();
  }

  /// Remove a user's password (for deactivation)
  bool remove_password(const std::string& user_id) {
    std::unique_lock<std::shared_mutex> lock(g_password_mutex);
    return g_passwords.erase(user_id) > 0;
  }

  /// Check password strength (basic validation)
  json validate_password_strength(std::string_view password) {
    json result;
    result["valid"] = true;
    std::vector<std::string> warnings;

    if (password.size() < 8) {
      result["valid"] = false;
      warnings.push_back("Password must be at least 8 characters long");
    }
    if (password.size() > 128) {
      result["valid"] = false;
      warnings.push_back("Password must not exceed 128 characters");
    }

    bool has_upper = false, has_lower = false, has_digit = false, has_special = false;
    for (char c : password) {
      if (c >= 'A' && c <= 'Z') has_upper = true;
      else if (c >= 'a' && c <= 'z') has_lower = true;
      else if (c >= '0' && c <= '9') has_digit = true;
      else has_special = true;
    }

    int categories = (has_upper ? 1 : 0) + (has_lower ? 1 : 0) +
                     (has_digit ? 1 : 0) + (has_special ? 1 : 0);
    if (categories < 3) {
      warnings.push_back(
          "Password should contain at least 3 of: uppercase, lowercase, digit, special character");
      if (categories < 2) result["valid"] = false;
    }

    result["warnings"] = warnings;
    result["strength"] = categories;
    result["length"] = password.size();
    return result;
  }

  // ==========================================================================
  // Login Token Generation (Matrix SSO / Login Token flow)
  // ==========================================================================

  /// Generate a login token for a user. These are short-lived and single-use.
  json create_login_token(const std::string& user_id,
                           std::optional<int64_t> ttl_sec = std::nullopt) {
    maybe_cleanup_ratelimits();
    int64_t ttl = ttl_sec.value_or(LOGIN_TOKEN_TTL_SEC);

    std::string token = generate_login_token();
    std::string thash = hash_token(token);
    int64_t now = now_ms();

    LoginTokenRecord rec;
    rec.token_hash = thash;
    rec.user_id = user_id;
    rec.created_at_ms = now;
    rec.expires_at_ms = now + ttl * 1000LL;
    rec.used = false;
    rec.used_at_ms = 0;
    rec.is_revoked = false;

    {
      std::unique_lock<std::shared_mutex> lock(g_login_token_mutex);
      g_login_tokens[thash] = std::move(rec);
    }

    audit_log("login_token_created", user_id, "", "", "ttl=" + std::to_string(ttl));

    json result;
    result["login_token"] = token;
    result["expires_in_ms"] = ttl * 1000LL;
    result["expires_in"] = ttl;
    return result;
  }

  /// Verify a login token and return the associated user_id if valid
  json verify_login_token(std::string_view token) {
    maybe_cleanup_ratelimits();
    std::string thash = hash_token(token);
    int64_t now = now_ms();

    std::unique_lock<std::shared_mutex> lock(g_login_token_mutex);
    auto it = g_login_tokens.find(thash);

    json result;
    if (it == g_login_tokens.end()) {
      result["valid"] = false;
      result["error"] = "Unknown login token";
      result["errcode"] = "M_UNKNOWN_TOKEN";
      return result;
    }

    auto& rec = it->second;

    if (rec.is_revoked) {
      result["valid"] = false;
      result["error"] = "Login token has been revoked";
      result["errcode"] = "M_UNKNOWN_TOKEN";
      return result;
    }

    if (rec.used) {
      result["valid"] = false;
      result["error"] = "Login token has already been used";
      result["errcode"] = "M_UNKNOWN_TOKEN";
      return result;
    }

    if (rec.expires_at_ms < now) {
      result["valid"] = false;
      result["error"] = "Login token has expired";
      result["errcode"] = "M_UNKNOWN_TOKEN";
      return result;
    }

    // Mark as used
    rec.used = true;
    rec.used_at_ms = now;

    result["valid"] = true;
    result["user_id"] = rec.user_id;
    audit_log("login_token_used", rec.user_id, "", "", "");

    return result;
  }

  // ==========================================================================
  // Access Token Generation (syt_ format)
  // ==========================================================================

  /// Create a full access token + refresh token pair with session metadata
  json create_access_token(const std::string& user_id,
                            const std::string& device_id = "",
                            std::optional<int64_t> access_ttl = std::nullopt,
                            std::optional<int64_t> refresh_ttl = std::nullopt,
                            const std::string& ip_address = "",
                            const std::string& user_agent = "") {
    maybe_cleanup_ratelimits();

    int64_t acc_ttl = access_ttl.value_or(ACCESS_TOKEN_TTL_SEC);
    int64_t ref_ttl = refresh_ttl.value_or(REFRESH_TOKEN_TTL_SEC);

    // Cap TTLs
    if (acc_ttl > ABSOLUTE_MAX_TOKEN_TTL) acc_ttl = ABSOLUTE_MAX_TOKEN_TTL;
    if (ref_ttl > ABSOLUTE_MAX_TOKEN_TTL) ref_ttl = ABSOLUTE_MAX_TOKEN_TTL;

    std::string access_token = generate_syt_token(user_id, device_id);
    std::string refresh_token = generate_refresh_token();

    std::string athash = hash_token(access_token);
    std::string rthash = hash_token(refresh_token);
    int64_t now = now_ms();

    AccessTokenRecord rec;
    rec.token = access_token;
    rec.token_hash = athash;
    rec.user_id = user_id;
    rec.device_id = device_id;
    rec.refresh_token = refresh_token;
    rec.refresh_token_hash = rthash;
    rec.created_at_ms = now;
    rec.expires_at_ms = now + acc_ttl * 1000LL;
    rec.last_used_ms = now;
    rec.rotated_at_ms = 0;
    rec.is_revoked = false;
    rec.revoked_at_ms = 0;
    rec.ip_address = ip_address;
    rec.user_agent = user_agent;
    rec.initial_ip = ip_address;
    rec.initial_user_agent = user_agent;

    {
      std::unique_lock<std::shared_mutex> lock(g_access_token_mutex);
      g_access_tokens[athash] = rec;
      g_access_tokens_by_user[user_id].insert(athash);
      if (!device_id.empty()) {
        g_access_tokens_by_device[device_id].insert(athash);
      }
      g_refresh_to_access[rthash] = athash;
    }

    // Track IP
    if (!ip_address.empty()) {
      track_ip(user_id, ip_address);
    }

    audit_log("token_created", user_id, device_id, ip_address, "");

    json result;
    result["access_token"] = access_token;
    result["refresh_token"] = refresh_token;
    result["user_id"] = user_id;
    result["device_id"] = device_id;
    result["expires_in_ms"] = acc_ttl * 1000LL;
    result["refresh_expires_in_ms"] = ref_ttl * 1000LL;

    return result;
  }

  // ==========================================================================
  // Token Verification
  // ==========================================================================

  /// Verify an access token and return user info if valid
  json verify_access_token(std::string_view token,
                            const std::string& ip_address = "") {
    maybe_cleanup_ratelimits();
    std::string thash = hash_token(token);
    int64_t now = now_ms();

    std::unique_lock<std::shared_mutex> lock(g_access_token_mutex);
    auto it = g_access_tokens.find(thash);

    json result;
    if (it == g_access_tokens.end()) {
      result["valid"] = false;
      result["error"] = "Unknown access token";
      result["errcode"] = "M_UNKNOWN_TOKEN";
      return result;
    }

    auto& rec = it->second;

    if (rec.is_revoked) {
      // Check if within rotation grace period
      if (rec.rotated_at_ms > 0 && (now - rec.rotated_at_ms) < TOKEN_ROTATION_GRACE_SEC * 1000LL) {
        // Allow during grace period but flag as rotated
        result["valid"] = true;
        result["user_id"] = rec.user_id;
        result["device_id"] = rec.device_id;
        result["rotated"] = true;
        result["warning"] = "Token has been rotated; please use new token";
        update_last_used_nolock(rec, now, ip_address);
        return result;
      }

      result["valid"] = false;
      result["error"] = "Access token has been revoked";
      result["errcode"] = "M_UNKNOWN_TOKEN";
      result["revoked_reason"] = rec.revoked_reason;
      return result;
    }

    if (rec.expires_at_ms < now) {
      result["valid"] = false;
      result["error"] = "Access token has expired";
      result["errcode"] = "M_UNKNOWN_TOKEN";
      result["expired_at"] = rec.expires_at_ms;
      return result;
    }

    result["valid"] = true;
    result["user_id"] = rec.user_id;
    result["device_id"] = rec.device_id;
    result["expires_at"] = rec.expires_at_ms;
    result["created_at"] = rec.created_at_ms;
    result["last_used"] = rec.last_used_ms;

    update_last_used_nolock(rec, now, ip_address);

    return result;
  }

  /// Refresh an access token using a refresh token (token rotation)
  json refresh_access_token(std::string_view refresh_token,
                              const std::string& ip_address = "",
                              const std::string& user_agent = "") {
    maybe_cleanup_ratelimits();

    std::string rthash = hash_token(refresh_token);
    int64_t now = now_ms();

    std::unique_lock<std::shared_mutex> lock(g_access_token_mutex);

    // Find the access token linked to this refresh token
    auto rit = g_refresh_to_access.find(rthash);
    json result;

    if (rit == g_refresh_to_access.end()) {
      result["valid"] = false;
      result["error"] = "Unknown refresh token";
      result["errcode"] = "M_UNKNOWN_TOKEN";
      return result;
    }

    std::string old_athash = rit->second;
    auto ait = g_access_tokens.find(old_athash);

    if (ait == g_access_tokens.end()) {
      // Clean up stale mapping
      g_refresh_to_access.erase(rit);
      result["valid"] = false;
      result["error"] = "Associated access token not found";
      result["errcode"] = "M_UNKNOWN_TOKEN";
      return result;
    }

    auto& old_rec = ait->second;

    if (old_rec.is_revoked) {
      result["valid"] = false;
      result["error"] = "Token has been revoked";
      result["errcode"] = "M_UNKNOWN_TOKEN";
      return result;
    }

    // The refresh token itself has an implicit expiry aligned with the access token
    // Check that the refresh hasn't expired (access token expired + refresh TTL)
    if (old_rec.expires_at_ms < now - (REFRESH_TOKEN_TTL_SEC - ACCESS_TOKEN_TTL_SEC) * 1000LL) {
      result["valid"] = false;
      result["error"] = "Refresh token has expired";
      result["errcode"] = "M_UNKNOWN_TOKEN";
      return result;
    }

    // Generate new tokens
    std::string new_access_token = generate_syt_token(old_rec.user_id, old_rec.device_id);
    std::string new_refresh_token = generate_refresh_token();

    std::string new_athash = hash_token(new_access_token);
    std::string new_rthash = hash_token(new_refresh_token);

    int64_t new_expiry = now + ACCESS_TOKEN_TTL_SEC * 1000LL;

    // Mark old token as rotated
    old_rec.is_revoked = true;
    old_rec.revoked_at_ms = now;
    old_rec.rotated_at_ms = now;
    old_rec.rotated_by_token = new_athash;
    old_rec.revoked_reason = "Token rotated";

    // Remove old refresh mapping
    g_refresh_to_access.erase(old_rec.refresh_token_hash);

    // Create new record copying session info
    AccessTokenRecord new_rec;
    new_rec.token = new_access_token;
    new_rec.token_hash = new_athash;
    new_rec.user_id = old_rec.user_id;
    new_rec.device_id = old_rec.device_id;
    new_rec.refresh_token = new_refresh_token;
    new_rec.refresh_token_hash = new_rthash;
    new_rec.created_at_ms = now;
    new_rec.expires_at_ms = new_expiry;
    new_rec.last_used_ms = now;
    new_rec.is_revoked = false;
    new_rec.ip_address = ip_address.empty() ? old_rec.ip_address : ip_address;
    new_rec.user_agent = user_agent.empty() ? old_rec.user_agent : user_agent;
    new_rec.initial_ip = old_rec.initial_ip;
    new_rec.initial_user_agent = old_rec.initial_user_agent;

    g_access_tokens[new_athash] = new_rec;
    g_access_tokens_by_user[new_rec.user_id].insert(new_athash);
    if (!new_rec.device_id.empty()) {
      g_access_tokens_by_device[new_rec.device_id].insert(new_athash);
    }
    g_refresh_to_access[new_rthash] = new_athash;

    audit_log("token_refreshed", old_rec.user_id, old_rec.device_id, ip_address, "");

    result["valid"] = true;
    result["access_token"] = new_access_token;
    result["refresh_token"] = new_refresh_token;
    result["user_id"] = new_rec.user_id;
    result["device_id"] = new_rec.device_id;
    result["expires_in_ms"] = ACCESS_TOKEN_TTL_SEC * 1000LL;

    return result;
  }

  // ==========================================================================
  // Token Revocation
  // ==========================================================================

  /// Revoke a single access token
  json revoke_access_token(std::string_view access_token,
                            const std::string& reason = "user_request") {
    std::string thash = hash_token(access_token);
    std::unique_lock<std::shared_mutex> lock(g_access_token_mutex);

    auto it = g_access_tokens.find(thash);
    json result;

    if (it == g_access_tokens.end()) {
      result["revoked"] = false;
      result["error"] = "Token not found";
      return result;
    }

    auto& rec = it->second;
    if (rec.is_revoked) {
      result["revoked"] = false;
      result["error"] = "Token already revoked";
      return result;
    }

    rec.is_revoked = true;
    rec.revoked_at_ms = now_ms();
    rec.revoked_reason = reason;

    // Remove refresh mapping
    if (!rec.refresh_token_hash.empty()) {
      g_refresh_to_access.erase(rec.refresh_token_hash);
    }

    audit_log("token_revoked", rec.user_id, rec.device_id,
              rec.ip_address, reason);

    result["revoked"] = true;
    result["user_id"] = rec.user_id;
    result["device_id"] = rec.device_id;

    return result;
  }

  /// Revoke all tokens for a user
  json revoke_all_user_tokens(const std::string& user_id,
                                const std::string& reason = "admin_action",
                                std::optional<std::string> except_token = std::nullopt) {
    std::unique_lock<std::shared_mutex> lock(g_access_token_mutex);
    int64_t now = now_ms();
    int count = 0;

    auto it = g_access_tokens_by_user.find(user_id);
    json result;

    if (it == g_access_tokens_by_user.end()) {
      result["revoked_count"] = 0;
      result["user_id"] = user_id;
      return result;
    }

    std::string except_hash;
    if (except_token) {
      except_hash = hash_token(*except_token);
    }

    for (const auto& thash : it->second) {
      if (!except_hash.empty() && thash == except_hash) continue;

      auto ait = g_access_tokens.find(thash);
      if (ait == g_access_tokens.end() || ait->second.is_revoked) continue;

      ait->second.is_revoked = true;
      ait->second.revoked_at_ms = now;
      ait->second.revoked_reason = reason;

      if (!ait->second.refresh_token_hash.empty()) {
        g_refresh_to_access.erase(ait->second.refresh_token_hash);
      }
      count++;
    }

    audit_log("all_tokens_revoked", user_id, "", "", reason);

    result["revoked_count"] = count;
    result["user_id"] = user_id;
    return result;
  }

  /// Revoke all tokens for a device
  json revoke_device_tokens(const std::string& device_id,
                              const std::string& reason = "user_request") {
    std::unique_lock<std::shared_mutex> lock(g_access_token_mutex);
    int64_t now = now_ms();
    int count = 0;

    auto it = g_access_tokens_by_device.find(device_id);
    json result;

    if (it == g_access_tokens_by_device.end()) {
      result["revoked_count"] = 0;
      result["device_id"] = device_id;
      return result;
    }

    for (const auto& thash : it->second) {
      auto ait = g_access_tokens.find(thash);
      if (ait == g_access_tokens.end() || ait->second.is_revoked) continue;

      ait->second.is_revoked = true;
      ait->second.revoked_at_ms = now;
      ait->second.revoked_reason = reason;

      if (!ait->second.refresh_token_hash.empty()) {
        g_refresh_to_access.erase(ait->second.refresh_token_hash);
      }
      count++;
    }

    audit_log("device_tokens_revoked", "", device_id, "", reason);

    result["revoked_count"] = count;
    result["device_id"] = device_id;
    return result;
  }

  /// Revoke a login token
  json revoke_login_token(std::string_view token) {
    std::string thash = hash_token(token);
    std::unique_lock<std::shared_mutex> lock(g_login_token_mutex);

    auto it = g_login_tokens.find(thash);
    json result;

    if (it == g_login_tokens.end()) {
      result["revoked"] = false;
      result["error"] = "Login token not found";
      return result;
    }

    it->second.is_revoked = true;
    result["revoked"] = true;

    return result;
  }

  // ==========================================================================
  // Token Expiry Management
  // ==========================================================================

  /// Check if a token has expired
  bool is_token_expired(std::string_view access_token) {
    std::string thash = hash_token(access_token);
    std::shared_lock<std::shared_mutex> lock(g_access_token_mutex);
    auto it = g_access_tokens.find(thash);
    if (it == g_access_tokens.end()) return true;
    return it->second.expires_at_ms < now_ms() || it->second.is_revoked;
  }

  /// Extend token expiry (prolong session)
  json extend_token_expiry(std::string_view access_token, int64_t additional_seconds) {
    std::string thash = hash_token(access_token);
    std::unique_lock<std::shared_mutex> lock(g_access_token_mutex);

    auto it = g_access_tokens.find(thash);
    json result;

    if (it == g_access_tokens.end() || it->second.is_revoked) {
      result["success"] = false;
      result["error"] = "Token not found or revoked";
      return result;
    }

    it->second.expires_at_ms += additional_seconds * 1000LL;
    int64_t max_expiry = now_ms() + ABSOLUTE_MAX_TOKEN_TTL * 1000LL;
    if (it->second.expires_at_ms > max_expiry) {
      it->second.expires_at_ms = max_expiry;
    }

    result["success"] = true;
    result["new_expires_at"] = it->second.expires_at_ms;
    result["extended_by_seconds"] = additional_seconds;

    return result;
  }

  // ==========================================================================
  // Token Rotation
  // ==========================================================================

  /// Check if a token is within rotation grace period
  bool is_token_in_rotation_grace(std::string_view access_token) {
    std::string thash = hash_token(access_token);
    std::shared_lock<std::shared_mutex> lock(g_access_token_mutex);
    auto it = g_access_tokens.find(thash);
    if (it == g_access_tokens.end()) return false;
    if (!it->second.is_revoked || it->second.rotated_at_ms == 0) return false;
    return (now_ms() - it->second.rotated_at_ms) < TOKEN_ROTATION_GRACE_SEC * 1000LL;
  }

  /// Get the replacement token for a rotated token
  std::optional<std::string> get_replacement_token(std::string_view old_token) {
    std::string thash = hash_token(old_token);
    std::shared_lock<std::shared_mutex> lock(g_access_token_mutex);
    auto it = g_access_tokens.find(thash);
    if (it == g_access_tokens.end()) return std::nullopt;
    if (it->second.rotated_by_token.empty()) return std::nullopt;

    auto rit = g_access_tokens.find(it->second.rotated_by_token);
    if (rit == g_access_tokens.end()) return std::nullopt;
    return rit->second.token;
  }

  // ==========================================================================
  // Device Token Tracking
  // ==========================================================================

  /// List tokens for a device
  json list_device_tokens(const std::string& device_id) {
    std::shared_lock<std::shared_mutex> lock(g_access_token_mutex);
    json result = json::array();

    auto it = g_access_tokens_by_device.find(device_id);
    if (it == g_access_tokens_by_device.end()) return result;

    int64_t now = now_ms();
    for (const auto& thash : it->second) {
      auto ait = g_access_tokens.find(thash);
      if (ait == g_access_tokens.end()) continue;

      const auto& rec = ait->second;
      json entry;
      entry["token_hash"] = thash;
      entry["user_id"] = rec.user_id;
      entry["created_at"] = rec.created_at_ms;
      entry["expires_at"] = rec.expires_at_ms;
      entry["last_used"] = rec.last_used_ms;
      entry["is_revoked"] = rec.is_revoked;
      entry["is_expired"] = rec.expires_at_ms < now;
      entry["ip_address"] = rec.ip_address;
      result.push_back(entry);
    }

    return result;
  }

  /// Count active devices for a user
  int count_user_devices(const std::string& user_id) {
    std::shared_lock<std::shared_mutex> lock(g_access_token_mutex);
    auto it = g_access_tokens_by_user.find(user_id);
    if (it == g_access_tokens_by_user.end()) return 0;

    std::unordered_set<std::string> devices;
    int64_t now = now_ms();
    for (const auto& thash : it->second) {
      auto ait = g_access_tokens.find(thash);
      if (ait == g_access_tokens.end() || ait->second.is_revoked) continue;
      if (ait->second.expires_at_ms < now) continue;
      if (!ait->second.device_id.empty()) {
        devices.insert(ait->second.device_id);
      }
    }
    return static_cast<int>(devices.size());
  }

  // ==========================================================================
  // Session Tracking
  // ==========================================================================

  /// Get session info for a token
  json get_session_info(std::string_view access_token) {
    std::string thash = hash_token(access_token);
    std::shared_lock<std::shared_mutex> lock(g_access_token_mutex);

    auto it = g_access_tokens.find(thash);
    json result;

    if (it == g_access_tokens.end()) {
      result["found"] = false;
      return result;
    }

    const auto& rec = it->second;
    result["found"] = true;
    result["user_id"] = rec.user_id;
    result["device_id"] = rec.device_id;
    result["created_at"] = rec.created_at_ms;
    result["expires_at"] = rec.expires_at_ms;
    result["last_used"] = rec.last_used_ms;
    result["is_revoked"] = rec.is_revoked;
    result["ip_address"] = rec.ip_address;
    result["user_agent"] = rec.user_agent;
    result["initial_ip"] = rec.initial_ip;
    result["initial_user_agent"] = rec.initial_user_agent;
    result["is_expired"] = rec.expires_at_ms < now_ms();
    result["rotated"] = rec.rotated_at_ms > 0;

    return result;
  }

  /// List all active sessions for a user
  json list_user_sessions(const std::string& user_id) {
    std::shared_lock<std::shared_mutex> lock(g_access_token_mutex);
    json result = json::array();
    int64_t now = now_ms();

    auto it = g_access_tokens_by_user.find(user_id);
    if (it == g_access_tokens_by_user.end()) return result;

    for (const auto& thash : it->second) {
      auto ait = g_access_tokens.find(thash);
      if (ait == g_access_tokens.end()) continue;

      const auto& rec = ait->second;
      if (rec.is_revoked) continue;
      if (rec.expires_at_ms < now) continue;

      json session;
      session["token_hash"] = thash;
      session["device_id"] = rec.device_id;
      session["created_at"] = rec.created_at_ms;
      session["expires_at"] = rec.expires_at_ms;
      session["last_used"] = rec.last_used_ms;
      session["ip_address"] = rec.ip_address;
      session["user_agent"] = rec.user_agent;
      result.push_back(session);
    }

    return result;
  }

  /// Get session statistics for a user
  json get_user_session_stats(const std::string& user_id) {
    std::shared_lock<std::shared_mutex> lock(g_access_token_mutex);
    int64_t now = now_ms();

    auto it = g_access_tokens_by_user.find(user_id);
    json result;

    if (it == g_access_tokens_by_user.end()) {
      result["active_sessions"] = 0;
      result["active_devices"] = 0;
      result["total_tokens"] = 0;
      return result;
    }

    int active_sessions = 0;
    int total_tokens = 0;
    std::unordered_set<std::string> devices;
    std::unordered_set<std::string> recent_ips;
    int64_t last_active = 0;

    for (const auto& thash : it->second) {
      auto ait = g_access_tokens.find(thash);
      if (ait == g_access_tokens.end()) continue;

      total_tokens++;
      const auto& rec = ait->second;

      if (!rec.is_revoked && rec.expires_at_ms >= now) {
        active_sessions++;
        if (!rec.device_id.empty()) devices.insert(rec.device_id);
        if (!rec.ip_address.empty()) recent_ips.insert(rec.ip_address);
        if (rec.last_used_ms > last_active) last_active = rec.last_used_ms;
      }
    }

    result["active_sessions"] = active_sessions;
    result["active_devices"] = static_cast<int>(devices.size());
    result["total_tokens"] = total_tokens;
    result["last_active_ms"] = last_active;
    result["recent_ips"] = std::vector<std::string>(recent_ips.begin(), recent_ips.end());

    return result;
  }

  // ==========================================================================
  // IP Tracking
  // ==========================================================================

  /// Update IP for a token
  bool update_token_ip(std::string_view access_token, const std::string& ip_address) {
    std::string thash = hash_token(access_token);
    std::unique_lock<std::shared_mutex> lock(g_access_token_mutex);

    auto it = g_access_tokens.find(thash);
    if (it == g_access_tokens.end() || it->second.is_revoked) return false;

    it->second.ip_address = ip_address;
    track_ip(it->second.user_id, ip_address);
    return true;
  }

  /// Get IP history for a user
  json get_user_ip_history(const std::string& user_id) {
    std::shared_lock<std::shared_mutex> lock(g_ip_track_mutex);
    json result = json::array();

    auto it = g_ip_tracking.find(user_id);
    if (it == g_ip_tracking.end()) return result;

    for (const auto& entry : it->second) {
      json e;
      e["ip_address"] = entry.ip_address;
      e["first_seen"] = entry.first_seen_ms;
      e["last_seen"] = entry.last_seen_ms;
      e["count"] = entry.count;
      result.push_back(e);
    }

    return result;
  }

  /// Check for anomalous IP activity
  json check_ip_anomaly(const std::string& user_id,
                          const std::string& current_ip) {
    json result;
    result["anomalous"] = detect_anomalous_ip_activity(user_id, current_ip);

    if (result["anomalous"].get<bool>()) {
      result["warning"] = "Multiple IP addresses detected in a short period";
    }

    return result;
  }

  // ==========================================================================
  // Last-Used Update (with debouncing)
  // ==========================================================================

private:
  static void update_last_used_nolock(AccessTokenRecord& rec, int64_t now,
                                       const std::string& ip_address) {
    // Debounce: only update if more than LAST_USED_DEBOUNCE_SEC since last update
    if (now - rec.last_used_ms >= LAST_USED_DEBOUNCE_SEC * 1000LL) {
      rec.last_used_ms = now;
    }
    if (!ip_address.empty()) {
      rec.ip_address = ip_address;
    }
  }

public:
  /// Manually update last-used timestamp
  bool touch_token(std::string_view access_token, const std::string& ip_address = "") {
    std::string thash = hash_token(access_token);
    std::unique_lock<std::shared_mutex> lock(g_access_token_mutex);

    auto it = g_access_tokens.find(thash);
    if (it == g_access_tokens.end() || it->second.is_revoked) return false;

    update_last_used_nolock(it->second, now_ms(), ip_address);
    return true;
  }

  // ==========================================================================
  // Brute Force Protection (Rate Limiting)
  // ==========================================================================

  /// Check if a login attempt for a user is allowed (rate limit check)
  json check_login_rate_limit(const std::string& user_id,
                                const std::string& ip_address = "") {
    maybe_cleanup_ratelimits();

    json result;
    result["allowed"] = true;

    // Check user-based rate limit
    std::string user_key = "login:" + user_id;
    if (!check_rate_limit(user_key, RATE_LIMIT_MAX_LOGIN, RATE_LIMIT_WINDOW_SEC)) {
      result["allowed"] = false;
      result["error"] = "Too many login attempts for this user. Please try again later.";
      result["errcode"] = "M_LIMIT_EXCEEDED";
      result["retry_after_ms"] = RATE_LIMIT_WINDOW_SEC * 1000LL;
      return result;
    }

    // Check IP-based rate limit
    if (!ip_address.empty()) {
      std::string ip_key = "login_ip:" + ip_address;
      if (!check_rate_limit(ip_key, RATE_LIMIT_MAX_LOGIN * 3, RATE_LIMIT_WINDOW_SEC)) {
        result["allowed"] = false;
        result["error"] = "Too many login attempts from this IP. Please try again later.";
        result["errcode"] = "M_LIMIT_EXCEEDED";
        result["retry_after_ms"] = RATE_LIMIT_WINDOW_SEC * 1000LL;
        return result;
      }
    }

    // Check failed-login rate for this user
    std::string failed_key = "failed:" + user_id;
    int failed_count = 0;
    {
      std::shared_lock<std::shared_mutex> lock(g_ratelimit_mutex);
      failed_count = count_ratelimit_entries(failed_key,
                                              RATE_LIMIT_WINDOW_SEC * 1000LL);
    }
    if (failed_count >= RATE_LIMIT_MAX_FAILED) {
      result["allowed"] = false;
      result["error"] = "Too many failed login attempts. Account temporarily locked.";
      result["errcode"] = "M_LIMIT_EXCEEDED";
      result["retry_after_ms"] = RATE_LIMIT_WINDOW_SEC * 1000LL;
      return result;
    }

    return result;
  }

  /// Record a failed login attempt
  void record_failed_login_attempt(const std::string& user_id,
                                    const std::string& ip_address = "") {
    std::string failed_key = "failed:" + user_id;
    record_ratelimit_entry(failed_key);

    if (!ip_address.empty()) {
      record_ratelimit_entry("failed_ip:" + ip_address);
    }

    // Check for lockout
    record_failed_login(user_id);

    audit_log("login_failed", user_id, "", ip_address, "");
  }

  /// Record a successful login (clears failure count)
  void record_successful_login(const std::string& user_id,
                                const std::string& ip_address = "") {
    clear_lockout(user_id);
    audit_log("login_success", user_id, "", ip_address, "");
  }

  /// Get rate-limit status for a user
  json get_rate_limit_status(const std::string& user_id,
                               const std::string& ip_address = "") {
    maybe_cleanup_ratelimits();
    json result;
    int64_t window_ms = RATE_LIMIT_WINDOW_SEC * 1000LL;

    {
      std::shared_lock<std::shared_mutex> lock(g_ratelimit_mutex);

      std::string user_key = "login:" + user_id;
      result["login_attempts_user"] = count_ratelimit_entries(user_key, window_ms);
      result["login_limit_user"] = RATE_LIMIT_MAX_LOGIN;

      std::string failed_key = "failed:" + user_id;
      result["failed_attempts"] = count_ratelimit_entries(failed_key, window_ms);
      result["failed_limit"] = RATE_LIMIT_MAX_FAILED;

      if (!ip_address.empty()) {
        std::string ip_key = "login_ip:" + ip_address;
        result["login_attempts_ip"] = count_ratelimit_entries(ip_key, window_ms);
        result["login_limit_ip"] = RATE_LIMIT_MAX_LOGIN * 3;
      }
    }

    result["window_seconds"] = RATE_LIMIT_WINDOW_SEC;

    // Lockout status
    int64_t remaining = lockout_remaining_sec(user_id);
    result["locked_out"] = remaining > 0;
    result["lockout_remaining_seconds"] = remaining;

    {
      std::shared_lock<std::shared_mutex> lock(g_lockout_mutex);
      auto it = g_lockouts.find(user_id);
      if (it != g_lockouts.end()) {
        result["consecutive_failures"] = it->second.consecutive_failures;
        result["total_lockouts"] = it->second.total_lockouts;
      }
    }

    return result;
  }

  // ==========================================================================
  // Account Lockout
  // ==========================================================================

  /// Check if a user account is locked
  bool is_account_locked(const std::string& user_id) {
    return is_locked_out(user_id);
  }

  /// Get lockout details for a user
  json get_lockout_status(const std::string& user_id) {
    json result;
    std::shared_lock<std::shared_mutex> lock(g_lockout_mutex);

    auto it = g_lockouts.find(user_id);
    if (it == g_lockouts.end()) {
      result["locked"] = false;
      result["consecutive_failures"] = 0;
      result["total_lockouts"] = 0;
      return result;
    }

    int64_t now = now_ms();
    result["locked"] = it->second.locked_until_ms > now;
    result["consecutive_failures"] = it->second.consecutive_failures;
    result["total_lockouts"] = it->second.total_lockouts;
    result["first_failure_ms"] = it->second.first_failure_ms;
    result["last_failure_ms"] = it->second.last_failure_ms;
    result["locked_until_ms"] = it->second.locked_until_ms;
    result["lockout_duration_sec"] = it->second.current_lockout_duration_sec;
    result["remaining_seconds"] = result["locked"].get<bool>() ?
        (it->second.locked_until_ms - now) / 1000 : 0;

    return result;
  }

  /// Admin: manually unlock an account
  json admin_unlock_account(const std::string& user_id) {
    std::unique_lock<std::shared_mutex> lock(g_lockout_mutex);
    json result;

    auto it = g_lockouts.find(user_id);
    if (it == g_lockouts.end()) {
      result["unlocked"] = true;
      result["message"] = "Account was not locked";
      return result;
    }

    it->second.consecutive_failures = 0;
    it->second.locked_until_ms = 0;
    it->second.current_lockout_duration_sec = 0;

    audit_log("admin_unlock", user_id, "", "", "");

    result["unlocked"] = true;
    result["user_id"] = user_id;
    return result;
  }

  /// Admin: manually lock an account
  json admin_lock_account(const std::string& user_id,
                            std::optional<int64_t> duration_sec = std::nullopt) {
    std::unique_lock<std::shared_mutex> lock(g_lockout_mutex);
    int64_t dur = duration_sec.value_or(LOCKOUT_DURATION_SEC);
    int64_t now = now_ms();

    auto& rec = g_lockouts[user_id];
    rec.user_id = user_id;
    rec.locked_until_ms = now + dur * 1000LL;
    rec.current_lockout_duration_sec = dur;
    if (rec.consecutive_failures == 0) {
      rec.consecutive_failures = LOCKOUT_THRESHOLD_FAILURES;
    }

    audit_log("admin_lock", user_id, "", "", "duration=" + std::to_string(dur));

    json result;
    result["locked"] = true;
    result["user_id"] = user_id;
    result["locked_until_ms"] = rec.locked_until_ms;
    result["duration_sec"] = dur;
    return result;
  }

  // ==========================================================================
  // Password Reset Token
  // ==========================================================================

  /// Generate a password reset token
  json create_password_reset_token(const std::string& user_id,
                                     std::optional<int64_t> ttl_sec = std::nullopt) {
    // Rate limit password reset requests
    std::string rl_key = "pwreset:" + user_id;
    if (!check_rate_limit(rl_key, RATE_LIMIT_MAX_PW_RESET, RATE_LIMIT_WINDOW_SEC)) {
      json result;
      result["success"] = false;
      result["error"] = "Too many password reset requests. Please try again later.";
      result["errcode"] = "M_LIMIT_EXCEEDED";
      result["retry_after_ms"] = RATE_LIMIT_WINDOW_SEC * 1000LL;
      return result;
    }

    int64_t ttl = ttl_sec.value_or(PASSWORD_RESET_TTL_SEC);
    std::string token = generate_password_reset_token();
    std::string thash = hash_token(token);
    int64_t now = now_ms();

    // Invalidate any previous unused tokens for this user
    {
      std::unique_lock<std::shared_mutex> lock(g_pw_reset_mutex);
      for (auto& [h, rec] : g_pw_reset_tokens) {
        if (rec.user_id == user_id && !rec.used) {
          rec.used = true; // effectively revoke old tokens
        }
      }
    }

    PasswordResetToken rec;
    rec.token_hash = thash;
    rec.user_id = user_id;
    rec.created_at_ms = now;
    rec.expires_at_ms = now + ttl * 1000LL;
    rec.used = false;
    rec.used_at_ms = 0;

    {
      std::unique_lock<std::shared_mutex> lock(g_pw_reset_mutex);
      g_pw_reset_tokens[thash] = std::move(rec);
    }

    audit_log("pw_reset_created", user_id, "", "", "");

    json result;
    result["success"] = true;
    result["reset_token"] = token;
    result["expires_in"] = ttl;
    result["expires_in_ms"] = ttl * 1000LL;
    return result;
  }

  /// Verify a password reset token
  json verify_password_reset_token(std::string_view token) {
    std::string thash = hash_token(token);
    int64_t now = now_ms();

    std::unique_lock<std::shared_mutex> lock(g_pw_reset_mutex);
    auto it = g_pw_reset_tokens.find(thash);

    json result;
    if (it == g_pw_reset_tokens.end()) {
      result["valid"] = false;
      result["error"] = "Invalid or unknown password reset token";
      return result;
    }

    auto& rec = it->second;
    if (rec.used) {
      result["valid"] = false;
      result["error"] = "Password reset token has already been used";
      return result;
    }

    if (rec.expires_at_ms < now) {
      result["valid"] = false;
      result["error"] = "Password reset token has expired";
      return result;
    }

    rec.used = true;
    rec.used_at_ms = now;

    result["valid"] = true;
    result["user_id"] = rec.user_id;

    audit_log("pw_reset_used", rec.user_id, "", "", "");

    return result;
  }

  /// Consume a password reset token and update the password
  json reset_password_with_token(std::string_view token,
                                   std::string_view new_password) {
    // First verify the token
    auto verify_result = verify_password_reset_token(token);
    if (!verify_result["valid"].get<bool>()) {
      return verify_result;
    }

    std::string user_id = verify_result["user_id"].get<std::string>();

    // Hash and store the new password
    hash_and_store_password(user_id, new_password);

    // Revoke all existing access tokens for security
    revoke_all_user_tokens(user_id, "password_reset");

    // Clear lockout
    clear_lockout(user_id);

    audit_log("password_reset_complete", user_id, "", "", "");

    json result;
    result["success"] = true;
    result["user_id"] = user_id;
    return result;
  }

  // ==========================================================================
  // Email Verification Token
  // ==========================================================================

  /// Create an email verification token
  json create_email_verification_token(const std::string& email,
                                         const std::string& client_secret = "",
                                         int send_attempt = 1,
                                         std::optional<std::string> user_id = std::nullopt,
                                         std::optional<int64_t> ttl_sec = std::nullopt) {
    // Rate limit
    std::string rl_key = "emailverify:" + email;
    if (!check_rate_limit(rl_key, RATE_LIMIT_MAX_EMAIL_VERIFY, RATE_LIMIT_WINDOW_SEC)) {
      json result;
      result["success"] = false;
      result["error"] = "Too many email verification attempts. Please try again later.";
      result["errcode"] = "M_LIMIT_EXCEEDED";
      result["retry_after_ms"] = RATE_LIMIT_WINDOW_SEC * 1000LL;
      return result;
    }

    int64_t ttl = ttl_sec.value_or(EMAIL_VERIFY_TTL_SEC);
    std::string token = generate_email_verification_token();
    std::string thash = hash_token(token);
    int64_t now = now_ms();

    EmailVerificationToken rec;
    rec.token_hash = thash;
    rec.email = email;
    rec.user_id = user_id.value_or("");
    rec.client_secret = client_secret;
    rec.send_attempt = send_attempt;
    rec.created_at_ms = now;
    rec.expires_at_ms = now + ttl * 1000LL;
    rec.used = false;
    rec.used_at_ms = 0;
    rec.validated = false;
    rec.validated_at_ms = 0;

    {
      std::unique_lock<std::shared_mutex> lock(g_email_verify_mutex);
      g_email_verify_tokens[thash] = std::move(rec);
    }

    json result;
    result["success"] = true;
    result["verification_token"] = token;
    result["expires_in"] = ttl;
    result["expires_in_ms"] = ttl * 1000LL;
    return result;
  }

  /// Validate an email verification token
  json validate_email_verification_token(std::string_view token) {
    std::string thash = hash_token(token);
    int64_t now = now_ms();

    std::unique_lock<std::shared_mutex> lock(g_email_verify_mutex);
    auto it = g_email_verify_tokens.find(thash);

    json result;
    if (it == g_email_verify_tokens.end()) {
      result["valid"] = false;
      result["error"] = "Invalid or unknown email verification token";
      return result;
    }

    auto& rec = it->second;
    if (rec.used) {
      result["valid"] = false;
      result["error"] = "Email verification token has already been used";
      return result;
    }

    if (rec.expires_at_ms < now) {
      result["valid"] = false;
      result["error"] = "Email verification token has expired";
      return result;
    }

    rec.used = true;
    rec.used_at_ms = now;
    rec.validated = true;
    rec.validated_at_ms = now;

    result["valid"] = true;
    result["email"] = rec.email;
    result["user_id"] = rec.user_id;
    result["client_secret"] = rec.client_secret;

    return result;
  }

  /// Check if an email is verified (has a validated token not yet expired)
  bool is_email_verified(const std::string& email) {
    std::shared_lock<std::shared_mutex> lock(g_email_verify_mutex);
    int64_t now = now_ms();

    // Look for a validated token for this email within a reasonable timeframe
    for (const auto& [thash, rec] : g_email_verify_tokens) {
      if (rec.email == email && rec.validated &&
          now - rec.validated_at_ms < 3600000LL) { // validated within last hour
        return true;
      }
    }
    return false;
  }

  // ==========================================================================
  // Admin Token Listing
  // ==========================================================================

  /// List all tokens (admin)
  json admin_list_tokens(std::optional<std::string> user_filter = std::nullopt,
                           std::optional<std::string> device_filter = std::nullopt,
                           std::optional<bool> active_only = std::nullopt,
                           int limit = 100, int offset = 0) {
    maybe_cleanup_ratelimits();
    cleanup_expired_tokens();

    std::shared_lock<std::shared_mutex> lock(g_access_token_mutex);
    json result = json::array();
    int64_t now = now_ms();
    int skipped = 0;
    int added = 0;

    for (const auto& [thash, rec] : g_access_tokens) {
      // Apply filters
      if (user_filter && rec.user_id != *user_filter) continue;
      if (device_filter && rec.device_id != *device_filter) continue;
      if (active_only.value_or(false)) {
        if (rec.is_revoked || rec.expires_at_ms < now) continue;
      }

      if (skipped < offset) {
        skipped++;
        continue;
      }

      json entry;
      entry["token_hash"] = thash;
      entry["user_id"] = rec.user_id;
      entry["device_id"] = rec.device_id;
      entry["created_at"] = rec.created_at_ms;
      entry["expires_at"] = rec.expires_at_ms;
      entry["last_used"] = rec.last_used_ms;
      entry["is_revoked"] = rec.is_revoked;
      entry["is_expired"] = rec.expires_at_ms < now;
      entry["ip_address"] = rec.ip_address;
      entry["initial_ip"] = rec.initial_ip;
      entry["user_agent"] = rec.user_agent;
      entry["revoked_reason"] = rec.is_revoked ? rec.revoked_reason : "";
      entry["rotated"] = rec.rotated_at_ms > 0;

      result.push_back(entry);
      added++;

      if (added >= limit) break;
    }

    json response;
    response["tokens"] = result;
    response["total"] = g_access_tokens.size();
    response["limit"] = limit;
    response["offset"] = offset;
    response["returned"] = added;

    return response;
  }

  /// Admin: list login tokens
  json admin_list_login_tokens() {
    std::shared_lock<std::shared_mutex> lock(g_login_token_mutex);
    json result = json::array();
    int64_t now = now_ms();

    for (const auto& [thash, rec] : g_login_tokens) {
      json entry;
      entry["token_hash"] = thash;
      entry["user_id"] = rec.user_id;
      entry["created_at"] = rec.created_at_ms;
      entry["expires_at"] = rec.expires_at_ms;
      entry["is_expired"] = rec.expires_at_ms < now;
      entry["used"] = rec.used;
      entry["is_revoked"] = rec.is_revoked;
      result.push_back(entry);
    }

    return result;
  }

  /// Admin: list password reset tokens
  json admin_list_password_reset_tokens() {
    std::shared_lock<std::shared_mutex> lock(g_pw_reset_mutex);
    json result = json::array();
    int64_t now = now_ms();

    for (const auto& [thash, rec] : g_pw_reset_tokens) {
      json entry;
      entry["token_hash"] = thash;
      entry["user_id"] = rec.user_id;
      entry["created_at"] = rec.created_at_ms;
      entry["expires_at"] = rec.expires_at_ms;
      entry["is_expired"] = rec.expires_at_ms < now;
      entry["used"] = rec.used;
      result.push_back(entry);
    }

    return result;
  }

  /// Admin: list email verification tokens
  json admin_list_email_verification_tokens() {
    std::shared_lock<std::shared_mutex> lock(g_email_verify_mutex);
    json result = json::array();
    int64_t now = now_ms();

    for (const auto& [thash, rec] : g_email_verify_tokens) {
      json entry;
      entry["token_hash"] = thash;
      entry["email"] = rec.email;
      entry["user_id"] = rec.user_id;
      entry["created_at"] = rec.created_at_ms;
      entry["expires_at"] = rec.expires_at_ms;
      entry["is_expired"] = rec.expires_at_ms < now;
      entry["used"] = rec.used;
      entry["validated"] = rec.validated;
      entry["send_attempt"] = rec.send_attempt;
      result.push_back(entry);
    }

    return result;
  }

  // ==========================================================================
  // Admin Token Revocation
  // ==========================================================================

  /// Admin: revoke a specific token by hash
  json admin_revoke_token_by_hash(const std::string& token_hash,
                                    const std::string& reason = "admin_revoked") {
    std::unique_lock<std::shared_mutex> lock(g_access_token_mutex);
    json result;

    auto it = g_access_tokens.find(token_hash);
    if (it == g_access_tokens.end()) {
      result["revoked"] = false;
      result["error"] = "Token hash not found";
      return result;
    }

    if (it->second.is_revoked) {
      result["revoked"] = false;
      result["error"] = "Token already revoked";
      result["previously_revoked_reason"] = it->second.revoked_reason;
      return result;
    }

    it->second.is_revoked = true;
    it->second.revoked_at_ms = now_ms();
    it->second.revoked_reason = reason;

    if (!it->second.refresh_token_hash.empty()) {
      g_refresh_to_access.erase(it->second.refresh_token_hash);
    }

    audit_log("admin_revoke", it->second.user_id, it->second.device_id, "", reason);

    result["revoked"] = true;
    result["user_id"] = it->second.user_id;
    result["device_id"] = it->second.device_id;
    return result;
  }

  /// Admin: bulk revoke all expired tokens
  json admin_revoke_expired_tokens() {
    std::unique_lock<std::shared_mutex> lock(g_access_token_mutex);
    int64_t now = now_ms();
    int count = 0;

    for (auto& [thash, rec] : g_access_tokens) {
      if (!rec.is_revoked && rec.expires_at_ms < now) {
        rec.is_revoked = true;
        rec.revoked_at_ms = now;
        rec.revoked_reason = "admin_bulk_expired";
        if (!rec.refresh_token_hash.empty()) {
          g_refresh_to_access.erase(rec.refresh_token_hash);
        }
        count++;
      }
    }

    json result;
    result["revoked_count"] = count;
    return result;
  }

  /// Admin: bulk revoke all tokens (nuclear option)
  json admin_revoke_all_tokens(const std::string& reason = "admin_bulk_revoke",
                                  std::optional<std::string> except_user = std::nullopt) {
    std::unique_lock<std::shared_mutex> lock(g_access_token_mutex);
    int64_t now = now_ms();
    int count = 0;

    for (auto& [thash, rec] : g_access_tokens) {
      if (rec.is_revoked) continue;
      if (except_user && rec.user_id == *except_user) continue;

      rec.is_revoked = true;
      rec.revoked_at_ms = now;
      rec.revoked_reason = reason;
      if (!rec.refresh_token_hash.empty()) {
        g_refresh_to_access.erase(rec.refresh_token_hash);
      }
      count++;
    }

    audit_log("admin_bulk_revoke_all", "", "", "", reason);

    json result;
    result["revoked_count"] = count;
    return result;
  }

  /// Admin: revoke tokens for a specific user
  json admin_revoke_user_tokens(const std::string& user_id,
                                  const std::string& reason = "admin_user_revoke") {
    return revoke_all_user_tokens(user_id, reason);
  }

  /// Admin: revoke tokens for a specific device
  json admin_revoke_device_tokens(const std::string& device_id,
                                    const std::string& reason = "admin_device_revoke") {
    return revoke_device_tokens(device_id, reason);
  }

  /// Admin: revoke login token
  json admin_revoke_login_token_by_hash(const std::string& token_hash) {
    std::unique_lock<std::shared_mutex> lock(g_login_token_mutex);
    json result;

    auto it = g_login_tokens.find(token_hash);
    if (it == g_login_tokens.end()) {
      result["revoked"] = false;
      result["error"] = "Login token not found";
      return result;
    }

    it->second.is_revoked = true;
    result["revoked"] = true;
    return result;
  }

  /// Admin: revoke password reset token
  json admin_revoke_password_reset_token(const std::string& token_hash) {
    std::unique_lock<std::shared_mutex> lock(g_pw_reset_mutex);
    json result;

    auto it = g_pw_reset_tokens.find(token_hash);
    if (it == g_pw_reset_tokens.end()) {
      result["revoked"] = false;
      result["error"] = "Password reset token not found";
      return result;
    }

    it->second.used = true;
    result["revoked"] = true;
    return result;
  }

  // ==========================================================================
  // Audit Log Access
  // ==========================================================================

  /// Get recent audit log entries
  json get_audit_log(int limit = 100,
                       std::optional<std::string> user_filter = std::nullopt,
                       std::optional<std::string> event_filter = std::nullopt) {
    std::shared_lock<std::shared_mutex> lock(g_audit_mutex);
    json result = json::array();

    // Iterate from newest to oldest
    auto it = g_audit_log.rbegin();
    int added = 0;
    while (it != g_audit_log.rend() && added < limit) {
      if (user_filter && it->user_id != *user_filter) { ++it; continue; }
      if (event_filter && it->event_type != *event_filter) { ++it; continue; }

      json entry;
      entry["timestamp_ms"] = it->timestamp_ms;
      entry["event_type"] = it->event_type;
      entry["user_id"] = it->user_id;
      entry["device_id"] = it->device_id;
      entry["ip_address"] = it->ip_address;
      entry["detail"] = it->detail;
      result.push_back(entry);
      added++;
      ++it;
    }

    json response;
    response["entries"] = result;
    response["total_log_size"] = g_audit_log.size();
    response["returned"] = added;
    return response;
  }

  // ==========================================================================
  // System Statistics
  // ==========================================================================

  /// Get overall token system statistics
  json get_system_stats() {
    maybe_cleanup_ratelimits();
    cleanup_expired_tokens();

    json stats;
    int64_t now = now_ms();

    // Access tokens
    {
      std::shared_lock<std::shared_mutex> lock(g_access_token_mutex);
      int total = 0, active = 0, revoked = 0, expired = 0;
      std::unordered_set<std::string> users, devices;

      for (const auto& [thash, rec] : g_access_tokens) {
        total++;
        if (rec.is_revoked) revoked++;
        else if (rec.expires_at_ms < now) expired++;
        else {
          active++;
          users.insert(rec.user_id);
          if (!rec.device_id.empty()) devices.insert(rec.device_id);
        }
      }

      stats["access_tokens"]["total"] = total;
      stats["access_tokens"]["active"] = active;
      stats["access_tokens"]["revoked"] = revoked;
      stats["access_tokens"]["expired"] = expired;
      stats["access_tokens"]["distinct_users"] = users.size();
      stats["access_tokens"]["distinct_devices"] = devices.size();
      stats["refresh_mappings"] = g_refresh_to_access.size();
    }

    // Login tokens
    {
      std::shared_lock<std::shared_mutex> lock(g_login_token_mutex);
      stats["login_tokens"]["total"] = g_login_tokens.size();
    }

    // Password reset tokens
    {
      std::shared_lock<std::shared_mutex> lock(g_pw_reset_mutex);
      stats["password_reset_tokens"]["total"] = g_pw_reset_tokens.size();
    }

    // Email verification tokens
    {
      std::shared_lock<std::shared_mutex> lock(g_email_verify_mutex);
      stats["email_verification_tokens"]["total"] = g_email_verify_tokens.size();
    }

    // Rate limits
    {
      std::shared_lock<std::shared_mutex> lock(g_ratelimit_mutex);
      stats["rate_limit_entries"] = g_ratelimit_entries.size();
    }

    // Lockouts
    {
      std::shared_lock<std::shared_mutex> lock(g_lockout_mutex);
      int locked_count = 0;
      for (const auto& [uid, rec] : g_lockouts) {
        if (rec.locked_until_ms > now) locked_count++;
      }
      stats["lockouts"]["total_tracked"] = g_lockouts.size();
      stats["lockouts"]["currently_locked"] = locked_count;
    }

    // Passwords
    {
      std::shared_lock<std::shared_mutex> lock(g_password_mutex);
      stats["stored_passwords"] = g_passwords.size();
    }

    // IP tracking
    {
      std::shared_lock<std::shared_mutex> lock(g_ip_track_mutex);
      stats["ip_tracked_users"] = g_ip_tracking.size();
    }

    // Audit log
    {
      std::shared_lock<std::shared_mutex> lock(g_audit_mutex);
      stats["audit_log_entries"] = g_audit_log.size();
      stats["audit_log_sequence"] = g_audit_sequence;
    }

    stats["timestamp_ms"] = now;

    return stats;
  }

  // ==========================================================================
  // Utility — Token Count for a User
  // ==========================================================================

  /// Count active access tokens for a user
  int count_active_tokens(const std::string& user_id) {
    std::shared_lock<std::shared_mutex> lock(g_access_token_mutex);
    auto it = g_access_tokens_by_user.find(user_id);
    if (it == g_access_tokens_by_user.end()) return 0;

    int64_t now = now_ms();
    int count = 0;
    for (const auto& thash : it->second) {
      auto ait = g_access_tokens.find(thash);
      if (ait == g_access_tokens.end() || ait->second.is_revoked) continue;
      if (ait->second.expires_at_ms >= now) count++;
    }
    return count;
  }

  /// Count total tokens (all states) for a user
  int count_total_tokens(const std::string& user_id) {
    std::shared_lock<std::shared_mutex> lock(g_access_token_mutex);
    auto it = g_access_tokens_by_user.find(user_id);
    if (it == g_access_tokens_by_user.end()) return 0;
    return static_cast<int>(it->second.size());
  }

  // ==========================================================================
  // Force cleanup
  // ==========================================================================

  /// Force immediate cleanup of expired tokens
  json force_cleanup() {
    g_last_token_cleanup_ms.store(0, std::memory_order_relaxed);
    g_last_ratelimit_cleanup_ms.store(0, std::memory_order_relaxed);
    cleanup_expired_tokens();

    std::unique_lock<std::shared_mutex> lock(g_ratelimit_mutex);
    int64_t window_ms = RATE_LIMIT_WINDOW_SEC * 1000LL;
    prune_ratelimit_entries(window_ms);

    return get_system_stats();
  }

  // ==========================================================================
  // Login flow: combined password check + rate limit + lockout
  // ==========================================================================

  /// Attempt a full login with password, respecting rate limits and lockout
  json attempt_login(const std::string& user_id,
                      std::string_view password,
                      const std::string& ip_address = "",
                      const std::string& user_agent = "",
                      const std::string& device_id = "") {
    json result;

    // Step 1: Check lockout
    if (is_locked_out(user_id)) {
      int64_t remaining = lockout_remaining_sec(user_id);
      result["success"] = false;
      result["error"] = "Account is temporarily locked due to too many failed attempts";
      result["errcode"] = "M_LIMIT_EXCEEDED";
      result["retry_after_ms"] = remaining * 1000LL;
      result["locked_out"] = true;
      return result;
    }

    // Step 2: Rate limit check
    auto rl = check_login_rate_limit(user_id, ip_address);
    if (!rl["allowed"].get<bool>()) {
      rl["success"] = false;
      return rl;
    }

    // Step 3: Verify password
    if (!verify_password(user_id, password)) {
      record_failed_login_attempt(user_id, ip_address);

      result["success"] = false;
      result["error"] = "Invalid username or password";
      result["errcode"] = "M_FORBIDDEN";

      // Check if this failure triggered lockout
      if (is_locked_out(user_id)) {
        result["locked_out"] = true;
        result["retry_after_ms"] = lockout_remaining_sec(user_id) * 1000LL;
      }

      return result;
    }

    // Step 4: Success — record, create token
    record_successful_login(user_id, ip_address);

    auto token_result = create_access_token(user_id, device_id,
                                              std::nullopt, std::nullopt,
                                              ip_address, user_agent);

    result["success"] = true;
    result["user_id"] = user_id;
    result["access_token"] = token_result["access_token"];
    result["refresh_token"] = token_result["refresh_token"];
    result["device_id"] = token_result["device_id"];
    result["expires_in_ms"] = token_result["expires_in_ms"];

    return result;
  }

  /// Attempt login using a login token (Matrix login token flow)
  json attempt_login_with_token(std::string_view login_token,
                                  const std::string& ip_address = "",
                                  const std::string& user_agent = "",
                                  const std::string& device_id = "") {
    json result;

    auto verify_result = verify_login_token(login_token);
    if (!verify_result["valid"].get<bool>()) {
      verify_result["success"] = false;
      return verify_result;
    }

    std::string user_id = verify_result["user_id"].get<std::string>();

    // Check lockout
    if (is_locked_out(user_id)) {
      int64_t remaining = lockout_remaining_sec(user_id);
      result["success"] = false;
      result["error"] = "Account is temporarily locked";
      result["errcode"] = "M_LIMIT_EXCEEDED";
      result["retry_after_ms"] = remaining * 1000LL;
      return result;
    }

    // Create access token
    auto token_result = create_access_token(user_id, device_id,
                                              std::nullopt, std::nullopt,
                                              ip_address, user_agent);

    record_successful_login(user_id, ip_address);

    result["success"] = true;
    result["user_id"] = user_id;
    result["access_token"] = token_result["access_token"];
    result["refresh_token"] = token_result["refresh_token"];
    result["device_id"] = token_result["device_id"];
    result["expires_in_ms"] = token_result["expires_in_ms"];

    return result;
  }

  // ==========================================================================
  // Logout
  // ==========================================================================

  /// Logout — revoke a specific access token
  json logout(std::string_view access_token, const std::string& ip_address = "") {
    std::string thash = hash_token(access_token);
    std::unique_lock<std::shared_mutex> lock(g_access_token_mutex);

    auto it = g_access_tokens.find(thash);
    json result;

    if (it == g_access_tokens.end()) {
      result["success"] = false;
      result["error"] = "Token not found";
      return result;
    }

    if (it->second.is_revoked) {
      result["success"] = true;  // idempotent
      result["already_revoked"] = true;
      return result;
    }

    it->second.is_revoked = true;
    it->second.revoked_at_ms = now_ms();
    it->second.revoked_reason = "user_logout";

    if (!it->second.refresh_token_hash.empty()) {
      g_refresh_to_access.erase(it->second.refresh_token_hash);
    }

    audit_log("logout", it->second.user_id, it->second.device_id, ip_address, "");

    result["success"] = true;
    return result;
  }

  /// Logout all sessions for a user
  json logout_all(const std::string& user_id, const std::string& ip_address = "") {
    auto result = revoke_all_user_tokens(user_id, "user_logout_all");
    audit_log("logout_all", user_id, "", ip_address, "");
    json out;
    out["success"] = true;
    out["revoked_count"] = result["revoked_count"];
    return out;
  }
};

/* ============================================================================
 * Singleton Access
 * ========================================================================== */

static std::unique_ptr<LoginTokenManager> g_instance;
static std::mutex g_instance_mutex;

LoginTokenManager& get_login_token_manager() {
  if (!g_instance) {
    std::lock_guard<std::mutex> lock(g_instance_mutex);
    if (!g_instance) {
      g_instance = std::make_unique<LoginTokenManager>();
    }
  }
  return *g_instance;
}

/* ============================================================================
 * C-Friendly Wrapper Functions
 *
 * These are the primary entry points used by the rest of the codebase.
 * ========================================================================== */

// --- Password ---

std::string hash_password(const std::string& password) {
  return get_login_token_manager().hash_password(password);
}

bool verify_password(const std::string& user_id, const std::string& password) {
  return get_login_token_manager().verify_password(user_id, password);
}

void store_password(const std::string& user_id, const std::string& hashed) {
  get_login_token_manager().store_password(user_id, hashed);
}

std::string hash_and_store_password(const std::string& user_id,
                                     const std::string& password) {
  return get_login_token_manager().hash_and_store_password(user_id, password);
}

json validate_password_strength(const std::string& password) {
  return get_login_token_manager().validate_password_strength(password);
}

// --- Login Tokens ---

json create_login_token(const std::string& user_id, std::optional<int64_t> ttl) {
  return get_login_token_manager().create_login_token(user_id, ttl);
}

json verify_login_token(const std::string& token) {
  return get_login_token_manager().verify_login_token(token);
}

// --- Access Tokens ---

json create_access_token(const std::string& user_id, const std::string& device_id,
                           const std::string& ip, const std::string& ua) {
  return get_login_token_manager().create_access_token(user_id, device_id,
                                                         std::nullopt, std::nullopt,
                                                         ip, ua);
}

json create_access_token_full(const std::string& user_id, const std::string& device_id,
                                int64_t access_ttl, int64_t refresh_ttl,
                                const std::string& ip, const std::string& ua) {
  return get_login_token_manager().create_access_token(user_id, device_id,
                                                         access_ttl, refresh_ttl,
                                                         ip, ua);
}

json verify_access_token(const std::string& token, const std::string& ip) {
  return get_login_token_manager().verify_access_token(token, ip);
}

json refresh_access_token(const std::string& refresh_token,
                            const std::string& ip, const std::string& ua) {
  return get_login_token_manager().refresh_access_token(refresh_token, ip, ua);
}

// --- Revocation ---

json revoke_access_token(const std::string& token, const std::string& reason) {
  return get_login_token_manager().revoke_access_token(token, reason);
}

json revoke_all_user_tokens(const std::string& user_id, const std::string& reason) {
  return get_login_token_manager().revoke_all_user_tokens(user_id, reason);
}

json revoke_device_tokens(const std::string& device_id, const std::string& reason) {
  return get_login_token_manager().revoke_device_tokens(device_id, reason);
}

// --- Session & Device ---

json list_user_sessions(const std::string& user_id) {
  return get_login_token_manager().list_user_sessions(user_id);
}

json get_session_info(const std::string& token) {
  return get_login_token_manager().get_session_info(token);
}

json list_device_tokens(const std::string& device_id) {
  return get_login_token_manager().list_device_tokens(device_id);
}

int count_user_devices(const std::string& user_id) {
  return get_login_token_manager().count_user_devices(user_id);
}

json get_user_session_stats(const std::string& user_id) {
  return get_login_token_manager().get_user_session_stats(user_id);
}

// --- IP Tracking ---

bool update_token_ip(const std::string& token, const std::string& ip) {
  return get_login_token_manager().update_token_ip(token, ip);
}

json get_user_ip_history(const std::string& user_id) {
  return get_login_token_manager().get_user_ip_history(user_id);
}

json check_ip_anomaly(const std::string& user_id, const std::string& ip) {
  return get_login_token_manager().check_ip_anomaly(user_id, ip);
}

// --- Rate Limiting & Lockout ---

json check_login_rate_limit(const std::string& user_id, const std::string& ip) {
  return get_login_token_manager().check_login_rate_limit(user_id, ip);
}

void record_failed_login_attempt(const std::string& user_id, const std::string& ip) {
  get_login_token_manager().record_failed_login_attempt(user_id, ip);
}

void record_successful_login(const std::string& user_id, const std::string& ip) {
  get_login_token_manager().record_successful_login(user_id, ip);
}

bool is_account_locked(const std::string& user_id) {
  return get_login_token_manager().is_account_locked(user_id);
}

json get_lockout_status(const std::string& user_id) {
  return get_login_token_manager().get_lockout_status(user_id);
}

json get_rate_limit_status(const std::string& user_id, const std::string& ip) {
  return get_login_token_manager().get_rate_limit_status(user_id, ip);
}

// --- Password Reset ---

json create_password_reset_token(const std::string& user_id, std::optional<int64_t> ttl) {
  return get_login_token_manager().create_password_reset_token(user_id, ttl);
}

json verify_password_reset_token(const std::string& token) {
  return get_login_token_manager().verify_password_reset_token(token);
}

json reset_password_with_token(const std::string& token, const std::string& new_password) {
  return get_login_token_manager().reset_password_with_token(token, new_password);
}

// --- Email Verification ---

json create_email_verification_token(const std::string& email,
                                       const std::string& client_secret,
                                       int send_attempt,
                                       const std::string& user_id) {
  return get_login_token_manager().create_email_verification_token(
      email, client_secret, send_attempt, user_id);
}

json validate_email_verification_token(const std::string& token) {
  return get_login_token_manager().validate_email_verification_token(token);
}

bool is_email_verified(const std::string& email) {
  return get_login_token_manager().is_email_verified(email);
}

// --- Admin ---

json admin_list_tokens(const std::string& user_filter, int limit, int offset) {
  std::optional<std::string> uf;
  if (!user_filter.empty()) uf = user_filter;
  return get_login_token_manager().admin_list_tokens(uf, std::nullopt, std::nullopt,
                                                       limit, offset);
}

json admin_list_all_tokens(int limit, int offset) {
  return get_login_token_manager().admin_list_tokens(std::nullopt, std::nullopt,
                                                       std::nullopt, limit, offset);
}

json admin_list_login_tokens() {
  return get_login_token_manager().admin_list_login_tokens();
}

json admin_list_password_reset_tokens() {
  return get_login_token_manager().admin_list_password_reset_tokens();
}

json admin_list_email_verification_tokens() {
  return get_login_token_manager().admin_list_email_verification_tokens();
}

json admin_revoke_token(const std::string& token_hash, const std::string& reason) {
  return get_login_token_manager().admin_revoke_token_by_hash(token_hash, reason);
}

json admin_revoke_user_tokens(const std::string& user_id, const std::string& reason) {
  return get_login_token_manager().admin_revoke_user_tokens(user_id, reason);
}

json admin_revoke_device_tokens(const std::string& device_id, const std::string& reason) {
  return get_login_token_manager().admin_revoke_device_tokens(device_id, reason);
}

json admin_revoke_all_tokens(const std::string& reason) {
  return get_login_token_manager().admin_revoke_all_tokens(reason);
}

json admin_revoke_expired_tokens() {
  return get_login_token_manager().admin_revoke_expired_tokens();
}

json admin_unlock_account(const std::string& user_id) {
  return get_login_token_manager().admin_unlock_account(user_id);
}

json admin_lock_account(const std::string& user_id, int64_t duration_sec) {
  return get_login_token_manager().admin_lock_account(user_id, duration_sec);
}

// --- Audit ---

json get_audit_log(int limit) {
  return get_login_token_manager().get_audit_log(limit);
}

// --- Stats & Utility ---

json get_token_system_stats() {
  return get_login_token_manager().get_system_stats();
}

json force_token_cleanup() {
  return get_login_token_manager().force_cleanup();
}

int count_active_tokens(const std::string& user_id) {
  return get_login_token_manager().count_active_tokens(user_id);
}

int count_total_tokens(const std::string& user_id) {
  return get_login_token_manager().count_total_tokens(user_id);
}

bool touch_token(const std::string& token, const std::string& ip) {
  return get_login_token_manager().touch_token(token, ip);
}

bool is_token_expired(const std::string& token) {
  return get_login_token_manager().is_token_expired(token);
}

json extend_token_expiry(const std::string& token, int64_t seconds) {
  return get_login_token_manager().extend_token_expiry(token, seconds);
}

// --- Full Login Flow ---

json attempt_login(const std::string& user_id, const std::string& password,
                     const std::string& ip, const std::string& ua,
                     const std::string& device_id) {
  return get_login_token_manager().attempt_login(user_id, password, ip, ua, device_id);
}

json attempt_login_with_token(const std::string& login_token,
                                const std::string& ip, const std::string& ua,
                                const std::string& device_id) {
  return get_login_token_manager().attempt_login_with_token(login_token, ip, ua, device_id);
}

// --- Logout ---

json logout(const std::string& token, const std::string& ip) {
  return get_login_token_manager().logout(token, ip);
}

json logout_all(const std::string& user_id, const std::string& ip) {
  return get_login_token_manager().logout_all(user_id, ip);
}

}  // namespace auth
}  // namespace progressive

/* ============================================================================
 * End of LoginTokenManager
 *
 * This module provides complete Matrix authentication token lifecycle
 * management with password hashing, multi-format token generation,
 * rate limiting, lockout protection, device/session tracking, IP
 * anomaly detection, admin inspection and revocation, and audit logging.
 * ========================================================================== */
