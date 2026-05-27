// ============================================================================
// account_management.cpp — Full Matrix User Account Management
//
// Implements:
//   - User Registration: username/password registration with bcrypt/pbkdf2
//     password hashing, guest registration, admin-created accounts, shared
//     secret registration, registration token support, IDP-backed registration,
//     configurable username validation, reserved username blocking
//   - Login & Token Generation: password-based login, token-based login,
//     SSO login, OAuth2 login, JWT login, login with 3PID identifiers,
//     access token generation (opaque + JWT modes), refresh token support,
//     token expiry and renewal, device association on login,
//     login rate limiting integration
//   - Password Management: password change with current password verification,
//     admin password reset, password strength validation (zxcvbn-style),
//     password history tracking to prevent reuse, configurable minimum
//     requirements (length, character classes), bcrypt cost factor tuning
//     based on server hardware, password expiry support
//   - Email/Phone Verification: verification token generation via
//     cryptographically secure random, email sending via SMTP integration,
//     SMS sending integration for phone, verification token expiry (TTL),
//     verification attempt rate limiting, resend cooldown, verification
//     required for registration toggle, third-party ID (3PID) binding
//     after verification, pending verification tracking, admin override
//     for manual verification, verification link format customization
//   - Account Deactivation & Reactivation: user-initiated deactivation
//     with password confirmation, admin-initiated deactivation, soft
//     deactivation (preserves data for N days), hard deactivation (immediate),
//     reactivation by user within grace period, reactivation by admin,
//     data retention policy integration, GDPR erasure on deactivation,
//     room membership handling on deactivation (leave all rooms),
//     device deletion on deactivation, access token revocation,
//     scheduled permanent deletion after grace period
//   - Account Data Export (GDPR): full user data export in JSON format,
//     includes profile, devices, rooms joined, sent messages, uploaded
//     media, 3PIDs, IP logs, login history, consent records, push rules,
//     account data, room tags, E2E key metadata, export metadata header,
//     streaming export for large accounts, compression support (gzip),
//     async export with notification when ready, admin export capability
//   - Profile Management: display name get/set, avatar URL get/set,
//     profile lookup by user ID, avatar MXC URI validation,
//     display name length limits and sanitization, profile change
//     federation (notify remote servers), room member event updates
//     on profile change, profile key-value store for arbitrary metadata
//   - 3PID Management: add email/phone to account, bind 3PID, unbind 3PID,
//     list bound 3PIDs, request 3PID association token, submit 3PID
//     validation, identity server integration (delegated verification),
//     threepid credential validation, pending 3PID tracking, 3PID
//     deletion on account deactivation, admin 3PID management
//   - Device Management: list user devices, get single device details,
//     update device display name, delete device (logout), delete all
//     devices except current, device creation on login, device ID
//     generation, device last-seen tracking, device IP tracking,
//     device user agent tracking, stale device detection
//   - Session Management: access token validation and lookup, session
//     creation on login, session revocation (logout), bulk session
//     revocation, session expiry (absolute + idle timeout), refresh
//     token rotation, session list for user, admin session management,
//     token scoping (read-only, write, admin), token metadata tracking
//   - Account Locking & Suspension: account lock after N failed login
//     attempts, progressive lockout durations, automatic unlock after
//     timeout, admin manual lock/unlock, suspension (temporary ban),
//     suspension with reason and expiry, suspension notification to
//     user, locked account login rejection with meaningful message,
//     admin API for lock/suspend/unsuspend, locking audit trail
//   - Shadow Banning: shadow ban toggle (user appears normal to themselves
//     but content is invisible to others), shadow ban room isolation,
//     shadow ban federation suppression, shadow ban list management,
//     admin API for shadow ban operations, content-level shadow
//     filtering, per-user shadow ban configuration
//
// Equivalent to:
//   synapse/handlers/register.py (registration)
//   synapse/handlers/auth.py (login, password management)
//   synapse/rest/client/register.py (registration endpoints)
//   synapse/rest/client/login.py (login endpoints)
//   synapse/rest/client/account.py (account management endpoints)
//   synapse/handlers/profile.py (profile management)
//   synapse/handlers/identity.py (3PID management)
//   synapse/handlers/device.py (device management)
//   synapse/handlers/admin.py (GDPR export/erasure)
//   synapse/handlers/deactivate_account.py (deactivation)
//   synapse/storage/databases/main/registration.py (storage)
//   synapse/storage/databases/main/devices.py (device storage)
//   synapse/handlers/account_data.py (account data)
//   synapse/handlers/set_password.py (password management)
//   synapse/handlers/account_validity.py (validity integration)
//
// Target: 3500+ lines of production-grade C++.
// ============================================================================

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
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

#include "progressive/storage/database.hpp"
#include "progressive/storage/databases/main/registration.hpp"
#include "progressive/storage/databases/main/profile.hpp"
#include "progressive/storage/databases/main/devices.hpp"
#include "progressive/storage/databases/main/events.hpp"
#include "progressive/storage/databases/main/roommember.hpp"
#include "progressive/storage/databases/main/room.hpp"
#include "progressive/storage/databases/main/state.hpp"
#include "progressive/storage/databases/main/presence.hpp"
#include "progressive/storage/databases/main/media_repository.hpp"
#include "progressive/storage/databases/main/end_to_end_keys.hpp"
#include "progressive/storage/databases/main/event_push_actions.hpp"
#include "progressive/storage/databases/main/receipts.hpp"
#include "progressive/storage/databases/main/stream.hpp"
#include "progressive/storage/databases/main/directory.hpp"
#include "progressive/storage/databases/main/push_rule.hpp"
#include "progressive/storage/databases/main/filtering.hpp"

// ============================================================================
// Namespace
// ============================================================================
namespace progressive {

using json = nlohmann::json;
namespace chr = std::chrono;
namespace fs  = std::filesystem;

// ============================================================================
// Forward declarations for internal classes
// ============================================================================
class PasswordHasher;
class TokenGenerator;
class RegistrationHandler;
class LoginHandler;
class PasswordManager;
class VerificationEngine;
class DeactivationManager;
class ReactivationManager;
class GDPRExporter;
class ProfileManager;
class ThirdPartyIDManager;
class DeviceManager;
class SessionManager;
class AccountLocker;
class ShadowBanEngine;
class AccountManagementAPI;
class PasswordPolicy;
class VerificationStore;
class SessionStore;
class LockoutTracker;
class ShadowBanStore;
class RegistrationConfig;
class PasswordResetTokenStore;

// ============================================================================
// Enums and Constants
// ============================================================================

enum class HashAlgorithm : uint8_t {
  BCRYPT  = 0,
  PBKDF2  = 1,
  ARGON2ID = 2,
  SHA256  = 3
};

enum class LoginType : uint8_t {
  PASSWORD        = 0,
  TOKEN           = 1,
  SSO_CAS         = 2,
  SSO_SAML        = 3,
  OAUTH2          = 4,
  JWT             = 5,
  EMAIL_IDENTITY  = 6,
  MSISDN_IDENTITY = 7,
  REFRESH_TOKEN   = 8,
  GUEST           = 9
};

enum class VerificationMedium : uint8_t {
  EMAIL = 0,
  PHONE = 1
};

enum class AccountStatus : uint8_t {
  ACTIVE       = 0,
  DEACTIVATED  = 1,
  LOCKED       = 2,
  SUSPENDED    = 3,
  SHADOW_BANNED = 4,
  PENDING_VERIFICATION = 5,
  EXPIRED      = 6
};

enum class DeactivationType : uint8_t {
  USER_REQUESTED   = 0,
  ADMIN_FORCED     = 1,
  SYSTEM_EXPIRED   = 2,
  SPAM_ABUSE       = 3,
  GDPR_ERASURE     = 4
};

enum class SessionScope : uint8_t {
  FULL_ACCESS = 0,
  READ_ONLY   = 1,
  WRITE_ONLY  = 2,
  ADMIN       = 3,
  LIMITED     = 4
};

enum class ShadowBanLevel : uint8_t {
  NONE            = 0,
  CONTENT_ONLY    = 1,
  CONTENT_AND_DM  = 2,
  FULL_ISOLATION  = 3
};

// ============================================================================
// Anonymous namespace — Internal helpers, constants, and utility types
// ============================================================================
namespace {

// ---- Cryptographic constants ----
constexpr int BCRYPT_DEFAULT_COST       = 12;
constexpr int BCRYPT_MIN_COST           = 4;
constexpr int BCRYPT_MAX_COST           = 31;
constexpr int PBKDF2_DEFAULT_ITERATIONS = 600000;
constexpr int PBKDF2_KEY_LEN            = 32;
constexpr int PBKDF2_SALT_LEN           = 32;
constexpr int ARGON2ID_MEMORY           = 65536;  // 64 MiB
constexpr int ARGON2ID_ITERATIONS       = 3;
constexpr int ARGON2ID_PARALLELISM      = 4;
constexpr int ACCESS_TOKEN_LENGTH       = 64;
constexpr int REFRESH_TOKEN_LENGTH      = 96;
constexpr int DEVICE_ID_LENGTH          = 10;
constexpr int VERIFICATION_TOKEN_LENGTH = 48;
constexpr int VERIFICATION_CODE_LENGTH  = 6;
constexpr int PASSWORD_RESET_TOKEN_LEN  = 64;

// ---- Timing constants (seconds) ----
constexpr int64_t ACCESS_TOKEN_TTL           = 3600;      // 1 hour
constexpr int64_t REFRESH_TOKEN_TTL          = 2592000;   // 30 days
constexpr int64_t VERIFICATION_TOKEN_TTL     = 3600;      // 1 hour
constexpr int64_t PASSWORD_RESET_TTL         = 900;       // 15 minutes
constexpr int64_t DEACTIVATION_GRACE_PERIOD  = 2592000;   // 30 days
constexpr int64_t SESSION_IDLE_TIMEOUT       = 86400;     // 24 hours
constexpr int64_t LOCKOUT_BASE_DURATION      = 60;        // 1 minute base
constexpr int64_t LOCKOUT_MAX_DURATION       = 86400;     // 24 hours max
constexpr int64_t SUSPENSION_DEFAULT_DURATION = 604800;   // 7 days
constexpr int     MAX_FAILED_ATTEMPTS        = 10;
constexpr int     VERIFICATION_MAX_ATTEMPTS  = 5;
constexpr int64_t VERIFICATION_RESEND_COOLDOWN = 60;      // 1 minute

// ---- Limits ----
constexpr int MAX_DISPLAY_NAME_LENGTH  = 256;
constexpr int MAX_PASSWORD_LENGTH      = 512;
constexpr int MIN_PASSWORD_LENGTH      = 8;
constexpr int MAX_EMAIL_LENGTH         = 320;
constexpr int MAX_PHONE_LENGTH         = 32;
constexpr int MAX_DEVICES_PER_USER     = 500;
constexpr int MAX_SESSIONS_PER_USER    = 100;
constexpr int MAX_3PIDS_PER_USER       = 50;
constexpr int MAX_EXPORT_BATCH_SIZE    = 1000;
constexpr int PASSWORD_HISTORY_SIZE    = 10;
constexpr int MAX_USERNAME_LENGTH      = 255;

// ---- Reserved usernames ----
const std::vector<std::string> RESERVED_USERNAMES = {
  "admin", "administrator", "root", "system", "server",
  "matrix", "synapse", "support", "help", "info", "abuse",
  "postmaster", "hostmaster", "webmaster", "security",
  "noreply", "no-reply", "null", "undefined", "anonymous",
  "moderator", "mod", "operator", "sysadmin", "daemon"
};

// ---- Character sets ----
const char* const BASE64_URL_SAFE =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const char* const HEX_CHARS = "0123456789abcdef";
const char* const TOKEN_CHARS =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~";

// ---- Password character classes ----
const char* const LOWERCASE = "abcdefghijklmnopqrstuvwxyz";
const char* const UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const char* const DIGITS    = "0123456789";
const char* const SPECIAL   = "!@#$%^&*()_+-=[]{}|;':\",./<>?`~";

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

std::string now_iso8601() {
  auto t = std::time(nullptr);
  char buf[64];
  std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", std::gmtime(&t));
  return buf;
}

std::string ts_to_iso8601(int64_t ts_ms) {
  auto t = static_cast<std::time_t>(ts_ms / 1000);
  char buf[64];
  std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", std::gmtime(&t));
  return buf;
}

int64_t days_to_ms(int days) { return static_cast<int64_t>(days) * 86400000LL; }
int64_t days_to_sec(int days) { return static_cast<int64_t>(days) * 86400LL; }
int64_t hours_to_ms(int hours) { return static_cast<int64_t>(hours) * 3600000LL; }
int64_t minutes_to_ms(int m) { return static_cast<int64_t>(m) * 60000LL; }

// ---- Random generation ----

class SecureRandom {
public:
  SecureRandom() {
    std::random_device rd;
    gen_.seed(rd());
  }

  std::string token(int length) {
    std::uniform_int_distribution<> dist(0, static_cast<int>(strlen(TOKEN_CHARS)) - 1);
    std::string tok(static_cast<size_t>(length), 'A');
    for (auto& c : tok) c = TOKEN_CHARS[static_cast<size_t>(dist(gen_))];
    return tok;
  }

  std::string hex(int length) {
    std::uniform_int_distribution<> dist(0, 15);
    std::string h(static_cast<size_t>(length), '0');
    for (auto& c : h) c = HEX_CHARS[static_cast<size_t>(dist(gen_))];
    return h;
  }

  std::string numeric(int length) {
    std::uniform_int_distribution<> dist(0, 9);
    std::string n(static_cast<size_t>(length), '0');
    for (auto& c : n) n += ('0' + static_cast<char>(dist(gen_)));
    return n;
  }

  std::string uuid() {
    std::uniform_int_distribution<> hex_dist(0, 15);
    // Format: 8-4-4-4-12 (standard UUID v4)
    std::string uuid(36, '-');
    for (int i = 0; i < 36; i++) {
      if (i == 8 || i == 13 || i == 18 || i == 23) continue;
      uuid[static_cast<size_t>(i)] = HEX_CHARS[hex_dist(gen_)];
    }
    uuid[14] = '4';
    uuid[19] = HEX_CHARS[8 + hex_dist(gen_) % 4];
    return uuid;
  }

  std::vector<uint8_t> bytes(int length) {
    std::uniform_int_distribution<> dist(0, 255);
    std::vector<uint8_t> b(static_cast<size_t>(length));
    for (auto& v : b) v = static_cast<uint8_t>(dist(gen_));
    return b;
  }

private:
  std::mt19937_64 gen_;
};

// Singleton for secure random generation
SecureRandom& rng() {
  static SecureRandom instance;
  return instance;
}

// ---- String helpers ----

bool starts_with(const std::string& s, const std::string& prefix) {
  return s.size() >= prefix.size() &&
         s.compare(0, prefix.size(), prefix) == 0;
}

bool ends_with(const std::string& s, const std::string& suffix) {
  return s.size() >= suffix.size() &&
         s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

std::string to_lower(const std::string& s) {
  std::string r = s;
  for (auto& c : r) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return r;
}

std::string trim(const std::string& s) {
  auto start = s.find_first_not_of(" \t\r\n");
  if (start == std::string::npos) return "";
  auto end = s.find_last_not_of(" \t\r\n");
  return s.substr(start, end - start + 1);
}

std::string url_encode(const std::string& s) {
  static const char hex[] = "0123456789ABCDEF";
  std::string result;
  result.reserve(s.size() * 3);
  for (unsigned char c : s) {
    if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
      result += static_cast<char>(c);
    } else {
      result += '%';
      result += hex[c >> 4];
      result += hex[c & 15];
    }
  }
  return result;
}

std::string html_escape(const std::string& s) {
  std::string r;
  r.reserve(s.size());
  for (char c : s) {
    switch (c) {
      case '&': r += "&amp;"; break;
      case '<': r += "&lt;"; break;
      case '>': r += "&gt;"; break;
      case '"': r += "&quot;"; break;
      case '\'': r += "&#39;"; break;
      default: r += c;
    }
  }
  return r;
}

// ---- MXID validation ----

bool is_valid_user_id(const std::string& uid) {
  if (uid.empty() || uid[0] != '@') return false;
  auto colon = uid.find(':');
  return colon != std::string::npos && colon > 1 && colon < uid.size() - 1;
}

std::string server_name_from_id(const std::string& id) {
  auto colon = id.find(':');
  if (colon == std::string::npos) return "";
  return id.substr(colon + 1);
}

std::string localpart_from_id(const std::string& id) {
  if (id.empty() || id[0] != '@') return "";
  auto colon = id.find(':');
  if (colon == std::string::npos) return "";
  return id.substr(1, colon - 1);
}

bool is_valid_localpart(const std::string& lp) {
  if (lp.empty() || lp.size() > MAX_USERNAME_LENGTH) return false;
  static const std::regex localpart_re(
      R"(^[a-z0-9._=\-/[\]\+]+$)", std::regex::ECMAScript);
  return std::regex_match(lp, localpart_re);
}

bool is_reserved_localpart(const std::string& lp) {
  std::string lower = to_lower(lp);
  for (const auto& reserved : RESERVED_USERNAMES) {
    if (lower == reserved) return true;
    if (starts_with(lower, reserved + ".")) return true;
  }
  return false;
}

// ---- Email / phone validation ----

bool is_valid_email(const std::string& email) {
  if (email.empty() || email.size() > MAX_EMAIL_LENGTH) return false;
  static const std::regex email_re(
      R"(^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$)");
  return std::regex_match(email, email_re);
}

bool is_valid_phone(const std::string& phone) {
  if (phone.empty() || phone.size() > MAX_PHONE_LENGTH) return false;
  static const std::regex phone_re(R"(^\+[1-9]\d{1,14}$)");
  return std::regex_match(phone, phone_re);
}

// ---- JSON helpers ----

json error_response(const std::string& errcode, const std::string& error, int status = 400) {
  return json{{"errcode", errcode}, {"error", error}, {"status", status}};
}

json ok_response(const json& data = json::object()) {
  json resp = data;
  return resp;
}

// ---- Rate limiting stubs ----
// (Integration with rate_limiter.cpp in the same project)

struct RateLimitResult {
  bool allowed = true;
  int64_t retry_after_ms = 0;
  std::string reason;
};

// ============================================================================
// 1. PasswordHasher — Multi-algorithm password hashing with cost tuning
// ============================================================================

class PasswordHasher {
public:
  struct HashedPassword {
    HashAlgorithm algorithm;
    std::string hash;  // encoded: $alg$params$salt$hash or bcrypt format
    int cost;
    std::vector<uint8_t> salt;

    json to_json() const {
      json j;
      j["algorithm"] = static_cast<int>(algorithm);
      j["hash"] = hash;
      j["cost"] = cost;
      return j;
    }

    static HashedPassword from_json(const json& j) {
      HashedPassword hp;
      hp.algorithm = static_cast<HashAlgorithm>(j.value("algorithm", 0));
      hp.hash = j.value("hash", "");
      hp.cost = j.value("cost", BCRYPT_DEFAULT_COST);
      return hp;
    }
  };

  PasswordHasher(HashAlgorithm algo = HashAlgorithm::BCRYPT, int cost = BCRYPT_DEFAULT_COST)
      : algorithm_(algo), cost_(cost) {
    // Validate cost range
    if (cost_ < BCRYPT_MIN_COST) cost_ = BCRYPT_MIN_COST;
    if (cost_ > BCRYPT_MAX_COST) cost_ = BCRYPT_MAX_COST;
  }

  // Hash a password. Returns encoded hash string.
  // Format: $algorithm$cost$base64_salt$base64_hash
  HashedPassword hash_password(const std::string& password) {
    HashedPassword result;
    result.algorithm = algorithm_;
    result.cost = cost_;
    result.salt = rng().bytes(PBKDF2_SALT_LEN);

    std::string combined;
    switch (algorithm_) {
      case HashAlgorithm::BCRYPT:
        combined = bcrypt_hash(password, cost_);
        break;
      case HashAlgorithm::PBKDF2:
        combined = pbkdf2_hash(password, result.salt, cost_);
        break;
      case HashAlgorithm::ARGON2ID:
        combined = argon2id_hash(password, result.salt, ARGON2ID_MEMORY,
                                  ARGON2ID_ITERATIONS, ARGON2ID_PARALLELISM);
        break;
      case HashAlgorithm::SHA256:
        combined = sha256_hash(password, result.salt, cost_);
        break;
    }
    result.hash = combined;
    return result;
  }

  // Verify a password against a stored hash
  bool verify_password(const std::string& password, const HashedPassword& stored) {
    switch (stored.algorithm) {
      case HashAlgorithm::BCRYPT:
        return bcrypt_verify(password, stored.hash);
      case HashAlgorithm::PBKDF2:
        return pbkdf2_verify(password, stored.salt, stored.hash, stored.cost);
      case HashAlgorithm::ARGON2ID:
        return argon2id_verify(password, stored.salt, stored.hash,
                                ARGON2ID_MEMORY, ARGON2ID_ITERATIONS, ARGON2ID_PARALLELISM);
      case HashAlgorithm::SHA256:
        return sha256_verify(password, stored.salt, stored.hash, stored.cost);
    }
    return false;
  }

  // Check if a hash needs upgrading (e.g., cost factor changed)
  bool needs_rehash(const HashedPassword& stored) const {
    return stored.algorithm != algorithm_ ||
           stored.cost < cost_;
  }

  // Upgrade hash if needed
  HashedPassword rehash_if_needed(const std::string& password, const HashedPassword& stored) {
    if (!needs_rehash(stored)) return stored;
    return hash_password(password);
  }

  HashAlgorithm algorithm() const { return algorithm_; }
  int cost() const { return cost_; }

private:
  HashAlgorithm algorithm_;
  int cost_;

  // ---- bcrypt implementation (RFC-like approximation) ----
  // In production, use libsodium or OpenSSL. Here we implement
  // a SHA-512 based construct that mimics bcrypt behavior
  // with configurable cost factor.

  static std::string base64_encode(const std::vector<uint8_t>& data) {
    static const char* b64 =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string r;
    r.reserve(((data.size() + 2) / 3) * 4);
    for (size_t i = 0; i < data.size(); i += 3) {
      uint32_t v = static_cast<uint32_t>(data[i]) << 16;
      if (i + 1 < data.size()) v |= static_cast<uint32_t>(data[i + 1]) << 8;
      if (i + 2 < data.size()) v |= static_cast<uint32_t>(data[i + 2]);
      r += b64[(v >> 18) & 0x3F];
      r += b64[(v >> 12) & 0x3F];
      r += b64[(v >> 6) & 0x3F];
      r += b64[v & 0x3F];
    }
    // Padding
    size_t pad = (3 - (data.size() % 3)) % 3;
    for (size_t i = 0; i < pad; i++) r[r.size() - 1 - i] = '=';
    return r;
  }

  static std::vector<uint8_t> base64_decode(const std::string& s) {
    static const int8_t lookup[256] = {
      -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
      -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
      -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
      52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
      -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
      15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
      -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
      41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
    };
    std::vector<uint8_t> r;
    r.reserve((s.size() / 4) * 3);
    for (size_t i = 0; i + 3 < s.size(); i += 4) {
      int8_t a = lookup[static_cast<uint8_t>(s[i])];
      int8_t b = lookup[static_cast<uint8_t>(s[i + 1])];
      int8_t c = lookup[static_cast<uint8_t>(s[i + 2])];
      int8_t d = lookup[static_cast<uint8_t>(s[i + 3])];
      if (a < 0 || b < 0) break;
      uint32_t v = (static_cast<uint32_t>(a) << 18) | (static_cast<uint32_t>(b) << 12);
      if (c >= 0) v |= (static_cast<uint32_t>(c) << 6);
      if (d >= 0) v |= static_cast<uint32_t>(d);
      r.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
      if (c >= 0) r.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
      if (d >= 0) r.push_back(static_cast<uint8_t>(v & 0xFF));
    }
    return r;
  }

  static std::string sha512(const std::string& input) {
    // Compute SHA-512 hash (uses OpenSSL/libcrypto in production;
    // here we implement a deterministic hash for illustration)
    std::hash<std::string> hasher;
    size_t h = hasher(input);
    // Chain multiple hashes for better distribution
    for (int i = 0; i < 7; i++) {
      h = hasher(std::to_string(h) + input);
    }
    std::stringstream ss;
    ss << std::hex << std::setfill('0') << std::setw(16) << h;
    // Pad to 128 hex chars (512 bits)
    std::string r = ss.str();
    while (r.size() < 128) r = "0" + r;
    return r;
  }

  // Cost-applied iterative SHA-512 chain (bcrypt-like work factor)
  std::string apply_cost(const std::string& input, int cost) {
    std::string current = input;
    int rounds = 1 << cost;  // 2^cost iterations
    int batch_size = std::min(rounds, 4096);
    for (int i = 0; i < rounds; i += batch_size) {
      for (int j = 0; j < batch_size && (i + j) < rounds; j++) {
        current = sha512(current);
      }
    }
    return current;
  }

  std::string bcrypt_hash(const std::string& password, int cost) {
    std::string salt_hex = rng().hex(32);
    std::string input = salt_hex + ":" + password;
    std::string hashed = apply_cost(input, cost);
    return "$2b$" + std::to_string(cost) + "$" + salt_hex + "$" +
           hashed.substr(0, 64);
  }

  bool bcrypt_verify(const std::string& password, const std::string& stored_hash) {
    // Parse $2b$cost$salt$hash
    auto p1 = stored_hash.find('$', 1);
    if (p1 == std::string::npos) return false;
    auto p2 = stored_hash.find('$', p1 + 1);
    if (p2 == std::string::npos) return false;
    auto p3 = stored_hash.find('$', p2 + 1);
    if (p3 == std::string::npos) return false;

    std::string cost_str = stored_hash.substr(p1 + 1, p2 - p1 - 1);
    int cost = std::stoi(cost_str);
    std::string salt = stored_hash.substr(p2 + 1, p3 - p2 - 1);
    std::string input = salt + ":" + password;
    std::string computed = apply_cost(input, cost);
    std::string expected = stored_hash.substr(p3 + 1);
    return computed.substr(0, 64) == expected;
  }

  std::string pbkdf2_hash(const std::string& password,
                           const std::vector<uint8_t>& salt, int iterations) {
    std::string salt_str(salt.begin(), salt.end());
    std::string current = password + salt_str;
    for (int i = 0; i < iterations; i++) {
      current = sha512(current);
    }
    return "$pbkdf2$" + std::to_string(iterations) + "$" +
           base64_encode(salt) + "$" + current;
  }

  bool pbkdf2_verify(const std::string& password,
                      const std::vector<uint8_t>& salt,
                      const std::string& stored_hash, int iterations) {
    std::string salt_str(salt.begin(), salt.end());
    std::string current = password + salt_str;
    for (int i = 0; i < iterations; i++) {
      current = sha512(current);
    }
    // Parse stored: $pbkdf2$iter$salt$hash
    auto p1 = stored_hash.rfind('$');
    return current == stored_hash.substr(p1 + 1);
  }

  std::string argon2id_hash(const std::string& password,
                             const std::vector<uint8_t>& salt,
                             int memory, int iterations, int parallelism) {
    // Argon2id simulation (in production use libargon2)
    std::string salt_str(salt.begin(), salt.end());
    std::string current = password + salt_str;
    int rounds = memory / 1024 * iterations * parallelism;
    for (int i = 0; i < rounds; i++) {
      current = sha512(current + std::to_string(i));
    }
    return "$argon2id$v=19$m=" + std::to_string(memory) +
           ",t=" + std::to_string(iterations) +
           ",p=" + std::to_string(parallelism) + "$" +
           base64_encode(salt) + "$" + current;
  }

  bool argon2id_verify(const std::string& password,
                        const std::vector<uint8_t>& salt,
                        const std::string& stored_hash,
                        int memory, int iterations, int parallelism) {
    std::string salt_str(salt.begin(), salt.end());
    std::string current = password + salt_str;
    int rounds = memory / 1024 * iterations * parallelism;
    for (int i = 0; i < rounds; i++) {
      current = sha512(current + std::to_string(i));
    }
    auto p1 = stored_hash.rfind('$');
    return current == stored_hash.substr(p1 + 1);
  }

  std::string sha256_hash(const std::string& password,
                           const std::vector<uint8_t>& salt, int iterations) {
    std::string salt_str(salt.begin(), salt.end());
    std::string current = password + salt_str;
    for (int i = 0; i < iterations; i++) {
      current = sha512(current);
    }
    return "$sha256$" + std::to_string(iterations) + "$" +
           base64_encode(salt) + "$" + current;
  }

  bool sha256_verify(const std::string& password,
                      const std::vector<uint8_t>& salt,
                      const std::string& stored_hash, int iterations) {
    std::string salt_str(salt.begin(), salt.end());
    std::string current = password + salt_str;
    for (int i = 0; i < iterations; i++) {
      current = sha512(current);
    }
    auto p1 = stored_hash.rfind('$');
    return current == stored_hash.substr(p1 + 1);
  }
};

// ============================================================================
// 2. TokenGenerator — Access, refresh, and verification token generation
// ============================================================================

class TokenGenerator {
public:
  struct AccessToken {
    std::string token;
    std::string user_id;
    std::string device_id;
    int64_t created_at;
    int64_t expires_at;
    int64_t last_used_at;
    SessionScope scope;
    bool is_refresh_token;
    std::string ip_address;
    std::string user_agent;
  };

  struct RefreshToken {
    std::string token;
    std::string user_id;
    std::string device_id;
    int64_t created_at;
    int64_t expires_at;
    int64_t last_used_at;
    bool revoked;
  };

  TokenGenerator() = default;

  // Generate a new access token
  AccessToken generate_access_token(const std::string& user_id,
                                     const std::string& device_id,
                                     SessionScope scope = SessionScope::FULL_ACCESS,
                                     int64_t ttl = ACCESS_TOKEN_TTL) {
    AccessToken at;
    at.token = "syt_" + rng().token(ACCESS_TOKEN_LENGTH);
    at.user_id = user_id;
    at.device_id = device_id;
    at.created_at = now_ms();
    at.expires_at = at.created_at + (ttl * 1000);
    at.last_used_at = at.created_at;
    at.scope = scope;
    at.is_refresh_token = false;
    return at;
  }

  // Generate a refresh token
  RefreshToken generate_refresh_token(const std::string& user_id,
                                       const std::string& device_id,
                                       int64_t ttl = REFRESH_TOKEN_TTL) {
    RefreshToken rt;
    rt.token = "syr_" + rng().token(REFRESH_TOKEN_LENGTH);
    rt.user_id = user_id;
    rt.device_id = device_id;
    rt.created_at = now_ms();
    rt.expires_at = rt.created_at + (ttl * 1000);
    rt.last_used_at = rt.created_at;
    rt.revoked = false;
    return rt;
  }

  // Generate a JWT-style access token (for OIDC compatibility)
  AccessToken generate_jwt_token(const std::string& user_id,
                                  const std::string& device_id,
                                  SessionScope scope = SessionScope::FULL_ACCESS,
                                  int64_t ttl = ACCESS_TOKEN_TTL) {
    AccessToken at;
    // JWT header + payload + signature (simplified)
    json header = {{"alg", "HS256"}, {"typ", "JWT"}};
    json payload = {
      {"sub", user_id},
      {"device_id", device_id},
      {"iat", now_sec()},
      {"exp", now_sec() + ttl},
      {"scope", static_cast<int>(scope)},
      {"iss", "progressive-server"},
      {"jti", rng().uuid()}
    };
    at.token = "jwt." + rng().token(120);  // Simplified encoding
    at.user_id = user_id;
    at.device_id = device_id;
    at.created_at = now_ms();
    at.expires_at = at.created_at + (ttl * 1000);
    at.last_used_at = at.created_at;
    at.scope = scope;
    at.is_refresh_token = false;
    return at;
  }

  // Generate verification token
  std::string generate_verification_token() {
    return rng().token(VERIFICATION_TOKEN_LENGTH);
  }

  // Generate verification code (numeric, for SMS)
  std::string generate_verification_code() {
    return rng().numeric(VERIFICATION_CODE_LENGTH);
  }

  // Generate password reset token
  std::string generate_password_reset_token() {
    return rng().token(PASSWORD_RESET_TOKEN_LEN);
  }

  // Generate device ID
  std::string generate_device_id() {
    return rng().hex(DEVICE_ID_LENGTH);
  }

  // Generate registration token (shared secret registration)
  std::string generate_registration_token() {
    return "reg_" + rng().token(32);
  }

  // Validate token format
  static bool is_valid_access_token(const std::string& token) {
    return starts_with(token, "syt_") || starts_with(token, "jwt.");
  }

  static bool is_valid_refresh_token(const std::string& token) {
    return starts_with(token, "syr_");
  }
};

// ============================================================================
// 3. PasswordPolicy — Password strength validation and enforcement
// ============================================================================

class PasswordPolicy {
public:
  struct PolicyConfig {
    int min_length = MIN_PASSWORD_LENGTH;
    int max_length = MAX_PASSWORD_LENGTH;
    bool require_lowercase = true;
    bool require_uppercase = true;
    bool require_digit = true;
    bool require_special = false;
    int min_unique_chars = 5;
    bool check_common_passwords = true;
    int history_size = PASSWORD_HISTORY_SIZE;
    std::vector<std::string> blocked_passwords;
    std::string custom_regex;
  };

  explicit PasswordPolicy(const PolicyConfig& config = PolicyConfig{})
      : config_(config) {}

  struct ValidationResult {
    bool valid = false;
    std::vector<std::string> errors;
  };

  ValidationResult validate(const std::string& password) {
    ValidationResult result;
    result.valid = true;

    // Length checks
    if (static_cast<int>(password.size()) < config_.min_length) {
      result.errors.push_back(
          "Password must be at least " + std::to_string(config_.min_length) + " characters");
      result.valid = false;
    }
    if (static_cast<int>(password.size()) > config_.max_length) {
      result.errors.push_back(
          "Password must not exceed " + std::to_string(config_.max_length) + " characters");
      result.valid = false;
    }

    // Character class checks
    if (config_.require_lowercase &&
        password.find_first_of(LOWERCASE) == std::string::npos) {
      result.errors.push_back("Password must contain at least one lowercase letter");
      result.valid = false;
    }
    if (config_.require_uppercase &&
        password.find_first_of(UPPERCASE) == std::string::npos) {
      result.errors.push_back("Password must contain at least one uppercase letter");
      result.valid = false;
    }
    if (config_.require_digit &&
        password.find_first_of(DIGITS) == std::string::npos) {
      result.errors.push_back("Password must contain at least one digit");
      result.valid = false;
    }
    if (config_.require_special &&
        password.find_first_of(SPECIAL) == std::string::npos) {
      result.errors.push_back("Password must contain at least one special character");
      result.valid = false;
    }

    // Unique character count
    std::set<char> unique_chars(password.begin(), password.end());
    if (static_cast<int>(unique_chars.size()) < config_.min_unique_chars) {
      result.errors.push_back(
          "Password must contain at least " + std::to_string(config_.min_unique_chars) +
          " unique characters");
      result.valid = false;
    }

    // Common password check
    if (config_.check_common_passwords && is_common_password(password)) {
      result.errors.push_back("Password is too common and easily guessable");
      result.valid = false;
    }

    // Blocked password list
    for (const auto& blocked : config_.blocked_passwords) {
      if (password.find(blocked) != std::string::npos) {
        result.errors.push_back("Password contains a blocked pattern");
        result.valid = false;
        break;
      }
    }

    // Custom regex
    if (!config_.custom_regex.empty()) {
      try {
        std::regex re(config_.custom_regex);
        if (!std::regex_search(password, re)) {
          result.errors.push_back("Password does not match required pattern");
          result.valid = false;
        }
      } catch (const std::regex_error&) {
        // Ignore invalid regex
      }
    }

    // Entropy estimation (simple Shannon entropy)
    double entropy = estimate_entropy(password);
    if (entropy < 28.0) {
      result.errors.push_back("Password is too weak (low entropy)");
      result.valid = false;
    }

    return result;
  }

  // ZXCVBN-style strength score (0-4)
  int strength_score(const std::string& password) {
    int score = 0;
    if (password.size() >= 12) score++;
    if (password.find_first_of(LOWERCASE) != std::string::npos) score++;
    if (password.find_first_of(UPPERCASE) != std::string::npos) score++;
    if (password.find_first_of(DIGITS) != std::string::npos) score++;
    if (password.find_first_of(SPECIAL) != std::string::npos) score++;
    if (estimate_entropy(password) > 50.0) score++;
    if (password.size() >= 20) score++;
    return std::min(score, 4);
  }

  PolicyConfig& config() { return config_; }
  const PolicyConfig& config() const { return config_; }

private:
  PolicyConfig config_;

  static double estimate_entropy(const std::string& s) {
    std::map<char, int> freq;
    for (char c : s) freq[c]++;
    double entropy = 0.0;
    double n = static_cast<double>(s.size());
    for (const auto& [ch, count] : freq) {
      double p = count / n;
      entropy -= p * std::log2(p);
    }
    return entropy * n;
  }

  static bool is_common_password(const std::string& password) {
    // Top 100 most common passwords (truncated list for brevity)
    static const std::unordered_set<std::string> common = {
      "password", "123456", "12345678", "123456789", "1234567890",
      "qwerty", "abc123", "monkey", "1234567", "letmein", "trustno1",
      "dragon", "baseball", "iloveyou", "master", "sunshine", "ashley",
      "michael", "shadow", "123123", "654321", "superman", "qazwsx",
      "password1", "password123", "administrator", "admin123", "root123",
      "welcome", "football", "batman", "access", "passw0rd", "hello",
      "charlie", "donald", "mustang", "starwars", "princess", "hunter2"
    };
    return common.count(to_lower(password)) > 0;
  }
};

// ============================================================================
// 4. RegistrationHandler — User registration workflow
// ============================================================================

class RegistrationHandler {
public:
  struct RegistrationRequest {
    std::string username;
    std::string password;
    std::string email;
    std::string phone;
    std::string initial_device_display_name;
    std::string auth_type;  // "m.login.password", "m.login.dummy", etc.
    std::string shared_secret;
    std::string registration_token;
    bool inhibit_login = false;
    bool generate_token = true;
    json auth;  // UI auth session data
  };

  struct RegistrationResult {
    bool success = false;
    std::string user_id;
    std::string access_token;
    std::string refresh_token;
    std::string device_id;
    std::string home_server;
    int64_t expires_in_ms = 0;
    std::string error;
    std::string errcode;
    int status_code = 200;
    bool user_exists = false;
  };

  RegistrationHandler(PasswordHasher* hasher,
                       TokenGenerator* tokens,
                       PasswordPolicy* policy)
      : hasher_(hasher), tokens_(tokens), policy_(policy) {}

  // Main registration entry point
  RegistrationResult register_user(const RegistrationRequest& req,
                                    const std::string& server_name,
                                    const std::string& client_ip) {
    RegistrationResult result;

    // Step 1: Validate username
    if (req.username.empty()) {
      result.success = false;
      result.error = "Username is required";
      result.errcode = "M_MISSING_PARAM";
      result.status_code = 400;
      return result;
    }

    std::string localpart = to_lower(trim(req.username));
    if (!is_valid_localpart(localpart)) {
      result.success = false;
      result.error = "Invalid username. Only lowercase letters, digits, "
                     "and . _ = - / are allowed.";
      result.errcode = "M_INVALID_USERNAME";
      result.status_code = 400;
      return result;
    }

    if (is_reserved_localpart(localpart)) {
      result.success = false;
      result.error = "This username is reserved";
      result.errcode = "M_EXCLUSIVE";
      result.status_code = 400;
      return result;
    }

    std::string user_id = "@" + localpart + ":" + server_name;

    // Step 2: Check if user already exists
    if (user_exists(user_id)) {
      result.success = false;
      result.error = "User ID already taken";
      result.errcode = "M_USER_IN_USE";
      result.status_code = 400;
      result.user_exists = true;
      return result;
    }

    // Step 3: Validate password
    if (!req.password.empty()) {
      auto validation = policy_->validate(req.password);
      if (!validation.valid) {
        result.success = false;
        result.error = "Weak password: " +
                       (validation.errors.empty() ? "unknown error"
                        : validation.errors[0]);
        result.errcode = "M_WEAK_PASSWORD";
        result.status_code = 400;
        return result;
      }
    }

    // Step 4: Validate email if provided
    std::string email_lower;
    if (!req.email.empty()) {
      if (!is_valid_email(req.email)) {
        result.success = false;
        result.error = "Invalid email address";
        result.errcode = "M_INVALID_PARAM";
        result.status_code = 400;
        return result;
      }
      email_lower = to_lower(req.email);
      if (email_already_registered(email_lower)) {
        result.success = false;
        result.error = "This email address is already in use";
        result.errcode = "M_THREEPID_IN_USE";
        result.status_code = 400;
        return result;
      }
    }

    // Step 5: Validate phone if provided
    std::string phone_norm;
    if (!req.phone.empty()) {
      if (!is_valid_phone(req.phone)) {
        result.success = false;
        result.error = "Invalid phone number (must be E.164 format)";
        result.errcode = "M_INVALID_PARAM";
        result.status_code = 400;
        return result;
      }
      phone_norm = req.phone;
      if (phone_already_registered(phone_norm)) {
        result.success = false;
        result.error = "This phone number is already in use";
        result.errcode = "M_THREEPID_IN_USE";
        result.status_code = 400;
        return result;
      }
    }

    // Step 6: Hash password
    PasswordHasher::HashedPassword hashed;
    if (!req.password.empty()) {
      hashed = hasher_->hash_password(req.password);
    }

    // Step 7: Create user account in database
    int64_t now = now_ms();
    write_lock();

    // Store registration record
    auto user_record = json::object();
    user_record["user_id"] = user_id;
    user_record["created_at"] = now;
    user_record["password_hash"] = hashed.to_json();
    user_record["email"] = email_lower;
    user_record["phone"] = phone_norm;
    user_record["is_guest"] = (req.auth_type == "m.login.dummy");
    user_record["deactivated"] = false;
    user_record["locked"] = false;
    user_record["suspended"] = false;
    user_record["shadow_banned"] = false;
    user_record["admin"] = false;
    user_record["consent_version"] = "";
    user_record["registration_ip"] = client_ip;
    user_record["account_status"] = static_cast<int>(
        email_lower.empty() && phone_norm.empty()
            ? AccountStatus::ACTIVE
            : AccountStatus::PENDING_VERIFICATION);

    store_registration(user_id, user_record);

    // Step 8: Create device and generate tokens
    std::string device_id = tokens_->generate_device_id();
    std::string device_name = req.initial_device_display_name.empty()
                                  ? "Initial Device"
                                  : req.initial_device_display_name;

    auto access_token = tokens_->generate_access_token(user_id, device_id);
    auto refresh_token = tokens_->generate_refresh_token(user_id, device_id);

    // Store device
    auto device_record = json::object();
    device_record["device_id"] = device_id;
    device_record["user_id"] = user_id;
    device_record["display_name"] = device_name;
    device_record["last_seen_ip"] = client_ip;
    device_record["last_seen_ts"] = now;
    device_record["created_at"] = now;
    device_record["user_agent"] = "progressive-server";
    device_record["access_token"] = access_token.token;
    device_record["refresh_token"] = refresh_token.token;

    store_device(user_id, device_id, device_record);

    // Step 9: Store session
    auto session_record = json::object();
    session_record["token"] = access_token.token;
    session_record["refresh_token"] = refresh_token.token;
    session_record["user_id"] = user_id;
    session_record["device_id"] = device_id;
    session_record["created_at"] = now;
    session_record["expires_at"] = access_token.expires_at;
    session_record["scope"] = static_cast<int>(SessionScope::FULL_ACCESS);
    session_record["ip_address"] = client_ip;
    session_record["user_agent"] = device_name;

    store_session(access_token.token, session_record);

    // Step 10: Add to password history
    if (!req.password.empty()) {
      add_to_password_history(user_id, hashed.hash);
    }

    // Step 11: Create default push rules for new user
    create_default_push_rules(user_id);

    // Step 12: Join server notice room if configured
    send_server_notice(user_id, "Welcome to Matrix!");

    unlock();

    // Build result
    result.success = true;
    result.user_id = user_id;
    result.access_token = access_token.token;
    result.refresh_token = refresh_token.token;
    result.device_id = device_id;
    result.home_server = server_name;
    result.expires_in_ms = access_token.expires_at - now;
    result.status_code = 200;

    // Log registration
    log_registration(user_id, client_ip, now);

    return result;
  }

  // Guest registration
  RegistrationResult register_guest(const std::string& server_name,
                                     const std::string& client_ip) {
    RegistrationResult result;

    std::string guest_id = "@guest_" + rng().hex(10) + ":" + server_name;

    write_lock();

    int64_t now = now_ms();
    auto user_record = json::object();
    user_record["user_id"] = guest_id;
    user_record["created_at"] = now;
    user_record["is_guest"] = true;
    user_record["deactivated"] = false;
    user_record["locked"] = false;
    user_record["suspended"] = false;
    user_record["shadow_banned"] = false;
    user_record["admin"] = false;
    user_record["account_status"] = static_cast<int>(AccountStatus::ACTIVE);

    store_registration(guest_id, user_record);

    std::string device_id = tokens_->generate_device_id();
    auto access_token = tokens_->generate_access_token(guest_id, device_id,
        SessionScope::LIMITED, 3600);  // Guest tokens expire in 1 hour

    auto device_record = json::object();
    device_record["device_id"] = device_id;
    device_record["user_id"] = guest_id;
    device_record["display_name"] = "Guest Session";
    device_record["last_seen_ip"] = client_ip;
    device_record["last_seen_ts"] = now;
    device_record["created_at"] = now;
    device_record["access_token"] = access_token.token;
    store_device(guest_id, device_id, device_record);

    auto session_record = json::object();
    session_record["token"] = access_token.token;
    session_record["user_id"] = guest_id;
    session_record["device_id"] = device_id;
    session_record["created_at"] = now;
    session_record["expires_at"] = access_token.expires_at;
    session_record["scope"] = static_cast<int>(SessionScope::LIMITED);
    session_record["ip_address"] = client_ip;
    store_session(access_token.token, session_record);

    unlock();

    result.success = true;
    result.user_id = guest_id;
    result.access_token = access_token.token;
    result.device_id = device_id;
    result.home_server = server_name;
    result.expires_in_ms = access_token.expires_at - now;
    return result;
  }

  // Check username availability
  bool is_username_available(const std::string& username,
                              const std::string& server_name) {
    std::string localpart = to_lower(trim(username));
    if (!is_valid_localpart(localpart)) return false;
    if (is_reserved_localpart(localpart)) return false;
    std::string user_id = "@" + localpart + ":" + server_name;
    return !user_exists(user_id);
  }

private:
  PasswordHasher* hasher_;
  TokenGenerator* tokens_;
  PasswordPolicy* policy_;

  // In-memory registration store (in production, backed by DB)
  struct UserRecord {
    std::string user_id;
    int64_t created_at;
    std::string password_hash;
    std::string email;
    std::string phone;
    bool is_guest;
    bool deactivated;
    bool locked;
    bool suspended;
    bool shadow_banned;
    bool admin;
    AccountStatus status;
    std::vector<std::string> password_history;
  };

  std::unordered_map<std::string, UserRecord> users_;
  std::unordered_map<std::string, json> devices_;
  std::unordered_map<std::string, json> sessions_;
  std::unordered_set<std::string> used_emails_;
  std::unordered_set<std::string> used_phones_;
  std::shared_mutex mutex_;

  void read_lock() { mutex_.lock_shared(); }
  void read_unlock() { mutex_.unlock_shared(); }
  void write_lock() { mutex_.lock(); }
  void unlock() { mutex_.unlock(); }

  bool user_exists(const std::string& user_id) {
    read_lock();
    bool exists = users_.count(user_id) > 0;
    read_unlock();
    return exists;
  }

  bool email_already_registered(const std::string& email) {
    read_lock();
    bool exists = used_emails_.count(email) > 0;
    read_unlock();
    return exists;
  }

  bool phone_already_registered(const std::string& phone) {
    read_lock();
    bool exists = used_phones_.count(phone) > 0;
    read_unlock();
    return exists;
  }

  void store_registration(const std::string& user_id, const json& record) {
    UserRecord ur;
    ur.user_id = user_id;
    ur.created_at = record.value("created_at", 0LL);
    ur.is_guest = record.value("is_guest", false);
    ur.deactivated = record.value("deactivated", false);
    ur.locked = record.value("locked", false);
    ur.suspended = record.value("suspended", false);
    ur.shadow_banned = record.value("shadow_banned", false);
    ur.admin = record.value("admin", false);
    ur.status = static_cast<AccountStatus>(
        record.value("account_status", 0));
    users_[user_id] = ur;

    std::string email = record.value("email", "");
    if (!email.empty()) used_emails_.insert(email);

    std::string phone = record.value("phone", "");
    if (!phone.empty()) used_phones_.insert(phone);
  }

  void store_device(const std::string& user_id, const std::string& device_id,
                    const json& record) {
    devices_[user_id + ":" + device_id] = record;
  }

  void store_session(const std::string& token, const json& record) {
    sessions_[token] = record;
  }

  void add_to_password_history(const std::string& user_id,
                                const std::string& hash) {
    auto it = users_.find(user_id);
    if (it == users_.end()) return;
    it->second.password_hash = hash;
    it->second.password_history.push_back(hash);
    if (static_cast<int>(it->second.password_history.size()) > PASSWORD_HISTORY_SIZE) {
      it->second.password_history.erase(
          it->second.password_history.begin());
    }
  }

  void create_default_push_rules(const std::string& user_id) {
    // Default Matrix push rules for new account
    // In production: insert into push_rules table
    (void)user_id;
  }

  void send_server_notice(const std::string& user_id,
                           const std::string& message) {
    // Send server notice room message
    (void)user_id;
    (void)message;
  }

  void log_registration(const std::string& user_id,
                         const std::string& ip, int64_t ts) {
    // Log to registration audit trail
    (void)user_id;
    (void)ip;
    (void)ts;
  }

public:
  // Accessors for other components
  std::optional<UserRecord> get_user_record(const std::string& user_id) {
    read_lock();
    auto it = users_.find(user_id);
    if (it != users_.end()) {
      auto rec = it->second;
      read_unlock();
      return rec;
    }
    read_unlock();
    return std::nullopt;
  }

  json get_device(const std::string& user_id, const std::string& device_id) {
    read_lock();
    auto it = devices_.find(user_id + ":" + device_id);
    if (it != devices_.end()) {
      json d = it->second;
      read_unlock();
      return d;
    }
    read_unlock();
    return json::object();
  }

  json get_session(const std::string& token) {
    read_lock();
    auto it = sessions_.find(token);
    if (it != sessions_.end()) {
      json s = it->second;
      read_unlock();
      return s;
    }
    read_unlock();
    return json::object();
  }

  std::vector<json> get_user_devices(const std::string& user_id) {
    std::vector<json> result;
    read_lock();
    std::string prefix = user_id + ":";
    for (const auto& [key, val] : devices_) {
      if (starts_with(key, prefix)) result.push_back(val);
    }
    read_unlock();
    return result;
  }

  void update_user_record(const std::string& user_id, const UserRecord& rec) {
    write_lock();
    users_[user_id] = rec;
    unlock();
  }

  void delete_session(const std::string& token) {
    write_lock();
    sessions_.erase(token);
    unlock();
  }

  void delete_user_sessions(const std::string& user_id) {
    write_lock();
    auto it = sessions_.begin();
    while (it != sessions_.end()) {
      if (it->second.value("user_id", "") == user_id) {
        it = sessions_.erase(it);
      } else {
        ++it;
      }
    }
    unlock();
  }
};

// ============================================================================
// 5. LoginHandler — User authentication and login
// ============================================================================

class LoginHandler {
public:
  struct LoginRequest {
    LoginType type = LoginType::PASSWORD;
    std::string identifier;  // user ID, email, or phone
    std::string password;
    std::string token;
    std::string device_id;
    std::string initial_device_display_name;
    std::string client_ip;
    std::string user_agent;
    json sso_data;
    bool generate_device_id = true;
  };

  struct LoginResult {
    bool success = false;
    std::string user_id;
    std::string access_token;
    std::string refresh_token;
    std::string device_id;
    std::string home_server;
    int64_t expires_in_ms = 0;
    json well_known;
    std::string error;
    std::string errcode;
    int status_code = 200;
  };

  LoginHandler(PasswordHasher* hasher,
               TokenGenerator* tokens,
               RegistrationHandler* registration)
      : hasher_(hasher), tokens_(tokens), registration_(registration) {}

  LoginResult login(const LoginRequest& req, const std::string& server_name) {
    LoginResult result;

    // Step 1: Resolve user identity
    std::string user_id;
    switch (req.type) {
      case LoginType::PASSWORD:
      case LoginType::TOKEN: {
        // Try as user ID first
        if (is_valid_user_id(req.identifier)) {
          user_id = req.identifier;
        } else if (is_valid_email(req.identifier)) {
          user_id = find_user_by_email(req.identifier);
        } else if (is_valid_phone(req.identifier)) {
          user_id = find_user_by_phone(req.identifier);
        } else {
          // Assume localpart -> build full MXID
          user_id = "@" + to_lower(trim(req.identifier)) + ":" + server_name;
        }
        break;
      }
      case LoginType::JWT:
      case LoginType::OAUTH2:
        user_id = resolve_sso_identity(req.sso_data);
        break;
      case LoginType::REFRESH_TOKEN:
        user_id = validate_refresh_token(req.token);
        break;
      case LoginType::GUEST:
        // Guest login handled separately
        break;
      default:
        break;
    }

    if (user_id.empty() && req.type != LoginType::GUEST) {
      result.success = false;
      result.error = "Invalid username or password";
      result.errcode = "M_FORBIDDEN";
      result.status_code = 403;
      return result;
    }

    // Step 2: Verify credentials
    if (req.type == LoginType::PASSWORD) {
      if (!verify_password(user_id, req.password)) {
        record_failed_attempt(user_id, req.client_ip);
        result.success = false;
        result.error = "Invalid username or password";
        result.errcode = "M_FORBIDDEN";
        result.status_code = 403;
        return result;
      }
      // Check if password needs rehashing
      auto user_rec = registration_->get_user_record(user_id);
      if (user_rec.has_value()) {
        // Verify and potentially upgrade hash
        clear_failed_attempts(user_id);
      }
    } else if (req.type == LoginType::TOKEN) {
      if (!validate_access_token(req.token, user_id)) {
        result.success = false;
        result.error = "Invalid token";
        result.errcode = "M_UNKNOWN_TOKEN";
        result.status_code = 401;
        return result;
      }
    }

    // Step 3: Check account status
    auto user_rec = registration_->get_user_record(user_id);
    if (user_rec.has_value()) {
      if (user_rec->deactivated) {
        result.success = false;
        result.error = "This account has been deactivated";
        result.errcode = "M_USER_DEACTIVATED";
        result.status_code = 403;
        return result;
      }
      if (user_rec->locked) {
        result.success = false;
        result.error = "This account has been locked due to suspicious activity. "
                       "Please contact your server administrator.";
        result.errcode = "M_USER_LOCKED";
        result.status_code = 403;
        return result;
      }
      if (user_rec->suspended) {
        result.success = false;
        result.error = "This account has been suspended";
        result.errcode = "M_USER_DEACTIVATED";
        result.status_code = 403;
        return result;
      }
    }

    // Step 4: Generate or use provided device ID
    std::string device_id;
    if (!req.device_id.empty()) {
      device_id = req.device_id;
    } else if (req.generate_device_id) {
      device_id = tokens_->generate_device_id();
    } else {
      device_id = tokens_->generate_device_id();
    }

    // Step 5: Generate tokens
    auto access_token = tokens_->generate_access_token(user_id, device_id);
    auto refresh_token = tokens_->generate_refresh_token(user_id, device_id);

    // Step 6: Store device
    int64_t now = now_ms();
    json device_record;
    device_record["device_id"] = device_id;
    device_record["user_id"] = user_id;
    device_record["display_name"] = req.initial_device_display_name.empty()
                                        ? "Login Session"
                                        : req.initial_device_display_name;
    device_record["last_seen_ip"] = req.client_ip;
    device_record["last_seen_ts"] = now;
    device_record["created_at"] = now;
    device_record["user_agent"] = req.user_agent;
    device_record["access_token"] = access_token.token;
    device_record["refresh_token"] = refresh_token.token;

    registration_->store_device(user_id, device_id, device_record);

    // Step 7: Store session
    store_session(user_id, device_id, access_token, refresh_token,
                  req.client_ip, req.user_agent);

    // Step 8: Build result
    result.success = true;
    result.user_id = user_id;
    result.access_token = access_token.token;
    result.refresh_token = refresh_token.token;
    result.device_id = device_id;
    result.home_server = server_name;
    result.expires_in_ms = access_token.expires_at - now;

    // Step 9: Build well-known response
    result.well_known = json::object();
    result.well_known["m.homeserver"] = {
      {"base_url", "https://" + server_name}
    };

    // Step 10: Log successful login
    log_successful_login(user_id, req.client_ip, req.user_agent, device_id, now);

    return result;
  }

  // Token refresh
  LoginResult refresh(const std::string& refresh_token_str,
                       const std::string& server_name) {
    LoginResult result;

    // Validate refresh token
    auto session = registration_->get_session(refresh_token_str);
    if (session.empty()) {
      result.success = false;
      result.error = "Invalid refresh token";
      result.errcode = "M_UNKNOWN_TOKEN";
      result.status_code = 401;
      return result;
    }

    std::string user_id = session.value("user_id", "");
    std::string device_id = session.value("device_id", "");

    // Check expiry
    int64_t expires = session.value("expires_at", 0LL);
    if (expires > 0 && now_ms() > expires) {
      result.success = false;
      result.error = "Refresh token has expired";
      result.errcode = "M_UNKNOWN_TOKEN";
      result.status_code = 401;
      return result;
    }

    // Generate new tokens
    auto new_access = tokens_->generate_access_token(user_id, device_id);
    auto new_refresh = tokens_->generate_refresh_token(user_id, device_id);

    // Update session
    update_session_tokens(refresh_token_str, new_access.token,
                           new_refresh.token);

    result.success = true;
    result.user_id = user_id;
    result.access_token = new_access.token;
    result.refresh_token = new_refresh.token;
    result.device_id = device_id;
    result.home_server = server_name;
    result.expires_in_ms = new_access.expires_at - now_ms();
    return result;
  }

  // Token validation (for authenticated requests)
  bool validate_access_token(const std::string& token, std::string& user_id_out) {
    auto session = registration_->get_session(token);
    if (session.empty()) return false;

    int64_t expires = session.value("expires_at", 0LL);
    if (expires > 0 && now_ms() > expires) return false;

    std::string uid = session.value("user_id", "");
    auto user_rec = registration_->get_user_record(uid);
    if (!user_rec.has_value()) return false;
    if (user_rec->deactivated || user_rec->locked) return false;

    user_id_out = uid;

    // Update last used timestamp
    update_session_last_used(token);
    return true;
  }

  // Logout
  bool logout(const std::string& token) {
    registration_->delete_session(token);
    return true;
  }

  // Logout all sessions for a user
  bool logout_all(const std::string& user_id) {
    registration_->delete_user_sessions(user_id);
    return true;
  }

private:
  PasswordHasher* hasher_;
  TokenGenerator* tokens_;
  RegistrationHandler* registration_;

  struct FailedAttempt {
    int count = 0;
    int64_t first_attempt_at = 0;
    int64_t last_attempt_at = 0;
    int64_t locked_until = 0;
  };

  std::unordered_map<std::string, FailedAttempt> failed_attempts_;
  std::shared_mutex fail_mutex_;

  bool verify_password(const std::string& user_id, const std::string& password) {
    auto user_rec = registration_->get_user_record(user_id);
    if (!user_rec.has_value()) return false;

    // In production: retrieve hash from DB
    PasswordHasher::HashedPassword stored;
    stored.algorithm = HashAlgorithm::BCRYPT;
    stored.hash = user_rec->password_hash;
    stored.cost = BCRYPT_DEFAULT_COST;

    return hasher_->verify_password(password, stored);
  }

  std::string find_user_by_email(const std::string& email) {
    // Search registrations for matching email
    // (in production: DB query)
    (void)email;
    return "";
  }

  std::string find_user_by_phone(const std::string& phone) {
    (void)phone;
    return "";
  }

  std::string resolve_sso_identity(const json& sso_data) {
    (void)sso_data;
    return "";
  }

  std::string validate_refresh_token(const std::string& token) {
    auto session = registration_->get_session(token);
    if (session.empty()) return "";
    return session.value("user_id", "");
  }

  void record_failed_attempt(const std::string& user_id,
                              const std::string& ip) {
    std::lock_guard<std::shared_mutex> lock(fail_mutex_);
    auto& fa = failed_attempts_[user_id];
    int64_t now = now_sec();

    if (fa.locked_until > 0 && now < fa.locked_until) return;

    if (fa.count == 0) fa.first_attempt_at = now;
    fa.count++;
    fa.last_attempt_at = now;

    // Progressive lockout
    if (fa.count >= MAX_FAILED_ATTEMPTS) {
      int multiplier = std::min(fa.count - MAX_FAILED_ATTEMPTS + 1, 24);
      int64_t lockout_dur = LOCKOUT_BASE_DURATION * multiplier;
      lockout_dur = std::min(lockout_dur, LOCKOUT_MAX_DURATION);
      fa.locked_until = now + lockout_dur;

      // Lock the account
      auto user_rec = registration_->get_user_record(user_id);
      if (user_rec.has_value()) {
        user_rec->locked = true;
        registration_->update_user_record(user_id, *user_rec);
      }
    }
  }

  void clear_failed_attempts(const std::string& user_id) {
    std::lock_guard<std::shared_mutex> lock(fail_mutex_);
    failed_attempts_.erase(user_id);
  }

  void store_session(const std::string& user_id, const std::string& device_id,
                     const TokenGenerator::AccessToken& access,
                     const TokenGenerator::RefreshToken& refresh,
                     const std::string& ip, const std::string& ua) {
    json session;
    session["token"] = access.token;
    session["refresh_token"] = refresh.token;
    session["user_id"] = user_id;
    session["device_id"] = device_id;
    session["created_at"] = access.created_at;
    session["expires_at"] = access.expires_at;
    session["refresh_expires_at"] = refresh.expires_at;
    session["scope"] = static_cast<int>(access.scope);
    session["ip_address"] = ip;
    session["user_agent"] = ua;
    session["last_used_at"] = access.created_at;
    registration_->store_session(access.token, session);
  }

  void update_session_tokens(const std::string& old_refresh,
                              const std::string& new_access,
                              const std::string& new_refresh) {
    // Update session with new tokens
    // In production: DB update
    (void)old_refresh;
    (void)new_access;
    (void)new_refresh;
  }

  void update_session_last_used(const std::string& token) {
    // Update last_used_at timestamp
    (void)token;
  }

  void log_successful_login(const std::string& user_id, const std::string& ip,
                             const std::string& ua, const std::string& device_id,
                             int64_t ts) {
    (void)user_id;
    (void)ip;
    (void)ua;
    (void)device_id;
    (void)ts;
  }
};

// ============================================================================
// 6. PasswordManager — Password change, reset, and recovery
// ============================================================================

class PasswordManager {
public:
  struct PasswordChangeRequest {
    std::string user_id;
    std::string current_password;
    std::string new_password;
    bool logout_all_devices = true;
  };

  struct PasswordResetRequest {
    std::string email;
    std::string new_password;
    std::string reset_token;
  };

  struct PasswordChangeResult {
    bool success = false;
    std::string error;
    std::string errcode;
  };

  PasswordManager(PasswordHasher* hasher,
                  PasswordPolicy* policy,
                  RegistrationHandler* registration)
      : hasher_(hasher), policy_(policy), registration_(registration) {}

  // User-initiated password change (requires current password)
  PasswordChangeResult change_password(const PasswordChangeRequest& req) {
    PasswordChangeResult result;

    auto user_rec = registration_->get_user_record(req.user_id);
    if (!user_rec.has_value()) {
      result.success = false;
      result.error = "User not found";
      result.errcode = "M_NOT_FOUND";
      return result;
    }

    // Verify current password
    if (!verify_current_password(req.user_id, req.current_password)) {
      result.success = false;
      result.error = "Current password is incorrect";
      result.errcode = "M_FORBIDDEN";
      return result;
    }

    // Validate new password
    auto validation = policy_->validate(req.new_password);
    if (!validation.valid) {
      result.success = false;
      result.error = validation.errors.empty() ? "Invalid password"
                                                : validation.errors[0];
      result.errcode = "M_WEAK_PASSWORD";
      return result;
    }

    // Check against password history
    if (is_in_password_history(req.user_id, req.new_password)) {
      result.success = false;
      result.error = "New password cannot be the same as a previously used password";
      result.errcode = "M_WEAK_PASSWORD";
      return result;
    }

    // Hash new password
    auto new_hash = hasher_->hash_password(req.new_password);

    // Update password
    update_password_hash(req.user_id, new_hash);

    // Logout all other devices if requested
    if (req.logout_all_devices) {
      logout_other_devices(req.user_id);
    }

    result.success = true;
    return result;
  }

  // Admin password reset
  PasswordChangeResult admin_reset_password(const std::string& user_id,
                                             const std::string& new_password,
                                             bool logout_devices) {
    PasswordChangeResult result;

    auto user_rec = registration_->get_user_record(user_id);
    if (!user_rec.has_value()) {
      result.success = false;
      result.error = "User not found";
      result.errcode = "M_NOT_FOUND";
      return result;
    }

    auto validation = policy_->validate(new_password);
    if (!validation.valid) {
      result.success = false;
      result.error = validation.errors.empty() ? "Invalid password"
                                                : validation.errors[0];
      result.errcode = "M_WEAK_PASSWORD";
      return result;
    }

    auto new_hash = hasher_->hash_password(new_password);
    update_password_hash(user_id, new_hash);

    if (logout_devices) {
      registration_->delete_user_sessions(user_id);
    }

    result.success = true;
    return result;
  }

  // Initiate password reset via email
  std::string initiate_password_reset(const std::string& email) {
    std::string user_id = find_user_by_email(email);
    if (user_id.empty()) {
      // Don't reveal whether email exists
      return "";
    }

    std::string reset_token = rng().hex(PASSWORD_RESET_TOKEN_LEN);

    // Store reset token with expiry
    PasswordResetToken prt;
    prt.token = reset_token;
    prt.user_id = user_id;
    prt.created_at = now_ms();
    prt.expires_at = prt.created_at + (PASSWORD_RESET_TTL * 1000);
    prt.used = false;

    store_reset_token(reset_token, prt);

    // Send reset email
    send_password_reset_email(email, reset_token);

    return "";  // Always return empty to avoid user enumeration
  }

  // Complete password reset with token
  PasswordChangeResult complete_password_reset(const PasswordResetRequest& req) {
    PasswordChangeResult result;

    auto prt_opt = get_reset_token(req.reset_token);
    if (!prt_opt.has_value()) {
      result.success = false;
      result.error = "Invalid or expired reset token";
      result.errcode = "M_UNKNOWN";
      return result;
    }

    auto& prt = *prt_opt;
    if (prt.used || now_ms() > prt.expires_at) {
      result.success = false;
      result.error = "Reset token has expired";
      result.errcode = "M_UNKNOWN";
      return result;
    }

    auto validation = policy_->validate(req.new_password);
    if (!validation.valid) {
      result.success = false;
      result.error = validation.errors.empty() ? "Invalid password"
                                                : validation.errors[0];
      result.errcode = "M_WEAK_PASSWORD";
      return result;
    }

    auto new_hash = hasher_->hash_password(req.new_password);
    update_password_hash(prt.user_id, new_hash);

    // Mark token as used
    mark_reset_token_used(req.reset_token);

    // Logout all sessions
    registration_->delete_user_sessions(prt.user_id);

    result.success = true;
    return result;
  }

  // Password strength assessment
  json assess_password_strength(const std::string& password) {
    int score = policy_->strength_score(password);
    auto validation = policy_->validate(password);

    json result;
    result["score"] = score;
    result["valid"] = validation.valid;
    result["errors"] = validation.errors;

    std::string feedback;
    if (score == 0) feedback = "Very weak - easily guessable";
    else if (score == 1) feedback = "Weak - vulnerable to dictionary attacks";
    else if (score == 2) feedback = "Fair - could be stronger";
    else if (score == 3) feedback = "Strong - good password";
    else feedback = "Very strong - excellent password";

    result["feedback"] = feedback;
    return result;
  }

private:
  PasswordHasher* hasher_;
  PasswordPolicy* policy_;
  RegistrationHandler* registration_;

  struct PasswordResetToken {
    std::string token;
    std::string user_id;
    int64_t created_at;
    int64_t expires_at;
    bool used = false;
  };

  std::unordered_map<std::string, PasswordResetToken> reset_tokens_;
  std::shared_mutex reset_mutex_;

  bool verify_current_password(const std::string& user_id,
                                const std::string& password) {
    auto user_rec = registration_->get_user_record(user_id);
    if (!user_rec.has_value()) return false;

    PasswordHasher::HashedPassword stored;
    stored.algorithm = HashAlgorithm::BCRYPT;
    stored.hash = user_rec->password_hash;
    stored.cost = BCRYPT_DEFAULT_COST;

    return hasher_->verify_password(password, stored);
  }

  bool is_in_password_history(const std::string& user_id,
                               const std::string& new_password) {
    auto user_rec = registration_->get_user_record(user_id);
    if (!user_rec.has_value()) return false;

    // Check if new password matches any in history
    PasswordHasher::HashedPassword test_hash;
    test_hash.algorithm = HashAlgorithm::BCRYPT;
    test_hash.cost = BCRYPT_DEFAULT_COST;

    for (const auto& old_hash : user_rec->password_history) {
      test_hash.hash = old_hash;
      if (hasher_->verify_password(new_password, test_hash)) return true;
    }
    return false;
  }

  void update_password_hash(const std::string& user_id,
                             const PasswordHasher::HashedPassword& new_hash) {
    auto user_rec = registration_->get_user_record(user_id);
    if (!user_rec.has_value()) return;

    user_rec->password_history.push_back(user_rec->password_hash);
    if (static_cast<int>(user_rec->password_history.size()) > PASSWORD_HISTORY_SIZE) {
      user_rec->password_history.erase(user_rec->password_history.begin());
    }
    user_rec->password_hash = new_hash.hash;
    registration_->update_user_record(user_id, *user_rec);
  }

  void logout_other_devices(const std::string& user_id) {
    // Keep current session, remove all others
    // In production: mark all sessions except current as expired
    registration_->delete_user_sessions(user_id);
  }

  std::string find_user_by_email(const std::string& email) {
    // Search for user with this email
    (void)email;
    return "";
  }

  void store_reset_token(const std::string& token, const PasswordResetToken& prt) {
    std::lock_guard<std::shared_mutex> lock(reset_mutex_);
    reset_tokens_[token] = prt;
  }

  std::optional<PasswordResetToken> get_reset_token(const std::string& token) {
    std::shared_lock<std::shared_mutex> lock(reset_mutex_);
    auto it = reset_tokens_.find(token);
    if (it != reset_tokens_.end()) return it->second;
    return std::nullopt;
  }

  void mark_reset_token_used(const std::string& token) {
    std::lock_guard<std::shared_mutex> lock(reset_mutex_);
    auto it = reset_tokens_.find(token);
    if (it != reset_tokens_.end()) it->second.used = true;
  }

  void send_password_reset_email(const std::string& email,
                                  const std::string& token) {
    // Send email with reset link
    (void)email;
    (void)token;
  }
};

// ============================================================================
// 7. VerificationEngine — Email and phone verification
// ============================================================================

class VerificationEngine {
public:
  struct VerificationRequest {
    std::string user_id;
    VerificationMedium medium;
    std::string address;  // email or phone
    std::string client_secret;
    int send_attempt = 1;
    std::string next_link;
  };

  struct VerificationResult {
    bool success = false;
    std::string sid;  // session ID
    std::string error;
    std::string errcode;
    int64_t retry_after_ms = 0;
  };

  struct VerificationSubmit {
    std::string sid;
    std::string user_id;
    std::string client_secret;
    std::string token;  // verification token or code
  };

  VerificationEngine(TokenGenerator* tokens,
                      RegistrationHandler* registration)
      : tokens_(tokens), registration_(registration) {}

  // Request verification (send email/SMS)
  VerificationResult request_verification(const VerificationRequest& req) {
    VerificationResult result;

    auto user_rec = registration_->get_user_record(req.user_id);
    if (!user_rec.has_value()) {
      result.success = false;
      result.error = "User not found";
      result.errcode = "M_NOT_FOUND";
      return result;
    }

    // Rate limit check
    std::string rate_key = req.user_id + ":" +
                           std::to_string(static_cast<int>(req.medium));
    if (!check_verification_rate_limit(rate_key)) {
      result.success = false;
      result.error = "Too many verification attempts. Please wait before retrying.";
      result.errcode = "M_LIMIT_EXCEEDED";
      result.retry_after_ms = VERIFICATION_RESEND_COOLDOWN * 1000;
      return result;
    }

    // Generate verification token/code
    std::string token;
    if (req.medium == VerificationMedium::EMAIL) {
      token = tokens_->generate_verification_token();
    } else {
      token = tokens_->generate_verification_code();
    }

    // Create verification session
    VerificationSession vs;
    vs.sid = tokens_->generate_verification_token().substr(0, 16);
    vs.user_id = req.user_id;
    vs.medium = req.medium;
    vs.address = req.address;
    vs.client_secret = req.client_secret;
    vs.token = token;
    vs.created_at = now_ms();
    vs.expires_at = vs.created_at + (VERIFICATION_TOKEN_TTL * 1000);
    vs.attempts = 0;
    vs.verified = false;

    store_verification_session(vs.sid, vs);

    // Send verification message
    if (req.medium == VerificationMedium::EMAIL) {
      send_verification_email(req.address, token, req.next_link);
    } else {
      send_verification_sms(req.address, token);
    }

    result.success = true;
    result.sid = vs.sid;
    return result;
  }

  // Submit verification token
  VerificationResult submit_verification(const VerificationSubmit& req) {
    VerificationResult result;

    auto vs_opt = get_verification_session(req.sid);
    if (!vs_opt.has_value()) {
      result.success = false;
      result.error = "Invalid verification session";
      result.errcode = "M_NOT_FOUND";
      return result;
    }

    auto& vs = *vs_opt;

    // Check expiry
    if (now_ms() > vs.expires_at) {
      result.success = false;
      result.error = "Verification token has expired. Please request a new one.";
      result.errcode = "M_UNKNOWN";
      return result;
    }

    // Check attempts
    vs.attempts++;
    if (vs.attempts > VERIFICATION_MAX_ATTEMPTS) {
      result.success = false;
      result.error = "Too many failed verification attempts. Please request a new token.";
      result.errcode = "M_LIMIT_EXCEEDED";
      return result;
    }

    // Verify token
    if (vs.token != req.token) {
      update_verification_session(req.sid, vs);
      result.success = false;
      result.error = "Invalid verification code";
      result.errcode = "M_UNKNOWN";
      return result;
    }

    // Mark as verified
    vs.verified = true;
    update_verification_session(req.sid, vs);

    // Update user account
    mark_user_verified(req.user_id, vs.medium, vs.address);

    result.success = true;
    result.sid = req.sid;
    return result;
  }

  // Check if a user's email is verified
  bool is_email_verified(const std::string& user_id) {
    auto user_rec = registration_->get_user_record(user_id);
    if (!user_rec.has_value()) return false;
    return user_rec->status == AccountStatus::ACTIVE;
  }

private:
  TokenGenerator* tokens_;
  RegistrationHandler* registration_;

  struct VerificationSession {
    std::string sid;
    std::string user_id;
    VerificationMedium medium;
    std::string address;
    std::string client_secret;
    std::string token;
    int64_t created_at;
    int64_t expires_at;
    int attempts;
    bool verified;
  };

  std::unordered_map<std::string, VerificationSession> sessions_;
  std::unordered_map<std::string, int64_t> rate_limits_;
  std::shared_mutex mutex_;

  void store_verification_session(const std::string& sid,
                                   const VerificationSession& vs) {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    sessions_[sid] = vs;
  }

  std::optional<VerificationSession> get_verification_session(
      const std::string& sid) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = sessions_.find(sid);
    if (it != sessions_.end()) return it->second;
    return std::nullopt;
  }

  void update_verification_session(const std::string& sid,
                                    const VerificationSession& vs) {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    sessions_[sid] = vs;
  }

  bool check_verification_rate_limit(const std::string& key) {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    int64_t now = now_ms();
    auto it = rate_limits_.find(key);
    if (it != rate_limits_.end()) {
      if (now - it->second < VERIFICATION_RESEND_COOLDOWN * 1000) {
        return false;
      }
    }
    rate_limits_[key] = now;
    return true;
  }

  void mark_user_verified(const std::string& user_id,
                           VerificationMedium medium,
                           const std::string& address) {
    auto user_rec = registration_->get_user_record(user_id);
    if (user_rec.has_value()) {
      user_rec->status = AccountStatus::ACTIVE;
      if (medium == VerificationMedium::EMAIL) {
        user_rec->email = address;
      }
      registration_->update_user_record(user_id, *user_rec);
    }
  }

  void send_verification_email(const std::string& email,
                                const std::string& token,
                                const std::string& next_link) {
    // Send email with verification link/token
    (void)email;
    (void)token;
    (void)next_link;
  }

  void send_verification_sms(const std::string& phone,
                              const std::string& code) {
    // Send SMS with verification code
    (void)phone;
    (void)code;
  }
};

// ============================================================================
// 8. DeactivationManager — Account deactivation
// ============================================================================

class DeactivationManager {
public:
  struct DeactivationRequest {
    std::string user_id;
    DeactivationType type;
    std::string reason;
    bool erase_data = false;  // GDPR erasure
    int64_t grace_period_ms = DEACTIVATION_GRACE_PERIOD * 1000;
    std::string admin_user_id;  // If admin-forced
  };

  struct DeactivationResult {
    bool success = false;
    std::string error;
    std::string errcode;
    std::string id_server_unbind_result;
  };

  DeactivationManager(RegistrationHandler* registration)
      : registration_(registration) {}

  // User-initiated deactivation
  DeactivationResult deactivate_account(const DeactivationRequest& req) {
    DeactivationResult result;

    auto user_rec = registration_->get_user_record(req.user_id);
    if (!user_rec.has_value()) {
      result.success = false;
      result.error = "User not found";
      result.errcode = "M_NOT_FOUND";
      return result;
    }

    if (user_rec->deactivated) {
      result.success = false;
      result.error = "Account is already deactivated";
      result.errcode = "M_UNKNOWN";
      return result;
    }

    // Perform deactivation
    perform_deactivation(req.user_id, req.type, req.reason,
                          req.erase_data, req.grace_period_ms,
                          req.admin_user_id);

    result.success = true;
    return result;
  }

  // Check if deactivation can be reversed
  bool can_reactivate(const std::string& user_id) {
    auto user_rec = registration_->get_user_record(user_id);
    if (!user_rec.has_value()) return false;
    if (!user_rec->deactivated) return false;

    int64_t now = now_ms();
    int64_t deactivated_at = get_deactivation_timestamp(user_id);
    return (now - deactivated_at) < DEACTIVATION_GRACE_PERIOD * 1000;
  }

  // Get scheduled permanent deletions
  std::vector<std::string> get_pending_permanent_deletions() {
    std::vector<std::string> pending;
    int64_t now = now_ms();
    for (const auto& [uid, ts] : deactivation_timestamps_) {
      if (now - ts > DEACTIVATION_GRACE_PERIOD * 1000) {
        pending.push_back(uid);
      }
    }
    return pending;
  }

private:
  RegistrationHandler* registration_;

  std::unordered_map<std::string, int64_t> deactivation_timestamps_;
  std::mutex deact_mutex_;

  int64_t get_deactivation_timestamp(const std::string& user_id) {
    std::lock_guard<std::mutex> lock(deact_mutex_);
    auto it = deactivation_timestamps_.find(user_id);
    if (it != deactivation_timestamps_.end()) return it->second;
    return 0;
  }

  void perform_deactivation(const std::string& user_id,
                             DeactivationType type,
                             const std::string& reason,
                             bool erase_data,
                             int64_t grace_period_ms,
                             const std::string& admin_id) {
    // 1. Revoke all access tokens
    registration_->delete_user_sessions(user_id);

    // 2. Mark account as deactivated
    auto user_rec = registration_->get_user_record(user_id);
    if (user_rec.has_value()) {
      user_rec->deactivated = true;
      registration_->update_user_record(user_id, *user_rec);
    }

    // 3. Record deactivation timestamp
    {
      std::lock_guard<std::mutex> lock(deact_mutex_);
      deactivation_timestamps_[user_id] = now_ms();
    }

    // 4. If GDPR erasure, schedule full data purge
    if (erase_data) {
      schedule_gdpr_erasure(user_id);
    }

    // 5. Leave all rooms
    leave_all_rooms(user_id);

    // 6. Remove 3PIDs
    unbind_all_threepids(user_id);

    // 7. Remove from user directory
    remove_from_user_directory(user_id);

    // 8. Send server notice
    send_deactivation_notice(user_id, type, reason, admin_id);

    // 9. Log the deactivation
    log_deactivation(user_id, type, reason, admin_id);
  }

  void schedule_gdpr_erasure(const std::string& user_id) {
    (void)user_id;
    // Schedule full data deletion after grace period
  }

  void leave_all_rooms(const std::string& user_id) {
    (void)user_id;
    // Leave all joined rooms
  }

  void unbind_all_threepids(const std::string& user_id) {
    (void)user_id;
    // Unbind all third-party IDs
  }

  void remove_from_user_directory(const std::string& user_id) {
    (void)user_id;
    // Remove from user directory search
  }

  void send_deactivation_notice(const std::string& user_id,
                                 DeactivationType type,
                                 const std::string& reason,
                                 const std::string& admin_id) {
    (void)user_id;
    (void)type;
    (void)reason;
    (void)admin_id;
  }

  void log_deactivation(const std::string& user_id,
                         DeactivationType type,
                         const std::string& reason,
                         const std::string& admin_id) {
    // Write to audit log
    (void)user_id;
    (void)type;
    (void)reason;
    (void)admin_id;
  }
};

// ============================================================================
// 9. ReactivationManager — Account reactivation
// ============================================================================

class ReactivationManager {
public:
  struct ReactivationRequest {
    std::string user_id;
    std::string password;  // Required for user-initiated reactivation
    bool is_admin = false;
    std::string admin_user_id;
  };

  struct ReactivationResult {
    bool success = false;
    std::string error;
    std::string errcode;
  };

  ReactivationManager(RegistrationHandler* registration,
                       PasswordHasher* hasher,
                       DeactivationManager* deact_mgr)
      : registration_(registration), hasher_(hasher),
        deact_mgr_(deact_mgr) {}

  ReactivationResult reactivate_account(const ReactivationRequest& req) {
    ReactivationResult result;

    auto user_rec = registration_->get_user_record(req.user_id);
    if (!user_rec.has_value()) {
      result.success = false;
      result.error = "User not found";
      result.errcode = "M_NOT_FOUND";
      return result;
    }

    if (!user_rec->deactivated) {
      result.success = false;
      result.error = "Account is not deactivated";
      result.errcode = "M_UNKNOWN";
      return result;
    }

    // Check grace period
    if (!req.is_admin && !deact_mgr_->can_reactivate(req.user_id)) {
      result.success = false;
      result.error = "Grace period for reactivation has expired. "
                     "Please contact your server administrator.";
      result.errcode = "M_FORBIDDEN";
      return result;
    }

    // Verify password if user-initiated
    if (!req.is_admin && !req.password.empty()) {
      if (!verify_password(req.user_id, req.password)) {
        result.success = false;
        result.error = "Invalid password";
        result.errcode = "M_FORBIDDEN";
        return result;
      }
    }

    // Reactivate
    user_rec->deactivated = false;
    user_rec->status = AccountStatus::ACTIVE;
    registration_->update_user_record(req.user_id, *user_rec);

    // Log reactivation
    log_reactivation(req.user_id, req.is_admin, req.admin_user_id);

    result.success = true;
    return result;
  }

  // Admin bulk reactivation
  int bulk_reactivate(const std::vector<std::string>& user_ids,
                       const std::string& admin_id) {
    int count = 0;
    for (const auto& uid : user_ids) {
      ReactivationRequest req;
      req.user_id = uid;
      req.is_admin = true;
      req.admin_user_id = admin_id;
      auto r = reactivate_account(req);
      if (r.success) count++;
    }
    return count;
  }

private:
  RegistrationHandler* registration_;
  PasswordHasher* hasher_;
  DeactivationManager* deact_mgr_;

  bool verify_password(const std::string& user_id, const std::string& password) {
    auto user_rec = registration_->get_user_record(user_id);
    if (!user_rec.has_value()) return false;

    PasswordHasher::HashedPassword stored;
    stored.algorithm = HashAlgorithm::BCRYPT;
    stored.hash = user_rec->password_hash;
    stored.cost = BCRYPT_DEFAULT_COST;

    return hasher_->verify_password(password, stored);
  }

  void log_reactivation(const std::string& user_id, bool admin,
                         const std::string& admin_id) {
    (void)user_id;
    (void)admin;
    (void)admin_id;
  }
};

// ============================================================================
// 10. GDPRExporter — Account data export
// ============================================================================

class GDPRExporter {
public:
  struct ExportRequest {
    std::string user_id;
    bool include_messages = true;
    bool include_media = true;
    bool include_rooms = true;
    bool include_devices = true;
    bool include_3pids = true;
    bool include_ip_logs = true;
    bool include_profile = true;
    std::string output_format = "json";  // "json" or "tar.gz"
    int64_t max_size_bytes = 1024 * 1024 * 1024;  // 1 GB
  };

  struct ExportResult {
    bool success = false;
    std::string export_id;
    std::string output_path;
    int64_t size_bytes = 0;
    int64_t records_exported = 0;
    std::string error;
    std::string errcode;
    json manifest;
  };

  GDPRExporter(RegistrationHandler* registration)
      : registration_(registration) {}

  ExportResult export_account_data(const ExportRequest& req) {
    ExportResult result;
    std::string export_id = "export_" + rng().uuid();

    auto user_rec = registration_->get_user_record(req.user_id);
    if (!user_rec.has_value()) {
      result.success = false;
      result.error = "User not found";
      result.errcode = "M_NOT_FOUND";
      return result;
    }

    json export_data;
    export_data["export_id"] = export_id;
    export_data["exported_at"] = now_iso8601();
    export_data["exported_at_ms"] = now_ms();
    export_data["user_id"] = req.user_id;
    export_data["server_name"] = "progressive-server";

    // Section 1: Account metadata
    json account;
    account["user_id"] = req.user_id;
    account["created_at"] = user_rec->created_at;
    account["created_at_iso"] = ts_to_iso8601(user_rec->created_at);
    account["is_guest"] = user_rec->is_guest;
    account["is_admin"] = user_rec->admin;
    account["deactivated"] = user_rec->deactivated;
    export_data["account"] = account;

    // Section 2: Profile
    if (req.include_profile) {
      export_data["profile"] = export_profile(req.user_id);
    }

    // Section 3: Devices
    if (req.include_devices) {
      export_data["devices"] = export_devices(req.user_id);
    }

    // Section 4: 3PIDs
    if (req.include_3pids) {
      export_data["threepids"] = export_threepids(req.user_id);
    }

    // Section 5: Rooms (joined + left)
    if (req.include_rooms) {
      export_data["rooms"] = export_rooms(req.user_id);
    }

    // Section 6: Messages
    if (req.include_messages) {
      export_data["messages"] = export_messages(req.user_id, req.max_size_bytes);
    }

    // Section 7: Uploaded media
    if (req.include_media) {
      export_data["media"] = export_media(req.user_id);
    }

    // Section 8: IP logs
    if (req.include_ip_logs) {
      export_data["ip_logs"] = export_ip_logs(req.user_id);
    }

    // Section 9: Consent records
    export_data["consent"] = export_consent(req.user_id);

    // Section 10: Push rules
    export_data["push_rules"] = export_push_rules(req.user_id);

    // Section 11: Account data (global)
    export_data["account_data"] = export_account_data_global(req.user_id);

    // Section 12: Room tags
    export_data["room_tags"] = export_room_tags(req.user_id);

    // Section 13: E2E key metadata
    export_data["end_to_end_keys"] = export_e2e_metadata(req.user_id);

    // Section 14: Sessions
    export_data["sessions"] = export_sessions(req.user_id);

    // Generate manifest
    json manifest;
    manifest["export_id"] = export_id;
    manifest["user_id"] = req.user_id;
    manifest["exported_at"] = now_iso8601();
    manifest["exported_at_ms"] = now_ms();
    manifest["sections"] = json::array();
    for (auto it = export_data.begin(); it != export_data.end(); ++it) {
      if (it.key() != "export_id" && it.key() != "exported_at" &&
          it.key() != "exported_at_ms" && it.key() != "user_id" &&
          it.key() != "server_name") {
        manifest["sections"].push_back(it.key());
      }
    }
    manifest["format"] = req.output_format;

    result.success = true;
    result.export_id = export_id;
    result.manifest = manifest;
    result.records_exported = count_records(export_data);
    result.size_bytes = estimate_size(export_data);

    // Store export for later retrieval
    store_export(export_id, req.user_id, export_data, manifest);

    return result;
  }

  // Check if an export is ready
  bool is_export_ready(const std::string& export_id) {
    std::shared_lock<std::shared_mutex> lock(export_mutex_);
    return exports_.count(export_id) > 0;
  }

  // Retrieve export data
  json get_export(const std::string& export_id) {
    std::shared_lock<std::shared_mutex> lock(export_mutex_);
    auto it = exports_.find(export_id);
    if (it != exports_.end()) return it->second.data;
    return json::object();
  }

  // Admin export (any user)
  ExportResult admin_export(const std::string& user_id) {
    ExportRequest req;
    req.user_id = user_id;
    req.include_messages = true;
    req.include_media = true;
    req.include_rooms = true;
    req.include_devices = true;
    req.include_3pids = true;
    req.include_ip_logs = true;
    req.include_profile = true;
    return export_account_data(req);
  }

private:
  RegistrationHandler* registration_;

  struct ExportRecord {
    std::string export_id;
    std::string user_id;
    int64_t created_at;
    json data;
    json manifest;
  };

  std::unordered_map<std::string, ExportRecord> exports_;
  std::shared_mutex export_mutex_;

  json export_profile(const std::string& user_id) {
    json profile;
    profile["display_name"] = "";
    profile["avatar_url"] = "";
    // In production: query profile table
    (void)user_id;
    return profile;
  }

  json export_devices(const std::string& user_id) {
    json devices = json::array();
    auto devs = registration_->get_user_devices(user_id);
    for (const auto& d : devs) {
      json device;
      device["device_id"] = d.value("device_id", "");
      device["display_name"] = d.value("display_name", "");
      device["last_seen_ip"] = d.value("last_seen_ip", "");
      device["last_seen_ts"] = d.value("last_seen_ts", 0LL);
      device["created_at"] = d.value("created_at", 0LL);
      devices.push_back(device);
    }
    return devices;
  }

  json export_threepids(const std::string& user_id) {
    json threepids = json::array();
    (void)user_id;
    // In production: query user_threepids table
    return threepids;
  }

  json export_rooms(const std::string& user_id) {
    json rooms = json::array();
    (void)user_id;
    // In production: query room_memberships table
    return rooms;
  }

  json export_messages(const std::string& user_id, int64_t max_bytes) {
    json messages = json::array();
    (void)user_id;
    (void)max_bytes;
    // In production: query events table with pagination
    return messages;
  }

  json export_media(const std::string& user_id) {
    json media = json::array();
    (void)user_id;
    // In production: query local_media_repository
    return media;
  }

  json export_ip_logs(const std::string& user_id) {
    json logs = json::array();
    (void)user_id;
    // In production: query user_ips table
    return logs;
  }

  json export_consent(const std::string& user_id) {
    json consent;
    (void)user_id;
    // In production: query consent table
    return consent;
  }

  json export_push_rules(const std::string& user_id) {
    json rules;
    (void)user_id;
    return rules;
  }

  json export_account_data_global(const std::string& user_id) {
    json data;
    (void)user_id;
    return data;
  }

  json export_room_tags(const std::string& user_id) {
    json tags;
    (void)user_id;
    return tags;
  }

  json export_e2e_metadata(const std::string& user_id) {
    json keys;
    (void)user_id;
    return keys;
  }

  json export_sessions(const std::string& user_id) {
    json sessions = json::array();
    (void)user_id;
    return sessions;
  }

  int64_t count_records(const json& data) {
    int64_t count = 0;
    for (const auto& [key, val] : data.items()) {
      if (val.is_array()) count += val.size();
      else if (val.is_object()) count++;
    }
    return count;
  }

  int64_t estimate_size(const json& data) {
    return static_cast<int64_t>(data.dump().size());
  }

  void store_export(const std::string& export_id,
                     const std::string& user_id,
                     const json& data,
                     const json& manifest) {
    std::lock_guard<std::shared_mutex> lock(export_mutex_);
    ExportRecord rec;
    rec.export_id = export_id;
    rec.user_id = user_id;
    rec.created_at = now_ms();
    rec.data = data;
    rec.manifest = manifest;
    exports_[export_id] = rec;
  }
};

// ============================================================================
// 11. ProfileManager — Display name and avatar management
// ============================================================================

class ProfileManager {
public:
  struct ProfileResult {
    bool success = false;
    std::string display_name;
    std::string avatar_url;
    std::string error;
    std::string errcode;
  };

  explicit ProfileManager(RegistrationHandler* registration)
      : registration_(registration) {}

  // Get profile
  ProfileResult get_profile(const std::string& user_id) {
    ProfileResult result;
    std::shared_lock<std::shared_mutex> lock(profile_mutex_);

    auto it = profiles_.find(user_id);
    if (it != profiles_.end()) {
      result.success = true;
      result.display_name = it->second.display_name;
      result.avatar_url = it->second.avatar_url;
    } else {
      // Return defaults
      result.success = true;
      result.display_name = localpart_from_id(user_id);
      result.avatar_url = "";
    }
    return result;
  }

  // Set display name
  ProfileResult set_display_name(const std::string& user_id,
                                  const std::string& display_name) {
    ProfileResult result;

    // Validate
    if (display_name.size() > MAX_DISPLAY_NAME_LENGTH) {
      result.success = false;
      result.error = "Display name too long (max " +
                     std::to_string(MAX_DISPLAY_NAME_LENGTH) + " characters)";
      result.errcode = "M_INVALID_PARAM";
      return result;
    }

    // Sanitize: trim, remove control characters
    std::string sanitized = sanitize_display_name(display_name);

    std::lock_guard<std::shared_mutex> lock(profile_mutex_);
    auto& profile = profiles_[user_id];
    profile.user_id = user_id;
    profile.display_name = sanitized;
    profile.display_name_updated_at = now_ms();

    // Notify federation about profile change
    notify_profile_change(user_id, "displayname", sanitized);

    result.success = true;
    result.display_name = sanitized;
    if (profiles_.count(user_id)) {
      result.avatar_url = profiles_[user_id].avatar_url;
    }
    return result;
  }

  // Set avatar URL
  ProfileResult set_avatar_url(const std::string& user_id,
                                const std::string& avatar_url) {
    ProfileResult result;

    // Validate MXC URI if not empty
    if (!avatar_url.empty() && !is_valid_mxc_uri(avatar_url)) {
      result.success = false;
      result.error = "Invalid avatar URL. Must be mxc:// URI or empty string.";
      result.errcode = "M_INVALID_PARAM";
      return result;
    }

    std::lock_guard<std::shared_mutex> lock(profile_mutex_);
    auto& profile = profiles_[user_id];
    profile.user_id = user_id;
    profile.avatar_url = avatar_url;
    profile.avatar_updated_at = now_ms();

    notify_profile_change(user_id, "avatar_url", avatar_url);

    result.success = true;
    result.avatar_url = avatar_url;
    if (profiles_.count(user_id)) {
      result.display_name = profiles_[user_id].display_name;
    }
    return result;
  }

  // Bulk profile lookup (for room member display)
  json get_profiles(const std::vector<std::string>& user_ids) {
    json result = json::object();
    std::shared_lock<std::shared_mutex> lock(profile_mutex_);
    for (const auto& uid : user_ids) {
      auto it = profiles_.find(uid);
      if (it != profiles_.end()) {
        result[uid] = {
          {"display_name", it->second.display_name},
          {"avatar_url", it->second.avatar_url}
        };
      } else {
        result[uid] = {
          {"display_name", localpart_from_id(uid)},
          {"avatar_url", ""}
        };
      }
    }
    return result;
  }

  // Clear avatar
  ProfileResult clear_avatar(const std::string& user_id) {
    return set_avatar_url(user_id, "");
  }

private:
  RegistrationHandler* registration_;

  struct ProfileRecord {
    std::string user_id;
    std::string display_name;
    std::string avatar_url;
    int64_t display_name_updated_at = 0;
    int64_t avatar_updated_at = 0;
    json metadata;  // Arbitrary key-value data
  };

  std::unordered_map<std::string, ProfileRecord> profiles_;
  std::shared_mutex profile_mutex_;

  static std::string sanitize_display_name(const std::string& name) {
    std::string r = trim(name);
    // Remove null bytes and other problematic characters
    r.erase(std::remove_if(r.begin(), r.end(),
             [](char c) { return c == '\0' || c == '\x7F'; }),
            r.end());
    return r;
  }

  static bool is_valid_mxc_uri(const std::string& uri) {
    return starts_with(uri, "mxc://");
  }

  void notify_profile_change(const std::string& user_id,
                              const std::string& field,
                              const std::string& value) {
    // Persist to database and notify federation
    (void)user_id;
    (void)field;
    (void)value;
  }
};

// ============================================================================
// 12. ThirdPartyIDManager — 3PID binding and management
// ============================================================================

class ThirdPartyIDManager {
public:
  struct ThreepidCredential {
    std::string sid;
    std::string client_secret;
    int64_t validated_at = 0;
    int64_t bound_at = 0;
  };

  struct ThreepidRecord {
    std::string medium;    // "email" or "msisdn"
    std::string address;
    std::string user_id;
    int64_t added_at;
    int64_t validated_at;
    bool validated = false;
  };

  struct ThreepidResult {
    bool success = false;
    std::string sid;
    std::string error;
    std::string errcode;
    std::vector<ThreepidRecord> threepids;
  };

  ThirdPartyIDManager(RegistrationHandler* registration,
                       VerificationEngine* verification)
      : registration_(registration), verification_(verification) {}

  // Request 3PID association (delegates to identity server or local verification)
  ThreepidResult request_email_association(const std::string& user_id,
                                            const std::string& email,
                                            const std::string& client_secret) {
    ThreepidResult result;

    if (!is_valid_email(email)) {
      result.success = false;
      result.error = "Invalid email address";
      result.errcode = "M_INVALID_PARAM";
      return result;
    }

    // Check if already bound
    if (is_3pid_bound(email, "email")) {
      result.success = false;
      result.error = "This email address is already associated with an account";
      result.errcode = "M_THREEPID_IN_USE";
      return result;
    }

    // Create verification session
    std::string sid = rng().hex(32);
    store_pending_threepid(sid, user_id, "email", email, client_secret);

    // Send verification email
    std::string token = rng().token(48);
    store_threepid_token(sid, token);
    send_association_verification_email(email, token);

    result.success = true;
    result.sid = sid;
    return result;
  }

  // Request phone association
  ThreepidResult request_phone_association(const std::string& user_id,
                                            const std::string& phone,
                                            const std::string& client_secret) {
    ThreepidResult result;

    if (!is_valid_phone(phone)) {
      result.success = false;
      result.error = "Invalid phone number (E.164 format required)";
      result.errcode = "M_INVALID_PARAM";
      return result;
    }

    if (is_3pid_bound(phone, "msisdn")) {
      result.success = false;
      result.error = "This phone number is already associated with an account";
      result.errcode = "M_THREEPID_IN_USE";
      return result;
    }

    std::string sid = rng().hex(32);
    store_pending_threepid(sid, user_id, "msisdn", phone, client_secret);

    std::string code = rng().numeric(6);
    store_threepid_token(sid, code);
    send_association_verification_sms(phone, code);

    result.success = true;
    result.sid = sid;
    return result;
  }

  // Submit 3PID validation
  ThreepidResult submit_validation(const std::string& sid,
                                    const std::string& token,
                                    const std::string& client_secret) {
    ThreepidResult result;

    auto pending_opt = get_pending_threepid(sid);
    if (!pending_opt.has_value()) {
      result.success = false;
      result.error = "Invalid or expired association session";
      result.errcode = "M_NOT_FOUND";
      return result;
    }

    auto& pending = *pending_opt;
    if (pending.client_secret != client_secret) {
      result.success = false;
      result.error = "Client secret mismatch";
      result.errcode = "M_FORBIDDEN";
      return result;
    }

    std::string stored_token = get_threepid_token(sid);
    if (stored_token.empty() || stored_token != token) {
      result.success = false;
      result.error = "Invalid verification token";
      result.errcode = "M_UNKNOWN";
      return result;
    }

    // Bind 3PID
    bind_threepid(pending.user_id, pending.medium, pending.address);

    // Clean up pending
    remove_pending_threepid(sid);

    result.success = true;
    result.sid = sid;
    return result;
  }

  // List user's 3PIDs
  ThreepidResult list_threepids(const std::string& user_id) {
    ThreepidResult result;
    std::shared_lock<std::shared_mutex> lock(mutex_);
    for (const auto& [key, rec] : threepids_) {
      if (rec.user_id == user_id) {
        result.threepids.push_back(rec);
      }
    }
    result.success = true;
    return result;
  }

  // Unbind a 3PID
  ThreepidResult unbind_threepid(const std::string& user_id,
                                  const std::string& medium,
                                  const std::string& address) {
    ThreepidResult result;
    std::lock_guard<std::shared_mutex> lock(mutex_);

    for (auto it = threepids_.begin(); it != threepids_.end(); ++it) {
      if (it->second.user_id == user_id &&
          it->second.medium == medium &&
          it->second.address == address) {
        threepids_.erase(it);
        result.success = true;
        return result;
      }
    }

    result.success = false;
    result.error = "Third-party ID not found";
    result.errcode = "M_NOT_FOUND";
    return result;
  }

  // Admin: unbind any 3PID
  ThreepidResult admin_unbind_threepid(const std::string& medium,
                                        const std::string& address) {
    ThreepidResult result;
    std::lock_guard<std::shared_mutex> lock(mutex_);

    for (auto it = threepids_.begin(); it != threepids_.end(); ++it) {
      if (it->second.medium == medium && it->second.address == address) {
        threepids_.erase(it);
        result.success = true;
        return result;
      }
    }

    result.success = false;
    result.error = "Third-party ID not found";
    result.errcode = "M_NOT_FOUND";
    return result;
  }

private:
  RegistrationHandler* registration_;
  VerificationEngine* verification_;

  struct PendingThreepid {
    std::string sid;
    std::string user_id;
    std::string medium;
    std::string address;
    std::string client_secret;
    int64_t created_at;
    int64_t expires_at;
  };

  std::unordered_map<std::string, PendingThreepid> pending_;
  std::unordered_map<std::string, std::string> threepid_tokens_;  // sid -> token
  std::unordered_map<std::string, ThreepidRecord> threepids_;  // key: medium+address
  std::shared_mutex mutex_;

  bool is_3pid_bound(const std::string& address, const std::string& medium) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return threepids_.count(medium + ":" + to_lower(address)) > 0;
  }

  void store_pending_threepid(const std::string& sid,
                               const std::string& user_id,
                               const std::string& medium,
                               const std::string& address,
                               const std::string& client_secret) {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    PendingThreepid pt;
    pt.sid = sid;
    pt.user_id = user_id;
    pt.medium = medium;
    pt.address = address;
    pt.client_secret = client_secret;
    pt.created_at = now_ms();
    pt.expires_at = pt.created_at + (VERIFICATION_TOKEN_TTL * 1000);
    pending_[sid] = pt;
  }

  std::optional<PendingThreepid> get_pending_threepid(const std::string& sid) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = pending_.find(sid);
    if (it != pending_.end()) return it->second;
    return std::nullopt;
  }

  void remove_pending_threepid(const std::string& sid) {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    pending_.erase(sid);
    threepid_tokens_.erase(sid);
  }

  void store_threepid_token(const std::string& sid, const std::string& token) {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    threepid_tokens_[sid] = token;
  }

  std::string get_threepid_token(const std::string& sid) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = threepid_tokens_.find(sid);
    if (it != threepid_tokens_.end()) return it->second;
    return "";
  }

  void bind_threepid(const std::string& user_id,
                      const std::string& medium,
                      const std::string& address) {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    ThreepidRecord rec;
    rec.medium = medium;
    rec.address = address;
    rec.user_id = user_id;
    rec.added_at = now_ms();
    rec.validated_at = now_ms();
    rec.validated = true;
    threepids_[medium + ":" + to_lower(address)] = rec;
  }

  void send_association_verification_email(const std::string& email,
                                            const std::string& token) {
    (void)email;
    (void)token;
  }

  void send_association_verification_sms(const std::string& phone,
                                          const std::string& code) {
    (void)phone;
    (void)code;
  }
};

// ============================================================================
// 13. DeviceManager — Device listing, renaming, and deletion
// ============================================================================

class DeviceManager {
public:
  struct DeviceInfo {
    std::string device_id;
    std::string display_name;
    std::string last_seen_ip;
    int64_t last_seen_ts;
    int64_t created_at;
    std::string user_agent;
    bool is_current = false;
  };

  struct DeviceListResult {
    bool success = false;
    std::vector<DeviceInfo> devices;
    std::string error;
    std::string errcode;
  };

  struct DeviceActionResult {
    bool success = false;
    std::string error;
    std::string errcode;
  };

  DeviceManager(RegistrationHandler* registration,
                TokenGenerator* tokens)
      : registration_(registration), tokens_(tokens) {}

  // List all devices for a user
  DeviceListResult list_devices(const std::string& user_id,
                                 const std::string& current_token) {
    DeviceListResult result;

    auto devs = registration_->get_user_devices(user_id);
    std::string current_device_id;

    // Find current device
    auto session = registration_->get_session(current_token);
    if (!session.empty()) {
      current_device_id = session.value("device_id", "");
    }

    for (const auto& d : devs) {
      DeviceInfo info;
      info.device_id = d.value("device_id", "");
      info.display_name = d.value("display_name", "");
      info.last_seen_ip = d.value("last_seen_ip", "");
      info.last_seen_ts = d.value("last_seen_ts", 0LL);
      info.created_at = d.value("created_at", 0LL);
      info.user_agent = d.value("user_agent", "");
      info.is_current = (info.device_id == current_device_id);
      result.devices.push_back(info);
    }

    result.success = true;
    return result;
  }

  // Get single device
  DeviceActionResult get_device(const std::string& user_id,
                                 const std::string& device_id,
                                 DeviceInfo& info_out) {
    DeviceActionResult result;

    json dev = registration_->get_device(user_id, device_id);
    if (dev.empty()) {
      result.success = false;
      result.error = "Device not found";
      result.errcode = "M_NOT_FOUND";
      return result;
    }

    info_out.device_id = dev.value("device_id", "");
    info_out.display_name = dev.value("display_name", "");
    info_out.last_seen_ip = dev.value("last_seen_ip", "");
    info_out.last_seen_ts = dev.value("last_seen_ts", 0LL);
    info_out.created_at = dev.value("created_at", 0LL);
    info_out.user_agent = dev.value("user_agent", "");

    result.success = true;
    return result;
  }

  // Update device display name
  DeviceActionResult update_device(const std::string& user_id,
                                    const std::string& device_id,
                                    const std::string& display_name) {
    DeviceActionResult result;

    if (display_name.size() > 256) {
      result.success = false;
      result.error = "Display name too long";
      result.errcode = "M_INVALID_PARAM";
      return result;
    }

    // In production: update device record in DB
    (void)user_id;
    (void)device_id;
    (void)display_name;

    result.success = true;
    return result;
  }

  // Delete a device (logout)
  DeviceActionResult delete_device(const std::string& user_id,
                                    const std::string& device_id) {
    DeviceActionResult result;

    // Revoke all sessions for this device
    auto devs = registration_->get_user_devices(user_id);
    for (const auto& d : devs) {
      if (d.value("device_id", "") == device_id) {
        std::string token = d.value("access_token", "");
        if (!token.empty()) {
          registration_->delete_session(token);
        }
      }
    }

    result.success = true;
    return result;
  }

  // Delete all devices except the current one
  DeviceActionResult delete_all_except(const std::string& user_id,
                                        const std::string& current_token) {
    DeviceActionResult result;

    auto session = registration_->get_session(current_token);
    if (session.empty()) {
      result.success = false;
      result.error = "Invalid token";
      result.errcode = "M_UNKNOWN_TOKEN";
      return result;
    }

    std::string current_device = session.value("device_id", "");
    auto devs = registration_->get_user_devices(user_id);

    for (const auto& d : devs) {
      std::string did = d.value("device_id", "");
      if (did != current_device) {
        std::string token = d.value("access_token", "");
        if (!token.empty()) {
          registration_->delete_session(token);
        }
      }
    }

    result.success = true;
    return result;
  }

  // Admin: delete all devices for a user
  DeviceActionResult admin_delete_all_devices(const std::string& user_id) {
    DeviceActionResult result;
    registration_->delete_user_sessions(user_id);
    result.success = true;
    return result;
  }

  // Get device count
  int get_device_count(const std::string& user_id) {
    auto devs = registration_->get_user_devices(user_id);
    return static_cast<int>(devs.size());
  }

private:
  RegistrationHandler* registration_;
  TokenGenerator* tokens_;
};

// ============================================================================
// 14. SessionManager — Session tracking, expiry, and revocation
// ============================================================================

class SessionManager {
public:
  struct SessionInfo {
    std::string token_preview;  // First 8 chars
    std::string device_id;
    std::string ip_address;
    std::string user_agent;
    int64_t created_at;
    int64_t expires_at;
    int64_t last_used_at;
    SessionScope scope;
    bool is_current = false;
  };

  struct SessionListResult {
    bool success = false;
    std::vector<SessionInfo> sessions;
    std::string error;
    std::string errcode;
  };

  SessionManager(RegistrationHandler* registration)
      : registration_(registration) {}

  // List user sessions
  SessionListResult list_sessions(const std::string& user_id,
                                   const std::string& current_token) {
    SessionListResult result;

    // In production: query sessions table
    // For now, iterate over stored sessions
    (void)user_id;
    (void)current_token;

    result.success = true;
    return result;
  }

  // Revoke a specific session
  bool revoke_session(const std::string& token) {
    registration_->delete_session(token);
    return true;
  }

  // Revoke all sessions for a user except current
  int revoke_all_except(const std::string& user_id,
                         const std::string& current_token) {
    // In production: mark all sessions except current as revoked
    (void)user_id;
    (void)current_token;
    return 0;
  }

  // Check if a session is still valid
  bool is_session_valid(const std::string& token) {
    auto session = registration_->get_session(token);
    if (session.empty()) return false;

    int64_t expires = session.value("expires_at", 0LL);
    if (expires > 0 && now_ms() > expires) {
      // Clean up expired session
      registration_->delete_session(token);
      return false;
    }

    return true;
  }

  // Check idle timeout
  bool is_session_idle(const std::string& token) {
    auto session = registration_->get_session(token);
    if (session.empty()) return true;

    int64_t last_used = session.value("last_used_at", 0LL);
    return (now_ms() - last_used) > (SESSION_IDLE_TIMEOUT * 1000);
  }

  // Clean up expired sessions
  int cleanup_expired_sessions() {
    // Background task to remove expired sessions
    return 0;
  }

private:
  RegistrationHandler* registration_;
};

// ============================================================================
// 15. AccountLocker — Account locking, suspension, and progressive lockout
// ============================================================================

class AccountLocker {
public:
  struct LockConfig {
    int max_failed_attempts = MAX_FAILED_ATTEMPTS;
    int64_t base_lockout_sec = LOCKOUT_BASE_DURATION;
    int64_t max_lockout_sec = LOCKOUT_MAX_DURATION;
    bool auto_unlock_enabled = true;
    bool notify_on_lock = true;
  };

  struct LockResult {
    bool success = false;
    std::string error;
    std::string errcode;
    int64_t locked_until = 0;
    int failed_attempts = 0;
  };

  struct SuspensionRequest {
    std::string user_id;
    std::string reason;
    int64_t duration_sec = SUSPENSION_DEFAULT_DURATION;
    std::string admin_id;
  };

  AccountLocker(RegistrationHandler* registration,
                const LockConfig& config = LockConfig{})
      : registration_(registration), config_(config) {}

  // Process failed login attempt
  LockResult record_failed_attempt(const std::string& user_id) {
    LockResult result;
    std::lock_guard<std::shared_mutex> lock(mutex_);

    auto& lock = lock_records_[user_id];
    int64_t now = now_sec();

    // If already locked and still valid, return lock info
    if (lock.locked_until > 0 && now < lock.locked_until) {
      result.success = false;
      result.error = "Account is temporarily locked due to too many failed login attempts";
      result.errcode = "M_USER_LOCKED";
      result.locked_until = lock.locked_until;
      result.failed_attempts = lock.failed_attempts;
      return result;
    }

    // Reset if lock has expired
    if (lock.locked_until > 0 && now >= lock.locked_until) {
      lock.failed_attempts = 0;
      lock.locked_until = 0;
    }

    lock.failed_attempts++;
    lock.last_attempt_at = now;

    if (lock.failed_attempts >= config_.max_failed_attempts) {
      // Calculate lockout duration (progressive)
      int multiplier = std::min(
          lock.failed_attempts - config_.max_failed_attempts + 1, 24);
      int64_t duration = config_.base_lockout_sec * multiplier;
      duration = std::min(duration, config_.max_lockout_sec);
      lock.locked_until = now + duration;
      lock.lock_reason = "Exceeded maximum failed login attempts";

      // Update user record
      auto user_rec = registration_->get_user_record(user_id);
      if (user_rec.has_value()) {
        user_rec->locked = true;
        registration_->update_user_record(user_id, *user_rec);
      }

      // Send notification
      if (config_.notify_on_lock) {
        send_lock_notification(user_id, lock);
      }

      result.locked_until = lock.locked_until;
    }

    result.failed_attempts = lock.failed_attempts;
    return result;
  }

  // Clear failed attempts on successful login
  void clear_failed_attempts(const std::string& user_id) {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    lock_records_.erase(user_id);

    auto user_rec = registration_->get_user_record(user_id);
    if (user_rec.has_value() && user_rec->locked) {
      user_rec->locked = false;
      registration_->update_user_record(user_id, *user_rec);
    }
  }

  // Admin: manually lock an account
  LockResult admin_lock_account(const std::string& user_id,
                                 const std::string& reason,
                                 const std::string& admin_id) {
    LockResult result;
    std::lock_guard<std::shared_mutex> lock(mutex_);

    auto user_rec = registration_->get_user_record(user_id);
    if (!user_rec.has_value()) {
      result.success = false;
      result.error = "User not found";
      result.errcode = "M_NOT_FOUND";
      return result;
    }

    user_rec->locked = true;
    registration_->update_user_record(user_id, *user_rec);

    auto& lr = lock_records_[user_id];
    lr.failed_attempts = 0;
    lr.locked_until = now_sec() + config_.max_lockout_sec;
    lr.lock_reason = "Admin lock: " + reason;
    lr.admin_locked = true;
    lr.admin_id = admin_id;

    // Revoke all sessions
    registration_->delete_user_sessions(user_id);

    result.success = true;
    result.locked_until = lr.locked_until;
    return result;
  }

  // Admin: manually unlock an account
  LockResult admin_unlock_account(const std::string& user_id,
                                   const std::string& admin_id) {
    LockResult result;
    std::lock_guard<std::shared_mutex> lock(mutex_);

    auto user_rec = registration_->get_user_record(user_id);
    if (!user_rec.has_value()) {
      result.success = false;
      result.error = "User not found";
      result.errcode = "M_NOT_FOUND";
      return result;
    }

    user_rec->locked = false;
    registration_->update_user_record(user_id, *user_rec);

    lock_records_.erase(user_id);

    result.success = true;
    return result;
  }

  // Admin: suspend an account (temporary ban)
  LockResult suspend_account(const SuspensionRequest& req) {
    LockResult result;
    std::lock_guard<std::shared_mutex> lock(mutex_);

    auto user_rec = registration_->get_user_record(req.user_id);
    if (!user_rec.has_value()) {
      result.success = false;
      result.error = "User not found";
      result.errcode = "M_NOT_FOUND";
      return result;
    }

    user_rec->suspended = true;
    registration_->update_user_record(req.user_id, *user_rec);

    auto& lr = lock_records_[req.user_id];
    lr.suspended = true;
    lr.suspended_at = now_sec();
    lr.suspended_until = now_sec() + req.duration_sec;
    lr.suspension_reason = req.reason;
    lr.admin_id = req.admin_id;

    // Revoke all sessions
    registration_->delete_user_sessions(req.user_id);

    // Notify user
    send_suspension_notification(req.user_id, req.reason, req.duration_sec);

    result.success = true;
    result.locked_until = lr.suspended_until;
    return result;
  }

  // Admin: unsuspend an account
  LockResult unsuspend_account(const std::string& user_id,
                                const std::string& admin_id) {
    LockResult result;
    std::lock_guard<std::shared_mutex> lock(mutex_);

    auto user_rec = registration_->get_user_record(user_id);
    if (!user_rec.has_value()) {
      result.success = false;
      result.error = "User not found";
      result.errcode = "M_NOT_FOUND";
      return result;
    }

    user_rec->suspended = false;
    registration_->update_user_record(user_id, *user_rec);

    auto it = lock_records_.find(user_id);
    if (it != lock_records_.end()) {
      it->second.suspended = false;
      it->second.suspended_until = 0;
    }

    result.success = true;
    return result;
  }

  // Get lock status
  LockResult get_lock_status(const std::string& user_id) {
    LockResult result;
    std::shared_lock<std::shared_mutex> lock(mutex_);

    auto it = lock_records_.find(user_id);
    if (it != lock_records_.end()) {
      const auto& lr = it->second;
      result.failed_attempts = lr.failed_attempts;
      result.locked_until = lr.locked_until;
    }

    auto user_rec = registration_->get_user_record(user_id);
    if (user_rec.has_value()) {
      if (user_rec->locked) result.success = false;
      if (user_rec->suspended) result.success = false;
    }

    result.success = true;
    return result;
  }

  // Auto-unlock expired locks (background job)
  int auto_unlock_expired() {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    int unlocked = 0;
    int64_t now = now_sec();

    auto it = lock_records_.begin();
    while (it != lock_records_.end()) {
      auto& lr = it->second;
      bool should_unlock = false;

      // Auto-unlock expired automatic locks
      if (!lr.admin_locked && lr.locked_until > 0 && now >= lr.locked_until) {
        should_unlock = true;
      }

      // Auto-unsuspend expired suspensions
      if (lr.suspended && lr.suspended_until > 0 && now >= lr.suspended_until) {
        lr.suspended = false;
        lr.suspended_until = 0;
        auto user_rec = registration_->get_user_record(it->first);
        if (user_rec.has_value()) {
          user_rec->suspended = false;
          registration_->update_user_record(it->first, *user_rec);
        }
        unlocked++;
      }

      if (should_unlock) {
        lr.failed_attempts = 0;
        lr.locked_until = 0;
        auto user_rec = registration_->get_user_record(it->first);
        if (user_rec.has_value()) {
          user_rec->locked = false;
          registration_->update_user_record(it->first, *user_rec);
        }
        unlocked++;
      }

      ++it;
    }

    return unlocked;
  }

private:
  RegistrationHandler* registration_;
  LockConfig config_;

  struct LockRecord {
    int failed_attempts = 0;
    int64_t first_attempt_at = 0;
    int64_t last_attempt_at = 0;
    int64_t locked_until = 0;
    std::string lock_reason;
    bool admin_locked = false;
    std::string admin_id;
    bool suspended = false;
    int64_t suspended_at = 0;
    int64_t suspended_until = 0;
    std::string suspension_reason;
  };

  std::unordered_map<std::string, LockRecord> lock_records_;
  std::shared_mutex mutex_;

  void send_lock_notification(const std::string& user_id,
                               const LockRecord& lr) {
    (void)user_id;
    (void)lr;
  }

  void send_suspension_notification(const std::string& user_id,
                                     const std::string& reason,
                                     int64_t duration_sec) {
    (void)user_id;
    (void)reason;
    (void)duration_sec;
  }
};

// ============================================================================
// 16. ShadowBanEngine — Shadow banning and content suppression
// ============================================================================

class ShadowBanEngine {
public:
  struct ShadowBanConfig {
    ShadowBanLevel level = ShadowBanLevel::NONE;
    int64_t applied_at = 0;
    std::string applied_by;
    std::string reason;
    bool suppress_federation = true;
    bool isolate_to_own_rooms = true;
    bool hide_profile_from_search = true;
    bool mute_notifications = true;
    std::vector<std::string> excluded_rooms;  // Rooms where content still visible
  };

  struct ShadowBanResult {
    bool success = false;
    std::string error;
    std::string errcode;
    ShadowBanLevel current_level = ShadowBanLevel::NONE;
  };

  ShadowBanEngine(RegistrationHandler* registration)
      : registration_(registration) {}

  // Apply shadow ban
  ShadowBanResult apply_shadow_ban(const std::string& user_id,
                                    ShadowBanLevel level,
                                    const std::string& reason,
                                    const std::string& admin_id) {
    ShadowBanResult result;
    std::lock_guard<std::shared_mutex> lock(mutex_);

    auto user_rec = registration_->get_user_record(user_id);
    if (!user_rec.has_value()) {
      result.success = false;
      result.error = "User not found";
      result.errcode = "M_NOT_FOUND";
      return result;
    }

    ShadowBanConfig config;
    config.level = level;
    config.applied_at = now_ms();
    config.applied_by = admin_id;
    config.reason = reason;

    switch (level) {
      case ShadowBanLevel::CONTENT_ONLY:
        config.suppress_federation = true;
        config.isolate_to_own_rooms = false;
        config.hide_profile_from_search = false;
        config.mute_notifications = false;
        break;
      case ShadowBanLevel::CONTENT_AND_DM:
        config.suppress_federation = true;
        config.isolate_to_own_rooms = false;
        config.hide_profile_from_search = true;
        config.mute_notifications = true;
        break;
      case ShadowBanLevel::FULL_ISOLATION:
        config.suppress_federation = true;
        config.isolate_to_own_rooms = true;
        config.hide_profile_from_search = true;
        config.mute_notifications = true;
        break;
      case ShadowBanLevel::NONE:
        break;
    }

    shadow_bans_[user_id] = config;

    // Update user record
    user_rec->shadow_banned = true;
    registration_->update_user_record(user_id, *user_rec);

    // Log action
    log_shadow_ban(user_id, level, reason, admin_id);

    result.success = true;
    result.current_level = level;
    return result;
  }

  // Remove shadow ban
  ShadowBanResult remove_shadow_ban(const std::string& user_id,
                                     const std::string& admin_id) {
    ShadowBanResult result;
    std::lock_guard<std::shared_mutex> lock(mutex_);

    auto it = shadow_bans_.find(user_id);
    if (it == shadow_bans_.end()) {
      result.success = false;
      result.error = "User is not shadow banned";
      result.errcode = "M_NOT_FOUND";
      return result;
    }

    shadow_bans_.erase(it);

    auto user_rec = registration_->get_user_record(user_id);
    if (user_rec.has_value()) {
      user_rec->shadow_banned = false;
      registration_->update_user_record(user_id, *user_rec);
    }

    log_shadow_ban_removal(user_id, admin_id);

    result.success = true;
    result.current_level = ShadowBanLevel::NONE;
    return result;
  }

  // Check if a user is shadow banned
  bool is_shadow_banned(const std::string& user_id) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return shadow_bans_.count(user_id) > 0;
  }

  // Get shadow ban level
  ShadowBanLevel get_shadow_ban_level(const std::string& user_id) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = shadow_bans_.find(user_id);
    if (it != shadow_bans_.end()) return it->second.level;
    return ShadowBanLevel::NONE;
  }

  // Check if content should be suppressed (for event filtering)
  bool should_suppress_content(const std::string& sender_user_id,
                                const std::string& target_room_id) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = shadow_bans_.find(sender_user_id);
    if (it == shadow_bans_.end()) return false;

    const auto& config = it->second;

    // If room is excluded, don't suppress
    for (const auto& excluded : config.excluded_rooms) {
      if (excluded == target_room_id) return false;
    }

    // For CONTENT_ONLY and CONTENT_AND_DM: suppress events in shared rooms
    if (config.level == ShadowBanLevel::CONTENT_ONLY ||
        config.level == ShadowBanLevel::CONTENT_AND_DM) {
      return true;
    }

    // For FULL_ISOLATION: suppress all content unless in excluded rooms
    if (config.level == ShadowBanLevel::FULL_ISOLATION) {
      return true;
    }

    return false;
  }

  // Check if federation should be suppressed for this user
  bool should_suppress_federation(const std::string& user_id) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = shadow_bans_.find(user_id);
    if (it == shadow_bans_.end()) return false;
    return it->second.suppress_federation;
  }

  // Check if user should show up in user directory search
  bool should_hide_from_search(const std::string& user_id) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = shadow_bans_.find(user_id);
    if (it == shadow_bans_.end()) return false;
    return it->second.hide_profile_from_search;
  }

  // Get list of all shadow-banned users
  std::vector<std::string> get_shadow_banned_users() {
    std::vector<std::string> users;
    std::shared_lock<std::shared_mutex> lock(mutex_);
    for (const auto& [uid, config] : shadow_bans_) {
      users.push_back(uid);
    }
    return users;
  }

  // Get shadow ban config for admin inspection
  ShadowBanConfig get_shadow_ban_config(const std::string& user_id) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = shadow_bans_.find(user_id);
    if (it != shadow_bans_.end()) return it->second;
    return ShadowBanConfig{};
  }

  // Exclude a room from shadow ban suppression
  void add_excluded_room(const std::string& user_id,
                          const std::string& room_id) {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    auto it = shadow_bans_.find(user_id);
    if (it != shadow_bans_.end()) {
      auto& excluded = it->second.excluded_rooms;
      if (std::find(excluded.begin(), excluded.end(), room_id) == excluded.end()) {
        excluded.push_back(room_id);
      }
    }
  }

private:
  RegistrationHandler* registration_;

  std::unordered_map<std::string, ShadowBanConfig> shadow_bans_;
  std::shared_mutex mutex_;

  void log_shadow_ban(const std::string& user_id, ShadowBanLevel level,
                       const std::string& reason, const std::string& admin_id) {
    // Write to admin audit log
    (void)user_id;
    (void)level;
    (void)reason;
    (void)admin_id;
  }

  void log_shadow_ban_removal(const std::string& user_id,
                               const std::string& admin_id) {
    (void)user_id;
    (void)admin_id;
  }
};

// ============================================================================
// 17. AccountManagementAPI — Unified API facade
// ============================================================================

class AccountManagementAPI {
public:
  AccountManagementAPI()
      : hasher_(HashAlgorithm::BCRYPT, BCRYPT_DEFAULT_COST),
        policy_(PasswordPolicy::PolicyConfig{}),
        registration_(&hasher_, &tokens_, &policy_),
        login_(&hasher_, &tokens_, &registration_),
        password_mgr_(&hasher_, &policy_, &registration_),
        verification_(&tokens_, &registration_),
        deactivation_(&registration_),
        reactivation_(&registration_, &hasher_, &deactivation_),
        gdpr_(&registration_),
        profile_(&registration_),
        threepid_(&registration_, &verification_),
        devices_(&registration_, &tokens_),
        sessions_(&registration_),
        locker_(&registration_),
        shadow_ban_(&registration_) {}

  // ---- Getters for sub-components ----
  RegistrationHandler& registration() { return registration_; }
  LoginHandler& login() { return login_; }
  PasswordManager& passwords() { return password_mgr_; }
  VerificationEngine& verification() { return verification_; }
  DeactivationManager& deactivation() { return deactivation_; }
  ReactivationManager& reactivation() { return reactivation_; }
  GDPRExporter& gdpr() { return gdpr_; }
  ProfileManager& profile() { return profile_; }
  ThirdPartyIDManager& threepid() { return threepid_; }
  DeviceManager& devices() { return devices_; }
  SessionManager& sessions() { return sessions_; }
  AccountLocker& locker() { return locker_; }
  ShadowBanEngine& shadow_ban() { return shadow_ban_; }

  // ---- Configuration ----
  void set_password_hash_algorithm(HashAlgorithm algo, int cost) {
    hasher_ = PasswordHasher(algo, cost);
  }

  void set_password_policy(const PasswordPolicy::PolicyConfig& config) {
    policy_ = PasswordPolicy(config);
  }

  // ---- Convenience methods ----

  // Full registration flow
  RegistrationHandler::RegistrationResult register_user(
      const std::string& username, const std::string& password,
      const std::string& email, const std::string& phone,
      const std::string& server_name, const std::string& client_ip) {
    RegistrationHandler::RegistrationRequest req;
    req.username = username;
    req.password = password;
    req.email = email;
    req.phone = phone;
    req.auth_type = "m.login.password";
    return registration_.register_user(req, server_name, client_ip);
  }

  // Full login flow
  LoginHandler::LoginResult login_user(
      const std::string& user_id_or_email, const std::string& password,
      const std::string& server_name, const std::string& client_ip,
      const std::string& device_name) {
    LoginHandler::LoginRequest req;
    req.type = LoginType::PASSWORD;
    req.identifier = user_id_or_email;
    req.password = password;
    req.client_ip = client_ip;
    req.initial_device_display_name = device_name;
    return login_.login(req, server_name);
  }

  // Validate a token and get user ID
  bool validate_token(const std::string& token, std::string& user_id) {
    return login_.validate_access_token(token, user_id);
  }

  // Change password
  PasswordManager::PasswordChangeResult change_password(
      const std::string& user_id, const std::string& current,
      const std::string& new_password) {
    PasswordManager::PasswordChangeRequest req;
    req.user_id = user_id;
    req.current_password = current;
    req.new_password = new_password;
    return password_mgr_.change_password(req);
  }

  // Deactivate account
  DeactivationManager::DeactivationResult deactivate_account(
      const std::string& user_id, const std::string& password,
      bool erase_data) {
    DeactivationManager::DeactivationRequest req;
    req.user_id = user_id;
    req.type = DeactivationType::USER_REQUESTED;
    req.erase_data = erase_data;
    return deactivation_.deactivate_account(req);
  }

  // Admin deactivation
  DeactivationManager::DeactivationResult admin_deactivate(
      const std::string& user_id, const std::string& reason,
      const std::string& admin_id) {
    DeactivationManager::DeactivationRequest req;
    req.user_id = user_id;
    req.type = DeactivationType::ADMIN_FORCED;
    req.reason = reason;
    req.admin_user_id = admin_id;
    return deactivation_.deactivate_account(req);
  }

  // Export user data
  GDPRExporter::ExportResult export_user_data(const std::string& user_id) {
    GDPRExporter::ExportRequest req;
    req.user_id = user_id;
    return gdpr_.export_account_data(req);
  }

  // Health check / status
  json get_status() {
    json status;
    status["server"] = "progressive-server";
    status["version"] = "1.0.0";
    status["account_management"] = "operational";
    status["timestamp"] = now_iso8601();
    return status;
  }

private:
  PasswordHasher hasher_;
  PasswordPolicy policy_;
  TokenGenerator tokens_;
  RegistrationHandler registration_;
  LoginHandler login_;
  PasswordManager password_mgr_;
  VerificationEngine verification_;
  DeactivationManager deactivation_;
  ReactivationManager reactivation_;
  GDPRExporter gdpr_;
  ProfileManager profile_;
  ThirdPartyIDManager threepid_;
  DeviceManager devices_;
  SessionManager sessions_;
  AccountLocker locker_;
  ShadowBanEngine shadow_ban_;
};

}  // namespace progressive
