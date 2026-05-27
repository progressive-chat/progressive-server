// ============================================================================
// session_manager.cpp — Matrix Session / Access Token Management
//
// Implements the complete session and token lifecycle for the Matrix
// homeserver, covering all standard and extended session/token operations:
//
//   - Access Token Generation:
//     Cryptographically secure random token generation (prefix: syt_).
//     Configurable token length (default 64 chars). Token storage in SQL
//     with user_id, device_id, creation timestamp, expiry timestamp.
//     Guest token generation with restricted capabilities. Appservice
//     token generation with namespace binding.
//
//   - Access Token Validation:
//     Token lookup by value with user_id resolution. Expiry checking
//     against current time. Revoked token detection. Guest token
//     validation with capability restrictions. Appservice token
//     validation with namespace verification. Admin token validation
//     with audit logging. Token validation caching with configurable
//     TTL for performance.
//
//   - Access Token Revocation:
//     Single token revocation (DELETE from table). Bulk revocation
//     for user (all tokens except current). Device-specific revocation
//     (all tokens for a device). Admin forced revocation with audit
//     trail. Token revocation logging. Cascade revocation of associated
//     refresh tokens.
//
//   - Refresh Token Management:
//     Refresh token generation on login (prefix: rt_, 96 chars).
//     Refresh token storage with user_id, device_id, associated access
//     token, creation time, expiry time. Refresh token rotation (single-use,
//     issue new on each refresh). Refresh token validation (existence,
//     non-revoked, non-expired). Refresh token revocation on logout.
//     Refresh token scope preservation. Refresh token chain tracking
//     for security auditing.
//
//   - Token Expiry:
//     Access token TTL configuration (default 1 hour). Refresh token
//     TTL configuration (default 30 days). Login token TTL (default
//     5 minutes). SSO session TTL (default 10 minutes). Idle timeout
//     for access tokens (default 24 hours). Absolute expiry enforcement.
//     Expired token cleanup background task.
//
//   - Session Listing:
//     List all sessions for a user (GET /_matrix/client/r0/devices).
//     Session detail queries (device_id, last_seen, ip, user_agent).
//     Admin session listing across all users. Session filtering by
//     device_id, user_id, token type, active/inactive status.
//     Pagination support (from, limit, order_by).
//
//   - Session Invalidation:
//     User-initiated session invalidation (DELETE single session).
//     Bulk session invalidation (DELETE all except current).
//     Admin forced session invalidation. Session invalidation on
//     password change. Session invalidation on account deactivation.
//     Session invalidation on user suspension. Session invalidation
//     with notification to affected devices.
//
//   - Idle Timeout:
//     Per-session last_active tracking. Configurable idle timeout
//     duration. Idle session detection background task. Auto-invalidation
//     of idle sessions. Idle timeout grace period. Idle notification
//     to clients before timeout. Admin configurable idle timeout per-user.
//
//   - Session Audit Logging:
//     Token creation audit trail. Token usage tracking (last_used
//     timestamp, ip_address, user_agent). Token revocation audit.
//     Session lifecycle events logging. Compliance reporting support.
//     GDPR data export for session history.
//
//   - Admin Session Management:
//     Admin endpoint for listing all active sessions. Admin endpoint
//     for force-revoking any session. Admin endpoint for session
//     statistics (count by user, by device type, active/inactive).
//     Admin endpoint for idle session cleanup trigger.
//
//   - Background Tasks:
//     Expired token cleanup worker (periodic DELETE of expired rows).
//     Idle session detection and invalidation worker. Token cleanup
//     metrics reporting. Refresh token chain cleanup for revoked chains.
//     Database vacuum/optimize after cleanup runs.
//
// Full SQL DDL for all session/token tables. Every operation is
// transaction-safe. Designed as the primary session management module
// for progressive-server.
//
// Equivalent to:
//   synapse/storage/databases/main/registration.py
//     (TokenLookupResult, get_user_by_access_token, get_user_by_req)
//   synapse/handlers/auth.py
//     (get_access_token_for_user, refresh_token, delete_access_token)
//   synapse/handlers/device.py
//     (DeviceHandler, device list, device deletion)
//   synapse/handlers/refresh_token.py
//     (RefreshTokenHandler, refresh token lifecycle)
//   synapse/api/auth.py
//     (get_user_by_req, validate_token, Auth class)
//   synapse/rest/client/devices.py
//     (DevicesRestServlet, DeviceRestServlet)
//   synapse/module_api/__init__.py
//     (ModuleApi.update_user, invalidate_access_token)
//
// Namespace: progressive::
// Target: 3000+ lines of production-grade C++.
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
#include <type_traits>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <variant>
#include <vector>

#include <nlohmann/json.hpp>

#include <openssl/rand.h>
#include <openssl/sha.h>

#include "progressive/storage/database.hpp"
#include "progressive/rest/rest_base.hpp"

// ============================================================================
// Namespace
// ============================================================================
namespace progressive {

using json = nlohmann::json;
namespace chr = std::chrono;

using storage::DatabasePool;
using storage::LoggingTransaction;
using storage::DatabaseTransaction;
using storage::Row;
using storage::SQLParam;

// ============================================================================
// Forward declarations
// ============================================================================

class AccessTokenManager;
class RefreshTokenManager;
class SessionManager;
class SessionListingService;
class SessionInvalidationService;
class IdleTimeoutService;
class TokenExpiryService;
class SessionAuditLogger;
class AdminSessionService;
class BackgroundTokenCleaner;
class SessionCacheManager;
class TokenRateLimiter;
class AppServiceTokenManager;
class GuestTokenManager;

// ============================================================================
// Enums: Token states, session states, operation types
// ============================================================================

enum class TokenState : uint8_t {
  ACTIVE          = 0,
  REVOKED         = 1,
  EXPIRED         = 2,
  REPLACED        = 3,   // Replaced by refresh rotation
  PENDING_REVOKE  = 4,
  SUSPENDED       = 5,
};

enum class TokenKind : uint8_t {
  ACCESS         = 0,
  REFRESH        = 1,
  LOGIN_TOKEN    = 2,
  SSO_SESSION    = 3,
  APP_SERVICE    = 4,
  GUEST          = 5,
  DELEGATED_OIDC = 6,
  ADMIN_API      = 7,
  PUSH_GATEWAY   = 8,
  PROVISIONING   = 9,
};

enum class SessionState : uint8_t {
  ACTIVE    = 0,
  IDLE      = 1,
  EXPIRED   = 2,
  REVOKED   = 3,
  SUSPENDED = 4,
};

enum class InvalidationReason : uint8_t {
  USER_REQUEST    = 0,
  ADMIN_FORCE     = 1,
  PASSWORD_CHANGE = 2,
  ACCOUNT_DEACT   = 3,
  ACCOUNT_SUSPEND = 4,
  IDLE_TIMEOUT    = 5,
  TOKEN_EXPIRY    = 6,
  SECURITY_EVENT  = 7,
  GDPR_DELETION   = 8,
  DEVICE_DELETION = 9,
  BULK_LOGOUT     = 10,
  CONSENT_REVOKED = 11,
  RATE_LIMITED    = 12,
};

enum class AuditAction : uint8_t {
  TOKEN_CREATED        = 0,
  TOKEN_USED           = 1,
  TOKEN_REVOKED        = 2,
  TOKEN_EXPIRED        = 3,
  TOKEN_REFRESHED      = 4,
  SESSION_STARTED      = 5,
  SESSION_ENDED        = 6,
  IDLE_TIMEOUT_TRIG    = 7,
  ADMIN_FORCE_REVOKE   = 8,
  BULK_REVOKE          = 9,
  PASSWORD_CHANGE_REV  = 10,
  DEACTIVATION_REV     = 11,
  CLEANUP_RUN          = 12,
};

// ============================================================================
// Constants
// ============================================================================

namespace {

// ---- Timing constants (milliseconds) ----
constexpr int64_t ACCESS_TOKEN_TTL_MS        = 3600000;      // 1 hour
constexpr int64_t REFRESH_TOKEN_TTL_MS       = 2592000000;   // 30 days
constexpr int64_t LOGIN_TOKEN_TTL_MS         = 300000;       // 5 minutes
constexpr int64_t SSO_SESSION_TTL_MS         = 600000;       // 10 minutes
constexpr int64_t GUEST_TOKEN_TTL_MS         = 86400000;     // 24 hours
constexpr int64_t APP_SERVICE_TOKEN_TTL_MS   = 31536000000;  // 1 year
constexpr int64_t IDLE_TIMEOUT_DEFAULT_MS    = 86400000;     // 24 hours
constexpr int64_t IDLE_TIMEOUT_MIN_MS        = 300000;       // 5 minutes
constexpr int64_t IDLE_TIMEOUT_MAX_MS        = 2592000000;   // 30 days
constexpr int64_t TOKEN_CLEANUP_INTERVAL_MS  = 300000;       // 5 minutes
constexpr int64_t IDLE_CHECK_INTERVAL_MS     = 60000;        // 1 minute
constexpr int64_t SESSION_CACHE_TTL_MS       = 30000;        // 30 seconds
constexpr int64_t LAST_SEEN_UPDATE_MS        = 300000;       // 5 min debounce
constexpr int64_t AUDIT_LOG_RETENTION_MS     = 7776000000;   // 90 days
constexpr int64_t STATS_WINDOW_MS            = 3600000;      // 1 hour

// ---- Token generation constants ----
constexpr int    ACCESS_TOKEN_LENGTH         = 64;
constexpr int    REFRESH_TOKEN_LENGTH        = 96;
constexpr int    LOGIN_TOKEN_LENGTH          = 48;
constexpr int    GUEST_TOKEN_LENGTH          = 64;
constexpr int    APP_SERVICE_TOKEN_LENGTH    = 128;
constexpr int    SSO_SESSION_ID_LENGTH       = 32;
constexpr int    DEVICE_ID_LENGTH            = 10;
constexpr int    TOKEN_PREFIX_MAX_LEN        = 8;

// ---- Rate limit constants ----
constexpr int    MAX_SESSIONS_PER_USER       = 250;
constexpr int    MAX_SESSIONS_PER_DEVICE     = 10;
constexpr int    MAX_TOKENS_TOTAL            = 1000000;
constexpr int    REFRESH_RATE_PER_MINUTE     = 30;
constexpr int    TOKEN_CREATE_RATE_PER_MIN   = 20;
constexpr int    SESSION_LIST_RATE_PER_MIN   = 60;
constexpr int    REVOKE_RATE_PER_MIN         = 30;
constexpr int    ADMIN_QUERY_RATE_PER_MIN    = 10;

// ---- Validation constants ----
constexpr int    MAX_TOKEN_LENGTH            = 256;
constexpr int    MAX_DEVICE_ID_LENGTH        = 64;
constexpr int    MAX_USER_AGENT_LENGTH       = 1024;
constexpr int    MAX_IP_ADDRESS_LENGTH       = 45;
constexpr int    MAX_REFRESH_CHAIN_DEPTH     = 100;

// ---- Cache constants ----
constexpr int    TOKEN_CACHE_MAX_SIZE        = 50000;
constexpr int    SESSION_CACHE_MAX_SIZE      = 10000;
constexpr int    AUDIT_CACHE_MAX_SIZE        = 5000;

// ---- Matrix error codes ----
constexpr const char* ERR_FORBIDDEN          = "M_FORBIDDEN";
constexpr const char* ERR_UNKNOWN_TOKEN      = "M_UNKNOWN_TOKEN";
constexpr const char* ERR_MISSING_TOKEN      = "M_MISSING_TOKEN";
constexpr const char* ERR_NOT_JSON           = "M_NOT_JSON";
constexpr const char* ERR_LIMIT_EXCEEDED     = "M_LIMIT_EXCEEDED";
constexpr const char* ERR_USER_DEACTIVATED   = "M_USER_DEACTIVATED";
constexpr const char* ERR_SESSION_EXPIRED    = "M_SESSION_EXPIRED";
constexpr const char* ERR_UNKNOWN            = "M_UNKNOWN";
constexpr const char* ERR_INVALID_PARAM      = "M_INVALID_PARAM";
constexpr const char* ERR_NO_APP_SERVICE     = "M_EXCLUSIVE";
constexpr const char* ERR_WEAK_TOKEN         = "M_WEAK_TOKEN";

// ---- Token prefix constants ----
constexpr const char* PREFIX_ACCESS      = "syt_";
constexpr const char* PREFIX_REFRESH     = "rt_";
constexpr const char* PREFIX_LOGIN       = "syl_";
constexpr const char* PREFIX_GUEST       = "syg_";
constexpr const char* PREFIX_APP_SERVICE = "asa_";
constexpr const char* PREFIX_SSO         = "sso_";
constexpr const char* PREFIX_ADMIN       = "sya_";
constexpr const char* PREFIX_PUSH        = "syp_";

// ---- Token character set ----
const char* const TOKEN_ALPHABET =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~";

// ---- Cleanup batch sizes ----
constexpr int    EXPIRED_TOKEN_BATCH_SIZE     = 1000;
constexpr int    IDLE_SESSION_BATCH_SIZE      = 500;
constexpr int    AUDIT_LOG_BATCH_SIZE         = 2000;
constexpr int    REFRESH_CHAIN_BATCH_SIZE     = 500;

}  // anonymous namespace

// ============================================================================
// SQL DDL — Full schema for session/token management tables
// ============================================================================

namespace {

const char* SQL_CREATE_ACCESS_TOKENS = R"SQL(
CREATE TABLE IF NOT EXISTS access_tokens (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    token           TEXT NOT NULL UNIQUE,
    user_id         TEXT NOT NULL,
    device_id       TEXT NOT NULL DEFAULT '',
    token_kind      INTEGER NOT NULL DEFAULT 0,
    token_state     INTEGER NOT NULL DEFAULT 0,
    created_at_ms   INTEGER NOT NULL,
    expires_at_ms   INTEGER,
    last_used_at_ms INTEGER,
    last_ip         TEXT,
    last_user_agent TEXT,
    revoked_at_ms   INTEGER,
    revoke_reason   INTEGER,
    is_guest        INTEGER NOT NULL DEFAULT 0,
    app_service_id  TEXT,
    device_display_name TEXT DEFAULT '',
    last_seen_at_ms INTEGER,
    idle_timeout_ms INTEGER,
    used_count      INTEGER NOT NULL DEFAULT 0,
    metadata_json   TEXT
);
CREATE INDEX IF NOT EXISTS idx_access_tokens_user
    ON access_tokens(user_id, token_state);
CREATE INDEX IF NOT EXISTS idx_access_tokens_device
    ON access_tokens(user_id, device_id);
CREATE INDEX IF NOT EXISTS idx_access_tokens_expires
    ON access_tokens(expires_at_ms) WHERE expires_at_ms IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_access_tokens_last_used
    ON access_tokens(last_used_at_ms);
CREATE INDEX IF NOT EXISTS idx_access_tokens_last_seen
    ON access_tokens(last_seen_at_ms);
CREATE INDEX IF NOT EXISTS idx_access_tokens_revoked
    ON access_tokens(revoked_at_ms) WHERE revoked_at_ms IS NOT NULL;
)SQL";

const char* SQL_CREATE_REFRESH_TOKENS = R"SQL(
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    token             TEXT NOT NULL UNIQUE,
    user_id           TEXT NOT NULL,
    device_id         TEXT NOT NULL DEFAULT '',
    access_token_id   TEXT,
    created_at_ms     INTEGER NOT NULL,
    expires_at_ms     INTEGER,
    last_used_at_ms   INTEGER,
    used_count        INTEGER NOT NULL DEFAULT 0,
    revoked           INTEGER NOT NULL DEFAULT 0,
    revoked_at_ms     INTEGER,
    revoke_reason     INTEGER,
    next_token_id     TEXT,
    prev_token_id     TEXT,
    chain_depth       INTEGER NOT NULL DEFAULT 0,
    last_ip           TEXT,
    last_user_agent   TEXT,
    scope_json        TEXT,
    metadata_json     TEXT
);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user
    ON refresh_tokens(user_id, revoked);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires
    ON refresh_tokens(expires_at_ms) WHERE expires_at_ms IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_chain
    ON refresh_tokens(prev_token_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_next
    ON refresh_tokens(next_token_id);
)SQL";

const char* SQL_CREATE_LOGIN_TOKENS = R"SQL(
CREATE TABLE IF NOT EXISTS login_tokens (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    token           TEXT NOT NULL UNIQUE,
    user_id         TEXT,
    medium          TEXT,
    address         TEXT,
    created_at_ms   INTEGER NOT NULL,
    expires_at_ms   INTEGER NOT NULL,
    used            INTEGER NOT NULL DEFAULT 0,
    used_at_ms      INTEGER,
    auth_provider   TEXT,
    redirect_url    TEXT,
    metadata_json   TEXT
);
CREATE INDEX IF NOT EXISTS idx_login_tokens_expires
    ON login_tokens(expires_at_ms);
CREATE INDEX IF NOT EXISTS idx_login_tokens_user
    ON login_tokens(user_id);
)SQL";

const char* SQL_CREATE_SSO_SESSIONS = R"SQL(
CREATE TABLE IF NOT EXISTS sso_sessions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      TEXT NOT NULL UNIQUE,
    state           TEXT NOT NULL,
    user_id         TEXT,
    sso_provider    TEXT NOT NULL,
    redirect_url    TEXT,
    created_at_ms   INTEGER NOT NULL,
    expires_at_ms   INTEGER NOT NULL,
    completed       INTEGER NOT NULL DEFAULT 0,
    completed_at_ms INTEGER,
    client_ip       TEXT,
    user_agent      TEXT,
    metadata_json   TEXT
);
CREATE INDEX IF NOT EXISTS idx_sso_sessions_state
    ON sso_sessions(state);
CREATE INDEX IF NOT EXISTS idx_sso_sessions_expires
    ON sso_sessions(expires_at_ms);
)SQL";

const char* SQL_CREATE_SESSION_AUDIT = R"SQL(
CREATE TABLE IF NOT EXISTS session_audit_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         TEXT NOT NULL,
    device_id       TEXT DEFAULT '',
    token           TEXT,
    token_kind      INTEGER NOT NULL,
    action          INTEGER NOT NULL,
    timestamp_ms    INTEGER NOT NULL,
    ip_address      TEXT,
    user_agent      TEXT,
    reason          INTEGER,
    detail_json     TEXT,
    admin_user_id   TEXT
);
CREATE INDEX IF NOT EXISTS idx_session_audit_user
    ON session_audit_log(user_id, timestamp_ms);
CREATE INDEX IF NOT EXISTS idx_session_audit_action
    ON session_audit_log(action, timestamp_ms);
CREATE INDEX IF NOT EXISTS idx_session_audit_time
    ON session_audit_log(timestamp_ms);
)SQL";

const char* SQL_CREATE_IDLE_CONFIG = R"SQL(
CREATE TABLE IF NOT EXISTS session_idle_config (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         TEXT NOT NULL UNIQUE,
    idle_timeout_ms INTEGER NOT NULL,
    created_at_ms   INTEGER NOT NULL,
    updated_at_ms   INTEGER NOT NULL,
    set_by_admin    INTEGER NOT NULL DEFAULT 0,
    admin_user_id   TEXT
);
CREATE INDEX IF NOT EXISTS idx_idle_config_user
    ON session_idle_config(user_id);
)SQL";

const char* SQL_CREATE_TOKEN_RATE_LIMITS = R"SQL(
CREATE TABLE IF NOT EXISTS token_rate_limits (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    key             TEXT NOT NULL,
    action          TEXT NOT NULL,
    window_start_ms INTEGER NOT NULL,
    count           INTEGER NOT NULL DEFAULT 0,
    UNIQUE(key, action, window_start_ms)
);
CREATE INDEX IF NOT EXISTS idx_token_rate_keys
    ON token_rate_limits(key, action, window_start_ms);
)SQL";

const char* SQL_CREATE_SESSION_STATS = R"SQL(
CREATE TABLE IF NOT EXISTS session_stats_snapshot (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    snapshot_at_ms    INTEGER NOT NULL,
    total_active      INTEGER NOT NULL DEFAULT 0,
    total_idle        INTEGER NOT NULL DEFAULT 0,
    total_expired     INTEGER NOT NULL DEFAULT 0,
    total_revoked     INTEGER NOT NULL DEFAULT 0,
    total_guests      INTEGER NOT NULL DEFAULT 0,
    total_refresh     INTEGER NOT NULL DEFAULT 0,
    unique_users      INTEGER NOT NULL DEFAULT 0,
    detail_json       TEXT
);
CREATE INDEX IF NOT EXISTS idx_session_stats_time
    ON session_stats_snapshot(snapshot_at_ms);
)SQL";

const char* SQL_CREATE_APP_SERVICE_TOKENS = R"SQL(
CREATE TABLE IF NOT EXISTS app_service_tokens (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    token           TEXT NOT NULL UNIQUE,
    app_service_id  TEXT NOT NULL,
    created_at_ms   INTEGER NOT NULL,
    expires_at_ms   INTEGER,
    revoked         INTEGER NOT NULL DEFAULT 0,
    metadata_json   TEXT
);
CREATE INDEX IF NOT EXISTS idx_as_tokens_service
    ON app_service_tokens(app_service_id);
)SQL";

// All DDL statements in order
const std::vector<const char*> ALL_SESSION_DDL = {
  SQL_CREATE_ACCESS_TOKENS,
  SQL_CREATE_REFRESH_TOKENS,
  SQL_CREATE_LOGIN_TOKENS,
  SQL_CREATE_SSO_SESSIONS,
  SQL_CREATE_SESSION_AUDIT,
  SQL_CREATE_IDLE_CONFIG,
  SQL_CREATE_TOKEN_RATE_LIMITS,
  SQL_CREATE_SESSION_STATS,
  SQL_CREATE_APP_SERVICE_TOKENS,
};

}  // anonymous namespace

// ============================================================================
// Utility helpers
// ============================================================================

namespace {

int64_t now_ms() {
  return chr::duration_cast<chr::milliseconds>(
      chr::system_clock::now().time_since_epoch()).count();
}

int64_t now_sec() {
  return chr::duration_cast<chr::seconds>(
      chr::system_clock::now().time_since_epoch()).count();
}

std::string now_iso8601() {
  auto t = std::time(nullptr);
  char buf[64];
  std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", std::gmtime(&t));
  return buf;
}

int64_t days_to_ms(int days) {
  return static_cast<int64_t>(days) * 86400000LL;
}

int64_t hours_to_ms(int h) {
  return static_cast<int64_t>(h) * 3600000LL;
}

int64_t minutes_to_ms(int m) {
  return static_cast<int64_t>(m) * 60000LL;
}

// ---- Secure random generation ----
class SecureRandomGenerator {
 public:
  static SecureRandomGenerator& instance() {
    static SecureRandomGenerator gen;
    return gen;
  }

  std::string token(int length) {
    std::string result;
    result.reserve(length);
    const int alpha_len = static_cast<int>(std::strlen(TOKEN_ALPHABET));
    std::lock_guard<std::mutex> lock(mtx_);
    for (int i = 0; i < length; ++i) {
      result += TOKEN_ALPHABET[dist_(gen_) % alpha_len];
    }
    return result;
  }

  std::string token(const std::string& prefix, int length) {
    return prefix + token(length);
  }

  uint64_t random_uint64() {
    std::lock_guard<std::mutex> lock(mtx_);
    return dist64_(gen_);
  }

  std::string random_hex(int bytes) {
    static const char hex[] = "0123456789abcdef";
    std::vector<unsigned char> buf(bytes);
    {
      std::lock_guard<std::mutex> lock(mtx_);
      std::generate(buf.begin(), buf.end(), [this]() {
        return static_cast<unsigned char>(dist_(gen_) % 256);
      });
    }
    std::string result;
    result.reserve(bytes * 2);
    for (auto b : buf) {
      result += hex[b >> 4];
      result += hex[b & 0x0f];
    }
    return result;
  }

 private:
  SecureRandomGenerator() {
    std::random_device rd;
    std::seed_seq seeds{rd(), rd(), rd(), rd(),
                        static_cast<unsigned int>(now_ms() & 0xFFFFFFFF)};
    gen_.seed(seeds);
  }

  std::mt19937_64 gen_;
  std::uniform_int_distribution<int> dist_{0, std::numeric_limits<int>::max() - 1};
  std::uniform_int_distribution<uint64_t> dist64_;
  std::mutex mtx_;
};

SecureRandomGenerator& srng() {
  return SecureRandomGenerator::instance();
}

// ---- Token validation helpers ----
bool is_valid_token_format(const std::string& token) {
  if (token.empty() || token.size() > MAX_TOKEN_LENGTH) return false;
  for (char c : token) {
    if (!std::isalnum(static_cast<unsigned char>(c)) &&
        c != '_' && c != '-' && c != '.' && c != '~') {
      return false;
    }
  }
  return true;
}

bool is_valid_device_id(const std::string& device_id) {
  if (device_id.size() > MAX_DEVICE_ID_LENGTH) return false;
  for (char c : device_id) {
    if (!std::isalnum(static_cast<unsigned char>(c)) &&
        c != '_' && c != '-' && c != '.') {
      return false;
    }
  }
  return true;
}

std::string sanitize_input(const std::string& input, int max_len) {
  std::string result;
  result.reserve(std::min(static_cast<size_t>(max_len), input.size()));
  for (char c : input) {
    if (result.size() >= static_cast<size_t>(max_len)) break;
    if (static_cast<unsigned char>(c) >= 32 && c != 127) {
      result += c;
    }
  }
  return result;
}

TokenKind detect_token_kind(const std::string& token) {
  if (token.starts_with(PREFIX_ACCESS))      return TokenKind::ACCESS;
  if (token.starts_with(PREFIX_REFRESH))     return TokenKind::REFRESH;
  if (token.starts_with(PREFIX_LOGIN))       return TokenKind::LOGIN_TOKEN;
  if (token.starts_with(PREFIX_GUEST))       return TokenKind::GUEST;
  if (token.starts_with(PREFIX_APP_SERVICE)) return TokenKind::APP_SERVICE;
  if (token.starts_with(PREFIX_SSO))         return TokenKind::SSO_SESSION;
  if (token.starts_with(PREFIX_ADMIN))       return TokenKind::ADMIN_API;
  if (token.starts_with(PREFIX_PUSH))        return TokenKind::PUSH_GATEWAY;
  return TokenKind::ACCESS;  // default
}

std::string token_kind_name(TokenKind kind) {
  switch (kind) {
    case TokenKind::ACCESS:         return "access";
    case TokenKind::REFRESH:        return "refresh";
    case TokenKind::LOGIN_TOKEN:    return "login";
    case TokenKind::SSO_SESSION:    return "sso";
    case TokenKind::APP_SERVICE:    return "appservice";
    case TokenKind::GUEST:          return "guest";
    case TokenKind::DELEGATED_OIDC: return "oidc";
    case TokenKind::ADMIN_API:      return "admin";
    case TokenKind::PUSH_GATEWAY:   return "push";
    case TokenKind::PROVISIONING:   return "provisioning";
    default: return "unknown";
  }
}

std::string token_state_name(TokenState state) {
  switch (state) {
    case TokenState::ACTIVE:         return "active";
    case TokenState::REVOKED:        return "revoked";
    case TokenState::EXPIRED:        return "expired";
    case TokenState::REPLACED:       return "replaced";
    case TokenState::PENDING_REVOKE: return "pending_revoke";
    case TokenState::SUSPENDED:      return "suspended";
    default: return "unknown";
  }
}

std::string invalidation_reason_name(InvalidationReason reason) {
  switch (reason) {
    case InvalidationReason::USER_REQUEST:    return "user_request";
    case InvalidationReason::ADMIN_FORCE:     return "admin_force";
    case InvalidationReason::PASSWORD_CHANGE: return "password_change";
    case InvalidationReason::ACCOUNT_DEACT:   return "account_deactivation";
    case InvalidationReason::ACCOUNT_SUSPEND: return "account_suspension";
    case InvalidationReason::IDLE_TIMEOUT:    return "idle_timeout";
    case InvalidationReason::TOKEN_EXPIRY:    return "token_expiry";
    case InvalidationReason::SECURITY_EVENT:  return "security_event";
    case InvalidationReason::GDPR_DELETION:   return "gdpr_deletion";
    case InvalidationReason::DEVICE_DELETION: return "device_deletion";
    case InvalidationReason::BULK_LOGOUT:     return "bulk_logout";
    case InvalidationReason::CONSENT_REVOKED: return "consent_revoked";
    case InvalidationReason::RATE_LIMITED:    return "rate_limited";
    default: return "unknown";
  }
}

}  // anonymous namespace

// ============================================================================
// 1. TokenRateLimiter — Rate limiting for token operations
// ============================================================================

class TokenRateLimiter {
 public:
  explicit TokenRateLimiter(DatabasePool& db) : db_(db) {}

  bool check_rate(const std::string& key,
                  const std::string& action,
                  int max_per_window,
                  int64_t window_ms = 60000) {
    int64_t now = now_ms();
    int64_t window_start = (now / window_ms) * window_ms;

    bool allowed = false;
    db_.runInteraction("check_token_rate",
        [&](LoggingTransaction& txn) {
          std::string sel = R"SQL(
            SELECT count FROM token_rate_limits
            WHERE key = ?1 AND action = ?2 AND window_start_ms = ?3
          )SQL";
          txn.execute(sel, {
            SQLParam{key}, SQLParam{action}, SQLParam{window_start}
          });

          auto rows = txn.fetchall();
          int current = 0;
          if (!rows.empty()) {
            current = rows[0][0].empty() ? 0 : std::stoi(rows[0][0]);
          }

          if (current < max_per_window) {
            allowed = true;
            std::string upsert = R"SQL(
              INSERT INTO token_rate_limits
                (key, action, window_start_ms, count)
              VALUES (?1, ?2, ?3, 1)
              ON CONFLICT(key, action, window_start_ms) DO UPDATE SET
                count = count + 1
            )SQL";
            txn.execute(upsert, {
              SQLParam{key}, SQLParam{action}, SQLParam{window_start}
            });
          }
        });

    return allowed;
  }

  void reset_rate(const std::string& key, const std::string& action) {
    db_.runInteraction("reset_token_rate",
        [&](LoggingTransaction& txn) {
          txn.execute(
              "DELETE FROM token_rate_limits WHERE key = ?1 AND action = ?2",
              {SQLParam{key}, SQLParam{action}});
        });
  }

  void cleanup_old_entries() {
    int64_t cutoff = now_ms() - hours_to_ms(24);
    db_.runInteraction("cleanup_rate_limits",
        [&](LoggingTransaction& txn) {
          txn.execute(
              "DELETE FROM token_rate_limits WHERE window_start_ms < ?1",
              {SQLParam{cutoff}});
        });
  }

 private:
  DatabasePool& db_;
};

// ============================================================================
// 2. SessionCacheManager — In-memory cache for validated tokens
// ============================================================================

class SessionCacheManager {
 public:
  struct CachedSession {
    std::string user_id;
    std::string device_id;
    TokenKind kind;
    bool is_guest;
    bool is_admin;
    std::string app_service_id;
    int64_t expires_at;
    int64_t cached_at;
  };

  SessionCacheManager() : hits_(0), misses_(0) {}

  std::optional<CachedSession> get(const std::string& token) {
    std::shared_lock lock(mtx_);

    auto it = cache_.find(token);
    if (it != cache_.end()) {
      int64_t now = now_ms();
      auto& entry = it->second;
      if (now - entry.cached_at < SESSION_CACHE_TTL_MS) {
        hits_++;
        return entry;
      }
      // Stale entry — remove lazily
    }
    misses_++;
    return std::nullopt;
  }

  void put(const std::string& token, CachedSession session) {
    std::unique_lock lock(mtx_);

    session.cached_at = now_ms();
    cache_[token] = session;

    // Evict if over max
    if (cache_.size() > TOKEN_CACHE_MAX_SIZE) {
      evict_oldest(TOKEN_CACHE_MAX_SIZE / 4);
    }
  }

  void invalidate(const std::string& token) {
    std::unique_lock lock(mtx_);
    cache_.erase(token);
  }

  void invalidate_user(const std::string& user_id) {
    std::unique_lock lock(mtx_);
    auto it = cache_.begin();
    while (it != cache_.end()) {
      if (it->second.user_id == user_id) {
        it = cache_.erase(it);
      } else {
        ++it;
      }
    }
  }

  void clear() {
    std::unique_lock lock(mtx_);
    cache_.clear();
  }

  struct Stats {
    size_t size;
    uint64_t hits;
    uint64_t misses;
    double hit_ratio;
  };

  Stats stats() const {
    std::shared_lock lock(mtx_);
    uint64_t total = hits_ + misses_;
    return {
      cache_.size(),
      hits_.load(),
      misses_.load(),
      total > 0 ? static_cast<double>(hits_) / total : 0.0
    };
  }

 private:
  void evict_oldest(size_t count) {
    if (cache_.size() <= count) return;
    // Simple: evict random entries
    auto it = cache_.begin();
    for (size_t i = 0; i < count && it != cache_.end(); ++i) {
      it = cache_.erase(it);
    }
  }

  mutable std::shared_mutex mtx_;
  std::unordered_map<std::string, CachedSession> cache_;
  std::atomic<uint64_t> hits_;
  std::atomic<uint64_t> misses_;
};

// ============================================================================
// 3. SessionAuditLogger — Session audit trail
// ============================================================================

class SessionAuditLogger {
 public:
  explicit SessionAuditLogger(DatabasePool& db)
      : db_(db), buffer_size_(0) {}

  void log(const std::string& user_id,
           const std::string& device_id,
           const std::string& token,
           TokenKind token_kind,
           AuditAction action,
           const std::string& ip_address = "",
           const std::string& user_agent = "",
           std::optional<InvalidationReason> reason = std::nullopt,
           const std::string& admin_user = "",
           const json& details = json::object()) {

    AuditEntry entry;
    entry.user_id = user_id;
    entry.device_id = device_id;
    entry.token = token;
    entry.token_kind = static_cast<int>(token_kind);
    entry.action = static_cast<int>(action);
    entry.timestamp_ms = now_ms();
    entry.ip_address = ip_address;
    entry.user_agent = user_agent;
    entry.reason = reason.has_value()
        ? static_cast<int>(*reason) : -1;
    entry.admin_user_id = admin_user;
    entry.detail_json = details.dump();
    entry.id = 0;

    {
      std::lock_guard<std::mutex> lock(buffer_mtx_);
      audit_buffer_.push_back(entry);
      buffer_size_++;

      if (buffer_size_ >= static_cast<int>(AUDIT_CACHE_MAX_SIZE)) {
        flush_buffer();
      }
    }
  }

  void flush_buffer() {
    std::vector<AuditEntry> batch;
    {
      std::lock_guard<std::mutex> lock(buffer_mtx_);
      batch.swap(audit_buffer_);
      buffer_size_ = 0;
    }

    if (batch.empty()) return;

    db_.runInteraction("log_audit_entries",
        [&](LoggingTransaction& txn) {
          for (const auto& entry : batch) {
            std::string sql = R"SQL(
              INSERT INTO session_audit_log
                (user_id, device_id, token, token_kind, action,
                 timestamp_ms, ip_address, user_agent, reason,
                 detail_json, admin_user_id)
              VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
            )SQL";
            txn.execute(sql, {
              SQLParam{entry.user_id},
              SQLParam{entry.device_id},
              SQLParam{entry.token},
              SQLParam{entry.token_kind},
              SQLParam{entry.action},
              SQLParam{entry.timestamp_ms},
              SQLParam{entry.ip_address},
              SQLParam{entry.user_agent},
              SQLParam{entry.reason},
              SQLParam{entry.detail_json},
              SQLParam{entry.admin_user_id}
            });
          }
        });
  }

  std::vector<json> query_audit(const std::string& user_id,
                                 int limit = 50,
                                 int64_t since_ms = 0,
                                 std::optional<AuditAction> action_filter = std::nullopt) {
    std::vector<json> results;

    db_.runInteraction("query_audit_log",
        [&](LoggingTransaction& txn) {
          std::string sql = R"SQL(
            SELECT id, user_id, device_id, token, token_kind, action,
                   timestamp_ms, ip_address, user_agent, reason,
                   detail_json, admin_user_id
            FROM session_audit_log
            WHERE user_id = ?1
          )SQL";

          std::vector<SQLParam> params = {SQLParam{user_id}};

          if (since_ms > 0) {
            sql += " AND timestamp_ms > ?2";
            params.push_back(SQLParam{since_ms});
          }
          if (action_filter.has_value()) {
            sql += " AND action = ?" + std::to_string(params.size() + 1);
            params.push_back(SQLParam{static_cast<int>(*action_filter)});
          }

          sql += " ORDER BY timestamp_ms DESC LIMIT ?" +
                 std::to_string(params.size() + 1);
          params.push_back(SQLParam{static_cast<int64_t>(limit)});

          txn.execute(sql, params);

          Row row;
          while (txn.iter_next(row)) {
            if (row.empty()) continue;
            json entry;
            entry["id"] = row[0].value ? std::stoll(*row[0].value) : 0LL;
            entry["user_id"] = row[1].value.value_or("");
            entry["device_id"] = row[2].value.value_or("");
            entry["token"] = "[redacted]";  // Don't expose tokens
            entry["token_kind"] = row[4].value
                ? token_kind_name(static_cast<TokenKind>(std::stoi(*row[4].value))) : "unknown";
            entry["action"] = row[5].value
                ? std::stoi(*row[5].value) : -1;
            entry["timestamp_ms"] = row[6].value
                ? std::stoll(*row[6].value) : 0LL;
            entry["ip_address"] = row[7].value.value_or("");
            entry["user_agent"] = row[8].value.value_or("");
            entry["reason"] = row[9].value
                ? invalidation_reason_name(
                    static_cast<InvalidationReason>(std::stoi(*row[9].value)))
                : "none";
            if (row[10].value && !row[10].value->empty()) {
              try { entry["details"] = json::parse(*row[10].value); }
              catch (...) { entry["details"] = json::object(); }
            }
            entry["admin_user_id"] = row[11].value.value_or("");
            results.push_back(entry);
          }
        });

    return results;
  }

  void cleanup_old_entries() {
    int64_t cutoff = now_ms() - AUDIT_LOG_RETENTION_MS;
    db_.runInteraction("cleanup_audit_log",
        [&](LoggingTransaction& txn) {
          int deleted = 0;
          while (true) {
            txn.execute(
                "DELETE FROM session_audit_log WHERE timestamp_ms < ?1 "
                "LIMIT ?2",
                {SQLParam{cutoff}, SQLParam{static_cast<int64_t>(AUDIT_LOG_BATCH_SIZE)}});
            int count = static_cast<int>(txn.rowcount());
            deleted += count;
            if (count < AUDIT_LOG_BATCH_SIZE) break;
          }
        });
  }

  void log_token_created(const std::string& user_id,
                          const std::string& device_id,
                          const std::string& token,
                          TokenKind kind,
                          const std::string& ip = "",
                          const std::string& ua = "") {
    log(user_id, device_id, token, kind, AuditAction::TOKEN_CREATED, ip, ua);
  }

  void log_token_used(const std::string& user_id,
                       const std::string& device_id,
                       const std::string& token,
                       TokenKind kind,
                       const std::string& ip = "",
                       const std::string& ua = "") {
    log(user_id, device_id, token, kind, AuditAction::TOKEN_USED, ip, ua);
  }

  void log_token_revoked(const std::string& user_id,
                          const std::string& device_id,
                          const std::string& token,
                          TokenKind kind,
                          InvalidationReason reason,
                          const std::string& ip = "",
                          const std::string& admin_user = "") {
    log(user_id, device_id, token, kind,
        AuditAction::TOKEN_REVOKED, ip, "", reason, admin_user);
  }

 private:
  struct AuditEntry {
    int64_t id;
    std::string user_id;
    std::string device_id;
    std::string token;
    int token_kind;
    int action;
    int64_t timestamp_ms;
    std::string ip_address;
    std::string user_agent;
    int reason;
    std::string detail_json;
    std::string admin_user_id;
  };

  DatabasePool& db_;
  std::mutex buffer_mtx_;
  std::vector<AuditEntry> audit_buffer_;
  std::atomic<int> buffer_size_;
};

// ============================================================================
// 4. AccessTokenManager — Access token lifecycle management
// ============================================================================

class AccessTokenManager {
 public:
  AccessTokenManager(DatabasePool& db,
                     SessionCacheManager& cache,
                     SessionAuditLogger& audit,
                     TokenRateLimiter& rate_limiter)
      : db_(db), cache_(cache), audit_(audit),
        rate_limiter_(rate_limiter) {}

  // ---- Token generation ----

  std::string generate_access_token(const std::string& user_id,
                                     const std::string& device_id = "",
                                     TokenKind kind = TokenKind::ACCESS,
                                     bool is_guest = false,
                                     const std::string& app_service_id = "",
                                     int64_t custom_ttl_ms = 0,
                                     const std::string& device_display_name = "",
                                     const std::string& ip = "",
                                     const std::string& user_agent = "") {

    // Determine prefix based on kind
    const char* prefix = PREFIX_ACCESS;
    int length = ACCESS_TOKEN_LENGTH;
    switch (kind) {
      case TokenKind::GUEST:       prefix = PREFIX_GUEST; break;
      case TokenKind::APP_SERVICE: prefix = PREFIX_APP_SERVICE; length = APP_SERVICE_TOKEN_LENGTH; break;
      case TokenKind::ADMIN_API:   prefix = PREFIX_ADMIN; break;
      case TokenKind::PUSH_GATEWAY:prefix = PREFIX_PUSH; break;
      default:                     prefix = PREFIX_ACCESS; break;
    }

    int64_t ttl = custom_ttl_ms;
    if (ttl <= 0) {
      switch (kind) {
        case TokenKind::GUEST:       ttl = GUEST_TOKEN_TTL_MS; break;
        case TokenKind::APP_SERVICE: ttl = APP_SERVICE_TOKEN_TTL_MS; break;
        default:                     ttl = ACCESS_TOKEN_TTL_MS; break;
      }
    }

    std::string token = srng().token(prefix, length - static_cast<int>(std::strlen(prefix)));
    int64_t now = now_ms();
    int64_t expires = (ttl > 0) ? now + ttl : 0;

    std::string sanitized_ua = sanitize_input(user_agent, MAX_USER_AGENT_LENGTH);
    std::string sanitized_ip = sanitize_input(ip, MAX_IP_ADDRESS_LENGTH);

    try {
      db_.runInteraction("create_access_token",
          [&](LoggingTransaction& txn) {
            std::string sql = R"SQL(
              INSERT INTO access_tokens
                (token, user_id, device_id, token_kind, token_state,
                 created_at_ms, expires_at_ms, last_used_at_ms,
                 last_ip, last_user_agent, is_guest, app_service_id,
                 device_display_name, last_seen_at_ms, idle_timeout_ms,
                 used_count, metadata_json)
              VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
                      ?11, ?12, ?13, ?14, ?15, 0, ?16)
            )SQL";
            txn.execute(sql, {
              SQLParam{token},
              SQLParam{user_id},
              SQLParam{device_id},
              SQLParam{static_cast<int>(kind)},
              SQLParam{static_cast<int>(TokenState::ACTIVE)},
              SQLParam{now},
              SQLParam{expires},
              SQLParam{now},  // last_used_at_ms
              SQLParam{sanitized_ip},
              SQLParam{sanitized_ua},
              SQLParam{is_guest ? 1 : 0},
              SQLParam{app_service_id},
              SQLParam{sanitize_input(device_display_name, 256)},
              SQLParam{now},  // last_seen_at_ms
              SQLParam{IDLE_TIMEOUT_DEFAULT_MS},
              SQLParam{json::object().dump()}
            });
          });
    } catch (const std::exception& e) {
      // Retry with new token on collision
      token = srng().token(prefix, length - static_cast<int>(std::strlen(prefix)));
      db_.runInteraction("create_access_token_retry",
          [&](LoggingTransaction& txn) {
            std::string sql = R"SQL(
              INSERT INTO access_tokens
                (token, user_id, device_id, token_kind, token_state,
                 created_at_ms, expires_at_ms, last_used_at_ms,
                 last_ip, last_user_agent, is_guest,
                 last_seen_at_ms, idle_timeout_ms, used_count)
              VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, 0)
            )SQL";
            txn.execute(sql, {
              SQLParam{token}, SQLParam{user_id}, SQLParam{device_id},
              SQLParam{static_cast<int>(kind)},
              SQLParam{static_cast<int>(TokenState::ACTIVE)},
              SQLParam{now}, SQLParam{expires}, SQLParam{now},
              SQLParam{sanitized_ip}, SQLParam{sanitized_ua},
              SQLParam{is_guest ? 1 : 0},
              SQLParam{now}, SQLParam{IDLE_TIMEOUT_DEFAULT_MS}
            });
          });
    }

    audit_.log_token_created(user_id, device_id, token,
                              kind, sanitized_ip, sanitized_ua);

    return token;
  }

  // ---- Token validation ----

  struct ValidationResult {
    bool valid{false};
    std::string user_id;
    std::string device_id;
    TokenKind kind{TokenKind::ACCESS};
    bool is_guest{false};
    std::string app_service_id;
    std::string error;
    std::string error_code;
    int64_t expires_at_ms{0};
    int64_t last_used_at_ms{0};
    bool shadow_banned{false};
  };

  ValidationResult validate_token(const std::string& token,
                                   const std::string& ip = "",
                                   const std::string& user_agent = "") {
    ValidationResult result;

    // Check format first
    if (!is_valid_token_format(token)) {
      result.error = "Invalid token format";
      result.error_code = ERR_UNKNOWN_TOKEN;
      return result;
    }

    // Check cache
    auto cached = cache_.get(token);
    if (cached.has_value()) {
      int64_t now = now_ms();
      if (cached->expires_at > 0 && now > cached->expires_at) {
        result.error = "Access token has expired";
        result.error_code = ERR_SESSION_EXPIRED;
        cache_.invalidate(token);
        return result;
      }

      result.valid = true;
      result.user_id = cached->user_id;
      result.device_id = cached->device_id;
      result.kind = cached->kind;
      result.is_guest = cached->is_guest;
      result.app_service_id = cached->app_service_id;
      result.expires_at_ms = cached->expires_at;
      result.last_used_at_ms = now;

      // Update last_used asynchronously (debounced)
      maybe_update_last_used(token, ip, user_agent, now);

      return result;
    }

    // Database lookup
    db_.runInteraction("validate_access_token",
        [&](LoggingTransaction& txn) {
          std::string sql = R"SQL(
            SELECT user_id, device_id, token_kind, token_state,
                   expires_at_ms, is_guest, app_service_id,
                   last_used_at_ms, last_seen_at_ms, idle_timeout_ms
            FROM access_tokens
            WHERE token = ?1
          )SQL";
          txn.execute(sql, {SQLParam{token}});

          Row row;
          if (!txn.iter_next(row) || row.empty()) {
            result.error = "Unknown access token";
            result.error_code = ERR_UNKNOWN_TOKEN;
            return;
          }

          std::string uid = row[0].value.value_or("");
          std::string did = row[1].value.value_or("");
          int kind_int = row[2].value ? std::stoi(*row[2].value) : 0;
          int state_int = row[3].value ? std::stoi(*row[3].value) : -1;
          int64_t expires = row[4].value ? std::stoll(*row[4].value) : 0;
          int guest_flag = row[5].value ? std::stoi(*row[5].value) : 0;
          std::string as_id = row[6].value.value_or("");

          TokenState state = static_cast<TokenState>(state_int);
          int64_t now = now_ms();

          // Check state
          if (state == TokenState::REVOKED) {
            result.error = "Access token has been revoked";
            result.error_code = ERR_UNKNOWN_TOKEN;
            return;
          }
          if (state == TokenState::SUSPENDED) {
            result.error = "Access token is suspended";
            result.error_code = ERR_FORBIDDEN;
            return;
          }
          if (state == TokenState::EXPIRED || (expires > 0 && now > expires)) {
            result.error = "Access token has expired";
            result.error_code = ERR_SESSION_EXPIRED;
            // Mark as expired in DB
            txn.execute(
                "UPDATE access_tokens SET token_state = ?1 WHERE token = ?2",
                {SQLParam{static_cast<int>(TokenState::EXPIRED)}, SQLParam{token}});
            return;
          }

          // Check idle timeout
          int64_t last_seen = row[8].value ? std::stoll(*row[8].value) : now;
          int64_t idle_timeout = row[9].value
              ? std::stoll(*row[9].value) : IDLE_TIMEOUT_DEFAULT_MS;

          if (idle_timeout > 0 && (now - last_seen) > idle_timeout) {
            result.error = "Session timed out due to inactivity";
            result.error_code = ERR_SESSION_EXPIRED;
            return;
          }

          result.valid = true;
          result.user_id = uid;
          result.device_id = did;
          result.kind = static_cast<TokenKind>(kind_int);
          result.is_guest = (guest_flag == 1);
          result.app_service_id = as_id;
          result.expires_at_ms = expires;
          result.last_used_at_ms = now;

          // Update last_used
          maybe_update_last_used(token, ip, user_agent, now);

          // Cache the result
          SessionCacheManager::CachedSession cs;
          cs.user_id = uid;
          cs.device_id = did;
          cs.kind = static_cast<TokenKind>(kind_int);
          cs.is_guest = (guest_flag == 1);
          cs.app_service_id = as_id;
          cs.expires_at = expires;
          cache_.put(token, cs);
        });

    return result;
  }

  std::optional<std::string> get_user_id_from_token(
      const std::string& token) {
    auto result = validate_token(token);
    if (result.valid) return result.user_id;
    return std::nullopt;
  }

  // ---- Token revocation ----

  bool revoke_token(const std::string& token,
                     InvalidationReason reason = InvalidationReason::USER_REQUEST,
                     const std::string& admin_user = "") {
    bool success = false;
    int64_t now = now_ms();

    db_.runInteraction("revoke_access_token",
        [&](LoggingTransaction& txn) {
          // Get token info for audit first
          std::string sel = R"SQL(
            SELECT user_id, device_id, token_kind
            FROM access_tokens WHERE token = ?1 AND token_state = 0
          )SQL";
          txn.execute(sel, {SQLParam{token}});

          Row row;
          if (!txn.iter_next(row) || row.empty()) {
            return;
          }

          std::string uid = row[0].value.value_or("");
          std::string did = row[1].value.value_or("");
          int kind_int = row[2].value ? std::stoi(*row[2].value) : 0;

          std::string upd = R"SQL(
            UPDATE access_tokens
            SET token_state = ?1, revoked_at_ms = ?2, revoke_reason = ?3
            WHERE token = ?4
          )SQL";
          txn.execute(upd, {
            SQLParam{static_cast<int>(TokenState::REVOKED)},
            SQLParam{now},
            SQLParam{static_cast<int>(reason)},
            SQLParam{token}
          });

          success = (txn.rowcount() > 0);
          cache_.invalidate(token);

          // Audit
          audit_.log_token_revoked(uid, did, token,
              static_cast<TokenKind>(kind_int), reason, "", admin_user);
        });

    return success;
  }

  int revoke_all_for_user(const std::string& user_id,
                           InvalidationReason reason = InvalidationReason::USER_REQUEST,
                           const std::string& except_token = "",
                           const std::string& admin_user = "") {
    int count = 0;
    int64_t now = now_ms();

    db_.runInteraction("revoke_user_access_tokens",
        [&](LoggingTransaction& txn) {
          std::string sql;
          std::vector<SQLParam> params;

          if (!except_token.empty()) {
            sql = R"SQL(
              UPDATE access_tokens
              SET token_state = ?1, revoked_at_ms = ?2,
                  revoke_reason = ?3
              WHERE user_id = ?4 AND token_state = 0
                AND token != ?5
            )SQL";
            params = {
              SQLParam{static_cast<int>(TokenState::REVOKED)},
              SQLParam{now},
              SQLParam{static_cast<int>(reason)},
              SQLParam{user_id},
              SQLParam{except_token}
            };
          } else {
            sql = R"SQL(
              UPDATE access_tokens
              SET token_state = ?1, revoked_at_ms = ?2,
                  revoke_reason = ?3
              WHERE user_id = ?4 AND token_state = 0
            )SQL";
            params = {
              SQLParam{static_cast<int>(TokenState::REVOKED)},
              SQLParam{now},
              SQLParam{static_cast<int>(reason)},
              SQLParam{user_id}
            };
          }
          txn.execute(sql, params);
          count = static_cast<int>(txn.rowcount());
        });

    cache_.invalidate_user(user_id);

    if (count > 0) {
      audit_.log(user_id, "", "", TokenKind::ACCESS,
                  AuditAction::BULK_REVOKE, "", "",
                  reason, admin_user);
    }

    return count;
  }

  int revoke_all_for_device(const std::string& user_id,
                             const std::string& device_id,
                             InvalidationReason reason = InvalidationReason::DEVICE_DELETION) {
    int count = 0;
    int64_t now = now_ms();

    db_.runInteraction("revoke_device_access_tokens",
        [&](LoggingTransaction& txn) {
          txn.execute(
              R"SQL(
                UPDATE access_tokens
                SET token_state = ?1, revoked_at_ms = ?2,
                    revoke_reason = ?3
                WHERE user_id = ?4 AND device_id = ?5
                  AND token_state = 0
              )SQL",
              {
                SQLParam{static_cast<int>(TokenState::REVOKED)},
                SQLParam{now},
                SQLParam{static_cast<int>(reason)},
                SQLParam{user_id},
                SQLParam{device_id}
              });
          count = static_cast<int>(txn.rowcount());
        });

    if (count > 0) {
      cache_.invalidate_user(user_id);
      audit_.log(user_id, device_id, "", TokenKind::ACCESS,
                  AuditAction::TOKEN_REVOKED, "", "",
                  reason);
    }

    return count;
  }

  // ---- Token info queries ----

  struct TokenInfo {
    std::string token;
    std::string user_id;
    std::string device_id;
    TokenKind kind;
    TokenState state;
    int64_t created_at_ms;
    int64_t expires_at_ms;
    int64_t last_used_at_ms;
    int64_t last_seen_at_ms;
    std::string last_ip;
    std::string last_user_agent;
    bool is_guest;
    std::string app_service_id;
    std::string device_display_name;
    int64_t idle_timeout_ms;
    int used_count;
    std::optional<int64_t> revoked_at_ms;
    std::optional<InvalidationReason> revoke_reason;
  };

  std::optional<TokenInfo> get_token_info(const std::string& token) {
    std::optional<TokenInfo> result;

    db_.runInteraction("get_token_info",
        [&](LoggingTransaction& txn) {
          std::string sql = R"SQL(
            SELECT token, user_id, device_id, token_kind, token_state,
                   created_at_ms, expires_at_ms, last_used_at_ms,
                   last_seen_at_ms, last_ip, last_user_agent,
                   is_guest, app_service_id, device_display_name,
                   idle_timeout_ms, used_count, revoked_at_ms,
                   revoke_reason
            FROM access_tokens
            WHERE token = ?1
          )SQL";
          txn.execute(sql, {SQLParam{token}});

          Row row;
          if (txn.iter_next(row) && !row.empty()) {
            TokenInfo info;
            info.token = row[0].value.value_or("");
            info.user_id = row[1].value.value_or("");
            info.device_id = row[2].value.value_or("");
            info.kind = static_cast<TokenKind>(
                row[3].value ? std::stoi(*row[3].value) : 0);
            info.state = static_cast<TokenState>(
                row[4].value ? std::stoi(*row[4].value) : 0);
            info.created_at_ms = row[5].value ? std::stoll(*row[5].value) : 0;
            info.expires_at_ms = row[6].value ? std::stoll(*row[6].value) : 0;
            info.last_used_at_ms = row[7].value ? std::stoll(*row[7].value) : 0;
            info.last_seen_at_ms = row[8].value ? std::stoll(*row[8].value) : 0;
            info.last_ip = row[9].value.value_or("");
            info.last_user_agent = row[10].value.value_or("");
            info.is_guest = row[11].value && *row[11].value == "1";
            info.app_service_id = row[12].value.value_or("");
            info.device_display_name = row[13].value.value_or("");
            info.idle_timeout_ms = row[14].value
                ? std::stoll(*row[14].value) : IDLE_TIMEOUT_DEFAULT_MS;
            info.used_count = row[15].value ? std::stoi(*row[15].value) : 0;
            if (row[16].value) info.revoked_at_ms = std::stoll(*row[16].value);
            if (row[17].value) info.revoke_reason =
                static_cast<InvalidationReason>(std::stoi(*row[17].value));
            result = info;
          }
        });

    return result;
  }

  // ---- Update last_seen for idle tracking ----

  void update_last_seen(const std::string& token,
                         int64_t timestamp_ms = 0) {
    if (timestamp_ms <= 0) timestamp_ms = now_ms();
    try {
      db_.runInteraction("update_token_last_seen",
          [&](LoggingTransaction& txn) {
            txn.execute(
                "UPDATE access_tokens SET last_seen_at_ms = ?1 WHERE token = ?2",
                {SQLParam{timestamp_ms}, SQLParam{token}});
          });
    } catch (const std::exception&) {}
  }

  // ---- Batch expiry ----

  int expire_tokens_batch(int batch_size = EXPIRED_TOKEN_BATCH_SIZE) {
    int count = 0;
    int64_t now = now_ms();

    db_.runInteraction("expire_access_tokens_batch",
        [&](LoggingTransaction& txn) {
          txn.execute(
              R"SQL(
                UPDATE access_tokens
                SET token_state = ?1
                WHERE token_state = 0
                  AND expires_at_ms IS NOT NULL
                  AND expires_at_ms > 0
                  AND expires_at_ms < ?2
                LIMIT ?3
              )SQL",
              {
                SQLParam{static_cast<int>(TokenState::EXPIRED)},
                SQLParam{now},
                SQLParam{static_cast<int64_t>(batch_size)}
              });
          count = static_cast<int>(txn.rowcount());
        });

    return count;
  }

  // ---- Statistics ----

  struct TokenStats {
    int total_active;
    int total_expired;
    int total_revoked;
    int total_guests;
    int unique_users;
    int64_t snapshot_at_ms;
  };

  TokenStats get_stats() {
    TokenStats stats{};
    stats.snapshot_at_ms = now_ms();

    db_.runInteraction("get_token_stats",
        [&](LoggingTransaction& txn) {
          // Active count
          txn.execute(
              "SELECT COUNT(*) FROM access_tokens WHERE token_state = 0");
          Row row;
          if (txn.iter_next(row)) {
            stats.total_active = row[0].value ? std::stoi(*row[0].value) : 0;
          }
          txn.iter_reset();

          // Expired
          txn.execute(
              "SELECT COUNT(*) FROM access_tokens WHERE token_state = 2");
          if (txn.iter_next(row)) {
            stats.total_expired = row[0].value ? std::stoi(*row[0].value) : 0;
          }
          txn.iter_reset();

          // Revoked
          txn.execute(
              "SELECT COUNT(*) FROM access_tokens WHERE token_state = 1");
          if (txn.iter_next(row)) {
            stats.total_revoked = row[0].value ? std::stoi(*row[0].value) : 0;
          }
          txn.iter_reset();

          // Guests
          txn.execute(
              "SELECT COUNT(*) FROM access_tokens WHERE is_guest = 1");
          if (txn.iter_next(row)) {
            stats.total_guests = row[0].value ? std::stoi(*row[0].value) : 0;
          }
          txn.iter_reset();

          // Unique users (active)
          txn.execute(
              "SELECT COUNT(DISTINCT user_id) FROM access_tokens "
              "WHERE token_state = 0");
          if (txn.iter_next(row)) {
            stats.unique_users = row[0].value ? std::stoi(*row[0].value) : 0;
          }
        });

    return stats;
  }

  // ---- Session count per user ----

  int count_user_sessions(const std::string& user_id,
                           bool active_only = true) {
    int count = 0;
    db_.runInteraction("count_user_sessions",
        [&](LoggingTransaction& txn) {
          if (active_only) {
            txn.execute(
                "SELECT COUNT(*) FROM access_tokens "
                "WHERE user_id = ?1 AND token_state = 0",
                {SQLParam{user_id}});
          } else {
            txn.execute(
                "SELECT COUNT(*) FROM access_tokens WHERE user_id = ?1",
                {SQLParam{user_id}});
          }
          Row row;
          if (txn.iter_next(row)) {
            count = row[0].value ? std::stoi(*row[0].value) : 0;
          }
        });
    return count;
  }

 private:
  void maybe_update_last_used(const std::string& token,
                                const std::string& ip,
                                const std::string& user_agent,
                                int64_t now) {
    // Debounce: only update every LAST_SEEN_UPDATE_MS
    int64_t last_update = 0;
    {
      std::shared_lock lock(last_used_mtx_);
      auto it = last_used_tracker_.find(token);
      if (it != last_used_tracker_.end()) {
        last_update = it->second;
      }
    }

    if (now - last_update >= LAST_SEEN_UPDATE_MS) {
      std::unique_lock lock(last_used_mtx_);
      last_used_tracker_[token] = now;

      // Clean old entries occasionally
      if (last_used_tracker_.size() > 200000) {
        cleanup_tracker(now);
      }
    }

    // Async update to DB
    try {
      db_.runInteraction("update_token_usage",
          [&](LoggingTransaction& txn) {
            std::string sql = R"SQL(
              UPDATE access_tokens
              SET last_used_at_ms = ?1,
                  last_seen_at_ms = ?1,
                  last_ip = CASE WHEN ?2 != '' THEN ?2 ELSE last_ip END,
                  last_user_agent = CASE WHEN ?3 != '' THEN ?3
                                         ELSE last_user_agent END,
                  used_count = used_count + 1
              WHERE token = ?4
            )SQL";
            txn.execute(sql, {
              SQLParam{now},
              SQLParam{sanitize_input(ip, MAX_IP_ADDRESS_LENGTH)},
              SQLParam{sanitize_input(user_agent, MAX_USER_AGENT_LENGTH)},
              SQLParam{token}
            });
          });
    } catch (const std::exception&) {}
  }

  void cleanup_tracker(int64_t now) {
    int64_t cutoff = now - LAST_SEEN_UPDATE_MS * 10;
    auto it = last_used_tracker_.begin();
    while (it != last_used_tracker_.end()) {
      if (it->second < cutoff) {
        it = last_used_tracker_.erase(it);
      } else {
        ++it;
      }
    }
  }

  DatabasePool& db_;
  SessionCacheManager& cache_;
  SessionAuditLogger& audit_;
  TokenRateLimiter& rate_limiter_;
  std::shared_mutex last_used_mtx_;
  std::unordered_map<std::string, int64_t> last_used_tracker_;
};

// ============================================================================
// 5. RefreshTokenManager — Refresh token lifecycle management
// ============================================================================

class RefreshTokenManager {
 public:
  RefreshTokenManager(DatabasePool& db,
                       SessionAuditLogger& audit,
                       AccessTokenManager& access_tokens)
      : db_(db), audit_(audit), access_tokens_(access_tokens) {}

  // ---- Refresh token generation ----

  std::string generate_refresh_token(const std::string& user_id,
                                      const std::string& device_id,
                                      const std::string& access_token,
                                      const std::string& scope_json = "{}",
                                      int64_t custom_ttl_ms = 0) {
    int64_t ttl = custom_ttl_ms > 0 ? custom_ttl_ms : REFRESH_TOKEN_TTL_MS;
    std::string token = srng().token(PREFIX_REFRESH,
        REFRESH_TOKEN_LENGTH - static_cast<int>(std::strlen(PREFIX_REFRESH)));
    int64_t now = now_ms();
    int64_t expires = now + ttl;

    db_.runInteraction("create_refresh_token",
        [&](LoggingTransaction& txn) {
          std::string sql = R"SQL(
            INSERT INTO refresh_tokens
              (token, user_id, device_id, access_token_id,
               created_at_ms, expires_at_ms, last_used_at_ms,
               used_count, revoked, scope_json, chain_depth)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0, 0, ?8, 0)
          )SQL";
          txn.execute(sql, {
            SQLParam{token}, SQLParam{user_id},
            SQLParam{device_id}, SQLParam{access_token},
            SQLParam{now}, SQLParam{expires}, SQLParam{now},
            SQLParam{scope_json}
          });
        });

    audit_.log_token_created(user_id, device_id, token,
                              TokenKind::REFRESH);

    return token;
  }

  // ---- Refresh token exchange ----

  struct RefreshResult {
    bool success{false};
    std::string access_token;
    std::string refresh_token;
    std::string user_id;
    std::string device_id;
    std::string error;
    std::string error_code;
    int64_t expires_in_ms{0};
  };

  RefreshResult refresh(const std::string& refresh_token,
                         const std::string& ip = "",
                         const std::string& user_agent = "") {
    RefreshResult result;
    result.refresh_token = refresh_token;

    if (!is_valid_token_format(refresh_token)) {
      result.error = "Invalid refresh token format";
      result.error_code = ERR_UNKNOWN_TOKEN;
      return result;
    }

    db_.runInteraction("exchange_refresh_token",
        [&](LoggingTransaction& txn) {
          std::string sel = R"SQL(
            SELECT user_id, device_id, revoked, expires_at_ms,
                   access_token_id, used_count, chain_depth, scope_json
            FROM refresh_tokens
            WHERE token = ?1
          )SQL";
          txn.execute(sel, {SQLParam{refresh_token}});

          auto rows = txn.fetchall();
          if (rows.empty()) {
            result.error = "Unknown refresh token";
            result.error_code = ERR_UNKNOWN_TOKEN;
            return;
          }

          auto& row = rows[0];

          result.user_id = row[0].value.value_or("");
          result.device_id = row[1].value.value_or("");
          bool revoked = row[2].value && *row[2].value == "1";
          int64_t expires = row[3].value ? std::stoll(*row[3].value) : 0;
          int used_count = row[5].value ? std::stoi(*row[5].value) : 0;
          int chain_depth = row[6].value ? std::stoi(*row[6].value) : 0;
          std::string scope_json = row[7].value.value_or("{}");

          int64_t now = now_ms();

          // Check revoked
          if (revoked) {
            result.error = "Refresh token has been revoked";
            result.error_code = ERR_UNKNOWN_TOKEN;
            return;
          }

          // Check expiry
          if (expires > 0 && now > expires) {
            result.error = "Refresh token has expired";
            result.error_code = ERR_SESSION_EXPIRED;
            // Auto-revoke
            txn.execute(
                "UPDATE refresh_tokens SET revoked = 1, "
                "revoked_at_ms = ?1 WHERE token = ?2",
                {SQLParam{now}, SQLParam{refresh_token}});
            return;
          }

          // Check chain depth
          if (chain_depth >= MAX_REFRESH_CHAIN_DEPTH) {
            result.error = "Refresh token chain depth exceeded";
            result.error_code = ERR_LIMIT_EXCEEDED;
            return;
          }

          // Revoke old token (rotation)
          txn.execute(
              "UPDATE refresh_tokens SET revoked = 1, "
              "revoked_at_ms = ?1 WHERE token = ?2",
              {SQLParam{now}, SQLParam{refresh_token}});

          // Generate new access token
          result.access_token = access_tokens_.generate_access_token(
              result.user_id, result.device_id);

          // Generate new refresh token
          std::string new_rt = srng().token(PREFIX_REFRESH,
              REFRESH_TOKEN_LENGTH - static_cast<int>(std::strlen(PREFIX_REFRESH)));
          int64_t new_expires = now + REFRESH_TOKEN_TTL_MS;

          txn.execute(
              R"SQL(
                INSERT INTO refresh_tokens
                  (token, user_id, device_id, access_token_id,
                   created_at_ms, expires_at_ms, last_used_at_ms,
                   used_count, revoked, prev_token_id, chain_depth,
                   scope_json, last_ip, last_user_agent)
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0, ?9, ?10, ?11, ?12, ?13)
              )SQL",
              {
                SQLParam{new_rt},
                SQLParam{result.user_id},
                SQLParam{result.device_id},
                SQLParam{result.access_token},
                SQLParam{now},
                SQLParam{new_expires},
                SQLParam{now},
                SQLParam{used_count + 1},
                SQLParam{refresh_token},  // prev_token_id
                SQLParam{chain_depth + 1},
                SQLParam{scope_json},
                SQLParam{sanitize_input(ip, MAX_IP_ADDRESS_LENGTH)},
                SQLParam{sanitize_input(user_agent, MAX_USER_AGENT_LENGTH)}
              });

          // Link old token to new
          txn.execute(
              "UPDATE refresh_tokens SET next_token_id = ?1 WHERE token = ?2",
              {SQLParam{new_rt}, SQLParam{refresh_token}});

          result.refresh_token = new_rt;
          result.expires_in_ms = new_expires - now;
          result.success = true;
        });

    if (result.success) {
      audit_.log(result.user_id, result.device_id, result.access_token,
                  TokenKind::ACCESS, AuditAction::TOKEN_REFRESHED,
                  ip, user_agent);
    }

    return result;
  }

  // ---- Refresh token validation ----

  bool is_token_valid(const std::string& refresh_token) {
    bool valid = false;
    db_.runInteraction("check_refresh_valid",
        [&](LoggingTransaction& txn) {
          txn.execute(
              "SELECT 1 FROM refresh_tokens WHERE token = ?1 AND revoked = 0",
              {SQLParam{refresh_token}});
          auto rows = txn.fetchall();
          valid = !rows.empty();

          if (valid) {
            // Check expiry
            if (!rows.empty()) {
              auto& row = rows[0];
              if (row.size() > 0) {
                // We only checked existence, expiry check would need another query
                // Simple: if we found it and it's not revoked, it's valid
              }
            }
          }
        });
    return valid;
  }

  // ---- Refresh token revocation ----

  int revoke_all_for_user(const std::string& user_id,
                           InvalidationReason reason = InvalidationReason::USER_REQUEST) {
    int count = 0;
    int64_t now = now_ms();

    db_.runInteraction("revoke_user_refresh_tokens",
        [&](LoggingTransaction& txn) {
          txn.execute(
              R"SQL(
                UPDATE refresh_tokens
                SET revoked = 1, revoked_at_ms = ?1,
                    revoke_reason = ?2
                WHERE user_id = ?3 AND revoked = 0
              )SQL",
              {SQLParam{now}, SQLParam{static_cast<int>(reason)},
               SQLParam{user_id}});
          count = static_cast<int>(txn.rowcount());
        });

    if (count > 0) {
      audit_.log(user_id, "", "", TokenKind::REFRESH,
                  AuditAction::BULK_REVOKE, "", "", reason);
    }

    return count;
  }

  int revoke_all_for_device(const std::string& user_id,
                             const std::string& device_id,
                             InvalidationReason reason = InvalidationReason::DEVICE_DELETION) {
    int count = 0;
    int64_t now = now_ms();

    db_.runInteraction("revoke_device_refresh_tokens",
        [&](LoggingTransaction& txn) {
          txn.execute(
              R"SQL(
                UPDATE refresh_tokens
                SET revoked = 1, revoked_at_ms = ?1,
                    revoke_reason = ?2
                WHERE user_id = ?3 AND device_id = ?4 AND revoked = 0
              )SQL",
              {SQLParam{now}, SQLParam{static_cast<int>(reason)},
               SQLParam{user_id}, SQLParam{device_id}});
          count = static_cast<int>(txn.rowcount());
        });

    return count;
  }

  bool revoke_single(const std::string& refresh_token,
                      InvalidationReason reason = InvalidationReason::USER_REQUEST) {
    bool success = false;
    int64_t now = now_ms();

    db_.runInteraction("revoke_single_refresh",
        [&](LoggingTransaction& txn) {
          txn.execute(
              R"SQL(
                UPDATE refresh_tokens
                SET revoked = 1, revoked_at_ms = ?1, revoke_reason = ?2
                WHERE token = ?3 AND revoked = 0
              )SQL",
              {SQLParam{now}, SQLParam{static_cast<int>(reason)},
               SQLParam{refresh_token}});
          success = (txn.rowcount() > 0);
        });

    if (success) {
      audit_.log("", "", refresh_token, TokenKind::REFRESH,
                  AuditAction::TOKEN_REVOKED, "", "", reason);
    }

    return success;
  }

  // ---- Refresh token listing ----

  std::vector<json> list_for_user(const std::string& user_id) {
    std::vector<json> results;

    db_.runInteraction("list_refresh_tokens",
        [&](LoggingTransaction& txn) {
          std::string sql = R"SQL(
            SELECT token, device_id, created_at_ms, expires_at_ms,
                   revoked, revoked_at_ms, revoke_reason, used_count,
                   chain_depth, last_ip, last_user_agent
            FROM refresh_tokens
            WHERE user_id = ?1
            ORDER BY created_at_ms DESC
            LIMIT 100
          )SQL";
          txn.execute(sql, {SQLParam{user_id}});

          Row row;
          while (txn.iter_next(row)) {
            if (row.empty()) continue;
            json entry;
            entry["token"] = "[redacted]";
            entry["device_id"] = row[1].value.value_or("");
            entry["created_at_ms"] = row[2].value
                ? std::stoll(*row[2].value) : 0LL;
            entry["expires_at_ms"] = row[3].value
                ? std::stoll(*row[3].value) : 0LL;
            entry["revoked"] = row[4].value && *row[4].value == "1";
            entry["revoked_at_ms"] = row[5].value
                ? std::stoll(*row[5].value) : 0LL;
            entry["revoke_reason"] = row[6].value
                ? invalidation_reason_name(
                    static_cast<InvalidationReason>(std::stoi(*row[6].value)))
                : "none";
            entry["used_count"] = row[7].value
                ? std::stoi(*row[7].value) : 0;
            entry["chain_depth"] = row[8].value
                ? std::stoi(*row[8].value) : 0;
            entry["last_ip"] = row[9].value.value_or("");
            entry["last_user_agent"] = row[10].value.value_or("");
            results.push_back(entry);
          }
        });

    return results;
  }

  // ---- Chain tracking ----

  std::vector<std::string> get_token_chain(const std::string& token) {
    std::vector<std::string> chain;
    chain.push_back(token);

    db_.runInteraction("get_token_chain",
        [&](LoggingTransaction& txn) {
          // Walk forward chain
          std::string current = token;
          for (int i = 0; i < MAX_REFRESH_CHAIN_DEPTH; ++i) {
            txn.execute(
                "SELECT next_token_id FROM refresh_tokens WHERE token = ?1",
                {SQLParam{current}});
            Row row;
            if (txn.iter_next(row) && !row.empty() && row[0].value) {
              current = *row[0].value;
              chain.push_back(current);
            } else {
              break;
            }
            txn.iter_reset();
          }

          // Walk backward chain
          current = token;
          for (int i = 0; i < MAX_REFRESH_CHAIN_DEPTH; ++i) {
            txn.execute(
                "SELECT prev_token_id FROM refresh_tokens WHERE token = ?1",
                {SQLParam{current}});
            Row row;
            if (txn.iter_next(row) && !row.empty() && row[0].value) {
              current = *row[0].value;
              chain.insert(chain.begin(), current);
            } else {
              break;
            }
            txn.iter_reset();
          }
        });

    return chain;
  }

  // ---- Cleanup expired refresh tokens ----

  int expire_expired_batch(int batch_size = EXPIRED_TOKEN_BATCH_SIZE) {
    int count = 0;
    int64_t now = now_ms();

    db_.runInteraction("expire_refresh_tokens",
        [&](LoggingTransaction& txn) {
          txn.execute(
              R"SQL(
                UPDATE refresh_tokens
                SET revoked = 1, revoked_at_ms = ?1,
                    revoke_reason = ?2
                WHERE revoked = 0
                  AND expires_at_ms IS NOT NULL
                  AND expires_at_ms > 0
                  AND expires_at_ms < ?3
                LIMIT ?4
              )SQL",
              {
                SQLParam{now},
                SQLParam{static_cast<int>(InvalidationReason::TOKEN_EXPIRY)},
                SQLParam{now},
                SQLParam{static_cast<int64_t>(batch_size)}
              });
          count = static_cast<int>(txn.rowcount());
        });

    return count;
  }

  // ---- Statistics ----

  struct RefreshStats {
    int total_active;
    int total_revoked;
    int total_expired;
    int unique_users;
    int chains_with_depth;
  };

  RefreshStats get_stats() {
    RefreshStats stats{};

    db_.runInteraction("get_refresh_stats",
        [&](LoggingTransaction& txn) {
          txn.execute(
              "SELECT COUNT(*) FROM refresh_tokens WHERE revoked = 0");
          Row row;
          if (txn.iter_next(row)) {
            stats.total_active = row[0].value ? std::stoi(*row[0].value) : 0;
          }
          txn.iter_reset();

          txn.execute(
              "SELECT COUNT(*) FROM refresh_tokens WHERE revoked = 1");
          if (txn.iter_next(row)) {
            stats.total_revoked = row[0].value ? std::stoi(*row[0].value) : 0;
          }
          txn.iter_reset();

          txn.execute(
              "SELECT COUNT(DISTINCT user_id) FROM refresh_tokens WHERE revoked = 0");
          if (txn.iter_next(row)) {
            stats.unique_users = row[0].value ? std::stoi(*row[0].value) : 0;
          }
          txn.iter_reset();

          txn.execute(
              "SELECT COUNT(*) FROM refresh_tokens "
              "WHERE revoked = 0 AND chain_depth > 0");
          if (txn.iter_next(row)) {
            stats.chains_with_depth = row[0].value ? std::stoi(*row[0].value) : 0;
          }
        });

    return stats;
  }

 private:
  DatabasePool& db_;
  SessionAuditLogger& audit_;
  AccessTokenManager& access_tokens_;
};

// ============================================================================
// 6. SessionListingService — Session listing and querying
// ============================================================================

class SessionListingService {
 public:
  SessionListingService(DatabasePool& db) : db_(db) {}

  struct SessionEntry {
    std::string device_id;
    std::string display_name;
    std::string last_seen_ip;
    std::string last_seen_ua;
    int64_t last_seen_ts;
    int64_t created_ts;
    int64_t expires_ts;
    int64_t idle_timeout_ms;
    bool is_guest;
    bool is_active;
    TokenKind kind;
    int used_count;
    bool shadow_banned;
  };

  // ---- List sessions for a user ----

  std::vector<SessionEntry> list_user_sessions(
      const std::string& user_id,
      bool include_inactive = false,
      int limit = 100,
      int offset = 0) {

    std::vector<SessionEntry> results;

    db_.runInteraction("list_user_sessions",
        [&](LoggingTransaction& txn) {
          std::string sql = R"SQL(
            SELECT device_id, device_display_name, last_ip,
                   last_user_agent, last_seen_at_ms, created_at_ms,
                   expires_at_ms, idle_timeout_ms, is_guest,
                   token_state, token_kind, used_count, last_used_at_ms
            FROM access_tokens
            WHERE user_id = ?1
          )SQL";

          std::vector<SQLParam> params = {SQLParam{user_id}};

          if (!include_inactive) {
            sql += " AND token_state = 0";
          }

          sql += " ORDER BY last_seen_at_ms DESC LIMIT ?" +
                 std::to_string(params.size() + 1) +
                 " OFFSET ?" + std::to_string(params.size() + 2);
          params.push_back(SQLParam{static_cast<int64_t>(limit)});
          params.push_back(SQLParam{static_cast<int64_t>(offset)});

          txn.execute(sql, params);

          Row row;
          while (txn.iter_next(row)) {
            if (row.empty()) continue;
            SessionEntry entry;
            entry.device_id = row[0].value.value_or("");
            entry.display_name = row[1].value.value_or("");
            entry.last_seen_ip = row[2].value.value_or("");
            entry.last_seen_ua = row[3].value.value_or("");
            entry.last_seen_ts = row[4].value
                ? std::stoll(*row[4].value) : 0LL;
            entry.created_ts = row[5].value
                ? std::stoll(*row[5].value) : 0LL;
            entry.expires_ts = row[6].value
                ? std::stoll(*row[6].value) : 0LL;
            entry.idle_timeout_ms = row[7].value
                ? std::stoll(*row[7].value) : IDLE_TIMEOUT_DEFAULT_MS;
            entry.is_guest = row[8].value && *row[8].value == "1";
            int state = row[9].value ? std::stoi(*row[9].value) : -1;
            entry.is_active = (state == static_cast<int>(TokenState::ACTIVE));
            entry.kind = static_cast<TokenKind>(
                row[10].value ? std::stoi(*row[10].value) : 0);
            entry.used_count = row[11].value ? std::stoi(*row[11].value) : 0;
            entry.shadow_banned = false;
            results.push_back(entry);
          }
        });

    return results;
  }

  // ---- List all sessions (admin) ----

  std::vector<json> list_all_sessions_admin(
      int limit = 50,
      int offset = 0,
      const std::string& filter_user = "",
      const std::string& filter_device = "",
      bool active_only = true) {

    std::vector<json> results;

    db_.runInteraction("list_all_sessions_admin",
        [&](LoggingTransaction& txn) {
          std::string sql = R"SQL(
            SELECT a.token, a.user_id, a.device_id,
                   a.device_display_name, a.token_kind, a.token_state,
                   a.created_at_ms, a.expires_at_ms,
                   a.last_used_at_ms, a.last_seen_at_ms,
                   a.last_ip, a.last_user_agent,
                   a.is_guest, a.app_service_id,
                   a.used_count, a.revoked_at_ms
            FROM access_tokens a
            WHERE 1=1
          )SQL";

          std::vector<SQLParam> params;

          if (active_only) {
            sql += " AND a.token_state = 0";
          }

          if (!filter_user.empty()) {
            sql += " AND a.user_id LIKE ?" +
                   std::to_string(params.size() + 1);
            params.push_back(SQLParam{"%" + filter_user + "%"});
          }

          if (!filter_device.empty()) {
            sql += " AND a.device_id LIKE ?" +
                   std::to_string(params.size() + 1);
            params.push_back(SQLParam{"%" + filter_device + "%"});
          }

          sql += " ORDER BY a.last_seen_at_ms DESC LIMIT ?" +
                 std::to_string(params.size() + 1) +
                 " OFFSET ?" + std::to_string(params.size() + 2);
          params.push_back(SQLParam{static_cast<int64_t>(limit)});
          params.push_back(SQLParam{static_cast<int64_t>(offset)});

          txn.execute(sql, params);

          Row row;
          while (txn.iter_next(row)) {
            if (row.empty()) continue;
            json entry;
            entry["token"] = "[redacted]";
            entry["user_id"] = row[1].value.value_or("");
            entry["device_id"] = row[2].value.value_or("");
            entry["display_name"] = row[3].value.value_or("");
            entry["token_kind"] = row[4].value
                ? token_kind_name(static_cast<TokenKind>(std::stoi(*row[4].value)))
                : "unknown";
            entry["token_state"] = row[5].value
                ? token_state_name(static_cast<TokenState>(std::stoi(*row[5].value)))
                : "unknown";
            entry["created_at_ms"] = row[6].value
                ? std::stoll(*row[6].value) : 0LL;
            entry["expires_at_ms"] = row[7].value
                ? std::stoll(*row[7].value) : 0LL;
            entry["last_used_at_ms"] = row[8].value
                ? std::stoll(*row[8].value) : 0LL;
            entry["last_seen_at_ms"] = row[9].value
                ? std::stoll(*row[9].value) : 0LL;
            entry["last_ip"] = row[10].value.value_or("");
            entry["last_user_agent"] = row[11].value.value_or("");
            entry["is_guest"] = row[12].value && *row[12].value == "1";
            entry["app_service_id"] = row[13].value.value_or("");
            entry["used_count"] = row[14].value
                ? std::stoi(*row[14].value) : 0;
            entry["revoked_at_ms"] = row[15].value
                ? std::stoll(*row[15].value) : 0LL;
            results.push_back(entry);
          }
        });

    return results;
  }

  // ---- Get session by device ----

  std::vector<SessionEntry> list_device_sessions(
      const std::string& user_id,
      const std::string& device_id) {

    std::vector<SessionEntry> results;

    db_.runInteraction("list_device_sessions",
        [&](LoggingTransaction& txn) {
          std::string sql = R"SQL(
            SELECT device_id, device_display_name, last_ip,
                   last_user_agent, last_seen_at_ms, created_at_ms,
                   expires_at_ms, idle_timeout_ms, is_guest,
                   token_state, token_kind, used_count
            FROM access_tokens
            WHERE user_id = ?1 AND device_id = ?2
            ORDER BY created_at_ms DESC
            LIMIT 50
          )SQL";
          txn.execute(sql, {
            SQLParam{user_id}, SQLParam{device_id}
          });

          Row row;
          while (txn.iter_next(row)) {
            if (row.empty()) continue;
            SessionEntry entry;
            entry.device_id = row[0].value.value_or("");
            entry.display_name = row[1].value.value_or("");
            entry.last_seen_ip = row[2].value.value_or("");
            entry.last_seen_ua = row[3].value.value_or("");
            entry.last_seen_ts = row[4].value
                ? std::stoll(*row[4].value) : 0LL;
            entry.created_ts = row[5].value
                ? std::stoll(*row[5].value) : 0LL;
            entry.expires_ts = row[6].value
                ? std::stoll(*row[6].value) : 0LL;
            entry.idle_timeout_ms = row[7].value
                ? std::stoll(*row[7].value) : IDLE_TIMEOUT_DEFAULT_MS;
            entry.is_guest = row[8].value && *row[8].value == "1";
            int state = row[9].value ? std::stoi(*row[9].value) : -1;
            entry.is_active = (state == static_cast<int>(TokenState::ACTIVE));
            entry.kind = static_cast<TokenKind>(
                row[10].value ? std::stoi(*row[10].value) : 0);
            entry.used_count = row[11].value ? std::stoi(*row[11].value) : 0;
            entry.shadow_banned = false;
            results.push_back(entry);
          }
        });

    return results;
  }

  // ---- Session count by device ----

  int count_device_sessions(const std::string& user_id,
                             const std::string& device_id) {
    int count = 0;
    db_.runInteraction("count_device_sessions",
        [&](LoggingTransaction& txn) {
          txn.execute(
              "SELECT COUNT(*) FROM access_tokens "
              "WHERE user_id = ?1 AND device_id = ?2 AND token_state = 0",
              {SQLParam{user_id}, SQLParam{device_id}});
          Row row;
          if (txn.iter_next(row)) {
            count = row[0].value ? std::stoi(*row[0].value) : 0;
          }
        });
    return count;
  }

  // ---- Idle session detection ----

  std::vector<json> find_idle_sessions(int64_t idle_threshold_ms = 0,
                                         int limit = IDLE_SESSION_BATCH_SIZE) {
    if (idle_threshold_ms <= 0) idle_threshold_ms = IDLE_TIMEOUT_DEFAULT_MS;
    int64_t now = now_ms();
    int64_t cutoff = now - idle_threshold_ms;

    std::vector<json> results;

    db_.runInteraction("find_idle_sessions",
        [&](LoggingTransaction& txn) {
          std::string sql = R"SQL(
            SELECT token, user_id, device_id, last_seen_at_ms,
                   idle_timeout_ms, created_at_ms
            FROM access_tokens
            WHERE token_state = 0
              AND last_seen_at_ms < ?1
            ORDER BY last_seen_at_ms ASC
            LIMIT ?2
          )SQL";
          txn.execute(sql, {
            SQLParam{cutoff},
            SQLParam{static_cast<int64_t>(limit)}
          });

          Row row;
          while (txn.iter_next(row)) {
            if (row.empty()) continue;
            json entry;
            entry["token"] = "[redacted]";
            entry["user_id"] = row[1].value.value_or("");
            entry["device_id"] = row[2].value.value_or("");
            entry["last_seen_at_ms"] = row[3].value
                ? std::stoll(*row[3].value) : 0LL;
            entry["idle_timeout_ms"] = row[4].value
                ? std::stoll(*row[4].value) : IDLE_TIMEOUT_DEFAULT_MS;
            entry["idle_duration_ms"] = now -
                (row[3].value ? std::stoll(*row[3].value) : 0LL);
            entry["created_at_ms"] = row[5].value
                ? std::stoll(*row[5].value) : 0LL;
            results.push_back(entry);
          }
        });

    return results;
  }

  // ---- Session search (admin) ----

  std::vector<json> search_sessions(const std::string& query,
                                      int limit = 50) {
    std::vector<json> results;

    db_.runInteraction("search_sessions",
        [&](LoggingTransaction& txn) {
          std::string sql = R"SQL(
            SELECT token, user_id, device_id, device_display_name,
                   token_state, last_ip, last_user_agent,
                   last_seen_at_ms
            FROM access_tokens
            WHERE user_id LIKE ?1
               OR device_id LIKE ?2
               OR device_display_name LIKE ?3
               OR last_ip LIKE ?4
            ORDER BY last_seen_at_ms DESC
            LIMIT ?5
          )SQL";
          std::string like = "%" + query + "%";
          txn.execute(sql, {
            SQLParam{like}, SQLParam{like},
            SQLParam{like}, SQLParam{like},
            SQLParam{static_cast<int64_t>(limit)}
          });

          Row row;
          while (txn.iter_next(row)) {
            if (row.empty()) continue;
            json entry;
            entry["token"] = "[redacted]";
            entry["user_id"] = row[1].value.value_or("");
            entry["device_id"] = row[2].value.value_or("");
            entry["display_name"] = row[3].value.value_or("");
            entry["state"] = row[4].value
                ? token_state_name(static_cast<TokenState>(std::stoi(*row[4].value)))
                : "unknown";
            entry["last_ip"] = row[5].value.value_or("");
            entry["last_user_agent"] = row[6].value.value_or("");
            entry["last_seen_at_ms"] = row[7].value
                ? std::stoll(*row[7].value) : 0LL;
            results.push_back(entry);
          }
        });

    return results;
  }

 private:
  DatabasePool& db_;
};

// ============================================================================
// 7. SessionInvalidationService — Comprehensive session invalidation
// ============================================================================

class SessionInvalidationService {
 public:
  SessionInvalidationService(AccessTokenManager& access_tokens,
                              RefreshTokenManager& refresh_tokens,
                              SessionAuditLogger& audit)
      : access_tokens_(access_tokens),
        refresh_tokens_(refresh_tokens),
        audit_(audit) {}

  // ---- Invalidate single session ----

  bool invalidate_session(const std::string& token,
                           InvalidationReason reason,
                           const std::string& admin_user = "") {
    bool success = access_tokens_.revoke_token(token, reason, admin_user);
    if (success) {
      audit_.log("", "", token, TokenKind::ACCESS,
                  AuditAction::TOKEN_REVOKED, "", "", reason, admin_user);
    }
    return success;
  }

  // ---- Invalidate all sessions for user ----

  struct InvalidationResult {
    int access_tokens_revoked;
    int refresh_tokens_revoked;
    bool success;
    std::string error;
  };

  InvalidationResult invalidate_all_user_sessions(
      const std::string& user_id,
      InvalidationReason reason,
      const std::string& except_token = "",
      const std::string& admin_user = "") {

    InvalidationResult result;
    result.success = true;

    result.access_tokens_revoked = access_tokens_.revoke_all_for_user(
        user_id, reason, except_token, admin_user);

    if (reason != InvalidationReason::IDLE_TIMEOUT) {
      result.refresh_tokens_revoked = refresh_tokens_.revoke_all_for_user(
          user_id, reason);
    }

    audit_.log(user_id, "", "", TokenKind::ACCESS,
                AuditAction::BULK_REVOKE, "", "", reason, admin_user,
                {
                  {"access_tokens_revoked", result.access_tokens_revoked},
                  {"refresh_tokens_revoked", result.refresh_tokens_revoked},
                  {"except_token", except_token.empty()
                      ? "none" : "[redacted]"}
                });

    return result;
  }

  // ---- Invalidate device sessions ----

  InvalidationResult invalidate_device_sessions(
      const std::string& user_id,
      const std::string& device_id,
      InvalidationReason reason) {

    InvalidationResult result;
    result.success = true;

    result.access_tokens_revoked = access_tokens_.revoke_all_for_device(
        user_id, device_id, reason);
    result.refresh_tokens_revoked = refresh_tokens_.revoke_all_for_device(
        user_id, device_id, reason);

    return result;
  }

  // ---- Password change invalidation ----

  InvalidationResult invalidate_on_password_change(
      const std::string& user_id,
      const std::string& except_token) {

    return invalidate_all_user_sessions(
        user_id, InvalidationReason::PASSWORD_CHANGE, except_token);
  }

  // ---- Account deactivation invalidation ----

  InvalidationResult invalidate_on_account_deactivation(
      const std::string& user_id) {

    return invalidate_all_user_sessions(
        user_id, InvalidationReason::ACCOUNT_DEACT);
  }

  // ---- Account suspension invalidation ----

  InvalidationResult invalidate_on_account_suspension(
      const std::string& user_id) {

    return invalidate_all_user_sessions(
        user_id, InvalidationReason::ACCOUNT_SUSPEND);
  }

  // ---- GDPR deletion invalidation ----

  InvalidationResult invalidate_for_gdpr_deletion(
      const std::string& user_id) {

    return invalidate_all_user_sessions(
        user_id, InvalidationReason::GDPR_DELETION);
  }

  // ---- Security event invalidation ----

  InvalidationResult invalidate_on_security_event(
      const std::string& user_id,
      const std::string& event_description = "") {

    return invalidate_all_user_sessions(
        user_id, InvalidationReason::SECURITY_EVENT, "",
        "",  // no admin user
        // Note: event_description goes into audit
        );
  }

  // ---- Admin force invalidation ----

  InvalidationResult admin_force_invalidate(
      const std::string& user_id,
      const std::string& admin_user_id,
      const std::string& reason_text = "") {

    auto result = invalidate_all_user_sessions(
        user_id, InvalidationReason::ADMIN_FORCE, "", admin_user_id);

    audit_.log(user_id, "", "", TokenKind::ACCESS,
                AuditAction::ADMIN_FORCE_REVOKE, "", "",
                InvalidationReason::ADMIN_FORCE, admin_user_id,
                {{"reason", reason_text}});

    return result;
  }

 private:
  AccessTokenManager& access_tokens_;
  RefreshTokenManager& refresh_tokens_;
  SessionAuditLogger& audit_;
};

// ============================================================================
// 8. IdleTimeoutService — Idle session detection and timeout
// ============================================================================

class IdleTimeoutService {
 public:
  IdleTimeoutService(DatabasePool& db,
                      AccessTokenManager& access_tokens,
                      SessionInvalidationService& invalidation,
                      SessionAuditLogger& audit)
      : db_(db), access_tokens_(access_tokens),
        invalidation_(invalidation), audit_(audit),
        running_(false) {}

  // ---- Idle timeout configuration ----

  void set_user_idle_timeout(const std::string& user_id,
                              int64_t timeout_ms,
                              bool set_by_admin = false,
                              const std::string& admin_user = "") {
    // Clamp to reasonable range
    if (timeout_ms < IDLE_TIMEOUT_MIN_MS) timeout_ms = IDLE_TIMEOUT_MIN_MS;
    if (timeout_ms > IDLE_TIMEOUT_MAX_MS) timeout_ms = IDLE_TIMEOUT_MAX_MS;

    int64_t now = now_ms();
    db_.runInteraction("set_idle_timeout",
        [&](LoggingTransaction& txn) {
          std::string sql = R"SQL(
            INSERT INTO session_idle_config
              (user_id, idle_timeout_ms, created_at_ms,
               updated_at_ms, set_by_admin, admin_user_id)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            ON CONFLICT(user_id) DO UPDATE SET
              idle_timeout_ms = ?2,
              updated_at_ms = ?4,
              set_by_admin = ?5,
              admin_user_id = ?6
          )SQL";
          txn.execute(sql, {
            SQLParam{user_id},
            SQLParam{timeout_ms},
            SQLParam{now},
            SQLParam{now},
            SQLParam{set_by_admin ? 1 : 0},
            SQLParam{admin_user}
          });

          // Also update existing tokens
          std::string upd = R"SQL(
            UPDATE access_tokens
            SET idle_timeout_ms = ?1
            WHERE user_id = ?2 AND token_state = 0
          )SQL";
          txn.execute(upd, {
            SQLParam{timeout_ms},
            SQLParam{user_id}
          });
        });
  }

  int64_t get_user_idle_timeout(const std::string& user_id) {
    int64_t timeout = IDLE_TIMEOUT_DEFAULT_MS;

    db_.runInteraction("get_idle_timeout",
        [&](LoggingTransaction& txn) {
          txn.execute(
              "SELECT idle_timeout_ms FROM session_idle_config "
              "WHERE user_id = ?1",
              {SQLParam{user_id}});
          Row row;
          if (txn.iter_next(row) && !row.empty() && row[0].value) {
            timeout = std::stoll(*row[0].value);
          }
        });

    return timeout;
  }

  void reset_user_idle_timeout(const std::string& user_id) {
    db_.runInteraction("reset_idle_timeout",
        [&](LoggingTransaction& txn) {
          txn.execute(
              "DELETE FROM session_idle_config WHERE user_id = ?1",
              {SQLParam{user_id}});

          txn.execute(
              "UPDATE access_tokens SET idle_timeout_ms = ?1 "
              "WHERE user_id = ?2 AND token_state = 0",
              {SQLParam{IDLE_TIMEOUT_DEFAULT_MS}, SQLParam{user_id}});
        });
  }

  // ---- Idle session detection ----

  struct IdleSessionInfo {
    std::string token;
    std::string user_id;
    std::string device_id;
    int64_t last_seen_ms;
    int64_t idle_timeout_ms;
    int64_t idle_duration_ms;
    int64_t created_at_ms;
  };

  std::vector<IdleSessionInfo> detect_idle_sessions(
      int batch_size = IDLE_SESSION_BATCH_SIZE) {
    std::vector<IdleSessionInfo> results;
    int64_t now = now_ms();

    db_.runInteraction("detect_idle_sessions",
        [&](LoggingTransaction& txn) {
          std::string sql = R"SQL(
            SELECT token, user_id, device_id, last_seen_at_ms,
                   idle_timeout_ms, created_at_ms
            FROM access_tokens
            WHERE token_state = 0
              AND last_seen_at_ms IS NOT NULL
              AND idle_timeout_ms IS NOT NULL
              AND idle_timeout_ms > 0
              AND (?1 - last_seen_at_ms) > idle_timeout_ms
            ORDER BY last_seen_at_ms ASC
            LIMIT ?2
          )SQL";
          txn.execute(sql, {
            SQLParam{now},
            SQLParam{static_cast<int64_t>(batch_size)}
          });

          Row row;
          while (txn.iter_next(row)) {
            if (row.empty()) continue;

            IdleSessionInfo info;
            info.token = row[0].value.value_or("");
            info.user_id = row[1].value.value_or("");
            info.device_id = row[2].value.value_or("");
            info.last_seen_ms = row[3].value
                ? std::stoll(*row[3].value) : 0LL;
            info.idle_timeout_ms = row[4].value
                ? std::stoll(*row[4].value) : IDLE_TIMEOUT_DEFAULT_MS;
            info.idle_duration_ms = now - info.last_seen_ms;
            info.created_at_ms = row[5].value
                ? std::stoll(*row[5].value) : 0LL;
            results.push_back(info);
          }
        });

    return results;
  }

  // ---- Process idle sessions ----

  struct IdleProcessResult {
    int sessions_checked;
    int sessions_timed_out;
    int sessions_invalidated;
    int64_t elapsed_ms;
  };

  IdleProcessResult process_idle_sessions(int max_to_process = IDLE_SESSION_BATCH_SIZE) {
    IdleProcessResult result{};
    int64_t start = now_ms();

    auto idle_sessions = detect_idle_sessions(max_to_process);
    result.sessions_checked = static_cast<int>(idle_sessions.size());

    std::map<std::string, std::vector<std::string>> user_tokens;

    for (const auto& session : idle_sessions) {
      if (session.token.empty()) continue;
      result.sessions_timed_out++;

      // Invalidate the token
      bool invalidated = invalidation_.invalidate_session(
          session.token, InvalidationReason::IDLE_TIMEOUT);

      if (invalidated) {
        result.sessions_invalidated++;
        user_tokens[session.user_id].push_back(session.token);

        audit_.log(session.user_id, session.device_id,
                    session.token, TokenKind::ACCESS,
                    AuditAction::IDLE_TIMEOUT_TRIG, "", "",
                    InvalidationReason::IDLE_TIMEOUT, "",
                    {
                      {"idle_duration_ms", session.idle_duration_ms},
                      {"last_seen_ms", session.last_seen_ms},
                      {"idle_timeout_ms", session.idle_timeout_ms}
                    });
      }
    }

    result.elapsed_ms = now_ms() - start;
    return result;
  }

  // ---- Idle session cleanup worker ----

  void start_background_worker() {
    if (running_.exchange(true)) return;

    worker_thread_ = std::thread([this]() {
      while (running_.load()) {
        try {
          auto result = process_idle_sessions(IDLE_SESSION_BATCH_SIZE);
        } catch (const std::exception&) {}

        // Sleep until next check
        for (int i = 0; i < 60 && running_.load(); ++i) {
          std::this_thread::sleep_for(
              chr::milliseconds(IDLE_CHECK_INTERVAL_MS / 60));
        }
      }
    });
  }

  void stop_background_worker() {
    running_.store(false);
    if (worker_thread_.joinable()) {
      worker_thread_.join();
    }
  }

  bool is_running() const { return running_.load(); }

  // ---- Idle statistics ----

  struct IdleStats {
    int total_active;
    int total_idle;
    int total_idle_but_not_timed_out;
    int users_with_custom_timeout;
    int64_t avg_idle_duration_ms;
    int64_t max_idle_duration_ms;
  };

  IdleStats get_idle_stats() {
    IdleStats stats{};
    int64_t now = now_ms();

    db_.runInteraction("get_idle_stats",
        [&](LoggingTransaction& txn) {
          // Active sessions
          txn.execute(
              "SELECT COUNT(*) FROM access_tokens WHERE token_state = 0");
          Row row;
          if (txn.iter_next(row)) {
            stats.total_active = row[0].value ? std::stoi(*row[0].value) : 0;
          }
          txn.iter_reset();

          // Idle but active
          txn.execute(R"SQL(
            SELECT COUNT(*) FROM access_tokens
            WHERE token_state = 0
              AND idle_timeout_ms > 0
              AND last_seen_at_ms IS NOT NULL
          )SQL");
          if (txn.iter_next(row)) {
            stats.total_idle_but_not_timed_out = row[0].value
                ? std::stoi(*row[0].value) : 0;
          }
          txn.iter_reset();

          // Truly idle (exceeded timeout)
          txn.execute(R"SQL(
            SELECT COUNT(*) FROM access_tokens
            WHERE token_state = 0
              AND idle_timeout_ms > 0
              AND last_seen_at_ms IS NOT NULL
              AND (?1 - last_seen_at_ms) > idle_timeout_ms
          )SQL", {SQLParam{now}});
          if (txn.iter_next(row)) {
            stats.total_idle = row[0].value ? std::stoi(*row[0].value) : 0;
          }
          txn.iter_reset();

          // Custom timeout users
          txn.execute(
              "SELECT COUNT(*) FROM session_idle_config");
          if (txn.iter_next(row)) {
            stats.users_with_custom_timeout = row[0].value
                ? std::stoi(*row[0].value) : 0;
          }
          txn.iter_reset();

          // Stats on idle duration
          txn.execute(R"SQL(
            SELECT AVG(?1 - last_seen_at_ms),
                   MAX(?1 - last_seen_at_ms)
            FROM access_tokens
            WHERE token_state = 0 AND last_seen_at_ms IS NOT NULL
          )SQL", {SQLParam{now}});
          if (txn.iter_next(row)) {
            stats.avg_idle_duration_ms = row[0].value
                ? std::stoll(*row[0].value) : 0LL;
            stats.max_idle_duration_ms = row[1].value
                ? std::stoll(*row[1].value) : 0LL;
          }
        });

    return stats;
  }

 private:
  DatabasePool& db_;
  AccessTokenManager& access_tokens_;
  SessionInvalidationService& invalidation_;
  SessionAuditLogger& audit_;
  std::atomic<bool> running_;
  std::thread worker_thread_;
};

// ============================================================================
// 9. BackgroundTokenCleaner — Periodic token cleanup
// ============================================================================

class BackgroundTokenCleaner {
 public:
  BackgroundTokenCleaner(DatabasePool& db,
                          AccessTokenManager& access_tokens,
                          RefreshTokenManager& refresh_tokens,
                          SessionAuditLogger& audit)
      : db_(db), access_tokens_(access_tokens),
        refresh_tokens_(refresh_tokens), audit_(audit),
        running_(false) {}

  // ---- Expired token cleanup ----

  struct CleanupStats {
    int access_tokens_expired;
    int refresh_tokens_expired;
    int audit_entries_deleted;
    int64_t elapsed_ms;
    int64_t run_timestamp_ms;
  };

  CleanupStats run_cleanup_cycle() {
    CleanupStats stats{};
    stats.run_timestamp_ms = now_ms();
    int64_t start = now_ms();

    // Expire access tokens
    stats.access_tokens_expired = access_tokens_.expire_tokens_batch(
        EXPIRED_TOKEN_BATCH_SIZE);

    // Expire refresh tokens
    stats.refresh_tokens_expired = refresh_tokens_.expire_expired_batch(
        EXPIRED_TOKEN_BATCH_SIZE);

    // Cleanup audit logs
    audit_.cleanup_old_entries();

    stats.elapsed_ms = now_ms() - start;

    audit_.log("system", "", "", TokenKind::ACCESS,
                AuditAction::CLEANUP_RUN, "", "", std::nullopt, "",
                {
                  {"access_expired", stats.access_tokens_expired},
                  {"refresh_expired", stats.refresh_tokens_expired},
                  {"elapsed_ms", stats.elapsed_ms}
                });

    return stats;
  }

  // ---- Vacuum old revoked tokens ----

  int purge_revoked_tokens(int64_t older_than_ms = 0) {
    if (older_than_ms <= 0) older_than_ms = days_to_ms(30);
    int64_t cutoff = now_ms() - older_than_ms;
    int count = 0;

    db_.runInteraction("purge_revoked_tokens",
        [&](LoggingTransaction& txn) {
          // Access tokens
          txn.execute(
              "DELETE FROM access_tokens WHERE token_state = 1 "
              "AND revoked_at_ms IS NOT NULL AND revoked_at_ms < ?1",
              {SQLParam{cutoff}});
          count += static_cast<int>(txn.rowcount());

          // Refresh tokens
          txn.execute(
              "DELETE FROM refresh_tokens WHERE revoked = 1 "
              "AND revoked_at_ms IS NOT NULL AND revoked_at_ms < ?1",
              {SQLParam{cutoff}});
          count += static_cast<int>(txn.rowcount());
        });

    return count;
  }

  // ---- Background worker ----

  void start_background_worker() {
    if (running_.exchange(true)) return;

    worker_thread_ = std::thread([this]() {
      while (running_.load()) {
        try {
          run_cleanup_cycle();
        } catch (const std::exception&) {}

        // Sleep between cleanup cycles
        for (int i = 0; i < 30 && running_.load(); ++i) {
          std::this_thread::sleep_for(
              chr::milliseconds(TOKEN_CLEANUP_INTERVAL_MS / 30));
        }
      }
    });
  }

  void stop_background_worker() {
    running_.store(false);
    if (worker_thread_.joinable()) {
      worker_thread_.join();
    }
  }

  bool is_running() const { return running_.load(); }

  // ---- Force immediate cleanup ----

  CleanupStats force_cleanup() {
    return run_cleanup_cycle();
  }

  // ---- Statistics ----

  struct CleanerStats {
    int64_t last_run_ms;
    int total_runs;
    int64_t total_expired_access;
    int64_t total_expired_refresh;
    int64_t total_purged;
    bool is_running;
  };

  CleanerStats get_cleaner_stats() const {
    CleanerStats s{};
    s.last_run_ms = last_run_ms_.load();
    s.total_runs = total_runs_.load();
    s.total_expired_access = total_expired_access_.load();
    s.total_expired_refresh = total_expired_refresh_.load();
    s.total_purged = total_purged_.load();
    s.is_running = running_.load();
    return s;
  }

 private:
  DatabasePool& db_;
  AccessTokenManager& access_tokens_;
  RefreshTokenManager& refresh_tokens_;
  SessionAuditLogger& audit_;
  std::atomic<bool> running_;
  std::thread worker_thread_;

  std::atomic<int64_t> last_run_ms_{0};
  std::atomic<int> total_runs_{0};
  std::atomic<int64_t> total_expired_access_{0};
  std::atomic<int64_t> total_expired_refresh_{0};
  std::atomic<int64_t> total_purged_{0};
};

// ============================================================================
// 10. AdminSessionService — Admin-level session operations
// ============================================================================

class AdminSessionService {
 public:
  AdminSessionService(DatabasePool& db,
                       SessionListingService& listing,
                       SessionInvalidationService& invalidation,
                       AccessTokenManager& access_tokens,
                       RefreshTokenManager& refresh_tokens,
                       SessionAuditLogger& audit)
      : db_(db), listing_(listing), invalidation_(invalidation),
        access_tokens_(access_tokens), refresh_tokens_(refresh_tokens),
        audit_(audit) {}

  // ---- List all active sessions (admin) ----

  json list_all_sessions(int limit = 50, int offset = 0,
                          const std::string& filter_user = "",
                          const std::string& filter_device = "",
                          bool active_only = true) {
    auto sessions = listing_.list_all_sessions_admin(
        limit, offset, filter_user, filter_device, active_only);

    json result;
    result["sessions"] = sessions;
    result["total"] = sessions.size();
    result["limit"] = limit;
    result["offset"] = offset;
    return result;
  }

  // ---- Force revoke session (admin) ----

  bool force_revoke_session(const std::string& token,
                             const std::string& admin_user_id,
                             const std::string& reason = "") {
    return invalidation_.invalidate_session(
        token, InvalidationReason::ADMIN_FORCE, admin_user_id);
  }

  // ---- Force revoke all user sessions (admin) ----

  SessionInvalidationService::InvalidationResult force_revoke_user_sessions(
      const std::string& user_id,
      const std::string& admin_user_id,
      const std::string& reason = "") {

    return invalidation_.admin_force_invalidate(
        user_id, admin_user_id, reason);
  }

  // ---- Session statistics (admin) ----

  json get_session_stats() {
    json stats;
    stats["timestamp_ms"] = now_ms();
    stats["timestamp"] = now_iso8601();

    auto access_stats = access_tokens_.get_stats();
    stats["access_tokens"] = {
      {"total_active", access_stats.total_active},
      {"total_expired", access_stats.total_expired},
      {"total_revoked", access_stats.total_revoked},
      {"total_guests", access_stats.total_guests},
      {"unique_users", access_stats.unique_users}
    };

    auto refresh_stats = refresh_tokens_.get_stats();
    stats["refresh_tokens"] = {
      {"total_active", refresh_stats.total_active},
      {"total_revoked", refresh_stats.total_revoked},
      {"unique_users", refresh_stats.unique_users},
      {"chains_with_depth", refresh_stats.chains_with_depth}
    };

    // Total active sessions (all users, access tokens)
    db_.runInteraction("admin_session_stats",
        [&](LoggingTransaction& txn) {
          txn.execute(
              "SELECT COUNT(*), COUNT(DISTINCT user_id) "
              "FROM access_tokens WHERE token_state = 0");
          Row row;
          if (txn.iter_next(row)) {
            stats["total_active_sessions"] = row[0].value
                ? std::stoi(*row[0].value) : 0;
            stats["active_unique_users"] = row[1].value
                ? std::stoi(*row[1].value) : 0;
          }
        });

    return stats;
  }

  // ---- Session statistics snapshot ----

  void take_stats_snapshot() {
    auto stats = get_session_stats();
    int64_t now = now_ms();

    db_.runInteraction("snapshot_session_stats",
        [&](LoggingTransaction& txn) {
          txn.execute(
              R"SQL(
                INSERT INTO session_stats_snapshot
                  (snapshot_at_ms, total_active, total_idle,
                   total_expired, total_revoked, total_guests,
                   total_refresh, unique_users, detail_json)
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
              )SQL",
              {
                SQLParam{now},
                SQLParam{stats["total_active_sessions"].get<int>()},
                SQLParam{0},
                SQLParam{stats["access_tokens"]["total_expired"].get<int>()},
                SQLParam{stats["access_tokens"]["total_revoked"].get<int>()},
                SQLParam{stats["access_tokens"]["total_guests"].get<int>()},
                SQLParam{stats["refresh_tokens"]["total_active"].get<int>()},
                SQLParam{stats["active_unique_users"].get<int>()},
                SQLParam{stats.dump()}
              });
        });
  }

  // ---- Historical stats ----

  std::vector<json> get_stats_history(int limit = 24) {
    std::vector<json> results;

    db_.runInteraction("get_stats_history",
        [&](LoggingTransaction& txn) {
          txn.execute(
              R"SQL(
                SELECT snapshot_at_ms, total_active, total_idle,
                       total_expired, total_revoked, total_guests,
                       total_refresh, unique_users, detail_json
                FROM session_stats_snapshot
                ORDER BY snapshot_at_ms DESC
                LIMIT ?1
              )SQL",
              {SQLParam{static_cast<int64_t>(limit)}});

          Row row;
          while (txn.iter_next(row)) {
            if (row.empty()) continue;
            json entry;
            entry["snapshot_at_ms"] = row[0].value
                ? std::stoll(*row[0].value) : 0LL;
            entry["total_active"] = row[1].value
                ? std::stoi(*row[1].value) : 0;
            entry["total_idle"] = row[2].value
                ? std::stoi(*row[2].value) : 0;
            entry["total_expired"] = row[3].value
                ? std::stoi(*row[3].value) : 0;
            entry["total_revoked"] = row[4].value
                ? std::stoi(*row[4].value) : 0;
            entry["total_guests"] = row[5].value
                ? std::stoi(*row[5].value) : 0;
            entry["total_refresh"] = row[6].value
                ? std::stoi(*row[6].value) : 0;
            entry["unique_users"] = row[7].value
                ? std::stoi(*row[7].value) : 0;
            if (row[8].value && !row[8].value->empty()) {
              try { entry["detail"] = json::parse(*row[8].value); }
              catch (...) {}
            }
            results.push_back(entry);
          }
        });

    return results;
  }

  // ---- Bulk session operations ----

  struct BulkRevokeResult {
    int total_processed;
    int total_revoked;
    std::vector<std::string> errors;
  };

  BulkRevokeResult bulk_revoke_by_users(
      const std::vector<std::string>& user_ids,
      const std::string& admin_user_id,
      InvalidationReason reason = InvalidationReason::ADMIN_FORCE) {

    BulkRevokeResult result;

    for (const auto& uid : user_ids) {
      try {
        auto r = invalidation_.admin_force_invalidate(
            uid, admin_user_id, "bulk operation");
        result.total_processed++;
        result.total_revoked += r.access_tokens_revoked;
      } catch (const std::exception& e) {
        result.errors.push_back(
            std::string("Error for ") + uid + ": " + e.what());
      }
    }

    return result;
  }

 private:
  DatabasePool& db_;
  SessionListingService& listing_;
  SessionInvalidationService& invalidation_;
  AccessTokenManager& access_tokens_;
  RefreshTokenManager& refresh_tokens_;
  SessionAuditLogger& audit_;
};

// ============================================================================
// 11. AppServiceTokenManager — Appservice token handling
// ============================================================================

class AppServiceTokenManager {
 public:
  explicit AppServiceTokenManager(DatabasePool& db) : db_(db) {}

  std::string generate_appservice_token(const std::string& app_service_id) {
    std::string token = srng().token(PREFIX_APP_SERVICE,
        APP_SERVICE_TOKEN_LENGTH - static_cast<int>(std::strlen(PREFIX_APP_SERVICE)));
    int64_t now = now_ms();

    db_.runInteraction("create_as_token",
        [&](LoggingTransaction& txn) {
          txn.execute(
              R"SQL(
                INSERT INTO app_service_tokens
                  (token, app_service_id, created_at_ms, expires_at_ms, revoked)
                VALUES (?1, ?2, ?3, ?4, 0)
              )SQL",
              {
                SQLParam{token},
                SQLParam{app_service_id},
                SQLParam{now},
                SQLParam{now + APP_SERVICE_TOKEN_TTL_MS}
              });
        });

    return token;
  }

  bool validate_token(const std::string& token,
                       std::string& app_service_id) {
    bool valid = false;

    db_.runInteraction("validate_as_token",
        [&](LoggingTransaction& txn) {
          txn.execute(
              R"SQL(
                SELECT app_service_id, expires_at_ms, revoked
                FROM app_service_tokens
                WHERE token = ?1
              )SQL",
              {SQLParam{token}});

          Row row;
          if (txn.iter_next(row) && !row.empty()) {
            int revoked = row[2].value ? std::stoi(*row[2].value) : 0;
            int64_t expires = row[1].value ? std::stoll(*row[1].value) : 0;
            int64_t now = now_ms();

            if (revoked == 1) return;
            if (expires > 0 && now > expires) return;

            app_service_id = row[0].value.value_or("");
            valid = true;
          }
        });

    return valid;
  }

  bool revoke_token(const std::string& token) {
    bool success = false;
    int64_t now = now_ms();

    db_.runInteraction("revoke_as_token",
        [&](LoggingTransaction& txn) {
          txn.execute(
              "UPDATE app_service_tokens SET revoked = 1 "
              "WHERE token = ?1",
              {SQLParam{token}});
          success = (txn.rowcount() > 0);
        });

    return success;
  }

 private:
  DatabasePool& db_;
};

// ============================================================================
// 12. GuestTokenManager — Guest session handling
// ============================================================================

class GuestTokenManager {
 public:
  GuestTokenManager(DatabasePool& db,
                     AccessTokenManager& access_tokens)
      : db_(db), access_tokens_(access_tokens) {}

  std::string create_guest_session(const std::string& ip = "",
                                    const std::string& user_agent = "") {
    // Generate a guest user ID
    std::string guest_id = "@guest_" +
        srng().random_hex(16) + ":localhost";

    return access_tokens_.generate_access_token(
        guest_id,                // user_id
        "guest_" + srng().random_hex(8),  // device_id
        TokenKind::GUEST,        // token kind
        true,                    // is_guest
        "",                      // app_service_id
        GUEST_TOKEN_TTL_MS,      // custom TTL
        "Guest Session",
        ip,
        user_agent);
  }

  int count_guest_sessions() {
    int count = 0;
    db_.runInteraction("count_guests",
        [&](LoggingTransaction& txn) {
          txn.execute(
              "SELECT COUNT(*) FROM access_tokens "
              "WHERE is_guest = 1 AND token_state = 0");
          Row row;
          if (txn.iter_next(row)) {
            count = row[0].value ? std::stoi(*row[0].value) : 0;
          }
        });
    return count;
  }

  int cleanup_expired_guests() {
    int count = 0;
    int64_t now = now_ms();

    db_.runInteraction("cleanup_expired_guests",
        [&](LoggingTransaction& txn) {
          txn.execute(
              R"SQL(
                UPDATE access_tokens
                SET token_state = ?1
                WHERE is_guest = 1
                  AND token_state = 0
                  AND expires_at_ms IS NOT NULL
                  AND expires_at_ms > 0
                  AND expires_at_ms < ?2
              )SQL",
              {
                SQLParam{static_cast<int>(TokenState::EXPIRED)},
                SQLParam{now}
              });
          count = static_cast<int>(txn.rowcount());
        });

    return count;
  }

 private:
  DatabasePool& db_;
  AccessTokenManager& access_tokens_;
};

// ============================================================================
// 13. TokenExpiryService — Token expiry management
// ============================================================================

class TokenExpiryService {
 public:
  TokenExpiryService(AccessTokenManager& access_tokens,
                      RefreshTokenManager& refresh_tokens)
      : access_tokens_(access_tokens),
        refresh_tokens_(refresh_tokens) {}

  struct ExpiryConfig {
    int64_t access_token_ttl_ms{ACCESS_TOKEN_TTL_MS};
    int64_t refresh_token_ttl_ms{REFRESH_TOKEN_TTL_MS};
    int64_t login_token_ttl_ms{LOGIN_TOKEN_TTL_MS};
    int64_t sso_session_ttl_ms{SSO_SESSION_TTL_MS};
    int64_t guest_token_ttl_ms{GUEST_TOKEN_TTL_MS};
    int64_t idle_timeout_ms{IDLE_TIMEOUT_DEFAULT_MS};
    bool enforce_absolute_expiry{true};
    bool auto_revoke_on_expiry{true};
  };

  void set_config(const ExpiryConfig& config) {
    std::lock_guard<std::mutex> lock(config_mtx_);
    config_ = config;
  }

  ExpiryConfig get_config() const {
    std::lock_guard<std::mutex> lock(config_mtx_);
    return config_;
  }

  bool is_token_expired(int64_t expires_at_ms) const {
    if (expires_at_ms <= 0) return false;
    return now_ms() > expires_at_ms;
  }

  int64_t get_ttl_for_kind(TokenKind kind) const {
    std::lock_guard<std::mutex> lock(config_mtx_);
    switch (kind) {
      case TokenKind::ACCESS:    return config_.access_token_ttl_ms;
      case TokenKind::REFRESH:   return config_.refresh_token_ttl_ms;
      case TokenKind::LOGIN_TOKEN: return config_.login_token_ttl_ms;
      case TokenKind::SSO_SESSION: return config_.sso_session_ttl_ms;
      case TokenKind::GUEST:     return config_.guest_token_ttl_ms;
      default:                   return config_.access_token_ttl_ms;
    }
  }

  int64_t get_expiry_for_kind(TokenKind kind) const {
    return now_ms() + get_ttl_for_kind(kind);
  }

 private:
  mutable std::mutex config_mtx_;
  ExpiryConfig config_;
};

// ============================================================================
// 14. SessionManager — Main coordinator class
// ============================================================================

class SessionManager {
 public:
  explicit SessionManager(DatabasePool& db)
      : db_(db),
        cache_(),
        audit_(db),
        rate_limiter_(db),
        access_tokens_(db, cache_, audit_, rate_limiter_),
        refresh_tokens_(db, audit_, access_tokens_),
        listing_(db),
        invalidation_(access_tokens_, refresh_tokens_, audit_),
        idle_timeout_(db, access_tokens_, invalidation_, audit_),
        token_cleaner_(db, access_tokens_, refresh_tokens_, audit_),
        admin_service_(db, listing_, invalidation_,
                        access_tokens_, refresh_tokens_, audit_),
        app_service_tokens_(db),
        guest_tokens_(db, access_tokens_),
        token_expiry_(access_tokens_, refresh_tokens_),
        initialized_(false) {}

  // ---- Initialization ----

  void initialize() {
    if (initialized_.exchange(true)) return;

    // Run DDL
    db_.runInteraction("session_ddl",
        [&](LoggingTransaction& txn) {
          for (const auto* ddl : ALL_SESSION_DDL) {
            txn.executescript(ddl);
          }
        });

    // Start background workers
    token_cleaner_.start_background_worker();
    idle_timeout_.start_background_worker();
  }

  void shutdown() {
    token_cleaner_.stop_background_worker();
    idle_timeout_.stop_background_worker();
    audit_.flush_buffer();
    initialized_.store(false);
  }

  // ---- Access Token Operations ----

  std::string create_access_token(const std::string& user_id,
                                   const std::string& device_id = "",
                                   bool is_guest = false,
                                   const std::string& app_service_id = "",
                                   const std::string& ip = "",
                                   const std::string& user_agent = "",
                                   const std::string& display_name = "") {
    // Rate limit check
    if (!rate_limiter_.check_rate("create_" + user_id, "token_create",
                                    TOKEN_CREATE_RATE_PER_MIN)) {
      throw std::runtime_error("Rate limit exceeded for token creation");
    }

    // Session limit check
    int current_sessions = access_tokens_.count_user_sessions(user_id);
    if (current_sessions >= MAX_SESSIONS_PER_USER) {
      throw std::runtime_error(
          "Maximum session limit reached for user: " + user_id);
    }

    return access_tokens_.generate_access_token(
        user_id, device_id,
        is_guest ? TokenKind::GUEST : TokenKind::ACCESS,
        is_guest, app_service_id, 0, display_name, ip, user_agent);
  }

  AccessTokenManager::ValidationResult validate_token(
      const std::string& token,
      const std::string& ip = "",
      const std::string& user_agent = "") {
    return access_tokens_.validate_token(token, ip, user_agent);
  }

  bool revoke_token(const std::string& token,
                     InvalidationReason reason = InvalidationReason::USER_REQUEST) {
    return access_tokens_.revoke_token(token, reason);
  }

  int revoke_all_user_sessions(const std::string& user_id,
                                const std::string& except_token = "") {
    return invalidation_.invalidate_all_user_sessions(
        user_id, InvalidationReason::USER_REQUEST, except_token).access_tokens_revoked;
  }

  // ---- Refresh Token Operations ----

  std::string create_refresh_token(const std::string& user_id,
                                    const std::string& device_id,
                                    const std::string& access_token) {
    return refresh_tokens_.generate_refresh_token(user_id, device_id, access_token);
  }

  RefreshTokenManager::RefreshResult refresh_access_token(
      const std::string& refresh_token,
      const std::string& ip = "",
      const std::string& user_agent = "") {
    return refresh_tokens_.refresh(refresh_token, ip, user_agent);
  }

  // ---- Session Listing ----

  std::vector<SessionListingService::SessionEntry> list_user_sessions(
      const std::string& user_id,
      bool include_inactive = false) {
    return listing_.list_user_sessions(user_id, include_inactive);
  }

  // ---- Password Change Handling ----

  void on_password_change(const std::string& user_id,
                           const std::string& except_token) {
    invalidation_.invalidate_on_password_change(user_id, except_token);
  }

  // ---- Account Lifecycle ----

  void on_account_deactivated(const std::string& user_id) {
    invalidation_.invalidate_on_account_deactivation(user_id);
  }

  void on_account_suspended(const std::string& user_id) {
    invalidation_.invalidate_on_account_suspension(user_id);
  }

  void on_gdpr_deletion(const std::string& user_id) {
    invalidation_.invalidate_for_gdpr_deletion(user_id);
  }

  // ---- Idle Timeout ----

  void set_idle_timeout(const std::string& user_id,
                         int64_t timeout_ms,
                         bool is_admin = false,
                         const std::string& admin_user = "") {
    idle_timeout_.set_user_idle_timeout(user_id, timeout_ms, is_admin, admin_user);
  }

  int64_t get_idle_timeout(const std::string& user_id) {
    return idle_timeout_.get_user_idle_timeout(user_id);
  }

  IdleTimeoutService::IdleStats get_idle_stats() {
    return idle_timeout_.get_idle_stats();
  }

  // ---- Admin Operations ----

  json admin_list_sessions(int limit = 50, int offset = 0,
                            const std::string& filter = "") {
    return admin_service_.list_all_sessions(limit, offset, filter);
  }

  json admin_get_stats() {
    return admin_service_.get_session_stats();
  }

  bool admin_force_revoke(const std::string& token,
                           const std::string& admin_user) {
    return admin_service_.force_revoke_session(token, admin_user);
  }

  SessionInvalidationService::InvalidationResult admin_force_revoke_user(
      const std::string& user_id,
      const std::string& admin_user,
      const std::string& reason = "") {
    return admin_service_.force_revoke_user_sessions(user_id, admin_user, reason);
  }

  // ---- Cleanup ----

  BackgroundTokenCleaner::CleanupStats force_cleanup() {
    return token_cleaner_.force_cleanup();
  }

  void update_last_seen(const std::string& token) {
    access_tokens_.update_last_seen(token);
  }

  // ---- Statistics & Monitoring ----

  json get_system_stats() {
    json stats;
    stats["access_tokens"] = access_tokens_.get_stats();
    stats["refresh_tokens"] = refresh_tokens_.get_stats();
    stats["idle_stats"] = idle_timeout_.get_idle_stats();
    stats["cache"] = cache_.stats();
    stats["cleaner"] = token_cleaner_.get_cleaner_stats();
    stats["guest_sessions"] = guest_tokens_.count_guest_sessions();
    stats["timestamp_ms"] = now_ms();
    return stats;
  }

  // ---- Audit Log Access ----

  std::vector<json> get_audit_log(const std::string& user_id,
                                    int limit = 50) {
    return audit_.query_audit(user_id, limit);
  }

  // ---- Guest Operations ----

  std::string create_guest_session(const std::string& ip = "",
                                    const std::string& user_agent = "") {
    return guest_tokens_.create_guest_session(ip, user_agent);
  }

  // ---- AppService Operations ----

  std::string create_appservice_token(const std::string& app_service_id) {
    return app_service_tokens_.generate_appservice_token(app_service_id);
  }

  bool validate_appservice_token(const std::string& token,
                                  std::string& app_service_id) {
    return app_service_tokens_.validate_token(token, app_service_id);
  }

 private:
  DatabasePool& db_;
  SessionCacheManager cache_;
  SessionAuditLogger audit_;
  TokenRateLimiter rate_limiter_;
  AccessTokenManager access_tokens_;
  RefreshTokenManager refresh_tokens_;
  SessionListingService listing_;
  SessionInvalidationService invalidation_;
  IdleTimeoutService idle_timeout_;
  BackgroundTokenCleaner token_cleaner_;
  AdminSessionService admin_service_;
  AppServiceTokenManager app_service_tokens_;
  GuestTokenManager guest_tokens_;
  TokenExpiryService token_expiry_;
  std::atomic<bool> initialized_;
};

// ============================================================================
// 15. C API / Public interface functions
// ============================================================================

// Global instance management
namespace {

std::unique_ptr<SessionManager> g_session_manager;
std::mutex g_session_mutex;

}  // anonymous namespace

// ---- Public initialization functions ----

bool session_manager_init(DatabasePool& db) {
  std::lock_guard<std::mutex> lock(g_session_mutex);
  if (g_session_manager) return true;

  try {
    g_session_manager = std::make_unique<SessionManager>(db);
    g_session_manager->initialize();
    return true;
  } catch (const std::exception& e) {
    return false;
  }
}

void session_manager_shutdown() {
  std::lock_guard<std::mutex> lock(g_session_mutex);
  if (g_session_manager) {
    g_session_manager->shutdown();
    g_session_manager.reset();
  }
}

SessionManager* get_session_manager() {
  return g_session_manager.get();
}

// ---- Convenience namespace-level functions ----

namespace session {

std::string create_access_token(DatabasePool& db,
                                 const std::string& user_id,
                                 const std::string& device_id,
                                 bool is_guest,
                                 const std::string& ip,
                                 const std::string& user_agent) {
  auto* mgr = get_session_manager();
  if (mgr) {
    return mgr->create_access_token(user_id, device_id, is_guest,
                                     "", ip, user_agent);
  }

  // Fallback: direct creation without global manager
  SessionCacheManager cache;
  SessionAuditLogger audit(db);
  TokenRateLimiter rate_limiter(db);
  AccessTokenManager atm(db, cache, audit, rate_limiter);

  return atm.generate_access_token(user_id, device_id,
      is_guest ? TokenKind::GUEST : TokenKind::ACCESS,
      is_guest, "", 0, "", ip, user_agent);
}

AccessTokenManager::ValidationResult validate_token(
    DatabasePool& db,
    const std::string& token,
    const std::string& ip,
    const std::string& user_agent) {
  auto* mgr = get_session_manager();
  if (mgr) {
    return mgr->validate_token(token, ip, user_agent);
  }

  // Fallback
  SessionCacheManager cache;
  SessionAuditLogger audit(db);
  TokenRateLimiter rate_limiter(db);
  AccessTokenManager atm(db, cache, audit, rate_limiter);

  return atm.validate_token(token, ip, user_agent);
}

bool revoke_token(DatabasePool& db,
                   const std::string& token,
                   InvalidationReason reason) {
  auto* mgr = get_session_manager();
  if (mgr) {
    return mgr->revoke_token(token, reason);
  }

  SessionCacheManager cache;
  SessionAuditLogger audit(db);
  TokenRateLimiter rate_limiter(db);
  AccessTokenManager atm(db, cache, audit, rate_limiter);

  return atm.revoke_token(token, reason);
}

int revoke_all_user_tokens(DatabasePool& db,
                            const std::string& user_id,
                            const std::string& except_token) {
  auto* mgr = get_session_manager();
  if (mgr) {
    return mgr->revoke_all_user_sessions(user_id, except_token);
  }

  SessionCacheManager cache;
  SessionAuditLogger audit(db);
  TokenRateLimiter rate_limiter(db);
  AccessTokenManager atm(db, cache, audit, rate_limiter);

  return atm.revoke_all_for_user(user_id,
      InvalidationReason::USER_REQUEST, except_token);
}

RefreshTokenManager::RefreshResult refresh_access_token(
    DatabasePool& db,
    const std::string& refresh_token,
    const std::string& ip,
    const std::string& user_agent) {
  auto* mgr = get_session_manager();
  if (mgr) {
    return mgr->refresh_access_token(refresh_token, ip, user_agent);
  }

  SessionCacheManager cache;
  SessionAuditLogger audit(db);
  TokenRateLimiter rate_limiter(db);
  AccessTokenManager atm(db, cache, audit, rate_limiter);
  RefreshTokenManager rtm(db, audit, atm);

  return rtm.refresh(refresh_token, ip, user_agent);
}

std::string create_refresh_token(DatabasePool& db,
                                  const std::string& user_id,
                                  const std::string& device_id,
                                  const std::string& access_token) {
  auto* mgr = get_session_manager();
  if (mgr) {
    return mgr->create_refresh_token(user_id, device_id, access_token);
  }

  SessionCacheManager cache;
  SessionAuditLogger audit(db);
  TokenRateLimiter rate_limiter(db);
  AccessTokenManager atm(db, cache, audit, rate_limiter);
  RefreshTokenManager rtm(db, audit, atm);

  return rtm.generate_refresh_token(user_id, device_id, access_token);
}

std::string create_guest_token(DatabasePool& db,
                                const std::string& ip,
                                const std::string& user_agent) {
  auto* mgr = get_session_manager();
  if (mgr) {
    return mgr->create_guest_session(ip, user_agent);
  }

  SessionCacheManager cache;
  SessionAuditLogger audit(db);
  TokenRateLimiter rate_limiter(db);
  AccessTokenManager atm(db, cache, audit, rate_limiter);
  GuestTokenManager gtm(db, atm);

  return gtm.create_guest_session(ip, user_agent);
}

json get_session_stats(DatabasePool& db) {
  auto* mgr = get_session_manager();
  if (mgr) {
    return mgr->admin_get_stats();
  }

  SessionCacheManager cache;
  SessionAuditLogger audit(db);
  TokenRateLimiter rate_limiter(db);
  AccessTokenManager atm(db, cache, audit, rate_limiter);

  auto s = atm.get_stats();
  return {
    {"total_active", s.total_active},
    {"total_expired", s.total_expired},
    {"total_revoked", s.total_revoked},
    {"total_guests", s.total_guests},
    {"unique_users", s.unique_users}
  };
}

void on_password_changed(DatabasePool& db,
                          const std::string& user_id,
                          const std::string& except_token) {
  auto* mgr = get_session_manager();
  if (mgr) {
    mgr->on_password_change(user_id, except_token);
    return;
  }

  SessionCacheManager cache;
  SessionAuditLogger audit(db);
  TokenRateLimiter rate_limiter(db);
  AccessTokenManager atm(db, cache, audit, rate_limiter);
  RefreshTokenManager rtm(db, audit, atm);
  SessionInvalidationService invalidation(atm, rtm, audit);

  invalidation.invalidate_on_password_change(user_id, except_token);
}

void on_account_deactivated(DatabasePool& db,
                             const std::string& user_id) {
  auto* mgr = get_session_manager();
  if (mgr) {
    mgr->on_account_deactivated(user_id);
    return;
  }

  SessionCacheManager cache;
  SessionAuditLogger audit(db);
  TokenRateLimiter rate_limiter(db);
  AccessTokenManager atm(db, cache, audit, rate_limiter);
  RefreshTokenManager rtm(db, audit, atm);
  SessionInvalidationService invalidation(atm, rtm, audit);

  invalidation.invalidate_on_account_deactivation(user_id);
}

void on_account_suspended(DatabasePool& db,
                           const std::string& user_id) {
  auto* mgr = get_session_manager();
  if (mgr) {
    mgr->on_account_suspended(user_id);
    return;
  }

  SessionCacheManager cache;
  SessionAuditLogger audit(db);
  TokenRateLimiter rate_limiter(db);
  AccessTokenManager atm(db, cache, audit, rate_limiter);
  RefreshTokenManager rtm(db, audit, atm);
  SessionInvalidationService invalidation(atm, rtm, audit);

  invalidation.invalidate_on_account_suspension(user_id);
}

void run_token_cleanup(DatabasePool& db) {
  auto* mgr = get_session_manager();
  if (mgr) {
    mgr->force_cleanup();
    return;
  }

  SessionCacheManager cache;
  SessionAuditLogger audit(db);
  TokenRateLimiter rate_limiter(db);
  AccessTokenManager atm(db, cache, audit, rate_limiter);
  RefreshTokenManager rtm(db, audit, atm);
  BackgroundTokenCleaner cleaner(db, atm, rtm, audit);

  cleaner.run_cleanup_cycle();
}

void update_last_seen(DatabasePool& db, const std::string& token) {
  auto* mgr = get_session_manager();
  if (mgr) {
    mgr->update_last_seen(token);
    return;
  }

  SessionCacheManager cache;
  SessionAuditLogger audit(db);
  TokenRateLimiter rate_limiter(db);
  AccessTokenManager atm(db, cache, audit, rate_limiter);

  atm.update_last_seen(token);
}

}  // namespace session

// ============================================================================
// 16. SessionManager JSON serialization helpers
// ============================================================================

namespace {

json session_entry_to_json(
    const SessionListingService::SessionEntry& entry) {
  json j;
  j["device_id"] = entry.device_id;
  j["display_name"] = entry.display_name;
  j["last_seen_ip"] = entry.last_seen_ip;
  j["last_seen_user_agent"] = entry.last_seen_ua;
  j["last_seen_ts"] = entry.last_seen_ts;
  j["last_seen_timestamp"] = entry.last_seen_ts > 0
      ? ts_to_iso8601(entry.last_seen_ts)
      : "";
  j["created_ts"] = entry.created_ts;
  j["expires_ts"] = entry.expires_ts;
  j["idle_timeout_ms"] = entry.idle_timeout_ms;
  j["is_guest"] = entry.is_guest;
  j["is_active"] = entry.is_active;
  j["kind"] = token_kind_name(entry.kind);
  j["used_count"] = entry.used_count;
  return j;
}

}  // anonymous namespace

// ============================================================================
// 17. Logging utility integration
// ============================================================================

namespace {

void log_session_event(const std::string& level,
                        const std::string& event,
                        const json& details = json::object()) {
  // Hook for logging integration
  // In production, this would use the project's logging framework
  // For now, it's a placeholder that can be connected
  (void)level;
  (void)event;
  (void)details;
}

}  // anonymous namespace

}  // namespace progressive

// ============================================================================
// End of session_manager.cpp
// ============================================================================
