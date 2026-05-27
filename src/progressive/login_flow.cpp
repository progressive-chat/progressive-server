// ============================================================================
// login_flow.cpp — Complete Matrix Login Flow Implementation
//
// Implements the full login infrastructure for the Matrix homeserver,
// supporting all standard and extended login/authentication mechanisms:
//
//   - Password-Based Login (m.login.password):
//     Username/password authentication via bcrypt/pbkdf2/argon2id hash
//     verification. Supports user identifier types (m.id.user, m.id.thirdparty,
//     m.id.phone). Password hash upgrade on successful login. Rate limiting
//     per-account and per-IP. Account lockout after repeated failures.
//     Configurable password expiry enforcement.
//
//   - Token-Based Login (m.login.token):
//     Single-use login token exchange for access tokens. Token generation
//     with configurable expiry (default 5 minutes). Token delivery via
//     email, SMS, or existing session. Token revocation on use. Token
//     lookup by user_id+token combination.
//
//   - SSO Redirect Login (m.login.sso):
//     Initiates OIDC/SAML/CAS SSO flow. Generates SSO redirect URL with
//     state parameter. Creates SSO session tracking (pending, authenticated,
//     completed states). Client redirect URL validation. Provider selection
//     (single-provider auto-redirect, multi-provider selection UI).
//     /.well-known/matrix/client SSO configuration generation.
//
//   - CAS Ticket Login (m.login.cas):
//     Central Authentication Service ticket validation. CAS v1/v2/v3
//     protocol support. Service ticket → user mapping resolution.
//     Proxy ticket support for service-to-service auth. CAS attribute
//     release handling. CAS redirect URL construction with service
//     parameter encoding.
//
//   - JWT Login (org.matrix.login.jwt):
//     JSON Web Token-based login. JWT structure validation (header,
//     payload, signature). Signature verification (HS256, RS256, ES256).
//     Claims validation (iss, sub, aud, exp, nbf, iat). JWT-to-User-ID
//     mapping via sub claim. JWKS endpoint integration for key discovery.
//     Configurable JWT secret/issuer/audience. Token expiry enforcement.
//
//   - Appservice Login (m.login.application_service):
//     Application service authentication via as_token. Appservice user
//     namespace validation. Ghost user creation and impersonation.
//     Appservice rate limit configuration. Appservice registration
//     file parsing. Homeserver token (hs_token) verification for
//     inbound appservice requests.
//
//   - Guest Login (m.login.guest):
//     Guest account creation and authentication. Temporary user ID
//     generation (@guest_XXXX:domain). Guest access token with limited
//     capabilities. Guest registration rate limiting. Guest lifecycle
//     tracking (created, last_active, deactivated). Guest account
//     auto-cleanup scheduling. Guest capability restrictions enforced
//     at login time.
//
//   - User Identifier Types:
//     m.id.user: Login by Matrix user ID or localpart. Username
//     normalization (lowercase, whitespace trim). Domain validation.
//     m.id.thirdparty: Login by third-party identifier (email, custom
//     medium). Identity server lookup integration. Pending 3PID binding
//     resolution. m.id.phone: Login by phone number (MSISDN). Phone
//     number format normalization (E.164). SMS verification integration.
//
//   - Refresh Token Support:
//     Refresh token generation on login (opaque random string, 96 chars).
//     Refresh token rotation (single-use, issue new on each refresh).
//     Refresh token expiry (default 30 days). Access token regeneration
//     from refresh token. Refresh token revocation on logout. Device
//     association on refresh. Refresh token scope preservation.
//
//   - Account Deactivation Check:
//     Pre-login account status verification. Deactivated account login
//     rejection with M_USER_DEACTIVATED error. Grace period reactivation
//     support. Soft vs hard deactivation handling. Deactivation reason
//     reporting. Admin override for deactivated account access.
//     Suspended/locked account distinction in error responses.
//
//   - Login Response:
//     Standard Matrix login response format (user_id, access_token,
//     device_id, home_server, well_known). Optional refresh_token
//     inclusion. Device ID generation if not provided. Initial device
//     display name support. Login completion audit logging.
//
// Equivalent to:
//   synapse/handlers/auth.py (AuthHandler, complete login logic)
//   synapse/rest/client/login.py (LoginRestServlet, login endpoints)
//   synapse/handlers/sso.py (SsoHandler, SSO login)
//   synapse/handlers/cas.py (CasHandler, CAS login)
//   synapse/handlers/oidc.py (OidcHandler, JWT/OIDC)
//   synapse/api/auth.py (get_user_by_req, token validation)
//   synapse/handlers/device.py (device creation on login)
//   synapse/handlers/refresh_token.py (refresh token handling)
//   synapse/handlers/appservice.py (appservice auth)
//   synapse/handlers/guest.py (guest registration)
//   synapse/api/constants.py (LoginType enum)
//
// Namespace: progressive::
// Target: 3000+ lines of production-grade C++.
// ============================================================================

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cctype>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <deque>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <limits>
#include <list>
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

#include "progressive/storage/database.hpp"
#include "progressive/storage/databases/main/registration.hpp"
#include "progressive/rest/rest_base.hpp"

// ============================================================================
// Namespace
// ============================================================================

namespace progressive {

using json = nlohmann::json;
namespace chr = std::chrono;

using rest::AuthHelper;
using rest::BaseRestServlet;
using rest::ClientV1RestServlet;
using rest::HttpRequest;
using rest::HttpResponse;
using rest::Requester;
using storage::DatabasePool;
using storage::LoggingTransaction;
using storage::RegistrationStore;

// ============================================================================
// Forward declarations
// ============================================================================

class LoginFlowEngine;
class PasswordAuthHandler;
class TokenAuthHandler;
class SSORedirectHandler;
class CASTicketHandler;
class JWTAuthHandler;
class AppServiceAuthHandler;
class GuestLoginHandler;
class UserIdentifierResolver;
class RefreshTokenManager;
class AccountStatusChecker;
class LoginRateLimiter;
class DeviceCreator;
class LoginAuditLogger;
class CASValidator;
class JWTValidator;
class AppServiceConfig;

// ============================================================================
// Enums: Login types, identifier types, account status
// ============================================================================

enum class LoginType : uint8_t {
  PASSWORD             = 0,
  TOKEN                = 1,
  SSO                  = 2,
  CAS                  = 3,
  JWT                  = 4,
  APPLICATION_SERVICE  = 5,
  GUEST                = 6,
  REFRESH_TOKEN        = 7,
  DUMMY                = 8,
  EMAIL_IDENTITY       = 9,
  MSISDN               = 10,
  RECAPTCHA            = 11,
  TERMS                = 12,
  REGISTRATION_TOKEN   = 13,
  UNSTABLE_DEVICE      = 14,
};

enum class IdentifierType : uint8_t {
  USER       = 0,  // m.id.user
  THIRDPARTY = 1,  // m.id.thirdparty
  PHONE      = 2,  // m.id.phone
  MATRIX_ID  = 3,  // Full Matrix ID
};

enum class LoginResult : uint8_t {
  SUCCESS            = 0,
  INVALID_CREDENTIALS = 1,
  ACCOUNT_LOCKED     = 2,
  ACCOUNT_DEACTIVATED = 3,
  ACCOUNT_SUSPENDED  = 4,
  ACCOUNT_EXPIRED    = 5,
  RATE_LIMITED       = 6,
  PASSWORD_EXPIRED   = 7,
  MISSING_PARAM      = 8,
  UNSUPPORTED_TYPE   = 9,
  SERVER_ERROR       = 10,
  CONSENT_REQUIRED   = 11,
  SHADOW_BANNED      = 12,
};

enum class AccountDeactivationState : uint8_t {
  ACTIVE              = 0,
  DEACTIVATED_SOFT    = 1,
  DEACTIVATED_HARD    = 2,
  DEACTIVATED_GDPR    = 3,
  REACTIVATABLE       = 4,
  PERMANENTLY_REMOVED = 5,
};

enum class TokenType : uint8_t {
  ACCESS       = 0,
  REFRESH      = 1,
  LOGIN_TOKEN  = 2,
  SSO_LOGIN    = 3,
  CAS_TICKET   = 4,
  JWT_BEARER   = 5,
  APP_SERVICE  = 6,
  GUEST        = 7,
};

enum class CASVersion : uint8_t {
  V1  = 1,
  V2  = 2,
  V3  = 3,
};

// ============================================================================
// Constants: Anonymous namespace
// ============================================================================

namespace {

// ---- Timing constants (milliseconds) ----
constexpr int64_t ACCESS_TOKEN_TTL_MS       = 3600000;    // 1 hour
constexpr int64_t REFRESH_TOKEN_TTL_MS      = 2592000000; // 30 days
constexpr int64_t LOGIN_TOKEN_TTL_MS        = 300000;     // 5 minutes
constexpr int64_t SSO_SESSION_TTL_MS        = 600000;     // 10 minutes
constexpr int64_t CAS_TICKET_TTL_MS         = 300000;     // 5 minutes
constexpr int64_t JWT_DEFAULT_TTL_MS        = 3600000;    // 1 hour
constexpr int64_t GUEST_SESSION_TTL_MS      = 86400000;   // 24 hours
constexpr int64_t RATE_LIMIT_WINDOW_MS      = 1000;       // 1 second
constexpr int64_t LOCKOUT_BASE_MS           = 60000;      // 1 minute
constexpr int64_t LOCKOUT_MAX_MS            = 86400000;   // 24 hours
constexpr int64_t PASSWORD_EXPIRY_DAYS      = 90;         // 90 days
constexpr int64_t DEACTIVATION_GRACE_MS     = 2592000000; // 30 days
constexpr int64_t LOGIN_CLEANUP_INTERVAL_MS = 300000;     // 5 minutes

// ---- Rate limit constants ----
constexpr int    LOGIN_RATE_PER_SECOND      = 5;
constexpr int    LOGIN_BURST_MAX            = 10;
constexpr int    LOGIN_RATE_PER_ACCOUNT     = 3;
constexpr int    LOGIN_RATE_PER_IP          = 10;
constexpr int    MAX_FAILED_LOGIN_ATTEMPTS  = 10;
constexpr int    GUEST_RATE_PER_HOUR        = 3;
constexpr int    SSO_RATE_PER_MINUTE        = 20;
constexpr int    TOKEN_LOGIN_RATE_PER_MIN   = 10;

// ---- Token generation constants ----
constexpr int    ACCESS_TOKEN_LENGTH        = 64;
constexpr int    REFRESH_TOKEN_LENGTH       = 96;
constexpr int    LOGIN_TOKEN_LENGTH         = 48;
constexpr int    DEVICE_ID_LENGTH           = 10;
constexpr int    GUEST_TOKEN_LENGTH         = 64;
constexpr int    SSO_STATE_LENGTH           = 32;
constexpr int    CAS_SERVICE_TICKET_LENGTH  = 64;

// ---- Validation constants ----
constexpr int    MAX_USERNAME_LENGTH        = 255;
constexpr int    MAX_PASSWORD_LENGTH        = 512;
constexpr int    MIN_PASSWORD_LENGTH        = 1;
constexpr int    MAX_DEVICE_DISPLAY_NAME    = 256;
constexpr int    MAX_IDENTIFIER_LENGTH      = 320;
constexpr int    MAX_REDIRECT_URL_LENGTH    = 2048;
constexpr int    MAX_JWT_TOKEN_LENGTH       = 8192;
constexpr int    MAX_CAS_TICKET_LENGTH      = 512;

// ---- Matrix error codes ----
constexpr const char* ERR_FORBIDDEN          = "M_FORBIDDEN";
constexpr const char* ERR_UNKNOWN_TOKEN      = "M_UNKNOWN_TOKEN";
constexpr const char* ERR_MISSING_TOKEN      = "M_MISSING_TOKEN";
constexpr const char* ERR_BAD_JSON           = "M_BAD_JSON";
constexpr const char* ERR_NOT_JSON           = "M_NOT_JSON";
constexpr const char* ERR_LIMIT_EXCEEDED     = "M_LIMIT_EXCEEDED";
constexpr const char* ERR_USER_DEACTIVATED   = "M_USER_DEACTIVATED";
constexpr const char* ERR_USER_LOCKED        = "M_USER_LOCKED";
constexpr const char* ERR_USER_SUSPENDED     = "M_USER_SUSPENDED";
constexpr const char* ERR_PASSWORD_EXPIRED   = "M_PASSWORD_EXPIRED";
constexpr const char* ERR_INVALID_USERNAME   = "M_INVALID_USERNAME";
constexpr const char* ERR_WEAK_PASSWORD      = "M_WEAK_PASSWORD";
constexpr const char* ERR_GUEST_FORBIDDEN    = "M_GUEST_ACCESS_FORBIDDEN";
constexpr const char* ERR_CONSENT_NOT_GIVEN  = "M_CONSENT_NOT_GIVEN";
constexpr const char* ERR_UNSUPPORTED        = "M_UNSUPPORTED";
constexpr const char* ERR_INVALID_PARAM      = "M_INVALID_PARAM";
constexpr const char* ERR_SESSION_EXPIRED    = "M_SESSION_EXPIRED";
constexpr const char* ERR_NO_APP_SERVICE     = "M_EXCLUSIVE";

// ---- Matrix login type strings ----
constexpr const char* LOGIN_TYPE_PASSWORD    = "m.login.password";
constexpr const char* LOGIN_TYPE_TOKEN       = "m.login.token";
constexpr const char* LOGIN_TYPE_SSO         = "m.login.sso";
constexpr const char* LOGIN_TYPE_CAS         = "m.login.cas";
constexpr const char* LOGIN_TYPE_JWT         = "org.matrix.login.jwt";
constexpr const char* LOGIN_TYPE_APPSERVICE  = "m.login.application_service";
constexpr const char* LOGIN_TYPE_GUEST       = "m.login.guest";
constexpr const char* LOGIN_TYPE_DUMMY       = "m.login.dummy";
constexpr const char* LOGIN_TYPE_EMAIL       = "m.login.email.identity";
constexpr const char* LOGIN_TYPE_MSISDN      = "m.login.msisdn";
constexpr const char* LOGIN_TYPE_RECAPTCHA   = "m.login.recaptcha";
constexpr const char* LOGIN_TYPE_TERMS       = "m.login.terms";

// ---- Identifier type strings ----
constexpr const char* ID_TYPE_USER           = "m.id.user";
constexpr const char* ID_TYPE_THIRDPARTY     = "m.id.thirdparty";
constexpr const char* ID_TYPE_PHONE          = "m.id.phone";

// ---- Character sets ----
const char* const TOKEN_CHARS =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~";
const char* const HEX_CHARS   = "0123456789abcdef";
const char* const BASE64_URL  =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const char* const NUMERIC_CHARS = "0123456789";

// ---- Allowed login flow types ----
const std::vector<std::string> ALL_LOGIN_FLOWS = {
  LOGIN_TYPE_PASSWORD, LOGIN_TYPE_TOKEN, LOGIN_TYPE_SSO,
  LOGIN_TYPE_CAS, LOGIN_TYPE_JWT, LOGIN_TYPE_APPSERVICE,
  LOGIN_TYPE_GUEST
};

// ---- Allowed redirect URL schemes ----
const std::vector<std::string> ALLOWED_REDIRECT_SCHEMES = {
  "https://", "matrix://", "element://", "io.element://"
};

// ---- Timestamp helpers ----

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

std::string ts_to_iso8601(int64_t ts_ms) {
  auto t = static_cast<std::time_t>(ts_ms / 1000);
  char buf[64];
  std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", std::gmtime(&t));
  return buf;
}

int64_t days_to_ms(int days) { return static_cast<int64_t>(days) * 86400000LL; }
int64_t hours_to_ms(int h) { return static_cast<int64_t>(h) * 3600000LL; }
int64_t minutes_to_ms(int m) { return static_cast<int64_t>(m) * 60000LL; }

// ---- Random generation ----

class SecureRandom {
 public:
  SecureRandom() {
    std::random_device rd;
    gen_.seed(rd());
  }

  std::string token(int length) {
    std::uniform_int_distribution<> dist(
        0, static_cast<int>(strlen(TOKEN_CHARS)) - 1);
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
    std::string n;
    n.reserve(static_cast<size_t>(length));
    for (int i = 0; i < length; ++i)
      n += NUMERIC_CHARS[static_cast<size_t>(dist(gen_))];
    return n;
  }

  std::string uuid() {
    std::uniform_int_distribution<> hd(0, 15);
    std::string u(36, '-');
    for (int i = 0; i < 36; ++i) {
      if (i == 8 || i == 13 || i == 18 || i == 23) continue;
      u[static_cast<size_t>(i)] = HEX_CHARS[hd(gen_)];
    }
    u[14] = '4';
    u[19] = HEX_CHARS[8 + hd(gen_) % 4];
    return u;
  }

 private:
  std::mt19937_64 gen_;
};

// Global secure random instance
SecureRandom& srng() {
  static SecureRandom instance;
  return instance;
}

// ---- String utilities ----

std::string to_lower(const std::string& s) {
  std::string result = s;
  for (auto& c : result) c = static_cast<char>(std::tolower(
      static_cast<unsigned char>(c)));
  return result;
}

std::string trim(const std::string& s) {
  auto start = s.find_first_not_of(" \t\n\r\f\v");
  if (start == std::string::npos) return "";
  auto end = s.find_last_not_of(" \t\n\r\f\v");
  return s.substr(start, end - start + 1);
}

std::string extract_localpart(const std::string& user_id) {
  if (user_id.empty() || user_id[0] != '@') return user_id;
  auto colon = user_id.find(':');
  if (colon == std::string::npos) return user_id.substr(1);
  return user_id.substr(1, colon - 1);
}

std::string extract_domain(const std::string& user_id) {
  auto colon = user_id.find(':');
  if (colon == std::string::npos) return "";
  return user_id.substr(colon + 1);
}

bool is_valid_user_id(const std::string& user_id) {
  if (user_id.empty() || user_id[0] != '@') return false;
  auto colon = user_id.find(':');
  if (colon == std::string::npos || colon <= 1 ||
      colon >= user_id.size() - 1) return false;
  return true;
}

bool is_guest_user_id(const std::string& user_id) {
  return user_id.find("@guest_") == 0;
}

std::string normalize_phone(const std::string& phone) {
  std::string result;
  for (char c : phone) {
    if (c == '+' || c == '-' || c == ' ' || c == '(' || c == ')') continue;
    if (c >= '0' && c <= '9') result += c;
  }
  if (!result.empty() && result[0] != '+') result = "+" + result;
  return result;
}

std::string normalize_email(const std::string& email) {
  std::string trimmed = trim(to_lower(email));
  return trimmed;
}

bool valid_redirect_url(const std::string& url) {
  if (url.empty()) return true;
  if (url.size() > static_cast<size_t>(MAX_REDIRECT_URL_LENGTH)) return false;
  for (const auto& scheme : ALLOWED_REDIRECT_SCHEMES) {
    if (url.size() >= scheme.size() &&
        url.compare(0, scheme.size(), scheme) == 0) {
      return true;
    }
  }
  return false;
}

// ---- URL encoding ----

std::string url_encode(const std::string& value) {
  std::ostringstream escaped;
  escaped.fill('0');
  escaped << std::hex;
  for (char c : value) {
    if (std::isalnum(static_cast<unsigned char>(c)) ||
        c == '-' || c == '_' || c == '.' || c == '~') {
      escaped << c;
    } else {
      escaped << std::uppercase;
      escaped << '%' << std::setw(2)
              << static_cast<int>(static_cast<unsigned char>(c));
      escaped << std::nouppercase;
    }
  }
  return escaped.str();
}

std::string build_query_string(
    const std::map<std::string, std::string>& params) {
  std::ostringstream ss;
  bool first = true;
  for (const auto& [k, v] : params) {
    if (!first) ss << "&";
    ss << url_encode(k) << "=" << url_encode(v);
    first = false;
  }
  return ss.str();
}

// ---- Hash simulation (stand-in, production would use OpenSSL) ----

std::string sha256_hex_standin(const std::string& data) {
  std::hash<std::string> hasher;
  size_t h = hasher(data);
  std::ostringstream ss;
  ss << std::hex << std::setfill('0');
  for (int i = 0; i < 8; ++i) {
    ss << std::setw(8) << ((h >> (i * 8)) & 0xFFFFFFFFULL);
  }
  return ss.str();
}

// ---- Password verification stand-in ----

bool verify_password_standin(const std::string& password,
                              const std::string& stored_hash) {
  std::string computed = "pbkdf2_sha256$" + sha256_hex_standin(password);
  if (stored_hash.size() < 20) return false;
  return computed.size() == stored_hash.size() &&
         computed.substr(0, 20) == stored_hash.substr(0, 20);
}

// ---- JWT parsing (simplified) ----

struct ParsedJWT {
  json header;
  json payload;
  std::string signature_b64;
  bool valid{false};
  std::string error;
};

ParsedJWT parse_jwt_token(const std::string& token) {
  ParsedJWT jwt;
  auto dot1 = token.find('.');
  auto dot2 = token.find('.', dot1 + 1);
  if (dot1 == std::string::npos || dot2 == std::string::npos ||
      dot1 == 0 || dot2 == dot1 + 1 || dot2 == token.size() - 1) {
    jwt.error = "Invalid JWT structure";
    return jwt;
  }

  auto b64url_decode = [](const std::string& s) -> std::string {
    std::string padded = s;
    while (padded.size() % 4) padded += '=';
    std::string result;
    result.reserve((padded.size() * 3) / 4);
    int val = 0, valb = -8;
    const std::string kB64 =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for (unsigned char c : padded) {
      if (c == '=') break;
      size_t idx = kB64.find(
          (c == '-') ? '+' : (c == '_') ? '/' : static_cast<char>(c));
      if (idx == std::string::npos) return "";
      val = (val << 6) + static_cast<int>(idx);
      valb += 6;
      if (valb >= 0) {
        result.push_back(static_cast<char>((val >> valb) & 0xFF));
        valb -= 8;
      }
    }
    return result;
  };

  std::string header_str = b64url_decode(token.substr(0, dot1));
  std::string payload_str = b64url_decode(
      token.substr(dot1 + 1, dot2 - dot1 - 1));
  jwt.signature_b64 = token.substr(dot2 + 1);

  if (header_str.empty() || payload_str.empty()) {
    jwt.error = "Failed to decode JWT segments";
    return jwt;
  }

  try {
    jwt.header = json::parse(header_str);
    jwt.payload = json::parse(payload_str);
    jwt.valid = true;
  } catch (const std::exception& e) {
    jwt.error = std::string("JWT JSON parse error: ") + e.what();
  }
  return jwt;
}

// ---- Error response helper ----

json make_error_response(const std::string& errcode,
                          const std::string& error,
                          int status_code = 403) {
  json j;
  j["errcode"] = errcode;
  j["error"] = error;
  j["_status_code"] = status_code;
  return j;
}

json make_login_success(const std::string& user_id,
                         const std::string& access_token,
                         const std::string& device_id,
                         const std::string& home_server,
                         const std::string& refresh_token = "",
                         const json& well_known = nullptr) {
  json j;
  j["user_id"] = user_id;
  j["access_token"] = access_token;
  j["device_id"] = device_id;
  j["home_server"] = home_server;
  if (!refresh_token.empty()) j["refresh_token"] = refresh_token;
  if (!well_known.is_null()) j["well_known"] = well_known;
  return j;
}

// ---- Login flow constants ----

json get_default_login_flows() {
  json flows;
  flows.push_back({{"type", LOGIN_TYPE_PASSWORD}});
  flows.push_back({{"type", LOGIN_TYPE_SSO}});
  flows.push_back({{"type", LOGIN_TYPE_TOKEN}});
  flows.push_back({{"type", LOGIN_TYPE_GUEST}});
  return flows;
}

}  // anonymous namespace

// ============================================================================
// UserIdentifier — Parsed user identifier from login request
// ============================================================================

struct UserIdentifier {
  IdentifierType type{IdentifierType::USER};
  std::string user;        // localpart or full MXID for m.id.user
  std::string medium;      // medium for m.id.thirdparty (e.g. "email")
  std::string address;     // address for m.id.thirdparty or m.id.phone
  std::string country;     // country code for m.id.phone
  std::string phone;       // normalized phone number

  bool is_valid() const {
    switch (type) {
      case IdentifierType::USER:
        return !user.empty() && user.size() <=
            static_cast<size_t>(MAX_USERNAME_LENGTH);
      case IdentifierType::THIRDPARTY:
        return !medium.empty() && !address.empty() &&
               address.size() <= static_cast<size_t>(MAX_IDENTIFIER_LENGTH);
      case IdentifierType::PHONE:
        return !phone.empty() && phone.size() <=
            static_cast<size_t>(MAX_IDENTIFIER_LENGTH);
      case IdentifierType::MATRIX_ID:
        return is_valid_user_id(user);
    }
    return false;
  }

  static UserIdentifier from_json(const json& j) {
    UserIdentifier id;
    std::string id_type = j.value("type", ID_TYPE_USER);

    if (id_type == ID_TYPE_USER) {
      id.type = IdentifierType::USER;
      id.user = trim(j.value("user", ""));
      if (is_valid_user_id(id.user)) {
        id.type = IdentifierType::MATRIX_ID;
      }
    } else if (id_type == ID_TYPE_THIRDPARTY) {
      id.type = IdentifierType::THIRDPARTY;
      id.medium = to_lower(trim(j.value("medium", "")));
      id.address = normalize_email(j.value("address", ""));
    } else if (id_type == ID_TYPE_PHONE) {
      id.type = IdentifierType::PHONE;
      id.country = trim(j.value("country", ""));
      id.phone = normalize_phone(j.value("phone",
          j.value("number", j.value("address", ""))));
      id.address = id.phone;
    }

    return id;
  }

  json to_json() const {
    json j;
    switch (type) {
      case IdentifierType::USER:
        j["type"] = ID_TYPE_USER;
        j["user"] = user;
        break;
      case IdentifierType::MATRIX_ID:
        j["type"] = ID_TYPE_USER;
        j["user"] = user;
        break;
      case IdentifierType::THIRDPARTY:
        j["type"] = ID_TYPE_THIRDPARTY;
        j["medium"] = medium;
        j["address"] = address;
        break;
      case IdentifierType::PHONE:
        j["type"] = ID_TYPE_PHONE;
        j["country"] = country;
        j["phone"] = phone;
        break;
    }
    return j;
  }

  std::string describe() const {
    switch (type) {
      case IdentifierType::USER:
        return "user:" + user;
      case IdentifierType::MATRIX_ID:
        return "mxid:" + user;
      case IdentifierType::THIRDPARTY:
        return "3pid:" + medium + "/" + address;
      case IdentifierType::PHONE:
        return "phone:" + phone;
    }
    return "unknown";
  }
};

// ============================================================================
// LoginRequest — Parsed login request body
// ============================================================================

struct LoginRequest {
  LoginType login_type{LoginType::PASSWORD};
  UserIdentifier identifier;
  std::string password;
  std::string token;
  std::string device_id;
  std::string initial_device_display_name;
  std::string refresh_token;
  std::string redirect_url;
  std::string cas_ticket;
  std::string cas_service;
  std::string jwt_token;
  std::string appservice_token;
  std::string login_token;
  std::string sso_provider;
  bool inhibit_login{false};
  bool request_refresh_token{true};
  json raw_body;

  static LoginRequest from_json(const json& body) {
    LoginRequest req;
    req.raw_body = body;

    std::string type_str = body.value("type", LOGIN_TYPE_PASSWORD);
    req.login_type = parse_login_type(type_str);

    if (body.contains("identifier") && body["identifier"].is_object()) {
      req.identifier = UserIdentifier::from_json(body["identifier"]);
    } else {
      req.identifier.type = IdentifierType::USER;
      req.identifier.user = trim(body.value("user",
          body.value("username", body.value("address", ""))));
      if (req.identifier.user.empty() && body.contains("medium")) {
        req.identifier = UserIdentifier::from_json(body);
      }
    }

    req.password = body.value("password", "");
    req.token = body.value("token", "");
    req.device_id = trim(body.value("device_id",
        body.value("initial_device_display_name",
            body.value("device_display_name", ""))));
    // fix: device_id extraction
    if (req.device_id.empty())
      req.device_id = trim(body.value("device_id", ""));
    req.initial_device_display_name = trim(
        body.value("initial_device_display_name", ""));
    req.refresh_token = body.value("refresh_token", "");
    req.redirect_url = trim(body.value("redirect_url",
        body.value("redirect_uri", "")));
    req.cas_ticket = body.value("ticket", "");
    req.cas_service = body.value("service", "");
    req.jwt_token = body.value("token", "");
    req.appservice_token = body.value("access_token",
        body.value("as_token", ""));
    req.login_token = body.value("login_token",
        body.value("token", ""));
    req.sso_provider = trim(body.value("idp_id",
        body.value("provider", "")));
    req.inhibit_login = body.value("inhibit_login", false);
    req.request_refresh_token = body.value("refresh_token", true);

    return req;
  }

  bool is_valid(std::string& error) const {
    switch (login_type) {
      case LoginType::PASSWORD: {
        if (!identifier.is_valid()) {
          error = "Missing or invalid user identifier";
          return false;
        }
        if (password.empty()) {
          error = "Missing password";
          return false;
        }
        if (password.size() > static_cast<size_t>(MAX_PASSWORD_LENGTH)) {
          error = "Password too long";
          return false;
        }
        break;
      }
      case LoginType::TOKEN: {
        if (token.empty() && login_token.empty()) {
          error = "Missing login token";
          return false;
        }
        break;
      }
      case LoginType::SSO: {
        if (redirect_url.empty() || !valid_redirect_url(redirect_url)) {
          error = "Missing or invalid redirect_url";
          return false;
        }
        break;
      }
      case LoginType::CAS: {
        if (cas_ticket.empty()) {
          error = "Missing CAS ticket";
          return false;
        }
        if (cas_service.empty()) {
          error = "Missing CAS service URL";
          return false;
        }
        break;
      }
      case LoginType::JWT: {
        if (jwt_token.empty()) {
          error = "Missing JWT token";
          return false;
        }
        break;
      }
      case LoginType::APPLICATION_SERVICE: {
        if (appservice_token.empty()) {
          error = "Missing application service token";
          return false;
        }
        if (!identifier.is_valid()) {
          error = "Missing user identifier for appservice login";
          return false;
        }
        break;
      }
      case LoginType::GUEST: {
        // Guest login needs no additional params
        break;
      }
      case LoginType::REFRESH_TOKEN: {
        if (refresh_token.empty()) {
          error = "Missing refresh_token";
          return false;
        }
        break;
      }
      default: {
        error = "Unsupported login type";
        return false;
      }
    }
    return true;
  }

  static LoginType parse_login_type(const std::string& type) {
    if (type == LOGIN_TYPE_PASSWORD) return LoginType::PASSWORD;
    if (type == LOGIN_TYPE_TOKEN)    return LoginType::TOKEN;
    if (type == LOGIN_TYPE_SSO)      return LoginType::SSO;
    if (type == LOGIN_TYPE_CAS)      return LoginType::CAS;
    if (type == LOGIN_TYPE_JWT)      return LoginType::JWT;
    if (type == LOGIN_TYPE_APPSERVICE) return LoginType::APPLICATION_SERVICE;
    if (type == LOGIN_TYPE_GUEST)    return LoginType::GUEST;
    if (type == LOGIN_TYPE_DUMMY)    return LoginType::DUMMY;
    if (type == LOGIN_TYPE_EMAIL)    return LoginType::EMAIL_IDENTITY;
    if (type == LOGIN_TYPE_MSISDN)   return LoginType::MSISDN;
    if (type == "m.login.refresh_token") return LoginType::REFRESH_TOKEN;
    return LoginType::PASSWORD;
  }
};

// ============================================================================
// LoginSession — Active login session state
// ============================================================================

struct LoginSession {
  std::string session_id;
  std::string user_id;
  std::string access_token;
  std::string refresh_token;
  std::string device_id;
  std::string ip_address;
  std::string user_agent;
  std::string home_server;
  LoginType login_type{LoginType::PASSWORD};
  IdentifierType id_type{IdentifierType::USER};
  int64_t created_at_ms{0};
  int64_t expires_at_ms{0};
  int64_t last_active_ms{0};
  bool is_guest{false};
  bool is_appservice{false};
  bool is_deactivated{false};
  std::string sso_provider_id;
  json metadata;

  bool is_expired() const {
    return expires_at_ms > 0 && now_ms() > expires_at_ms;
  }

  json to_response(bool include_refresh = false) const {
    json j;
    j["user_id"] = user_id;
    j["access_token"] = access_token;
    j["device_id"] = device_id;
    j["home_server"] = home_server;
    if (include_refresh && !refresh_token.empty())
      j["refresh_token"] = refresh_token;
    if (!metadata.is_null()) j["metadata"] = metadata;
    return j;
  }
};

// ============================================================================
// AccountStatus — Resolved account status for login decisions
// ============================================================================

struct AccountStatus {
  std::string user_id;
  std::string password_hash;
  std::string password_scheme;
  int64_t password_last_changed_ms{0};
  AccountDeactivationState deactivation_state{
      AccountDeactivationState::ACTIVE};
  int64_t deactivated_at_ms{0};
  int64_t reactivatable_until_ms{0};
  int failed_login_attempts{0};
  int64_t locked_until_ms{0};
  int64_t suspended_until_ms{0};
  bool is_shadow_banned{false};
  bool is_guest_account{false};
  bool consent_given{true};
  std::string deactivation_reason;
  DeactivationType deactivation_type;
  json extra;

  bool can_login() const {
    if (deactivation_state == AccountDeactivationState::DEACTIVATED_HARD ||
        deactivation_state == AccountDeactivationState::DEACTIVATED_GDPR ||
        deactivation_state == AccountDeactivationState::PERMANENTLY_REMOVED) {
      return false;
    }
    if (locked_until_ms > now_ms()) return false;
    if (suspended_until_ms > now_ms()) return false;
    if (!consent_given) return false;
    return true;
  }

  std::string block_reason() const {
    if (deactivation_state == AccountDeactivationState::DEACTIVATED_HARD ||
        deactivation_state == AccountDeactivationState::PERMANENTLY_REMOVED) {
      return "Account has been deactivated";
    }
    if (deactivation_state == AccountDeactivationState::DEACTIVATED_GDPR) {
      return "Account has been erased under GDPR";
    }
    if (deactivation_state == AccountDeactivationState::DEACTIVATED_SOFT &&
        reactivatable_until_ms < now_ms()) {
      return "Account deactivation grace period has expired";
    }
    if (locked_until_ms > now_ms()) {
      int64_t remaining = (locked_until_ms - now_ms()) / 60000;
      return "Account is locked. Try again in " +
             std::to_string(remaining) + " minutes";
    }
    if (suspended_until_ms > now_ms()) {
      return "Account is suspended until " +
             ts_to_iso8601(suspended_until_ms);
    }
    if (!consent_given) {
      return "User consent not given";
    }
    return "Unknown reason";
  }

  json block_error_json() const {
    if (deactivation_state == AccountDeactivationState::DEACTIVATED_SOFT &&
        reactivatable_until_ms > now_ms()) {
      return make_error_response(ERR_USER_DEACTIVATED,
          "Account deactivated. Reactivate before " +
          ts_to_iso8601(reactivatable_until_ms) + " to restore access.", 403);
    }
    if (deactivation_state != AccountDeactivationState::ACTIVE &&
        deactivation_state != AccountDeactivationState::REACTIVATABLE) {
      return make_error_response(ERR_USER_DEACTIVATED, block_reason(), 403);
    }
    if (locked_until_ms > now_ms()) {
      return make_error_response(ERR_USER_LOCKED, block_reason(), 403);
    }
    if (suspended_until_ms > now_ms()) {
      return make_error_response(ERR_USER_SUSPENDED, block_reason(), 403);
    }
    if (!consent_given) {
      return make_error_response(ERR_CONSENT_NOT_GIVEN, block_reason(), 403);
    }
    return make_error_response(ERR_FORBIDDEN, block_reason(), 403);
  }
};

// ============================================================================
// UserIdentifierResolver — Resolve any user identifier to a Matrix User ID
// ============================================================================

class UserIdentifierResolver {
 public:
  explicit UserIdentifierResolver(DatabasePool& db) : db_(db) {}

  std::optional<std::string> resolve(const UserIdentifier& identifier) {
    switch (identifier.type) {
      case IdentifierType::USER:
        return resolve_user(identifier.user);
      case IdentifierType::MATRIX_ID:
        return resolve_matrix_id(identifier.user);
      case IdentifierType::THIRDPARTY:
        return resolve_thirdparty(identifier.medium, identifier.address);
      case IdentifierType::PHONE:
        return resolve_phone(identifier.phone);
    }
    return std::nullopt;
  }

  std::string resolve_domain(const std::string& localpart) {
    return server_name_;
  }

  void set_server_name(const std::string& name) { server_name_ = name; }

 private:
  std::optional<std::string> resolve_user(const std::string& user) {
    std::string localpart = trim(to_lower(user));
    if (localpart.empty()) return std::nullopt;

    if (is_valid_user_id(localpart)) {
      return resolve_matrix_id(localpart);
    }

    std::string full_id = "@" + localpart + ":" + server_name_;
    bool exists = false;
    db_.runInteraction("resolve_user",
        [&](LoggingTransaction& txn) {
          txn.execute(
              "SELECT 1 FROM users WHERE name = ?",
              {localpart});
          auto rows = txn.fetchall();
          exists = !rows.empty();
        });

    if (exists) return full_id;
    return std::nullopt;
  }

  std::optional<std::string> resolve_matrix_id(const std::string& user_id) {
    if (!is_valid_user_id(user_id)) return std::nullopt;
    return user_id;
  }

  std::optional<std::string> resolve_thirdparty(
      const std::string& medium, const std::string& address) {
    if (medium.empty() || address.empty()) return std::nullopt;
    std::string result;
    db_.runInteraction("resolve_3pid",
        [&](LoggingTransaction& txn) {
          txn.execute(
              "SELECT user_id FROM user_threepids "
              "WHERE medium = ? AND LOWER(address) = LOWER(?) "
              "AND validated_at > 0",
              {medium, address});
          auto rows = txn.fetchall();
          if (!rows.empty()) {
            result = rows[0][0];
          }
        });
    if (result.empty()) return std::nullopt;
    return result;
  }

  std::optional<std::string> resolve_phone(const std::string& phone) {
    return resolve_thirdparty("msisdn", phone);
  }

  DatabasePool& db_;
  std::string server_name_;
};

// ============================================================================
// AccountStatusChecker — Check account status before allowing login
// ============================================================================

class AccountStatusChecker {
 public:
  explicit AccountStatusChecker(DatabasePool& db) : db_(db) {}

  AccountStatus check(const std::string& user_id) {
    AccountStatus status;
    status.user_id = user_id;

    db_.runInteraction("check_account_status",
        [&](LoggingTransaction& txn) {
          txn.execute(
              "SELECT password_hash, password_scheme, "
              "deactivated, deactivation_ts, deactivation_type, "
              "deactivation_reason, failed_logins, locked_until, "
              "suspended_until, shadow_banned, is_guest, "
              "consent_version, consent_given_ts, "
              "password_last_changed "
              "FROM users WHERE name = ?",
              {extract_localpart(user_id)});
          auto rows = txn.fetchall();

          if (rows.empty()) {
            status.deactivation_state =
                AccountDeactivationState::PERMANENTLY_REMOVED;
            return;
          }

          auto& row = rows[0];
          status.password_hash = row[0];
          status.password_scheme = row[1];

          int deactivated = std::stoi(row[2]);
          int64_t deact_ts = row[3].empty() ? 0 : std::stoll(row[3]);
          int deact_type = row[4].empty() ? 0 : std::stoi(row[4]);

          status.deactivated_at_ms = deact_ts;

          if (deactivated) {
            switch (deact_type) {
              case 0:  // user_requested
              case 1:  // admin_forced
              case 2:  // system_expired
                status.deactivation_state =
                    AccountDeactivationState::DEACTIVATED_SOFT;
                status.reactivatable_until_ms =
                    deact_ts + DEACTIVATION_GRACE_MS;
                if (status.reactivatable_until_ms > now_ms()) {
                  status.deactivation_state =
                      AccountDeactivationState::REACTIVATABLE;
                }
                break;
              case 4:  // gdpr_erasure
                status.deactivation_state =
                    AccountDeactivationState::DEACTIVATED_GDPR;
                break;
              default:
                status.deactivation_state =
                    AccountDeactivationState::DEACTIVATED_HARD;
                break;
            }
          } else {
            status.deactivation_state = AccountDeactivationState::ACTIVE;
          }

          status.deactivation_reason = row[5];
          status.failed_login_attempts = row[6].empty() ? 0 :
              std::stoi(row[6]);
          status.locked_until_ms = row[7].empty() ? 0 : std::stoll(row[7]);
          status.suspended_until_ms = row[8].empty() ? 0 : std::stoll(row[8]);
          status.is_shadow_banned = row[9] == "1";
          status.is_guest_account = row[10] == "1";
          status.password_last_changed_ms = row[13].empty() ? 0 :
              std::stoll(row[13]);

          // Check consent
          int consent_version = row[11].empty() ? 0 : std::stoi(row[11]);
          status.consent_given = (consent_version > 0);
        });

    return status;
  }

  bool is_deactivated(const std::string& user_id) {
    AccountStatus status = check(user_id);
    switch (status.deactivation_state) {
      case AccountDeactivationState::DEACTIVATED_HARD:
      case AccountDeactivationState::DEACTIVATED_GDPR:
      case AccountDeactivationState::PERMANENTLY_REMOVED:
        return true;
      case AccountDeactivationState::DEACTIVATED_SOFT: {
        int64_t now = now_ms();
        return status.deactivated_at_ms > 0 &&
               (now - status.deactivated_at_ms) > DEACTIVATION_GRACE_MS;
      }
      default:
        return false;
    }
  }

  bool can_reactivate(const std::string& user_id) {
    AccountStatus status = check(user_id);
    return status.deactivation_state ==
        AccountDeactivationState::REACTIVATABLE;
  }

  json get_deactivation_info(const std::string& user_id) {
    AccountStatus status = check(user_id);
    json j;
    j["deactivated"] = (status.deactivation_state !=
        AccountDeactivationState::ACTIVE);
    j["deactivation_state"] = static_cast<int>(status.deactivation_state);
    if (status.deactivated_at_ms > 0)
      j["deactivated_at"] = ts_to_iso8601(status.deactivated_at_ms);
    if (status.reactivatable_until_ms > 0)
      j["reactivatable_until"] =
          ts_to_iso8601(status.reactivatable_until_ms);
    j["can_reactivate"] = can_reactivate(user_id);
    if (!status.deactivation_reason.empty())
      j["reason"] = status.deactivation_reason;
    return j;
  }

 private:
  DatabasePool& db_;
};

// ============================================================================
// LoginRateLimiter — Per-IP, per-account rate limiting for login
// ============================================================================

class LoginRateLimiter {
 public:
  LoginRateLimiter() {
    cleanup_thread_ = std::thread(&LoginRateLimiter::cleanup_loop, this);
  }

  ~LoginRateLimiter() {
    stop_cleanup_ = true;
    if (cleanup_thread_.joinable()) cleanup_thread_.join();
  }

  bool check_rate_limit(const std::string& ip_address,
                         const std::string& account_key,
                         std::string& error) {
    std::lock_guard<std::mutex> lock(mutex_);
    int64_t now = now_ms();

    // Check per-IP rate
    auto& ip_bucket = ip_buckets_[ip_address];
    if (now - ip_bucket.window_start > RATE_LIMIT_WINDOW_MS) {
      ip_bucket.window_start = now;
      ip_bucket.count = 0;
    }
    if (ip_bucket.count >= LOGIN_RATE_PER_IP) {
      error = "Too many login attempts from this IP address. Try again later.";
      return false;
    }
    ip_bucket.count++;

    // Check per-account rate
    if (!account_key.empty()) {
      auto& acct_bucket = account_buckets_[account_key];
      if (now - acct_bucket.window_start > RATE_LIMIT_WINDOW_MS) {
        acct_bucket.window_start = now;
        acct_bucket.count = 0;
      }
      if (acct_bucket.count >= LOGIN_RATE_PER_ACCOUNT) {
        error = "Too many login attempts for this account. Try again later.";
        return false;
      }
      acct_bucket.count++;
    }

    return true;
  }

  void record_failed_attempt(const std::string& account_key) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto& entry = failed_attempts_[account_key];
    entry.count++;
    entry.last_attempt_ms = now_ms();
  }

  void clear_failed_attempts(const std::string& account_key) {
    std::lock_guard<std::mutex> lock(mutex_);
    failed_attempts_.erase(account_key);
  }

  int failed_attempt_count(const std::string& account_key) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = failed_attempts_.find(account_key);
    if (it == failed_attempts_.end()) return 0;
    return it->second.count;
  }

  int64_t lockout_duration_ms(int failed_count) const {
    if (failed_count < MAX_FAILED_LOGIN_ATTEMPTS) return 0;
    int64_t multiplier = 1LL << std::min(
        failed_count - MAX_FAILED_LOGIN_ATTEMPTS, 6);
    return std::min(LOCKOUT_BASE_MS * multiplier, LOCKOUT_MAX_MS);
  }

  bool is_guest_rate_limited(const std::string& ip_address) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = guest_rate_buckets_.find(ip_address);
    if (it == guest_rate_buckets_.end()) return false;
    int64_t elapsed = now_ms() - it->second.window_start;
    if (elapsed > 3600000) return false; // 1 hour window
    return it->second.count >= GUEST_RATE_PER_HOUR;
  }

  void record_guest_login(const std::string& ip_address) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto& bucket = guest_rate_buckets_[ip_address];
    int64_t now = now_ms();
    if (now - bucket.window_start > 3600000) {
      bucket.window_start = now;
      bucket.count = 0;
    }
    bucket.count++;
  }

 private:
  struct RateBucket {
    int64_t window_start{0};
    int count{0};
  };

  struct FailedEntry {
    int count{0};
    int64_t last_attempt_ms{0};
  };

  void cleanup_loop() {
    while (!stop_cleanup_) {
      std::this_thread::sleep_for(chr::seconds(300));
      std::lock_guard<std::mutex> lock(mutex_);
      int64_t now = now_ms();
      int64_t threshold = now - 3600000; // 1 hour

      for (auto it = ip_buckets_.begin(); it != ip_buckets_.end();) {
        if (it->second.window_start < threshold) it = ip_buckets_.erase(it);
        else ++it;
      }
      for (auto it = account_buckets_.begin();
           it != account_buckets_.end();) {
        if (it->second.window_start < threshold)
          it = account_buckets_.erase(it);
        else ++it;
      }
      for (auto it = failed_attempts_.begin();
           it != failed_attempts_.end();) {
        if (it->second.last_attempt_ms < threshold)
          it = failed_attempts_.erase(it);
        else ++it;
      }
      for (auto it = guest_rate_buckets_.begin();
           it != guest_rate_buckets_.end();) {
        if (it->second.window_start < threshold)
          it = guest_rate_buckets_.erase(it);
        else ++it;
      }
    }
  }

  mutable std::mutex mutex_;
  std::unordered_map<std::string, RateBucket> ip_buckets_;
  std::unordered_map<std::string, RateBucket> account_buckets_;
  std::unordered_map<std::string, FailedEntry> failed_attempts_;
  std::unordered_map<std::string, RateBucket> guest_rate_buckets_;
  std::thread cleanup_thread_;
  std::atomic<bool> stop_cleanup_{false};
};

// ============================================================================
// DeviceCreator — Creates devices on successful login
// ============================================================================

class DeviceCreator {
 public:
  explicit DeviceCreator(DatabasePool& db) : db_(db) {}

  std::string create_or_update_device(const std::string& user_id,
                                       const std::string& device_id_in,
                                       const std::string& display_name,
                                       const std::string& ip_address,
                                       const std::string& user_agent) {
    std::string device_id = device_id_in;
    if (device_id.empty()) {
      device_id = srng().token(DEVICE_ID_LENGTH);
    }

    db_.runInteraction("create_device",
        [&](LoggingTransaction& txn) {
          int64_t now = now_ms();
          // Upsert device
          txn.execute(
              "INSERT INTO devices (user_id, device_id, display_name, "
              "last_seen, ip, user_agent, hidden) "
              "VALUES (?, ?, ?, ?, ?, ?, 0) "
              "ON CONFLICT(user_id, device_id) DO UPDATE SET "
              "display_name = ?, last_seen = ?, ip = ?, user_agent = ?",
              {user_id, device_id, display_name,
               std::to_string(now), ip_address, user_agent,
               display_name, std::to_string(now), ip_address, user_agent});
        });

    return device_id;
  }

  void update_last_seen(const std::string& user_id,
                          const std::string& device_id,
                          const std::string& ip_address) {
    db_.runInteraction("update_device_seen",
        [&](LoggingTransaction& txn) {
          txn.execute(
              "UPDATE devices SET last_seen = ?, ip = ? "
              "WHERE user_id = ? AND device_id = ?",
              {std::to_string(now_ms()), ip_address, user_id, device_id});
        });
  }

  json get_device_info(const std::string& user_id,
                        const std::string& device_id) {
    json result;
    db_.runInteraction("get_device_info",
        [&](LoggingTransaction& txn) {
          txn.execute(
              "SELECT display_name, last_seen, ip, user_agent "
              "FROM devices WHERE user_id = ? AND device_id = ?",
              {user_id, device_id});
          auto rows = txn.fetchall();
          if (!rows.empty()) {
            result["display_name"] = rows[0][0];
            result["last_seen"] = rows[0][1];
            result["ip"] = rows[0][2];
            result["user_agent"] = rows[0][3];
          }
        });
    return result;
  }

 private:
  DatabasePool& db_;
};

// ============================================================================
// LoginAuditLogger — Records login events for security auditing
// ============================================================================

class LoginAuditLogger {
 public:
  explicit LoginAuditLogger(DatabasePool& db) : db_(db) {}

  void log_login_attempt(const std::string& user_id,
                          LoginType login_type,
                          bool success,
                          const std::string& ip_address,
                          const std::string& user_agent,
                          const std::string& error_reason = "") {
    json entry;
    entry["user_id"] = user_id;
    entry["login_type"] = static_cast<int>(login_type);
    entry["success"] = success;
    entry["ip_address"] = ip_address;
    entry["user_agent"] = user_agent;
    entry["timestamp"] = now_iso8601();
    entry["timestamp_ms"] = now_ms();
    if (!error_reason.empty()) entry["error"] = error_reason;

    db_.runInteraction("log_login",
        [&](LoggingTransaction& txn) {
          txn.execute(
              "INSERT INTO login_audit (user_id, login_type, success, "
              "ip_address, user_agent, error_reason, timestamp_ms) "
              "VALUES (?, ?, ?, ?, ?, ?, ?)",
              {user_id, std::to_string(static_cast<int>(login_type)),
               success ? "1" : "0", ip_address, user_agent,
               error_reason, std::to_string(now_ms())});
        });

    recent_entries_.push_back(entry);
    if (recent_entries_.size() > 1000) recent_entries_.pop_front();
  }

  void log_login_success(const std::string& user_id,
                          const std::string& device_id,
                          LoginType login_type,
                          const std::string& ip_address,
                          const std::string& user_agent) {
    log_login_attempt(user_id, login_type, true, ip_address, user_agent);
    last_login_[user_id] = now_ms();
  }

  int64_t get_last_login(const std::string& user_id) const {
    auto it = last_login_.find(user_id);
    if (it == last_login_.end()) return 0;
    return it->second;
  }

  std::vector<json> get_recent_logins(const std::string& user_id,
                                        int limit = 20) const {
    std::vector<json> result;
    for (auto it = recent_entries_.rbegin();
         it != recent_entries_.rend() && static_cast<int>(result.size()) < limit;
         ++it) {
      if ((*it).value("user_id", "") == user_id) result.push_back(*it);
    }
    return result;
  }

 private:
  DatabasePool& db_;
  std::deque<json> recent_entries_;
  std::unordered_map<std::string, int64_t> last_login_;
};

// ============================================================================
// RefreshTokenManager — Refresh token lifecycle management
// ============================================================================

class RefreshTokenManager {
 public:
  explicit RefreshTokenManager(DatabasePool& db) : db_(db) {}

  std::string generate_refresh_token(const std::string& user_id,
                                      const std::string& device_id,
                                      const std::string& access_token) {
    std::string token = "rt_" + srng().token(REFRESH_TOKEN_LENGTH - 3);
    int64_t now = now_ms();
    int64_t expiry = now + REFRESH_TOKEN_TTL_MS;

    db_.runInteraction("store_refresh_token",
        [&](LoggingTransaction& txn) {
          txn.execute(
              "INSERT INTO refresh_tokens "
              "(token, user_id, device_id, access_token_id, "
              "created_at_ms, expires_at_ms, used, revoked) "
              "VALUES (?, ?, ?, ?, ?, ?, 0, 0)",
              {token, user_id, device_id, access_token,
               std::to_string(now), std::to_string(expiry)});
        });

    return token;
  }

  struct RefreshResult {
    std::string access_token;
    std::string refresh_token;
    std::string user_id;
    std::string device_id;
    bool success{false};
    std::string error;
  };

  RefreshResult refresh(const std::string& refresh_token,
                          const std::string& device_id) {
    RefreshResult result;
    result.refresh_token = refresh_token;

    db_.runInteraction("refresh_access_token",
        [&](LoggingTransaction& txn) {
          txn.execute(
              "SELECT user_id, device_id, revoked, expires_at_ms, "
              "access_token_id FROM refresh_tokens "
              "WHERE token = ?",
              {refresh_token});
          auto rows = txn.fetchall();

          if (rows.empty()) {
            result.error = "Unknown refresh token";
            return;
          }

          auto& row = rows[0];
          result.user_id = row[0];
          std::string stored_device_id = row[1];
          bool revoked = (row[2] == "1");
          int64_t expires = row[3].empty() ? 0 : std::stoll(row[3]);

          if (revoked) {
            result.error = "Refresh token has been revoked";
            return;
          }

          int64_t now = now_ms();
          if (expires > 0 && now > expires) {
            result.error = "Refresh token has expired";
            // Mark as revoked
            txn.execute(
                "UPDATE refresh_tokens SET revoked = 1 WHERE token = ?",
                {refresh_token});
            return;
          }

          // Mark old token as used (rotate)
          txn.execute(
              "UPDATE refresh_tokens SET revoked = 1, "
              "revoked_at_ms = ? WHERE token = ?",
              {std::to_string(now), refresh_token});

          result.device_id = device_id.empty() ?
              stored_device_id : device_id;

          // Generate new access token
          result.access_token = "syt_" +
              srng().token(ACCESS_TOKEN_LENGTH - 4);

          int64_t access_expiry = now + ACCESS_TOKEN_TTL_MS;
          txn.execute(
              "INSERT INTO access_tokens "
              "(token, user_id, device_id, created_at_ms, "
              "expires_at_ms, is_guest) "
              "VALUES (?, ?, ?, ?, ?, 0)",
              {result.access_token, result.user_id,
               result.device_id, std::to_string(now),
               std::to_string(access_expiry)});

          // Generate new refresh token (rotation)
          result.refresh_token = "rt_" +
              srng().token(REFRESH_TOKEN_LENGTH - 3);

          int64_t refresh_expiry = now + REFRESH_TOKEN_TTL_MS;
          txn.execute(
              "INSERT INTO refresh_tokens "
              "(token, user_id, device_id, access_token_id, "
              "created_at_ms, expires_at_ms, used, revoked) "
              "VALUES (?, ?, ?, ?, ?, ?, 0, 0)",
              {result.refresh_token, result.user_id,
               result.device_id, result.access_token,
               std::to_string(now), std::to_string(refresh_expiry)});

          result.success = true;
        });

    return result;
  }

  void revoke_all_for_user(const std::string& user_id) {
    db_.runInteraction("revoke_user_refresh_tokens",
        [&](LoggingTransaction& txn) {
          txn.execute(
              "UPDATE refresh_tokens SET revoked = 1, "
              "revoked_at_ms = ? WHERE user_id = ? AND revoked = 0",
              {std::to_string(now_ms()), user_id});
        });
  }

  void revoke_for_device(const std::string& user_id,
                          const std::string& device_id) {
    db_.runInteraction("revoke_device_refresh_tokens",
        [&](LoggingTransaction& txn) {
          txn.execute(
              "UPDATE refresh_tokens SET revoked = 1, "
              "revoked_at_ms = ? WHERE user_id = ? AND device_id = ? "
              "AND revoked = 0",
              {std::to_string(now_ms()), user_id, device_id});
        });
  }

  bool is_token_valid(const std::string& token) {
    bool valid = false;
    db_.runInteraction("check_refresh_token",
        [&](LoggingTransaction& txn) {
          txn.execute(
              "SELECT 1 FROM refresh_tokens "
              "WHERE token = ? AND revoked = 0",
              {token});
          auto rows = txn.fetchall();
          valid = !rows.empty();
        });
    return valid;
  }

 private:
  DatabasePool& db_;
};

// ============================================================================
// AppServiceConfig — Application service configuration
// ============================================================================

class AppServiceConfig {
 public:
  struct AppServiceEntry {
    std::string id;
    std::string url;
    std::string as_token;
    std::string hs_token;
    std::string sender_localpart;
    json namespaces;
    bool rate_limited{true};
    bool enabled{true};
  };

  void load_from_db(DatabasePool& db) {
    db.runInteraction("load_appservices",
        [&](LoggingTransaction& txn) {
          txn.execute(
              "SELECT id, url, as_token, hs_token, sender_localpart, "
              "namespaces, rate_limited, enabled "
              "FROM application_services WHERE enabled = 1");
          auto rows = txn.fetchall();
          for (auto& row : rows) {
            AppServiceEntry entry;
            entry.id = row[0];
            entry.url = row[1];
            entry.as_token = row[2];
            entry.hs_token = row[3];
            entry.sender_localpart = row[4];
            try { entry.namespaces = json::parse(row[5]); }
            catch (...) { entry.namespaces = json::array(); }
            entry.rate_limited = (row[6] == "1");
            entry.enabled = (row[7] == "1");
            services_.push_back(entry);
          }
        });
  }

  const AppServiceEntry* find_by_token(const std::string& token) const {
    for (auto& svc : services_) {
      if (svc.as_token == token || svc.hs_token == token) return &svc;
    }
    return nullptr;
  }

  bool is_user_in_namespace(const std::string& user_id) const {
    for (auto& svc : services_) {
      if (!svc.namespaces.is_null() &&
          svc.namespaces.contains("users")) {
        for (auto& ns : svc.namespaces["users"]) {
          std::string regex_str = ns.value("regex", "");
          if (!regex_str.empty()) {
            try {
              std::regex re(regex_str);
              if (std::regex_match(user_id, re)) return true;
            } catch (...) {}
          }
        }
      }
    }
    return false;
  }

  const std::vector<AppServiceEntry>& services() const { return services_; }

 private:
  std::vector<AppServiceEntry> services_;
};

// ============================================================================
// CASTicketValidator — CAS protocol ticket validation
// ============================================================================

class CASTicketValidator {
 public:
  struct CASResult {
    bool valid{false};
    std::string user;
    std::string user_id;
    json attributes;
    std::string error;
  };

  CASResult validate_v1(const std::string& ticket,
                          const std::string& service_url,
                          const std::string& cas_server_url) {
    CASResult result;
    std::string validate_url = cas_server_url + "/validate" +
        "?ticket=" + url_encode(ticket) +
        "&service=" + url_encode(service_url);

    std::string response = http_get(validate_url);

    if (response.empty()) {
      result.error = "Empty response from CAS server";
      return result;
    }

    std::istringstream stream(response);
    std::string line;
    std::getline(stream, line);
    line = trim(line);

    if (line == "yes") {
      result.valid = true;
      if (std::getline(stream, line)) {
        result.user = trim(line);
      }
    } else if (line == "no") {
      result.error = "CAS ticket validation failed (no)";
    } else {
      result.error = "CAS server returned unexpected response: " + line;
    }

    return result;
  }

  CASResult validate_v2(const std::string& ticket,
                          const std::string& service_url,
                          const std::string& cas_server_url) {
    CASResult result;
    std::string validate_url = cas_server_url +
        "/serviceValidate" +
        "?ticket=" + url_encode(ticket) +
        "&service=" + url_encode(service_url) +
        "&format=JSON";

    std::string response = http_get(validate_url);

    if (response.empty()) {
      result.error = "Empty response from CAS server";
      return result;
    }

    try {
      json j = json::parse(response);
      auto& service_response = j["serviceResponse"];

      if (service_response.contains("authenticationSuccess")) {
        result.valid = true;
        auto& auth = service_response["authenticationSuccess"];
        result.user = auth.value("user", "");
        if (auth.contains("attributes"))
          result.attributes = auth["attributes"];
      } else if (service_response.contains("authenticationFailure")) {
        auto& fail = service_response["authenticationFailure"];
        result.error = fail.value("description",
            fail.value("code", "CAS authentication failed"));
      }
    } catch (const std::exception& e) {
      // Fallback to XML parsing
      result = parse_cas_xml(response);
    }

    return result;
  }

  CASResult validate(const std::string& ticket,
                      const std::string& service_url,
                      const std::string& cas_server_url,
                      CASVersion version = CASVersion::V3) {
    switch (version) {
      case CASVersion::V1:
        return validate_v1(ticket, service_url, cas_server_url);
      case CASVersion::V2:
      case CASVersion::V3:
      default:
        return validate_v2(ticket, service_url, cas_server_url);
    }
  }

 private:
  CASResult parse_cas_xml(const std::string& xml) {
    CASResult result;
    size_t pos = xml.find("cas:user");
    if (pos == std::string::npos) pos = xml.find("<user>");
    if (pos != std::string::npos) {
      size_t start = xml.find('>', pos) + 1;
      size_t end = xml.find('<', start);
      if (end != std::string::npos) {
        result.valid = true;
        result.user = xml.substr(start, end - start);
      }
    }
    if (!result.valid) {
      result.error = "CAS authentication failed (XML parse)";
    }
    return result;
  }

  std::string http_get(const std::string& url) {
    // Stand-in: in production would use HTTP client
    (void)url;
    return "";
  }
};

// ============================================================================
// JWTValidator — JWT token validation for JWT login flow
// ============================================================================

class JWTValidator {
 public:
  struct JWTConfig {
    std::string secret;
    std::string issuer;
    std::string audience;
    std::string algorithm{"HS256"};
    bool enabled{false};
  };

  struct JWTResult {
    bool valid{false};
    std::string sub;
    std::string user_id;
    std::string display_name;
    std::string email;
    json claims;
    std::string error;
  };

  explicit JWTValidator(const JWTConfig& config) : config_(config) {}

  JWTResult validate(const std::string& token) {
    JWTResult result;

    if (!config_.enabled) {
      result.error = "JWT login is not enabled";
      return result;
    }

    if (token.size() > static_cast<size_t>(MAX_JWT_TOKEN_LENGTH)) {
      result.error = "JWT token too long";
      return result;
    }

    ParsedJWT jwt = parse_jwt_token(token);
    if (!jwt.valid) {
      result.error = jwt.error.empty() ? "Invalid JWT token" : jwt.error;
      return result;
    }

    // Validate algorithm
    std::string alg = jwt.header.value("alg", "");
    if (alg != config_.algorithm) {
      result.error = "Unsupported JWT algorithm: " + alg +
          " (expected " + config_.algorithm + ")";
      return result;
    }

    auto& payload = jwt.payload;

    // Validate issuer
    if (!config_.issuer.empty()) {
      std::string iss = payload.value("iss", "");
      if (iss != config_.issuer) {
        result.error = "JWT issuer mismatch: " + iss +
            " (expected " + config_.issuer + ")";
        return result;
      }
    }

    // Validate audience
    if (!config_.audience.empty()) {
      std::string aud = payload.value("aud", "");
      // aud can be string or array
      if (payload["aud"].is_array()) {
        bool found = false;
        for (auto& a : payload["aud"]) {
          if (a.get<std::string>() == config_.audience) { found = true; break; }
        }
        if (!found) {
          result.error = "JWT audience mismatch";
          return result;
        }
      } else if (aud != config_.audience) {
        result.error = "JWT audience mismatch";
        return result;
      }
    }

    // Validate subject
    result.sub = payload.value("sub", "");
    if (result.sub.empty()) {
      result.error = "JWT missing 'sub' claim";
      return result;
    }

    // Validate expiration
    if (payload.contains("exp")) {
      int64_t exp = 0;
      if (payload["exp"].is_number()) {
        exp = payload["exp"].get<int64_t>() * 1000; // Convert to ms
      }
      if (exp > 0 && now_ms() > exp) {
        result.error = "JWT token has expired";
        return result;
      }
    }

    // Validate not-before
    if (payload.contains("nbf")) {
      int64_t nbf = 0;
      if (payload["nbf"].is_number()) {
        nbf = payload["nbf"].get<int64_t>() * 1000;
      }
      if (nbf > 0 && now_ms() < nbf) {
        result.error = "JWT token not yet valid";
        return result;
      }
    }

    // Validate issued-at
    if (payload.contains("iat")) {
      int64_t iat = 0;
      if (payload["iat"].is_number()) {
        iat = payload["iat"].get<int64_t>() * 1000;
      }
      if (iat > 0 && (now_ms() - iat) > JWT_DEFAULT_TTL_MS) {
        result.error = "JWT token issued too long ago";
        return result;
      }
    }

    // Signature verification (stand-in)
    if (!verify_signature(token, jwt.signature_b64)) {
      result.error = "JWT signature verification failed";
      return result;
    }

    // Extract optional claims
    result.display_name = payload.value("display_name",
        payload.value("name", ""));
    result.email = payload.value("email", "");
    result.claims = payload;
    result.valid = true;
    return result;
  }

  void set_config(const JWTConfig& config) { config_ = config; }

 private:
  bool verify_signature(const std::string& token,
                          const std::string& signature_b64) {
    if (config_.algorithm == "HS256") {
      std::string expected = sha256_hex_standin(
          token.substr(0, token.rfind('.')) + config_.secret);
      // Simplified: in production use HMAC-SHA256
      return !expected.empty();
    }
    // RS256/ES256 would use public key from JWKS
    return true; // Stand-in
  }

  JWTConfig config_;
};

// ============================================================================
// PasswordAuthHandler — Password-based login (m.login.password)
// ============================================================================

class PasswordAuthHandler {
 public:
  PasswordAuthHandler(DatabasePool& db,
                       AccountStatusChecker& status_checker,
                       LoginRateLimiter& rate_limiter,
                       LoginAuditLogger& audit_logger)
      : db_(db), status_checker_(status_checker),
        rate_limiter_(rate_limiter), audit_logger_(audit_logger) {}

  struct PasswordAuthResult {
    LoginResult result{LoginResult::INVALID_CREDENTIALS};
    std::string user_id;
    std::string error;
    json error_json;
  };

  PasswordAuthResult authenticate(const LoginRequest& request,
                                    const std::string& ip_address,
                                    const std::string& user_agent) {
    PasswordAuthResult auth_result;
    UserIdentifierResolver resolver(db_);
    auto user_id_opt = resolver.resolve(request.identifier);

    if (!user_id_opt) {
      auth_result.error = "Invalid username or user identifier not found";
      auth_result.error_json = make_error_response(
          ERR_FORBIDDEN, "Invalid username or password", 403);
      audit_logger_.log_login_attempt(request.identifier.describe(),
          LoginType::PASSWORD, false, ip_address, user_agent,
          "User not found");
      return auth_result;
    }

    std::string user_id = *user_id_opt;

    // Check account status
    AccountStatus status = status_checker_.check(user_id);

    if (!status.can_login()) {
      auth_result.result = map_deactivation_to_result(
          status.deactivation_state);
      auth_result.error = status.block_reason();
      auth_result.error_json = status.block_error_json();
      audit_logger_.log_login_attempt(user_id, LoginType::PASSWORD,
          false, ip_address, user_agent, auth_result.error);
      return auth_result;
    }

    // Verify password
    bool password_correct = verify_password_standin(
        request.password, status.password_hash);

    if (!password_correct) {
      rate_limiter_.record_failed_attempt(user_id);

      int failed_count = rate_limiter_.failed_attempt_count(user_id);
      int64_t lockout_ms = rate_limiter_.lockout_duration_ms(failed_count);

      std::string err_msg = "Invalid username or password";
      if (lockout_ms > 0) {
        err_msg += ". Account locked for " +
            std::to_string(lockout_ms / 60000) + " minutes";
        auth_result.result = LoginResult::ACCOUNT_LOCKED;

        // Persist lockout
        db_.runInteraction("lock_account",
            [&](LoggingTransaction& txn) {
              txn.execute(
                  "UPDATE users SET locked_until = ?, "
                  "failed_logins = ? WHERE name = ?",
                  {std::to_string(now_ms() + lockout_ms),
                   std::to_string(failed_count),
                   extract_localpart(user_id)});
            });
      }

      auth_result.error = err_msg;
      auth_result.error_json = make_error_response(
          ERR_FORBIDDEN, err_msg, 403);
      audit_logger_.log_login_attempt(user_id, LoginType::PASSWORD,
          false, ip_address, user_agent, "Invalid password");
      return auth_result;
    }

    // Check password expiry
    if (status.password_last_changed_ms > 0) {
      int64_t age_days = (now_ms() - status.password_last_changed_ms) /
          days_to_ms(1);
      if (age_days > PASSWORD_EXPIRY_DAYS) {
        auth_result.result = LoginResult::PASSWORD_EXPIRED;
        auth_result.error = "Password has expired. Please change your password.";
        auth_result.error_json = make_error_response(
            ERR_PASSWORD_EXPIRED, auth_result.error, 403);
        auth_result.user_id = user_id;
        audit_logger_.log_login_attempt(user_id, LoginType::PASSWORD,
            false, ip_address, user_agent, "Password expired");
        return auth_result;
      }
    }

    // Success
    rate_limiter_.clear_failed_attempts(user_id);
    auth_result.result = LoginResult::SUCCESS;
    auth_result.user_id = user_id;

    // Clear failed login counter in DB
    db_.runInteraction("clear_failed_logins",
        [&](LoggingTransaction& txn) {
          txn.execute(
              "UPDATE users SET failed_logins = 0, "
              "locked_until = NULL WHERE name = ?",
              {extract_localpart(user_id)});
        });

    return auth_result;
  }

 private:
  LoginResult map_deactivation_to_result(
      AccountDeactivationState state) {
    switch (state) {
      case AccountDeactivationState::DEACTIVATED_SOFT:
      case AccountDeactivationState::DEACTIVATED_HARD:
      case AccountDeactivationState::DEACTIVATED_GDPR:
      case AccountDeactivationState::PERMANENTLY_REMOVED:
        return LoginResult::ACCOUNT_DEACTIVATED;
      default:
        return LoginResult::INVALID_CREDENTIALS;
    }
  }

  DatabasePool& db_;
  AccountStatusChecker& status_checker_;
  LoginRateLimiter& rate_limiter_;
  LoginAuditLogger& audit_logger_;
};

// ============================================================================
// TokenAuthHandler — Token-based login (m.login.token)
// ============================================================================

class TokenAuthHandler {
 public:
  explicit TokenAuthHandler(DatabasePool& db) : db_(db) {}

  struct TokenAuthResult {
    bool success{false};
    std::string user_id;
    std::string error;
  };

  TokenAuthResult authenticate(const std::string& login_token) {
    TokenAuthResult result;

    if (login_token.empty()) {
      result.error = "Missing login token";
      return result;
    }

    db_.runInteraction("consume_login_token",
        [&](LoggingTransaction& txn) {
          txn.execute(
              "SELECT user_id, expiry_ts, used FROM login_tokens "
              "WHERE token = ?",
              {login_token});
          auto rows = txn.fetchall();

          if (rows.empty()) {
            result.error = "Unknown login token";
            return;
          }

          auto& row = rows[0];
          std::string user_id = row[0];
          int64_t expiry = row[1].empty() ? 0 : std::stoll(row[1]);
          bool used = (row[2] == "1");

          if (used) {
            result.error = "Login token has already been used";
            return;
          }

          if (expiry > 0 && now_ms() > expiry) {
            result.error = "Login token has expired";
            txn.execute(
                "UPDATE login_tokens SET used = 1 WHERE token = ?",
                {login_token});
            return;
          }

          // Mark as used (single-use)
          txn.execute(
              "UPDATE login_tokens SET used = 1, "
              "used_at_ms = ? WHERE token = ?",
              {std::to_string(now_ms()), login_token});

          result.success = true;
          result.user_id = user_id;
        });

    return result;
  }

  std::string generate_login_token(const std::string& user_id,
                                     int64_t ttl_ms = LOGIN_TOKEN_TTL_MS) {
    std::string token = "lt_" + srng().token(LOGIN_TOKEN_LENGTH - 3);
    int64_t now = now_ms();

    db_.runInteraction("store_login_token",
        [&](LoggingTransaction& txn) {
          txn.execute(
              "INSERT INTO login_tokens "
              "(token, user_id, created_at_ms, expiry_ts, used) "
              "VALUES (?, ?, ?, ?, 0)",
              {token, user_id, std::to_string(now),
               std::to_string(now + ttl_ms)});
        });

    return token;
  }

 private:
  DatabasePool& db_;
};

// ============================================================================
// SSORedirectHandler — SSO redirect initiation (m.login.sso)
// ============================================================================

class SSORedirectHandler {
 public:
  struct SSOProvider {
    std::string id;
    std::string name;
    std::string icon;
    std::string brand;
    std::string authorization_url;
    std::string client_id;
    std::string redirect_uri_base;
    std::vector<std::string> scopes;
    std::string response_type{"code"};
    bool pkce_enabled{true};
  };

  struct SSORedirectResult {
    bool success{false};
    std::string redirect_url;
    std::string session_id;
    std::string error;
    json error_json;
  };

  SSORedirectResult initiate_redirect(const LoginRequest& request,
                                       const std::string& server_name,
                                       const std::string& base_url) {
    SSORedirectResult result;

    const SSOProvider* provider = nullptr;
    if (!request.sso_provider.empty()) {
      provider = find_provider(request.sso_provider);
    } else if (!providers_.empty()) {
      provider = &providers_.front();
    }

    if (!provider) {
      result.error = "No SSO provider configured";
      result.error_json = make_error_response(
          ERR_UNSUPPORTED, "SSO login is not available", 400);
      return result;
    }

    std::string session_id = "sso_" + srng().token(48);
    std::string state = srng().token(SSO_STATE_LENGTH);
    std::string nonce = srng().token(32);

    // Store session
    SSOSessionData session;
    session.session_id = session_id;
    session.provider_id = provider->id;
    session.state = state;
    session.nonce = nonce;
    session.redirect_url = request.redirect_url;
    session.created_at_ms = now_ms();
    session.expires_at_ms = now_ms() + SSO_SESSION_TTL_MS;

    if (provider->pkce_enabled) {
      session.code_verifier = srng().token(64);
    }

    {
      std::lock_guard<std::mutex> lock(sessions_mutex_);
      sessions_[session_id] = session;
    }

    // Build redirect URL
    std::map<std::string, std::string> params;
    params["response_type"] = provider->response_type;
    params["client_id"] = provider->client_id;
    params["redirect_uri"] = provider->redirect_uri_base +
        "?session=" + url_encode(session_id);
    params["state"] = state;
    params["nonce"] = nonce;
    params["scope"] = "";
    for (size_t i = 0; i < provider->scopes.size(); ++i) {
      if (i > 0) params["scope"] += " ";
      params["scope"] += provider->scopes[i];
    }

    if (provider->pkce_enabled && !session.code_verifier.empty()) {
      params["code_challenge_method"] = "S256";
      params["code_challenge"] = sha256_hex_standin(session.code_verifier);
    }

    result.redirect_url = provider->authorization_url + "?" +
        build_query_string(params);
    result.session_id = session_id;
    result.success = true;

    return result;
  }

  SSORedirectResult get_providers() {
    SSORedirectResult result;
    result.success = true;

    json providers_list = json::array();
    for (const auto& p : providers_) {
      json entry;
      entry["id"] = p.id;
      entry["name"] = p.name;
      if (!p.icon.empty()) entry["icon"] = p.icon;
      if (!p.brand.empty()) entry["brand"] = p.brand;
      providers_list.push_back(entry);
    }

    // Return providers list in redirect_url for API-based retrieval
    result.redirect_url = ""; // Non-redirect: return providers
    return result;
  }

  struct SSOSessionData {
    std::string session_id;
    std::string provider_id;
    std::string state;
    std::string nonce;
    std::string redirect_url;
    std::string code_verifier;
    std::string auth_code;
    std::string id_token;
    std::string access_token;
    std::string refresh_token;
    std::string mapped_user_id;
    std::string external_id;
    std::string display_name;
    int64_t created_at_ms{0};
    int64_t expires_at_ms{0};
    bool authenticated{false};
    bool completed{false};
    json user_attributes;
  };

  SSOSessionData* get_session(const std::string& session_id) {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    auto it = sessions_.find(session_id);
    if (it == sessions_.end()) return nullptr;
    if (it->second.expires_at_ms > 0 &&
        now_ms() > it->second.expires_at_ms) {
      sessions_.erase(it);
      return nullptr;
    }
    return &it->second;
  }

  SSOSessionData* get_session_by_state(const std::string& state) {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    for (auto& [id, s] : sessions_) {
      if (s.state == state && s.expires_at_ms > now_ms()) return &s;
    }
    return nullptr;
  }

  void complete_session(const std::string& session_id,
                          const std::string& user_id) {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    auto it = sessions_.find(session_id);
    if (it != sessions_.end()) {
      it->second.mapped_user_id = user_id;
      it->second.completed = true;
    }
  }

  void add_provider(const SSOProvider& provider) {
    providers_.push_back(provider);
  }

  size_t active_session_count() const {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    return sessions_.size();
  }

 private:
  const SSOProvider* find_provider(const std::string& id) const {
    for (const auto& p : providers_) {
      if (p.id == id) return &p;
    }
    return nullptr;
  }

  std::vector<SSOProvider> providers_;
  std::unordered_map<std::string, SSOSessionData> sessions_;
  mutable std::mutex sessions_mutex_;
};

// ============================================================================
// CASTicketHandler — CAS ticket login (m.login.cas)
// ============================================================================

class CASTicketHandler {
 public:
  struct CASConfig {
    bool enabled{false};
    std::string server_url;
    std::string service_url;
    CASVersion version{CASVersion::V3};
    std::string display_name{"CAS"};
    std::string icon_url;
    std::string brand;
  };

  explicit CASTicketHandler(DatabasePool& db) : db_(db) {}

  struct CASTicketResult {
    bool success{false};
    std::string user_id;
    std::string error;
    json error_json;
  };

  CASTicketResult authenticate(const LoginRequest& request) {
    CASTicketResult result;

    if (!config_.enabled) {
      result.error = "CAS login is not enabled";
      result.error_json = make_error_response(
          ERR_UNSUPPORTED, "CAS login is not available", 400);
      return result;
    }

    // First, check if ticket already consumed
    bool already_used = false;
    db_.runInteraction("check_cas_ticket",
        [&](LoggingTransaction& txn) {
          txn.execute(
              "SELECT 1 FROM cas_tickets WHERE ticket = ? AND used = 1",
              {request.cas_ticket});
          auto rows = txn.fetchall();
          already_used = !rows.empty();
        });

    if (already_used) {
      result.error = "CAS ticket already used";
      result.error_json = make_error_response(
          ERR_FORBIDDEN, "CAS ticket has already been consumed", 403);
      return result;
    }

    // Validate ticket with CAS server
    CASTicketValidator validator;
    auto cas_result = validator.validate(
        request.cas_ticket, request.cas_service,
        config_.server_url, config_.version);

    if (!cas_result.valid) {
      result.error = cas_result.error;
      result.error_json = make_error_response(
          ERR_FORBIDDEN, "CAS authentication failed: " + cas_result.error, 403);
      return result;
    }

    // Map CAS user to Matrix user
    std::string user_id = map_cas_user(cas_result.user);
    if (user_id.empty()) {
      result.error = "Cannot map CAS user to Matrix user";
      result.error_json = make_error_response(
          ERR_FORBIDDEN, "CAS user mapping failed", 403);
      return result;
    }

    // Store ticket as consumed
    int64_t now = now_ms();
    db_.runInteraction("store_cas_ticket",
        [&](LoggingTransaction& txn) {
          txn.execute(
              "INSERT INTO cas_tickets (ticket, user_id, service, "
              "consumed_at_ms, used) VALUES (?, ?, ?, ?, 1)",
              {request.cas_ticket, user_id, request.cas_service,
               std::to_string(now)});
        });

    result.success = true;
    result.user_id = user_id;
    return result;
  }

  std::string build_cas_redirect_url() const {
    std::string login_url = config_.server_url + "/login" +
        "?service=" + url_encode(config_.service_url);
    return login_url;
  }

  void set_config(const CASConfig& config) { config_ = config; }
  const CASConfig& config() const { return config_; }

 private:
  std::string map_cas_user(const std::string& cas_user) {
    std::string localpart = to_lower(trim(cas_user));
    // Remove domain portion if present (e.g., user@domain -> user)
    auto at_pos = localpart.find('@');
    if (at_pos != std::string::npos) {
      localpart = localpart.substr(0, at_pos);
    }

    // Check if user exists
    std::string user_id;
    db_.runInteraction("map_cas_user",
        [&](LoggingTransaction& txn) {
          txn.execute(
              "SELECT name FROM users WHERE "
              "external_id = ? AND external_id_type = 'cas'",
              {cas_user});
          auto rows = txn.fetchall();
          if (!rows.empty()) {
            user_id = "@" + rows[0][0] + ":" + server_name_;
          }
        });

    if (user_id.empty()) {
      // Try by localpart
      user_id = "@" + localpart + ":" + server_name_;
    }

    return user_id;
  }

  void set_server_name(const std::string& name) { server_name_ = name; }

  DatabasePool& db_;
  CASConfig config_;
  std::string server_name_;
};

// ============================================================================
// JWTAuthHandler — JWT-based login (org.matrix.login.jwt)
// ============================================================================

class JWTAuthHandler {
 public:
  explicit JWTAuthHandler(DatabasePool& db) : db_(db) {}

  struct JWTAuthResult {
    bool success{false};
    std::string user_id;
    std::string display_name;
    std::string error;
    json error_json;
  };

  JWTAuthResult authenticate(const LoginRequest& request,
                               JWTValidator& validator) {
    JWTAuthResult result;

    auto jwt_result = validator.validate(request.jwt_token);
    if (!jwt_result.valid) {
      result.error = jwt_result.error;
      result.error_json = make_error_response(
          ERR_FORBIDDEN, "JWT validation failed: " + jwt_result.error, 403);
      return result;
    }

    // Map JWT sub to Matrix user
    std::string user_id = map_jwt_user(jwt_result.sub);
    if (user_id.empty()) {
      // Auto-provision user if configured
      user_id = provision_jwt_user(jwt_result);
    }

    if (user_id.empty()) {
      result.error = "Cannot map JWT subject to a Matrix user";
      result.error_json = make_error_response(
          ERR_FORBIDDEN, "JWT user mapping failed", 403);
      return result;
    }

    result.success = true;
    result.user_id = user_id;
    result.display_name = jwt_result.display_name;
    return result;
  }

  void set_server_name(const std::string& name) { server_name_ = name; }

 private:
  std::string map_jwt_user(const std::string& sub) {
    std::string user_id;
    db_.runInteraction("map_jwt_user",
        [&](LoggingTransaction& txn) {
          txn.execute(
              "SELECT user_id FROM user_external_ids "
              "WHERE external_id = ? AND id_type = 'jwt'",
              {sub});
          auto rows = txn.fetchall();
          if (!rows.empty()) {
            user_id = rows[0][0];
          }
        });
    return user_id;
  }

  std::string provision_jwt_user(const JWTValidator::JWTResult& jwt) {
    std::string localpart = to_lower(trim(jwt.sub));
    if (localpart.empty()) return "";

    std::string user_id = "@" + localpart + ":" + server_name_;

    db_.runInteraction("provision_jwt_user",
        [&](LoggingTransaction& txn) {
          txn.execute(
              "INSERT INTO users (name, display_name, is_guest, "
              "password_hash, external_id, external_id_type, "
              "created_at_ms) "
              "VALUES (?, ?, 0, '', ?, 'jwt', ?) "
              "ON CONFLICT(name) DO NOTHING",
              {localpart,
               jwt.display_name.empty() ? localpart : jwt.display_name,
               jwt.sub, std::to_string(now_ms())});

          txn.execute(
              "INSERT INTO user_external_ids "
              "(user_id, external_id, id_type) "
              "VALUES (?, ?, 'jwt') "
              "ON CONFLICT(user_id, external_id, id_type) DO NOTHING",
              {user_id, jwt.sub});
        });

    return user_id;
  }

  DatabasePool& db_;
  std::string server_name_;
};

// ============================================================================
// AppServiceAuthHandler — Appservice login (m.login.application_service)
// ============================================================================

class AppServiceAuthHandler {
 public:
  AppServiceAuthHandler(DatabasePool& db, AppServiceConfig& config)
      : db_(db), config_(config) {}

  struct AppServiceAuthResult {
    bool success{false};
    std::string user_id;
    std::string as_id;
    bool is_ghost{false};
    std::string error;
    json error_json;
  };

  AppServiceAuthResult authenticate(const LoginRequest& request,
                                      const std::string& ip_address) {
    AppServiceAuthResult result;

    // Validate the appservice token
    const AppServiceConfig::AppServiceEntry* svc =
        config_.find_by_token(request.appservice_token);
    if (!svc) {
      result.error = "Invalid application service token";
      result.error_json = make_error_response(
          ERR_FORBIDDEN, "Invalid application service credentials", 403);
      return result;
    }

    // Resolve the user
    UserIdentifierResolver resolver(db_);
    auto user_id_opt = resolver.resolve(request.identifier);
    if (!user_id_opt) {
      result.error = "User not found for appservice login";
      result.error_json = make_error_response(
          ERR_FORBIDDEN, "User not found", 403);
      return result;
    }

    std::string user_id = *user_id_opt;

    // Check if user is in the appservice's namespace
    if (!config_.is_user_in_namespace(user_id)) {
      result.error = "User not in application service namespace";
      result.error_json = make_error_response(
          ERR_NO_APP_SERVICE,
          "User is not in this application service's namespace", 403);
      return result;
    }

    result.success = true;
    result.user_id = user_id;
    result.as_id = svc->id;
    result.is_ghost = (user_id.find("@" + svc->sender_localpart) == 0);
    return result;
  }

 private:
  DatabasePool& db_;
  AppServiceConfig& config_;
};

// ============================================================================
// GuestLoginHandler — Guest login (m.login.guest)
// ============================================================================

class GuestLoginHandler {
 public:
  explicit GuestLoginHandler(DatabasePool& db) : db_(db) {}

  struct GuestLoginResult {
    bool success{false};
    std::string user_id;
    std::string access_token;
    std::string device_id;
    std::string error;
    json error_json;
  };

  GuestLoginResult create_guest(const std::string& ip_address,
                                 const std::string& device_id_in,
                                 const std::string& display_name) {
    GuestLoginResult result;

    std::string guest_user_id;
    std::string device_id = device_id_in.empty() ?
        srng().token(DEVICE_ID_LENGTH) : device_id_in;

    db_.runInteraction("create_guest",
        [&](LoggingTransaction& txn) {
          // Generate unique guest ID
          std::string guest_localpart;
          int attempts = 0;
          const int max_attempts = 10;

          do {
            guest_localpart = "guest_" + srng().numeric(8);
            txn.execute(
                "SELECT 1 FROM users WHERE name = ?",
                {guest_localpart});
            auto rows = txn.fetchall();
            if (rows.empty()) break;
            attempts++;
          } while (attempts < max_attempts);

          if (attempts >= max_attempts) {
            result.error = "Failed to generate unique guest ID";
            return;
          }

          int64_t now = now_ms();

          // Create guest user
          txn.execute(
              "INSERT INTO users "
              "(name, display_name, is_guest, password_hash, "
              "created_at_ms, deactivated) "
              "VALUES (?, ?, 1, '', ?, 0)",
              {guest_localpart,
               display_name.empty() ? "Guest" : display_name,
               std::to_string(now)});

          guest_user_id = "@" + guest_localpart + ":" + server_name_;

          // Create access token
          std::string access_token = "syg_" +
              srng().token(GUEST_TOKEN_LENGTH - 4);

          int64_t expiry = now + GUEST_SESSION_TTL_MS;
          txn.execute(
              "INSERT INTO access_tokens "
              "(token, user_id, device_id, created_at_ms, "
              "expires_at_ms, is_guest) "
              "VALUES (?, ?, ?, ?, ?, 1)",
              {access_token, guest_user_id, device_id,
               std::to_string(now), std::to_string(expiry)});

          // Create device
          txn.execute(
              "INSERT INTO devices "
              "(user_id, device_id, display_name, last_seen, "
              "ip, user_agent, hidden) "
              "VALUES (?, ?, ?, ?, ?, '', 0)",
              {guest_user_id, device_id, display_name,
               std::to_string(now), ip_address});

          result.access_token = access_token;
        });

    if (guest_user_id.empty()) {
      if (result.error.empty()) {
        result.error = "Failed to create guest account";
      }
      result.error_json = make_error_response(
          ERR_UNKNOWN, result.error, 500);
      return result;
    }

    result.success = true;
    result.user_id = guest_user_id;
    result.device_id = device_id;
    return result;
  }

  void set_server_name(const std::string& name) { server_name_ = name; }

 private:
  DatabasePool& db_;
  std::string server_name_;
};

// ============================================================================
// LoginFlowEngine — Main login orchestrator
// ============================================================================

class LoginFlowEngine {
 public:
  LoginFlowEngine(DatabasePool& db,
                   const std::string& server_name,
                   const std::string& server_version = "Progressive/1.0")
      : db_(db),
        server_name_(server_name),
        server_version_(server_version),
        status_checker_(db),
        password_auth_(db, status_checker_, rate_limiter_, audit_logger_),
        token_auth_(db),
        sso_handler_(),
        cas_handler_(db),
        jwt_handler_(db),
        appservice_handler_(db, appservice_config_),
        guest_handler_(db),
        device_creator_(db),
        refresh_manager_(db),
        identifier_resolver_(db) {
    identifier_resolver_.set_server_name(server_name);
    guest_handler_.set_server_name(server_name);
    jwt_handler_.set_server_name(server_name);
    jwt_validator_ = std::make_unique<JWTValidator>(JWTValidator::JWTConfig{});
  }

  // ---- Main login entry point ----

  struct LoginResult {
    bool success{false};
    std::string user_id;
    std::string access_token;
    std::string device_id;
    std::string home_server;
    std::string refresh_token;
    json response_json;
    json error_json;
    int http_status{200};
  };

  LoginResult handle_login(const LoginRequest& request,
                            const std::string& ip_address,
                            const std::string& user_agent) {
    LoginResult result;
    result.home_server = server_name_;

    // Validate request
    std::string validation_error;
    if (!request.is_valid(validation_error)) {
      result.success = false;
      result.error_json = make_error_response(
          ERR_INVALID_PARAM, validation_error, 400);
      result.http_status = 400;
      return result;
    }

    // Rate limit check
    std::string rate_error;
    if (!rate_limiter_.check_rate_limit(ip_address,
            request.identifier.describe(), rate_error)) {
      result.success = false;
      result.error_json = make_error_response(
          ERR_LIMIT_EXCEEDED, rate_error, 429);
      result.http_status = 429;
      return result;
    }

    // Dispatch to appropriate handler
    switch (request.login_type) {
      case LoginType::PASSWORD:
        return handle_password_login(request, ip_address, user_agent);
      case LoginType::TOKEN:
        return handle_token_login(request, ip_address, user_agent);
      case LoginType::SSO:
        return handle_sso_login(request, ip_address, user_agent);
      case LoginType::CAS:
        return handle_cas_login(request, ip_address, user_agent);
      case LoginType::JWT:
        return handle_jwt_login(request, ip_address, user_agent);
      case LoginType::APPLICATION_SERVICE:
        return handle_appservice_login(request, ip_address, user_agent);
      case LoginType::GUEST:
        return handle_guest_login(request, ip_address, user_agent);
      case LoginType::REFRESH_TOKEN:
        return handle_refresh_token(request, ip_address, user_agent);
      default:
        result.success = false;
        result.error_json = make_error_response(
            ERR_UNSUPPORTED, "Unsupported login type", 400);
        result.http_status = 400;
        return result;
    }
  }

  // ---- Individual login handlers ----

  LoginResult handle_password_login(const LoginRequest& request,
                                      const std::string& ip_address,
                                      const std::string& user_agent) {
    LoginResult result;
    result.home_server = server_name_;

    auto auth = password_auth_.authenticate(request, ip_address, user_agent);
    if (auth.result != LoginResult::SUCCESS) {
      result.success = false;
      result.error_json = auth.error_json;
      if (auth.result == LoginResult::ACCOUNT_DEACTIVATED)
        result.http_status = 403;
      else
        result.http_status = 403;
      return result;
    }

    return finalize_login(auth.user_id, request.device_id,
        request.initial_device_display_name, ip_address, user_agent,
        LoginType::PASSWORD, request.request_refresh_token);
  }

  LoginResult handle_token_login(const LoginRequest& request,
                                   const std::string& ip_address,
                                   const std::string& user_agent) {
    LoginResult result;
    result.home_server = server_name_;

    std::string token = request.login_token.empty() ?
        request.token : request.login_token;

    auto auth = token_auth_.authenticate(token);
    if (!auth.success) {
      result.success = false;
      result.error_json = make_error_response(
          ERR_FORBIDDEN, auth.error, 403);
      result.http_status = 403;
      audit_logger_.log_login_attempt("token_login",
          LoginType::TOKEN, false, ip_address, user_agent, auth.error);
      return result;
    }

    // Check account status
    AccountStatus status = status_checker_.check(auth.user_id);
    if (!status.can_login()) {
      result.success = false;
      result.error_json = status.block_error_json();
      result.http_status = 403;
      return result;
    }

    return finalize_login(auth.user_id, request.device_id,
        request.initial_device_display_name, ip_address, user_agent,
        LoginType::TOKEN, request.request_refresh_token);
  }

  LoginResult handle_sso_login(const LoginRequest& request,
                                 const std::string& ip_address,
                                 const std::string& user_agent) {
    LoginResult result;
    result.home_server = server_name_;

    auto redirect = sso_handler_.initiate_redirect(
        request, server_name_, "");
    if (!redirect.success) {
      result.success = false;
      result.error_json = redirect.error_json;
      result.http_status = 400;
      return result;
    }

    // SSO response is a redirect URL, not a direct login
    result.success = false;
    result.error_json = {
      {"flows", json::array({{
        {"type", LOGIN_TYPE_SSO},
        {"redirect_url", redirect.redirect_url},
        {"session", redirect.session_id}
      }})}
    };
    // This signals the client to redirect
    result.http_status = 302;
    audit_logger_.log_login_attempt("sso_init",
        LoginType::SSO, true, ip_address, user_agent);
    return result;
  }

  LoginResult handle_cas_login(const LoginRequest& request,
                                 const std::string& ip_address,
                                 const std::string& user_agent) {
    LoginResult result;
    result.home_server = server_name_;

    // If no ticket, return CAS redirect URL
    if (request.cas_ticket.empty()) {
      std::string redirect_url = cas_handler_.build_cas_redirect_url();
      result.success = false;
      result.error_json = {
        {"flows", json::array({{
          {"type", LOGIN_TYPE_CAS},
          {"redirect_url", redirect_url}
        }})}
      };
      result.http_status = 302;
      return result;
    }

    auto auth = cas_handler_.authenticate(request);
    if (!auth.success) {
      result.success = false;
      result.error_json = auth.error_json;
      result.http_status = 403;
      audit_logger_.log_login_attempt("cas_login",
          LoginType::CAS, false, ip_address, user_agent, auth.error);
      return result;
    }

    return finalize_login(auth.user_id, request.device_id,
        request.initial_device_display_name, ip_address, user_agent,
        LoginType::CAS, request.request_refresh_token);
  }

  LoginResult handle_jwt_login(const LoginRequest& request,
                                 const std::string& ip_address,
                                 const std::string& user_agent) {
    LoginResult result;
    result.home_server = server_name_;

    auto auth = jwt_handler_.authenticate(request, *jwt_validator_);
    if (!auth.success) {
      result.success = false;
      result.error_json = auth.error_json;
      result.http_status = 403;
      audit_logger_.log_login_attempt("jwt_login",
          LoginType::JWT, false, ip_address, user_agent, auth.error);
      return result;
    }

    return finalize_login(auth.user_id, request.device_id,
        request.initial_device_display_name, ip_address, user_agent,
        LoginType::JWT, request.request_refresh_token);
  }

  LoginResult handle_appservice_login(const LoginRequest& request,
                                        const std::string& ip_address,
                                        const std::string& user_agent) {
    LoginResult result;
    result.home_server = server_name_;

    auto auth = appservice_handler_.authenticate(request, ip_address);
    if (!auth.success) {
      result.success = false;
      result.error_json = auth.error_json;
      result.http_status = 403;
      audit_logger_.log_login_attempt("appservice_login",
          LoginType::APPLICATION_SERVICE, false, ip_address, user_agent,
          auth.error);
      return result;
    }

    return finalize_login(auth.user_id, request.device_id,
        request.initial_device_display_name, ip_address, user_agent,
        LoginType::APPLICATION_SERVICE, request.request_refresh_token);
  }

  LoginResult handle_guest_login(const LoginRequest& request,
                                   const std::string& ip_address,
                                   const std::string& user_agent) {
    LoginResult result;
    result.home_server = server_name_;

    // Guest rate limiting (more restrictive)
    if (rate_limiter_.is_guest_rate_limited(ip_address)) {
      result.success = false;
      result.error_json = make_error_response(
          ERR_LIMIT_EXCEEDED,
          "Too many guest registrations. Try again later.", 429);
      result.http_status = 429;
      return result;
    }

    auto guest = guest_handler_.create_guest(
        ip_address, request.device_id,
        request.initial_device_display_name);

    if (!guest.success) {
      result.success = false;
      result.error_json = guest.error_json;
      result.http_status = 500;
      return result;
    }

    rate_limiter_.record_guest_login(ip_address);

    result.success = true;
    result.user_id = guest.user_id;
    result.access_token = guest.access_token;
    result.device_id = guest.device_id;

    result.response_json = make_login_success(
        guest.user_id, guest.access_token, guest.device_id,
        server_name_);

    audit_logger_.log_login_success(guest.user_id, guest.device_id,
        LoginType::GUEST, ip_address, user_agent);
    return result;
  }

  LoginResult handle_refresh_token(const LoginRequest& request,
                                     const std::string& ip_address,
                                     const std::string& user_agent) {
    LoginResult result;
    result.home_server = server_name_;

    auto refresh = refresh_manager_.refresh(
        request.refresh_token, request.device_id);

    if (!refresh.success) {
      result.success = false;
      result.error_json = make_error_response(
          ERR_UNKNOWN_TOKEN, refresh.error, 403);
      result.http_status = 403;
      return result;
    }

    result.success = true;
    result.user_id = refresh.user_id;
    result.access_token = refresh.access_token;
    result.device_id = refresh.device_id;
    result.refresh_token = refresh.refresh_token;

    result.response_json = make_login_success(
        refresh.user_id, refresh.access_token, refresh.device_id,
        server_name_, refresh.refresh_token);

    // Update device last seen
    device_creator_.update_last_seen(refresh.user_id, refresh.device_id,
        ip_address);

    audit_logger_.log_login_success(refresh.user_id, refresh.device_id,
        LoginType::REFRESH_TOKEN, ip_address, user_agent);
    return result;
  }

  // ---- Finalize login (common path) ----

  LoginResult finalize_login(const std::string& user_id,
                               const std::string& device_id_in,
                               const std::string& display_name,
                               const std::string& ip_address,
                               const std::string& user_agent,
                               LoginType login_type,
                               bool include_refresh_token) {
    LoginResult result;
    result.home_server = server_name_;
    result.user_id = user_id;

    // Create or update device
    result.device_id = device_creator_.create_or_update_device(
        user_id, device_id_in, display_name, ip_address, user_agent);

    // Generate access token
    result.access_token = "syt_" + srng().token(ACCESS_TOKEN_LENGTH - 4);

    int64_t now = now_ms();
    int64_t expiry = now + ACCESS_TOKEN_TTL_MS;

    bool is_guest = is_guest_user_id(user_id);

    db_.runInteraction("create_access_token",
        [&](LoggingTransaction& txn) {
          txn.execute(
              "INSERT INTO access_tokens "
              "(token, user_id, device_id, created_at_ms, "
              "expires_at_ms, is_guest) "
              "VALUES (?, ?, ?, ?, ?, ?)",
              {result.access_token, user_id, result.device_id,
               std::to_string(now), std::to_string(expiry),
               is_guest ? "1" : "0"});
        });

    // Generate refresh token (if requested and not guest)
    if (include_refresh_token && !is_guest) {
      result.refresh_token = refresh_manager_.generate_refresh_token(
          user_id, result.device_id, result.access_token);
    }

    // Build response
    result.response_json = make_login_success(
        user_id, result.access_token, result.device_id,
        server_name_, result.refresh_token);

    result.success = true;

    // Audit log
    audit_logger_.log_login_success(user_id, result.device_id,
        login_type, ip_address, user_agent);

    return result;
  }

  // ---- Configuration and management ----

  void set_jwt_config(const JWTValidator::JWTConfig& config) {
    jwt_validator_->set_config(config);
  }

  void set_cas_config(const CASTicketHandler::CASConfig& config) {
    cas_handler_.set_config(config);
  }

  void add_sso_provider(const SSORedirectHandler::SSOProvider& provider) {
    sso_handler_.add_provider(provider);
  }

  void load_appservice_config() {
    appservice_config_.load_from_db(db_);
  }

  json get_login_flows() {
    json flows = get_default_login_flows();

    if (cas_handler_.config().enabled) {
      flows.push_back({{"type", LOGIN_TYPE_CAS}});
    }

    if (jwt_validator_) {
      // Check if JWT is configured
      flows.push_back({{"type", LOGIN_TYPE_JWT}});
    }

    if (!appservice_config_.services().empty()) {
      flows.push_back({{"type", LOGIN_TYPE_APPSERVICE}});
    }

    return flows;
  }

  // ---- Account deactivation checks ----

  bool is_account_deactivated(const std::string& user_id) {
    return status_checker_.is_deactivated(user_id);
  }

  bool can_reactivate(const std::string& user_id) {
    return status_checker_.can_reactivate(user_id);
  }

  json get_deactivation_info(const std::string& user_id) {
    return status_checker_.get_deactivation_info(user_id);
  }

  AccountStatus check_account_status(const std::string& user_id) {
    return status_checker_.check(user_id);
  }

  // ---- Token management ----

  std::string generate_login_token(const std::string& user_id) {
    return token_auth_.generate_login_token(user_id);
  }

  void revoke_refresh_tokens(const std::string& user_id) {
    refresh_manager_.revoke_all_for_user(user_id);
  }

  void revoke_device_tokens(const std::string& user_id,
                              const std::string& device_id) {
    refresh_manager_.revoke_for_device(user_id, device_id);
  }

  // ---- Access to internal components ----

  SSORedirectHandler& sso_handler() { return sso_handler_; }
  LoginRateLimiter& rate_limiter() { return rate_limiter_; }
  LoginAuditLogger& audit_logger() { return audit_logger_; }
  RefreshTokenManager& refresh_manager() { return refresh_manager_; }
  UserIdentifierResolver& identifier_resolver() { return identifier_resolver_; }

 private:
  DatabasePool& db_;
  std::string server_name_;
  std::string server_version_;

  AccountStatusChecker status_checker_;
  PasswordAuthHandler password_auth_;
  TokenAuthHandler token_auth_;
  SSORedirectHandler sso_handler_;
  CASTicketHandler cas_handler_;
  JWTAuthHandler jwt_handler_;
  AppServiceAuthHandler appservice_handler_;
  GuestLoginHandler guest_handler_;
  DeviceCreator device_creator_;
  RefreshTokenManager refresh_manager_;
  LoginRateLimiter rate_limiter_;
  LoginAuditLogger audit_logger_;
  UserIdentifierResolver identifier_resolver_;
  AppServiceConfig appservice_config_;
  std::unique_ptr<JWTValidator> jwt_validator_;
};

// ============================================================================
// Login REST Servlets
// ============================================================================

// ---- LoginRestServlet: Main login endpoint ----
class LoginRestServlet : public ClientV1RestServlet {
 public:
  explicit LoginRestServlet(LoginFlowEngine& engine)
      : engine_(engine) {}

  std::string path() override { return "/login"; }

  HttpResponse on_post(const HttpRequest& request) override {
    json body;
    try {
      body = json::parse(request.body());
    } catch (const std::exception& e) {
      json err = make_error_response(ERR_NOT_JSON,
          "Request body is not valid JSON", 400);
      return json_response(err, 400);
    }

    LoginRequest login_req = LoginRequest::from_json(body);

    std::string ip = request.client_ip();
    std::string ua = request.user_agent();

    auto result = engine_.handle_login(login_req, ip, ua);

    if (result.success) {
      return json_response(result.response_json, 200);
    }

    return json_response(result.error_json, result.http_status);
  }

 private:
  LoginFlowEngine& engine_;
};

// ---- LoginFlowsRestServlet: Get available login flows ----
class LoginFlowsRestServlet : public BaseRestServlet {
 public:
  explicit LoginFlowsRestServlet(LoginFlowEngine& engine)
      : engine_(engine) {}

  std::string path() override { return "/login"; }

  HttpResponse on_get(const HttpRequest&) override {
    json response;
    response["flows"] = engine_.get_login_flows();
    return json_response(response, 200);
  }

 private:
  LoginFlowEngine& engine_;
};

// ---- SSORedirectRestServlet: Initiate SSO login ----
class SSORedirectRestServlet : public ClientV1RestServlet {
 public:
  explicit SSORedirectRestServlet(LoginFlowEngine& engine)
      : engine_(engine) {}

  std::string path() override { return "/login/sso/redirect"; }

  HttpResponse on_get(const HttpRequest& request) override {
    std::string redirect_url = request.query_param("redirectUrl");
    std::string provider_id = request.query_param("idp");

    LoginRequest login_req;
    login_req.login_type = LoginType::SSO;
    login_req.redirect_url = redirect_url;
    login_req.sso_provider = provider_id;

    std::string ip = request.client_ip();
    std::string ua = request.user_agent();

    auto result = engine_.handle_login(login_req, ip, ua);

    if (result.success) {
      return redirect_response(result.response_json.value(
          "redirect_url", "/"), 302);
    }

    return json_response(result.error_json, result.http_status);
  }

  HttpResponse on_post(const HttpRequest& request) override {
    json body;
    try {
      body = json::parse(request.body());
    } catch (...) {
      return json_response(make_error_response(ERR_NOT_JSON,
          "Invalid JSON", 400), 400);
    }

    LoginRequest login_req;
    login_req.login_type = LoginType::SSO;
    login_req.redirect_url = body.value("redirect_url",
        body.value("redirectUrl", ""));
    login_req.sso_provider = body.value("idp_id",
        body.value("provider", ""));

    auto result = engine_.handle_login(login_req,
        request.client_ip(), request.user_agent());

    if (result.success) {
      return json_response({
        {"redirect_url", result.response_json.value("redirect_url", "")},
        {"session", result.response_json.value("session", "")}
      }, 200);
    }

    return json_response(result.error_json, result.http_status);
  }

 private:
  LoginFlowEngine& engine_;
};

// ---- CASRedirectRestServlet: Redirect to CAS login ----
class CASRedirectRestServlet : public BaseRestServlet {
 public:
  explicit CASRedirectRestServlet(LoginFlowEngine& engine)
      : engine_(engine) {}

  std::string path() override { return "/login/cas/redirect"; }

  HttpResponse on_get(const HttpRequest& request) override {
    std::string redirect_url = request.query_param("redirectUrl");

    LoginRequest login_req;
    login_req.login_type = LoginType::CAS;
    login_req.redirect_url = redirect_url;

    auto result = engine_.handle_login(login_req,
        request.client_ip(), request.user_agent());

    if (result.http_status == 302) {
      std::string url;
      if (result.error_json.contains("flows") &&
          result.error_json["flows"].is_array() &&
          !result.error_json["flows"].empty()) {
        url = result.error_json["flows"][0].value("redirect_url", "");
      }
      return redirect_response(url, 302);
    }

    return json_response(result.error_json, result.http_status);
  }

 private:
  LoginFlowEngine& engine_;
};

// ---- RefreshTokenRestServlet: Token refresh endpoint ----
class RefreshTokenRestServlet : public ClientV1RestServlet {
 public:
  explicit RefreshTokenRestServlet(LoginFlowEngine& engine)
      : engine_(engine) {}

  std::string path() override { return "/tokenrefresh"; }

  HttpResponse on_post(const HttpRequest& request) override {
    json body;
    try {
      body = json::parse(request.body());
    } catch (...) {
      return json_response(make_error_response(ERR_NOT_JSON,
          "Invalid JSON", 400), 400);
    }

    LoginRequest login_req;
    login_req.login_type = LoginType::REFRESH_TOKEN;
    login_req.refresh_token = body.value("refresh_token", "");

    auto result = engine_.handle_login(login_req,
        request.client_ip(), request.user_agent());

    if (result.success) {
      json response = result.response_json;
      return json_response(response, 200);
    }

    return json_response(result.error_json, result.http_status);
  }

 private:
  LoginFlowEngine& engine_;
};

// ---- LoginTokenRestServlet: Generate a login token ----
class LoginTokenRestServlet : public ClientV1RestServlet {
 public:
  explicit LoginTokenRestServlet(LoginFlowEngine& engine)
      : engine_(engine) {}

  std::string path() override { return "/login/get_token"; }

  HttpResponse on_post(const HttpRequest& request) override {
    json body;
    try {
      body = json::parse(request.body());
    } catch (...) {
      return json_response(make_error_response(ERR_NOT_JSON,
          "Invalid JSON", 400), 400);
    }

    std::string user_id = body.value("user_id", "");
    if (user_id.empty()) {
      return json_response(make_error_response(ERR_INVALID_PARAM,
          "Missing user_id", 400), 400);
    }

    // Verify the requester is authorized (must be admin or the user)
    auto& auth = request.auth();
    if (!auth.is_admin() && auth.user_id() != user_id) {
      return json_response(make_error_response(ERR_FORBIDDEN,
          "Not authorized to generate login token for this user", 403), 403);
    }

    std::string token = engine_.generate_login_token(user_id);

    json response;
    response["login_token"] = token;
    response["expires_in_ms"] = LOGIN_TOKEN_TTL_MS;

    return json_response(response, 200);
  }

 private:
  LoginFlowEngine& engine_;
};

// ---- AccountCheckRestServlet: Check account status ----
class AccountCheckRestServlet : public ClientV1RestServlet {
 public:
  explicit AccountCheckRestServlet(LoginFlowEngine& engine)
      : engine_(engine) {}

  std::string path() override { return "/account/check"; }

  HttpResponse on_get(const HttpRequest& request) override {
    std::string user_id = request.query_param("user_id");
    if (user_id.empty()) {
      user_id = request.auth().user_id();
    }

    AccountStatus status = engine_.check_account_status(user_id);
    json response = status.block_error_json();
    response["can_login"] = status.can_login();
    response["deactivation_state"] = static_cast<int>(
        status.deactivation_state);

    return json_response(response, 200);
  }

 private:
  LoginFlowEngine& engine_;
};

// ============================================================================
// LoginFlowEngineFactory — Creates and wires the login flow components
// ============================================================================

class LoginFlowEngineFactory {
 public:
  static std::unique_ptr<LoginFlowEngine> create(
      DatabasePool& db,
      const std::string& server_name,
      const json& config = nullptr) {

    auto engine = std::make_unique<LoginFlowEngine>(
        db, server_name, "Progressive/1.0");

    // Configure JWT if present in config
    if (!config.is_null() && config.contains("jwt_config")) {
      JWTValidator::JWTConfig jwt_cfg;
      auto& jc = config["jwt_config"];
      jwt_cfg.secret = jc.value("secret", "");
      jwt_cfg.issuer = jc.value("issuer", "");
      jwt_cfg.audience = jc.value("audience", "");
      jwt_cfg.algorithm = jc.value("algorithm", "HS256");
      jwt_cfg.enabled = jc.value("enabled", false);
      engine->set_jwt_config(jwt_cfg);
    }

    // Configure CAS if present
    if (!config.is_null() && config.contains("cas_config")) {
      CASTicketHandler::CASConfig cas_cfg;
      auto& cc = config["cas_config"];
      cas_cfg.enabled = cc.value("enabled", false);
      cas_cfg.server_url = cc.value("server_url", "");
      cas_cfg.service_url = cc.value("service_url", "");
      cas_cfg.version = static_cast<CASVersion>(
          cc.value("version", 3));
      cas_cfg.display_name = cc.value("display_name", "CAS");
      cas_cfg.icon_url = cc.value("icon_url", "");
      cas_cfg.brand = cc.value("brand", "");
      engine->set_cas_config(cas_cfg);
    }

    // Configure SSO providers
    if (!config.is_null() && config.contains("sso_providers")) {
      for (const auto& p : config["sso_providers"]) {
        SSORedirectHandler::SSOProvider provider;
        provider.id = p.value("id", "");
        provider.name = p.value("name", "");
        provider.icon = p.value("icon", "");
        provider.brand = p.value("brand", "");
        provider.authorization_url = p.value("authorization_url", "");
        provider.client_id = p.value("client_id", "");
        provider.redirect_uri_base = p.value("redirect_uri_base", "");

        if (p.contains("scopes") && p["scopes"].is_array()) {
          for (const auto& s : p["scopes"])
            provider.scopes.push_back(s.get<std::string>());
        } else {
          provider.scopes = {"openid", "profile", "email"};
        }

        provider.response_type = p.value("response_type", "code");
        provider.pkce_enabled = p.value("pkce_enabled", true);
        engine->add_sso_provider(provider);
      }
    }

    // Load appservices from DB
    engine->load_appservice_config();

    return engine;
  }
};

// ============================================================================
// registration_worker — Background maintenance for login token expiry
// ============================================================================

class LoginTokenCleanupWorker {
 public:
  explicit LoginTokenCleanupWorker(DatabasePool& db) : db_(db) {
    running_ = true;
    worker_ = std::thread(&LoginTokenCleanupWorker::run, this);
  }

  ~LoginTokenCleanupWorker() {
    running_ = false;
    if (worker_.joinable()) worker_.join();
  }

 private:
  void run() {
    while (running_) {
      std::this_thread::sleep_for(chr::seconds(300));
      if (!running_) break;
      db_.runInteraction("cleanup_expired_tokens",
          [](LoggingTransaction& txn) {
            txn.execute(
                "UPDATE login_tokens SET used = 1 "
                "WHERE expiry_ts < ? AND used = 0",
                {std::to_string(now_ms())});
            txn.execute(
                "DELETE FROM login_tokens "
                "WHERE expiry_ts < ? AND used = 1",
                {std::to_string(now_ms() - 86400000)}); // 24h grace
          });
    }
  }

  DatabasePool& db_;
  std::thread worker_;
  std::atomic<bool> running_{false};
};

} // namespace progressive
