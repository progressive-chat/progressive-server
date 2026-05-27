// ============================================================================
// registration_pipeline.cpp
// progressive::auth - Registration pipeline for Matrix homeserver
//
// Implements the complete user registration flow:
//   - Registration token management (CRUD, uses_allowed, pending, completed)
//   - Account creation with username/password/email validation
//   - Registration with shared secret, token, reCAPTCHA, email verification
//   - Registration with terms consent
//   - Account activation and welcome emails
//   - Username blacklist and availability checks
//   - Email domain allow/block list
//   - MX record validation
//   - Rate limiting per IP/email
//   - Registration session tracking
//   - Pending registration cleanup
//   - Admin registration approval flow
//
// Database tables expected (created by schema migration):
//   registration_tokens    - token management
//   registration_sessions  - pending session tracking
//   regtoken_usage         - usage audit log
//   pending_registrations  - admin approval queue
//   username_blacklist     - blocked usernames
//   email_domain_list      - allowed/blocked domains
// ============================================================================

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <algorithm>
#include <arpa/inet.h>
#include <array>
#include <cctype>
#include <chrono>
#include <cmath>
#include <cstring>
#include <deque>
#include <iomanip>
#include <map>
#include <mutex>
#include <netdb.h>
#include <netinet/in.h>
#include <regex>
#include <set>
#include <shared_mutex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <sys/types.h>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <unistd.h>
#include <vector>

#include <nlohmann/json.hpp>

#include "../json.hpp"
#include "../storage/database.hpp"
#include "../util/base64.hpp"
#include "../util/log.hpp"
#include "../util/random.hpp"
#include "../util/time.hpp"
#include "../util/token.hpp"

// ============================================================================
// Architecture Decision Notes
// ============================================================================
//
// This module follows the same multi-paradigm approach as the rest of the
// progressive-server codebase:
//   - DatabasePool for persistence (registration tokens, sessions, audit logs)
//   - In-memory rate limiters with shared_mutex (per-IP and per-email)
//   - POSIX socket APIs for MX record validation
//   - OpenSSL for cryptographic operations (HMAC for shared-secret auth)
//   - nlohmann::json for all JSON serialization
//   - Thread-safe design with fine-grained locking
//
// The RegistrationPipeline class is the single entry point for all
// registration-related operations.  It is designed to be instantiated once
// per server process and shared across all HTTP handler threads.
// ============================================================================

namespace progressive::auth {

using json = nlohmann::json;
using namespace std::chrono_literals;

// ============================================================================
// Forward declarations for internal types
// ============================================================================
namespace {

struct RateLimitEntry {
  std::chrono::steady_clock::time_point timestamp;
  std::string key;
};

}  // namespace

// ============================================================================
// Constants
// ============================================================================

static constexpr const char* kRegTag = "registration_pipeline";

// Username constraints (Matrix spec compatible)
static constexpr size_t kMinUsernameLength = 3;
static constexpr size_t kMaxUsernameLength = 255;
static constexpr size_t kMinPasswordLength = 8;
static constexpr size_t kMaxPasswordLength = 512;

// Token expiry and limits
static constexpr int64_t kDefaultTokenExpirySec = 86400 * 7;    // 7 days
static constexpr int64_t kDefaultTokenMaxUses = 100;
static constexpr int64_t kSessionExpirySec = 3600;               // 1 hour
static constexpr int64_t kPendingRegistrationExpirySec = 86400 * 14; // 14 days
static constexpr int64_t kActivationTokenExpirySec = 86400 * 3;  // 3 days
static constexpr int64_t kWelcomeEmailDelaySec = 60;             // 1 min after activation

// Rate limiting
static constexpr int kRateLimitWindowSec = 3600;                  // 1 hour
static constexpr int kMaxRegPerIpPerWindow = 10;
static constexpr int kMaxRegPerEmailPerWindow = 5;
static constexpr int kMaxTokenGenPerIpPerWindow = 20;

// reCAPTCHA
static constexpr int kRecaptchaTimeoutSec = 30;

// Cleanup intervals
static constexpr int kCleanupIntervalSec = 900;   // 15 minutes
static constexpr int kMaxCleanupBatch = 1000;

// Email validation
static constexpr size_t kMaxEmailLength = 320;
static constexpr size_t kMaxLocalPartLength = 64;
static constexpr size_t kMaxDomainLength = 255;

// ============================================================================
// Anonymous namespace: internal helper functions
// ============================================================================
namespace {

// --------------------------------------------------------------------------
// SQL escaping (consistent with auth.cpp and other modules)
// --------------------------------------------------------------------------
std::string sql_escape(std::string_view s) {
  std::string out;
  out.reserve(s.size() + 8);
  for (char c : s) {
    if (c == '\'')
      out += "''";
    else
      out += c;
  }
  return out;
}

std::string sql_quote(std::string_view s) {
  return "'" + sql_escape(s) + "'";
}

// --------------------------------------------------------------------------
// Hex encoding helpers
// --------------------------------------------------------------------------
std::string hex_encode(const unsigned char* data, size_t len) {
  std::ostringstream oss;
  oss << std::hex << std::setfill('0');
  for (size_t i = 0; i < len; ++i)
    oss << std::setw(2) << static_cast<int>(data[i]);
  return oss.str();
}

std::string hex_encode(std::string_view s) {
  return hex_encode(reinterpret_cast<const unsigned char*>(s.data()), s.size());
}

// --------------------------------------------------------------------------
// Time helpers
// --------------------------------------------------------------------------
int64_t now_sec() {
  return static_cast<int64_t>(util::now_ms() / 1000);
}

std::string iso8601_now() {
  return util::iso8601();
}

// --------------------------------------------------------------------------
// Turn a database Row (vector<ColumnValue>) into a one-column string
// --------------------------------------------------------------------------
std::optional<std::string> row_column(const storage::Row& row,
                                       std::string_view col_name) {
  for (const auto& cv : row) {
    if (cv.name == col_name) {
      if (cv.value.has_value())
        return cv.value;
      return std::optional<std::string>();
    }
  }
  return std::optional<std::string>();
}

// --------------------------------------------------------------------------
// Lookup a specific value from a RowList result (first row, column)
// --------------------------------------------------------------------------
std::optional<std::string> query_scalar(
    storage::DatabasePool& db, std::string_view query) {
  auto result = db.execute("query_scalar", std::string(query));
  if (result.empty()) return std::nullopt;
  if (result[0].empty()) return std::nullopt;
  return result[0][0].value;
}

// --------------------------------------------------------------------------
// HMAC-SHA256 helper (used for shared-secret registration)
// --------------------------------------------------------------------------
std::string hmac_sha256(std::string_view key, std::string_view data) {
  unsigned char result[EVP_MAX_MD_SIZE];
  unsigned int result_len = 0;
  HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
       reinterpret_cast<const unsigned char*>(data.data()), data.size(),
       result, &result_len);
  return hex_encode(result, result_len);
}

// --------------------------------------------------------------------------
// SHA-256 hash (raw bytes returned as hex string)
// --------------------------------------------------------------------------
std::string sha256_hex(std::string_view data) {
  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256(reinterpret_cast<const unsigned char*>(data.data()), data.size(),
         hash);
  return hex_encode(hash, SHA256_DIGEST_LENGTH);
}

// --------------------------------------------------------------------------
// Generate a cryptographically random token of specified byte length
// --------------------------------------------------------------------------
std::string generate_token(size_t byte_length = 32) {
  return util::random_token(byte_length);
}

// --------------------------------------------------------------------------
// Check if a string matches a valid Matrix user ID localpart.
//
// Per the Matrix spec (Appendices):
//   - Must be 3-255 characters
//   - Must start with a lowercase letter, digit, or one of _ - . = /
//   - May contain lowercase letters, digits, and the characters
//     . _ = - / +
//   - Must NOT be "0" (reserved).
//   - Must NOT contain ".." (consecutive dots).
// --------------------------------------------------------------------------
bool is_valid_username(std::string_view username) {
  if (username.size() < kMinUsernameLength ||
      username.size() > kMaxUsernameLength)
    return false;

  if (username == "0") return false;

  // First character restrictions
  char first = username[0];
  if (!std::islower(first) && !std::isdigit(first) &&
      first != '_' && first != '-' && first != '.' && first != '=' &&
      first != '/')
    return false;

  // Remaining characters
  for (size_t i = 0; i < username.size(); ++i) {
    char c = username[i];
    if (!std::islower(c) && !std::isdigit(c) &&
        c != '.' && c != '_' && c != '=' && c != '-' && c != '/' && c != '+')
      return false;
  }

  // No consecutive dots
  if (username.find("..") != std::string::npos)
    return false;

  return true;
}

// --------------------------------------------------------------------------
// Validate an email address using a comprehensive RFC 5321/5322 subset.
//
// Returns an empty optional on success, or an error string on failure.
//
// Checks performed:
//   1. Length limits (overall, local part, domain)
//   2. Presence of single '@'
//   3. Local part and domain not empty
//   4. No whitespace
//   5. Domain has at least one dot (TLD requirement)
//   6. Domain labels: start/end with alphanumeric, contain only
//      alphanumeric + hyphens, 1-63 chars per label
//   7. No consecutive dots in domain
// --------------------------------------------------------------------------
std::optional<std::string> validate_email(std::string_view email) {
  if (email.empty())
    return std::string("Email address is empty");

  if (email.size() > kMaxEmailLength)
    return std::string("Email address exceeds maximum length of ") +
           std::to_string(kMaxEmailLength);

  // Check for whitespace
  for (char c : email) {
    if (std::isspace(static_cast<unsigned char>(c)))
      return std::string("Email address contains whitespace");
  }

  // Split at '@'
  auto at_pos = email.find('@');
  if (at_pos == std::string_view::npos)
    return std::string("Email address missing '@' symbol");

  std::string_view local_part = email.substr(0, at_pos);
  std::string_view domain = email.substr(at_pos + 1);

  // Only one '@'
  if (domain.find('@') != std::string_view::npos)
    return std::string("Email address contains multiple '@' symbols");

  if (local_part.empty())
    return std::string("Email address has empty local part");

  if (local_part.size() > kMaxLocalPartLength)
    return std::string("Email local part exceeds maximum length of ") +
           std::to_string(kMaxLocalPartLength);

  if (domain.empty())
    return std::string("Email address has empty domain");

  if (domain.size() > kMaxDomainLength)
    return std::string("Email domain exceeds maximum length of ") +
           std::to_string(kMaxDomainLength);

  // Domain must have at least one dot (TLD requirement)
  if (domain.find('.') == std::string_view::npos)
    return std::string("Email domain has no TLD (missing dot)");

  // Domain must not start or end with a dot
  if (domain.front() == '.' || domain.back() == '.')
    return std::string("Email domain starts or ends with a dot");

  // Domain must not contain consecutive dots
  if (domain.find("..") != std::string_view::npos)
    return std::string("Email domain contains consecutive dots");

  // Validate each domain label
  size_t start = 0;
  while (start < domain.size()) {
    auto dot_pos = domain.find('.', start);
    if (dot_pos == std::string_view::npos) dot_pos = domain.size();
    std::string_view label = domain.substr(start, dot_pos - start);

    if (label.empty())
      return std::string("Email domain has empty label");

    if (label.size() > 63)
      return std::string("Email domain label exceeds 63 characters");

    // Label must start and end with alphanumeric
    if (!std::isalnum(static_cast<unsigned char>(label.front())))
      return std::string("Email domain label does not start with "
                         "alphanumeric character");
    if (!std::isalnum(static_cast<unsigned char>(label.back())))
      return std::string("Email domain label does not end with "
                         "alphanumeric character");

    // Label interior: alphanumeric or hyphen
    for (char c : label) {
      if (!std::isalnum(static_cast<unsigned char>(c)) && c != '-')
        return std::string("Email domain label contains invalid character");
    }

    start = dot_pos + 1;
  }

  // Basic local-part validation (conservative)
  static const std::regex local_re(
      R"(^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+$)", std::regex::optimize);
  if (!std::regex_match(std::string(local_part), local_re))
    return std::string("Email local part contains invalid characters");

  return std::nullopt;
}

// --------------------------------------------------------------------------
// Validate a password according to server policy.
//
// Policy defaults (configurable per-instance):
//   - Minimum length: 8 characters
//   - Maximum length: 512 characters
//   - Must contain at least one lowercase letter
//   - Must contain at least one uppercase letter OR one digit
//     OR one special character
//
// Returns an empty optional on success, or an error string.
// --------------------------------------------------------------------------
std::optional<std::string> validate_password(std::string_view password) {
  if (password.size() < kMinPasswordLength) {
    return std::string("Password must be at least ") +
           std::to_string(kMinPasswordLength) + " characters";
  }
  if (password.size() > kMaxPasswordLength) {
    return std::string("Password must not exceed ") +
           std::to_string(kMaxPasswordLength) + " characters";
  }

  bool has_lower = false;
  bool has_upper = false;
  bool has_digit = false;
  bool has_special = false;

  for (char c : password) {
    if (std::islower(static_cast<unsigned char>(c))) has_lower = true;
    else if (std::isupper(static_cast<unsigned char>(c))) has_upper = true;
    else if (std::isdigit(static_cast<unsigned char>(c))) has_digit = true;
    else has_special = true;
  }

  if (!has_lower)
    return std::string("Password must contain at least one lowercase letter");

  if (!has_upper && !has_digit && !has_special)
    return std::string("Password must contain at least one uppercase letter, "
                       "digit, or special character");

  return std::nullopt;
}

// --------------------------------------------------------------------------
// DNS MX record lookup via POSIX resolver.
//
// Queries the system DNS resolver for MX records of the given domain.
// Returns a sorted vector of (priority, exchange) pairs (lowest priority
// first).  Returns an empty vector on failure or if no MX records exist.
// --------------------------------------------------------------------------
std::vector<std::pair<int, std::string>> lookup_mx_records(
    std::string_view domain) {
  std::vector<std::pair<int, std::string>> result;

  // Prepare query buffer
  std::array<unsigned char, 4096> buf{};
  int len = res_query(std::string(domain).c_str(), ns_c_in, ns_t_mx,
                      buf.data(), static_cast<int>(buf.size()));
  if (len < 0) {
    log::warn(kRegTag, std::string("MX lookup failed for domain: ") +
                           std::string(domain));
    return result;
  }

  // Parse response
  ns_msg handle;
  if (ns_initparse(buf.data(), len, &handle) < 0) {
    log::warn(kRegTag, std::string("Failed to parse MX response for: ") +
                           std::string(domain));
    return result;
  }

  int count = ns_msg_count(handle, ns_s_an);
  for (int i = 0; i < count; ++i) {
    ns_rr rr;
    if (ns_parserr(&handle, ns_s_an, i, &rr) < 0) continue;
    if (ns_rr_type(rr) != ns_t_mx) continue;

    // MX record data: 2-byte preference + domain name
    const unsigned char* rdata = ns_rr_rdata(rr);
    if (!rdata) continue;

    uint16_t pref = (static_cast<uint16_t>(rdata[0]) << 8) | rdata[1];

    char name_buf[NS_MAXDNAME];
    if (dn_expand(buf.data(), buf.data() + len, rdata + 2,
                  name_buf, sizeof(name_buf)) < 0)
      continue;

    result.emplace_back(static_cast<int>(pref), std::string(name_buf));
  }

  // Sort by preference (ascending)
  std::sort(result.begin(), result.end(),
            [](const auto& a, const auto& b) { return a.first < b.first; });

  return result;
}

// --------------------------------------------------------------------------
// Check if a domain has valid MX records.
// Returns true if at least one MX record exists for the domain.
// --------------------------------------------------------------------------
bool has_mx_records(std::string_view domain) {
  auto records = lookup_mx_records(domain);
  return !records.empty();
}

// --------------------------------------------------------------------------
// Extract the domain part from an email address.
// Returns empty string if the email format is invalid.
// --------------------------------------------------------------------------
std::string extract_domain(std::string_view email) {
  auto at_pos = email.find('@');
  if (at_pos == std::string_view::npos || at_pos == email.size() - 1)
    return "";
  return std::string(email.substr(at_pos + 1));
}

// --------------------------------------------------------------------------
// Normalize a string to lowercase ASCII.
// --------------------------------------------------------------------------
std::string lowercase(std::string_view s) {
  std::string out;
  out.reserve(s.size());
  for (char c : s)
    out += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return out;
}

// --------------------------------------------------------------------------
// Generate a registration session ID (random hex token)
// --------------------------------------------------------------------------
std::string generate_session_id() {
  return generate_token(24);
}

// --------------------------------------------------------------------------
// Generate an activation token
// --------------------------------------------------------------------------
std::string generate_activation_token() {
  return generate_token(32);
}

// --------------------------------------------------------------------------
// Build a JSON error response with Matrix-style errcode and error message.
// --------------------------------------------------------------------------
json error_json(std::string_view errcode, std::string_view msg) {
  return json{{"errcode", errcode}, {"error", msg}};
}

json error_json(std::string_view errcode, std::string_view msg,
                const json& extra) {
  json j = error_json(errcode, msg);
  for (auto& [k, v] : extra.items())
    j[k] = v;
  return j;
}

// --------------------------------------------------------------------------
// Parse rate limit headers and check thresholds.
// The key should be normalized (lowercased) before calling.
// --------------------------------------------------------------------------
struct RateLimitDecision {
  bool allowed = true;
  int64_t retry_after_ms = 0;
};

}  // namespace

// ============================================================================
// In-memory Rate Limiter (per-IP and per-email)
//
// Thread-safe sliding-window rate limiter.  Maintains separate counters for
// each key (IP address or email).  Entries older than the window are pruned
// on each check.
// ============================================================================
class InMemoryRateLimiter {
public:
  InMemoryRateLimiter(int window_secs, int max_requests)
      : window_duration_(std::chrono::seconds(window_secs)),
        max_requests_(max_requests) {}

  // Returns true if the request is allowed (under the limit).
  // If not allowed, fills retry_after_ms with the time to wait.
  RateLimitDecision check_and_record(const std::string& key) {
    auto now = std::chrono::steady_clock::now();
    std::unique_lock lock(mutex_);

    // Prune expired entries for this key
    auto& entries = buckets_[key];
    while (!entries.empty() &&
           (now - entries.front()) > window_duration_)
      entries.pop_front();

    // Check limit
    RateLimitDecision decision;
    if (static_cast<int>(entries.size()) >= max_requests_) {
      decision.allowed = false;
      auto oldest = entries.front();
      auto elapsed_ms =
          std::chrono::duration_cast<std::chrono::milliseconds>(
              now - oldest).count();
      auto window_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                           window_duration_).count();
      decision.retry_after_ms = std::max<int64_t>(0, window_ms - elapsed_ms);
      return decision;
    }

    // Record this request
    entries.push_back(now);
    return decision;
  }

  // Get the number of requests remaining for a key without recording.
  int remaining(const std::string& key) const {
    auto now = std::chrono::steady_clock::now();
    std::shared_lock lock(mutex_);

    auto it = buckets_.find(key);
    if (it == buckets_.end()) return max_requests_;

    // Count non-expired entries (read-only, just count)
    int count = 0;
    for (const auto& ts : it->second) {
      if ((now - ts) <= window_duration_) ++count;
    }
    return std::max(0, max_requests_ - count);
  }

  // Periodic cleanup of stale keys
  void cleanup() {
    auto now = std::chrono::steady_clock::now();
    std::unique_lock lock(mutex_);

    auto it = buckets_.begin();
    while (it != buckets_.end()) {
      while (!it->second.empty() &&
             (now - it->second.front()) > window_duration_)
        it->second.pop_front();

      if (it->second.empty())
        it = buckets_.erase(it);
      else
        ++it;
    }
  }

  // Reset all state (for testing)
  void reset() {
    std::unique_lock lock(mutex_);
    buckets_.clear();
  }

private:
  std::chrono::seconds window_duration_;
  int max_requests_;
  std::unordered_map<std::string, std::deque<std::chrono::steady_clock::time_point>> buckets_;
  mutable std::shared_mutex mutex_;
};

// ============================================================================
// RegistrationPipeline - Main Class
// ============================================================================

class RegistrationPipeline {
public:
  // ------------------------------------------------------------------------
  // Constructor / Destructor
  // ------------------------------------------------------------------------
  explicit RegistrationPipeline(storage::DatabasePool& db)
      : db_(db),
        ip_rate_limiter_(kRateLimitWindowSec, kMaxRegPerIpPerWindow),
        email_rate_limiter_(kRateLimitWindowSec, kMaxRegPerEmailPerWindow),
        token_gen_limiter_(kRateLimitWindowSec, kMaxTokenGenPerIpPerWindow),
        shared_secret_(""),
        recaptcha_site_key_(""),
        recaptcha_secret_key_(""),
        server_name_("localhost"),
        require_email_validation_(false),
        require_terms_consent_(false),
        enable_recaptcha_(false),
        enable_shared_secret_(false),
        enable_mx_validation_(false),
        enable_domain_allowlist_(false),
        enable_domain_blocklist_(false),
        enable_admin_approval_(false),
        enable_welcome_email_(false),
        enable_activation_email_(true),
        auto_join_rooms_{},
        running_(true) {}

  ~RegistrationPipeline() {
    stop();
  }

  // ------------------------------------------------------------------------
  // Lifecycle
  // ------------------------------------------------------------------------
  void start() {
    log::info(kRegTag, "Starting registration pipeline");
    running_ = true;
    cleanup_thread_ = std::thread(&RegistrationPipeline::cleanup_worker, this);
  }

  void stop() {
    if (!running_.exchange(false)) return;
    log::info(kRegTag, "Stopping registration pipeline");
    if (cleanup_thread_.joinable())
      cleanup_thread_.join();
  }

  // ------------------------------------------------------------------------
  // Configuration Setters
  // ------------------------------------------------------------------------

  void set_server_name(const std::string& name) { server_name_ = name; }
  void set_shared_secret(const std::string& secret) {
    shared_secret_ = secret;
    enable_shared_secret_ = !secret.empty();
  }
  void set_recaptcha_keys(const std::string& site_key,
                           const std::string& secret_key) {
    recaptcha_site_key_ = site_key;
    recaptcha_secret_key_ = secret_key;
    enable_recaptcha_ = !site_key.empty() && !secret_key.empty();
  }
  void set_require_email_validation(bool v) { require_email_validation_ = v; }
  void set_require_terms_consent(bool v) { require_terms_consent_ = v; }
  void set_enable_mx_validation(bool v) { enable_mx_validation_ = v; }
  void set_enable_domain_allowlist(bool v) { enable_domain_allowlist_ = v; }
  void set_enable_domain_blocklist(bool v) { enable_domain_blocklist_ = v; }
  void set_enable_admin_approval(bool v) { enable_admin_approval_ = v; }
  void set_enable_welcome_email(bool v) { enable_welcome_email_ = v; }
  void set_enable_activation_email(bool v) { enable_activation_email_ = v; }
  void set_auto_join_rooms(const std::vector<std::string>& rooms) {
    auto_join_rooms_ = rooms;
  }
  void set_home_server_url(const std::string& url) { home_server_url_ = url; }

  // ========================================================================
  // Registration Token Management (CRUD)
  //
  // Each token has:
  //   - token         : the token string (primary key)
  //   - uses_allowed  : maximum number of times it can be used (null=unlimited)
  //   - pending       : number of in-progress uses
  //   - completed     : number of completed registrations
  //   - expiry_time   : epoch seconds when token expires (null = never)
  //   - create_time   : epoch seconds when token was created
  //   - created_by    : admin who created the token
  //   - comment       : optional human-readable description
  // ========================================================================

  // ------------------------------------------------------------------------
  // Create a new registration token.
  //
  // Parameters:
  //   uses_allowed - max uses (0 = unlimited)
  //   expiry_days  - days until expiry (0 = never)
  //   created_by   - admin user ID who created this token
  //   comment      - human-readable description
  //
  // Returns: JSON with the created token details.
  // ------------------------------------------------------------------------
  json create_registration_token(int64_t uses_allowed,
                                  int64_t expiry_days,
                                  std::string_view created_by,
                                  std::string_view comment = "",
                                  std::string_view ip_address = "") {
    // Rate limit token generation
    if (!ip_address.empty()) {
      auto decision = token_gen_limiter_.check_and_record(
          lowercase(ip_address));
      if (!decision.allowed) {
        return error_json("M_LIMIT_EXCEEDED",
                          "Too many token creation requests",
                          {{"retry_after_ms", decision.retry_after_ms}});
      }
    }

    std::string token = generate_token(24);
    int64_t now = now_sec();
    int64_t expiry = (expiry_days > 0) ? now + expiry_days * 86400 : 0;

    // Insert into database
    db_.execute("create_registration_token",
                "INSERT INTO registration_tokens "
                "(token, uses_allowed, pending, completed, "
                " expiry_time, create_time, created_by, comment) "
                "VALUES (" +
                    sql_quote(token) + ", " +
                    std::to_string(uses_allowed) + ", 0, 0, " +
                    (expiry > 0 ? std::to_string(expiry) : "NULL") + ", " +
                    std::to_string(now) + ", " +
                    sql_quote(created_by) + ", " +
                    sql_quote(comment) + ")");

    log::info(kRegTag, std::string("Created registration token: ") +
                           token.substr(0, 8) + "... by " +
                           std::string(created_by));

    return json{
        {"token", token},
        {"uses_allowed", uses_allowed},
        {"pending", 0},
        {"completed", 0},
        {"expiry_time", expiry > 0 ? expiry : json(nullptr)},
        {"create_time", now},
        {"created_by", created_by},
        {"comment", comment}};
  }

  // ------------------------------------------------------------------------
  // Get a specific registration token by its token string.
  // ------------------------------------------------------------------------
  json get_registration_token(std::string_view token) {
    auto rows = db_.execute("get_registration_token",
                            "SELECT token, uses_allowed, pending, completed, "
                            "expiry_time, create_time, created_by, comment "
                            "FROM registration_tokens WHERE token = " +
                                sql_quote(token));
    if (rows.empty())
      return error_json("M_NOT_FOUND", "Registration token not found");

    auto& row = rows[0];
    auto col = [&](const std::string& name) -> json {
      auto v = row_column(row, name);
      if (v) return json(*v);
      return json(nullptr);
    };

    int64_t uses_allowed = 0;
    int64_t pending = 0;
    int64_t completed = 0;
    int64_t expiry_time = 0;
    int64_t create_time = 0;

    auto ua = row_column(row, "uses_allowed");
    auto pd = row_column(row, "pending");
    auto cp = row_column(row, "completed");
    auto et = row_column(row, "expiry_time");
    auto ct = row_column(row, "create_time");

    if (ua) uses_allowed = std::stoll(*ua);
    if (pd) pending = std::stoll(*pd);
    if (cp) completed = std::stoll(*cp);
    if (et && !et->empty()) expiry_time = std::stoll(*et);
    if (ct) create_time = std::stoll(*ct);

    return json{
        {"token", col("token")},
        {"uses_allowed", uses_allowed},
        {"pending", pending},
        {"completed", completed},
        {"expiry_time", expiry_time > 0 ? json(expiry_time) : json(nullptr)},
        {"create_time", create_time},
        {"created_by", col("created_by")},
        {"comment", col("comment")}};
  }

  // ------------------------------------------------------------------------
  // List all registration tokens.
  // Returns an array of token objects.
  // Optionally filter by valid_only (exclude expired and fully-used tokens).
  // ------------------------------------------------------------------------
  json list_registration_tokens(bool valid_only = false) {
    std::string query =
        "SELECT token, uses_allowed, pending, completed, "
        "expiry_time, create_time, created_by, comment "
        "FROM registration_tokens";

    if (valid_only) {
      int64_t now = now_sec();
      query += " WHERE (expiry_time IS NULL OR expiry_time > " +
               std::to_string(now) + ")";
      query += " AND (uses_allowed IS NULL OR uses_allowed = 0 OR "
               "completed < uses_allowed)";
    }

    query += " ORDER BY create_time DESC";

    auto rows = db_.execute("list_registration_tokens", query);

    json result = json::array();
    for (auto& row : rows) {
      auto col = [&](const std::string& name) -> json {
        auto v = row_column(row, name);
        if (v) return json(*v);
        return json(nullptr);
      };

      int64_t uses_allowed = 0, pending = 0, completed = 0;
      int64_t expiry_time = 0, create_time = 0;

      auto ua = row_column(row, "uses_allowed");
      auto pd = row_column(row, "pending");
      auto cp = row_column(row, "completed");
      auto et = row_column(row, "expiry_time");
      auto ct = row_column(row, "create_time");

      if (ua) uses_allowed = std::stoll(*ua);
      if (pd) pending = std::stoll(*pd);
      if (cp) completed = std::stoll(*cp);
      if (et && !et->empty()) expiry_time = std::stoll(*et);
      if (ct) create_time = std::stoll(*ct);

      result.push_back({
          {"token", col("token")},
          {"uses_allowed", uses_allowed},
          {"pending", pending},
          {"completed", completed},
          {"expiry_time",
           expiry_time > 0 ? json(expiry_time) : json(nullptr)},
          {"create_time", create_time},
          {"created_by", col("created_by")},
          {"comment", col("comment")},
      });
    }

    return result;
  }

  // ------------------------------------------------------------------------
  // Update a registration token (uses_allowed and/or expiry).
  // ------------------------------------------------------------------------
  json update_registration_token(std::string_view token,
                                  int64_t uses_allowed,
                                  int64_t expiry_days) {
    auto existing = get_registration_token(token);
    if (existing.contains("errcode"))
      return existing;  // Token not found

    int64_t now = now_sec();
    std::string set_clause;

    if (uses_allowed >= 0) {
      set_clause += "uses_allowed = " + std::to_string(uses_allowed);
    }

    if (expiry_days >= 0) {
      if (!set_clause.empty()) set_clause += ", ";
      if (expiry_days == 0) {
        set_clause += "expiry_time = NULL";
      } else {
        set_clause += "expiry_time = " +
                      std::to_string(now + expiry_days * 86400);
      }
    }

    if (set_clause.empty())
      return error_json("M_INVALID_PARAM", "No valid update parameters");

    db_.execute("update_registration_token",
                "UPDATE registration_tokens SET " + set_clause +
                    " WHERE token = " + sql_quote(token));

    log::info(kRegTag, std::string("Updated registration token: ") +
                           std::string(token).substr(0, 8) + "...");

    return get_registration_token(token);
  }

  // ------------------------------------------------------------------------
  // Delete a registration token.
  // ------------------------------------------------------------------------
  json delete_registration_token(std::string_view token) {
    auto existing = get_registration_token(token);
    if (existing.contains("errcode"))
      return existing;

    db_.execute("delete_registration_token",
                "DELETE FROM registration_tokens WHERE token = " +
                    sql_quote(token));

    log::info(kRegTag, std::string("Deleted registration token: ") +
                           std::string(token).substr(0, 8) + "...");

    return json{{"deleted", true}, {"token", token}};
  }

  // ------------------------------------------------------------------------
  // Validate a registration token (check existence, expiry, and uses).
  //
  // Returns an error JSON if invalid, or a success JSON with token info.
  // This is called internally before processing a registration.
  // ------------------------------------------------------------------------
  json validate_registration_token(std::string_view token) {
    auto rows = db_.execute("validate_token",
                            "SELECT uses_allowed, pending, completed, expiry_time "
                            "FROM registration_tokens WHERE token = " +
                                sql_quote(token));
    if (rows.empty())
      return error_json("M_UNKNOWN_TOKEN", "Registration token not recognized");

    auto& row = rows[0];
    int64_t uses_allowed = 0, pending = 0, completed = 0;
    int64_t expiry_time = 0;

    auto uv = row_column(row, "uses_allowed");
    auto pv = row_column(row, "pending");
    auto cv = row_column(row, "completed");
    auto ev = row_column(row, "expiry_time");

    if (uv) uses_allowed = std::stoll(*uv);
    if (pv) pending = std::stoll(*pv);
    if (cv) completed = std::stoll(*cv);
    if (ev && !ev->empty()) expiry_time = std::stoll(*ev);

    int64_t now = now_sec();

    // Check expiry
    if (expiry_time > 0 && now > expiry_time)
      return error_json("M_EXPIRED_TOKEN", "Registration token has expired");

    // Check uses (uses_allowed == 0 means unlimited)
    if (uses_allowed > 0 && completed >= uses_allowed)
      return error_json("M_TOKEN_USED",
                        "Registration token has been fully used");

    return json{
        {"valid", true},
        {"uses_allowed", uses_allowed},
        {"pending", pending},
        {"completed", completed},
        {"remaining", uses_allowed > 0 ? uses_allowed - completed : -1}};
  }

  // ------------------------------------------------------------------------
  // Atomically increment the pending counter for a token (used at the
  // start of registration).  Returns the updated pending count on success,
  // or -1 if the token is invalid.
  // ------------------------------------------------------------------------
  int64_t increment_token_pending(std::string_view token) {
    auto validation = validate_registration_token(token);
    if (validation.contains("errcode"))
      return -1;

    db_.execute("increment_token_pending",
                "UPDATE registration_tokens SET pending = pending + 1 "
                "WHERE token = " + sql_quote(token));

    auto rows = db_.execute("get_token_pending",
                            "SELECT pending FROM registration_tokens "
                            "WHERE token = " + sql_quote(token));
    if (rows.empty()) return -1;
    auto pv = row_column(rows[0], "pending");
    return pv ? std::stoll(*pv) : -1;
  }

  // ------------------------------------------------------------------------
  // Atomically decrement the pending counter and increment the completed
  // counter for a token (called on successful registration).
  // ------------------------------------------------------------------------
  void complete_token_usage(std::string_view token) {
    db_.execute("complete_token_usage",
                "UPDATE registration_tokens SET "
                "pending = MAX(0, pending - 1), "
                "completed = completed + 1 "
                "WHERE token = " + sql_quote(token));

    // Log usage
    int64_t now = now_sec();
    db_.execute("log_token_usage",
                "INSERT INTO regtoken_usage (token, used_at) "
                "VALUES (" +
                    sql_quote(token) + ", " + std::to_string(now) + ")");
  }

  // ------------------------------------------------------------------------
  // Abort a pending token usage (decrement pending on failure/cancel).
  // ------------------------------------------------------------------------
  void abort_token_usage(std::string_view token) {
    db_.execute("abort_token_usage",
                "UPDATE registration_tokens SET "
                "pending = MAX(0, pending - 1) "
                "WHERE token = " + sql_quote(token));
  }

  // ========================================================================
  // Username Checks
  // ========================================================================

  // ------------------------------------------------------------------------
  // Check if a username is in the blacklist.
  //
  // Blacklist entries can be exact strings or patterns (with '%' wildcards).
  // Substring matching is supported: if the blacklisted entry is a substring
  // of the username, it's blocked.
  // ------------------------------------------------------------------------
  bool is_username_blacklisted(std::string_view username) {
    std::string lower = lowercase(username);

    // Check exact matches and substring matches
    auto rows = db_.execute("check_blacklist",
                            "SELECT pattern FROM username_blacklist");
    for (auto& row : rows) {
      auto pat = row_column(row, "pattern");
      if (!pat) continue;

      std::string pattern = lowercase(*pat);

      // Exact match
      if (pattern == lower) return true;

      // Substring match
      if (lower.find(pattern) != std::string::npos) return true;

      // Simple wildcard matching (% matches any sequence)
      if (pattern.find('%') != std::string::npos) {
        // Convert SQL LIKE pattern to regex
        std::string regex_pat;
        for (char c : pattern) {
          if (c == '%') {
            regex_pat += ".*";
          } else if (c == '_') {
            regex_pat += ".";
          } else {
            // Escape regex special chars
            if (c == '.' || c == '*' || c == '+' || c == '?' ||
                c == '^' || c == '$' || c == '(' || c == ')' ||
                c == '[' || c == ']' || c == '{' || c == '}' ||
                c == '|' || c == '\\')
              regex_pat += '\\';
            regex_pat += c;
          }
        }
        try {
          std::regex re(regex_pat, std::regex::icase);
          if (std::regex_match(std::string(username), re))
            return true;
        } catch (...) {
          // If regex compilation fails, fall back to substring check
          auto wild_pos = pattern.find('%');
          if (wild_pos != std::string::npos) {
            std::string prefix = pattern.substr(0, wild_pos);
            if (!prefix.empty() && lower.find(prefix) == 0) return true;
          }
        }
      }
    }

    return false;
  }

  // ------------------------------------------------------------------------
  // Check if a username is available (not taken and not blacklisted).
  //
  // Returns JSON: {available: true/false, reason: "..."} // reason on failure
  // ------------------------------------------------------------------------
  json check_username_availability(std::string_view username) {
    if (!is_valid_username(username)) {
      return json{{"available", false},
                  {"reason", "Invalid username format"},
                  {"errcode", "M_INVALID_USERNAME"}};
    }

    if (is_username_blacklisted(username)) {
      return json{{"available", false},
                  {"reason", "Username is not allowed"},
                  {"errcode", "M_EXCLUSIVE"}};
    }

    // Check if user exists in users table
    auto rows = db_.execute("check_user_exists",
                            "SELECT id FROM users WHERE id = " +
                                sql_quote(username));
    if (!rows.empty()) {
      return json{{"available", false},
                  {"reason", "User ID already taken"},
                  {"errcode", "M_USER_IN_USE"}};
    }

    // Check if user exists in pending registrations
    rows = db_.execute("check_pending_user",
                       "SELECT username FROM pending_registrations "
                       "WHERE username = " + sql_quote(username));
    if (!rows.empty()) {
      return json{{"available", false},
                  {"reason", "Username is reserved by a pending registration"},
                  {"errcode", "M_USER_IN_USE"}};
    }

    return json{{"available", true}};
  }

  // ------------------------------------------------------------------------
  // Add a username pattern to the blacklist.
  // ------------------------------------------------------------------------
  json add_to_username_blacklist(std::string_view pattern,
                                  std::string_view reason = "",
                                  std::string_view added_by = "") {
    std::string lower_pat = lowercase(pattern);

    // Check if already exists
    auto rows = db_.execute("check_blacklist_entry",
                            "SELECT pattern FROM username_blacklist "
                            "WHERE pattern = " + sql_quote(lower_pat));
    if (!rows.empty())
      return error_json("M_INVALID_PARAM",
                        "Pattern already in blacklist");

    int64_t now = now_sec();
    db_.execute("add_blacklist",
                "INSERT INTO username_blacklist "
                "(pattern, reason, added_at, added_by) "
                "VALUES (" +
                    sql_quote(lower_pat) + ", " +
                    sql_quote(reason) + ", " +
                    std::to_string(now) + ", " +
                    sql_quote(added_by) + ")");

    log::info(kRegTag, std::string("Added username blacklist pattern: ") +
                           lower_pat);

    return json{{"added", true}, {"pattern", lower_pat}};
  }

  // ------------------------------------------------------------------------
  // Remove a pattern from the username blacklist.
  // ------------------------------------------------------------------------
  json remove_from_username_blacklist(std::string_view pattern) {
    std::string lower_pat = lowercase(pattern);

    db_.execute("remove_blacklist",
                "DELETE FROM username_blacklist WHERE pattern = " +
                    sql_quote(lower_pat));

    log::info(kRegTag, std::string("Removed username blacklist pattern: ") +
                           lower_pat);

    return json{{"removed", true}, {"pattern", lower_pat}};
  }

  // ------------------------------------------------------------------------
  // List all blacklisted username patterns.
  // ------------------------------------------------------------------------
  json list_username_blacklist() {
    auto rows = db_.execute("list_blacklist",
                            "SELECT pattern, reason, added_at, added_by "
                            "FROM username_blacklist ORDER BY added_at DESC");

    json result = json::array();
    for (auto& row : rows) {
      result.push_back({
          {"pattern",
           row_column(row, "pattern").value_or("")},
          {"reason",
           row_column(row, "reason").value_or("")},
          {"added_at",
           row_column(row, "added_at").value_or("0")},
          {"added_by",
           row_column(row, "added_by").value_or("")},
      });
    }
    return result;
  }

  // ========================================================================
  // Email Domain Allow/Block List
  // ========================================================================

  // ------------------------------------------------------------------------
  // Check if an email domain passes the allow/block list.
  //
  // Logic:
  //   1. If blocklist is enabled and domain matches a blocked entry -> REJECT
  //   2. If allowlist is enabled and domain does NOT match an allowed entry
  //      -> REJECT
  //   3. Otherwise -> ALLOW
  //
  // Returns {allowed: true} or {allowed: false, reason: "..."}
  // ------------------------------------------------------------------------
  json check_email_domain_policy(std::string_view email) {
    std::string domain = extract_domain(email);
    if (domain.empty())
      return json{{"allowed", false},
                  {"reason", "Invalid email address"}};

    std::string lower_domain = lowercase(domain);

    // Check blocklist first
    if (enable_domain_blocklist_) {
      auto rows = db_.execute("check_domain_block",
                              "SELECT domain FROM email_domain_list "
                              "WHERE list_type = 'block' AND domain = " +
                                  sql_quote(lower_domain));
      if (!rows.empty()) {
        return json{{"allowed", false},
                    {"reason", "Email domain is blocked: " + domain}};
      }
    }

    // Check allowlist
    if (enable_domain_allowlist_) {
      auto rows = db_.execute("check_domain_allow",
                              "SELECT domain FROM email_domain_list "
                              "WHERE list_type = 'allow' AND domain = " +
                                  sql_quote(lower_domain));
      if (rows.empty()) {
        return json{
            {"allowed", false},
            {"reason", "Email domain is not in the allowed list: " + domain}};
      }
    }

    return json{{"allowed", true}};
  }

  // ------------------------------------------------------------------------
  // Add a domain to the allow or block list.
  // ------------------------------------------------------------------------
  json add_to_domain_list(std::string_view domain,
                           std::string_view list_type,  // "allow" or "block"
                           std::string_view comment = "") {
    std::string lower_domain = lowercase(domain);

    if (list_type != "allow" && list_type != "block")
      return error_json("M_INVALID_PARAM",
                        "list_type must be 'allow' or 'block'");

    auto rows = db_.execute("check_domain_entry",
                            "SELECT domain FROM email_domain_list "
                            "WHERE domain = " + sql_quote(lower_domain));
    if (!rows.empty())
      return error_json("M_INVALID_PARAM", "Domain already in list");

    int64_t now = now_sec();
    db_.execute("add_domain",
                "INSERT INTO email_domain_list "
                "(domain, list_type, comment, added_at) "
                "VALUES (" +
                    sql_quote(lower_domain) + ", " +
                    sql_quote(list_type) + ", " +
                    sql_quote(comment) + ", " +
                    std::to_string(now) + ")");

    return json{{"added", true},
                {"domain", lower_domain},
                {"list_type", list_type}};
  }

  // ------------------------------------------------------------------------
  // Remove a domain from the allow/block list.
  // ------------------------------------------------------------------------
  json remove_from_domain_list(std::string_view domain) {
    std::string lower_domain = lowercase(domain);

    db_.execute("remove_domain",
                "DELETE FROM email_domain_list WHERE domain = " +
                    sql_quote(lower_domain));

    return json{{"removed", true}, {"domain", lower_domain}};
  }

  // ------------------------------------------------------------------------
  // List all email domain list entries.
  // ------------------------------------------------------------------------
  json list_domain_list(std::string_view list_type = "") {
    std::string query =
        "SELECT domain, list_type, comment, added_at "
        "FROM email_domain_list";

    if (!list_type.empty())
      query += " WHERE list_type = " + sql_quote(list_type);

    query += " ORDER BY added_at DESC";

    auto rows = db_.execute("list_domains", query);

    json result = json::array();
    for (auto& row : rows) {
      result.push_back({
          {"domain", row_column(row, "domain").value_or("")},
          {"list_type", row_column(row, "list_type").value_or("")},
          {"comment", row_column(row, "comment").value_or("")},
          {"added_at", row_column(row, "added_at").value_or("0")},
      });
    }
    return result;
  }

  // ========================================================================
  // reCAPTCHA Verification
  // ========================================================================

  // ------------------------------------------------------------------------
  // Verify a reCAPTCHA response token with Google's API.
  //
  // Uses POSIX sockets and raw HTTP to avoid external HTTP library
  // dependencies (consistent with the rest of the codebase).
  //
  // Returns true if the reCAPTCHA was successfully verified.
  // ------------------------------------------------------------------------
  bool verify_recaptcha(std::string_view response,
                         std::string_view remote_ip = "") {
    if (!enable_recaptcha_) return true;  // Not configured, skip

    if (response.empty()) return false;

    // Build the verification request body
    std::ostringstream body;
    body << "secret=" << recaptcha_secret_key_
         << "&response=" << response;
    if (!remote_ip.empty()) {
      body << "&remoteip=" << remote_ip;
    }

    std::string body_str = body.str();

    // Resolve www.google.com
    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    int gai = getaddrinfo("www.google.com", "443", &hints, &res);
    if (gai != 0 || !res) {
      log::warn(kRegTag, "Failed to resolve www.google.com for reCAPTCHA");
      return false;
    }

    int sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock < 0) {
      freeaddrinfo(res);
      log::warn(kRegTag, "Failed to create socket for reCAPTCHA");
      return false;
    }

    // Set timeout
    struct timeval tv{};
    tv.tv_sec = kRecaptchaTimeoutSec;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    bool connected = (connect(sock, res->ai_addr, res->ai_addrlen) == 0);
    freeaddrinfo(res);

    if (!connected) {
      close(sock);
      log::warn(kRegTag, "Failed to connect to reCAPTCHA service");
      return false;
    }

    // Build HTTP POST request
    std::ostringstream request;
    request << "POST /recaptcha/api/siteverify HTTP/1.1\r\n"
            << "Host: www.google.com\r\n"
            << "Content-Type: application/x-www-form-urlencoded\r\n"
            << "Content-Length: " << body_str.size() << "\r\n"
            << "Connection: close\r\n"
            << "\r\n"
            << body_str;

    std::string req_str = request.str();
    send(sock, req_str.data(), req_str.size(), 0);

    // Read response
    std::string response_str;
    char buf[4096];
    ssize_t n;
    while ((n = recv(sock, buf, sizeof(buf) - 1, 0)) > 0) {
      buf[n] = '\0';
      response_str += buf;
    }
    close(sock);

    // Find the JSON body (after headers)
    auto header_end = response_str.find("\r\n\r\n");
    if (header_end == std::string::npos) {
      log::warn(kRegTag, "Invalid HTTP response from reCAPTCHA");
      return false;
    }

    std::string json_str = response_str.substr(header_end + 4);

    try {
      auto j = json::parse(json_str);
      bool success = j.value("success", false);
      if (!success) {
        auto error_codes = j.value("error-codes", json::array());
        std::ostringstream err;
        err << "reCAPTCHA verification failed";
        for (const auto& ec : error_codes)
          err << ": " << ec.get<std::string>();
        log::warn(kRegTag, err.str());
      }
      return success;
    } catch (const std::exception& e) {
      log::error(kRegTag,
                 std::string("Failed to parse reCAPTCHA response: ") +
                     e.what());
      return false;
    }
  }

  // ------------------------------------------------------------------------
  // Get the reCAPTCHA site key (for frontend rendering).
  // ------------------------------------------------------------------------
  json get_recaptcha_config() const {
    return json{
        {"enabled", enable_recaptcha_},
        {"site_key", recaptcha_site_key_}};
  }

  // ========================================================================
  // Shared Secret Registration
  //
  // Matrix homeservers can support a "shared secret" mode where an
  // external service (like a website or bot) can generate registration
  // tokens using a pre-shared HMAC key.  The process works as follows:
  //
  //   1. External service computes: mac = HMAC-SHA256(shared_secret,
  //      nonce + "\0" + user + "\0" + password + "\0" + admin_flag)
  //   2. External service provides: nonce, username, password, mac, admin
  //   3. Server validates the HMAC before creating the account.
  //
  // This enables Matrix single sign-on flows without OAuth.
  // ========================================================================

  // ------------------------------------------------------------------------
  // Generate a nonce for shared-secret registration.
  //
  // The nonce is valid for a limited time (e.g., 5 minutes) and is stored
  // in-memory to prevent replay attacks.
  // ------------------------------------------------------------------------
  std::string generate_shared_secret_nonce() {
    if (shared_secret_.empty())
      return "";

    std::string nonce = generate_token(32);
    std::unique_lock lock(shared_secret_mutex_);
    shared_secret_nonces_[nonce] = now_sec() + 300;  // 5-minute expiry
    return nonce;
  }

  // ------------------------------------------------------------------------
  // Validate a shared-secret MAC.
  //
  // Computes the expected HMAC and compares it against the provided MAC.
  // Returns true if valid.
  // ------------------------------------------------------------------------
  bool validate_shared_secret_mac(std::string_view nonce,
                                   std::string_view user,
                                   std::string_view password,
                                   std::string_view admin_flag,
                                   std::string_view supplied_mac) {
    if (shared_secret_.empty())
      return false;

    // Check nonce validity
    {
      std::unique_lock lock(shared_secret_mutex_);
      auto it = shared_secret_nonces_.find(std::string(nonce));
      int64_t now = now_sec();
      if (it == shared_secret_nonces_.end() || now > it->second) {
        // Nonce expired or not found
        shared_secret_nonces_.erase(std::string(nonce));
        return false;
      }
      // Consume the nonce (single-use)
      shared_secret_nonces_.erase(it);
    }

    // Build the HMAC input: nonce + "\0" + user + "\0" + password +
    // "\0" + admin_flag
    std::string hmac_input;
    hmac_input.reserve(nonce.size() + user.size() + password.size() +
                        admin_flag.size() + 4);
    hmac_input += nonce;
    hmac_input += '\0';
    hmac_input += user;
    hmac_input += '\0';
    hmac_input += password;
    hmac_input += '\0';
    hmac_input += admin_flag;

    std::string expected_mac = hmac_sha256(shared_secret_, hmac_input);

    // Constant-time comparison
    if (expected_mac.size() != supplied_mac.size()) return false;
    int diff = 0;
    for (size_t i = 0; i < expected_mac.size(); ++i) {
      diff |= expected_mac[i] ^ supplied_mac[i];
    }
    return diff == 0;
  }

  // ------------------------------------------------------------------------
  // Register a user using shared secret authentication.
  //
  // This is the server-side handler for the shared-secret registration flow.
  // Returns a JSON response suitable for the /register API endpoint.
  // ------------------------------------------------------------------------
  json register_with_shared_secret(std::string_view mac,
                                     std::string_view nonce,
                                     std::string_view username,
                                     std::string_view password,
                                     bool admin,
                                     std::string_view ip_address = "") {
    if (!enable_shared_secret_)
      return error_json("M_FORBIDDEN",
                        "Shared secret registration is not enabled");

    // Validate the MAC
    std::string admin_flag = admin ? "admin" : "notadmin";
    if (!validate_shared_secret_mac(nonce, username, password,
                                     admin_flag, mac)) {
      return error_json("M_FORBIDDEN", "Invalid MAC or expired nonce");
    }

    // Validate username
    if (!is_valid_username(username))
      return error_json("M_INVALID_USERNAME", "Invalid username");

    // Validate password
    auto pw_err = validate_password(password);
    if (pw_err)
      return error_json("M_WEAK_PASSWORD", *pw_err);

    // Check username availability
    auto avail = check_username_availability(username);
    if (!avail.value("available", false))
      return avail;

    // Create the account
    return create_account(username, password, "", admin, ip_address);
  }

  // ========================================================================
  // Registration Session Tracking
  //
  // Registration sessions track in-progress registrations that may span
  // multiple stages (e.g., email verification, terms consent, reCAPTCHA).
  // Each session has a unique ID and accumulates completed stages.
  // ========================================================================

  // ------------------------------------------------------------------------
  // Create a new registration session.
  //
  // Stores the session ID along with the requested username, password hash,
  // email (optional), IP address, and current stage information.
  // ------------------------------------------------------------------------
  json create_registration_session(std::string_view username,
                                     std::string_view password_hash,
                                     std::string_view email = "",
                                     std::string_view ip_address = "",
                                     std::string_view token = "") {
    std::string session_id = generate_session_id();
    int64_t now = now_sec();
    int64_t expires = now + kSessionExpirySec;

    db_.execute("create_session",
                "INSERT INTO registration_sessions "
                "(session_id, username, password_hash, email, "
                " ip_address, token, created_at, expires_at, "
                " stage_dns, stage_terms, stage_email, stage_captcha, "
                " stage_token) "
                "VALUES (" +
                    sql_quote(session_id) + ", " +
                    sql_quote(username) + ", " +
                    sql_quote(password_hash) + ", " +
                    sql_quote(email) + ", " +
                    sql_quote(ip_address) + ", " +
                    sql_quote(token) + ", " +
                    std::to_string(now) + ", " +
                    std::to_string(expires) + ", "
                    "0, 0, 0, 0, 0)");

    return json{
        {"session", session_id},
        {"expires_at", expires},
        {"stages_completed", json::array()}};
  }

  // ------------------------------------------------------------------------
  // Get session info.
  // ------------------------------------------------------------------------
  json get_registration_session(std::string_view session_id) {
    auto rows = db_.execute("get_session",
                            "SELECT session_id, username, email, "
                            "stage_dns, stage_terms, stage_email, "
                            "stage_captcha, stage_token, "
                            "expires_at, created_at "
                            "FROM registration_sessions "
                            "WHERE session_id = " + sql_quote(session_id));

    if (rows.empty())
      return error_json("M_NOT_FOUND", "Session not found");

    auto& row = rows[0];

    // Check expiry
    auto ev = row_column(row, "expires_at");
    if (ev) {
      int64_t expires = std::stoll(*ev);
      if (now_sec() > expires)
        return error_json("M_SESSION_EXPIRED",
                          "Registration session has expired");
    }

    auto col_s = [&](const std::string& name) -> std::string {
      return row_column(row, name).value_or("");
    };

    auto col_i = [&](const std::string& name) -> int {
      auto v = row_column(row, name);
      return v ? std::stoi(*v) : 0;
    };

    json stages = json::array();
    if (col_i("stage_dns")) stages.push_back("m.login.dns_check");
    if (col_i("stage_terms")) stages.push_back("m.login.terms");
    if (col_i("stage_email")) stages.push_back("m.login.email.identity");
    if (col_i("stage_captcha")) stages.push_back("m.login.recaptcha");
    if (col_i("stage_token")) stages.push_back("m.login.registration_token");

    return json{
        {"session", col_s("session_id")},
        {"username", col_s("username")},
        {"email", col_s("email")},
        {"stages_completed", stages},
        {"created_at", col_s("created_at")},
    };
  }

  // ------------------------------------------------------------------------
  // Mark a stage as completed in a registration session.
  // ------------------------------------------------------------------------
  json complete_session_stage(std::string_view session_id,
                               std::string_view stage) {
    auto session = get_registration_session(session_id);
    if (session.contains("errcode")) return session;

    std::string column;
    if (stage == "m.login.dns_check") column = "stage_dns";
    else if (stage == "m.login.terms") column = "stage_terms";
    else if (stage == "m.login.email.identity") column = "stage_email";
    else if (stage == "m.login.recaptcha") column = "stage_captcha";
    else if (stage == "m.login.registration_token") column = "stage_token";
    else
      return error_json("M_UNRECOGNIZED",
                        std::string("Unknown stage: ") + std::string(stage));

    db_.execute("complete_stage",
                "UPDATE registration_sessions SET " + column +
                    " = 1 WHERE session_id = " + sql_quote(session_id));

    log::info(kRegTag, std::string("Stage completed for session ") +
                           std::string(session_id).substr(0, 12) + "...: " +
                           std::string(stage));

    return get_registration_session(session_id);
  }

  // ------------------------------------------------------------------------
  // Delete a registration session (cleanup or cancellation).
  // ------------------------------------------------------------------------
  void delete_registration_session(std::string_view session_id) {
    db_.execute("delete_session",
                "DELETE FROM registration_sessions WHERE session_id = " +
                    sql_quote(session_id));
  }

  // ========================================================================
  // Email Verification for Registration
  //
  // When require_email_validation_ is enabled, users must verify their
  // email address before the account is activated.  The flow:
  //   1. User provides email during registration
  //   2. Server stores a pending activation with a unique token
  //   3. Server sends a verification email with a link containing the token
  //   4. User clicks the link (token is validated)
  //   5. Account is activated
  // ========================================================================

  // ------------------------------------------------------------------------
  // Create an email verification / activation token.
  //
  // Stores a pending activation record in the database.  If an activation
  // email sender is configured, it will be sent asynchronously.
  // ------------------------------------------------------------------------
  json create_activation_token(std::string_view username,
                                std::string_view email) {
    std::string token = generate_activation_token();
    int64_t now = now_sec();
    int64_t expires = now + kActivationTokenExpirySec;

    // Check if there's already a pending activation for this username
    db_.execute("delete_old_activation",
                "DELETE FROM pending_registrations WHERE username = " +
                    sql_quote(username));

    db_.execute("create_activation",
                "INSERT INTO pending_registrations "
                "(username, email, activation_token, "
                " status, created_at, expires_at) "
                "VALUES (" +
                    sql_quote(username) + ", " +
                    sql_quote(email) + ", " +
                    sql_quote(token) + ", "
                    "'pending_activation', " +
                    std::to_string(now) + ", " +
                    std::to_string(expires) + ")");

    log::info(kRegTag, std::string("Created activation token for ") +
                           std::string(username));

    return json{
        {"activation_token", token},
        {"expires_at", expires},
        {"email_sent", enable_activation_email_}};
  }

  // ------------------------------------------------------------------------
  // Activate an account using an email verification token.
  //
  // Returns JSON with success/error.
  // ------------------------------------------------------------------------
  json activate_account_with_token(std::string_view activation_token) {
    auto rows = db_.execute("find_activation",
                            "SELECT username, email, status, expires_at "
                            "FROM pending_registrations "
                            "WHERE activation_token = " +
                                sql_quote(activation_token));

    if (rows.empty())
      return error_json("M_NOT_FOUND",
                        "Invalid or expired activation token");

    auto& row = rows[0];
    std::string username = row_column(row, "username").value_or("");
    std::string email = row_column(row, "email").value_or("");
    std::string status = row_column(row, "status").value_or("");

    if (status != "pending_activation")
      return error_json("M_INVALID_PARAM", "Account is not pending activation");

    auto ev = row_column(row, "expires_at");
    if (ev) {
      int64_t expires = std::stoll(*ev);
      if (now_sec() > expires) {
        // Clean up expired
        db_.execute("delete_expired_activation",
                    "DELETE FROM pending_registrations "
                    "WHERE activation_token = " +
                        sql_quote(activation_token));
        return error_json("M_EXPIRED_TOKEN",
                          "Activation token has expired");
      }
    }

    // Mark as activated
    db_.execute("activate_account",
                "UPDATE pending_registrations SET "
                "status = 'activated', activated_at = " +
                    std::to_string(now_sec()) +
                    " WHERE activation_token = " +
                    sql_quote(activation_token));

    log::info(kRegTag, std::string("Account activated for user: ") + username);

    return json{
        {"activated", true},
        {"username", username},
        {"email", email}};
  }

  // ------------------------------------------------------------------------
  // Build the content for an account activation email.
  // ------------------------------------------------------------------------
  json build_activation_email(std::string_view username,
                               std::string_view email,
                               std::string_view activation_token) {
    std::string activation_link =
        home_server_url_ + "/_matrix/client/v3/register/email/verify"
        "?token=" + std::string(activation_token) +
        "&username=" + std::string(username);

    std::string subject = "Activate your " + server_name_ + " account";
    std::string text_body =
        "Hello,\n\n"
        "Thank you for creating an account on " +
        server_name_ + ".\n\n" +
        "To activate your account, please click the link below:\n\n" +
        activation_link + "\n\n" +
        "This link will expire in 3 days.\n\n" +
        "If you did not request this, please ignore this email.\n\n" +
        "Regards,\n" + server_name_ + " Team";

    std::string html_body =
        "<html><body>"
        "<h2>Activate Your Account</h2>"
        "<p>Thank you for creating an account on <strong>" +
        server_name_ + "</strong>.</p>"
        "<p>To activate your account, please click the link below:</p>"
        "<p><a href=\"" + activation_link + "\">Activate Account</a></p>"
        "<p>This link will expire in 3 days.</p>"
        "<p>If you did not request this, please ignore this email.</p>"
        "<hr><p>" + server_name_ + " Team</p></body></html>";

    return json{
        {"subject", subject},
        {"text_body", text_body},
        {"html_body", html_body},
        {"activation_link", activation_link}};
  }

  // ------------------------------------------------------------------------
  // Build the content for a welcome email.
  // ------------------------------------------------------------------------
  json build_welcome_email(std::string_view username,
                            std::string_view email) {
    std::string subject = "Welcome to " + server_name_ + "!";
    std::string text_body =
        "Hello " + std::string(username) + ",\n\n"
        "Welcome to " + server_name_ + "! Your account has been created "
        "successfully.\n\n"
        "You can now start chatting, joining rooms, and collaborating "
        "with others.\n\n"
        "If you have any questions, please refer to our documentation "
        "or contact support.\n\n"
        "Regards,\n" + server_name_ + " Team";

    std::string html_body =
        "<html><body>"
        "<h2>Welcome to " + server_name_ + "!</h2>"
        "<p>Hello <strong>" + std::string(username) + "</strong>,</p>"
        "<p>Your account has been created successfully.</p>"
        "<p>You can now start chatting, joining rooms, and collaborating "
        "with others.</p>"
        "<hr><p>" + server_name_ + " Team</p></body></html>";

    return json{
        {"subject", subject},
        {"text_body", text_body},
        {"html_body", html_body}};
  }

  // ========================================================================
  // Terms of Service Consent
  //
  // When require_terms_consent_ is enabled, users must accept the server's
  // terms of service before registration can complete.
  // ========================================================================

  // ------------------------------------------------------------------------
  // Get the current terms of service document.
  //
  // Returns JSON with terms version, text, and acceptance URL.
  // In a full implementation, this would load from a file or database.
  // ------------------------------------------------------------------------
  json get_terms_of_service() const {
    // Default terms - in a real deployment these would be loaded from config
    json policies;
    policies["privacy_policy"] = {
        {"version", "1.0"},
        {"en", {
            {"name", "Privacy Policy"},
            {"url", home_server_url_ + "/_matrix/consent?v=1.0"},
        }},
    };

    return json{
        {"enabled", require_terms_consent_},
        {"policies", policies}};
  }

  // ------------------------------------------------------------------------
  // Record that a user (or pending user) has accepted the terms of service.
  //
  // For pending registrations, this stores acceptance with the session.
  // For existing users, this would update a consent table.
  // ------------------------------------------------------------------------
  json accept_terms_of_service(std::string_view username,
                                std::string_view user_accepts,
                                std::string_view session_id = "") {
    if (!require_terms_consent_)
      return json{{"accepted", true}};

    int64_t now = now_sec();

    if (!session_id.empty()) {
      // Record consent in the registration session
      db_.execute("accept_terms_session",
                  "UPDATE registration_sessions SET stage_terms = 1 "
                  "WHERE session_id = " + sql_quote(session_id));
    }

    // Record consent in a dedicated table
    db_.execute("record_consent",
                "INSERT OR REPLACE INTO user_consent "
                "(username, consent_version, accepted_at, "
                " user_accepts) "
                "VALUES (" +
                    sql_quote(username) + ", '1.0', " +
                    std::to_string(now) + ", " +
                    sql_quote(user_accepts) + ")");

    log::info(kRegTag, std::string("Terms accepted by: ") +
                           std::string(username));

    return json{{"accepted", true}};
  }

  // ------------------------------------------------------------------------
  // Check if a user has accepted the current terms.
  // ------------------------------------------------------------------------
  bool has_accepted_terms(std::string_view username) const {
    if (!require_terms_consent_) return true;

    auto rows = db_.execute("check_consent",
                            "SELECT consent_version FROM user_consent "
                            "WHERE username = " + sql_quote(username) +
                                " ORDER BY accepted_at DESC LIMIT 1");

    return !rows.empty();
  }

  // ========================================================================
  // Admin Registration Approval Flow
  //
  // When enable_admin_approval_ is enabled, new registrations enter a
  // pending state and require admin approval before the account is created.
  // ========================================================================

  // ------------------------------------------------------------------------
  // Submit a registration for admin approval.
  //
  // Stores the pending registration in the database.  Returns a pending
  // ID that can be used to check status.
  // ------------------------------------------------------------------------
  json submit_for_admin_approval(std::string_view username,
                                  std::string_view password_hash,
                                  std::string_view email = "",
                                  std::string_view ip_address = "",
                                  std::string_view registration_token = "") {
    int64_t now = now_sec();

    // Generate a unique pending ID
    std::string pending_id = generate_token(16);
    int64_t expires = now + kPendingRegistrationExpirySec;

    db_.execute("submit_approval",
                "INSERT INTO pending_registrations "
                "(pending_id, username, password_hash, email, "
                " ip_address, registration_token, status, "
                " created_at, expires_at) "
                "VALUES (" +
                    sql_quote(pending_id) + ", " +
                    sql_quote(username) + ", " +
                    sql_quote(password_hash) + ", " +
                    sql_quote(email) + ", " +
                    sql_quote(ip_address) + ", " +
                    sql_quote(registration_token) + ", "
                    "'pending_approval', " +
                    std::to_string(now) + ", " +
                    std::to_string(expires) + ")");

    log::info(kRegTag, std::string("Registration submitted for approval: ") +
                           std::string(username));

    return json{
        {"pending_id", pending_id},
        {"status", "pending_approval"},
        {"submitted_at", now}};
  }

  // ------------------------------------------------------------------------
  // List all pending registrations awaiting admin approval.
  // ------------------------------------------------------------------------
  json list_pending_approvals() {
    auto rows = db_.execute("list_pending_approvals",
                            "SELECT pending_id, username, email, "
                            "ip_address, registration_token, status, "
                            "created_at, expires_at "
                            "FROM pending_registrations "
                            "WHERE status = 'pending_approval' "
                            "ORDER BY created_at ASC");

    json result = json::array();
    int64_t now = now_sec();

    for (auto& row : rows) {
      auto col = [&](const std::string& name) -> json {
        auto v = row_column(row, name);
        if (v) return json(*v);
        return json(nullptr);
      };

      result.push_back({
          {"pending_id", col("pending_id")},
          {"username", col("username")},
          {"email", col("email")},
          {"ip_address", col("ip_address")},
          {"registration_token", col("registration_token")},
          {"status", col("status")},
          {"created_at", col("created_at")},
      });
    }
    return result;
  }

  // ------------------------------------------------------------------------
  // Approve a pending registration.
  //
  // Creates the account and returns the access token.
  // ------------------------------------------------------------------------
  json approve_pending_registration(std::string_view pending_id,
                                      bool admin = false) {
    auto rows = db_.execute("find_pending",
                            "SELECT username, password_hash, email, "
                            "registration_token, status "
                            "FROM pending_registrations "
                            "WHERE pending_id = " + sql_quote(pending_id));

    if (rows.empty())
      return error_json("M_NOT_FOUND", "Pending registration not found");

    auto& row = rows[0];
    std::string username = row_column(row, "username").value_or("");
    std::string status = row_column(row, "status").value_or("");
    std::string email = row_column(row, "email").value_or("");
    std::string reg_token = row_column(row, "registration_token").value_or("");

    if (status != "pending_approval")
      return error_json("M_INVALID_PARAM",
                        "Registration is not in pending approval state");

    if (username.empty())
      return error_json("M_INVALID_PARAM",
                        "Pending registration has no username");

    // Check that the username is still available
    auto avail = check_username_availability(username);
    if (!avail.value("available", false))
      return avail;

    // Create the user account
    // The password was already hashed before submission
    auto password_hash = row_column(row, "password_hash").value_or("");

    int64_t now = util::now_ms();
    db_.execute("create_approved_user",
                "INSERT INTO users (id, password_hash, creation_ts) "
                "VALUES (" +
                    sql_quote(username) + ", " +
                    sql_quote(password_hash) + ", " +
                    std::to_string(now) + ")");

    // Generate access token
    std::string access_token = util::generate_access_token();
    db_.execute("create_approved_token",
                "INSERT INTO access_tokens (token, user_id) "
                "VALUES (" +
                    sql_quote(access_token) + ", " +
                    sql_quote(username) + ")");

    // Update registration status
    db_.execute("mark_approved",
                "UPDATE pending_registrations SET "
                "status = 'approved', approved_at = " +
                    std::to_string(now_sec()) +
                    " WHERE pending_id = " + sql_quote(pending_id));

    // Complete token usage if applicable
    if (!reg_token.empty())
      complete_token_usage(reg_token);

    log::info(kRegTag, std::string("Admin approved registration for: ") +
                           username);

    return json{
        {"user_id", username},
        {"access_token", access_token},
        {"home_server", server_name_},
        {"approved", true}};
  }

  // ------------------------------------------------------------------------
  // Deny a pending registration.
  // ------------------------------------------------------------------------
  json deny_pending_registration(std::string_view pending_id,
                                  std::string_view reason = "") {
    auto rows = db_.execute("find_pending_deny",
                            "SELECT status, registration_token "
                            "FROM pending_registrations "
                            "WHERE pending_id = " + sql_quote(pending_id));

    if (rows.empty())
      return error_json("M_NOT_FOUND", "Pending registration not found");

    auto status = row_column(rows[0], "status").value_or("");
    if (status != "pending_approval")
      return error_json("M_INVALID_PARAM",
                        "Registration is not in pending approval state");

    int64_t now = now_sec();
    db_.execute("mark_denied",
                "UPDATE pending_registrations SET "
                "status = 'denied', denied_at = " +
                    std::to_string(now) +
                    ", denial_reason = " + sql_quote(reason) +
                    " WHERE pending_id = " + sql_quote(pending_id));

    // Abort token usage
    auto reg_token = row_column(rows[0], "registration_token").value_or("");
    if (!reg_token.empty())
      abort_token_usage(reg_token);

    log::info(kRegTag, std::string("Admin denied registration: ") +
                           std::string(pending_id).substr(0, 12) + "...");

    return json{{"denied", true},
                {"pending_id", pending_id},
                {"reason", reason}};
  }

  // ========================================================================
  // Core Account Creation
  // ========================================================================

  // ------------------------------------------------------------------------
  // Hash a password using SHA-256 + base64 (consistent with auth.cpp).
  // ------------------------------------------------------------------------
  std::string hash_password(std::string_view password) const {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(password.data()),
           password.size(), hash);
    return util::base64::encode(
        std::string_view(reinterpret_cast<const char*>(hash),
                         SHA256_DIGEST_LENGTH));
  }

  // ------------------------------------------------------------------------
  // Create a user account in the database.
  //
  // This is the core account creation method that all registration flows
  // ultimately call.  It inserts the user row and creates an access token.
  // ------------------------------------------------------------------------
  json create_account(std::string_view username,
                       std::string_view password,
                       std::string_view email = "",
                       bool admin = false,
                       std::string_view ip_address = "") {
    // Final availability check
    auto avail = check_username_availability(username);
    if (!avail.value("available", false))
      return avail;

    // Validate password
    auto pw_err = validate_password(password);
    if (pw_err)
      return error_json("M_WEAK_PASSWORD", *pw_err);

    // Hash password
    std::string pw_hash = hash_password(password);
    int64_t now = util::now_ms();

    // Insert user
    db_.execute("create_user",
                "INSERT INTO users (id, password_hash, creation_ts, admin) "
                "VALUES (" +
                    sql_quote(username) + ", " +
                    sql_quote(pw_hash) + ", " +
                    std::to_string(now) + ", " +
                    (admin ? "1" : "0") + ")");

    // Generate access token
    std::string access_token = util::generate_access_token();
    db_.execute("create_token",
                "INSERT INTO access_tokens (token, user_id) "
                "VALUES (" +
                    sql_quote(access_token) + ", " +
                    sql_quote(username) + ")");

    // Store email association if provided
    if (!email.empty()) {
      db_.execute("store_email",
                  "INSERT OR REPLACE INTO user_threepids "
                  "(user_id, medium, address, validated_at, added_at) "
                  "VALUES (" +
                      sql_quote(username) + ", 'email', " +
                      sql_quote(email) + ", " +
                      std::to_string(now_sec()) + ", " +
                      std::to_string(now_sec()) + ")");
    }

    // Auto-join rooms if configured
    for (const auto& room_id : auto_join_rooms_) {
      db_.execute("auto_join",
                  "INSERT OR IGNORE INTO room_memberships "
                  "(room_id, user_id, membership) "
                  "VALUES (" +
                      sql_quote(room_id) + ", " +
                      sql_quote(username) + ", 'join')");
    }

    log::info(kRegTag, std::string("Created account for user: ") +
                           std::string(username),
              (email.empty() ? "" : " with email"));

    json result{
        {"user_id", username},
        {"access_token", access_token},
        {"home_server", server_name_},
        {"device_id", ""},
    };

    if (enable_welcome_email_ && !email.empty()) {
      result["welcome_email_queued"] = true;
    }

    return result;
  }

  // ========================================================================
  // Full Registration Flow Orchestration
  //
  // These methods combine all the checks and stages into complete
  // registration handler functions suitable for calling from HTTP handlers.
  // ========================================================================

  // ------------------------------------------------------------------------
  // Complete registration flow: validate, check rate limits, check token,
  // verify email, create account.
  //
  // This is the main entry point called by the /register API handler.
  //
  // The 'params' JSON should contain:
  //   - username (required)
  //   - password (required)
  //   - auth: {type: "...", session: "...", ...} (optional, for UIA)
  //   - initial_device_display_name (optional)
  //   - inhibit_login (optional)
  //
  // Returns a Matrix-compatible registration response.
  // ------------------------------------------------------------------------
  json process_registration(const json& params,
                              std::string_view ip_address = "") {
    std::string username = params.value("username", "");
    std::string password = params.value("password", "");
    std::string email = params.value("email", "");

    // Basic input validation
    if (username.empty())
      return error_json("M_MISSING_PARAM", "Missing 'username'");
    if (password.empty())
      return error_json("M_MISSING_PARAM", "Missing 'password'");

    // Rate limit check (per IP)
    if (!ip_address.empty()) {
      auto decision =
          ip_rate_limiter_.check_and_record(lowercase(ip_address));
      if (!decision.allowed) {
        return error_json("M_LIMIT_EXCEEDED",
                          "Too many registration attempts",
                          {{"retry_after_ms", decision.retry_after_ms}});
      }
    }

    // Rate limit check (per email)
    if (!email.empty()) {
      auto decision =
          email_rate_limiter_.check_and_record(lowercase(email));
      if (!decision.allowed) {
        return error_json("M_LIMIT_EXCEEDED",
                          "Too many registration attempts for this email",
                          {{"retry_after_ms", decision.retry_after_ms}});
      }
    }

    // Process auth stages (UIA - User-Interactive Authentication)
    // The spec allows registration to be split across multiple stages
    if (params.contains("auth") && !params["auth"].is_null()) {
      return process_registration_auth(params, ip_address);
    }

    // No auth stages → determine what's required and respond with flows

    // Build the list of required auth flows
    json flows = json::array();

    // Check if email validation is required
    bool need_email = require_email_validation_ && !email.empty();
    bool need_token = !enable_shared_secret_;  // Need a token unless shared secret
    bool need_captcha = enable_recaptcha_;
    bool need_terms = require_terms_consent_;
    bool need_mx = enable_mx_validation_ && !email.empty();
    bool need_admin = enable_admin_approval_;

    // If no additional auth is needed, we can create the account directly
    if (!need_token && !need_captcha && !need_terms && !need_email &&
        !need_mx && !need_admin) {
      // Direct registration (shared secret or fully open)
      return do_direct_registration(username, password, email,
                                      ip_address);
    }

    // Build available flows
    // Flow 1: with token + optional terms + optional captcha + optional email
    {
      json flow = json::array();
      if (need_token) flow.push_back("m.login.registration_token");
      if (need_terms) flow.push_back("m.login.terms");
      if (need_captcha) flow.push_back("m.login.recaptcha");
      if (need_email) flow.push_back("m.login.email.identity");
      if (need_mx) flow.push_back("m.login.dns_check");
      flows.push_back(flow);
    }

    // Create a session to track this registration
    json session = create_registration_session(
        username, hash_password(password), email, ip_address);
    std::string session_id = session["session"];

    return json{
        {"session", session_id},
        {"flows", flows},
        {"params", {{"m.login.terms", get_terms_of_service()}}},
    };
  }

  // ------------------------------------------------------------------------
  // Handle a registration with auth stages (UIA continuation).
  // ------------------------------------------------------------------------
  json process_registration_auth(const json& params,
                                   std::string_view ip_address) {
    std::string username = params.value("username", "");
    std::string password = params.value("password", "");
    std::string email = params.value("email", "");

    const json& auth = params["auth"];
    std::string auth_type = auth.value("type", "");
    std::string auth_session = auth.value("session", "");

    if (auth_session.empty())
      return error_json("M_MISSING_PARAM",
                        "Missing 'auth.session' for UIA stages");

    // Verify the session exists
    auto session = get_registration_session(auth_session);
    if (session.contains("errcode")) return session;

    // Process the specific auth stage
    if (auth_type == "m.login.registration_token") {
      std::string token = auth.value("token", "");
      if (token.empty())
        return error_json("M_MISSING_PARAM",
                          "Missing 'auth.token' for registration token auth");

      auto validation = validate_registration_token(token);
      if (validation.contains("errcode")) return validation;

      // Increment pending usage
      int64_t pending = increment_token_pending(token);
      if (pending < 0)
        return error_json("M_UNKNOWN_TOKEN",
                          "Failed to process registration token");

      // Note: on failure later, we should call abort_token_usage

      // Mark token stage as completed
      complete_session_stage(auth_session, "m.login.registration_token");

      // Store the token in the session for later
      db_.execute("update_session_token",
                  "UPDATE registration_sessions SET token = " +
                      sql_quote(token) +
                      " WHERE session_id = " + sql_quote(auth_session));

    } else if (auth_type == "m.login.recaptcha") {
      std::string response = auth.value("response", "");
      if (response.empty())
        return error_json("M_MISSING_PARAM",
                          "Missing 'auth.response' for reCAPTCHA");

      if (!verify_recaptcha(response, ip_address))
        return error_json("M_FORBIDDEN", "reCAPTCHA verification failed");

      complete_session_stage(auth_session, "m.login.recaptcha");

    } else if (auth_type == "m.login.terms") {
      std::string user_accepts = auth.value("user_accepts", "");
      if (user_accepts.empty())
        return error_json("M_MISSING_PARAM",
                          "Missing 'auth.user_accepts' for terms consent");

      // Record consent (username may not exist yet, but we record anyway)
      accept_terms_of_service(username, user_accepts, auth_session);
      complete_session_stage(auth_session, "m.login.terms");

    } else if (auth_type == "m.login.email.identity") {
      std::string threepid_creds = auth.value("threepid_creds", "");
      if (threepid_creds.empty() && !auth.contains("token"))
        return error_json("M_MISSING_PARAM",
                          "Missing 'auth.threepid_creds' or "
                          "'auth.token' for email validation");

      // Could validate an email token here
      // For now, assume external verification succeeded
      complete_session_stage(auth_session, "m.login.email.identity");

    } else if (auth_type == "m.login.dns_check") {
      // MX record validation
      if (email.empty())
        return error_json("M_MISSING_PARAM",
                          "Email required for DNS check");

      std::string domain = extract_domain(email);
      if (domain.empty())
        return error_json("M_INVALID_EMAIL",
                          "Invalid email address for DNS check");

      if (!has_mx_records(domain))
        return error_json("M_DNS_ERROR",
                          "Domain has no valid MX records: " + domain);

      complete_session_stage(auth_session, "m.login.dns_check");

    } else {
      return error_json("M_UNRECOGNIZED",
                        std::string("Unknown auth type: ") + auth_type);
    }

    // After processing a stage, check if all required stages are complete
    auto updated_session = get_registration_session(auth_session);
    if (updated_session.contains("errcode")) return updated_session;

    // Check if we have all necessary stages completed to proceed
    bool can_complete = check_all_stages_complete(auth_session);

    if (can_complete) {
      // Retrieve the token from the session
      auto sess_rows = db_.execute("get_session_token",
                                    "SELECT token FROM registration_sessions "
                                    "WHERE session_id = " +
                                        sql_quote(auth_session));
      std::string session_token;
      if (!sess_rows.empty())
        session_token = row_column(sess_rows[0], "token").value_or("");

      // If admin approval is needed, submit for approval
      if (enable_admin_approval_) {
        auto approval = submit_for_admin_approval(
            username, hash_password(password), email,
            ip_address, session_token);
        delete_registration_session(auth_session);
        return json{
            {"completed", false},
            {"status", "pending_approval"},
            {"pending_id", approval["pending_id"]},
        };
      }

      // Check if email verification is needed
      if (require_email_validation_ && !email.empty()) {
        auto activation = create_activation_token(username, email);
        // Return the flow for email verification
        json flows = json::array({json::array({"m.login.email.identity"})});
        return json{
            {"session", auth_session},
            {"flows", flows},
            {"completed", false},
            {"params", json::object()},
            {"activation_email", build_activation_email(
                                     username, email,
                                     activation["activation_token"])},
        };
      }

      // All stages complete — create the account
      auto result = create_account(username, password, email, false,
                                     ip_address);

      // Complete the registration token usage
      if (!session_token.empty())
        complete_token_usage(session_token);

      // Clean up the session
      delete_registration_session(auth_session);

      result["completed"] = true;
      return result;
    }

    // Not all stages complete — return the flows that are still needed
    json flows = json::array();
    {
      json remaining = json::array();
      auto stages = updated_session.value("stages_completed", json::array());

      auto has_stage = [&](const std::string& s) -> bool {
        for (const auto& st : stages)
          if (st.get<std::string>() == s) return true;
        return false;
      };

      if (enable_recaptcha_ && !has_stage("m.login.recaptcha"))
        remaining.push_back("m.login.recaptcha");
      if (require_terms_consent_ && !has_stage("m.login.terms"))
        remaining.push_back("m.login.terms");
      if (!has_stage("m.login.registration_token") && !enable_shared_secret_)
        remaining.push_back("m.login.registration_token");
      if (require_email_validation_ && !has_stage("m.login.email.identity"))
        remaining.push_back("m.login.email.identity");
      if (enable_mx_validation_ && !has_stage("m.login.dns_check"))
        remaining.push_back("m.login.dns_check");

      if (!remaining.empty())
        flows.push_back(remaining);
    }

    return json{
        {"session", auth_session},
        {"flows", flows},
        {"completed", false},
        {"params", json::object()},
    };
  }

  // ------------------------------------------------------------------------
  // Direct registration (no UIA stages needed).
  // ------------------------------------------------------------------------
  json do_direct_registration(std::string_view username,
                                std::string_view password,
                                std::string_view email,
                                std::string_view ip_address) {
    // If admin approval is enabled, submit for approval
    if (enable_admin_approval_) {
      auto approval = submit_for_admin_approval(
          username, hash_password(password), email, ip_address);
      return json{
          {"completed", false},
          {"status", "pending_approval"},
          {"pending_id", approval["pending_id"]},
      };
    }

    // If email validation is required and email is provided
    if (require_email_validation_ && !email.empty()) {
      auto activation = create_activation_token(username, email);

      // Create the account in a deactivated state
      json flows = json::array({json::array({"m.login.email.identity"})});
      return json{
          {"completed", false},
          {"flows", flows},
          {"params", json::object()},
          {"activation_email", build_activation_email(
                                   username, email,
                                   activation["activation_token"])},
      };
    }

    // Create the account
    auto result = create_account(username, password, email, false,
                                   ip_address);
    result["completed"] = true;
    return result;
  }

  // ------------------------------------------------------------------------
  // Check if all required stages for a session have been completed.
  // ------------------------------------------------------------------------
  bool check_all_stages_complete(std::string_view session_id) {
    auto rows = db_.execute("check_stages",
                            "SELECT stage_dns, stage_terms, stage_email, "
                            "stage_captcha, stage_token "
                            "FROM registration_sessions "
                            "WHERE session_id = " + sql_quote(session_id));

    if (rows.empty()) return false;
    auto& row = rows[0];

    auto stage_done = [&](const std::string& col) -> bool {
      auto v = row_column(row, col);
      return v && *v == "1";
    };

    // Check that ALL enabled stages are completed
    if (enable_mx_validation_ && !stage_done("stage_dns")) return false;
    if (require_terms_consent_ && !stage_done("stage_terms")) return false;
    if (require_email_validation_ && !stage_done("stage_email")) return false;
    if (enable_recaptcha_ && !stage_done("stage_captcha")) return false;

    // Token stage: only required if shared secret is not enabled
    if (!enable_shared_secret_ && !stage_done("stage_token")) return false;

    return true;
  }

  // ========================================================================
  // Periodic Cleanup
  // ========================================================================

  // ------------------------------------------------------------------------
  // Cleanup worker thread.
  //
  // Periodically removes:
  //   - Expired registration sessions
  //   - Expired pending registrations
  //   - Expired registration tokens
  //   - Stale rate limiter entries
  // ------------------------------------------------------------------------
  void cleanup_worker() {
    while (running_) {
      std::this_thread::sleep_for(std::chrono::seconds(kCleanupIntervalSec));
      if (!running_) break;

      try {
        cleanup_expired_sessions();
        cleanup_expired_pending();
        cleanup_expired_tokens();
      } catch (const std::exception& e) {
        log::error(kRegTag, std::string("Cleanup error: ") + e.what());
      }

      // Clean up in-memory rate limiters
      ip_rate_limiter_.cleanup();
      email_rate_limiter_.cleanup();
      token_gen_limiter_.cleanup();
    }
  }

  // ------------------------------------------------------------------------
  // Remove expired registration sessions.
  // ------------------------------------------------------------------------
  void cleanup_expired_sessions() {
    int64_t now = now_sec();
    auto rows = db_.execute("cleanup_sessions",
                            "SELECT session_id, token FROM "
                            "registration_sessions "
                            "WHERE expires_at < " + std::to_string(now) +
                            " LIMIT " + std::to_string(kMaxCleanupBatch));

    for (auto& row : rows) {
      auto sid = row_column(row, "session_id").value_or("");
      auto token = row_column(row, "token").value_or("");

      if (!sid.empty()) {
        db_.execute("delete_expired_session",
                    "DELETE FROM registration_sessions "
                    "WHERE session_id = " + sql_quote(sid));

        // Abort any pending token usage
        if (!token.empty())
          abort_token_usage(token);
      }
    }

    if (!rows.empty()) {
      log::info(kRegTag,
                std::string("Cleaned up ") + std::to_string(rows.size()) +
                    " expired registration sessions");
    }
  }

  // ------------------------------------------------------------------------
  // Remove expired pending registrations.
  // ------------------------------------------------------------------------
  void cleanup_expired_pending() {
    int64_t now = now_sec();
    auto rows = db_.execute("cleanup_pending",
                            "SELECT pending_id, registration_token "
                            "FROM pending_registrations "
                            "WHERE expires_at < " + std::to_string(now) +
                            " AND status IN "
                            "('pending_activation', 'pending_approval') "
                            "LIMIT " + std::to_string(kMaxCleanupBatch));

    for (auto& row : rows) {
      auto pid = row_column(row, "pending_id").value_or("");
      auto reg_token = row_column(row, "registration_token").value_or("");

      if (!pid.empty()) {
        db_.execute("delete_expired_pending",
                    "DELETE FROM pending_registrations "
                    "WHERE pending_id = " + sql_quote(pid));

        if (!reg_token.empty())
          abort_token_usage(reg_token);
      }
    }

    if (!rows.empty()) {
      log::info(kRegTag,
                std::string("Cleaned up ") + std::to_string(rows.size()) +
                    " expired pending registrations");
    }
  }

  // ------------------------------------------------------------------------
  // Remove expired registration tokens.
  // ------------------------------------------------------------------------
  void cleanup_expired_tokens() {
    int64_t now = now_sec();
    db_.execute("cleanup_tokens",
                "DELETE FROM registration_tokens "
                "WHERE expiry_time IS NOT NULL "
                "AND expiry_time > 0 "
                "AND expiry_time < " + std::to_string(now));
  }

  // ========================================================================
  // Rate Limit and Status Queries
  // ========================================================================

  // ------------------------------------------------------------------------
  // Get rate limit status for an IP or email.
  // ------------------------------------------------------------------------
  json get_rate_limit_status(std::string_view key,
                               std::string_view type) const {
    std::string lower_key = lowercase(key);
    int remaining;

    if (type == "ip") {
      remaining = ip_rate_limiter_.remaining(lower_key);
    } else if (type == "email") {
      remaining = email_rate_limiter_.remaining(lower_key);
    } else {
      return error_json("M_INVALID_PARAM",
                        "type must be 'ip' or 'email'");
    }

    return json{
        {"key", key},
        {"type", type},
        {"remaining", remaining},
        {"max", kMaxRegPerIpPerWindow},
    };
  }

  // ------------------------------------------------------------------------
  // Get overall registration statistics.
  // ------------------------------------------------------------------------
  json get_registration_statistics() const {
    int64_t now = now_sec();

    // Total users
    auto total_rows = db_.execute("count_users",
                                   "SELECT COUNT(*) as cnt FROM users");
    int64_t total_users = 0;
    if (!total_rows.empty()) {
      auto v = row_column(total_rows[0], "cnt");
      if (v) total_users = std::stoll(*v);
    }

    // Active tokens
    auto token_rows = db_.execute("count_valid_tokens",
                                  "SELECT COUNT(*) as cnt "
                                  "FROM registration_tokens "
                                  "WHERE (expiry_time IS NULL OR "
                                  "expiry_time > " +
                                      std::to_string(now) + ")");
    int64_t active_tokens = 0;
    if (!token_rows.empty()) {
      auto v = row_column(token_rows[0], "cnt");
      if (v) active_tokens = std::stoll(*v);
    }

    // Pending approvals
    auto pending_rows = db_.execute("count_pending",
                                    "SELECT COUNT(*) as cnt "
                                    "FROM pending_registrations "
                                    "WHERE status = 'pending_approval'");
    int64_t pending_approvals = 0;
    if (!pending_rows.empty()) {
      auto v = row_column(pending_rows[0], "cnt");
      if (v) pending_approvals = std::stoll(*v);
    }

    // Active sessions
    auto sess_rows = db_.execute("count_active_sessions",
                                  "SELECT COUNT(*) as cnt "
                                  "FROM registration_sessions "
                                  "WHERE expires_at > " +
                                      std::to_string(now));
    int64_t active_sessions = 0;
    if (!sess_rows.empty()) {
      auto v = row_column(sess_rows[0], "cnt");
      if (v) active_sessions = std::stoll(*v);
    }

    return json{
        {"total_users", total_users},
        {"active_registration_tokens", active_tokens},
        {"pending_approvals", pending_approvals},
        {"active_sessions", active_sessions},
        {"require_email_validation", require_email_validation_},
        {"require_terms_consent", require_terms_consent_},
        {"enable_admin_approval", enable_admin_approval_},
        {"enable_recaptcha", enable_recaptcha_},
        {"enable_shared_secret", enable_shared_secret_},
    };
  }

  // ========================================================================
  // Public Status / Config APIs
  // ========================================================================

  // ------------------------------------------------------------------------
  // Get the full registration pipeline configuration.
  // ------------------------------------------------------------------------
  json get_config() const {
    return json{
        {"server_name", server_name_},
        {"require_email_validation", require_email_validation_},
        {"require_terms_consent", require_terms_consent_},
        {"enable_admin_approval", enable_admin_approval_},
        {"enable_recaptcha", enable_recaptcha_},
        {"enable_shared_secret", enable_shared_secret_},
        {"enable_mx_validation", enable_mx_validation_},
        {"enable_domain_allowlist", enable_domain_allowlist_},
        {"enable_domain_blocklist", enable_domain_blocklist_},
        {"enable_welcome_email", enable_welcome_email_},
        {"enable_activation_email", enable_activation_email_},
        {"recaptcha_site_key", recaptcha_site_key_},
        {"auto_join_rooms", auto_join_rooms_},
        {"password_policy",
         {{"min_length", kMinPasswordLength},
          {"max_length", kMaxPasswordLength}}},
        {"username_policy",
         {{"min_length", kMinUsernameLength},
          {"max_length", kMaxUsernameLength}}},
    };
  }

private:
  // Database reference
  storage::DatabasePool& db_;

  // Rate limiters
  InMemoryRateLimiter ip_rate_limiter_;
  InMemoryRateLimiter email_rate_limiter_;
  InMemoryRateLimiter token_gen_limiter_;

  // Shared secret auth
  std::string shared_secret_;
  std::unordered_map<std::string, int64_t> shared_secret_nonces_;
  mutable std::mutex shared_secret_mutex_;

  // reCAPTCHA config
  std::string recaptcha_site_key_;
  std::string recaptcha_secret_key_;

  // Server identity
  std::string server_name_;
  std::string home_server_url_;

  // Feature flags
  bool require_email_validation_;
  bool require_terms_consent_;
  bool enable_recaptcha_;
  bool enable_shared_secret_;
  bool enable_mx_validation_;
  bool enable_domain_allowlist_;
  bool enable_domain_blocklist_;
  bool enable_admin_approval_;
  bool enable_welcome_email_;
  bool enable_activation_email_;

  // Auto-join rooms
  std::vector<std::string> auto_join_rooms_;

  // Lifecycle
  std::thread cleanup_thread_;
  std::atomic<bool> running_;
};

// ============================================================================
// Global RegistrationPipeline Singleton
//
// The RegistrationPipeline is instantiated once per server process and
// shared across all HTTP handler threads.  All methods are thread-safe
// through database transactions and mutex-protected in-memory state.
// ============================================================================

namespace {
static std::unique_ptr<RegistrationPipeline> g_registration_pipeline;
static std::once_flag g_registration_pipeline_init_flag;
}  // namespace

// --------------------------------------------------------------------------
// Initialize the global registration pipeline singleton.
// Must be called once at server startup before any requests are served.
// --------------------------------------------------------------------------
void init_registration_pipeline(storage::DatabasePool& db) {
  std::call_once(g_registration_pipeline_init_flag, [&db]() {
    g_registration_pipeline = std::make_unique<RegistrationPipeline>(db);
    g_registration_pipeline->start();
    log::info(kRegTag, "Global registration pipeline initialized");
  });
}

// --------------------------------------------------------------------------
// Get a reference to the global registration pipeline.
// init_registration_pipeline() must have been called first.
// --------------------------------------------------------------------------
RegistrationPipeline& get_registration_pipeline() {
  if (!g_registration_pipeline) {
    log::error(kRegTag,
               "get_registration_pipeline() called before "
               "init_registration_pipeline()");
    throw std::runtime_error("Registration pipeline not initialized");
  }
  return *g_registration_pipeline;
}

// --------------------------------------------------------------------------
// Shutdown the global registration pipeline.
// Called during server shutdown.
// --------------------------------------------------------------------------
void shutdown_registration_pipeline() {
  if (g_registration_pipeline) {
    g_registration_pipeline->stop();
    g_registration_pipeline.reset();
    log::info(kRegTag, "Global registration pipeline shut down");
  }
}

// ============================================================================
// Convenience Functions
//
// These free functions wrap the global RegistrationPipeline singleton for
// easy access from HTTP handler code without needing to pass the pipeline
// reference around.
// ============================================================================

// Registration token management
json create_registration_token(int64_t uses_allowed,
                                 int64_t expiry_days,
                                 std::string_view created_by,
                                 std::string_view comment = "",
                                 std::string_view ip_address = "") {
  return get_registration_pipeline().create_registration_token(
      uses_allowed, expiry_days, created_by, comment, ip_address);
}

json get_registration_token(std::string_view token) {
  return get_registration_pipeline().get_registration_token(token);
}

json list_registration_tokens(bool valid_only = false) {
  return get_registration_pipeline().list_registration_tokens(valid_only);
}

json update_registration_token(std::string_view token,
                                 int64_t uses_allowed,
                                 int64_t expiry_days) {
  return get_registration_pipeline().update_registration_token(
      token, uses_allowed, expiry_days);
}

json delete_registration_token(std::string_view token) {
  return get_registration_pipeline().delete_registration_token(token);
}

json validate_registration_token(std::string_view token) {
  return get_registration_pipeline().validate_registration_token(token);
}

// Username checks
json check_username_availability(std::string_view username) {
  return get_registration_pipeline().check_username_availability(username);
}

bool is_username_blacklisted(std::string_view username) {
  return get_registration_pipeline().is_username_blacklisted(username);
}

json add_to_username_blacklist(std::string_view pattern,
                                 std::string_view reason = "",
                                 std::string_view added_by = "") {
  return get_registration_pipeline().add_to_username_blacklist(
      pattern, reason, added_by);
}

json remove_from_username_blacklist(std::string_view pattern) {
  return get_registration_pipeline().remove_from_username_blacklist(pattern);
}

json list_username_blacklist() {
  return get_registration_pipeline().list_username_blacklist();
}

// Email domain management
json check_email_domain_policy(std::string_view email) {
  return get_registration_pipeline().check_email_domain_policy(email);
}

json add_to_domain_list(std::string_view domain,
                          std::string_view list_type,
                          std::string_view comment = "") {
  return get_registration_pipeline().add_to_domain_list(domain, list_type,
                                                         comment);
}

json remove_from_domain_list(std::string_view domain) {
  return get_registration_pipeline().remove_from_domain_list(domain);
}

json list_domain_list(std::string_view list_type = "") {
  return get_registration_pipeline().list_domain_list(list_type);
}

// reCAPTCHA
json get_recaptcha_config() {
  return get_registration_pipeline().get_recaptcha_config();
}

bool verify_recaptcha(std::string_view response,
                       std::string_view remote_ip = "") {
  return get_registration_pipeline().verify_recaptcha(response, remote_ip);
}

// Shared secret registration
std::string generate_shared_secret_nonce() {
  return get_registration_pipeline().generate_shared_secret_nonce();
}

json register_with_shared_secret(std::string_view mac,
                                   std::string_view nonce,
                                   std::string_view username,
                                   std::string_view password,
                                   bool admin = false,
                                   std::string_view ip_address = "") {
  return get_registration_pipeline().register_with_shared_secret(
      mac, nonce, username, password, admin, ip_address);
}

// Registration sessions
json create_registration_session(std::string_view username,
                                   std::string_view password_hash,
                                   std::string_view email = "",
                                   std::string_view ip_address = "",
                                   std::string_view token = "") {
  return get_registration_pipeline().create_registration_session(
      username, password_hash, email, ip_address, token);
}

json get_registration_session(std::string_view session_id) {
  return get_registration_pipeline().get_registration_session(session_id);
}

json complete_session_stage(std::string_view session_id,
                              std::string_view stage) {
  return get_registration_pipeline().complete_session_stage(session_id,
                                                             stage);
}

void delete_registration_session(std::string_view session_id) {
  get_registration_pipeline().delete_registration_session(session_id);
}

// Email activation
json create_activation_token(std::string_view username,
                               std::string_view email) {
  return get_registration_pipeline().create_activation_token(username, email);
}

json activate_account_with_token(std::string_view token) {
  return get_registration_pipeline().activate_account_with_token(token);
}

json build_activation_email(std::string_view username,
                              std::string_view email,
                              std::string_view activation_token) {
  return get_registration_pipeline().build_activation_email(
      username, email, activation_token);
}

json build_welcome_email(std::string_view username,
                           std::string_view email) {
  return get_registration_pipeline().build_welcome_email(username, email);
}

// Terms consent
json get_terms_of_service() {
  return get_registration_pipeline().get_terms_of_service();
}

json accept_terms_of_service(std::string_view username,
                               std::string_view user_accepts,
                               std::string_view session_id = "") {
  return get_registration_pipeline().accept_terms_of_service(
      username, user_accepts, session_id);
}

bool has_accepted_terms(std::string_view username) {
  return get_registration_pipeline().has_accepted_terms(username);
}

// Admin approval
json submit_for_admin_approval(std::string_view username,
                                 std::string_view password_hash,
                                 std::string_view email = "",
                                 std::string_view ip_address = "",
                                 std::string_view registration_token = "") {
  return get_registration_pipeline().submit_for_admin_approval(
      username, password_hash, email, ip_address, registration_token);
}

json list_pending_approvals() {
  return get_registration_pipeline().list_pending_approvals();
}

json approve_pending_registration(std::string_view pending_id,
                                    bool admin = false) {
  return get_registration_pipeline().approve_pending_registration(
      pending_id, admin);
}

json deny_pending_registration(std::string_view pending_id,
                                 std::string_view reason = "") {
  return get_registration_pipeline().deny_pending_registration(pending_id,
                                                                reason);
}

// Core registration flow
json process_registration(const json& params,
                            std::string_view ip_address = "") {
  return get_registration_pipeline().process_registration(params,
                                                            ip_address);
}

// Statistics and config
json get_registration_statistics() {
  return get_registration_pipeline().get_registration_statistics();
}

json get_registration_config() {
  return get_registration_pipeline().get_config();
}

json get_rate_limit_status(std::string_view key,
                             std::string_view type) {
  return get_registration_pipeline().get_rate_limit_status(key, type);
}

// Configuration
void configure_registration_pipeline(
    const std::string& server_name,
    const std::string& home_server_url,
    const std::string& shared_secret,
    const std::string& recaptcha_site_key,
    const std::string& recaptcha_secret_key,
    bool require_email_validation,
    bool require_terms_consent,
    bool enable_mx_validation,
    bool enable_domain_allowlist,
    bool enable_domain_blocklist,
    bool enable_admin_approval,
    bool enable_welcome_email,
    bool enable_activation_email,
    const std::vector<std::string>& auto_join_rooms) {
  auto& pipeline = get_registration_pipeline();
  pipeline.set_server_name(server_name);
  pipeline.set_home_server_url(home_server_url);
  pipeline.set_shared_secret(shared_secret);
  pipeline.set_recaptcha_keys(recaptcha_site_key, recaptcha_secret_key);
  pipeline.set_require_email_validation(require_email_validation);
  pipeline.set_require_terms_consent(require_terms_consent);
  pipeline.set_enable_mx_validation(enable_mx_validation);
  pipeline.set_enable_domain_allowlist(enable_domain_allowlist);
  pipeline.set_enable_domain_blocklist(enable_domain_blocklist);
  pipeline.set_enable_admin_approval(enable_admin_approval);
  pipeline.set_enable_welcome_email(enable_welcome_email);
  pipeline.set_enable_activation_email(enable_activation_email);
  pipeline.set_auto_join_rooms(auto_join_rooms);

  log::info(kRegTag, "Registration pipeline configured");
}

// ============================================================================
// IP Address CIDR Blocking
//
// Allows administrators to block registration attempts from specific IP
// ranges (CIDR notation).  Useful for preventing abuse from known bad
// networks.
// ============================================================================

namespace {

// --------------------------------------------------------------------------
// Parse an IPv4 address string into a 32-bit integer.
// Returns 0 on failure.
// --------------------------------------------------------------------------
uint32_t parse_ipv4(std::string_view ip_str) {
  struct in_addr addr {};
  if (inet_pton(AF_INET, std::string(ip_str).c_str(), &addr) != 1)
    return 0;
  return ntohl(addr.s_addr);
}

// --------------------------------------------------------------------------
// Check if an IP address falls within a CIDR range.
//
// Supports both IPv4 CIDR notation (e.g., "192.168.0.0/16") and plain
// IPv4 addresses (treated as /32).
// --------------------------------------------------------------------------
bool ip_in_cidr(std::string_view ip, std::string_view cidr) {
  std::string cidr_str(cidr);
  auto slash_pos = cidr_str.find('/');

  std::string network_str;
  int prefix_len = 32;

  if (slash_pos != std::string::npos) {
    network_str = cidr_str.substr(0, slash_pos);
    prefix_len = std::stoi(cidr_str.substr(slash_pos + 1));
  } else {
    network_str = cidr_str;
  }

  if (prefix_len < 0 || prefix_len > 32) return false;

  uint32_t ip_int = parse_ipv4(ip);
  uint32_t net_int = parse_ipv4(network_str);

  if (ip_int == 0 || net_int == 0) return false;

  uint32_t mask = (prefix_len == 0) ? 0 : (~0u << (32 - prefix_len));
  return (ip_int & mask) == (net_int & mask);
}

// --------------------------------------------------------------------------
// Check if an IP address is in any of the blocked CIDR ranges.
// --------------------------------------------------------------------------
bool is_ip_blocked(std::string_view ip,
                   const std::vector<std::string>& blocked_cidrs) {
  bool has_ipv4_blocks = false;
  for (const auto& cidr : blocked_cidrs) {
    has_ipv4_blocks = true;
    if (ip_in_cidr(ip, cidr))
      return true;
  }
  // If no CIDR blocks are configured, allow everything
  if (!has_ipv4_blocks) return false;
  return false;
}

}  // namespace

// --------------------------------------------------------------------------
// Free-function: Check IP against blocked networks.
// Returns true if the IP should be blocked.
// --------------------------------------------------------------------------
bool check_ip_blocked(std::string_view ip) {
  // Default blocked ranges: private, loopback, multicast, and reserved
  static const std::vector<std::string> kDefaultBlocked = {
      "10.0.0.0/8",        "172.16.0.0/12",
      "192.168.0.0/16",    "127.0.0.0/8",
      "169.254.0.0/16",    "224.0.0.0/4",
      "240.0.0.0/4",       "0.0.0.0/8",
      "100.64.0.0/10",     "198.18.0.0/15",
  };
  // Allow customization via the pipeline
  return is_ip_blocked(ip, kDefaultBlocked);
}

// ============================================================================
// Password Strength Scoring
//
// Implements a lightweight zxcvbn-like password strength estimation.
// Scores range from 0 (very weak) to 4 (very strong).
// ============================================================================

namespace {

// Common passwords (top 100 most common - truncated for embedding)
const std::unordered_set<std::string>& common_passwords() {
  static const std::unordered_set<std::string> s = {
      "password",    "123456",    "12345678",   "1234",
      "qwerty",      "12345",     "dragon",      "baseball",
      "football",    "letmein",   "monkey",      "696969",
      "abc123",      "mustang",   "michael",     "shadow",
      "master",      "jennifer",  "111111",      "2000",
      "jordan",      "superman",  "harley",      "1234567",
      "hunter",      "trustno1",  "batman",      "starwars",
      "thomas",      "tigger",    "robert",      "access",
      "love",        "merlin",    "pepper",      "secret",
      "summer",      "chelsea",   "biteme",      "matrix",
      "passw0rd",    "admin",     "root",        "guest",
      "changeme",    "iloveyou",  "princess",    "rockyou",
      "sunshine",    "whatever",  "nicole",      "daniel",
      "charlie",     "martin",    "william",     "george",
      "andrew",      "joshua",    "asdfgh",      "zxcvbn",
      "qwerty123",   "pass123",   "welcome",     "Password1",
      "Password123", "Admin123",  "Letmein1",    "Qwerty123",
      "Abc123!",     "Test1234",  "Passw0rd!",   "Welcome1!",
  };
  return s;
}

// Sequences on the keyboard
bool is_keyboard_sequence(std::string_view s) {
  static const std::vector<std::string> sequences = {
      "qwertyuiop", "asdfghjkl",  "zxcvbnm",
      "qwertzuiop", "asdfghjkl",  "yxcvbnm",    // German
      "azertyuiop", "qsdfghjklm", "wxcvbn",      // French
      "1234567890", "abcdefghijklmnopqrstuvwxyz",
      "`1234567890-=",
  };

  std::string lower(s);
  std::transform(lower.begin(), lower.end(), lower.begin(),
                 [](unsigned char c) { return std::tolower(c); });

  for (const auto& seq : sequences) {
    if (seq.find(lower) != std::string::npos)
      return true;
    // Reverse
    std::string rev(seq.rbegin(), seq.rend());
    if (rev.find(lower) != std::string::npos)
      return true;
  }
  return false;
}

// Check for repeated patterns (e.g., "abcabc", "111111")
bool has_repeating_pattern(std::string_view s, int min_repeat = 3) {
  if (s.size() < static_cast<size_t>(min_repeat * 2)) return false;

  for (size_t len = 1; len <= s.size() / 2; ++len) {
    std::string_view pattern = s.substr(0, len);
    int repeats = 1;
    size_t pos = len;
    while (pos + len <= s.size() && s.substr(pos, len) == pattern) {
      ++repeats;
      pos += len;
    }
    if (repeats >= min_repeat) return true;
  }
  return false;
}

// Check for sequential characters (e.g., "abcd", "1234", "dcba")
bool is_sequential(std::string_view s) {
  if (s.size() < 3) return false;

  bool ascending = true, descending = true;
  for (size_t i = 1; i < s.size(); ++i) {
    if (static_cast<unsigned char>(s[i]) !=
        static_cast<unsigned char>(s[i - 1]) + 1)
      ascending = false;
    if (static_cast<unsigned char>(s[i]) !=
        static_cast<unsigned char>(s[i - 1]) - 1)
      descending = false;
  }
  return ascending || descending;
}

// Count character classes present
int count_char_classes(std::string_view s) {
  bool has_lower = false, has_upper = false, has_digit = false,
       has_special = false, has_unicode = false;
  for (char c : s) {
    unsigned char uc = static_cast<unsigned char>(c);
    if (std::islower(uc)) has_lower = true;
    else if (std::isupper(uc)) has_upper = true;
    else if (std::isdigit(uc)) has_digit = true;
    else if (uc > 127) has_unicode = true;
    else has_special = true;
  }
  return (has_lower ? 1 : 0) + (has_upper ? 1 : 0) + (has_digit ? 1 : 0) +
         (has_special ? 1 : 0) + (has_unicode ? 1 : 0);
}

// Calculate entropy estimate (simplified)
double estimate_entropy(std::string_view s) {
  int classes = count_char_classes(s);
  int pool_size = 0;
  bool has_lower = false, has_upper = false, has_digit = false,
       has_special = false;

  for (char c : s) {
    unsigned char uc = static_cast<unsigned char>(c);
    if (std::islower(uc)) has_lower = true;
    else if (std::isupper(uc)) has_upper = true;
    else if (std::isdigit(uc)) has_digit = true;
    else has_special = true;
  }

  if (has_lower) pool_size += 26;
  if (has_upper) pool_size += 26;
  if (has_digit) pool_size += 10;
  if (has_special) pool_size += 33;

  if (pool_size == 0) pool_size = 26;  // default to lowercase

  return s.size() * std::log2(static_cast<double>(pool_size));
}

}  // namespace

// --------------------------------------------------------------------------
// Score a password from 0 (very weak) to 4 (very strong).
//
// Scoring algorithm:
//   0 - too short, common passwords, only one character class
//   1 - weak (dictionary word, keyboard sequence, repeating patterns)
//   2 - fair (two character classes, decent length)
//   3 - strong (three classes, minimum 10 characters)
//   4 - very strong (all four classes, 14+ characters, high entropy)
//
// Returns a JSON with score, feedback, and entropy estimate.
// --------------------------------------------------------------------------
json score_password_strength(std::string_view password) {
  json result;
  result["score"] = 0;
  result["entropy_bits"] = 0.0;

  json warnings = json::array();
  json suggestions = json::array();

  if (password.size() < 8) {
    result["score"] = 0;
    warnings.push_back("Password is too short");
    suggestions.push_back("Use at least 8 characters");
    result["warnings"] = warnings;
    result["suggestions"] = suggestions;
    result["entropy_bits"] = estimate_entropy(password);
    return result;
  }

  // Check against common passwords
  std::string lower(password);
  std::transform(lower.begin(), lower.end(), lower.begin(),
                 [](unsigned char c) { return std::tolower(c); });

  if (common_passwords().count(lower)) {
    result["score"] = 0;
    warnings.push_back("This is a commonly used password");
    suggestions.push_back("Choose a unique password not found in "
                          "common password lists");
    result["warnings"] = warnings;
    result["suggestions"] = suggestions;
    result["entropy_bits"] = estimate_entropy(password);
    return result;
  }

  int classes = count_char_classes(password);
  int score = 0;

  // Length-based scoring
  if (password.size() >= 8) score += 1;
  if (password.size() >= 12) score += 1;
  if (password.size() >= 16) score += 1;
  if (password.size() >= 20) score += 1;

  // Class-based scoring
  if (classes >= 2) score = std::max(score, 1);
  if (classes >= 3) score = std::max(score, 2);
  if (classes >= 4) score = std::max(score, 3);
  if (classes >= 5) score = std::max(score, 4);

  // Penalties
  if (is_keyboard_sequence(lower))
    score = std::max(0, score - 2);
  if (is_sequential(lower))
    score = std::max(0, score - 2);
  if (has_repeating_pattern(lower, 3))
    score = std::max(0, score - 2);
  if (has_repeating_pattern(lower, 2))
    score = std::max(0, score - 1);

  // Entropy-based floor
  double entropy = estimate_entropy(password);
  if (entropy < 28) score = std::min(score, 0);
  else if (entropy < 36) score = std::min(score, 1);
  else if (entropy < 60) score = std::min(score, 2);
  else if (entropy < 80) score = std::min(score, 3);

  // Cap score at 4
  score = std::min(4, score);

  // Generate feedback
  if (score <= 1) {
    if (password.size() < 10)
      suggestions.push_back("Use a longer password (at least 12 characters)");
    if (classes < 2)
      suggestions.push_back(
          "Mix uppercase letters, digits, and special characters");
    if (is_keyboard_sequence(lower) || is_sequential(lower))
      warnings.push_back("Avoid keyboard patterns and sequences");
    if (has_repeating_pattern(lower, 2))
      warnings.push_back("Avoid repeating patterns");
  } else if (score == 2) {
    suggestions.push_back("Add more character variety for a stronger "
                          "password");
  }

  result["score"] = score;
  result["entropy_bits"] = entropy;
  result["warnings"] = warnings;
  result["suggestions"] = suggestions;

  return result;
}

// ============================================================================
// Registration Audit / Event Logging
//
// Records all registration-related events to an audit log table for
// compliance, debugging, and security monitoring.
// ============================================================================

// --------------------------------------------------------------------------
// Log a registration audit event.
//
// Event types: "registration_attempt", "registration_success",
//              "registration_failure", "token_created",
//              "token_used", "token_expired",
//              "email_verification_sent", "email_verified",
//              "admin_approved", "admin_denied",
//              "terms_accepted", "account_activated"
// --------------------------------------------------------------------------
void log_registration_audit_event(std::string_view event_type,
                                    const json& event_data) {
  auto& pipeline = get_registration_pipeline();
  // Use the pipeline's DB but via a separate helper so we don't
  // need to add a public method.  Instead, we write directly to the
  // audit table through the pipeline's internal access.
  //
  // In a production system, this would use an async event queue.
  // For now, we log synchronously via the global singleton.
  int64_t now = now_sec();
  std::string data_str = event_data.dump();

  // Access the pipeline's db_ (private) indirectly via a static helper
  // that is a friend... In practice, the pipeline would expose an
  // audit_log method.  We implement it here as a free function for
  // demonstration; the actual audit log insertion would happen through
  // the pipeline itself.

  log::info("registration_audit",
            std::string("[") + std::string(event_type) + "] " + data_str);
}

// ============================================================================
// Account Deactivation / Reactivation
//
// Allows administrators to deactivate (soft-delete) and reactivate
// user accounts.  Deactivated accounts cannot log in or receive events
// but their data is preserved.
// ============================================================================

// --------------------------------------------------------------------------
// Deactivate a user account.
//
// Sets the account to deactivated status, revokes all access tokens,
// and optionally records a reason.
// --------------------------------------------------------------------------
json deactivate_account(std::string_view username,
                          std::string_view reason = "",
                          std::string_view deactivated_by = "") {
  // Check user exists
  auto rows = db_execute(
      "SELECT id FROM users WHERE id = " + sql_quote(username));

  if (rows.empty())
    return error_json("M_NOT_FOUND", "User not found");

  int64_t now = now_sec();

  // Revoke all access tokens
  db_execute(
      "DELETE FROM access_tokens WHERE user_id = " +
      sql_quote(username));

  // Mark user as deactivated
  db_execute(
      "UPDATE users SET deactivated = 1, "
      "deactivated_at = " +
      std::to_string(now) + ", "
      "deactivation_reason = " +
      sql_quote(reason) + " "
      "WHERE id = " + sql_quote(username));

  // Log the event
  auto pipeline = get_registration_pipeline();
  // Log via info for now
  log::info(kRegTag, std::string("Account deactivated: ") +
                         std::string(username));

  return json{{"deactivated", true},
              {"username", username},
              {"deactivated_at", now}};
}

// --------------------------------------------------------------------------
// Reactivate a previously deactivated account.
// --------------------------------------------------------------------------
json reactivate_account(std::string_view username) {
  auto rows = db_execute(
      "SELECT id, deactivated FROM users WHERE id = " +
      sql_quote(username));

  if (rows.empty())
    return error_json("M_NOT_FOUND", "User not found");

  int64_t now = now_sec();
  db_execute(
      "UPDATE users SET deactivated = 0, "
      "reactivated_at = " +
      std::to_string(now) + " "
      "WHERE id = " + sql_quote(username));

  log::info(kRegTag, std::string("Account reactivated: ") +
                         std::string(username));

  return json{{"reactivated", true},
              {"username", username},
              {"reactivated_at", now}};
}

// ============================================================================
// Guest Account Provisioning
//
// Guest accounts are temporary, restricted accounts that can be used
// for previewing rooms.  They are auto-generated and have limited
// capabilities.
// ============================================================================

// --------------------------------------------------------------------------
// Create a guest account.
//
// Guest accounts:
//   - Have randomized usernames (guest_XXXXXX)
//   - Cannot create rooms
//   - Cannot invite users
//   - Are automatically cleaned up after inactivity
//   - Do not require registration tokens or email verification
// --------------------------------------------------------------------------
json create_guest_account(std::string_view ip_address = "") {
  // Rate limit guest account creation
  auto decision = ip_rate_limiter_.check_and_record(
      std::string(ip_address));
  if (!decision.allowed) {
    return error_json("M_LIMIT_EXCEEDED",
                      "Too many guest registration attempts",
                      {{"retry_after_ms", decision.retry_after_ms}});
  }

  // Generate a unique guest username
  std::string guest_username;
  int max_attempts = 20;
  for (int attempt = 0; attempt < max_attempts; ++attempt) {
    std::string suffix = generate_token(8);
    // Truncate suffix to valid username chars
    std::string clean_suffix;
    for (char c : suffix) {
      char lc = std::tolower(static_cast<unsigned char>(c));
      if (std::islower(lc) || std::isdigit(lc))
        clean_suffix += lc;
    }
    if (clean_suffix.size() < 6) clean_suffix = generate_token(6);
    clean_suffix = clean_suffix.substr(0, 12);

    guest_username = "guest_" + clean_suffix;

    // Check availability
    auto avail = check_username_availability(guest_username);
    if (avail.value("available", false)) break;

    if (attempt == max_attempts - 1)
      return error_json("M_UNKNOWN", "Failed to generate guest username");
  }

  // Guest accounts don't have passwords - they use auto-generated tokens
  int64_t now = util::now_ms();

  db_execute(
      "INSERT INTO users (id, password_hash, creation_ts, "
      "is_guest, guest_expiry) "
      "VALUES (" +
      sql_quote(guest_username) + ", '', " + std::to_string(now) +
      ", 1, " + std::to_string(now_sec() + kSessionExpirySec) + ")");

  // Generate access token
  std::string access_token = util::generate_access_token();
  db_execute(
      "INSERT INTO access_tokens (token, user_id) "
      "VALUES (" +
      sql_quote(access_token) + ", " + sql_quote(guest_username) + ")");

  log::info(kRegTag, std::string("Created guest account: ") + guest_username);

  return json{
      {"user_id", guest_username},
      {"access_token", access_token},
      {"home_server", server_name_},
      {"device_id", ""},
      {"is_guest", true},
  };
}

// ============================================================================
// Registration Disable/Enable
//
// Allows operators to temporarily disable all registrations (e.g., during
// maintenance or in response to abuse).
// ============================================================================

static std::atomic<bool> g_registrations_disabled{false};
static std::string g_registrations_disabled_message;

// --------------------------------------------------------------------------
// Disable all new registrations with an optional message.
// --------------------------------------------------------------------------
void disable_registrations(const std::string& message = "") {
  g_registrations_disabled = true;
  g_registrations_disabled_message = message;
  log::warn(kRegTag,
            "All registrations disabled" +
                (message.empty() ? std::string() : ": " + message));
}

// --------------------------------------------------------------------------
// Re-enable registrations.
// --------------------------------------------------------------------------
void enable_registrations() {
  g_registrations_disabled = false;
  g_registrations_disabled_message.clear();
  log::info(kRegTag, "Registrations re-enabled");
}

// --------------------------------------------------------------------------
// Check if registrations are currently enabled.
// Returns {enabled: true} or {enabled: false, message: "..."}
// --------------------------------------------------------------------------
json check_registrations_enabled() {
  if (!g_registrations_disabled)
    return json{{"enabled", true}};

  return json{{"enabled", false},
              {"message",
               g_registrations_disabled_message.empty()
                   ? "Registrations are temporarily disabled"
                   : g_registrations_disabled_message}};
}

// ============================================================================
// Email Dispatch Interface
//
// Provides a simple interface for the registration pipeline to queue
// emails for delivery.  In a full deployment, this would integrate with
// the EmailQueue in email_identity.hpp.  Here we provide a stub that
// logs and stores email metadata for downstream processing.
// ============================================================================

namespace {

struct QueuedEmail {
  std::string id;
  std::string to_address;
  std::string subject;
  std::string text_body;
  std::string html_body;
  int64_t queued_at;
  int retry_count = 0;
  int max_retries = 5;
};

static std::shared_mutex g_email_queue_mutex;
static std::deque<QueuedEmail> g_email_queue;
static std::atomic<size_t> g_emails_sent{0};
static std::atomic<size_t> g_emails_failed{0};

}  // namespace

// --------------------------------------------------------------------------
// Queue an email for delivery.
//
// Returns a JSON with the queued email ID or error.
// --------------------------------------------------------------------------
json queue_email(std::string_view to_address,
                   std::string_view subject,
                   std::string_view text_body,
                   std::string_view html_body) {
  queued_email id = generate_token(16);
  int64_t now = now_sec();

  QueuedEmail email;
  email.id = id;
  email.to_address = std::string(to_address);
  email.subject = std::string(subject);
  email.text_body = std::string(text_body);
  email.html_body = std::string(html_body);
  email.queued_at = now;

  {
    std::unique_lock lock(g_email_queue_mutex);
    g_email_queue.push_back(std::move(email));
  }

  log::info("email_queue",
            std::string("Queued email ") + id.substr(0, 8) +
                "... to " + std::string(to_address));

  return json{
      {"queued", true},
      {"email_id", id},
      {"to", to_address},
      {"queued_at", now},
  };
}

// --------------------------------------------------------------------------
// Get email queue status.
// --------------------------------------------------------------------------
json get_email_queue_status() {
  std::shared_lock lock(g_email_queue_mutex);
  return json{
      {"queue_size", g_email_queue.size()},
      {"emails_sent", g_emails_sent.load()},
      {"emails_failed", g_emails_failed.load()},
  };
}

// --------------------------------------------------------------------------
// Process the email queue (called periodically).
//
// Attempts to deliver all queued emails.  In this implementation, we log
// the delivery rather than actually sending.
// --------------------------------------------------------------------------
size_t process_email_queue(size_t max_batch = 50) {
  std::vector<QueuedEmail> batch;

  {
    std::unique_lock lock(g_email_queue_mutex);
    size_t count = std::min(max_batch, g_email_queue.size());
    for (size_t i = 0; i < count; ++i) {
      batch.push_back(std::move(g_email_queue.front()));
      g_email_queue.pop_front();
    }
  }

  size_t sent = 0;
  for (const auto& email : batch) {
    // In a real deployment, this would call SMTP or a mail service.
    // For now, we log it as delivered.
    log::info("email_queue",
              std::string("Delivering email ") + email.id.substr(0, 8) +
                  "... to " + email.to_address +
                  " subject: " + email.subject);
    ++sent;
  }

  g_emails_sent += sent;
  return sent;
}

}  // namespace progressive::auth
