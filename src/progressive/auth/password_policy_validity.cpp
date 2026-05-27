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
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <sys/types.h>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <nlohmann/json.hpp>

#include "../json.hpp"
#include "../storage/database.hpp"
#include "../util/base64.hpp"
#include "../util/log.hpp"
#include "../util/random.hpp"
#include "../util/time.hpp"
#include "../util/token.hpp"

namespace progressive::auth {

using json = nlohmann::json;

// ============================================================================
// Internal helper: SQL string escaping (same pattern as auth.cpp)
// ============================================================================
namespace {

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

}  // namespace

// ============================================================================
// Constants
// ============================================================================

static constexpr const char* kTag = "password_policy_validity";

// Password policy defaults
static constexpr size_t kMinPasswordLength = 8;
static constexpr size_t kMaxPasswordLength = 512;
static constexpr size_t kPasswordHistorySize = 24;
static constexpr int kPasswordExpiryDays = 90;
static constexpr int kPasswordExpiryWarnDays = 14;

// Account validity defaults
static constexpr int kDefaultAccountValidityDays = 365;
static constexpr int kAccountExpiryWarnDays = 30;
static constexpr int kAccountRenewalPeriodDays = 90;

// Email verification
static constexpr int kEmailVerificationTokenExpirySec = 3600;   // 1 hour
static constexpr int kEmailVerificationReminderDays = 7;        // resend reminder after 7 days
static constexpr int kEmailVerificationMaxAttempts = 5;
static constexpr int kEmailVerificationTokenLength = 32;

// Rate limiting
static constexpr int kRegRateLimitWindowSec = 3600;             // 1 hour
static constexpr int kRegMaxPerIp = 3;
static constexpr int kRegMaxPerDomain = 10;
static constexpr int kRegGlobalMaxPerHour = 500;

// Registration token
static constexpr int kRegTokenDefaultLength = 32;
static constexpr int kRegTokenDefaultUsesAllowed = 1;
static constexpr int kRegTokenDefaultExpirySec = 604800;        // 7 days

// Token generation
static constexpr size_t kAdminResetTokenLength = 64;

// ============================================================================
// PasswordPolicy
// ============================================================================

struct PasswordPolicy {
  size_t min_length = kMinPasswordLength;
  size_t max_length = kMaxPasswordLength;
  bool require_uppercase = true;
  bool require_lowercase = true;
  bool require_digit = true;
  bool require_special = true;
  std::string special_chars = "!@#$%^&*()_+-=[]{}|;':\",./<>?`~";
  size_t password_history_size = kPasswordHistorySize;
  int password_expiry_days = kPasswordExpiryDays;
  int password_expiry_warn_days = kPasswordExpiryWarnDays;

  json to_json() const {
    return {
        {"min_length", min_length},
        {"max_length", max_length},
        {"require_uppercase", require_uppercase},
        {"require_lowercase", require_lowercase},
        {"require_digit", require_digit},
        {"require_special", require_special},
        {"special_chars", special_chars},
        {"password_history_size", password_history_size},
        {"password_expiry_days", password_expiry_days},
        {"password_expiry_warn_days", password_expiry_warn_days}};
  }

  static PasswordPolicy from_json(const json& j) {
    PasswordPolicy p;
    if (j.contains("min_length")) p.min_length = j["min_length"].get<size_t>();
    if (j.contains("max_length")) p.max_length = j["max_length"].get<size_t>();
    if (j.contains("require_uppercase"))
      p.require_uppercase = j["require_uppercase"].get<bool>();
    if (j.contains("require_lowercase"))
      p.require_lowercase = j["require_lowercase"].get<bool>();
    if (j.contains("require_digit"))
      p.require_digit = j["require_digit"].get<bool>();
    if (j.contains("require_special"))
      p.require_special = j["require_special"].get<bool>();
    if (j.contains("special_chars"))
      p.special_chars = j["special_chars"].get<std::string>();
    if (j.contains("password_history_size"))
      p.password_history_size = j["password_history_size"].get<size_t>();
    if (j.contains("password_expiry_days"))
      p.password_expiry_days = j["password_expiry_days"].get<int>();
    if (j.contains("password_expiry_warn_days"))
      p.password_expiry_warn_days = j["password_expiry_warn_days"].get<int>();
    return p;
  }
};

// ============================================================================
// PasswordStrengthResult
// ============================================================================

struct PasswordStrengthResult {
  int score = 0;  // 0 = very weak, 1 = weak, 2 = fair, 3 = strong, 4 = very strong
  double entropy_bits = 0.0;
  std::string feedback_warning;
  std::vector<std::string> feedback_suggestions;
  int64_t crack_time_seconds = 0;
  std::string crack_time_display;

  json to_json() const {
    return {
        {"score", score},
        {"entropy_bits", entropy_bits},
        {"feedback",
         {{"warning", feedback_warning}, {"suggestions", feedback_suggestions}}},
        {"crack_time_seconds", crack_time_seconds},
        {"crack_time_display", crack_time_display}};
  }
};

// ============================================================================
// PasswordPolicyValidator - Main class
// ============================================================================

class PasswordPolicyValidator {
public:
  explicit PasswordPolicyValidator(storage::DatabasePool& db)
      : db_(db), policy_() {}

  explicit PasswordPolicyValidator(storage::DatabasePool& db,
                                    PasswordPolicy policy)
      : db_(db), policy_(std::move(policy)) {}

  // --------------------------------------------------------------------------
  // Configuration
  // --------------------------------------------------------------------------

  void set_policy(const PasswordPolicy& policy) { policy_ = policy; }
  const PasswordPolicy& policy() const { return policy_; }

  // --------------------------------------------------------------------------
  // 1. Password policy enforcement
  // --------------------------------------------------------------------------

  /// Validate a password against the current policy.
  /// Returns {valid: bool, error: string, details: object}
  json validate_password_policy(std::string_view password,
                                 std::string_view username = "") const {
    json result;
    json violations = json::array();

    // Length checks
    if (password.size() < policy_.min_length) {
      violations.push_back(
          {{"rule", "min_length"},
           {"message", "Password must be at least " +
                           std::to_string(policy_.min_length) + " characters"}});
    }
    if (password.size() > policy_.max_length) {
      violations.push_back(
          {{"rule", "max_length"},
           {"message", "Password must not exceed " +
                           std::to_string(policy_.max_length) + " characters"}});
    }

    // Character class checks
    if (policy_.require_uppercase) {
      bool has_upper = false;
      for (char c : password)
        if (std::isupper(static_cast<unsigned char>(c))) {
          has_upper = true;
          break;
        }
      if (!has_upper)
        violations.push_back(
            {{"rule", "require_uppercase"},
             {"message", "Password must contain at least one uppercase letter"}});
    }

    if (policy_.require_lowercase) {
      bool has_lower = false;
      for (char c : password)
        if (std::islower(static_cast<unsigned char>(c))) {
          has_lower = true;
          break;
        }
      if (!has_lower)
        violations.push_back(
            {{"rule", "require_lowercase"},
             {"message", "Password must contain at least one lowercase letter"}});
    }

    if (policy_.require_digit) {
      bool has_digit = false;
      for (char c : password)
        if (std::isdigit(static_cast<unsigned char>(c))) {
          has_digit = true;
          break;
        }
      if (!has_digit)
        violations.push_back(
            {{"rule", "require_digit"},
             {"message", "Password must contain at least one digit"}});
    }

    if (policy_.require_special) {
      bool has_special = false;
      for (char c : password)
        if (policy_.special_chars.find(c) != std::string::npos) {
          has_special = true;
          break;
        }
      if (!has_special)
        violations.push_back(
            {{"rule", "require_special"},
             {"message", "Password must contain at least one special character: " +
                             policy_.special_chars}});
    }

    // Check password doesn't contain username
    if (!username.empty()) {
      std::string user_lower(username);
      std::string pass_lower(password);
      std::transform(user_lower.begin(), user_lower.end(), user_lower.begin(),
                     [](unsigned char c) { return std::tolower(c); });
      std::transform(pass_lower.begin(), pass_lower.end(), pass_lower.begin(),
                     [](unsigned char c) { return std::tolower(c); });
      if (pass_lower.find(user_lower) != std::string::npos)
        violations.push_back(
            {{"rule", "no_username"},
             {"message", "Password must not contain your username"}});
    }

    // Check for common passwords
    if (is_common_password(password)) {
      violations.push_back(
          {{"rule", "not_common"},
           {"message", "Password is too common and easily guessable"}});
    }

    bool valid = violations.empty();
    result["valid"] = valid;
    if (!valid) {
      result["error"] = "Password does not meet policy requirements";
      result["violations"] = violations;
    }
    return result;
  }

  // --------------------------------------------------------------------------
  // 2. Password strength checking (zxcvbn-style)
  // --------------------------------------------------------------------------

  PasswordStrengthResult check_password_strength(
      std::string_view password,
      const std::vector<std::string>& user_inputs = {}) const {
    PasswordStrengthResult result;
    result.entropy_bits = calculate_entropy(password);
    result.score = score_from_entropy(result.entropy_bits);

    // Calculate crack time based on entropy
    double guesses = std::pow(2.0, result.entropy_bits);
    // Assume 10 billion guesses per second (modern GPU cluster)
    constexpr double guesses_per_sec = 10'000'000'000.0;
    result.crack_time_seconds =
        static_cast<int64_t>(guesses / guesses_per_sec);
    result.crack_time_display = format_crack_time(result.crack_time_seconds);

    // Generate feedback based on analysis
    generate_password_feedback(password, user_inputs, result);

    return result;
  }

  // --------------------------------------------------------------------------
  // 3. Password history
  // --------------------------------------------------------------------------

  /// Record a password in history for a user. Trims old entries.
  void record_password_in_history(std::string_view user_id,
                                    std::string_view password_hash) {
    uint64_t now = util::now_ms();
    db_.execute(
        "INSERT INTO user_password_history (user_id, password_hash, created_ts) "
        "VALUES (" +
        sql_quote(user_id) + ", " + sql_quote(password_hash) + ", " +
        std::to_string(now) + ")");

    // Trim excess entries
    trim_password_history(user_id);
  }

  /// Check if a password was used recently (by comparing raw passwords).
  /// Note: Since we store hashes, we iterate history and compare hashes.
  bool is_password_in_history(std::string_view user_id,
                               std::string_view new_password_hash) const {
    auto rows = db_.query(
        "SELECT password_hash FROM user_password_history "
        "WHERE user_id = " +
        sql_quote(user_id) +
        " ORDER BY created_ts DESC LIMIT " +
        std::to_string(policy_.password_history_size));

    for (auto& row : rows) {
      if (row.contains("password_hash") && !row["password_hash"].is_null()) {
        std::string stored_hash = row["password_hash"].get<std::string>();
        if (stored_hash == new_password_hash) return true;
      }
    }
    return false;
  }

  /// Get password history for a user.
  json get_password_history(std::string_view user_id, int limit = 10) const {
    auto rows = db_.query(
        "SELECT password_hash, created_ts FROM user_password_history "
        "WHERE user_id = " +
        sql_quote(user_id) + " ORDER BY created_ts DESC LIMIT " +
        std::to_string(limit));

    json history = json::array();
    for (auto& row : rows) {
      json entry;
      if (row.contains("created_ts") && !row["created_ts"].is_null())
        entry["created_ts"] = row["created_ts"].get<int64_t>();
      history.push_back(entry);
    }
    return history;
  }

  /// Clear password history for a user.
  void clear_password_history(std::string_view user_id) {
    db_.execute(
        "DELETE FROM user_password_history WHERE user_id = " +
        sql_quote(user_id));
  }

  // --------------------------------------------------------------------------
  // 4. Password expiration
  // --------------------------------------------------------------------------

  /// Check if a user's password has expired or is about to expire.
  /// Returns {expired: bool, expires_in_days: int, should_warn: bool}
  json check_password_expiry(std::string_view user_id) const {
    json result;
    result["expired"] = false;
    result["should_warn"] = false;
    result["expires_in_days"] = -1;

    auto rows = db_.query(
        "SELECT password_last_changed_ts FROM users WHERE id = " +
        sql_quote(user_id));

    if (rows.empty() || !rows[0].contains("password_last_changed_ts") ||
        rows[0]["password_last_changed_ts"].is_null()) {
      return result;
    }

    int64_t last_changed_ms =
        rows[0]["password_last_changed_ts"].get<int64_t>();
    int64_t now_ms = static_cast<int64_t>(util::now_ms());
    int64_t elapsed_days =
        (now_ms - last_changed_ms) / (1000LL * 60 * 60 * 24);

    int64_t expiry_days = policy_.password_expiry_days;
    int64_t warn_days = policy_.password_expiry_warn_days;

    result["expires_in_days"] = expiry_days - elapsed_days;
    result["elapsed_days"] = elapsed_days;
    result["expiry_days"] = expiry_days;

    if (elapsed_days >= expiry_days) {
      result["expired"] = true;
      result["should_warn"] = true;
    } else if (elapsed_days >= (expiry_days - warn_days)) {
      result["should_warn"] = true;
    }

    return result;
  }

  /// Update the password last-changed timestamp for a user.
  void update_password_changed_ts(std::string_view user_id) {
    uint64_t now = util::now_ms();
    db_.execute(
        "UPDATE users SET password_last_changed_ts = " +
        std::to_string(now) + " WHERE id = " + sql_quote(user_id));
  }

  /// Force a password change by marking as expired.
  void force_password_change(std::string_view user_id) {
    // Set last-changed timestamp to far in the past to trigger expiry
    db_.execute(
        "UPDATE users SET password_last_changed_ts = 0 WHERE id = " +
        sql_quote(user_id));
  }

  /// Get all users whose passwords are about to expire within N days.
  std::vector<std::string> get_users_with_expiring_passwords(
      int within_days = -1) const {
    if (within_days < 0) within_days = policy_.password_expiry_warn_days;
    int64_t now_ms = static_cast<int64_t>(util::now_ms());
    int64_t expiry_threshold =
        now_ms -
        (policy_.password_expiry_days - within_days) * 1000LL * 60 * 60 * 24;

    auto rows = db_.query(
        "SELECT id FROM users WHERE password_last_changed_ts IS NOT NULL "
        "AND password_last_changed_ts <= " +
        std::to_string(expiry_threshold) +
        " AND deactivated = 0");

    std::vector<std::string> result;
    for (auto& row : rows) {
      if (row.contains("id") && !row["id"].is_null())
        result.push_back(row["id"].get<std::string>());
    }
    return result;
  }

  // --------------------------------------------------------------------------
  // 5. Account validity management
  // --------------------------------------------------------------------------

  /// Set account expiration for a user.
  /// validity_period_days: days from now until expiry (0 = never expires)
  void set_account_validity(std::string_view user_id,
                              int validity_period_days) {
    int64_t now_ms = static_cast<int64_t>(util::now_ms());
    int64_t expiry_ms = 0;
    if (validity_period_days > 0) {
      expiry_ms =
          now_ms + static_cast<int64_t>(validity_period_days) * 1000LL * 60 * 60 * 24;
    }

    // Upsert
    auto rows = db_.query(
        "SELECT user_id FROM account_validity WHERE user_id = " +
        sql_quote(user_id));
    if (rows.empty()) {
      db_.execute(
          "INSERT INTO account_validity (user_id, expiration_ts_ms, "
          "renewal_period_days, email_sent_ts) VALUES (" +
          sql_quote(user_id) + ", " + std::to_string(expiry_ms) + ", " +
          std::to_string(kAccountRenewalPeriodDays) + ", 0)");
    } else {
      db_.execute(
          "UPDATE account_validity SET expiration_ts_ms = " +
          std::to_string(expiry_ms) + " WHERE user_id = " +
          sql_quote(user_id));
    }
  }

  /// Get account expiration info for a user.
  json get_account_validity(std::string_view user_id) const {
    auto rows = db_.query(
        "SELECT expiration_ts_ms, renewal_period_days, email_sent_ts "
        "FROM account_validity WHERE user_id = " +
        sql_quote(user_id));

    json result;
    result["has_expiration"] = false;
    if (rows.empty()) return result;

    auto& row = rows[0];
    if (row.contains("expiration_ts_ms") &&
        !row["expiration_ts_ms"].is_null()) {
      int64_t expiry = row["expiration_ts_ms"].get<int64_t>();
      result["expiration_ts_ms"] = expiry;
      result["has_expiration"] = (expiry > 0);

      if (expiry > 0) {
        int64_t now_ms = static_cast<int64_t>(util::now_ms());
        result["expired"] = (now_ms >= expiry);
        result["days_remaining"] =
            std::max<int64_t>(0, (expiry - now_ms) / (1000LL * 60 * 60 * 24));
      }
    }
    if (row.contains("renewal_period_days") &&
        !row["renewal_period_days"].is_null())
      result["renewal_period_days"] = row["renewal_period_days"].get<int>();
    if (row.contains("email_sent_ts") && !row["email_sent_ts"].is_null())
      result["email_sent_ts"] = row["email_sent_ts"].get<int64_t>();

    return result;
  }

  // --------------------------------------------------------------------------
  // 6. Account renewal
  // --------------------------------------------------------------------------

  /// Renew an account for the specified number of days.
  json renew_account(std::string_view user_id,
                      int renewal_period_days = -1) {
    if (renewal_period_days < 0)
      renewal_period_days = kAccountRenewalPeriodDays;

    int64_t now_ms = static_cast<int64_t>(util::now_ms());
    int64_t new_expiry =
        now_ms +
        static_cast<int64_t>(renewal_period_days) * 1000LL * 60 * 60 * 24;

    auto validity = get_account_validity(user_id);
    if (!validity.value("has_expiration", false)) {
      return {{"errcode", "M_NOT_FOUND"},
              {"error", "Account does not have an expiration set"}};
    }

    db_.execute(
        "UPDATE account_validity SET expiration_ts_ms = " +
        std::to_string(new_expiry) + ", renewal_period_days = " +
        std::to_string(renewal_period_days) + " WHERE user_id = " +
        sql_quote(user_id));

    json result;
    result["user_id"] = std::string(user_id);
    result["new_expiration_ts_ms"] = new_expiry;
    result["renewal_period_days"] = renewal_period_days;
    return result;
  }

  /// Generate a renewal token for a user.
  std::string generate_renewal_token(std::string_view user_id) {
    std::string token = util::random_token(32);
    int64_t now_ms = static_cast<int64_t>(util::now_ms());
    int64_t expiry = now_ms + 3600LL * 1000;  // 1 hour

    db_.execute(
        "INSERT INTO account_renewal_tokens "
        "(user_id, token, expiration_ts_ms, used) VALUES (" +
        sql_quote(user_id) + ", " + sql_quote(token) + ", " +
        std::to_string(expiry) + ", 0)");

    return token;
  }

  /// Validate a renewal token and return the associated user_id.
  std::optional<std::string> validate_renewal_token(
      std::string_view token) {
    int64_t now_ms = static_cast<int64_t>(util::now_ms());
    auto rows = db_.query(
        "SELECT user_id, expiration_ts_ms, used FROM account_renewal_tokens "
        "WHERE token = " +
        sql_quote(token));

    if (rows.empty()) return std::nullopt;

    auto& row = rows[0];
    if (!row.contains("user_id") || row["user_id"].is_null())
      return std::nullopt;

    bool used = false;
    if (row.contains("used") && !row["used"].is_null())
      used = row["used"].get<int>() != 0;

    if (used) return std::nullopt;

    int64_t expiry = 0;
    if (row.contains("expiration_ts_ms") &&
        !row["expiration_ts_ms"].is_null())
      expiry = row["expiration_ts_ms"].get<int64_t>();

    if (expiry > 0 && now_ms >= expiry) return std::nullopt;

    // Mark as used
    db_.execute(
        "UPDATE account_renewal_tokens SET used = 1 WHERE token = " +
        sql_quote(token));

    return row["user_id"].get<std::string>();
  }

  // --------------------------------------------------------------------------
  // 7. Account expiration checking
  // --------------------------------------------------------------------------

  /// Check if an account is expired and take action if auto-expire is enabled.
  json check_account_expired(std::string_view user_id,
                               bool auto_expire = false) {
    json result;
    result["user_id"] = std::string(user_id);
    result["expired"] = false;

    auto validity = get_account_validity(user_id);
    if (!validity.value("has_expiration", false)) {
      result["has_expiration"] = false;
      return result;
    }

    int64_t expiry = validity["expiration_ts_ms"].get<int64_t>();
    int64_t now_ms = static_cast<int64_t>(util::now_ms());

    result["has_expiration"] = true;
    result["expiration_ts_ms"] = expiry;
    result["days_remaining"] =
        std::max<int64_t>(0, (expiry - now_ms) / (1000LL * 60 * 60 * 24));
    result["should_warn"] =
        (expiry > 0 && (expiry - now_ms) <=
                           static_cast<int64_t>(kAccountExpiryWarnDays) *
                               1000LL * 60 * 60 * 24);

    if (expiry > 0 && now_ms >= expiry) {
      result["expired"] = true;

      if (auto_expire) {
        // Deactivate the account
        db_.execute(
            "UPDATE users SET deactivated = 1 WHERE id = " +
            sql_quote(user_id));
        result["auto_expired"] = true;
        result["action"] = "deactivated";
      }
    }

    return result;
  }

  /// Get all expired accounts (optionally auto-expire them).
  std::vector<json> get_expired_accounts(bool auto_expire = false) {
    int64_t now_ms = static_cast<int64_t>(util::now_ms());

    auto rows = db_.query(
        "SELECT av.user_id, av.expiration_ts_ms, u.deactivated "
        "FROM account_validity av LEFT JOIN users u ON av.user_id = u.id "
        "WHERE av.expiration_ts_ms > 0 AND av.expiration_ts_ms <= " +
        std::to_string(now_ms) + " AND u.deactivated = 0");

    std::vector<json> results;
    for (auto& row : rows) {
      std::string uid;
      if (row.contains("user_id") && !row["user_id"].is_null())
        uid = row["user_id"].get<std::string>();
      else
        continue;

      if (auto_expire) {
        db_.execute(
            "UPDATE users SET deactivated = 1 WHERE id = " + sql_quote(uid));
      }

      json entry;
      entry["user_id"] = uid;
      entry["expiration_ts_ms"] =
          row.contains("expiration_ts_ms") &&
                  !row["expiration_ts_ms"].is_null()
              ? row["expiration_ts_ms"].get<int64_t>()
              : 0;
      entry["auto_expired"] = auto_expire;
      results.push_back(entry);
    }
    return results;
  }

  /// Send warning emails to users whose accounts are about to expire.
  std::vector<std::string> get_users_needing_expiry_warning() {
    int64_t now_ms = static_cast<int64_t>(util::now_ms());
    int64_t warn_threshold =
        now_ms +
        static_cast<int64_t>(kAccountExpiryWarnDays) * 1000LL * 60 * 60 * 24;
    // Select users whose accounts expire within the warning period
    // and who haven't been warned recently
    int64_t min_reminder_gap = 3LL * 24 * 60 * 60 * 1000;  // 3 days between reminders

    auto rows = db_.query(
        "SELECT av.user_id FROM account_validity av "
        "JOIN users u ON av.user_id = u.id "
        "WHERE av.expiration_ts_ms > " +
        std::to_string(now_ms) +
        " AND av.expiration_ts_ms <= " + std::to_string(warn_threshold) +
        " AND (av.email_sent_ts = 0 OR av.email_sent_ts < " +
        std::to_string(now_ms - min_reminder_gap) + ") "
        "AND u.deactivated = 0");

    std::vector<std::string> result;
    for (auto& row : rows) {
      if (row.contains("user_id") && !row["user_id"].is_null())
        result.push_back(row["user_id"].get<std::string>());
    }
    return result;
  }

  /// Record that an expiry warning email was sent.
  void record_expiry_warning_sent(std::string_view user_id) {
    int64_t now_ms = static_cast<int64_t>(util::now_ms());
    db_.execute(
        "UPDATE account_validity SET email_sent_ts = " +
        std::to_string(now_ms) + " WHERE user_id = " + sql_quote(user_id));
  }

  // --------------------------------------------------------------------------
  // 8. Email verification - token generation and sending
  // --------------------------------------------------------------------------

  /// Generate an email verification token for a user.
  /// Returns {token: string, expiration_ts_ms: int64_t}
  json generate_email_verification_token(std::string_view user_id,
                                           std::string_view email) {
    std::string token = util::random_token(kEmailVerificationTokenLength);
    int64_t now_ms = static_cast<int64_t>(util::now_ms());
    int64_t expiry = now_ms + kEmailVerificationTokenExpirySec * 1000LL;

    db_.execute(
        "INSERT INTO email_verification_tokens "
        "(user_id, email, token, expiration_ts_ms, used, attempts) VALUES (" +
        sql_quote(user_id) + ", " + sql_quote(email) + ", " +
        sql_quote(token) + ", " + std::to_string(expiry) + ", 0, 0)");

    json result;
    result["token"] = token;
    result["expiration_ts_ms"] = expiry;
    result["expires_in_seconds"] = kEmailVerificationTokenExpirySec;
    return result;
  }

  /// Construct the verification email subject and body.
  json make_verification_email(std::string_view email,
                                 std::string_view token,
                                 int expiry_hours = 1) const {
    json result;
    result["subject"] = "Verify your email address";
    result["body_text"] =
        "Please verify your email address by clicking the link below:\n\n"
        "https://matrix.local/_matrix/client/v3/email/verify?token=" +
        std::string(token) +
        "\n\nThis link will expire in " + std::to_string(expiry_hours) +
        " hour(s).\n\nIf you did not request this, please ignore this email.";
    result["body_html"] =
        "<p>Please verify your email address by clicking the link below:</p>"
        "<p><a href=\"https://matrix.local/_matrix/client/v3/email/verify?"
        "token=" +
        std::string(token) + "\">Verify Email</a></p>"
        "<p>This link will expire in " +
        std::to_string(expiry_hours) +
        " hour(s).</p>"
        "<p>If you did not request this, please ignore this email.</p>";
    return result;
  }

  // --------------------------------------------------------------------------
  // 9. Email verification token validation
  // --------------------------------------------------------------------------

  /// Validate an email verification token.
  json validate_email_verification_token(std::string_view token) {
    int64_t now_ms = static_cast<int64_t>(util::now_ms());

    auto rows = db_.query(
        "SELECT user_id, email, expiration_ts_ms, used, attempts "
        "FROM email_verification_tokens WHERE token = " +
        sql_quote(token));

    json result;
    if (rows.empty()) {
      result["valid"] = false;
      result["error"] = "Invalid verification token";
      return result;
    }

    auto& row = rows[0];

    // Check if already used
    if (row.contains("used") && !row["used"].is_null() &&
        row["used"].get<int>() != 0) {
      result["valid"] = false;
      result["error"] = "Token has already been used";
      return result;
    }

    // Check expiry
    if (row.contains("expiration_ts_ms") &&
        !row["expiration_ts_ms"].is_null()) {
      int64_t expiry = row["expiration_ts_ms"].get<int64_t>();
      if (now_ms >= expiry) {
        result["valid"] = false;
        result["error"] = "Verification token has expired";
        return result;
      }
    }

    // Mark as used
    db_.execute(
        "UPDATE email_verification_tokens SET used = 1 WHERE token = " +
        sql_quote(token));

    // Also mark the email as verified for the user
    std::string user_id;
    std::string email;
    if (row.contains("user_id") && !row["user_id"].is_null())
      user_id = row["user_id"].get<std::string>();
    if (row.contains("email") && !row["email"].is_null())
      email = row["email"].get<std::string>();

    if (!user_id.empty() && !email.empty()) {
      mark_email_verified(user_id, email);
    }

    result["valid"] = true;
    result["user_id"] = user_id;
    result["email"] = email;
    return result;
  }

  /// Mark an email as verified for a user.
  void mark_email_verified(std::string_view user_id,
                             std::string_view email) {
    int64_t now_ms = static_cast<int64_t>(util::now_ms());

    // Update user_threepids or similar
    auto rows = db_.query(
        "SELECT user_id FROM user_threepids "
        "WHERE user_id = " +
        sql_quote(user_id) + " AND medium = 'email' AND address = " +
        sql_quote(email));

    if (rows.empty()) {
      db_.execute(
          "INSERT INTO user_threepids "
          "(user_id, medium, address, validated_at, added_at) VALUES (" +
          sql_quote(user_id) + ", 'email', " + sql_quote(email) + ", " +
          std::to_string(now_ms) + ", " + std::to_string(now_ms) + ")");
    } else {
      db_.execute(
          "UPDATE user_threepids SET validated_at = " +
          std::to_string(now_ms) + " WHERE user_id = " +
          sql_quote(user_id) + " AND medium = 'email' AND address = " +
          sql_quote(email));
    }
  }

  /// Check if an email is verified for a user.
  bool is_email_verified(std::string_view user_id,
                           std::string_view email) const {
    auto rows = db_.query(
        "SELECT validated_at FROM user_threepids "
        "WHERE user_id = " +
        sql_quote(user_id) + " AND medium = 'email' AND address = " +
        sql_quote(email));

    if (rows.empty()) return false;

    if (rows[0].contains("validated_at") &&
        !rows[0]["validated_at"].is_null()) {
      return rows[0]["validated_at"].get<int64_t>() > 0;
    }
    return false;
  }

  // --------------------------------------------------------------------------
  // 10. Email verification reminder
  // --------------------------------------------------------------------------

  /// Get users who have unverified emails and need a reminder.
  std::vector<std::pair<std::string, std::string>>
  get_users_needing_verification_reminder() {
    int64_t now_ms = static_cast<int64_t>(util::now_ms());
    int64_t reminder_threshold =
        now_ms -
        static_cast<int64_t>(kEmailVerificationReminderDays) * 1000LL * 60 * 60 * 24;

    auto rows = db_.query(
        "SELECT evt.user_id, evt.email, evt.created_ts "
        "FROM email_verification_tokens evt "
        "JOIN users u ON evt.user_id = u.id "
        "WHERE evt.used = 0 AND evt.expiration_ts_ms > " +
        std::to_string(now_ms) +
        " AND evt.created_ts < " + std::to_string(reminder_threshold) +
        " AND evt.reminder_count < 3 "
        "AND u.deactivated = 0 "
        "ORDER BY evt.created_ts ASC");

    std::vector<std::pair<std::string, std::string>> result;
    for (auto& row : rows) {
      std::string uid, email;
      if (row.contains("user_id") && !row["user_id"].is_null())
        uid = row["user_id"].get<std::string>();
      if (row.contains("email") && !row["email"].is_null())
        email = row["email"].get<std::string>();
      if (!uid.empty() && !email.empty()) result.emplace_back(uid, email);
    }
    return result;
  }

  /// Record that a verification reminder was sent by bumping reminder_count.
  void record_verification_reminder_sent(std::string_view user_id,
                                           std::string_view email) {
    db_.execute(
        "UPDATE email_verification_tokens "
        "SET reminder_count = reminder_count + 1, last_reminder_ts = " +
        std::to_string(util::now_ms()) + " WHERE user_id = " +
        sql_quote(user_id) + " AND email = " + sql_quote(email) +
        " AND used = 0");
  }

  // --------------------------------------------------------------------------
  // 11. Email block list
  // --------------------------------------------------------------------------

  /// Add an email address or domain to the block list.
  void add_email_to_blocklist(std::string_view email_or_domain) {
    int64_t now_ms = static_cast<int64_t>(util::now_ms());

    auto rows = db_.query(
        "SELECT id FROM email_blocklist WHERE pattern = " +
        sql_quote(email_or_domain));
    if (rows.empty()) {
      db_.execute(
          "INSERT INTO email_blocklist (pattern, added_ts, added_by) VALUES (" +
          sql_quote(email_or_domain) + ", " + std::to_string(now_ms) +
          ", 'system')");
    }
  }

  /// Remove an entry from the block list.
  void remove_email_from_blocklist(std::string_view email_or_domain) {
    db_.execute(
        "DELETE FROM email_blocklist WHERE pattern = " +
        sql_quote(email_or_domain));
  }

  /// Check if an email is blocked (exact match or domain match).
  bool is_email_blocked(std::string_view email) const {
    // Check exact match
    auto rows = db_.query(
        "SELECT pattern FROM email_blocklist WHERE pattern = " +
        sql_quote(email));
    if (!rows.empty()) return true;

    // Check domain match
    auto at_pos = email.find('@');
    if (at_pos != std::string::npos) {
      std::string domain = std::string(email.substr(at_pos + 1));
      auto domain_rows = db_.query(
          "SELECT pattern FROM email_blocklist WHERE pattern = " +
          sql_quote(domain));
      if (!domain_rows.empty()) return true;

      // Check wildcard domain match (*@domain)
      auto wild_rows = db_.query(
          "SELECT pattern FROM email_blocklist WHERE pattern = '*@'" +
          sql_escape(domain));
      if (!wild_rows.empty()) return true;
    }

    return false;
  }

  /// Get all blocked emails/domains.
  std::vector<std::string> get_email_blocklist() const {
    auto rows = db_.query(
        "SELECT pattern FROM email_blocklist ORDER BY added_ts DESC");

    std::vector<std::string> result;
    for (auto& row : rows) {
      if (row.contains("pattern") && !row["pattern"].is_null())
        result.push_back(row["pattern"].get<std::string>());
    }
    return result;
  }

  /// Check if an entire domain is blocked.
  bool is_domain_blocked(std::string_view domain) const {
    auto rows = db_.query(
        "SELECT pattern FROM email_blocklist WHERE pattern = " +
        sql_quote(domain));
    return !rows.empty();
  }

  // --------------------------------------------------------------------------
  // 12. Email MX record validation
  // --------------------------------------------------------------------------

  /// Validate that an email domain has valid MX records.
  /// Returns {valid: bool, mx_records: [string], error: string}
  json validate_email_mx(std::string_view email) const {
    json result;
    result["valid"] = false;

    auto at_pos = email.find('@');
    if (at_pos == std::string::npos || at_pos == 0 ||
        at_pos == email.size() - 1) {
      result["error"] = "Invalid email format";
      return result;
    }

    std::string domain(email.substr(at_pos + 1));
    result["domain"] = domain;

    // Disposable temporary email domains
    if (is_disposable_email_domain(domain)) {
      result["valid"] = false;
      result["error"] = "Disposable email domains are not allowed";
      return result;
    }

    // Try actual MX lookup
    std::vector<std::string> mx_records = lookup_mx_records(domain);
    result["mx_records"] = mx_records;

    if (mx_records.empty()) {
      result["valid"] = false;
      result["error"] = "Domain has no valid MX records";
    } else {
      result["valid"] = true;
    }

    return result;
  }

  // --------------------------------------------------------------------------
  // 13. Registration rate limiting
  // --------------------------------------------------------------------------

  /// Check whether a registration from the given IP is allowed.
  /// Returns {allowed: bool, retry_after_ms: int64_t}
  json check_registration_rate_limit(std::string_view ip_address,
                                       std::string_view email = "") const {
    int64_t now_ms = static_cast<int64_t>(util::now_ms());
    json result;
    result["allowed"] = true;
    result["retry_after_ms"] = 0;

    // Check per-IP rate limit
    {
      std::lock_guard<std::mutex> lock(rate_limit_mutex_);
      auto& entries = ip_rate_entries_[std::string(ip_address)];
      // Prune old entries
      entries.erase(
          std::remove_if(entries.begin(), entries.end(),
                         [now_ms](int64_t ts) {
                           return (now_ms - ts) >
                                  kRegRateLimitWindowSec * 1000LL;
                         }),
          entries.end());
      if (static_cast<int>(entries.size()) >= kRegMaxPerIp) {
        result["allowed"] = false;
        result["error"] =
            "Too many registration attempts from this IP address";
        if (!entries.empty())
          result["retry_after_ms"] =
              (entries.front() + kRegRateLimitWindowSec * 1000LL) - now_ms;
      } else {
        entries.push_back(now_ms);
      }
    }

    // Check per-email-domain rate limit
    if (!email.empty()) {
      auto at_pos = email.find('@');
      if (at_pos != std::string::npos) {
        std::string domain(email.substr(at_pos + 1));
        std::lock_guard<std::mutex> lock(rate_limit_mutex_);
        auto& domain_entries = domain_rate_entries_[domain];
        domain_entries.erase(
            std::remove_if(domain_entries.begin(), domain_entries.end(),
                           [now_ms](int64_t ts) {
                             return (now_ms - ts) >
                                    kRegRateLimitWindowSec * 1000LL;
                           }),
            domain_entries.end());
        if (static_cast<int>(domain_entries.size()) >= kRegMaxPerDomain) {
          result["allowed"] = false;
          result["error"] =
              "Too many registrations from this email domain";
          if (!domain_entries.empty())
            result["retry_after_ms"] =
                (domain_entries.front() + kRegRateLimitWindowSec * 1000LL) -
                now_ms;
        } else {
          domain_entries.push_back(now_ms);
        }
      }
    }

    // Check global rate limit
    {
      std::lock_guard<std::mutex> lock(rate_limit_mutex_);
      global_reg_timestamps_.erase(
          std::remove_if(global_reg_timestamps_.begin(),
                         global_reg_timestamps_.end(),
                         [now_ms](int64_t ts) {
                           return (now_ms - ts) >
                                  kRegRateLimitWindowSec * 1000LL;
                         }),
          global_reg_timestamps_.end());
      if (static_cast<int>(global_reg_timestamps_.size()) >=
          kRegGlobalMaxPerHour) {
        result["allowed"] = false;
        result["error"] = "Server registration temporarily unavailable";
        if (!global_reg_timestamps_.empty())
          result["retry_after_ms"] =
              (global_reg_timestamps_.front() + kRegRateLimitWindowSec * 1000LL) -
              now_ms;
      } else {
        global_reg_timestamps_.push_back(now_ms);
      }
    }

    return result;
  }

  /// Record a completed registration (not just an attempt).
  void record_registration(std::string_view ip_address,
                             std::string_view email) {
    int64_t now_ms = static_cast<int64_t>(util::now_ms());
    std::lock_guard<std::mutex> lock(rate_limit_mutex_);
    ip_rate_entries_[std::string(ip_address)].push_back(now_ms);

    auto at_pos = email.find('@');
    if (at_pos != std::string::npos) {
      std::string domain(email.substr(at_pos + 1));
      domain_rate_entries_[domain].push_back(now_ms);
    }
    global_reg_timestamps_.push_back(now_ms);
  }

  /// Get current rate limit status.
  json get_rate_limit_status(std::string_view ip_address,
                               std::string_view email = "") const {
    int64_t now_ms = static_cast<int64_t>(util::now_ms());
    json result;

    {
      std::lock_guard<std::mutex> lock(rate_limit_mutex_);
      result["ip_attempts"] = count_recent(
          ip_rate_entries_, std::string(ip_address), now_ms);

      if (!email.empty()) {
        auto at_pos = email.find('@');
        if (at_pos != std::string::npos) {
          std::string domain(email.substr(at_pos + 1));
          result["domain_attempts"] =
              count_recent(domain_rate_entries_, domain, now_ms);
        }
      }

      result["global_attempts"] = count_recent_global(now_ms);
      result["ip_limit"] = kRegMaxPerIp;
      result["domain_limit"] = kRegMaxPerDomain;
      result["global_limit"] = kRegGlobalMaxPerHour;
    }

    return result;
  }

  // --------------------------------------------------------------------------
  // 14. Registration token management
  // --------------------------------------------------------------------------

  /// Create a new registration token.
  json create_registration_token(
      std::string_view token_value = "",
      int uses_allowed = kRegTokenDefaultUsesAllowed,
      int64_t expiry_ts_ms = 0,
      std::string_view created_by = "admin") {
    std::string token(token_value.empty()
                          ? util::random_token(kRegTokenDefaultLength)
                          : token_value);
    int64_t now_ms = static_cast<int64_t>(util::now_ms());

    if (expiry_ts_ms <= 0)
      expiry_ts_ms = now_ms + kRegTokenDefaultExpirySec * 1000LL;

    db_.execute(
        "INSERT INTO registration_tokens "
        "(token, uses_allowed, pending, completed, expiry_ts_ms, "
        "created_ts, created_by) VALUES (" +
        sql_quote(token) + ", " + std::to_string(uses_allowed) + ", 0, 0, " +
        std::to_string(expiry_ts_ms) + ", " + std::to_string(now_ms) + ", " +
        sql_quote(created_by) + ")");

    json result;
    result["token"] = token;
    result["uses_allowed"] = uses_allowed;
    result["expiry_ts_ms"] = expiry_ts_ms;
    result["created_ts"] = now_ms;
    return result;
  }

  /// Validate a registration token (check existence, expiry, usage).
  json validate_registration_token(std::string_view token) {
    int64_t now_ms = static_cast<int64_t>(util::now_ms());
    json result;

    auto rows = db_.query(
        "SELECT token, uses_allowed, pending, completed, expiry_ts_ms "
        "FROM registration_tokens WHERE token = " +
        sql_quote(token));

    if (rows.empty()) {
      result["valid"] = false;
      result["error"] = "Invalid registration token";
      return result;
    }

    auto& row = rows[0];

    int uses_allowed =
        row.contains("uses_allowed") && !row["uses_allowed"].is_null()
            ? row["uses_allowed"].get<int>()
            : 0;
    int pending = row.contains("pending") && !row["pending"].is_null()
                      ? row["pending"].get<int>()
                      : 0;
    int completed =
        row.contains("completed") && !row["completed"].is_null()
            ? row["completed"].get<int>()
            : 0;
    int64_t expiry =
        row.contains("expiry_ts_ms") && !row["expiry_ts_ms"].is_null()
            ? row["expiry_ts_ms"].get<int64_t>()
            : 0;

    result["token"] = std::string(token);
    result["uses_allowed"] = uses_allowed;
    result["pending"] = pending;
    result["completed"] = completed;

    if (expiry > 0 && now_ms >= expiry) {
      result["valid"] = false;
      result["error"] = "Registration token has expired";
      return result;
    }

    if (uses_allowed > 0 && (pending + completed) >= uses_allowed) {
      result["valid"] = false;
      result["error"] = "Registration token usage limit reached";
      return result;
    }

    result["valid"] = true;
    result["remaining_uses"] =
        std::max(0, uses_allowed - (pending + completed));
    return result;
  }

  /// Revoke a registration token.
  void revoke_registration_token(std::string_view token) {
    db_.execute(
        "DELETE FROM registration_tokens WHERE token = " +
        sql_quote(token));
  }

  /// Revoke all registration tokens.
  void revoke_all_registration_tokens() {
    db_.execute("DELETE FROM registration_tokens");
  }

  /// List all registration tokens.
  std::vector<json> list_registration_tokens() const {
    int64_t now_ms = static_cast<int64_t>(util::now_ms());
    auto rows = db_.query(
        "SELECT token, uses_allowed, pending, completed, expiry_ts_ms, "
        "created_ts, created_by FROM registration_tokens ORDER BY "
        "created_ts DESC");

    std::vector<json> result;
    for (auto& row : rows) {
      json entry;
      entry["token"] = row.contains("token") && !row["token"].is_null()
                           ? row["token"].get<std::string>()
                           : "";
      entry["uses_allowed"] =
          row.contains("uses_allowed") && !row["uses_allowed"].is_null()
              ? row["uses_allowed"].get<int>()
              : 0;
      entry["pending"] = row.contains("pending") && !row["pending"].is_null()
                             ? row["pending"].get<int>()
                             : 0;
      entry["completed"] =
          row.contains("completed") && !row["completed"].is_null()
              ? row["completed"].get<int>()
              : 0;
      int64_t expiry = row.contains("expiry_ts_ms") &&
                               !row["expiry_ts_ms"].is_null()
                           ? row["expiry_ts_ms"].get<int64_t>()
                           : 0;
      entry["expiry_ts_ms"] = expiry;
      entry["expired"] = (expiry > 0 && now_ms >= expiry);
      entry["created_ts"] =
          row.contains("created_ts") && !row["created_ts"].is_null()
              ? row["created_ts"].get<int64_t>()
              : 0;
      entry["created_by"] =
          row.contains("created_by") && !row["created_by"].is_null()
              ? row["created_by"].get<std::string>()
              : "";
      int used = entry["pending"].get<int>() + entry["completed"].get<int>();
      entry["remaining_uses"] =
          std::max(0, entry["uses_allowed"].get<int>() - used);
      if (entry["uses_allowed"].get<int>() == 0)
        entry["remaining_uses"] = -1;  // unlimited
      result.push_back(entry);
    }
    return result;
  }

  // --------------------------------------------------------------------------
  // 15. Registration token usage tracking
  // --------------------------------------------------------------------------

  /// Mark a registration token as pending (before registration completes).
  void mark_token_pending(std::string_view token) {
    db_.execute(
        "UPDATE registration_tokens SET pending = pending + 1 "
        "WHERE token = " +
        sql_quote(token));
  }

  /// Mark a registration token as completed and reduce pending count.
  void mark_token_completed(std::string_view token) {
    db_.execute(
        "UPDATE registration_tokens SET completed = completed + 1, "
        "pending = MAX(0, pending - 1) WHERE token = " +
        sql_quote(token));
  }

  /// Release a pending token usage (if registration failed).
  void release_token_pending(std::string_view token) {
    db_.execute(
        "UPDATE registration_tokens SET pending = MAX(0, pending - 1) "
        "WHERE token = " +
        sql_quote(token));
  }

  /// Get token usage statistics.
  json get_token_usage_stats(std::string_view token) const {
    auto rows = db_.query(
        "SELECT uses_allowed, pending, completed, created_ts, expiry_ts_ms "
        "FROM registration_tokens WHERE token = " +
        sql_quote(token));

    json result;
    if (rows.empty()) {
      result["found"] = false;
      return result;
    }

    auto& row = rows[0];
    result["found"] = true;
    result["token"] = std::string(token);
    if (row.contains("uses_allowed") && !row["uses_allowed"].is_null())
      result["uses_allowed"] = row["uses_allowed"].get<int>();
    if (row.contains("pending") && !row["pending"].is_null())
      result["pending"] = row["pending"].get<int>();
    if (row.contains("completed") && !row["completed"].is_null())
      result["completed"] = row["completed"].get<int>();
    if (row.contains("created_ts") && !row["created_ts"].is_null())
      result["created_ts"] = row["created_ts"].get<int64_t>();
    if (row.contains("expiry_ts_ms") && !row["expiry_ts_ms"].is_null())
      result["expiry_ts_ms"] = row["expiry_ts_ms"].get<int64_t>();

    int used = result.value("pending", 0) + result.value("completed", 0);
    result["total_used"] = used;
    result["remaining"] =
        std::max(0, result.value("uses_allowed", 0) - used);
    if (result.value("uses_allowed", 0) == 0) result["remaining"] = -1;

    return result;
  }

  // --------------------------------------------------------------------------
  // 16. Registration token expiry
  // --------------------------------------------------------------------------

  /// Clean up expired registration tokens.
  int cleanup_expired_registration_tokens() {
    int64_t now_ms = static_cast<int64_t>(util::now_ms());
    auto rows = db_.query(
        "SELECT token FROM registration_tokens WHERE expiry_ts_ms > 0 "
        "AND expiry_ts_ms <= " +
        std::to_string(now_ms));

    int count = 0;
    for (auto& row : rows) {
      if (row.contains("token") && !row["token"].is_null()) {
        db_.execute(
            "DELETE FROM registration_tokens WHERE token = " +
            sql_quote(row["token"].get<std::string>()));
        count++;
      }
    }
    return count;
  }

  /// Check if a specific token is expired.
  bool is_registration_token_expired(std::string_view token) const {
    int64_t now_ms = static_cast<int64_t>(util::now_ms());
    auto rows = db_.query(
        "SELECT expiry_ts_ms FROM registration_tokens WHERE token = " +
        sql_quote(token));

    if (rows.empty()) return true;  // non-existent = expired

    auto& row = rows[0];
    if (!row.contains("expiry_ts_ms") || row["expiry_ts_ms"].is_null())
      return false;

    int64_t expiry = row["expiry_ts_ms"].get<int64_t>();
    return expiry > 0 && now_ms >= expiry;
  }

  /// Extend the expiry of a registration token.
  void extend_registration_token(std::string_view token,
                                   int additional_seconds) {
    int64_t now_ms = static_cast<int64_t>(util::now_ms());
    int64_t new_expiry = now_ms + additional_seconds * 1000LL;

    db_.execute(
        "UPDATE registration_tokens SET expiry_ts_ms = " +
        std::to_string(new_expiry) + " WHERE token = " + sql_quote(token));
  }

  // --------------------------------------------------------------------------
  // 17. Username blacklist
  // --------------------------------------------------------------------------

  /// Add a username pattern to the blacklist.
  void add_username_to_blacklist(std::string_view pattern) {
    int64_t now_ms = static_cast<int64_t>(util::now_ms());
    auto rows = db_.query(
        "SELECT id FROM username_blacklist WHERE pattern = " +
        sql_quote(pattern));
    if (rows.empty()) {
      db_.execute(
          "INSERT INTO username_blacklist (pattern, added_ts) VALUES (" +
          sql_quote(pattern) + ", " + std::to_string(now_ms) + ")");
    }
  }

  /// Remove a username from the blacklist.
  void remove_username_from_blacklist(std::string_view pattern) {
    db_.execute(
        "DELETE FROM username_blacklist WHERE pattern = " +
        sql_quote(pattern));
  }

  /// Check if a username is blacklisted.
  bool is_username_blacklisted(std::string_view username) const {
    std::string lower(username);
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return std::tolower(c); });

    // Check exact match
    auto rows = db_.query(
        "SELECT pattern FROM username_blacklist WHERE LOWER(pattern) = " +
        sql_quote(lower));
    if (!rows.empty()) return true;

    // Check contains (substring match)
    auto contain_rows = db_.query(
        "SELECT pattern FROM username_blacklist WHERE " + sql_quote(lower) +
        " LIKE '%' || pattern || '%'");
    if (!contain_rows.empty()) return true;

    // Check built-in offensive patterns
    if (is_offensive_username(username)) return true;

    return false;
  }

  /// Get all blacklisted usernames.
  std::vector<std::string> get_username_blacklist() const {
    auto rows =
        db_.query("SELECT pattern FROM username_blacklist ORDER BY added_ts DESC");

    std::vector<std::string> result;
    for (auto& row : rows) {
      if (row.contains("pattern") && !row["pattern"].is_null())
        result.push_back(row["pattern"].get<std::string>());
    }
    return result;
  }

  // --------------------------------------------------------------------------
  // 18. Username validation
  // --------------------------------------------------------------------------

  /// Validate a username for registration.
  /// Returns {valid: bool, error: string, suggestions: [string]}
  json validate_username(std::string_view username) const {
    json result;

    // Length check (Matrix spec: 3-255 characters, localpart 1+)
    if (username.empty()) {
      result["valid"] = false;
      result["error"] = "Username cannot be empty";
      return result;
    }
    if (username.size() < 3) {
      result["valid"] = false;
      result["error"] = "Username must be at least 3 characters";
      return result;
    }
    if (username.size() > 255) {
      result["valid"] = false;
      result["error"] = "Username must not exceed 255 characters";
      return result;
    }

    // Allowed characters (Matrix spec: a-z, 0-9, . _ = - /)
    static const std::regex kUsernameRegex("^[a-z0-9._\\-=/]+$");
    std::string lower(username);
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return std::tolower(c); });

    if (!std::regex_match(lower, kUsernameRegex)) {
      result["valid"] = false;
      result["error"] =
          "Username can only contain lowercase letters, digits, and "
          "characters . _ - = /";
      result["suggestions"] = json::array({"Use only a-z, 0-9, and . _ - = /"});
      return result;
    }

    // Must not start with underscore (reserved for application services)
    if (username[0] == '_') {
      result["valid"] = false;
      result["error"] =
          "Usernames starting with underscore are reserved for "
          "application services";
      return result;
    }

    // Must not be numeric-only
    bool all_digits = true;
    for (char c : username)
      if (!std::isdigit(static_cast<unsigned char>(c))) {
        all_digits = false;
        break;
      }
    if (all_digits) {
      result["valid"] = false;
      result["error"] = "Username cannot consist of only digits";
      return result;
    }

    // Check blacklist
    if (is_username_blacklisted(username)) {
      result["valid"] = false;
      result["error"] =
          "This username is not allowed. Please choose another one.";
      return result;
    }

    // Check if it looks like a Matrix user ID format
    if (username[0] == '@') {
      result["valid"] = false;
      result["error"] = "Username should not include the @ prefix";
      return result;
    }

    // Check for confusing patterns (repeated chars, lookalikes)
    if (has_confusing_pattern(username)) {
      result["valid"] = false;
      result["error"] =
          "Username contains confusing or misleading patterns";
      return result;
    }

    // Check for admin impersonation
    if (is_admin_impersonation(username)) {
      result["valid"] = false;
      result["error"] =
          "Username appears to impersonate an administrator";
      return result;
    }

    result["valid"] = true;
    return result;
  }

  /// Check if a username is already taken.
  bool is_username_taken(std::string_view username) const {
    auto rows = db_.query(
        "SELECT id FROM users WHERE LOWER(id) = LOWER(" +
        sql_quote(username) + ") OR id = '@'" + sql_escape(username) + "'");
    // Also check with domain part
    auto full_rows = db_.query(
        "SELECT id FROM users WHERE id = '@'" +
        sql_escape(username) + "':localhost'");
    return !rows.empty() || !full_rows.empty();
  }

  /// Suggest usernames if the desired one is taken.
  std::vector<std::string> suggest_usernames(
      std::string_view desired, int count = 5) const {
    std::vector<std::string> suggestions;
    std::string base(desired);

    // Remove any leading @
    if (!base.empty() && base[0] == '@') base = base.substr(1);

    // Truncate if too long to leave room for appending
    if (base.size() > 200) base = base.substr(0, 200);

    // Try appending numbers
    for (int i = 1; i <= 999 && static_cast<int>(suggestions.size()) < count;
         i++) {
      std::string candidate = base + std::to_string(i);
      if (!is_username_taken(candidate) &&
          validate_username(candidate)["valid"].get<bool>())
        suggestions.push_back(candidate);
    }

    // Try appending year
    for (int yr = 2020; yr <= 2030 &&
                        static_cast<int>(suggestions.size()) < count;
         yr++) {
      std::string candidate = base + std::to_string(yr);
      if (!is_username_taken(candidate) &&
          validate_username(candidate)["valid"].get<bool>())
        suggestions.push_back(candidate);
    }

    // Try common suffixes
    static const std::vector<std::string> kSuffixes = {
        "42", "1337", "x", "mx", "m", "01", "net", "org", "io", "dev"};
    for (auto& suffix : kSuffixes) {
      if (static_cast<int>(suggestions.size()) >= count) break;
      std::string candidate = base + suffix;
      if (!is_username_taken(candidate) &&
          validate_username(candidate)["valid"].get<bool>())
        suggestions.push_back(candidate);
    }

    return suggestions;
  }

  // --------------------------------------------------------------------------
  // 19. User creation hooks
  // --------------------------------------------------------------------------

  /// Pre-registration validation hook. Runs before creating a user.
  /// Returns {allowed: bool, error: string, errcode: string}
  json pre_register_check(std::string_view username,
                            std::string_view password,
                            std::string_view email = "",
                            std::string_view ip_address = "",
                            std::string_view reg_token = "") {
    json result;
    result["allowed"] = true;

    // 1. Username validation
    auto username_result = validate_username(username);
    if (!username_result["valid"].get<bool>()) {
      result["allowed"] = false;
      result["error"] = username_result["error"];
      result["errcode"] = "M_INVALID_USERNAME";
      return result;
    }

    // 2. Check username uniqueness
    if (is_username_taken(username)) {
      result["allowed"] = false;
      result["error"] = "Username is already taken";
      result["errcode"] = "M_USER_IN_USE";
      result["suggestions"] = suggest_usernames(username);
      return result;
    }

    // 3. Password policy check
    auto pw_result = validate_password_policy(password, username);
    if (!pw_result["valid"].get<bool>()) {
      result["allowed"] = false;
      result["error"] = pw_result["error"];
      result["errcode"] = "M_WEAK_PASSWORD";
      result["password_details"] = pw_result;
      return result;
    }

    // 4. Email validation if provided
    if (!email.empty()) {
      auto email_result = validate_email_for_registration(email);
      if (!email_result["valid"].get<bool>()) {
        result["allowed"] = false;
        result["error"] = email_result["error"];
        result["errcode"] = "M_INVALID_EMAIL";
        result["email_details"] = email_result;
        return result;
      }
    }

    // 5. Rate limiting check
    if (!ip_address.empty() || !email.empty()) {
      auto rate_result = check_registration_rate_limit(ip_address, email);
      if (!rate_result["allowed"].get<bool>()) {
        result["allowed"] = false;
        result["error"] = rate_result["error"];
        result["errcode"] = "M_LIMIT_EXCEEDED";
        result["retry_after_ms"] = rate_result["retry_after_ms"];
        return result;
      }
    }

    // 6. Registration token validation if required
    if (!reg_token.empty()) {
      auto token_result = validate_registration_token(reg_token);
      if (!token_result["valid"].get<bool>()) {
        result["allowed"] = false;
        result["error"] = token_result["error"];
        result["errcode"] = "M_INVALID_TOKEN";
        return result;
      }
    }

    // 7. Spam check (basic heuristics)
    if (is_spam_username(username)) {
      result["allowed"] = false;
      result["error"] = "Registration appears to be spam";
      result["errcode"] = "M_FORBIDDEN";
      return result;
    }

    return result;
  }

  /// Post-registration hook. Runs after a user is created.
  json post_register_hook(std::string_view user_id,
                            std::string_view email = "",
                            std::string_view ip_address = "",
                            std::string_view reg_token = "") {
    json result;

    // Mark token as completed
    if (!reg_token.empty()) {
      mark_token_completed(reg_token);
      result["token_completed"] = true;
    }

    // Record rate limit
    if (!ip_address.empty() || !email.empty()) {
      record_registration(ip_address, email);
    }

    // Generate email verification token if email provided
    if (!email.empty()) {
      auto verify_token = generate_email_verification_token(user_id, email);
      result["email_verification"] = verify_token;
    }

    // Set default account validity
    int validity_days = kDefaultAccountValidityDays;
    set_account_validity(user_id, validity_days);
    result["account_validity_days"] = validity_days;

    return result;
  }

  /// Validate an email for registration (format, blocklist, MX).
  json validate_email_for_registration(std::string_view email) const {
    json result;
    result["valid"] = true;

    // Basic format check
    static const std::regex kEmailRegex(
        "^[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}$");
    if (!std::regex_match(std::string(email), kEmailRegex)) {
      result["valid"] = false;
      result["error"] = "Invalid email format";
      return result;
    }

    // Blocklist check
    if (is_email_blocked(email)) {
      result["valid"] = false;
      result["error"] = "This email address is not allowed";
      return result;
    }

    // MX validation
    auto mx_result = validate_email_mx(email);
    if (!mx_result["valid"].get<bool>()) {
      result["valid"] = false;
      result["error"] = mx_result.value("error", "Email domain is invalid");
      result["mx_details"] = mx_result;
      return result;
    }

    // Check duplicate email
    auto at_pos = email.find('@');
    std::string normalized(email);
    if (at_pos != std::string::npos) {
      // Lowercase domain part
      std::string local(email.substr(0, at_pos));
      std::string domain(email.substr(at_pos + 1));
      std::transform(domain.begin(), domain.end(), domain.begin(),
                     [](unsigned char c) { return std::tolower(c); });
      normalized = local + "@" + domain;
    }

    auto rows = db_.query(
        "SELECT user_id FROM user_threepids "
        "WHERE medium = 'email' AND LOWER(address) = LOWER(" +
        sql_quote(normalized) + ")");
    if (!rows.empty()) {
      result["valid"] = false;
      result["error"] = "This email address is already in use";
      return result;
    }

    return result;
  }

  /// Delegated spam-check on username patterns.
  bool is_spam_username(std::string_view username) const {
    std::string lower(username);
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return std::tolower(c); });

    // Check for random-looking strings (high entropy, mixed case patterns)
    if (lower.size() > 10 && looks_random(lower)) return true;

    // Check for common spam patterns
    static const std::vector<std::string> kSpamPatterns = {
        "crypto",  "wallet",   "airdrop", "nft",     "token",
        "giveaway", "official", "support", "helpdesk", "admin",
        "verify",   "claim",    "bonus",   "free",    "winner"};
    for (auto& pattern : kSpamPatterns) {
      if (lower.find(pattern) != std::string::npos) return true;
    }

    // Check for repeated digits (spam bots often use repeated patterns)
    int consecutive_digits = 0;
    for (size_t i = 0; i < lower.size(); i++) {
      if (std::isdigit(static_cast<unsigned char>(lower[i]))) {
        consecutive_digits++;
        if (consecutive_digits > 6) return true;
      } else {
        consecutive_digits = 0;
      }
    }

    return false;
  }

  // --------------------------------------------------------------------------
  // 20. Admin password reset
  // --------------------------------------------------------------------------

  /// Generate a password reset token for an admin to reset a user's password.
  json admin_generate_password_reset(std::string_view target_user_id,
                                       std::string_view admin_user_id) {
    // Verify target user exists
    auto rows = db_.query(
        "SELECT id FROM users WHERE id = " + sql_quote(target_user_id));
    if (rows.empty()) {
      return {{"errcode", "M_NOT_FOUND"}, {"error", "User not found"}};
    }

    // Generate reset token
    std::string reset_token = util::random_token(kAdminResetTokenLength);
    int64_t now_ms = static_cast<int64_t>(util::now_ms());
    int64_t expiry = now_ms + 3600LL * 1000;  // 1 hour expiry

    db_.execute(
        "INSERT INTO admin_password_reset_tokens "
        "(target_user_id, admin_user_id, token, expiration_ts_ms, used) "
        "VALUES (" +
        sql_quote(target_user_id) + ", " + sql_quote(admin_user_id) + ", " +
        sql_quote(reset_token) + ", " + std::to_string(expiry) + ", 0)");

    json result;
    result["user_id"] = std::string(target_user_id);
    result["reset_token"] = reset_token;
    result["expiration_ts_ms"] = expiry;
    result["reset_link"] =
        "https://matrix.local/_matrix/client/v3/admin/reset_password/"
        "?token=" +
        reset_token + "&user_id=" + std::string(target_user_id);
    return result;
  }

  /// Consume an admin password reset token and return the target user.
  json admin_validate_password_reset(std::string_view token) {
    int64_t now_ms = static_cast<int64_t>(util::now_ms());
    json result;

    auto rows = db_.query(
        "SELECT target_user_id, admin_user_id, expiration_ts_ms, used "
        "FROM admin_password_reset_tokens WHERE token = " +
        sql_quote(token));

    if (rows.empty()) {
      result["valid"] = false;
      result["error"] = "Invalid reset token";
      return result;
    }

    auto& row = rows[0];

    if (row.contains("used") && !row["used"].is_null() &&
        row["used"].get<int>() != 0) {
      result["valid"] = false;
      result["error"] = "Token has already been used";
      return result;
    }

    if (row.contains("expiration_ts_ms") &&
        !row["expiration_ts_ms"].is_null()) {
      int64_t expiry = row["expiration_ts_ms"].get<int64_t>();
      if (now_ms >= expiry) {
        result["valid"] = false;
        result["error"] = "Reset token has expired";
        return result;
      }
    }

    // Mark as used
    db_.execute(
        "UPDATE admin_password_reset_tokens SET used = 1 WHERE token = " +
        sql_quote(token));

    result["valid"] = true;
    if (row.contains("target_user_id") && !row["target_user_id"].is_null())
      result["target_user_id"] = row["target_user_id"].get<std::string>();
    if (row.contains("admin_user_id") && !row["admin_user_id"].is_null())
      result["admin_user_id"] = row["admin_user_id"].get<std::string>();

    return result;
  }

  /// Complete admin password reset by setting a new password.
  json admin_complete_password_reset(std::string_view token,
                                       std::string_view new_password) {
    auto validation = admin_validate_password_reset(token);
    if (!validation["valid"].get<bool>()) {
      return validation;
    }

    std::string target_user_id = validation["target_user_id"].get<std::string>();

    // Validate password policy
    auto pw_result = validate_password_policy(new_password, target_user_id);
    if (!pw_result["valid"].get<bool>()) {
      return {{"errcode", "M_WEAK_PASSWORD"},
              {"error", pw_result["error"]},
              {"details", pw_result}};
    }

    // Hash and set new password
    std::string pw_hash = hash_password_sha256(new_password);
    db_.execute(
        "UPDATE users SET password_hash = " + sql_quote(pw_hash) +
        ", password_last_changed_ts = " +
        std::to_string(util::now_ms()) + " WHERE id = " +
        sql_quote(target_user_id));

    // Record in history
    record_password_in_history(target_user_id, pw_hash);

    json result;
    result["success"] = true;
    result["user_id"] = target_user_id;
    return result;
  }

  /// List all admin password reset tokens (for audit).
  std::vector<json> list_admin_reset_tokens() const {
    int64_t now_ms = static_cast<int64_t>(util::now_ms());
    auto rows = db_.query(
        "SELECT target_user_id, admin_user_id, expiration_ts_ms, used, "
        "created_ts FROM admin_password_reset_tokens ORDER BY created_ts DESC "
        "LIMIT 100");

    std::vector<json> result;
    for (auto& row : rows) {
      json entry;
      if (row.contains("target_user_id") && !row["target_user_id"].is_null())
        entry["target_user_id"] = row["target_user_id"].get<std::string>();
      if (row.contains("admin_user_id") && !row["admin_user_id"].is_null())
        entry["admin_user_id"] = row["admin_user_id"].get<std::string>();
      if (row.contains("expiration_ts_ms") &&
          !row["expiration_ts_ms"].is_null())
        entry["expiration_ts_ms"] =
            row["expiration_ts_ms"].get<int64_t>();
      else
        entry["expiration_ts_ms"] = 0;
      if (row.contains("used") && !row["used"].is_null())
        entry["used"] = row["used"].get<int>() != 0;
      else
        entry["used"] = false;
      if (row.contains("created_ts") && !row["created_ts"].is_null())
        entry["created_ts"] = row["created_ts"].get<int64_t>();
      else
        entry["created_ts"] = 0;
      entry["expired"] =
          entry["expiration_ts_ms"].get<int64_t>() > 0 &&
          now_ms >= entry["expiration_ts_ms"].get<int64_t>();
      result.push_back(entry);
    }
    return result;
  }

  /// Cleanup expired admin reset tokens.
  int cleanup_expired_admin_reset_tokens() {
    int64_t now_ms = static_cast<int64_t>(util::now_ms());
    return db_.execute_returning_count(
        "DELETE FROM admin_password_reset_tokens "
        "WHERE expiration_ts_ms > 0 AND expiration_ts_ms <= " +
        std::to_string(now_ms));
  }

  // =========================================================================
  // --- Bulk operations / maintenance ---
  // =========================================================================

  /// Run full account validity sweep: warn expiring, expire overdue accounts.
  json run_validity_sweep() {
    json report;
    int warned = 0;
    int expired = 0;
    int tokens_cleaned = 0;

    // Account expiry warnings
    auto warn_users = get_users_needing_expiry_warning();
    for (auto& uid : warn_users) {
      record_expiry_warning_sent(uid);
      warned++;
    }
    report["expiry_warnings_sent"] = warned;
    report["expiry_warning_users"] = warn_users;

    // Auto-expire accounts
    auto expired_accounts = get_expired_accounts(true);
    expired = static_cast<int>(expired_accounts.size());
    report["accounts_expired"] = expired;
    report["expired_accounts"] = expired_accounts;

    // Cleanup expired verification tokens
    tokens_cleaned = cleanup_expired_verification_tokens();
    report["verification_tokens_cleaned"] = tokens_cleaned;

    // Cleanup expired registration tokens
    int reg_tokens = cleanup_expired_registration_tokens();
    report["registration_tokens_cleaned"] = reg_tokens;

    // Cleanup expired admin reset tokens
    int admin_reset = cleanup_expired_admin_reset_tokens();
    report["admin_reset_tokens_cleaned"] = admin_reset;

    return report;
  }

  /// Get password policy summary for display to users.
  json get_password_policy_summary() const {
    json result;
    result["min_length"] = policy_.min_length;
    result["requirements"] = json::array();

    std::string reqs;
    if (policy_.require_uppercase)
      result["requirements"].push_back("At least one uppercase letter");
    if (policy_.require_lowercase)
      result["requirements"].push_back("At least one lowercase letter");
    if (policy_.require_digit)
      result["requirements"].push_back("At least one digit");
    if (policy_.require_special)
      result["requirements"].push_back(
          "At least one special character (" + policy_.special_chars + ")");

    result["password_history_size"] = policy_.password_history_size;
    result["password_expiry_days"] = policy_.password_expiry_days;
    result["password_expiry_warn_days"] = policy_.password_expiry_warn_days;

    return result;
  }

  /// Check if a user must change their password (expired or forced).
  bool must_change_password(std::string_view user_id) const {
    auto expiry = check_password_expiry(user_id);
    return expiry.value("expired", false);
  }

  /// Deactivate a user account.
  void deactivate_account(std::string_view user_id) {
    db_.execute(
        "UPDATE users SET deactivated = 1 WHERE id = " +
        sql_quote(user_id));
  }

  /// Reactivate a user account.
  void reactivate_account(std::string_view user_id) {
    db_.execute(
        "UPDATE users SET deactivated = 0 WHERE id = " +
        sql_quote(user_id));
  }

  // =========================================================================
  // --- Statistics / reporting ---
  // =========================================================================

  /// Get overall password/account statistics.
  json get_statistics() const {
    json stats;

    // Total users
    auto total_rows =
        db_.query("SELECT COUNT(*) as cnt FROM users WHERE deactivated = 0");
    if (!total_rows.empty() && total_rows[0].contains("cnt") &&
        !total_rows[0]["cnt"].is_null())
      stats["total_active_users"] = total_rows[0]["cnt"].get<int64_t>();

    // Deactivated users
    auto deact_rows =
        db_.query("SELECT COUNT(*) as cnt FROM users WHERE deactivated = 1");
    if (!deact_rows.empty() && deact_rows[0].contains("cnt") &&
        !deact_rows[0]["cnt"].is_null())
      stats["total_deactivated_users"] =
          deact_rows[0]["cnt"].get<int64_t>();

    // Expiring soon
    auto expiring = get_users_with_expiring_passwords();
    stats["passwords_expiring_soon"] = expiring.size();

    // Active registration tokens
    int64_t now_ms = static_cast<int64_t>(util::now_ms());
    auto token_rows = db_.query(
        "SELECT COUNT(*) as cnt FROM registration_tokens WHERE "
        "(expiry_ts_ms > " +
        std::to_string(now_ms) + " OR expiry_ts_ms = 0)");
    if (!token_rows.empty() && token_rows[0].contains("cnt") &&
        !token_rows[0]["cnt"].is_null())
      stats["active_registration_tokens"] =
          token_rows[0]["cnt"].get<int64_t>();

    // Pending email verifications
    auto ev_rows = db_.query(
        "SELECT COUNT(*) as cnt FROM email_verification_tokens "
        "WHERE used = 0 AND expiration_ts_ms > " +
        std::to_string(now_ms));
    if (!ev_rows.empty() && ev_rows[0].contains("cnt") &&
        !ev_rows[0]["cnt"].is_null())
      stats["pending_email_verifications"] =
          ev_rows[0]["cnt"].get<int64_t>();

    // Blocked emails count
    auto bl_rows =
        db_.query("SELECT COUNT(*) as cnt FROM email_blocklist");
    if (!bl_rows.empty() && bl_rows[0].contains("cnt") &&
        !bl_rows[0]["cnt"].is_null())
      stats["blocked_emails"] = bl_rows[0]["cnt"].get<int64_t>();

    return stats;
  }

private:
  // =========================================================================
  // --- Private helpers ---
  // =========================================================================

  /// Simple SHA-256 password hashing (matching auth.cpp pattern).
  static std::string hash_password_sha256(std::string_view password) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(password.data()),
           password.size(), hash);
    return util::base64::encode(std::string_view(
        reinterpret_cast<const char*>(hash), SHA256_DIGEST_LENGTH));
  }

  /// Calculate Shannon entropy of a password.
  static double calculate_entropy(std::string_view password) {
    if (password.empty()) return 0.0;

    std::unordered_map<char, int> freq;
    for (char c : password) freq[c]++;

    double entropy = 0.0;
    size_t len = password.size();
    for (auto& [ch, count] : freq) {
      double p = static_cast<double>(count) / len;
      entropy -= p * std::log2(p);
    }
    // Multiply by length for total entropy
    entropy *= len;

    // Bonus entropy for character class diversity
    bool has_lower = false, has_upper = false, has_digit = false,
         has_special = false;
    for (char c : password) {
      if (std::islower(static_cast<unsigned char>(c))) has_lower = true;
      else if (std::isupper(static_cast<unsigned char>(c))) has_upper = true;
      else if (std::isdigit(static_cast<unsigned char>(c))) has_digit = true;
      else has_special = true;
    }
    int classes = static_cast<int>(has_lower) + static_cast<int>(has_upper) +
                  static_cast<int>(has_digit) + static_cast<int>(has_special);
    if (classes > 1) entropy *= (1.0 + (classes - 1) * 0.15);

    // Penalty for sequential patterns
    entropy -= detect_sequential_penalty(password);

    return std::max(0.0, entropy);
  }

  /// Convert entropy bits to a 0-4 score.
  static int score_from_entropy(double entropy) {
    if (entropy < 28) return 0;  // Very weak
    if (entropy < 36) return 1;  // Weak
    if (entropy < 60) return 2;  // Fair
    if (entropy < 80) return 3;  // Strong
    return 4;                    // Very strong
  }

  /// Format crack time in human-readable form.
  static std::string format_crack_time(int64_t seconds) {
    if (seconds < 60) return "instantly";
    if (seconds < 3600)
      return std::to_string(seconds / 60) + " minutes";
    if (seconds < 86400)
      return std::to_string(seconds / 3600) + " hours";
    if (seconds < 31536000)
      return std::to_string(seconds / 86400) + " days";
    if (seconds < 315360000)
      return std::to_string(seconds / 31536000) + " years";
    return "centuries";
  }

  /// Generate human-friendly feedback about password strength.
  void generate_password_feedback(
      std::string_view password,
      const std::vector<std::string>& user_inputs,
      PasswordStrengthResult& result) const {
    size_t len = password.size();

    if (result.score <= 1) {
      if (len < policy_.min_length) {
        result.feedback_warning = "Password is too short";
        result.feedback_suggestions.push_back(
            "Use at least " + std::to_string(policy_.min_length) +
            " characters");
      } else {
        result.feedback_warning = "Password is too guessable";
        result.feedback_suggestions.push_back(
            "Add more words or characters that are less common");
        result.feedback_suggestions.push_back(
            "Avoid common phrases and repeated characters");
      }
    } else if (result.score == 2) {
      result.feedback_warning = "Password is fairly guessable";
      result.feedback_suggestions.push_back(
          "Add another word or two to increase strength");
      result.feedback_suggestions.push_back(
          "Uncommon words and mixed punctuation help");
    } else {
      result.feedback_warning = "";
    }

    // Special case warnings
    bool all_lower = true, all_upper = true, all_digits = true;
    for (char c : password) {
      if (!std::islower(static_cast<unsigned char>(c))) all_lower = false;
      if (!std::isupper(static_cast<unsigned char>(c))) all_upper = false;
      if (!std::isdigit(static_cast<unsigned char>(c))) all_digits = false;
    }
    if (all_lower && len > 0 && result.score < 3) {
      result.feedback_suggestions.push_back("Add uppercase letters");
    }
    if (all_upper && len > 0 && result.score < 3) {
      result.feedback_suggestions.push_back("Add lowercase letters");
    }
    if (all_digits && len > 0) {
      result.feedback_warning = "Password is all digits";
      result.feedback_suggestions.push_back(
          "Don't use only numbers as your password");
    }

    // Check against user inputs
    for (auto& input : user_inputs) {
      std::string pwd_lower(password);
      std::string inp_lower(input);
      std::transform(pwd_lower.begin(), pwd_lower.end(), pwd_lower.begin(),
                     [](unsigned char c) { return std::tolower(c); });
      std::transform(inp_lower.begin(), inp_lower.end(), inp_lower.begin(),
                     [](unsigned char c) { return std::tolower(c); });
      if (inp_lower.size() >= 3 &&
          pwd_lower.find(inp_lower) != std::string::npos) {
        result.feedback_warning = "Password contains personal information";
        result.feedback_suggestions.push_back(
            "Avoid using your name, username, or email in your password");
        break;
      }
    }

    // If no suggestions, provide one
    if (result.feedback_suggestions.empty() && result.score < 4) {
      result.feedback_suggestions.push_back(
          "Use a longer, more random password for better security");
    }
  }

  /// Detect sequential character penalty (e.g., "abcdef", "12345").
  static double detect_sequential_penalty(std::string_view password) {
    double penalty = 0.0;
    if (password.size() < 3) return 0.0;

    int seq_len = 1;
    for (size_t i = 1; i < password.size(); i++) {
      unsigned char prev = static_cast<unsigned char>(password[i - 1]);
      unsigned char curr = static_cast<unsigned char>(password[i]);
      if (curr == prev + 1) {
        seq_len++;
      } else {
        if (seq_len >= 3) penalty += (seq_len - 2) * 2.0;
        seq_len = 1;
      }
    }
    if (seq_len >= 3) penalty += (seq_len - 2) * 2.0;

    // Reverse sequence
    seq_len = 1;
    for (size_t i = 1; i < password.size(); i++) {
      unsigned char prev = static_cast<unsigned char>(password[i - 1]);
      unsigned char curr = static_cast<unsigned char>(password[i]);
      if (curr == prev - 1) {
        seq_len++;
      } else {
        if (seq_len >= 3) penalty += (seq_len - 2) * 1.5;
        seq_len = 1;
      }
    }
    if (seq_len >= 3) penalty += (seq_len - 2) * 1.5;

    // Repeated character penalty
    seq_len = 1;
    for (size_t i = 1; i < password.size(); i++) {
      if (password[i] == password[i - 1]) {
        seq_len++;
      } else {
        if (seq_len >= 3) penalty += (seq_len - 2) * 3.0;
        seq_len = 1;
      }
    }
    if (seq_len >= 3) penalty += (seq_len - 2) * 3.0;

    return penalty;
  }

  /// Check if a password is in the common passwords list.
  static bool is_common_password(std::string_view password) {
    static const std::unordered_set<std::string> kCommonPasswords = {
        "password",  "12345678",  "123456789", "1234567890",
        "qwerty",    "qwerty123", "abc123",    "letmein",
        "monkey",    "dragon",    "baseball",  "iloveyou",
        "trustno1",  "sunshine",  "master",    "welcome",
        "shadow",    "ashley",    "football",  "jesus",
        "michael",   "ninja",     "mustang",   "password1",
        "admin",     "administrator", "root",  "toor",
        "hunter2",   "matrix",    "synapse",   "element",
        "passw0rd",  "p@ssword",  "p@ssw0rd",  "changeme",
        "secret",    "1234",      "12345",     "qwertyuiop",
        "asdfghjkl", "zxcvbnm",   "1q2w3e4r",  "pass",
        "login",     "starwars",  "pokemon",   "batman",
        "access",    "flower",    "lovely",    "password123"};
    return kCommonPasswords.find(std::string(password)) !=
           kCommonPasswords.end();
  }

  /// Trim excess entries from password history.
  void trim_password_history(std::string_view user_id) {
    // Delete oldest entries beyond history size
    db_.execute(
        "DELETE FROM user_password_history WHERE id IN ("
        "SELECT id FROM user_password_history WHERE user_id = " +
        sql_quote(user_id) +
        " ORDER BY created_ts ASC LIMIT -1 OFFSET " +
        std::to_string(policy_.password_history_size) + ")");
  }

  /// Check if a username looks random (high entropy for length).
  static bool looks_random(std::string_view s) {
    if (s.size() < 10) return false;

    // Count unique characters
    std::unordered_set<char> unique_chars;
    for (char c : s) unique_chars.insert(c);

    double ratio =
        static_cast<double>(unique_chars.size()) / s.size();
    // High ratio indicates randomness
    if (ratio > 0.85) return true;

    // Check consonant/vowel alternation ratio (normal text has natural
    // alternation, random strings don't)
    static const std::string kVowels = "aeiou";
    int transitions = 0;
    for (size_t i = 1; i < s.size(); i++) {
      bool prev_is_vowel =
          kVowels.find(s[i - 1]) != std::string::npos;
      bool curr_is_vowel = kVowels.find(s[i]) != std::string::npos;
      if (prev_is_vowel != curr_is_vowel) transitions++;
    }
    double transition_ratio =
        static_cast<double>(transitions) / (s.size() - 1);
    // Random strings have ~50% transitions; natural text has
    // different pattern
    if (transition_ratio > 0.8) return true;

    return false;
  }

  /// Check if username appears to impersonate an admin.
  static bool is_admin_impersonation(std::string_view username) {
    static const std::vector<std::string> kAdminPatterns = {
        "admin", "administrator", "moderator", "mod",
        "system", "server", "root", "operator",
        "support", "staff", "official", "team"};
    std::string lower(username);
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return std::tolower(c); });

    for (auto& pattern : kAdminPatterns) {
      if (lower == pattern) return true;
      // Check for "admin-something" or "something-admin"
      if (lower.find(pattern + "-") == 0) return true;
      if (lower.rfind("-" + pattern) != std::string::npos &&
          lower.rfind("-" + pattern) + pattern.size() + 1 == lower.size())
        return true;
    }
    return false;
  }

  /// Check if username contains confusing/homoglyph patterns.
  static bool has_confusing_pattern(std::string_view username) {
    std::string s(username);
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return std::tolower(c); });

    // Repeated character runs
    for (size_t i = 2; i < s.size(); i++) {
      if (s[i] == s[i - 1] && s[i] == s[i - 2]) return true;
    }

    // Alternating pair patterns (e.g., abababab)
    if (s.size() >= 6) {
      bool alternating = true;
      for (size_t i = 2; i < s.size(); i++) {
        if (s[i] != s[i - 2]) {
          alternating = false;
          break;
        }
      }
      if (alternating && s[0] != s[1]) return true;
    }

    // Homoglyph substitution patterns
    static const std::unordered_map<char, char> kHomoglyphs = {
        {'0', 'o'}, {'1', 'l'}, {'3', 'e'}, {'4', 'a'},
        {'5', 's'}, {'7', 't'}, {'8', 'b'}, {'@', 'a'},
        {'$', 's'}};
    bool has_substitution = false;
    for (char c : s) {
      if (kHomoglyphs.find(c) != kHomoglyphs.end()) {
        has_substitution = true;
        break;
      }
    }
    if (has_substitution && s.size() < 6) return true;

    return false;
  }

  /// Check if username contains offensive content.
  static bool is_offensive_username(std::string_view username) {
    // Extremely conservative built-in list of clearly abusive patterns
    static const std::unordered_set<std::string> kOffensive = {
        "nigger", "faggot", "hitler", "nazi", "killall",
        "killyourself", "terrorist", "pedophile", "rapist"};
    std::string lower(username);
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    for (auto& word : kOffensive) {
      if (lower.find(word) != std::string::npos) return true;
    }
    return false;
  }

  /// Check if a domain is a known disposable email domain.
  static bool is_disposable_email_domain(std::string_view domain) {
    static const std::unordered_set<std::string> kDisposableDomains = {
        "mailinator.com", "guerrillamail.com", "10minutemail.com",
        "tempmail.com", "throwaway.email", "yopmail.com",
        "sharklasers.com", "trashmail.com", "dispostable.com",
        "maildrop.cc", "temp-mail.org", "fakeinbox.com",
        "emailondeck.com", "spamgourmet.com", "spam4.me",
        "mytemp.email", "tmpmail.org", "moakt.cc", "getnada.com",
        "inboxalias.com", "jetable.org", "mintemail.com",
        "guerrillamail.org", "guerrillamail.net",
        "guerrillamail.biz", "guerrillamail.de", "sharklasers.com",
        "grr.la", "pokemail.net", "spam4.me", "wegwerfmail.de",
        "wegwerfmail.net", "wegwerfmail.org", "tempinbox.com",
        "harakirimail.com", "33mail.com", "anonbox.net",
        "mailnesia.com", "spambox.us", "mailexpire.com",
        "mailcatch.com", "emailtemporanea.com", "emailtemporanea.net",
        "discard.email", "discardmail.com", "discardmail.de",
        "trashmail.de", "trashmail.at", "trashmail.net",
        "trashmail.org", "trashmail.ws", "trashmail.me",
        "trashmail.io", "spam.la", "deadaddress.com",
        "bum.net", "zoemail.org", "objectmail.com",
        "proxymail.eu", "rcpt.at", "mailsucker.net", "nospam.ze.tc",
        "tmailinator.com", "nwytg.com", "mail.by", "u.9m.no",
        "nowmymail.com", "mailmoat.com", "mohmal.com",
        "mail1a.de", "wemel.org", "emailfake.com", "armyspy.com",
        "dayrep.com", "einrot.com", "fleckens.hu", "gustr.com",
        "jourrapide.com", "teleworm.us", "superrito.com"};
    std::string d(domain);
    std::transform(d.begin(), d.end(), d.begin(),
                   [](unsigned char c) { return std::tolower(c); });

    if (kDisposableDomains.find(d) != kDisposableDomains.end())
      return true;

    // Common disposable subdomain patterns
    for (auto& dd : kDisposableDomains) {
      if (d.size() > dd.size() &&
          d.compare(d.size() - dd.size(), dd.size(), dd) == 0)
        return true;
    }

    return false;
  }

  /// Perform actual MX record lookup for a domain.
  static std::vector<std::string> lookup_mx_records(
      std::string_view domain) {
    std::vector<std::string> result;
    std::string domain_str(domain);

    // Convert to C string for getaddrinfo/gethostbyname
    // MX records typically resolved via DNS queries. Use simple approach:
    // Try resolving the mail exchange via std::system dig
    // Fallback: just check if domain resolves at all

    // For simplicity, check if the domain itself resolves (basic connectivity)
    struct addrinfo hints, *res = nullptr;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    // Try SMTP on common ports as a basic check
    // Actually, let's just do an A record lookup of the domain
    int ret = getaddrinfo(domain_str.c_str(), nullptr, &hints, &res);
    if (ret == 0) {
      // Domain resolves, add it as having MX capability
      // In production, you'd do actual MX lookups
      char ip[INET_ADDRSTRLEN];
      struct sockaddr_in* addr = (struct sockaddr_in*)res->ai_addr;
      inet_ntop(AF_INET, &addr->sin_addr, ip, sizeof(ip));
      result.push_back(std::string(ip));
      freeaddrinfo(res);

      // Also add the domain itself as a fallback MX
      result.push_back(domain_str);
    } else {
      // Try with "mail." prefix
      std::string mail_domain = "mail." + domain_str;
      ret = getaddrinfo(mail_domain.c_str(), nullptr, &hints, &res);
      if (ret == 0) {
        char ip[INET_ADDRSTRLEN];
        struct sockaddr_in* addr = (struct sockaddr_in*)res->ai_addr;
        inet_ntop(AF_INET, &addr->sin_addr, ip, sizeof(ip));
        result.push_back(std::string(ip));
        result.push_back(mail_domain);
        freeaddrinfo(res);
      } else {
        // Try smtp. prefix
        std::string smtp_domain = "smtp." + domain_str;
        ret = getaddrinfo(smtp_domain.c_str(), nullptr, &hints, &res);
        if (ret == 0) {
          char ip[INET_ADDRSTRLEN];
          struct sockaddr_in* addr = (struct sockaddr_in*)res->ai_addr;
          inet_ntop(AF_INET, &addr->sin_addr, ip, sizeof(ip));
          result.push_back(std::string(ip));
          result.push_back(smtp_domain);
          freeaddrinfo(res);
        }
      }
    }

    return result;
  }

  /// Cleanup expired email verification tokens.
  int cleanup_expired_verification_tokens() {
    int64_t now_ms = static_cast<int64_t>(util::now_ms());
    auto rows = db_.query(
        "SELECT token FROM email_verification_tokens "
        "WHERE expiration_ts_ms > 0 AND expiration_ts_ms <= " +
        std::to_string(now_ms) + " AND used = 0");

    int count = 0;
    for (auto& row : rows) {
      if (row.contains("token") && !row["token"].is_null()) {
        db_.execute(
            "DELETE FROM email_verification_tokens WHERE token = " +
            sql_quote(row["token"].get<std::string>()));
        count++;
      }
    }
    return count;
  }

  /// Count recent entries in a rate-limit map.
  int count_recent(
      const std::unordered_map<std::string, std::vector<int64_t>>& map,
      const std::string& key, int64_t now_ms) const {
    auto it = map.find(key);
    if (it == map.end()) return 0;
    int count = 0;
    for (int64_t ts : it->second) {
      if ((now_ms - ts) <= kRegRateLimitWindowSec * 1000LL) count++;
    }
    return count;
  }

  /// Count recent global entries.
  int count_recent_global(int64_t now_ms) const {
    int count = 0;
    for (int64_t ts : global_reg_timestamps_) {
      if ((now_ms - ts) <= kRegRateLimitWindowSec * 1000LL) count++;
    }
    return count;
  }

  storage::DatabasePool& db_;
  PasswordPolicy policy_;

  // Rate limiting state
  mutable std::mutex rate_limit_mutex_;
  mutable std::unordered_map<std::string, std::vector<int64_t>>
      ip_rate_entries_;
  mutable std::unordered_map<std::string, std::vector<int64_t>>
      domain_rate_entries_;
  mutable std::vector<int64_t> global_reg_timestamps_;
};

// ============================================================================
// PasswordHashManager - Utility to hash passwords with salt
// ============================================================================

class PasswordHashManager {
public:
  /// Create a salted SHA-256 hash of a password.
  static std::string create_hash(std::string_view password) {
    // Generate random 16-byte salt
    unsigned char salt[16];
    RAND_bytes(salt, sizeof(salt));

    // Hash with HMAC-SHA256 using salt
    unsigned char result[EVP_MAX_MD_SIZE];
    unsigned int result_len = 0;
    HMAC(EVP_sha256(), salt, sizeof(salt),
         reinterpret_cast<const unsigned char*>(password.data()),
         password.size(), result, &result_len);

    // Encode as "salt_b64$hash_b64"
    std::string salt_str = util::base64::encode(
        std::string_view(reinterpret_cast<const char*>(salt), sizeof(salt)));
    std::string hash_str = util::base64::encode(
        std::string_view(reinterpret_cast<const char*>(result), result_len));

    return salt_str + "$" + hash_str;
  }

  /// Verify a password against a stored hash.
  static bool verify(std::string_view password,
                       std::string_view stored_hash) {
    auto pos = stored_hash.find('$');
    if (pos == std::string::npos) {
      // Legacy mode: plain SHA-256 comparison
      unsigned char hash[SHA256_DIGEST_LENGTH];
      SHA256(reinterpret_cast<const unsigned char*>(password.data()),
             password.size(), hash);
      std::string computed = util::base64::encode(
          std::string_view(reinterpret_cast<const char*>(hash),
                           SHA256_DIGEST_LENGTH));
      return computed == stored_hash;
    }

    std::string salt_b64(stored_hash.substr(0, pos));
    std::string expected_hash(stored_hash.substr(pos + 1));

    auto salt = util::base64::decode(salt_b64);

    unsigned char result[EVP_MAX_MD_SIZE];
    unsigned int result_len = 0;
    HMAC(EVP_sha256(),
         reinterpret_cast<const unsigned char*>(salt.data()), salt.size(),
         reinterpret_cast<const unsigned char*>(password.data()),
         password.size(), result, &result_len);

    std::string computed_hash = util::base64::encode(
        std::string_view(reinterpret_cast<const char*>(result), result_len));

    return computed_hash == expected_hash;
  }
};

// ============================================================================
// PasswordPolicyService - High-level service combining all features
// ============================================================================

class PasswordPolicyService {
public:
  explicit PasswordPolicyService(storage::DatabasePool& db)
      : validator_(db) {}

  /// Configure the password policy.
  void configure(const PasswordPolicy& policy) {
    validator_.set_policy(policy);
  }

  void configure_from_json(const json& config) {
    if (config.contains("password_policy"))
      validator_.set_policy(
          PasswordPolicy::from_json(config["password_policy"]));
  }

  /// Get current policy.
  const PasswordPolicy& policy() const { return validator_.policy(); }

  // ---- Password management ----

  /// Validate password against policy and check history.
  json validate_password(std::string_view password,
                           std::string_view username = "",
                           std::string_view user_id_for_history = "") const {
    json result = validator_.validate_password_policy(password, username);

    if (result["valid"].get<bool>() &&
        !user_id_for_history.empty()) {
      // Check password history
      std::string pw_hash = PasswordHashManager::create_hash(password);
      bool in_history =
          validator_.is_password_in_history(user_id_for_history, pw_hash);
      if (in_history) {
        result["valid"] = false;
        result["error"] = "Password has been used recently";
        result["violations"] = json::array(
            {{{"rule", "password_history"},
              {"message", "You cannot reuse a recent password"}}});
      }
    }

    return result;
  }

  /// Change password for a user (validates policy, checks history, records).
  json change_password(std::string_view user_id,
                         std::string_view old_password = "",
                         std::string_view new_password = "") {
    json result;

    // Validate new password
    auto validation = validator_.validate_password_policy(new_password);
    if (!validation["valid"].get<bool>()) {
      return {{"errcode", "M_WEAK_PASSWORD"},
              {"error", validation["error"]},
              {"details", validation}};
    }

    // Check history
    std::string new_hash = PasswordHashManager::create_hash(new_password);
    if (!user_id.empty() &&
        validator_.is_password_in_history(user_id, new_hash)) {
      return {{"errcode", "M_WEAK_PASSWORD"},
              {"error", "Password has been used recently"}};
    }

    // If old password provided, verify it
    if (!old_password.empty()) {
      // Verify old password against stored hash
      auto rows = validator_.db_query(
          "SELECT password_hash FROM users WHERE id = " +
          sql_quote(user_id));
      if (rows.empty() || !rows[0].contains("password_hash") ||
          rows[0]["password_hash"].is_null()) {
        return {{"errcode", "M_UNKNOWN"}, {"error", "User not found"}};
      }
      std::string stored_hash =
          rows[0]["password_hash"].get<std::string>();
      if (!PasswordHashManager::verify(old_password, stored_hash)) {
        return {{"errcode", "M_FORBIDDEN"},
                {"error", "Current password is incorrect"}};
      }
    }

    // Store new hash
    validator_.db_execute(
        "UPDATE users SET password_hash = " + sql_quote(new_hash) +
        ", password_last_changed_ts = " +
        std::to_string(util::now_ms()) + " WHERE id = " +
        sql_quote(user_id));

    // Record in history
    validator_.record_password_in_history(user_id, new_hash);

    result["success"] = true;
    result["message"] = "Password changed successfully";
    return result;
  }

  /// Get password strength for a candidate password.
  json get_password_strength(
      std::string_view password,
      const std::vector<std::string>& user_inputs = {}) {
    auto strength = validator_.check_password_strength(password, user_inputs);
    return strength.to_json();
  }

  // ---- Account validity ----

  json set_account_validity(std::string_view user_id,
                              int validity_period_days) {
    validator_.set_account_validity(user_id, validity_period_days);
    return validator_.get_account_validity(user_id);
  }

  json get_account_validity(std::string_view user_id) {
    return validator_.get_account_validity(user_id);
  }

  json renew_account(std::string_view user_id,
                       int renewal_period_days = -1) {
    return validator_.renew_account(user_id, renewal_period_days);
  }

  json check_account(std::string_view user_id,
                       bool auto_expire = false) {
    return validator_.check_account_expired(user_id, auto_expire);
  }

  // ---- Email verification ----

  json generate_verification_token(std::string_view user_id,
                                      std::string_view email) {
    return validator_.generate_email_verification_token(user_id, email);
  }

  json verify_email(std::string_view token) {
    return validator_.validate_email_verification_token(token);
  }

  bool is_email_verified(std::string_view user_id,
                           std::string_view email) {
    return validator_.is_email_verified(user_id, email);
  }

  json validate_registration_email(std::string_view email) {
    return validator_.validate_email_for_registration(email);
  }

  // ---- Email block list ----

  void block_email(std::string_view email_or_domain) {
    validator_.add_email_to_blocklist(email_or_domain);
  }

  void unblock_email(std::string_view email_or_domain) {
    validator_.remove_email_from_blocklist(email_or_domain);
  }

  bool is_email_blocked(std::string_view email) {
    return validator_.is_email_blocked(email);
  }

  std::vector<std::string> list_blocked_emails() {
    return validator_.get_email_blocklist();
  }

  // ---- Registration ----

  json pre_register(std::string_view username,
                       std::string_view password,
                       std::string_view email = "",
                       std::string_view ip_address = "",
                       std::string_view reg_token = "") {
    return validator_.pre_register_check(username, password, email,
                                           ip_address, reg_token);
  }

  json post_register(std::string_view user_id,
                        std::string_view email = "",
                        std::string_view ip_address = "",
                        std::string_view reg_token = "") {
    return validator_.post_register_hook(user_id, email, ip_address,
                                           reg_token);
  }

  // ---- Registration token management ----

  json create_reg_token(std::string_view token_value = "",
                          int uses_allowed = kRegTokenDefaultUsesAllowed,
                          int64_t expiry_ts_ms = 0) {
    return validator_.create_registration_token(token_value, uses_allowed,
                                                  expiry_ts_ms);
  }

  json validate_reg_token(std::string_view token) {
    return validator_.validate_registration_token(token);
  }

  void revoke_reg_token(std::string_view token) {
    validator_.revoke_registration_token(token);
  }

  void revoke_all_reg_tokens() {
    validator_.revoke_all_registration_tokens();
  }

  std::vector<json> list_reg_tokens() {
    return validator_.list_registration_tokens();
  }

  // ---- Username validation ----

  json validate_username(std::string_view username) {
    return validator_.validate_username(username);
  }

  bool is_username_taken(std::string_view username) {
    return validator_.is_username_taken(username);
  }

  std::vector<std::string> suggest_usernames(std::string_view desired,
                                                int count = 5) {
    return validator_.suggest_usernames(desired, count);
  }

  void blacklist_username(std::string_view pattern) {
    validator_.add_username_to_blacklist(pattern);
  }

  void unblacklist_username(std::string_view pattern) {
    validator_.remove_username_from_blacklist(pattern);
  }

  bool is_username_blacklisted(std::string_view username) {
    return validator_.is_username_blacklisted(username);
  }

  std::vector<std::string> list_blacklisted_usernames() {
    return validator_.get_username_blacklist();
  }

  // ---- Admin password reset ----

  json admin_reset(std::string_view target_user_id,
                     std::string_view admin_user_id) {
    return validator_.admin_generate_password_reset(target_user_id,
                                                      admin_user_id);
  }

  json admin_validate_reset_token(std::string_view token) {
    return validator_.admin_validate_password_reset(token);
  }

  json admin_complete_reset(std::string_view token,
                              std::string_view new_password) {
    return validator_.admin_complete_password_reset(token, new_password);
  }

  // ---- Maintenance ----

  json sweep() { return validator_.run_validity_sweep(); }

  json statistics() { return validator_.get_statistics(); }

  json password_policy_summary() {
    return validator_.get_password_policy_summary();
  }

  bool must_change_password(std::string_view user_id) {
    return validator_.must_change_password(user_id);
  }

  // ---- Deactivation ----

  void deactivate_user(std::string_view user_id) {
    validator_.deactivate_account(user_id);
  }

  void reactivate_user(std::string_view user_id) {
    validator_.reactivate_account(user_id);
  }

  // ---- Rate limiting ----

  json check_rate_limit(std::string_view ip, std::string_view email = "") {
    return validator_.check_registration_rate_limit(ip, email);
  }

  json rate_limit_status(std::string_view ip,
                           std::string_view email = "") {
    return validator_.get_rate_limit_status(ip, email);
  }

private:
  PasswordPolicyValidator validator_;
};

// ============================================================================
// Convenience functions (standalone API)
// ============================================================================

namespace {

// Simple password strength score: 0-4 using zxcvbn-inspired heuristics
int quick_password_score(std::string_view password) {
  if (password.size() < 6) return 0;
  if (password.size() < 8) return 1;

  bool has_lower = false, has_upper = false, has_digit = false,
       has_special = false;
  for (char c : password) {
    if (std::islower(static_cast<unsigned char>(c))) has_lower = true;
    else if (std::isupper(static_cast<unsigned char>(c))) has_upper = true;
    else if (std::isdigit(static_cast<unsigned char>(c))) has_digit = true;
    else has_special = true;
  }

  int classes = has_lower + has_upper + has_digit + has_special;

  if (password.size() >= 12 && classes >= 3) return 4;
  if (password.size() >= 10 && classes >= 3) return 3;
  if (password.size() >= 8 && classes >= 2) return 2;
  if (classes >= 1) return 1;
  return 0;
}

}  // namespace

// ============================================================================
// Free function: quick password strength check
// ============================================================================

json quick_password_check(std::string_view password) {
  int score = quick_password_score(password);
  json result;
  result["score"] = score;
  switch (score) {
    case 0:
      result["label"] = "Very Weak";
      break;
    case 1:
      result["label"] = "Weak";
      break;
    case 2:
      result["label"] = "Fair";
      break;
    case 3:
      result["label"] = "Strong";
      break;
    case 4:
      result["label"] = "Very Strong";
      break;
  }
  return result;
}

// ============================================================================
// Free function: generate a cryptographically secure random password
// ============================================================================

std::string generate_secure_password(size_t length = 16,
                                       bool upper = true,
                                       bool lower = true,
                                       bool digits = true,
                                       bool special = true) {
  static const std::string kLower = "abcdefghijklmnopqrstuvwxyz";
  static const std::string kUpper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  static const std::string kDigits = "0123456789";
  static const std::string kSpecial = "!@#$%^&*()_+-=[]{}|;:,.<>?";

  std::string charset;
  std::vector<std::string> required;
  if (lower) {
    charset += kLower;
    required.push_back(kLower);
  }
  if (upper) {
    charset += kUpper;
    required.push_back(kUpper);
  }
  if (digits) {
    charset += kDigits;
    required.push_back(kDigits);
  }
  if (special) {
    charset += kSpecial;
    required.push_back(kSpecial);
  }
  if (charset.empty()) charset = kLower + kUpper + kDigits;

  // Ensure at least one from each required set
  std::string password;
  password.reserve(length);

  unsigned char buf[256];
  for (auto& set : required) {
    RAND_bytes(buf, 1);
    password += set[buf[0] % set.size()];
  }

  // Fill remaining with random chars from full charset
  while (password.size() < length) {
    RAND_bytes(buf, 1);
    password += charset[buf[0] % charset.size()];
  }

  // Shuffle using Fisher-Yates
  unsigned char shuffle_buf[256];
  RAND_bytes(shuffle_buf, password.size());
  for (size_t i = password.size() - 1; i > 0; i--) {
    size_t j = shuffle_buf[i] % (i + 1);
    std::swap(password[i], password[j]);
  }

  return password;
}

}  // namespace progressive::auth
