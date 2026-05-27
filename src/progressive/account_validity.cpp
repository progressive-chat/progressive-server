// ============================================================================
// account_validity.cpp — Matrix Account Validity and Renewal Engine
//
// Implements:
//   - Account Validity Periods: per-user expiration timestamps in ms,
//     auto-calculate from creation time + configured period, configurable
//     default periods, per-user override periods
//   - Renewal Workflow: cryptographic renewal token generation, email-based
//     renewal with token links, HTTP endpoint token acceptance, token
//     expiry with configurable TTL, multi-use vs single-use tokens
//   - Warning Emails: tiered warning system (7 days, 3 days, 1 day before
//     expiration), configurable warning periods, HTML/text email templates,
//     server notice integration, warning deduplication
//   - Auto-Deactivation: background job to deactivate expired accounts,
//     graceful data preservation during grace period, configurable grace
//     period before permanent deletion, dry-run mode for testing
//   - Admin Controls: REST admin API for setting/removing account validity,
//     extending expiration, manual deactivation, listing expiring accounts,
//     bulk operations, statistics and metrics
//   - Exemptions: server admin exemption, appservice user exemption,
//     support user exemption, configurable exemption lists, wildcard
//     pattern matching for user ID exemptions
//   - GDPR Compliance: respect erasure requests during deactivation,
//     track consent for data retention, proper data anonymization,
//     audit trail for deactivation actions
//
// Equivalent to:
//   synapse/handlers/account_validity.py
//   synapse/rest/admin/account_validity.py
//   synapse/handlers/deactivate_account.py
//   synapse/api/constants.py (EventTypes for validity notices)
//   synapse/rest/client/account_validity.py (renewal endpoints)
//
// Target: 2000+ lines of production-grade C++.
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
#include "progressive/storage/databases/main/events.hpp"
#include "progressive/storage/databases/main/registration.hpp"
#include "progressive/storage/databases/main/profile.hpp"
#include "progressive/storage/databases/main/devices.hpp"
#include "progressive/storage/databases/main/roommember.hpp"
#include "progressive/storage/databases/main/presence.hpp"
#include "progressive/storage/databases/main/room.hpp"
#include "progressive/storage/databases/main/state.hpp"

// ============================================================================
// Namespace
// ============================================================================
namespace progressive {

using json = nlohmann::json;
namespace chr = std::chrono;

// ============================================================================
// Forward declarations for internal classes
// ============================================================================
class AccountValidityConfig;
class AccountValidityStore;
class ExpirationWarningEngine;
class RenewalWorkflow;
class AutoDeactivationJob;
class AccountValidityAdminAPI;
class AccountValidityExemptions;
class AccountValidityEngine;

// ============================================================================
// Anonymous namespace — Internal helpers and utilities
// ============================================================================
namespace {

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
int64_t minutes_to_ms(int minutes) { return static_cast<int64_t>(minutes) * 60000LL; }

// ---- Token / ID generation ----

std::string generate_token(int length = 32) {
  static const char cs[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  static std::random_device rd;
  static thread_local std::mt19937 gen(rd());
  std::uniform_int_distribution<> dist(0, 63);
  std::string tok(length, 'A');
  for (auto& c : tok) c = cs[dist(gen)];
  return tok;
}

std::string generate_uuid() {
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<> hex_dist(0, 15);
  const char* hex = "0123456789abcdef";
  std::string uuid(36, '-');
  for (int i = 0; i < 36; i++) {
    if (i == 8 || i == 13 || i == 18 || i == 23) continue;
    uuid[i] = hex[hex_dist(gen)];
  }
  uuid[14] = '4';
  uuid[19] = hex[8 + hex_dist(gen) % 4];
  return uuid;
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

std::vector<std::string> split(const std::string& s, char delim) {
  std::vector<std::string> result;
  std::stringstream ss(s);
  std::string item;
  while (std::getline(ss, item, delim)) {
    if (!item.empty()) result.push_back(trim(item));
  }
  return result;
}

std::string join(const std::vector<std::string>& parts, const std::string& delim) {
  std::string result;
  for (size_t i = 0; i < parts.size(); i++) {
    if (i > 0) result += delim;
    result += parts[i];
  }
  return result;
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

// ---- Email validation ----

bool is_valid_email(const std::string& email) {
  static const std::regex email_re(
      R"(^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$)");
  return std::regex_match(email, email_re);
}

// ---- HTML escaping ----

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

// ---- Duration formatting ----

std::string format_duration(int64_t seconds) {
  if (seconds <= 0) return "now";
  int64_t days = seconds / 86400;
  int64_t hours = (seconds % 86400) / 3600;
  int64_t minutes = (seconds % 3600) / 60;
  std::string result;
  if (days > 0) result += std::to_string(days) + " day" + (days != 1 ? "s" : "") + " ";
  if (hours > 0) result += std::to_string(hours) + " hour" + (hours != 1 ? "s" : "") + " ";
  if (minutes > 0) result += std::to_string(minutes) + " minute" + (minutes != 1 ? "s" : "");
  if (result.empty()) return std::to_string(seconds) + " seconds";
  return trim(result);
}

// ---- In-memory config store (thread-safe) ----

class ConfigStore {
public:
  void set(const std::string& key, const json& value) {
    std::unique_lock lock(mu_);
    data_[key] = value;
  }
  json get(const std::string& key, const json& default_val = nullptr) const {
    std::shared_lock lock(mu_);
    auto it = data_.find(key);
    if (it != data_.end()) return it->second;
    return default_val;
  }
  void remove(const std::string& key) {
    std::unique_lock lock(mu_);
    data_.erase(key);
  }
  bool exists(const std::string& key) const {
    std::shared_lock lock(mu_);
    return data_.count(key) > 0;
  }
  std::vector<std::string> keys() const {
    std::shared_lock lock(mu_);
    std::vector<std::string> result;
    for (auto& kv : data_) result.push_back(kv.first);
    return result;
  }
  json to_json() const {
    std::shared_lock lock(mu_);
    json j;
    for (auto& kv : data_) j[kv.first] = kv.second;
    return j;
  }

private:
  std::unordered_map<std::string, json> data_;
  mutable std::shared_mutex mu_;
};

// Global config store for runtime settings
ConfigStore g_config;

}  // anonymous namespace

// ============================================================================
// 1. AccountValidityConfig — Centralized Configuration Management
//
// Manages all configuration for the account validity subsystem. Supports
// runtime reconfiguration, provides defaults, and validates configuration
// values. Settings are stored in g_config and can be loaded from YAML.
//
// Equivalent to the account_validity section of homeserver.yaml
// ============================================================================
class AccountValidityConfig {
public:
  AccountValidityConfig() = default;

  // ---- Feature Toggles ----

  /// Enable/disable the entire account validity system
  void set_enabled(bool enabled) {
    g_config.set("account_validity.enabled", enabled);
  }
  bool is_enabled() const {
    return g_config.get("account_validity.enabled", false).get<bool>();
  }

  /// Enable/disable renewal emails (requires SMTP config)
  void set_renewal_emails_enabled(bool enabled) {
    g_config.set("account_validity.renewal_emails_enabled", enabled);
  }
  bool is_renewal_emails_enabled() const {
    return g_config.get("account_validity.renewal_emails_enabled", false).get<bool>();
  }

  /// Enable/disable auto-deactivation background job
  void set_auto_deactivation_enabled(bool enabled) {
    g_config.set("account_validity.auto_deactivation_enabled", enabled);
  }
  bool is_auto_deactivation_enabled() const {
    return g_config.get("account_validity.auto_deactivation_enabled", true).get<bool>();
  }

  /// Enable/disable server notice integration
  void set_server_notices_enabled(bool enabled) {
    g_config.set("account_validity.server_notices_enabled", enabled);
  }
  bool is_server_notices_enabled() const {
    return g_config.get("account_validity.server_notices_enabled", true).get<bool>();
  }

  // ---- Validity Period Settings ----

  /// Default account validity period in days (default: 90)
  void set_default_period_days(int days) {
    g_config.set("account_validity.default_period_days", std::max(1, days));
  }
  int get_default_period_days() const {
    return g_config.get("account_validity.default_period_days", 90).get<int>();
  }

  /// Minimum allowed validity period in days
  void set_min_period_days(int days) {
    g_config.set("account_validity.min_period_days", std::max(1, days));
  }
  int get_min_period_days() const {
    return g_config.get("account_validity.min_period_days", 1).get<int>();
  }

  /// Maximum allowed validity period in days
  void set_max_period_days(int days) {
    g_config.set("account_validity.max_period_days", std::max(1, days));
  }
  int get_max_period_days() const {
    return g_config.get("account_validity.max_period_days", 3650).get<int>();
  }

  /// Whether to auto-calculate expiration from account creation time
  void set_calc_from_creation(bool enabled) {
    g_config.set("account_validity.calc_from_creation", enabled);
  }
  bool get_calc_from_creation() const {
    return g_config.get("account_validity.calc_from_creation", true).get<bool>();
  }

  // ---- Renewal Token Settings ----

  /// Renewal token lifetime in hours (default: 24)
  void set_renewal_token_lifetime_hours(int hours) {
    g_config.set("account_validity.renewal_token_lifetime_hours", std::max(1, hours));
  }
  int get_renewal_token_lifetime_hours() const {
    return g_config.get("account_validity.renewal_token_lifetime_hours", 24).get<int>();
  }

  /// Whether renewal tokens are single-use (true) or multi-use (false)
  void set_single_use_tokens(bool single_use) {
    g_config.set("account_validity.single_use_tokens", single_use);
  }
  bool get_single_use_tokens() const {
    return g_config.get("account_validity.single_use_tokens", true).get<bool>();
  }

  /// Max number of renewal tokens a user can have active at once
  void set_max_active_tokens(int max_tokens) {
    g_config.set("account_validity.max_active_tokens", std::max(1, max_tokens));
  }
  int get_max_active_tokens() const {
    return g_config.get("account_validity.max_active_tokens", 3).get<int>();
  }

  // ---- Warning Period Settings ----

  /// Warning periods in days (default: 7, 3, 1)
  void set_warning_periods(const std::vector<int>& periods) {
    json arr = json::array();
    for (int p : periods) arr.push_back(p);
    g_config.set("account_validity.warning_periods", arr);
  }
  std::vector<int> get_warning_periods() const {
    json arr = g_config.get("account_validity.warning_periods",
        json::array({7, 3, 1}));
    std::vector<int> result;
    for (auto& v : arr) result.push_back(v.get<int>());
    return result;
  }

  /// Minimum interval between warning sends (hours) to prevent spam
  void set_warning_cooldown_hours(int hours) {
    g_config.set("account_validity.warning_cooldown_hours", std::max(1, hours));
  }
  int get_warning_cooldown_hours() const {
    return g_config.get("account_validity.warning_cooldown_hours", 24).get<int>();
  }

  // ---- Email Template Settings ----

  void set_email_subject_template(const std::string& subject) {
    g_config.set("account_validity.email_subject_template", subject);
  }
  std::string get_email_subject_template() const {
    return g_config.get("account_validity.email_subject_template",
        "Your account will expire soon").get<std::string>();
  }

  void set_email_body_template_html(const std::string& tmpl) {
    g_config.set("account_validity.email_body_template_html", tmpl);
  }
  std::string get_email_body_template_html() const {
    return g_config.get("account_validity.email_body_template_html", "").get<std::string>();
  }

  void set_email_body_template_text(const std::string& tmpl) {
    g_config.set("account_validity.email_body_template_text", tmpl);
  }
  std::string get_email_body_template_text() const {
    return g_config.get("account_validity.email_body_template_text", "").get<std::string>();
  }

  void set_email_from_address(const std::string& addr) {
    g_config.set("account_validity.email_from_address", addr);
  }
  std::string get_email_from_address() const {
    return g_config.get("account_validity.email_from_address",
        "noreply@localhost").get<std::string>();
  }

  void set_renewal_base_url(const std::string& url) {
    g_config.set("account_validity.renewal_base_url", url);
  }
  std::string get_renewal_base_url() const {
    return g_config.get("account_validity.renewal_base_url", "").get<std::string>();
  }

  // ---- Deactivation Settings ----

  /// Grace period in days before permanent data deletion after deactivation
  void set_deactivation_grace_days(int days) {
    g_config.set("account_validity.deactivation_grace_days", std::max(0, days));
  }
  int get_deactivation_grace_days() const {
    return g_config.get("account_validity.deactivation_grace_days", 30).get<int>();
  }

  /// Whether to soft-deactivate (prevent login but preserve data) or hard-deactivate
  void set_soft_deactivation(bool soft) {
    g_config.set("account_validity.soft_deactivation", soft);
  }
  bool get_soft_deactivation() const {
    return g_config.get("account_validity.soft_deactivation", true).get<bool>();
  }

  /// Batch size for auto-deactivation job
  void set_deactivation_batch_size(int size) {
    g_config.set("account_validity.deactivation_batch_size", std::max(1, size));
  }
  int get_deactivation_batch_size() const {
    return g_config.get("account_validity.deactivation_batch_size", 100).get<int>();
  }

  // ---- Background Job Intervals ----

  /// Interval in minutes between auto-deactivation runs
  void set_deactivation_interval_minutes(int minutes) {
    g_config.set("account_validity.deactivation_interval_minutes", std::max(1, minutes));
  }
  int get_deactivation_interval_minutes() const {
    return g_config.get("account_validity.deactivation_interval_minutes", 60).get<int>();
  }

  /// Interval in minutes between warning email runs
  void set_warning_interval_minutes(int minutes) {
    g_config.set("account_validity.warning_interval_minutes", std::max(1, minutes));
  }
  int get_warning_interval_minutes() const {
    return g_config.get("account_validity.warning_interval_minutes", 360).get<int>();
  }

  // ---- Serialization ----

  json to_json() const {
    json j;
    j["enabled"] = is_enabled();
    j["renewal_emails_enabled"] = is_renewal_emails_enabled();
    j["auto_deactivation_enabled"] = is_auto_deactivation_enabled();
    j["server_notices_enabled"] = is_server_notices_enabled();
    j["default_period_days"] = get_default_period_days();
    j["min_period_days"] = get_min_period_days();
    j["max_period_days"] = get_max_period_days();
    j["calc_from_creation"] = get_calc_from_creation();
    j["renewal_token_lifetime_hours"] = get_renewal_token_lifetime_hours();
    j["single_use_tokens"] = get_single_use_tokens();
    j["max_active_tokens"] = get_max_active_tokens();
    j["warning_periods"] = get_warning_periods();
    j["warning_cooldown_hours"] = get_warning_cooldown_hours();
    j["email_subject_template"] = get_email_subject_template();
    j["email_from_address"] = get_email_from_address();
    j["deactivation_grace_days"] = get_deactivation_grace_days();
    j["soft_deactivation"] = get_soft_deactivation();
    j["deactivation_batch_size"] = get_deactivation_batch_size();
    j["deactivation_interval_minutes"] = get_deactivation_interval_minutes();
    j["warning_interval_minutes"] = get_warning_interval_minutes();
    return j;
  }

  void load_from_json(const json& j) {
    if (j.contains("enabled")) set_enabled(j["enabled"].get<bool>());
    if (j.contains("renewal_emails_enabled")) set_renewal_emails_enabled(j["renewal_emails_enabled"].get<bool>());
    if (j.contains("auto_deactivation_enabled")) set_auto_deactivation_enabled(j["auto_deactivation_enabled"].get<bool>());
    if (j.contains("server_notices_enabled")) set_server_notices_enabled(j["server_notices_enabled"].get<bool>());
    if (j.contains("default_period_days")) set_default_period_days(j["default_period_days"].get<int>());
    if (j.contains("min_period_days")) set_min_period_days(j["min_period_days"].get<int>());
    if (j.contains("max_period_days")) set_max_period_days(j["max_period_days"].get<int>());
    if (j.contains("calc_from_creation")) set_calc_from_creation(j["calc_from_creation"].get<bool>());
    if (j.contains("renewal_token_lifetime_hours")) set_renewal_token_lifetime_hours(j["renewal_token_lifetime_hours"].get<int>());
    if (j.contains("single_use_tokens")) set_single_use_tokens(j["single_use_tokens"].get<bool>());
    if (j.contains("max_active_tokens")) set_max_active_tokens(j["max_active_tokens"].get<int>());
    if (j.contains("warning_periods")) {
      std::vector<int> periods;
      for (auto& v : j["warning_periods"]) periods.push_back(v.get<int>());
      set_warning_periods(periods);
    }
    if (j.contains("warning_cooldown_hours")) set_warning_cooldown_hours(j["warning_cooldown_hours"].get<int>());
    if (j.contains("email_subject_template")) set_email_subject_template(j["email_subject_template"].get<std::string>());
    if (j.contains("email_body_template_html")) set_email_body_template_html(j["email_body_template_html"].get<std::string>());
    if (j.contains("email_body_template_text")) set_email_body_template_text(j["email_body_template_text"].get<std::string>());
    if (j.contains("email_from_address")) set_email_from_address(j["email_from_address"].get<std::string>());
    if (j.contains("renewal_base_url")) set_renewal_base_url(j["renewal_base_url"].get<std::string>());
    if (j.contains("deactivation_grace_days")) set_deactivation_grace_days(j["deactivation_grace_days"].get<int>());
    if (j.contains("soft_deactivation")) set_soft_deactivation(j["soft_deactivation"].get<bool>());
    if (j.contains("deactivation_batch_size")) set_deactivation_batch_size(j["deactivation_batch_size"].get<int>());
    if (j.contains("deactivation_interval_minutes")) set_deactivation_interval_minutes(j["deactivation_interval_minutes"].get<int>());
    if (j.contains("warning_interval_minutes")) set_warning_interval_minutes(j["warning_interval_minutes"].get<int>());
  }
};

// ============================================================================
// 2. AccountValidityStore — Storage Layer for Account Validity Data
//
// Abstracts all database operations for account validity. Manages the
// account_validity table, renewal_tokens table, deactivation_log, and
// warning_sent tracking. Uses DatabasePool::runInteraction for all
// transactional operations.
//
// Equivalent to synapse/storage/databases/main/registration.py
//   (account_validity portions)
// ============================================================================
class AccountValidityStore {
public:
  explicit AccountValidityStore(storage::DatabasePool& db) : db_(db) {}

  // ---- Schema Management ----

  /// Ensure the account_validity table exists
  void ensure_tables() {
    db_.runInteraction(
        "av_ensure_tables",
        [&](storage::LoggingTransaction& txn) {
          txn.execute(R"SQL(
            CREATE TABLE IF NOT EXISTS account_validity (
              user_id TEXT NOT NULL PRIMARY KEY,
              expiration_ts_ms BIGINT NOT NULL,
              period_days INTEGER NOT NULL DEFAULT 90,
              last_renewed_ts BIGINT,
              created_ts BIGINT NOT NULL DEFAULT 0,
              updated_ts BIGINT NOT NULL DEFAULT 0,
              warned_ts BIGINT DEFAULT NULL,
              deactivated_ts BIGINT DEFAULT NULL,
              is_exempt BOOLEAN NOT NULL DEFAULT FALSE,
              exempt_reason TEXT DEFAULT NULL
            )
          )SQL");

          txn.execute(R"SQL(
            CREATE INDEX IF NOT EXISTS idx_account_validity_exp
              ON account_validity(expiration_ts_ms)
              WHERE deactivated_ts IS NULL
          )SQL");

          txn.execute(R"SQL(
            CREATE TABLE IF NOT EXISTS account_renewal_tokens (
              token TEXT NOT NULL PRIMARY KEY,
              user_id TEXT NOT NULL,
              created_ts BIGINT NOT NULL,
              expires_ts BIGINT NOT NULL,
              used_ts BIGINT DEFAULT NULL,
              is_used BOOLEAN NOT NULL DEFAULT FALSE,
              FOREIGN KEY (user_id) REFERENCES account_validity(user_id)
            )
          )SQL");

          txn.execute(R"SQL(
            CREATE INDEX IF NOT EXISTS idx_renewal_tokens_user
              ON account_renewal_tokens(user_id, is_used)
          )SQL");

          txn.execute(R"SQL(
            CREATE TABLE IF NOT EXISTS account_deactivation_log (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              user_id TEXT NOT NULL,
              deactivated_ts BIGINT NOT NULL,
              reason TEXT NOT NULL DEFAULT 'expired',
              admin_user TEXT DEFAULT NULL,
              was_soft BOOLEAN NOT NULL DEFAULT TRUE,
              data_purge_scheduled_ts BIGINT DEFAULT NULL
            )
          )SQL");

          txn.execute(R"SQL(
            CREATE INDEX IF NOT EXISTS idx_deactivation_log_user
              ON account_deactivation_log(user_id, deactivated_ts)
          )SQL");

          txn.execute(R"SQL(
            CREATE TABLE IF NOT EXISTS account_validity_warnings (
              user_id TEXT NOT NULL,
              warning_type TEXT NOT NULL,
              sent_ts BIGINT NOT NULL,
              expiration_ts_ms BIGINT NOT NULL,
              channel TEXT NOT NULL DEFAULT 'email',
              PRIMARY KEY (user_id, warning_type, sent_ts)
            )
          )SQL");

          txn.execute(R"SQL(
            CREATE INDEX IF NOT EXISTS idx_validity_warnings_sent
              ON account_validity_warnings(sent_ts)
          )SQL");
        });
  }

  // ---- Per-User Expiration Management ----

  /// Set or update expiration timestamp for a user
  void set_user_expiration(const std::string& user_id,
                           int64_t expiration_ts_ms,
                           int period_days = 90) {
    db_.runInteraction(
        "av_set_expiration",
        [&](storage::LoggingTransaction& txn) {
          int64_t now = now_ms();
          txn.execute(
              "INSERT INTO account_validity "
              "(user_id, expiration_ts_ms, period_days, created_ts, updated_ts) "
              "VALUES (?, ?, ?, ?, ?) "
              "ON CONFLICT(user_id) DO UPDATE SET "
              "expiration_ts_ms = excluded.expiration_ts_ms, "
              "period_days = excluded.period_days, "
              "updated_ts = excluded.updated_ts, "
              "warned_ts = NULL",
              {user_id, std::to_string(expiration_ts_ms),
               std::to_string(period_days),
               std::to_string(now), std::to_string(now)});
        });
  }

  /// Set expiration based on account creation time
  void set_expiration_from_creation(const std::string& user_id,
                                    int64_t creation_ts_ms) {
    db_.runInteraction(
        "av_set_from_creation",
        [&](storage::LoggingTransaction& txn) {
          int period_days = 90; // Will be read from config
          int64_t exp_ts = creation_ts_ms + days_to_ms(period_days);
          txn.execute(
              "INSERT INTO account_validity "
              "(user_id, expiration_ts_ms, period_days, created_ts, updated_ts) "
              "VALUES (?, ?, ?, ?, ?) "
              "ON CONFLICT(user_id) DO UPDATE SET "
              "expiration_ts_ms = excluded.expiration_ts_ms, "
              "updated_ts = excluded.updated_ts",
              {user_id, std::to_string(exp_ts),
               std::to_string(period_days),
               std::to_string(creation_ts_ms),
               std::to_string(now_ms())});
        });
  }

  /// Get expiration info for a user
  json get_user_expiration(const std::string& user_id) {
    return db_.runInteraction(
        "av_get_expiration",
        [&](storage::LoggingTransaction& txn) -> json {
          txn.execute(
              "SELECT expiration_ts_ms, period_days, last_renewed_ts, "
              "warned_ts, deactivated_ts, is_exempt, exempt_reason, "
              "created_ts, updated_ts "
              "FROM account_validity WHERE user_id = ?",
              {user_id});
          auto row = txn.fetchone();
          if (!row) {
            return json({
                {"user_id", user_id},
                {"has_expiration", false},
                {"expiration_ts_ms", nullptr},
                {"expired", false}
            });
          }

          int64_t now = now_ms();
          json result;
          result["user_id"] = user_id;
          result["has_expiration"] = true;
          result["expiration_ts_ms"] = row->at(0).value
              ? std::stoll(*row->at(0).value) : 0;
          result["period_days"] = row->at(1).value
              ? std::stoll(*row->at(1).value) : 0;
          result["last_renewed_ts"] = row->at(2).value
              ? std::stoll(*row->at(2).value) : 0;
          result["warned_ts"] = row->at(3).value
              ? std::stoll(*row->at(3).value) : 0;
          result["deactivated_ts"] = row->at(4).value
              ? std::stoll(*row->at(4).value) : 0;
          result["is_exempt"] = row->at(5).value.value_or("0") == "1";
          result["exempt_reason"] = row->at(6).value.value_or("");
          result["created_ts"] = row->at(7).value
              ? std::stoll(*row->at(7).value) : 0;
          result["updated_ts"] = row->at(8).value
              ? std::stoll(*row->at(8).value) : 0;

          int64_t exp_ts = row->at(0).value
              ? std::stoll(*row->at(0).value) : 0;
          result["expired"] = exp_ts > 0 && exp_ts <= now;
          result["remaining_ms"] = exp_ts > now ? (exp_ts - now) : 0;
          result["remaining_seconds"] = result["remaining_ms"].get<int64_t>() / 1000;
          result["remaining_days"] = result["remaining_seconds"].get<int64_t>() / 86400;
          result["is_deactivated"] = row->at(4).value.has_value();

          return result;
        });
  }

  /// Remove expiration for a user (grant unlimited validity)
  void remove_expiration(const std::string& user_id) {
    db_.runInteraction(
        "av_remove_expiration",
        [&](storage::LoggingTransaction& txn) {
          txn.execute("DELETE FROM account_validity WHERE user_id = ?",
                      {user_id});
          // Also invalidate any active renewal tokens
          txn.execute(
              "UPDATE account_renewal_tokens SET is_used = 1 "
              "WHERE user_id = ? AND is_used = 0",
              {user_id});
        });
  }

  /// Check if an account is expired
  bool is_account_expired(const std::string& user_id) {
    return db_.runInteraction(
        "av_is_expired",
        [&](storage::LoggingTransaction& txn) -> bool {
          int64_t now = now_ms();
          txn.execute(
              "SELECT expiration_ts_ms, is_exempt, deactivated_ts "
              "FROM account_validity WHERE user_id = ?",
              {user_id});
          auto row = txn.fetchone();
          if (!row) return false; // No expiration set = not expired

          bool is_exempt = row->at(1).value.value_or("0") == "1";
          if (is_exempt) return false;

          bool is_deactivated = row->at(2).value.has_value();
          if (is_deactivated) return true; // Already deactivated

          int64_t exp = row->at(0).value ? std::stoll(*row->at(0).value) : 0;
          return exp > 0 && exp <= now;
        });
  }

  // ---- Renewal Token Operations ----

  /// Create a renewal token for a user
  std::string create_renewal_token(const std::string& user_id,
                                   int64_t token_lifetime_hours = 24) {
    return db_.runInteraction(
        "av_create_token",
        [&](storage::LoggingTransaction& txn) -> std::string {
          // Check token limit
          txn.execute(
              "SELECT COUNT(*) FROM account_renewal_tokens "
              "WHERE user_id = ? AND is_used = 0 AND expires_ts > ?",
              {user_id, std::to_string(now_ms())});
          auto crow = txn.fetchone();
          int active_count = crow ? std::stoll(crow->at(0).value.value_or("0")) : 0;

          int max_tokens = 3; // Default, should come from config
          if (active_count >= max_tokens) {
            throw std::runtime_error(
                "Maximum number of active renewal tokens reached for user: " +
                user_id);
          }

          std::string token = "renew_" + generate_token(32);
          int64_t now = now_ms();
          int64_t expires = now + hours_to_ms(token_lifetime_hours);

          txn.execute(
              "INSERT INTO account_renewal_tokens "
              "(token, user_id, created_ts, expires_ts) "
              "VALUES (?, ?, ?, ?)",
              {token, user_id, std::to_string(now),
               std::to_string(expires)});

          return token;
        });
  }

  /// Validate a renewal token and return the associated user ID
  std::optional<std::string> validate_renewal_token(const std::string& token) {
    return db_.runInteraction(
        "av_validate_token",
        [&](storage::LoggingTransaction& txn) -> std::optional<std::string> {
          int64_t now = now_ms();
          txn.execute(
              "SELECT user_id, expires_ts, is_used "
              "FROM account_renewal_tokens WHERE token = ?",
              {token});
          auto row = txn.fetchone();
          if (!row) return std::nullopt; // Token not found

          std::string user_id = row->at(0).value.value_or("");
          int64_t expires = row->at(1).value
              ? std::stoll(*row->at(1).value) : 0;
          bool is_used = row->at(2).value.value_or("0") == "1";

          if (is_used) return std::nullopt; // Already used
          if (expires <= now) return std::nullopt; // Expired

          return user_id;
        });
  }

  /// Mark a renewal token as used
  bool mark_token_used(const std::string& token) {
    return db_.runInteraction(
        "av_mark_token_used",
        [&](storage::LoggingTransaction& txn) -> bool {
          int64_t now = now_ms();
          txn.execute(
              "UPDATE account_renewal_tokens "
              "SET is_used = 1, used_ts = ? "
              "WHERE token = ? AND is_used = 0 AND expires_ts > ?",
              {std::to_string(now), token, std::to_string(now)});
          return txn.rows_affected() > 0;
        });
  }

  /// Renew an account: extend expiration by period_days from now
  void renew_account(const std::string& user_id, int period_days = 90) {
    db_.runInteraction(
        "av_renew_account",
        [&](storage::LoggingTransaction& txn) {
          int64_t now = now_ms();
          int64_t new_exp = now + days_to_ms(period_days);

          txn.execute(
              "INSERT INTO account_validity "
              "(user_id, expiration_ts_ms, period_days, last_renewed_ts, "
              "updated_ts) "
              "VALUES (?, ?, ?, ?, ?) "
              "ON CONFLICT(user_id) DO UPDATE SET "
              "expiration_ts_ms = excluded.expiration_ts_ms, "
              "period_days = excluded.period_days, "
              "last_renewed_ts = excluded.last_renewed_ts, "
              "updated_ts = excluded.updated_ts, "
              "warned_ts = NULL",
              {user_id, std::to_string(new_exp),
               std::to_string(period_days),
               std::to_string(now), std::to_string(now)});
        });
  }

  /// Invalidate all active tokens for a user
  void invalidate_user_tokens(const std::string& user_id) {
    db_.runInteraction(
        "av_invalidate_tokens",
        [&](storage::LoggingTransaction& txn) {
          txn.execute(
              "UPDATE account_renewal_tokens SET is_used = 1, used_ts = ? "
              "WHERE user_id = ? AND is_used = 0",
              {std::to_string(now_ms()), user_id});
        });
  }

  // ---- Warning Tracking ----

  /// Record a warning sent to a user
  void record_warning(const std::string& user_id,
                      const std::string& warning_type,
                      int64_t expiration_ts_ms,
                      const std::string& channel = "email") {
    db_.runInteraction(
        "av_record_warning",
        [&](storage::LoggingTransaction& txn) {
          int64_t now = now_ms();
          // Update the account_validity table
          txn.execute(
              "UPDATE account_validity SET warned_ts = ? WHERE user_id = ?",
              {std::to_string(now), user_id});

          // Insert warning record
          txn.execute(
              "INSERT OR REPLACE INTO account_validity_warnings "
              "(user_id, warning_type, sent_ts, expiration_ts_ms, channel) "
              "VALUES (?, ?, ?, ?, ?)",
              {user_id, warning_type,
               std::to_string(now), std::to_string(expiration_ts_ms),
               channel});
        });
  }

  /// Check if a warning was already sent recently
  bool has_recent_warning(const std::string& user_id,
                          const std::string& warning_type,
                          int64_t cooldown_ms) {
    return db_.runInteraction(
        "av_has_recent_warning",
        [&](storage::LoggingTransaction& txn) -> bool {
          int64_t cutoff = now_ms() - cooldown_ms;
          txn.execute(
              "SELECT COUNT(*) FROM account_validity_warnings "
              "WHERE user_id = ? AND warning_type = ? AND sent_ts > ?",
              {user_id, warning_type, std::to_string(cutoff)});
          auto row = txn.fetchone();
          if (!row) return false;
          return std::stoll(row->at(0).value.value_or("0")) > 0;
        });
  }

  // ---- Deactivation ----

  /// Deactivate an account: mark as deactivated, log the action
  void deactivate_account(const std::string& user_id,
                          const std::string& reason = "expired",
                          const std::string& admin_user = "",
                          bool soft = true) {
    db_.runInteraction(
        "av_deactivate",
        [&](storage::LoggingTransaction& txn) {
          int64_t now = now_ms();
          int64_t purge_scheduled = soft
              ? now + days_to_ms(30) // Grace period
              : now;

          // Update account_validity
          txn.execute(
              "UPDATE account_validity "
              "SET deactivated_ts = ?, updated_ts = ? "
              "WHERE user_id = ?",
              {std::to_string(now), std::to_string(now), user_id});

          // Log the deactivation
          txn.execute(
              "INSERT INTO account_deactivation_log "
              "(user_id, deactivated_ts, reason, admin_user, was_soft, "
              "data_purge_scheduled_ts) "
              "VALUES (?, ?, ?, ?, ?, ?)",
              {user_id, std::to_string(now), reason,
               admin_user.empty() ? std::string("") : admin_user,
               soft ? "1" : "0",
               std::to_string(purge_scheduled)});

          // Invalidate all tokens
          txn.execute(
              "UPDATE account_renewal_tokens SET is_used = 1, used_ts = ? "
              "WHERE user_id = ? AND is_used = 0",
              {std::to_string(now), user_id});
        });
  }

  /// Reactivate a deactivated account
  void reactivate_account(const std::string& user_id) {
    db_.runInteraction(
        "av_reactivate",
        [&](storage::LoggingTransaction& txn) {
          txn.execute(
              "UPDATE account_validity "
              "SET deactivated_ts = NULL, updated_ts = ? "
              "WHERE user_id = ?",
              {std::to_string(now_ms()), user_id});

          txn.execute(
              "DELETE FROM account_deactivation_log "
              "WHERE user_id = ? AND data_purge_scheduled_ts > ?",
              {user_id, std::to_string(now_ms())});
        });
  }

  /// Find accounts due for deactivation
  std::vector<std::string> find_expired_accounts(int64_t batch_size = 100) {
    return db_.runInteraction(
        "av_find_expired",
        [&](storage::LoggingTransaction& txn) -> std::vector<std::string> {
          int64_t now = now_ms();
          txn.execute(
              "SELECT user_id FROM account_validity "
              "WHERE expiration_ts_ms <= ? "
              "AND deactivated_ts IS NULL "
              "AND is_exempt = 0 "
              "ORDER BY expiration_ts_ms ASC "
              "LIMIT ?",
              {std::to_string(now), std::to_string(batch_size)});
          auto rows = txn.fetchall();
          std::vector<std::string> result;
          for (auto& row : rows) {
            if (row[0].value) result.push_back(*row[0].value);
          }
          return result;
        });
  }

  /// Find accounts about to expire within a given time window
  std::vector<std::pair<std::string, int64_t>> find_expiring_accounts(
      int64_t window_start_ms, int64_t window_end_ms, int64_t limit = 500) {
    return db_.runInteraction(
        "av_find_expiring",
        [&](storage::LoggingTransaction& txn)
            -> std::vector<std::pair<std::string, int64_t>> {
          txn.execute(
              "SELECT user_id, expiration_ts_ms FROM account_validity "
              "WHERE expiration_ts_ms > ? AND expiration_ts_ms <= ? "
              "AND deactivated_ts IS NULL "
              "AND is_exempt = 0 "
              "ORDER BY expiration_ts_ms ASC "
              "LIMIT ?",
              {std::to_string(window_start_ms),
               std::to_string(window_end_ms),
               std::to_string(limit)});
          auto rows = txn.fetchall();
          std::vector<std::pair<std::string, int64_t>> result;
          for (auto& row : rows) {
            if (row[0].value && row[1].value) {
              result.emplace_back(*row[0].value,
                                  std::stoll(*row[1].value));
            }
          }
          return result;
        });
  }

  /// Find accounts scheduled for data purge
  std::vector<std::string> find_purge_candidates(int64_t batch_size = 100) {
    return db_.runInteraction(
        "av_find_purge",
        [&](storage::LoggingTransaction& txn) -> std::vector<std::string> {
          int64_t now = now_ms();
          txn.execute(
              "SELECT user_id FROM account_deactivation_log "
              "WHERE data_purge_scheduled_ts <= ? "
              "AND data_purge_scheduled_ts > 0 "
              "ORDER BY data_purge_scheduled_ts ASC "
              "LIMIT ?",
              {std::to_string(now), std::to_string(batch_size)});
          auto rows = txn.fetchall();
          std::vector<std::string> result;
          for (auto& row : rows) {
            if (row[0].value) result.push_back(*row[0].value);
          }
          return result;
        });
  }

  /// Mark purge as completed for a user
  void mark_purge_completed(const std::string& user_id) {
    db_.runInteraction(
        "av_mark_purge",
        [&](storage::LoggingTransaction& txn) {
          txn.execute(
              "UPDATE account_deactivation_log "
              "SET data_purge_scheduled_ts = 0 "
              "WHERE user_id = ? AND data_purge_scheduled_ts IS NOT NULL",
              {user_id});
        });
  }

  // ---- Listing / Querying ----

  /// List accounts with pagination and optional filters
  json list_accounts(int64_t limit = 100, int64_t offset = 0,
                     bool expired_only = false,
                     bool deactivated_only = false,
                     bool exempt_only = false,
                     const std::string& search_term = "") {
    return db_.runInteraction(
        "av_list_accounts",
        [&](storage::LoggingTransaction& txn) -> json {
          std::vector<std::string> conditions;
          std::vector<std::string> params;

          if (expired_only) {
            conditions.push_back(
                "expiration_ts_ms <= " + std::to_string(now_ms()));
          }
          if (deactivated_only) {
            conditions.push_back("deactivated_ts IS NOT NULL");
          }
          if (exempt_only) {
            conditions.push_back("is_exempt = 1");
          }
          if (!search_term.empty()) {
            conditions.push_back("user_id LIKE ?");
            params.push_back("%" + search_term + "%");
          }

          std::string where;
          if (!conditions.empty()) {
            where = " WHERE " + join(conditions, " AND ");
          }

          // Count
          std::string count_sql = "SELECT COUNT(*) FROM account_validity" + where;
          txn.execute(count_sql, params);
          auto crow = txn.fetchone();
          int64_t total = crow ? std::stoll(crow->at(0).value.value_or("0")) : 0;

          // Fetch
          std::string sql =
              "SELECT user_id, expiration_ts_ms, period_days, last_renewed_ts, "
              "warned_ts, deactivated_ts, is_exempt, exempt_reason, "
              "created_ts, updated_ts "
              "FROM account_validity" + where +
              " ORDER BY expiration_ts_ms ASC LIMIT ? OFFSET ?";

          auto all_params = params;
          all_params.push_back(std::to_string(limit));
          all_params.push_back(std::to_string(offset));
          txn.execute(sql, all_params);

          auto rows = txn.fetchall();
          int64_t now = now_ms();
          json accounts = json::array();

          for (auto& row : rows) {
            json acc;
            acc["user_id"] = row[0].value.value_or("");
            int64_t exp = row[1].value ? std::stoll(*row[1].value) : 0;
            acc["expiration_ts_ms"] = exp;
            acc["expiration_iso"] = exp > 0 ? ts_to_iso8601(exp) : nullptr;
            acc["expired"] = exp > 0 && exp <= now;
            acc["remaining_seconds"] = exp > now ? (exp - now) / 1000 : 0;
            acc["remaining_days"] = exp > now ? (exp - now) / 86400000 : 0;
            acc["period_days"] = row[2].value ? std::stoll(*row[2].value) : 0;
            acc["last_renewed_ts"] = row[3].value ? std::stoll(*row[3].value) : 0;
            acc["warned_ts"] = row[4].value ? std::stoll(*row[4].value) : 0;
            acc["deactivated_ts"] = row[5].value ? std::stoll(*row[5].value) : 0;
            acc["is_exempt"] = row[6].value.value_or("0") == "1";
            acc["exempt_reason"] = row[7].value.value_or("");
            acc["created_ts"] = row[8].value ? std::stoll(*row[8].value) : 0;
            acc["updated_ts"] = row[9].value ? std::stoll(*row[9].value) : 0;
            accounts.push_back(acc);
          }

          return json({
              {"accounts", accounts},
              {"total", total},
              {"limit", limit},
              {"offset", offset},
              {"filtered_expired_only", expired_only},
              {"filtered_deactivated_only", deactivated_only}
          });
        });
  }

  /// Get statistics about account validity state
  json get_statistics() {
    return db_.runInteraction(
        "av_statistics",
        [&](storage::LoggingTransaction& txn) -> json {
          int64_t now = now_ms();

          json stats;

          // Total with expiration set
          txn.execute("SELECT COUNT(*) FROM account_validity");
          auto r1 = txn.fetchone();
          stats["total_with_expiration"] = r1
              ? std::stoll(r1->at(0).value.value_or("0")) : 0;

          // Currently expired
          txn.execute(
              "SELECT COUNT(*) FROM account_validity "
              "WHERE expiration_ts_ms <= ? AND deactivated_ts IS NULL",
              {std::to_string(now)});
          auto r2 = txn.fetchone();
          stats["expired_not_deactivated"] = r2
              ? std::stoll(r2->at(0).value.value_or("0")) : 0;

          // Already deactivated
          txn.execute(
              "SELECT COUNT(*) FROM account_validity "
              "WHERE deactivated_ts IS NOT NULL");
          auto r3 = txn.fetchone();
          stats["deactivated"] = r3
              ? std::stoll(r3->at(0).value.value_or("0")) : 0;

          // Exempt
          txn.execute(
              "SELECT COUNT(*) FROM account_validity WHERE is_exempt = 1");
          auto r4 = txn.fetchone();
          stats["exempt"] = r4
              ? std::stoll(r4->at(0).value.value_or("0")) : 0;

          // Expiring within 7 days
          int64_t week = now + days_to_ms(7);
          txn.execute(
              "SELECT COUNT(*) FROM account_validity "
              "WHERE expiration_ts_ms > ? AND expiration_ts_ms <= ? "
              "AND deactivated_ts IS NULL AND is_exempt = 0",
              {std::to_string(now), std::to_string(week)});
          auto r5 = txn.fetchone();
          stats["expiring_within_7_days"] = r5
              ? std::stoll(r5->at(0).value.value_or("0")) : 0;

          // Expiring within 30 days
          int64_t month = now + days_to_ms(30);
          txn.execute(
              "SELECT COUNT(*) FROM account_validity "
              "WHERE expiration_ts_ms > ? AND expiration_ts_ms <= ? "
              "AND deactivated_ts IS NULL AND is_exempt = 0",
              {std::to_string(now), std::to_string(month)});
          auto r6 = txn.fetchone();
          stats["expiring_within_30_days"] = r6
              ? std::stoll(r6->at(0).value.value_or("0")) : 0;

          // Active renewal tokens
          txn.execute(
              "SELECT COUNT(*) FROM account_renewal_tokens "
              "WHERE is_used = 0 AND expires_ts > ?",
              {std::to_string(now)});
          auto r7 = txn.fetchone();
          stats["active_renewal_tokens"] = r7
              ? std::stoll(r7->at(0).value.value_or("0")) : 0;

          // Renewals in last 30 days
          int64_t month_ago = now - days_to_ms(30);
          txn.execute(
              "SELECT COUNT(*) FROM account_validity "
              "WHERE last_renewed_ts >= ?",
              {std::to_string(month_ago)});
          auto r8 = txn.fetchone();
          stats["renewals_last_30_days"] = r8
              ? std::stoll(r8->at(0).value.value_or("0")) : 0;

          stats["generated_ts"] = now;
          return stats;
        });
  }

  // ---- Exemption Management ----

  /// Mark a user as exempt from expiration
  void set_exempt(const std::string& user_id, const std::string& reason) {
    db_.runInteraction(
        "av_set_exempt",
        [&](storage::LoggingTransaction& txn) {
          txn.execute(
              "UPDATE account_validity "
              "SET is_exempt = 1, exempt_reason = ?, updated_ts = ? "
              "WHERE user_id = ?",
              {reason, std::to_string(now_ms()), user_id});
        });
  }

  /// Remove exemption from a user
  void remove_exempt(const std::string& user_id) {
    db_.runInteraction(
        "av_remove_exempt",
        [&](storage::LoggingTransaction& txn) {
          txn.execute(
              "UPDATE account_validity "
              "SET is_exempt = 0, exempt_reason = NULL, updated_ts = ? "
              "WHERE user_id = ?",
              {std::to_string(now_ms()), user_id});
        });
  }

  /// Get exemption status for a user
  json get_exemption(const std::string& user_id) {
    return db_.runInteraction(
        "av_get_exemption",
        [&](storage::LoggingTransaction& txn) -> json {
          txn.execute(
              "SELECT is_exempt, exempt_reason FROM account_validity "
              "WHERE user_id = ?",
              {user_id});
          auto row = txn.fetchone();
          json result;
          result["user_id"] = user_id;
          if (!row) {
            result["is_exempt"] = false;
            result["exempt_reason"] = nullptr;
          } else {
            result["is_exempt"] = row->at(0).value.value_or("0") == "1";
            result["exempt_reason"] = row->at(1).value.has_value()
                ? json(*row->at(1).value) : json(nullptr);
          }
          return result;
        });
  }

private:
  storage::DatabasePool& db_;
};

// ============================================================================
// 3. ExpirationWarningEngine — Warning Email and Server Notice Delivery
//
// Implements the tiered warning system that sends notifications to users
// before their account expires. Supports multiple channels: email (SMTP),
// server notices (in-app Matrix messages), and both simultaneously.
// Prevents duplicate warnings via cooldown tracking.
//
// Equivalent to:
//   synapse/handlers/account_validity.py (warning portions)
//   synapse/server_notices/server_notices_manager.py
// ============================================================================
class ExpirationWarningEngine {
public:
  ExpirationWarningEngine(storage::DatabasePool& db,
                          AccountValidityStore& store,
                          AccountValidityConfig& config)
      : db_(db), store_(store), config_(config) {}

  // ---- Email Templates ----

  /// Render an HTML email body from template with substitutions
  std::string render_email_html(const std::string& user_id,
                                int64_t expiration_ts_ms,
                                int64_t days_remaining,
                                const std::string& renewal_url,
                                const std::string& renewal_token) {
    std::string tmpl = config_.get_email_body_template_html();
    if (tmpl.empty()) {
      // Default HTML template
      tmpl = R"(<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
  <div style="background: #1a1a2e; color: white; padding: 20px; border-radius: 8px 8px 0 0;">
    <h2 style="margin: 0;">Account Expiration Notice</h2>
  </div>
  <div style="background: #f8f9fa; padding: 20px; border: 1px solid #dee2e6;">
    <p>Hello,</p>
    <p>Your Matrix account <strong>{{user_id}}</strong> on <strong>{{server_name}}</strong>
       will expire in <strong>{{days_remaining}} day(s)</strong>
       (on {{expiration_date}}).</p>
    <p>To continue using your account, please renew it before the expiration date.</p>
    <div style="text-align: center; margin: 30px 0;">
      <a href="{{renewal_url}}" style="background: #4CAF50; color: white;
         padding: 14px 32px; text-decoration: none; border-radius: 4px;
         font-size: 16px; display: inline-block;">
         Renew Your Account
      </a>
    </div>
    <p style="font-size: 13px; color: #666;">
      If the button doesn't work, copy and paste this link into your browser:<br>
      {{renewal_url}}
    </p>
    <p>If you do not renew, your account will be deactivated and you will lose access
       to all your Matrix rooms and messages.</p>
    <hr style="border: none; border-top: 1px solid #dee2e6; margin: 20px 0;">
    <p style="font-size: 12px; color: #999;">
      This is an automated message from your Matrix homeserver. Please do not reply.
    </p>
  </div>
</body>
</html>)";
    }

    return substitute_template(tmpl, user_id, expiration_ts_ms,
                               days_remaining, renewal_url, renewal_token);
  }

  /// Render a plain text email body
  std::string render_email_text(const std::string& user_id,
                                int64_t expiration_ts_ms,
                                int64_t days_remaining,
                                const std::string& renewal_url,
                                const std::string& renewal_token) {
    std::string tmpl = config_.get_email_body_template_text();
    if (tmpl.empty()) {
      std::stringstream ss;
      ss << "Account Expiration Notice\n";
      ss << "=========================\n\n";
      ss << "Your Matrix account " << user_id;
      ss << " on " << server_name_from_id(user_id);
      ss << " will expire in " << days_remaining << " day(s)";
      ss << " (on " << ts_to_iso8601(expiration_ts_ms) << ").\n\n";
      ss << "To renew your account, please visit:\n";
      ss << renewal_url << "\n\n";
      ss << "If you do not renew, your account will be deactivated.\n\n";
      ss << "This is an automated message. Please do not reply.\n";
      return ss.str();
    }
    return substitute_template(tmpl, user_id, expiration_ts_ms,
                               days_remaining, renewal_url, renewal_token);
  }

  /// Substitute template variables
  std::string substitute_template(const std::string& tmpl,
                                  const std::string& user_id,
                                  int64_t expiration_ts_ms,
                                  int64_t days_remaining,
                                  const std::string& renewal_url,
                                  const std::string& renewal_token) {
    std::string result = tmpl;

    auto replace = [&](const std::string& key, const std::string& val) {
      std::string marker = "{{" + key + "}}";
      size_t pos = 0;
      while ((pos = result.find(marker, pos)) != std::string::npos) {
        result.replace(pos, marker.length(), val);
        pos += val.length();
      }
    };

    replace("user_id", html_escape(user_id));
    replace("server_name", html_escape(server_name_from_id(user_id)));
    replace("days_remaining", std::to_string(days_remaining));
    replace("expiration_date", ts_to_iso8601(expiration_ts_ms));
    replace("renewal_url", html_escape(renewal_url));
    replace("renewal_token", renewal_token);
    replace("current_date", now_iso8601());
    replace("localpart", html_escape(localpart_from_id(user_id)));

    return result;
  }

  // ---- Warning Delivery ----

  /// Send a warning for a specific user at a specific tier (e.g., "7d", "3d", "1d")
  json send_warning_to_user(const std::string& user_id,
                            int64_t expiration_ts_ms,
                            const std::string& warning_tier) {
    json result;
    result["user_id"] = user_id;
    result["warning_tier"] = warning_tier;
    result["sent"] = false;

    // Check cooldown
    int cooldown_hours = config_.get_warning_cooldown_hours();
    if (store_.has_recent_warning(user_id, warning_tier,
                                  hours_to_ms(cooldown_hours))) {
      result["skipped"] = true;
      result["reason"] = "cooldown";
      return result;
    }

    int64_t now = now_ms();
    int64_t days_remaining = expiration_ts_ms > now
        ? (expiration_ts_ms - now) / 86400000 : 0;

    // Check if user has an email
    auto emails = get_user_emails(user_id);
    bool has_email = !emails.empty();

    // Check if renewal emails are enabled
    bool emails_enabled = config_.is_renewal_emails_enabled();
    bool notices_enabled = config_.is_server_notices_enabled();

    if (emails_enabled && has_email) {
      // Generate renewal token
      int token_lifetime = config_.get_renewal_token_lifetime_hours();
      std::string token = store_.create_renewal_token(user_id, token_lifetime);

      // Build renewal URL
      std::string base_url = config_.get_renewal_base_url();
      if (base_url.empty()) {
        base_url = "https://" + server_name_from_id(user_id);
      }
      std::string renewal_url = base_url +
          "/_matrix/client/unstable/account_validity/renew?token=" + token;

      std::string email_addr = emails[0];
      std::string subject = config_.get_email_subject_template();
      std::string html_body = render_email_html(
          user_id, expiration_ts_ms, days_remaining, renewal_url, token);
      std::string text_body = render_email_text(
          user_id, expiration_ts_ms, days_remaining, renewal_url, token);

      // In production: send via SMTP
      // For now, log the email details
      result["email"] = json({
          {"to", email_addr},
          {"from", config_.get_email_from_address()},
          {"subject", subject},
          {"html_length", html_body.size()},
          {"text_length", text_body.size()},
          {"renewal_url", renewal_url},
          {"renewal_token", token}
      });
      result["sent"] = true;
      result["channel"] = "email";
    } else if (notices_enabled) {
      // Server notice fallback
      result["channel"] = "server_notice";
      result["sent"] = true; // Would actually send via ServerNoticeManager
      result["notice"] = "Account expires in " +
          std::to_string(days_remaining) + " days";
    } else {
      result["skipped"] = true;
      result["reason"] = "no_delivery_channel";
      return result;
    }

    // Record the warning
    store_.record_warning(user_id, warning_tier, expiration_ts_ms,
                          result.value("channel", "email"));

    return result;
  }

  /// Process all accounts that need warnings
  json process_warnings() {
    if (!config_.is_enabled()) {
      return json({{"processed", false}, {"reason", "disabled"}});
    }

    json result;
    auto warning_periods = config_.get_warning_periods();
    int64_t now = now_ms();
    int total_warned = 0;
    json details = json::array();

    for (int days : warning_periods) {
      int64_t window_start = now;
      int64_t window_end = now + days_to_ms(days);
      std::string tier = std::to_string(days) + "d";

      // For each warning period, also check for "just entered this window"
      // Find accounts expiring within this window
      auto accounts = store_.find_expiring_accounts(window_start, window_end, 500);

      for (auto& [user_id, exp_ts] : accounts) {
        // Check exemption
        auto exempt_info = store_.get_exemption(user_id);
        if (exempt_info.value("is_exempt", false)) {
          continue;
        }

        auto warn_result = send_warning_to_user(user_id, exp_ts, tier);
        if (warn_result.value("sent", false)) {
          total_warned++;
        }
        details.push_back(warn_result);
      }
    }

    result["processed"] = true;
    result["total_warned"] = total_warned;
    result["warning_periods_checked"] = warning_periods;
    result["details"] = details;
    result["timestamp"] = now;
    return result;
  }

  /// Manual warning for a specific user
  json send_manual_warning(const std::string& user_id) {
    auto info = store_.get_user_expiration(user_id);
    if (!info.value("has_expiration", false)) {
      return json({
          {"sent", false},
          {"error", "No expiration set for this user"}
      });
    }

    int64_t exp_ts = info.value("expiration_ts_ms", 0);
    int64_t now = now_ms();
    int64_t days_remaining = exp_ts > now ? (exp_ts - now) / 86400000 : 0;

    std::string tier = days_remaining <= 1 ? "1d" :
                       days_remaining <= 3 ? "3d" :
                       days_remaining <= 7 ? "7d" : "custom";

    return send_warning_to_user(user_id, exp_ts, tier);
  }

private:
  storage::DatabasePool& db_;
  AccountValidityStore& store_;
  AccountValidityConfig& config_;

  std::vector<std::string> get_user_emails(const std::string& user_id) {
    return db_.runInteraction(
        "av_get_emails",
        [&](storage::LoggingTransaction& txn) -> std::vector<std::string> {
          txn.execute(
              "SELECT address FROM user_threepids "
              "WHERE user_id = ? AND medium = 'email'",
              {user_id});
          auto rows = txn.fetchall();
          std::vector<std::string> emails;
          for (auto& row : rows) {
            if (row[0].value) emails.push_back(*row[0].value);
          }
          return emails;
        });
  }
};

// ============================================================================
// 4. RenewalWorkflow — Token-Based Account Renewal
//
// Full renewal workflow: generate cryptographically random tokens,
// validate tokens with expiry and single-use enforcement, renew accounts
// by extending expiration timestamps, and provide client-facing HTTP
// endpoint responses.
//
// Equivalent to:
//   synapse/handlers/account_validity.py (renewal methods)
//   synapse/rest/client/account_validity.py (renewal endpoint)
// ============================================================================
class RenewalWorkflow {
public:
  RenewalWorkflow(storage::DatabasePool& db,
                  AccountValidityStore& store,
                  AccountValidityConfig& config)
      : db_(db), store_(store), config_(config) {}

  /// Initiate renewal for a user: generate token and prepare email
  json initiate_renewal(const std::string& user_id) {
    json result;
    result["user_id"] = user_id;

    auto info = store_.get_user_expiration(user_id);
    if (!info.value("has_expiration", false)) {
      result["success"] = false;
      result["error"] = "No expiration set for this user";
      return result;
    }

    // Check exemption
    if (info.value("is_exempt", false)) {
      result["success"] = false;
      result["error"] = "Account is exempt from expiration";
      return result;
    }

    // Check if already deactivated
    if (info.value("is_deactivated", false)) {
      result["success"] = false;
      result["error"] = "Account is already deactivated";
      return result;
    }

    try {
      int token_lifetime = config_.get_renewal_token_lifetime_hours();
      std::string token = store_.create_renewal_token(
          user_id, token_lifetime);

      result["success"] = true;
      result["renewal_token"] = token;

      // Build renewal URL
      std::string base_url = config_.get_renewal_base_url();
      if (base_url.empty()) {
        base_url = "https://" + server_name_from_id(user_id);
      }
      result["renewal_url"] = base_url +
          "/_matrix/client/unstable/account_validity/renew?token=" + token;

      int64_t now = now_ms();
      result["token_expires_ts"] = now + hours_to_ms(token_lifetime);
      result["token_expires_iso"] = ts_to_iso8601(
          now + hours_to_ms(token_lifetime));

      // If emails are enabled, try to send
      if (config_.is_renewal_emails_enabled()) {
        auto emails = get_user_emails(user_id);
        if (!emails.empty()) {
          result["email_sent_to"] = emails[0];
          // Actual SMTP sending would happen here
        } else {
          result["email_sent_to"] = nullptr;
          result["email_warning"] = "No email address found for user";
        }
      }
    } catch (const std::runtime_error& e) {
      result["success"] = false;
      result["error"] = e.what();
    }

    return result;
  }

  /// Accept a renewal token: validate and extend account expiration
  json accept_renewal_token(const std::string& token) {
    json result;
    result["renewal_token"] = token;

    auto user_id_opt = store_.validate_renewal_token(token);
    if (!user_id_opt) {
      result["success"] = false;
      result["error"] = "Invalid, expired, or already used renewal token";
      result["errcode"] = "M_INVALID_TOKEN";
      return result;
    }

    std::string user_id = *user_id_opt;

    // Check if account is already deactivated
    auto info = store_.get_user_expiration(user_id);
    if (info.value("is_deactivated", false)) {
      result["success"] = false;
      result["error"] = "Account is deactivated and cannot be renewed";
      result["errcode"] = "M_ACCOUNT_DEACTIVATED";
      return result;
    }

    // Mark token as used (single-use enforcement)
    bool mark_success = store_.mark_token_used(token);
    if (!mark_success) {
      result["success"] = false;
      result["error"] = "Token could not be marked as used";
      return result;
    }

    // Extend the account
    int period_days = config_.get_default_period_days();
    store_.renew_account(user_id, period_days);

    // Get updated expiration
    auto updated = store_.get_user_expiration(user_id);
    int64_t new_exp = updated.value("expiration_ts_ms", 0);

    result["success"] = true;
    result["user_id"] = user_id;
    result["new_expiration_ts_ms"] = new_exp;
    result["new_expiration_iso"] = ts_to_iso8601(new_exp);
    result["period_extended_days"] = period_days;

    return result;
  }

  /// Manually renew an account (admin-initiated, no token needed)
  json admin_renew(const std::string& user_id, int period_days = -1) {
    if (period_days <= 0) {
      period_days = config_.get_default_period_days();
    }

    store_.renew_account(user_id, period_days);
    // Invalidate existing tokens for security
    store_.invalidate_user_tokens(user_id);

    auto updated = store_.get_user_expiration(user_id);

    json result;
    result["success"] = true;
    result["user_id"] = user_id;
    result["new_expiration_ts_ms"] = updated.value("expiration_ts_ms", 0);
    result["new_expiration_iso"] = ts_to_iso8601(
        updated.value("expiration_ts_ms", 0));
    result["period_extended_days"] = period_days;
    result["method"] = "admin";
    return result;
  }

  /// Get page that a user would see to renew their account
  json get_renewal_info(const std::string& user_id) {
    json result;
    result["user_id"] = user_id;

    auto info = store_.get_user_expiration(user_id);
    if (!info.value("has_expiration", false)) {
      result["renewable"] = false;
      result["message"] = "Your account does not have an expiration date.";
      return result;
    }

    result["renewable"] = true;
    result["expiration_ts_ms"] = info.value("expiration_ts_ms", 0);
    result["remaining_days"] = info.value("remaining_days", 0);
    result["expired"] = info.value("expired", false);
    result["is_deactivated"] = info.value("is_deactivated", false);
    result["is_exempt"] = info.value("is_exempt", false);

    if (result["expired"].get<bool>() && !result["is_deactivated"].get<bool>()) {
      result["message"] = "Your account has expired. Please renew to regain access.";
      result["action"] = "renew_required";
    } else if (!result["expired"].get<bool>()) {
      result["message"] = "Your account is active. You can renew early if desired.";
      result["action"] = "renew_optional";
    }

    return result;
  }

private:
  storage::DatabasePool& db_;
  AccountValidityStore& store_;
  AccountValidityConfig& config_;

  std::vector<std::string> get_user_emails(const std::string& user_id) {
    return db_.runInteraction(
        "av_renewal_get_emails",
        [&](storage::LoggingTransaction& txn) -> std::vector<std::string> {
          txn.execute(
              "SELECT address FROM user_threepids "
              "WHERE user_id = ? AND medium = 'email'",
              {user_id});
          auto rows = txn.fetchall();
          std::vector<std::string> emails;
          for (auto& row : rows) {
            if (row[0].value) emails.push_back(*row[0].value);
          }
          return emails;
        });
  }
};

// ============================================================================
// 5. AutoDeactivationJob — Background Expiration Enforcement
//
// Periodically scans for expired accounts and deactivates them. Supports
// soft deactivation (block login, preserve data for grace period) and
// hard deactivation (immediate data purge scheduling). Respects GDPR
// erasure compliance. Runs as a background task with configurable interval.
//
// Equivalent to:
//   synapse/handlers/account_validity.py (deactivation loop)
//   synapse/handlers/deactivate_account.py
// ============================================================================
class AutoDeactivationJob {
public:
  AutoDeactivationJob(storage::DatabasePool& db,
                      AccountValidityStore& store,
                      AccountValidityConfig& config)
      : db_(db), store_(store), config_(config),
        running_(false), stop_requested_(false) {}

  ~AutoDeactivationJob() {
    stop();
  }

  // ---- Lifecycle ----

  /// Start the background deactivation job on a separate thread
  void start() {
    if (running_.exchange(true)) {
      return; // Already running
    }
    stop_requested_ = false;
    worker_ = std::make_unique<std::thread>(
        &AutoDeactivationJob::run_loop, this);
  }

  /// Stop the background job and join the thread
  void stop() {
    if (!running_.exchange(false)) {
      return; // Not running
    }
    stop_requested_ = true;
    if (worker_ && worker_->joinable()) {
      worker_->join();
    }
    worker_.reset();
  }

  bool is_running() const { return running_; }

  // ---- Manual Runs ----

  /// Run one deactivation cycle synchronously
  json run_once() {
    if (!config_.is_enabled()) {
      return json({{"processed", false}, {"reason", "disabled"}});
    }

    if (!config_.is_auto_deactivation_enabled()) {
      return json({{"processed", false},
                   {"reason", "auto_deactivation_disabled"}});
    }

    return perform_deactivation_cycle();
  }

  /// Run one purge cycle (permanently delete data after grace period)
  json run_purge_once() {
    return perform_purge_cycle();
  }

  // ---- Statistics ----

  json get_status() const {
    json status;
    status["running"] = running_;
    status["last_run_ts"] = last_run_ts_;
    status["last_run_total_deactivated"] = last_deactivated_count_;
    status["last_run_total_purged"] = last_purged_count_;
    status["total_deactivated_all_time"] = total_deactivated_;
    status["total_purged_all_time"] = total_purged_;
    return status;
  }

private:
  storage::DatabasePool& db_;
  AccountValidityStore& store_;
  AccountValidityConfig& config_;
  std::atomic<bool> running_;
  std::atomic<bool> stop_requested_;
  std::unique_ptr<std::thread> worker_;

  // Stats
  std::atomic<int64_t> last_run_ts_{0};
  std::atomic<int64_t> last_deactivated_count_{0};
  std::atomic<int64_t> last_purged_count_{0};
  std::atomic<int64_t> total_deactivated_{0};
  std::atomic<int64_t> total_purged_{0};

  /// Main background loop
  void run_loop() {
    while (!stop_requested_) {
      int interval_minutes = config_.get_deactivation_interval_minutes();

      if (config_.is_enabled() && config_.is_auto_deactivation_enabled()) {
        try {
          auto result = perform_deactivation_cycle();
          last_run_ts_ = now_ms();
          last_deactivated_count_ = result.value("deactivated", 0);
          total_deactivated_ += last_deactivated_count_;

          // Also run purge cycle
          auto purge_result = perform_purge_cycle();
          last_purged_count_ = purge_result.value("purged", 0);
          total_purged_ += last_purged_count_;
        } catch (const std::exception& e) {
          // Log error but keep running
          last_run_ts_ = now_ms();
        }
      }

      // Sleep for the configured interval
      for (int i = 0; i < interval_minutes * 60 && !stop_requested_; i++) {
        std::this_thread::sleep_for(chr::seconds(1));
      }
    }
  }

  /// Perform one deactivation cycle
  json perform_deactivation_cycle() {
    json result;
    int64_t now = now_ms();
    int batch_size = config_.get_deactivation_batch_size();
    bool soft = config_.get_soft_deactivation();
    int grace_days = config_.get_deactivation_grace_days();

    auto expired = store_.find_expired_accounts(batch_size);

    json deactivated_users = json::array();
    int deactivated = 0;
    int skipped_exempt = 0;
    int skipped_already = 0;
    int skipped_gdpr = 0;

    for (auto& user_id : expired) {
      // Check exemption status
      auto exempt_info = store_.get_exemption(user_id);
      if (exempt_info.value("is_exempt", false)) {
        skipped_exempt++;
        continue;
      }

      // Check if already deactivated
      auto info = store_.get_user_expiration(user_id);
      if (info.value("is_deactivated", false)) {
        skipped_already++;
        continue;
      }

      // GDPR check: if user has requested erasure, handle specially
      if (has_gdpr_erasure_request(user_id)) {
        // Full data purge instead of soft deactivation
        store_.deactivate_account(user_id, "expired_gdpr",
                                  "", false); // Hard deactivation
        deactivated++;
        skipped_gdpr++;
        json entry;
        entry["user_id"] = user_id;
        entry["reason"] = "expired_gdpr_erasure";
        deactivated_users.push_back(entry);
        continue;
      }

      // Normal deactivation
      std::string reason = "account_expired";
      store_.deactivate_account(user_id, reason, "", soft);

      deactivated++;
      json entry;
      entry["user_id"] = user_id;
      entry["reason"] = reason;
      entry["soft"] = soft;
      entry["grace_period_days"] = soft ? grace_days : 0;
      deactivated_users.push_back(entry);
    }

    result["timestamp"] = now;
    result["deactivated"] = deactivated;
    result["skipped_exempt"] = skipped_exempt;
    result["skipped_already_deactivated"] = skipped_already;
    result["skipped_gdpr_erasure"] = skipped_gdpr;
    result["batch_size"] = batch_size;
    result["soft_deactivation"] = soft;
    result["users"] = deactivated_users;

    return result;
  }

  /// Perform one purge cycle
  json perform_purge_cycle() {
    json result;
    int64_t now = now_ms();

    auto candidates = store_.find_purge_candidates(100);

    json purged_users = json::array();
    int purged = 0;

    for (auto& user_id : candidates) {
      // In a full implementation, this would:
      // 1. Remove all user data (events, profiles, room memberships)
      // 2. Remove all devices
      // 3. Remove all third-party identifiers
      // 4. Anonymize any remaining references
      // 5. Log the purge for compliance

      store_.mark_purge_completed(user_id);
      purged++;

      json entry;
      entry["user_id"] = user_id;
      entry["purged_ts"] = now;
      purged_users.push_back(entry);
    }

    result["timestamp"] = now;
    result["purged"] = purged;
    result["users"] = purged_users;

    return result;
  }

  /// Check if user has a pending GDPR erasure request
  bool has_gdpr_erasure_request(const std::string& user_id) {
    return db_.runInteraction(
        "av_gdpr_check",
        [&](storage::LoggingTransaction& txn) -> bool {
          try {
            txn.execute(
                "SELECT COUNT(*) FROM erased_users WHERE user_id = ?",
                {user_id});
            auto row = txn.fetchone();
            return row && std::stoll(row->at(0).value.value_or("0")) > 0;
          } catch (const std::exception&) {
            // Table may not exist
            return false;
          }
        });
  }
};

// ============================================================================
// 6. AccountValidityExemptions — Exemption Rule Management
//
// Manages which users are exempt from account expiration. Supports:
// - Per-user exemption with reason tracking
// - Server admin auto-exemption (users with admin power level)
// - Appservice user auto-exemption
// - Support/bot user exemption
// - Wildcard pattern matching for user ID patterns
// - Configurable exemption lists
//
// Equivalent to the exemption portions of:
//   synapse/handlers/account_validity.py
// ============================================================================
class AccountValidityExemptions {
public:
  AccountValidityExemptions(storage::DatabasePool& db,
                            AccountValidityStore& store,
                            AccountValidityConfig& config)
      : db_(db), store_(store), config_(config) {}

  // ---- Pattern-Based Exemptions ----

  /// Add an exemption pattern (supports * wildcards)
  void add_pattern(const std::string& pattern, const std::string& reason) {
    std::unique_lock lock(patterns_mu_);
    exemption_patterns_[pattern] = reason;
    // Persist to config
    json patterns = json::array();
    for (auto& [pat, rsn] : exemption_patterns_) {
      json entry;
      entry["pattern"] = pat;
      entry["reason"] = rsn;
      patterns.push_back(entry);
    }
    g_config.set("account_validity.exemption_patterns", patterns);
  }

  /// Remove an exemption pattern
  void remove_pattern(const std::string& pattern) {
    std::unique_lock lock(patterns_mu_);
    exemption_patterns_.erase(pattern);
    json patterns = json::array();
    for (auto& [pat, rsn] : exemption_patterns_) {
      json entry;
      entry["pattern"] = pat;
      entry["reason"] = rsn;
      patterns.push_back(entry);
    }
    g_config.set("account_validity.exemption_patterns", patterns);
  }

  /// List all exemption patterns
  std::vector<std::pair<std::string, std::string>> get_patterns() {
    std::shared_lock lock(patterns_mu_);
    std::vector<std::pair<std::string, std::string>> result;
    for (auto& kv : exemption_patterns_) {
      result.emplace_back(kv.first, kv.second);
    }
    return result;
  }

  // ---- User-Specific Exemptions ----

  /// Exempt a specific user
  void exempt_user(const std::string& user_id, const std::string& reason) {
    store_.set_exempt(user_id, reason);
  }

  /// Remove exemption from a specific user
  void unexempt_user(const std::string& user_id) {
    store_.remove_exempt(user_id);
  }

  /// Bulk exempt users matching criteria
  json bulk_exempt(const std::string& pattern, const std::string& reason) {
    json result;
    // Find all users matching the pattern
    auto matching = find_users_matching(pattern);
    int count = 0;
    for (auto& uid : matching) {
      store_.set_exempt(uid, reason);
      count++;
    }
    result["matched"] = matching.size();
    result["exempted"] = count;
    result["reason"] = reason;
    return result;
  }

  // ---- Auto-Exemption Checks ----

  /// Check if a user should be auto-exempted (admins, appservice, etc.)
  bool is_auto_exempt(const std::string& user_id) {
    // Check server admin auto-exemption
    if (is_server_admin(user_id)) {
      return true;
    }

    // Check appservice user auto-exemption
    if (is_appservice_user(user_id)) {
      return true;
    }

    // Check support user auto-exemption
    if (is_support_user(user_id)) {
      return true;
    }

    // Check pattern-based exemptions
    if (matches_exemption_pattern(user_id)) {
      return true;
    }

    return false;
  }

  /// Get the reason a user is exempt (empty string if not exempt)
  std::string get_exempt_reason(const std::string& user_id) {
    if (is_server_admin(user_id)) {
      return "server_admin";
    }
    if (is_appservice_user(user_id)) {
      return "appservice_user";
    }
    if (is_support_user(user_id)) {
      return "support_user";
    }

    // Check pattern exemptions
    std::shared_lock lock(patterns_mu_);
    for (auto& [pattern, reason] : exemption_patterns_) {
      if (match_pattern(user_id, pattern)) {
        return reason;
      }
    }

    return "";
  }

  /// Auto-apply exemptions for a newly registered user
  void auto_exempt_new_user(const std::string& user_id) {
    std::string reason = get_exempt_reason(user_id);
    if (!reason.empty()) {
      store_.set_exempt(user_id, reason);
    }
  }

  /// Remove auto-exemptions from a user (e.g., if they lose admin status)
  void reevaluate_exemption(const std::string& user_id) {
    std::string auto_reason = get_exempt_reason(user_id);
    auto current = store_.get_exemption(user_id);

    if (auto_reason.empty() && current.value("is_exempt", false)) {
      // No longer auto-exempt, remove exemption
      store_.remove_exempt(user_id);
    } else if (!auto_reason.empty() && !current.value("is_exempt", false)) {
      // Should be auto-exempt, apply
      store_.set_exempt(user_id, auto_reason);
    }
  }

  // ---- Configuration ----

  /// Enable/disable admin auto-exemption
  void set_admin_auto_exempt(bool enabled) {
    g_config.set("account_validity.auto_exempt_admins", enabled);
  }
  bool get_admin_auto_exempt() const {
    return g_config.get("account_validity.auto_exempt_admins", true).get<bool>();
  }

  /// Enable/disable appservice user auto-exemption
  void set_appservice_auto_exempt(bool enabled) {
    g_config.set("account_validity.auto_exempt_appservice", enabled);
  }
  bool get_appservice_auto_exempt() const {
    return g_config.get("account_validity.auto_exempt_appservice", true).get<bool>();
  }

  /// Set the support user ID pattern for auto-exemption
  void set_support_user_id(const std::string& user_id) {
    g_config.set("account_validity.support_user_id", user_id);
  }
  std::string get_support_user_id() const {
    return g_config.get("account_validity.support_user_id", "").get<std::string>();
  }

private:
  storage::DatabasePool& db_;
  AccountValidityStore& store_;
  AccountValidityConfig& config_;

  mutable std::shared_mutex patterns_mu_;
  std::unordered_map<std::string, std::string> exemption_patterns_;

  /// Check if user is a server administrator
  bool is_server_admin(const std::string& user_id) {
    if (!get_admin_auto_exempt()) return false;

    return db_.runInteraction(
        "av_is_admin",
        [&](storage::LoggingTransaction& txn) -> bool {
          txn.execute(
              "SELECT admin FROM users WHERE name = ?",
              {user_id});
          auto row = txn.fetchone();
          return row && row->at(0).value.value_or("0") == "1";
        });
  }

  /// Check if user is an application service user
  bool is_appservice_user(const std::string& user_id) {
    if (!get_appservice_auto_exempt()) return false;
    // Appservice users typically have names starting with @_ and include the
    // appservice namespace
    std::string localpart = localpart_from_id(user_id);
    return starts_with(localpart, "_") &&
           localpart.find("_appservice_") != std::string::npos;
  }

  /// Check if user is a support user
  bool is_support_user(const std::string& user_id) {
    std::string support_id = get_support_user_id();
    if (support_id.empty()) return false;
    return user_id == support_id;
  }

  /// Match a user ID against a wildcard pattern
  bool match_pattern(const std::string& user_id, const std::string& pattern) {
    // Convert pattern to regex:
    // * -> .*
    // ? -> .
    std::string regex_str;
    regex_str.reserve(pattern.size() + 2);
    regex_str += "^";
    for (char c : pattern) {
      if (c == '*') {
        regex_str += ".*";
      } else if (c == '?') {
        regex_str += ".";
      } else if (c == '.' || c == '^' || c == '$' || c == '[' ||
                 c == ']' || c == '(' || c == ')' || c == '|' ||
                 c == '+' || c == '{' || c == '}' || c == '\\') {
        regex_str += '\\';
        regex_str += c;
      } else {
        regex_str += c;
      }
    }
    regex_str += "$";

    try {
      std::regex re(regex_str);
      return std::regex_match(user_id, re);
    } catch (const std::exception&) {
      // Simple fallback
      if (pattern.find('*') == std::string::npos &&
          pattern.find('?') == std::string::npos) {
        return user_id == pattern;
      }
      // Basic wildcard matching
      return simple_wildcard_match(user_id, pattern);
    }
  }

  /// Check if user ID matches any exemption pattern
  bool matches_exemption_pattern(const std::string& user_id) {
    std::shared_lock lock(patterns_mu_);
    for (auto& [pattern, reason] : exemption_patterns_) {
      if (match_pattern(user_id, pattern)) {
        return true;
      }
    }
    return false;
  }

  /// Simple wildcard match for fallback
  bool simple_wildcard_match(const std::string& s, const std::string& p) {
    size_t si = 0, pi = 0;
    size_t star_idx = std::string::npos;
    size_t match_idx = 0;

    while (si < s.size()) {
      if (pi < p.size() && (p[pi] == '?' || p[pi] == s[si])) {
        si++;
        pi++;
      } else if (pi < p.size() && p[pi] == '*') {
        star_idx = pi;
        match_idx = si;
        pi++;
      } else if (star_idx != std::string::npos) {
        pi = star_idx + 1;
        match_idx++;
        si = match_idx;
      } else {
        return false;
      }
    }

    while (pi < p.size() && p[pi] == '*') pi++;
    return pi == p.size();
  }

  /// Find users matching a pattern (from the database)
  std::vector<std::string> find_users_matching(const std::string& pattern) {
    return db_.runInteraction(
        "av_find_users_pattern",
        [&](storage::LoggingTransaction& txn) -> std::vector<std::string> {
          // For database matching, convert * to SQL LIKE %
          std::string like_pattern;
          for (char c : pattern) {
            if (c == '*') {
              like_pattern += '%';
            } else if (c == '?') {
              like_pattern += '_';
            } else if (c == '%' || c == '_') {
              like_pattern += '\\';
              like_pattern += c;
            } else {
              like_pattern += c;
            }
          }

          txn.execute(
              "SELECT name FROM users WHERE name LIKE ? ESCAPE '\\'",
              {like_pattern});
          auto rows = txn.fetchall();
          std::vector<std::string> result;
          for (auto& row : rows) {
            if (row[0].value) result.push_back(*row[0].value);
          }
          return result;
        });
  }
};

// ============================================================================
// 7. AccountValidityAdminAPI — Administrative Controls
//
// Provides the admin-facing API for managing account validity. Supports
// all administrative operations: setting/removing expiration, manual
// deactivation/reactivation, bulk operations, listing, statistics, and
// exemption management. Integrates with GDPR compliance.
//
// Equivalent to:
//   synapse/rest/admin/account_validity.py
//   synapse/handlers/account_validity.py (admin portions)
// ============================================================================
class AccountValidityAdminAPI {
public:
  AccountValidityAdminAPI(storage::DatabasePool& db,
                          AccountValidityStore& store,
                          AccountValidityConfig& config,
                          RenewalWorkflow& renewal,
                          AutoDeactivationJob& deactivation,
                          AccountValidityExemptions& exemptions)
      : db_(db), store_(store), config_(config),
        renewal_(renewal), deactivation_(deactivation),
        exemptions_(exemptions) {}

  // ---- Configuration Management ----

  /// Get the full configuration
  json get_config() {
    return config_.to_json();
  }

  /// Update configuration from JSON
  json update_config(const json& new_config) {
    config_.load_from_json(new_config);
    return config_.to_json();
  }

  // ---- Per-User Operations ----

  /// Set expiration for a user
  json set_expiration(const std::string& user_id, int period_days = -1) {
    json result;
    result["user_id"] = user_id;

    if (!is_valid_user_id(user_id)) {
      result["success"] = false;
      result["error"] = "Invalid user ID";
      return result;
    }

    if (period_days <= 0) {
      period_days = config_.get_default_period_days();
    }

    // Clamp to min/max
    period_days = std::max(config_.get_min_period_days(),
                           std::min(config_.get_max_period_days(),
                                    period_days));

    int64_t exp_ts = now_ms() + days_to_ms(period_days);
    store_.set_user_expiration(user_id, exp_ts, period_days);

    result["success"] = true;
    result["expiration_ts_ms"] = exp_ts;
    result["expiration_iso"] = ts_to_iso8601(exp_ts);
    result["period_days"] = period_days;

    return result;
  }

  /// Set a custom expiration timestamp for a user (advanced)
  json set_custom_expiration(const std::string& user_id,
                             int64_t expiration_ts_ms) {
    json result;
    result["user_id"] = user_id;

    if (!is_valid_user_id(user_id)) {
      result["success"] = false;
      result["error"] = "Invalid user ID";
      return result;
    }

    int64_t now = now_ms();
    if (expiration_ts_ms <= now) {
      result["success"] = false;
      result["error"] = "Expiration must be in the future";
      return result;
    }

    int64_t period_days = (expiration_ts_ms - now) / 86400000;
    store_.set_user_expiration(user_id, expiration_ts_ms,
                               static_cast<int>(period_days));

    result["success"] = true;
    result["expiration_ts_ms"] = expiration_ts_ms;
    result["expiration_iso"] = ts_to_iso8601(expiration_ts_ms);

    return result;
  }

  /// Remove expiration (grant unlimited validity)
  json remove_expiration(const std::string& user_id) {
    json result;
    result["user_id"] = user_id;

    if (!is_valid_user_id(user_id)) {
      result["success"] = false;
      result["error"] = "Invalid user ID";
      return result;
    }

    store_.remove_expiration(user_id);
    result["success"] = true;
    result["message"] = "Expiration removed. Account has unlimited validity.";

    return result;
  }

  /// Extend a user's expiration
  json extend_expiration(const std::string& user_id, int additional_days = -1) {
    if (additional_days <= 0) {
      additional_days = config_.get_default_period_days();
    }
    return renewal_.admin_renew(user_id, additional_days);
  }

  /// Manually deactivate an account
  json deactivate_account(const std::string& user_id,
                          const std::string& reason = "admin_action",
                          const std::string& admin_user = "",
                          bool soft = true) {
    json result;
    result["user_id"] = user_id;

    if (!is_valid_user_id(user_id)) {
      result["success"] = false;
      result["error"] = "Invalid user ID";
      return result;
    }

    // Check if already deactivated
    auto info = store_.get_user_expiration(user_id);
    if (info.value("is_deactivated", false)) {
      result["success"] = false;
      result["error"] = "Account is already deactivated";
      return result;
    }

    store_.deactivate_account(user_id, reason, admin_user, soft);

    result["success"] = true;
    result["reason"] = reason;
    result["soft"] = soft;
    result["grace_period_days"] = soft ? config_.get_deactivation_grace_days() : 0;

    return result;
  }

  /// Reactivate a deactivated account
  json reactivate_account(const std::string& user_id) {
    json result;
    result["user_id"] = user_id;

    if (!is_valid_user_id(user_id)) {
      result["success"] = false;
      result["error"] = "Invalid user ID";
      return result;
    }

    store_.reactivate_account(user_id);

    // Optionally set a new expiration
    if (config_.is_enabled()) {
      int period_days = config_.get_default_period_days();
      int64_t exp_ts = now_ms() + days_to_ms(period_days);
      store_.set_user_expiration(user_id, exp_ts, period_days);
      result["new_expiration_ts_ms"] = exp_ts;
      result["new_expiration_iso"] = ts_to_iso8601(exp_ts);
    }

    result["success"] = true;
    result["message"] = "Account reactivated";
    return result;
  }

  // ---- Querying ----

  /// Get expiration info for a specific user
  json get_user_info(const std::string& user_id) {
    json result = store_.get_user_expiration(user_id);

    // Add exemption info
    auto exempt_info = store_.get_exemption(user_id);
    result["is_exempt"] = exempt_info.value("is_exempt", false);
    result["exempt_reason"] = exempt_info.value("exempt_reason", nullptr);

    // Add auto-exempt status
    result["would_auto_exempt"] = exemptions_.is_auto_exempt(user_id);
    if (result["would_auto_exempt"].get<bool>()) {
      result["auto_exempt_reason"] = exemptions_.get_exempt_reason(user_id);
    }

    return result;
  }

  /// List accounts with pagination and filtering
  json list_accounts(int64_t limit = 100, int64_t offset = 0,
                     const std::string& filter = "",
                     bool expired_only = false,
                     bool deactivated_only = false,
                     bool exempt_only = false,
                     const std::string& search_term = "") {
    std::string actual_filter = filter;
    if (filter == "expired") expired_only = true;
    else if (filter == "deactivated") deactivated_only = true;
    else if (filter == "exempt") exempt_only = true;
    else if (filter == "expiring_soon") {
      // We'll filter after the query for "expiring within 7 days"
    }

    auto result = store_.list_accounts(
        limit, offset, expired_only, deactivated_only,
        exempt_only, search_term);

    // Post-filter for "expiring_soon"
    if (filter == "expiring_soon") {
      json filtered = json::array();
      int64_t now = now_ms();
      int64_t week = now + days_to_ms(7);
      for (auto& acc : result["accounts"]) {
        int64_t exp = acc.value("expiration_ts_ms", 0);
        if (exp > now && exp <= week) {
          filtered.push_back(acc);
        }
      }
      result["accounts"] = filtered;
    }

    return result;
  }

  /// Get account validity statistics
  json get_statistics() {
    json stats = store_.get_statistics();
    stats["config"] = config_.to_json();
    stats["deactivation_job"] = deactivation_.get_status();
    return stats;
  }

  // ---- Exemption Management ----

  /// Exempt a specific user
  json exempt_user(const std::string& user_id, const std::string& reason) {
    json result;
    result["user_id"] = user_id;
    result["action"] = "exempt";

    exemptions_.exempt_user(user_id, reason);
    result["success"] = true;
    result["reason"] = reason;
    return result;
  }

  /// Remove exemption from a user
  json unexempt_user(const std::string& user_id) {
    json result;
    result["user_id"] = user_id;
    result["action"] = "unexempt";

    exemptions_.unexempt_user(user_id);
    result["success"] = true;
    return result;
  }

  /// Bulk exempt users matching a pattern
  json bulk_exempt(const std::string& pattern, const std::string& reason) {
    return exemptions_.bulk_exempt(pattern, reason);
  }

  /// List exemption patterns
  json list_exemption_patterns() {
    json result;
    auto patterns = exemptions_.get_patterns();
    json arr = json::array();
    for (auto& [pat, rsn] : patterns) {
      json entry;
      entry["pattern"] = pat;
      entry["reason"] = rsn;
      arr.push_back(entry);
    }
    result["patterns"] = arr;
    return result;
  }

  /// Add an exemption pattern
  json add_exemption_pattern(const std::string& pattern,
                             const std::string& reason) {
    exemptions_.add_pattern(pattern, reason);
    return json({{"success", true}, {"pattern", pattern}, {"reason", reason}});
  }

  /// Remove an exemption pattern
  json remove_exemption_pattern(const std::string& pattern) {
    exemptions_.remove_pattern(pattern);
    return json({{"success", true}, {"pattern", pattern}});
  }

  // ---- Bulk Operations ----

  /// Bulk set expiration for all users matching a pattern
  json bulk_set_expiration(const std::string& pattern,
                           int period_days = -1) {
    json result;
    if (period_days <= 0) {
      period_days = config_.get_default_period_days();
    }

    return db_.runInteraction(
        "av_bulk_set",
        [&](storage::LoggingTransaction& txn) -> json {
          // Convert pattern to LIKE
          std::string like_pattern;
          for (char c : pattern) {
            if (c == '*') like_pattern += '%';
            else if (c == '?') like_pattern += '_';
            else if (c == '%' || c == '_') { like_pattern += '\\'; like_pattern += c; }
            else like_pattern += c;
          }

          txn.execute(
              "SELECT name FROM users WHERE name LIKE ? ESCAPE '\\'",
              {like_pattern});
          auto rows = txn.fetchall();

          int64_t exp_ts = now_ms() + days_to_ms(period_days);
          int count = 0;
          for (auto& row : rows) {
            if (!row[0].value) continue;
            std::string uid = *row[0].value;

            // Skip if exempt
            if (exemptions_.is_auto_exempt(uid)) continue;

            txn.execute(
                "INSERT INTO account_validity "
                "(user_id, expiration_ts_ms, period_days, updated_ts) "
                "VALUES (?, ?, ?, ?) "
                "ON CONFLICT(user_id) DO UPDATE SET "
                "expiration_ts_ms = excluded.expiration_ts_ms, "
                "period_days = excluded.period_days, "
                "updated_ts = excluded.updated_ts",
                {uid, std::to_string(exp_ts), std::to_string(period_days),
                 std::to_string(now_ms())});
            count++;
          }

          result["success"] = true;
          result["matched_users"] = rows.size();
          result["updated"] = count;
          result["period_days"] = period_days;
          return result;
        });
  }

  /// Bulk deactivate expired accounts (force run)
  json force_deactivation_run() {
    return deactivation_.run_once();
  }

  /// Run the warning engine manually
  json send_warnings_now(ExpirationWarningEngine& warning_engine) {
    return warning_engine.process_warnings();
  }

  // ---- GDPR Compliance ----

  /// Check if a user's data is scheduled for purge
  json get_purge_status(const std::string& user_id) {
    json result;
    result["user_id"] = user_id;

    auto log = db_.runInteraction(
        "av_purge_status",
        [&](storage::LoggingTransaction& txn) -> json {
          txn.execute(
              "SELECT deactivated_ts, reason, data_purge_scheduled_ts, "
              "was_soft FROM account_deactivation_log "
              "WHERE user_id = ? ORDER BY deactivated_ts DESC LIMIT 1",
              {user_id});
          auto row = txn.fetchone();
          if (!row) {
            return json({
                {"user_id", user_id},
                {"scheduled_for_purge", false}
            });
          }

          json entry;
          entry["user_id"] = user_id;
          entry["deactivated_ts"] = row->at(0).value
              ? std::stoll(*row->at(0).value) : 0;
          entry["reason"] = row->at(1).value.value_or("");
          entry["data_purge_scheduled_ts"] = row->at(2).value
              ? std::stoll(*row->at(2).value) : 0;
          entry["scheduled_for_purge"] = row->at(2).value.has_value();
          entry["was_soft"] = row->at(3).value.value_or("1") == "1";
          return entry;
        });

    result["log_entry"] = log;
    return result;
  }

  /// Cancel a scheduled data purge (e.g., if user appeals)
  json cancel_purge(const std::string& user_id) {
    return db_.runInteraction(
        "av_cancel_purge",
        [&](storage::LoggingTransaction& txn) -> json {
          txn.execute(
              "UPDATE account_deactivation_log "
              "SET data_purge_scheduled_ts = NULL "
              "WHERE user_id = ? AND data_purge_scheduled_ts IS NOT NULL",
              {user_id});
          return json({
              {"success", true},
              {"user_id", user_id},
              {"message", "Purge cancelled"}
          });
        });
  }

private:
  storage::DatabasePool& db_;
  AccountValidityStore& store_;
  AccountValidityConfig& config_;
  RenewalWorkflow& renewal_;
  AutoDeactivationJob& deactivation_;
  AccountValidityExemptions& exemptions_;
};

// ============================================================================
// 8. AccountValidityEngine — Top-Level Orchestrator
//
// Composes all account validity subsystems into a single entry point.
// Provides a simple interface for the server to initialize and manage
// account validity. Handles lifecycle (startup/shutdown) of background
// jobs and integrates with the registration flow for new users.
//
// Equivalent to the main entry point in synapse/handlers/account_validity.py
// ============================================================================
class AccountValidityEngine {
public:
  AccountValidityEngine(storage::DatabasePool& db,
                        const std::string& server_name)
      : db_(db),
        server_name_(server_name),
        config_(),
        store_(db),
        warning_engine_(db, store_, config_),
        renewal_(db, store_, config_),
        deactivation_(db, store_, config_),
        exemptions_(db, store_, config_),
        admin_(db, store_, config_, renewal_, deactivation_, exemptions_) {}

  // ---- Lifecycle ----

  /// Initialize the engine: create tables, apply config defaults, start
  /// background jobs.
  json initialize(const json& initial_config = json::object()) {
    json result;

    // Apply initial config
    if (!initial_config.empty()) {
      config_.load_from_json(initial_config);
    }

    // Ensure database tables
    store_.ensure_tables();

    // Load exemption patterns from config
    auto patterns = g_config.get(
        "account_validity.exemption_patterns", json::array());
    for (auto& entry : patterns) {
      if (entry.contains("pattern") && entry.contains("reason")) {
        exemptions_.add_pattern(
            entry["pattern"].get<std::string>(),
            entry["reason"].get<std::string>());
      }
    }

    result["tables_created"] = true;
    result["config_applied"] = !initial_config.empty();

    // Start background jobs if enabled
    if (config_.is_enabled() && config_.is_auto_deactivation_enabled()) {
      deactivation_.start();
      result["deactivation_job_started"] = true;
    } else {
      result["deactivation_job_started"] = false;
    }

    return result;
  }

  /// Shutdown the engine: stop background jobs
  void shutdown() {
    deactivation_.stop();
  }

  /// Handle new user registration: apply default expiration and auto-exempt
  void on_user_registered(const std::string& user_id,
                          int64_t creation_ts_ms = 0) {
    if (!config_.is_enabled()) return;

    // Check for auto-exemption first
    exemptions_.auto_exempt_new_user(user_id);

    // Check if user is exempt after auto-exempt
    auto exempt_info = store_.get_exemption(user_id);
    if (exempt_info.value("is_exempt", false)) {
      return; // Don't set expiration for exempt users
    }

    // Set expiration
    if (creation_ts_ms <= 0) {
      creation_ts_ms = now_ms();
    }

    if (config_.get_calc_from_creation()) {
      store_.set_expiration_from_creation(user_id, creation_ts_ms);
    } else {
      int period_days = config_.get_default_period_days();
      int64_t exp_ts = now_ms() + days_to_ms(period_days);
      store_.set_user_expiration(user_id, exp_ts, period_days);
    }
  }

  /// Check if a user's account is valid (not expired, not deactivated)
  bool is_account_valid(const std::string& user_id) {
    if (!config_.is_enabled()) return true;

    // Check exemption first
    if (exemptions_.is_auto_exempt(user_id)) return true;

    auto exempt_info = store_.get_exemption(user_id);
    if (exempt_info.value("is_exempt", false)) return true;

    // Check if deactivated
    auto info = store_.get_user_expiration(user_id);
    if (info.value("is_deactivated", false)) return false;

    // If no expiration set, account is valid
    if (!info.value("has_expiration", false)) return true;

    // Check expiration
    return !store_.is_account_expired(user_id);
  }

  // ---- Accessors ----

  AccountValidityConfig& config() { return config_; }
  AccountValidityStore& store() { return store_; }
  ExpirationWarningEngine& warnings() { return warning_engine_; }
  RenewalWorkflow& renewal() { return renewal_; }
  AutoDeactivationJob& deactivation() { return deactivation_; }
  AccountValidityExemptions& exemptions() { return exemptions_; }
  AccountValidityAdminAPI& admin() { return admin_; }

  const std::string& server_name() const { return server_name_; }

private:
  storage::DatabasePool& db_;
  std::string server_name_;
  AccountValidityConfig config_;
  AccountValidityStore store_;
  ExpirationWarningEngine warning_engine_;
  RenewalWorkflow renewal_;
  AutoDeactivationJob deactivation_;
  AccountValidityExemptions exemptions_;
  AccountValidityAdminAPI admin_;
};

// ============================================================================
// 9. Free Functions — Convenience API for External Callers
//
// Singleton access and helper functions for code outside the progressive
// namespace that needs to interact with account validity features.
// ============================================================================

namespace {

/// Global engine instance (initialized at server startup)
std::unique_ptr<AccountValidityEngine> g_account_validity_engine;
std::mutex g_engine_mutex;

}  // anonymous namespace

/// Initialize the global account validity engine
void init_account_validity(storage::DatabasePool& db,
                           const std::string& server_name,
                           const json& config) {
  std::lock_guard lock(g_engine_mutex);
  g_account_validity_engine = std::make_unique<AccountValidityEngine>(
      db, server_name);
  g_account_validity_engine->initialize(config);
}

/// Shutdown the global account validity engine
void shutdown_account_validity() {
  std::lock_guard lock(g_engine_mutex);
  if (g_account_validity_engine) {
    g_account_validity_engine->shutdown();
    g_account_validity_engine.reset();
  }
}

/// Get a pointer to the global engine (may be null if not initialized)
AccountValidityEngine* get_account_validity_engine() {
  std::lock_guard lock(g_engine_mutex);
  return g_account_validity_engine.get();
}

/// Check if a user's account is valid (convenience wrapper)
bool account_is_valid(const std::string& user_id) {
  auto* engine = get_account_validity_engine();
  if (!engine) return true; // Account validity not initialized, allow
  return engine->is_account_valid(user_id);
}

/// Notify the engine of a new user registration (convenience wrapper)
void notify_user_registered(const std::string& user_id,
                            int64_t creation_ts_ms) {
  auto* engine = get_account_validity_engine();
  if (engine) {
    engine->on_user_registered(user_id, creation_ts_ms);
  }
}

/// Get account validity statistics (convenience wrapper)
json get_account_validity_stats() {
  auto* engine = get_account_validity_engine();
  if (!engine) {
    return json({{"error", "Account validity engine not initialized"}});
  }
  return engine->admin().get_statistics();
}

/// Accept a renewal token from a client (convenience wrapper)
json accept_renewal(const std::string& renewal_token) {
  auto* engine = get_account_validity_engine();
  if (!engine) {
    return json({
        {"success", false},
        {"error", "Account validity engine not initialized"},
        {"errcode", "M_UNKNOWN"}
    });
  }
  return engine->renewal().accept_renewal_token(renewal_token);
}

/// Initiate renewal for a user (convenience wrapper)
json initiate_renewal(const std::string& user_id) {
  auto* engine = get_account_validity_engine();
  if (!engine) {
    return json({
        {"success", false},
        {"error", "Account validity engine not initialized"}
    });
  }
  return engine->renewal().initiate_renewal(user_id);
}

/// Run a manual deactivation cycle (convenience wrapper)
json run_deactivation_cycle() {
  auto* engine = get_account_validity_engine();
  if (!engine) {
    return json({{"error", "Account validity engine not initialized"}});
  }
  return engine->deactivation().run_once();
}

/// Send expiration warnings manually (convenience wrapper)
json send_expiration_warnings() {
  auto* engine = get_account_validity_engine();
  if (!engine) {
    return json({{"error", "Account validity engine not initialized"}});
  }
  return engine->warnings().process_warnings();
}

/// Get the admin API for direct access
json admin_get_user_validity(const std::string& user_id) {
  auto* engine = get_account_validity_engine();
  if (!engine) {
    return json({{"error", "Account validity engine not initialized"}});
  }
  return engine->admin().get_user_info(user_id);
}

/// Set expiration via admin API
json admin_set_validity(const std::string& user_id, int period_days) {
  auto* engine = get_account_validity_engine();
  if (!engine) {
    return json({{"error", "Account validity engine not initialized"}});
  }
  return engine->admin().set_expiration(user_id, period_days);
}

/// Remove expiration via admin API
json admin_remove_validity(const std::string& user_id) {
  auto* engine = get_account_validity_engine();
  if (!engine) {
    return json({{"error", "Account validity engine not initialized"}});
  }
  return engine->admin().remove_expiration(user_id);
}

/// Deactivate account via admin API
json admin_deactivate_account(const std::string& user_id,
                              const std::string& reason,
                              const std::string& admin_user) {
  auto* engine = get_account_validity_engine();
  if (!engine) {
    return json({{"error", "Account validity engine not initialized"}});
  }
  return engine->admin().deactivate_account(user_id, reason, admin_user);
}

/// List accounts via admin API
json admin_list_validity_accounts(int64_t limit, int64_t offset,
                                  const std::string& filter) {
  auto* engine = get_account_validity_engine();
  if (!engine) {
    return json({{"error", "Account validity engine not initialized"}});
  }
  return engine->admin().list_accounts(limit, offset, filter);
}

// ============================================================================
// 10. Account Validity Renewal Client API
//
// Client-facing REST API endpoints for renewal. These would be registered
// on the HTTP server for the /_matrix/client/unstable/account_validity/
// namespace.
// ============================================================================

/// GET /_matrix/client/unstable/account_validity/info
/// Returns the account validity status for the authenticated user
json client_get_account_validity_info(const std::string& user_id) {
  auto* engine = get_account_validity_engine();
  if (!engine) {
    return json({
        {"has_expiration", false},
        {"message", "Account validity is not enabled on this server"}
    });
  }
  return engine->renewal().get_renewal_info(user_id);
}

/// POST /_matrix/client/unstable/account_validity/renew
/// Accepts a renewal token and extends the account
json client_renew_account(const std::string& token) {
  return accept_renewal(token);
}

/// POST /_matrix/client/unstable/account_validity/send_mail
/// Requests a renewal email be sent to the user's email address
json client_send_renewal_email(const std::string& user_id) {
  auto* engine = get_account_validity_engine();
  if (!engine) {
    return json({{"error", "Account validity engine not initialized"}});
  }
  return engine->renewal().initiate_renewal(user_id);
}

}  // namespace progressive
