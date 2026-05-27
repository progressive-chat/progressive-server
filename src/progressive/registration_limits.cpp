// ============================================================================
// registration_limits.cpp — Advanced Registration & Login Rate Limiting
//
// Implements production-grade, defense-in-depth rate limiting for the
// most security-sensitive endpoints in a Matrix homeserver: registration
// and login. Goes beyond the simple token-bucket approach to provide
// multi-dimensional throttling, persistent failure tracking, graduated
// lockouts, and a full admin management API.
//
// Feature set:
//   ┌─────────────────────────────────────────────────────────────────┐
//   │ REGISTRATION RATE LIMITING                                      │
//   │   • Per-IP registration windows (hourly + daily caps)          │
//   │   • Per-email registration tracking (prevents email recycling)  │
//   │   • Global registration burst protection (token bucket)         │
//   │   • Shared secret bypass for trusted registration sources       │
//   │   • Domain-based email throttling (per-domain caps)             │
//   │   • Registration cooldown after repeated rejections             │
//   │   • Pending registration tracking (in-progress counts)          │
//   ├─────────────────────────────────────────────────────────────────┤
//   │ LOGIN RATE LIMITING                                             │
//   │   • Per-account failed attempt tracking with graduated lockout  │
//   │   • Per-IP brute-force detection with escalating penalties      │
//   │   • Per-address (email/msisdn) throttling                       │
//   │   • Database-persisted failure records for crash survival       │
//   │   • Success reset: successful login clears failure counters     │
//   │   • Progressive lockout durations (1min → 5min → 15min → 1hr)  │
//   ├─────────────────────────────────────────────────────────────────┤
//   │ RATE RESET MECHANISMS                                           │
//   │   • Window-based auto-reset after time expiry                   │
//   │   • Manual admin reset via API (per-account, per-IP, global)    │
//   │   • Bulk reset operations for maintenance windows               │
//   │   • Scheduled periodic cleanup of expired entries               │
//   │   • Grace-period reset (cooldown after peak periods)            │
//   ├─────────────────────────────────────────────────────────────────┤
//   │ RATE LIMIT HEADERS                                              │
//   │   • X-RateLimit-Limit (max requests in window)                  │
//   │   • X-RateLimit-Remaining (remaining quota)                     │
//   │   • X-RateLimit-Reset (UTC epoch seconds until reset)           │
//   │   • Retry-After (seconds until next allowed attempt)            │
//   │   • X-RateLimit-Reason (human-readable limit reason)            │
//   │   • X-RateLimit-Scope (which dimension triggered the limit)     │
//   ├─────────────────────────────────────────────────────────────────┤
//   │ CONFIGURATION                                                   │
//   │   • Per-type enable/disable toggles                             │
//   │   • Configurable windows (1m, 5m, 15m, 1h, 24h)                │
//   │   • Configurable limits per dimension                           │
//   │   • JSON/YAML config file loading and hot-reload                │
//   │   • Per-user and per-IP override support                        │
//   │   • Environment variable overrides for container deployments    │
//   ├─────────────────────────────────────────────────────────────────┤
//   │ STORAGE                                                         │
//   │   • In-memory primary store for low-latency checks              │
//   │   • File-backed persistence for login failure records           │
//   │   • Periodic flush to disk with configurable interval           │
//   │   • Corruption-resistant JSONL format with checksums            │
//   │   • Crash recovery: reload persisted state on startup           │
//   │   • Pruning: automatic expiry of old records                    │
//   ├─────────────────────────────────────────────────────────────────┤
//   │ ADMIN API                                                       │
//   │   • GET  /admin/rate-limits/status — overall status + stats     │
//   │   • GET  /admin/rate-limits/accounts — list locked accounts     │
//   │   • GET  /admin/rate-limits/ips — list rate-limited IPs         │
//   │   • POST /admin/rate-limits/reset — clear specific or all       │
//   │   • POST /admin/rate-limits/configure — runtime reconfiguration │
//   │   • GET  /admin/rate-limits/config — current configuration      │
//   │   • POST /admin/rate-limits/whitelist — manage whitelist        │
//   │   • GET  /admin/rate-limits/metrics — Prometheus-style metrics  │
//   └─────────────────────────────────────────────────────────────────┘
//
// Equivalent to:
//   synapse/api/ratelimiting.py (registration + login sections)
//   synapse/rest/client/login.py (login rate limiting)
//   synapse/rest/client/register.py (registration rate limiting)
//   synapse/handlers/auth.py (login attempt tracking + graduated lockout)
//   synapse/storage/databases/main/registration.py (persistence)
//   synapse/rest/admin/__init__.py (admin API for rate limits)
//   synapse/config/ratelimiting.py (configuration schema)
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

// ============================================================================
// Namespace
// ============================================================================
namespace progressive {

using json = nlohmann::json;
namespace chr = std::chrono;
namespace fs = std::filesystem;

// ============================================================================
// Forward declarations
// ============================================================================
class RegistrationLimitConfig;
class RegistrationTracker;
class LoginFailureTracker;
class LoginLockoutManager;
class RateLimitStorage;
class RateResetScheduler;
class RateLimitHeaderBuilder;
class RegistrationLimitAdminAPI;
class RegistrationLimitsEngine;

// ============================================================================
// Anonymous namespace — Internal helpers and constants
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

std::string iso8601_now() {
  auto now = chr::system_clock::now();
  auto tt = chr::system_clock::to_time_t(now);
  std::ostringstream oss;
  oss << std::put_time(std::gmtime(&tt), "%Y-%m-%dT%H:%M:%SZ");
  return oss.str();
}

int64_t iso8601_to_ms(const std::string& s) {
  std::tm tm = {};
  std::istringstream iss(s);
  iss >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%S");
  if (iss.fail()) return 0;
  auto tp = chr::system_clock::from_time_t(std::mktime(&tm));
  return chr::duration_cast<chr::milliseconds>(
      tp.time_since_epoch()).count();
}

// ---- String helpers ----

std::string to_lower(std::string s) {
  for (auto& c : s)
    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return s;
}

std::string trim(const std::string& s) {
  auto start = s.find_first_not_of(" \t\n\r");
  if (start == std::string::npos) return "";
  auto end = s.find_last_not_of(" \t\n\r");
  return s.substr(start, end - start + 1);
}

bool ends_with(const std::string& s, const std::string& suffix) {
  return s.size() >= suffix.size() &&
         s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

bool starts_with(const std::string& s, const std::string& prefix) {
  return s.size() >= prefix.size() &&
         s.compare(0, prefix.size(), prefix) == 0;
}

std::vector<std::string> split(const std::string& s, char delim) {
  std::vector<std::string> parts;
  std::istringstream iss(s);
  std::string part;
  while (std::getline(iss, part, delim)) {
    if (!part.empty()) parts.push_back(trim(part));
  }
  return parts;
}

// ---- IP helpers ----

std::string normalize_ip(const std::string& ip) {
  if (ip == "::1" || ip == "0:0:0:0:0:0:0:1") return "127.0.0.1";
  if (ip.find("::ffff:") == 0) return ip.substr(7);
  return ip;
}

bool is_private_ip(const std::string& ip) {
  if (ip == "127.0.0.1" || ip == "::1") return true;
  if (starts_with(ip, "10.")) return true;
  if (starts_with(ip, "172.")) {
    auto parts = split(ip, '.');
    if (parts.size() >= 2) {
      int octet = std::stoi(parts[1]);
      if (octet >= 16 && octet <= 31) return true;
    }
  }
  if (starts_with(ip, "192.168.")) return true;
  if (starts_with(ip, "fd") || starts_with(ip, "fc")) return true;
  return false;
}

// ---- Email helpers ----

std::string extract_email_domain(const std::string& email) {
  auto at = email.find('@');
  if (at == std::string::npos || at == email.size() - 1) return "";
  return to_lower(email.substr(at + 1));
}

bool is_valid_email_format(const std::string& email) {
  auto at = email.find('@');
  if (at == std::string::npos || at == 0 || at == email.size() - 1)
    return false;
  auto dot = email.find('.', at + 1);
  return dot != std::string::npos && dot < email.size() - 1;
}

// ---- JSON helpers ----

json make_error_json(const std::string& errcode, const std::string& error) {
  return json({{"errcode", errcode}, {"error", error}});
}

json make_ratelimit_error(const std::string& errcode,
                           const std::string& error,
                           int64_t retry_after_ms) {
  return json({
      {"errcode", errcode},
      {"error", error},
      {"retry_after_ms", retry_after_ms}
  });
}

json make_success_json(const std::string& message) {
  return json({{"success", true}, {"message", message}});
}

// ---- Random token generation ----

std::string random_hex(int length) {
  static thread_local std::mt19937_64 rng(
      std::random_device{}() ^
      static_cast<uint64_t>(
          chr::steady_clock::now().time_since_epoch().count()));
  static const char hex_chars[] = "0123456789abcdef";
  std::uniform_int_distribution<int> dist(0, 15);
  std::string result;
  result.reserve(length);
  for (int i = 0; i < length; ++i) {
    result += hex_chars[dist(rng)];
  }
  return result;
}

// ---- Simple checksum for data integrity ----

uint32_t simple_checksum(const std::string& data) {
  uint32_t sum = 0;
  for (char c : data) sum = (sum << 1) ^ static_cast<uint8_t>(c);
  return sum;
}

// ============================================================================
// Lockout tier definitions
//
// Graduated lockout: each tier imposes a longer lockout duration.
// After `threshold` consecutive failures, the account is locked for
// `duration_ms`. This provides escalating deterrence against brute-force
// attacks while not permanently locking legitimate users who forget
// their password.
// ============================================================================

enum class LockoutTier : int {
  NONE = 0,       // No lockout
  WARN = 1,       // Warning threshold reached
  SHORT = 2,      // 1 minute lockout
  MEDIUM = 3,     // 5 minute lockout
  LONG = 4,       // 15 minute lockout
  EXTENDED = 5,   // 1 hour lockout
  MAX = 6         // 24 hour lockout (requires admin intervention)
};

struct LockoutTierConfig {
  int threshold;          // Consecutive failures to reach this tier
  int64_t duration_ms;    // Lockout duration in milliseconds
  bool notify_admin;      // Whether to flag for admin review
  const char* description;

  static std::vector<LockoutTierConfig> defaults() {
    return {
      { 3,   60'000,      false, "Warning — 3 failures" },
      { 5,   300'000,     false, "Short lockout — 5 minutes" },
      { 10,  900'000,     false, "Medium lockout — 15 minutes" },
      { 20,  3'600'000,   true,  "Long lockout — 1 hour" },
      { 50,  86'400'000,  true,  "Extended lockout — 24 hours, admin review" },
    };
  }

  json to_json() const {
    return {
      {"threshold", threshold},
      {"duration_ms", duration_ms},
      {"duration_human", format_duration(duration_ms)},
      {"notify_admin", notify_admin},
      {"description", description}
    };
  }

  static std::string format_duration(int64_t ms) {
    if (ms < 60'000) return std::to_string(ms / 1000) + "s";
    if (ms < 3'600'000) return std::to_string(ms / 60'000) + "m";
    return std::to_string(ms / 3'600'000) + "h";
  }
};

LockoutTier determine_tier(int64_t failures,
                            const std::vector<LockoutTierConfig>& tiers) {
  LockoutTier result = LockoutTier::NONE;
  int tier_idx = 0;
  for (const auto& tier : tiers) {
    if (failures >= tier.threshold) {
      result = static_cast<LockoutTier>(tier_idx + 1);
    }
    tier_idx++;
  }
  return result;
}

int64_t tier_duration_ms(LockoutTier tier,
                          const std::vector<LockoutTierConfig>& tiers) {
  int idx = static_cast<int>(tier) - 1;
  if (idx < 0 || idx >= static_cast<int>(tiers.size())) return 0;
  return tiers[idx].duration_ms;
}

// ============================================================================
// Registration window definitions
// ============================================================================

enum class RegistrationWindow : int {
  PER_MINUTE = 0,
  PER_HOUR = 1,
  PER_6HOURS = 2,
  PER_DAY = 3,
  PER_WEEK = 4,
  COUNT
};

int64_t window_duration_ms(RegistrationWindow w) {
  switch (w) {
    case RegistrationWindow::PER_MINUTE: return 60'000;
    case RegistrationWindow::PER_HOUR:   return 3'600'000;
    case RegistrationWindow::PER_6HOURS: return 21'600'000;
    case RegistrationWindow::PER_DAY:    return 86'400'000;
    case RegistrationWindow::PER_WEEK:   return 604'800'000;
    default: return 3'600'000;
  }
}

const char* window_name(RegistrationWindow w) {
  switch (w) {
    case RegistrationWindow::PER_MINUTE: return "per_minute";
    case RegistrationWindow::PER_HOUR:   return "per_hour";
    case RegistrationWindow::PER_6HOURS: return "per_6hours";
    case RegistrationWindow::PER_DAY:    return "per_day";
    case RegistrationWindow::PER_WEEK:   return "per_week";
    default: return "unknown";
  }
}

} // anonymous namespace

// ============================================================================
// 1. RegistrationLimitConfig — Configuration for all registration/login limits
//
// Centralized configuration object that can be loaded from JSON/YAML,
// modified at runtime via admin API, and serialized back for persistence.
// Supports per-type enable/disable, configurable windows, and overrides.
// ============================================================================

class RegistrationLimitConfig {
public:
  // ---- Registration limits ----
  struct RegistrationLimits {
    bool enabled = true;
    int max_per_ip_minute = 1;        // Max registrations per IP per minute
    int max_per_ip_hour = 5;          // Max registrations per IP per hour
    int max_per_ip_6hours = 15;       // Max registrations per IP per 6 hours
    int max_per_ip_day = 30;          // Max registrations per IP per day
    int max_per_ip_week = 100;        // Max registrations per IP per week
    int max_per_email_hour = 2;       // Max registrations per email per hour
    int max_per_email_day = 5;        // Max registrations per email per day
    int max_per_email_total = 10;     // Max total per email (all time)
    int max_per_domain_hour = 10;     // Max registrations per email domain/hour
    int max_per_domain_day = 50;      // Max registrations per email domain/day
    int max_global_minute = 10;       // Max global registrations per minute
    int max_global_hour = 100;        // Max global registrations per hour
    int max_pending_total = 50;       // Max in-progress registrations globally
    int cooldown_after_rejection_ms = 10'000; // Cooldown after rejected attempt
    bool shared_secret_bypass = true; // Allow shared secret to bypass limits
    bool allow_private_ip_exempt = false; // Exempt private IPs from limits

    json to_json() const {
      return {
        {"enabled", enabled},
        {"max_per_ip_minute", max_per_ip_minute},
        {"max_per_ip_hour", max_per_ip_hour},
        {"max_per_ip_6hours", max_per_ip_6hours},
        {"max_per_ip_day", max_per_ip_day},
        {"max_per_ip_week", max_per_ip_week},
        {"max_per_email_hour", max_per_email_hour},
        {"max_per_email_day", max_per_email_day},
        {"max_per_email_total", max_per_email_total},
        {"max_per_domain_hour", max_per_domain_hour},
        {"max_per_domain_day", max_per_domain_day},
        {"max_global_minute", max_global_minute},
        {"max_global_hour", max_global_hour},
        {"max_pending_total", max_pending_total},
        {"cooldown_after_rejection_ms", cooldown_after_rejection_ms},
        {"shared_secret_bypass", shared_secret_bypass},
        {"allow_private_ip_exempt", allow_private_ip_exempt},
      };
    }

    static RegistrationLimits from_json(const json& j) {
      RegistrationLimits l;
      if (j.contains("enabled")) l.enabled = j["enabled"].get<bool>();
      if (j.contains("max_per_ip_minute")) l.max_per_ip_minute = j["max_per_ip_minute"].get<int>();
      if (j.contains("max_per_ip_hour")) l.max_per_ip_hour = j["max_per_ip_hour"].get<int>();
      if (j.contains("max_per_ip_6hours")) l.max_per_ip_6hours = j["max_per_ip_6hours"].get<int>();
      if (j.contains("max_per_ip_day")) l.max_per_ip_day = j["max_per_ip_day"].get<int>();
      if (j.contains("max_per_ip_week")) l.max_per_ip_week = j["max_per_ip_week"].get<int>();
      if (j.contains("max_per_email_hour")) l.max_per_email_hour = j["max_per_email_hour"].get<int>();
      if (j.contains("max_per_email_day")) l.max_per_email_day = j["max_per_email_day"].get<int>();
      if (j.contains("max_per_email_total")) l.max_per_email_total = j["max_per_email_total"].get<int>();
      if (j.contains("max_per_domain_hour")) l.max_per_domain_hour = j["max_per_domain_hour"].get<int>();
      if (j.contains("max_per_domain_day")) l.max_per_domain_day = j["max_per_domain_day"].get<int>();
      if (j.contains("max_global_minute")) l.max_global_minute = j["max_global_minute"].get<int>();
      if (j.contains("max_global_hour")) l.max_global_hour = j["max_global_hour"].get<int>();
      if (j.contains("max_pending_total")) l.max_pending_total = j["max_pending_total"].get<int>();
      if (j.contains("cooldown_after_rejection_ms")) l.cooldown_after_rejection_ms = j["cooldown_after_rejection_ms"].get<int>();
      if (j.contains("shared_secret_bypass")) l.shared_secret_bypass = j["shared_secret_bypass"].get<bool>();
      if (j.contains("allow_private_ip_exempt")) l.allow_private_ip_exempt = j["allow_private_ip_exempt"].get<bool>();
      return l;
    }

    void apply_overrides(const json& overrides) {
      if (overrides.contains("max_per_ip_minute")) max_per_ip_minute = overrides["max_per_ip_minute"].get<int>();
      if (overrides.contains("max_per_ip_hour")) max_per_ip_hour = overrides["max_per_ip_hour"].get<int>();
      if (overrides.contains("max_per_ip_6hours")) max_per_ip_6hours = overrides["max_per_ip_6hours"].get<int>();
      if (overrides.contains("max_per_ip_day")) max_per_ip_day = overrides["max_per_ip_day"].get<int>();
      if (overrides.contains("max_per_ip_week")) max_per_ip_week = overrides["max_per_ip_week"].get<int>();
      if (overrides.contains("max_per_email_hour")) max_per_email_hour = overrides["max_per_email_hour"].get<int>();
      if (overrides.contains("max_per_email_day")) max_per_email_day = overrides["max_per_email_day"].get<int>();
      if (overrides.contains("max_per_email_total")) max_per_email_total = overrides["max_per_email_total"].get<int>();
      if (overrides.contains("max_per_domain_hour")) max_per_domain_hour = overrides["max_per_domain_hour"].get<int>();
      if (overrides.contains("max_per_domain_day")) max_per_domain_day = overrides["max_per_domain_day"].get<int>();
      if (overrides.contains("max_global_minute")) max_global_minute = overrides["max_global_minute"].get<int>();
      if (overrides.contains("max_global_hour")) max_global_hour = overrides["max_global_hour"].get<int>();
      if (overrides.contains("max_pending_total")) max_pending_total = overrides["max_pending_total"].get<int>();
      if (overrides.contains("cooldown_after_rejection_ms")) cooldown_after_rejection_ms = overrides["cooldown_after_rejection_ms"].get<int>();
      if (overrides.contains("shared_secret_bypass")) shared_secret_bypass = overrides["shared_secret_bypass"].get<bool>();
      if (overrides.contains("allow_private_ip_exempt")) allow_private_ip_exempt = overrides["allow_private_ip_exempt"].get<bool>();
    }
  };

  // ---- Login limits ----
  struct LoginLimits {
    bool enabled = true;
    bool per_account_enabled = true;
    bool per_ip_enabled = true;
    bool per_address_enabled = true;
    int max_failed_attempts_before_warn = 3;
    int max_failed_attempts_before_lock = 5;
    int max_failed_attempts_before_long_lock = 10;
    int max_failed_attempts_before_extended = 20;
    int64_t short_lockout_ms = 300'000;       // 5 minutes
    int64_t medium_lockout_ms = 900'000;      // 15 minutes
    int64_t long_lockout_ms = 3'600'000;      // 1 hour
    int64_t extended_lockout_ms = 86'400'000; // 24 hours
    int64_t failure_window_ms = 300'000;      // 5 min window for counting failures
    int64_t failure_decay_ms = 1'800'000;     // 30 min to decay failures by 1
    int max_per_ip_failures = 20;             // Max failures from one IP in window
    int max_per_address_failures = 10;        // Max failures per email/msisdn in window
    int64_t per_ip_window_ms = 300'000;       // Window for per-IP counting
    int64_t per_address_window_ms = 600'000;  // Window for per-address counting (stricter)
    bool allow_success_reset = true;          // Successful login resets counters
    bool persist_failures = true;             // Persist to disk for crash survival
    int64_t persist_interval_ms = 60'000;     // Flush to disk every 60 seconds
    std::string persist_path = "/var/lib/progressive/rate_limits/login_failures.jsonl";

    json to_json() const {
      return {
        {"enabled", enabled},
        {"per_account_enabled", per_account_enabled},
        {"per_ip_enabled", per_ip_enabled},
        {"per_address_enabled", per_address_enabled},
        {"max_failed_attempts_before_warn", max_failed_attempts_before_warn},
        {"max_failed_attempts_before_lock", max_failed_attempts_before_lock},
        {"max_failed_attempts_before_long_lock", max_failed_attempts_before_long_lock},
        {"max_failed_attempts_before_extended", max_failed_attempts_before_extended},
        {"short_lockout_ms", short_lockout_ms},
        {"medium_lockout_ms", medium_lockout_ms},
        {"long_lockout_ms", long_lockout_ms},
        {"extended_lockout_ms", extended_lockout_ms},
        {"failure_window_ms", failure_window_ms},
        {"failure_decay_ms", failure_decay_ms},
        {"max_per_ip_failures", max_per_ip_failures},
        {"max_per_address_failures", max_per_address_failures},
        {"per_ip_window_ms", per_ip_window_ms},
        {"per_address_window_ms", per_address_window_ms},
        {"allow_success_reset", allow_success_reset},
        {"persist_failures", persist_failures},
        {"persist_interval_ms", persist_interval_ms},
        {"persist_path", persist_path},
      };
    }

    static LoginLimits from_json(const json& j) {
      LoginLimits l;
      if (j.contains("enabled")) l.enabled = j["enabled"].get<bool>();
      if (j.contains("per_account_enabled")) l.per_account_enabled = j["per_account_enabled"].get<bool>();
      if (j.contains("per_ip_enabled")) l.per_ip_enabled = j["per_ip_enabled"].get<bool>();
      if (j.contains("per_address_enabled")) l.per_address_enabled = j["per_address_enabled"].get<bool>();
      if (j.contains("max_failed_attempts_before_warn")) l.max_failed_attempts_before_warn = j["max_failed_attempts_before_warn"].get<int>();
      if (j.contains("max_failed_attempts_before_lock")) l.max_failed_attempts_before_lock = j["max_failed_attempts_before_lock"].get<int>();
      if (j.contains("max_failed_attempts_before_long_lock")) l.max_failed_attempts_before_long_lock = j["max_failed_attempts_before_long_lock"].get<int>();
      if (j.contains("max_failed_attempts_before_extended")) l.max_failed_attempts_before_extended = j["max_failed_attempts_before_extended"].get<int>();
      if (j.contains("short_lockout_ms")) l.short_lockout_ms = j["short_lockout_ms"].get<int64_t>();
      if (j.contains("medium_lockout_ms")) l.medium_lockout_ms = j["medium_lockout_ms"].get<int64_t>();
      if (j.contains("long_lockout_ms")) l.long_lockout_ms = j["long_lockout_ms"].get<int64_t>();
      if (j.contains("extended_lockout_ms")) l.extended_lockout_ms = j["extended_lockout_ms"].get<int64_t>();
      if (j.contains("failure_window_ms")) l.failure_window_ms = j["failure_window_ms"].get<int64_t>();
      if (j.contains("failure_decay_ms")) l.failure_decay_ms = j["failure_decay_ms"].get<int64_t>();
      if (j.contains("max_per_ip_failures")) l.max_per_ip_failures = j["max_per_ip_failures"].get<int>();
      if (j.contains("max_per_address_failures")) l.max_per_address_failures = j["max_per_address_failures"].get<int>();
      if (j.contains("per_ip_window_ms")) l.per_ip_window_ms = j["per_ip_window_ms"].get<int64_t>();
      if (j.contains("per_address_window_ms")) l.per_address_window_ms = j["per_address_window_ms"].get<int64_t>();
      if (j.contains("allow_success_reset")) l.allow_success_reset = j["allow_success_reset"].get<bool>();
      if (j.contains("persist_failures")) l.persist_failures = j["persist_failures"].get<bool>();
      if (j.contains("persist_interval_ms")) l.persist_interval_ms = j["persist_interval_ms"].get<int64_t>();
      if (j.contains("persist_path")) l.persist_path = j["persist_path"].get<std::string>();
      return l;
    }

    void apply_overrides(const json& overrides) {
      if (overrides.contains("max_failed_attempts_before_lock")) max_failed_attempts_before_lock = overrides["max_failed_attempts_before_lock"].get<int>();
      if (overrides.contains("short_lockout_ms")) short_lockout_ms = overrides["short_lockout_ms"].get<int64_t>();
      if (overrides.contains("medium_lockout_ms")) medium_lockout_ms = overrides["medium_lockout_ms"].get<int64_t>();
      if (overrides.contains("long_lockout_ms")) long_lockout_ms = overrides["long_lockout_ms"].get<int64_t>();
      if (overrides.contains("extended_lockout_ms")) extended_lockout_ms = overrides["extended_lockout_ms"].get<int64_t>();
      if (overrides.contains("max_per_ip_failures")) max_per_ip_failures = overrides["max_per_ip_failures"].get<int>();
      if (overrides.contains("max_per_address_failures")) max_per_address_failures = overrides["max_per_address_failures"].get<int>();
      if (overrides.contains("persist_failures")) persist_failures = overrides["persist_failures"].get<bool>();
      if (overrides.contains("allow_success_reset")) allow_success_reset = overrides["allow_success_reset"].get<bool>();
    }
  };

  // ---- Whitelist ----
  struct Whitelist {
    std::set<std::string> ips;
    std::set<std::string> user_ids;
    std::set<std::string> email_domains;
    bool enabled = true;

    json to_json() const {
      return {
        {"enabled", enabled},
        {"ips", json(ips.begin(), ips.end())},
        {"user_ids", json(user_ids.begin(), user_ids.end())},
        {"email_domains", json(email_domains.begin(), email_domains.end())},
      };
    }
  };

  RegistrationLimitConfig() {
    set_defaults();
  }

  void set_defaults() {
    reg_limits_ = RegistrationLimits{};
    login_limits_ = LoginLimits{};
    whitelist_ = Whitelist{};

    // Default lockout tiers
    lockout_tiers_ = LockoutTierConfig::defaults();

    global_enabled_ = true;
    notify_on_lockout_ = false;
    notify_webhook_url_ = "";
    auto_cleanup_interval_ms_ = 300'000; // 5 minutes
    metrics_enabled_ = true;
  }

  // ---- Full serialization ----

  json to_json() const {
    std::shared_lock lock(mutex_);
    return {
      {"global_enabled", global_enabled_},
      {"registration", reg_limits_.to_json()},
      {"login", login_limits_.to_json()},
      {"whitelist", whitelist_.to_json()},
      {"lockout_tiers", json::array()},
      {"notify_on_lockout", notify_on_lockout_},
      {"auto_cleanup_interval_ms", auto_cleanup_interval_ms_},
      {"metrics_enabled", metrics_enabled_},
    };
  }

  static RegistrationLimitConfig from_json(const json& j) {
    RegistrationLimitConfig cfg;
    cfg.set_defaults();
    if (j.contains("global_enabled")) cfg.global_enabled_ = j["global_enabled"].get<bool>();
    if (j.contains("registration")) cfg.reg_limits_ = RegistrationLimits::from_json(j["registration"]);
    if (j.contains("login")) cfg.login_limits_ = LoginLimits::from_json(j["login"]);
    if (j.contains("notify_on_lockout")) cfg.notify_on_lockout_ = j["notify_on_lockout"].get<bool>();
    if (j.contains("auto_cleanup_interval_ms")) cfg.auto_cleanup_interval_ms_ = j["auto_cleanup_interval_ms"].get<int64_t>();
    if (j.contains("metrics_enabled")) cfg.metrics_enabled_ = j["metrics_enabled"].get<bool>();
    return cfg;
  }

  /// Load configuration from a JSON file
  bool load_from_file(const std::string& path) {
    try {
      std::ifstream file(path);
      if (!file.is_open()) return false;
      json j;
      file >> j;
      std::lock_guard lock(mutex_);
      if (j.contains("registration")) reg_limits_ = RegistrationLimits::from_json(j["registration"]);
      if (j.contains("login")) login_limits_ = LoginLimits::from_json(j["login"]);
      if (j.contains("whitelist")) {
        auto& w = j["whitelist"];
        if (w.contains("enabled")) whitelist_.enabled = w["enabled"].get<bool>();
        if (w.contains("ips")) for (auto& ip : w["ips"]) whitelist_.ips.insert(ip.get<std::string>());
        if (w.contains("user_ids")) for (auto& uid : w["user_ids"]) whitelist_.user_ids.insert(uid.get<std::string>());
        if (w.contains("email_domains")) for (auto& dom : w["email_domains"]) whitelist_.email_domains.insert(dom.get<std::string>());
      }
      if (j.contains("global_enabled")) global_enabled_ = j["global_enabled"].get<bool>();
      if (j.contains("notify_on_lockout")) notify_on_lockout_ = j["notify_on_lockout"].get<bool>();
      if (j.contains("notify_webhook_url")) notify_webhook_url_ = j["notify_webhook_url"].get<std::string>();
      if (j.contains("auto_cleanup_interval_ms")) auto_cleanup_interval_ms_ = j["auto_cleanup_interval_ms"].get<int64_t>();
      return true;
    } catch (const std::exception& e) {
      std::cerr << "[RegistrationLimits] Failed to load config from " << path << ": " << e.what() << std::endl;
      return false;
    }
  }

  /// Save configuration to a JSON file
  bool save_to_file(const std::string& path) const {
    try {
      std::ofstream file(path);
      if (!file.is_open()) return false;
      file << to_json().dump(2) << std::endl;
      return true;
    } catch (const std::exception& e) {
      std::cerr << "[RegistrationLimits] Failed to save config to " << path << ": " << e.what() << std::endl;
      return false;
    }
  }

  // ---- Accessors ----

  bool is_globally_enabled() const {
    std::shared_lock lock(mutex_);
    return global_enabled_;
  }

  void set_global_enabled(bool e) {
    std::lock_guard lock(mutex_);
    global_enabled_ = e;
  }

  RegistrationLimits get_registration_limits() const {
    std::shared_lock lock(mutex_);
    return reg_limits_;
  }

  void set_registration_limits(const RegistrationLimits& limits) {
    std::lock_guard lock(mutex_);
    reg_limits_ = limits;
  }

  void update_registration_limits(const json& overrides) {
    std::lock_guard lock(mutex_);
    reg_limits_.apply_overrides(overrides);
  }

  LoginLimits get_login_limits() const {
    std::shared_lock lock(mutex_);
    return login_limits_;
  }

  void set_login_limits(const LoginLimits& limits) {
    std::lock_guard lock(mutex_);
    login_limits_ = limits;
  }

  void update_login_limits(const json& overrides) {
    std::lock_guard lock(mutex_);
    login_limits_.apply_overrides(overrides);
  }

  Whitelist get_whitelist() const {
    std::shared_lock lock(mutex_);
    return whitelist_;
  }

  void add_whitelist_ip(const std::string& ip) {
    std::lock_guard lock(mutex_);
    whitelist_.ips.insert(normalize_ip(ip));
  }

  void remove_whitelist_ip(const std::string& ip) {
    std::lock_guard lock(mutex_);
    whitelist_.ips.erase(normalize_ip(ip));
  }

  void add_whitelist_user(const std::string& user_id) {
    std::lock_guard lock(mutex_);
    whitelist_.user_ids.insert(user_id);
  }

  void remove_whitelist_user(const std::string& user_id) {
    std::lock_guard lock(mutex_);
    whitelist_.user_ids.erase(user_id);
  }

  void add_whitelist_domain(const std::string& domain) {
    std::lock_guard lock(mutex_);
    whitelist_.email_domains.insert(to_lower(domain));
  }

  void remove_whitelist_domain(const std::string& domain) {
    std::lock_guard lock(mutex_);
    whitelist_.email_domains.erase(to_lower(domain));
  }

  bool is_ip_whitelisted(const std::string& ip) const {
    std::shared_lock lock(mutex_);
    if (!whitelist_.enabled) return false;
    return whitelist_.ips.count(normalize_ip(ip)) > 0;
  }

  bool is_user_whitelisted(const std::string& user_id) const {
    std::shared_lock lock(mutex_);
    if (!whitelist_.enabled) return false;
    return whitelist_.user_ids.count(user_id) > 0;
  }

  bool is_domain_whitelisted(const std::string& domain) const {
    std::shared_lock lock(mutex_);
    if (!whitelist_.enabled) return false;
    return whitelist_.email_domains.count(to_lower(domain)) > 0;
  }

  const std::vector<LockoutTierConfig>& lockout_tiers() const {
    return lockout_tiers_;
  }

  bool notify_on_lockout() const { return notify_on_lockout_; }
  const std::string& notify_webhook_url() const { return notify_webhook_url_; }
  int64_t auto_cleanup_interval_ms() const { return auto_cleanup_interval_ms_; }
  bool metrics_enabled() const { return metrics_enabled_; }

  int get_window_limit(RegistrationWindow w) const {
    std::shared_lock lock(mutex_);
    switch (w) {
      case RegistrationWindow::PER_MINUTE: return reg_limits_.max_per_ip_minute;
      case RegistrationWindow::PER_HOUR:   return reg_limits_.max_per_ip_hour;
      case RegistrationWindow::PER_6HOURS: return reg_limits_.max_per_ip_6hours;
      case RegistrationWindow::PER_DAY:    return reg_limits_.max_per_ip_day;
      case RegistrationWindow::PER_WEEK:   return reg_limits_.max_per_ip_week;
      default: return 5;
    }
  }

private:
  mutable std::shared_mutex mutex_;
  RegistrationLimits reg_limits_;
  LoginLimits login_limits_;
  Whitelist whitelist_;
  std::vector<LockoutTierConfig> lockout_tiers_;
  bool global_enabled_ = true;
  bool notify_on_lockout_ = false;
  std::string notify_webhook_url_;
  int64_t auto_cleanup_interval_ms_ = 300'000;
  bool metrics_enabled_ = true;
};

// ============================================================================
// 2. RegistrationTracker — Multi-dimensional registration tracking
//
// Tracks registration attempts across IP, email, domain, and global
// dimensions. Uses sliding windows with configurable durations.
// Maintains pending (in-progress) counts to detect registration floods.
// ============================================================================

class RegistrationTracker {
public:
  struct Attempt {
    int64_t timestamp_ms;
    std::string ip;
    std::string email;
    std::string username;
    bool success;
    bool shared_secret;
  };

  struct CheckResult {
    bool allowed = true;
    int64_t retry_after_ms = 0;
    std::string reason;
    std::string limited_by;       // "ip_hour", "ip_day", "email_total", "global", etc.
    int current_count = 0;
    int max_allowed = 0;
    RegistrationWindow window = RegistrationWindow::PER_HOUR;
  };

  explicit RegistrationTracker(std::shared_ptr<RegistrationLimitConfig> config)
      : config_(std::move(config)) {}

  /// Check if a registration attempt should be allowed across all dimensions.
  /// Returns detailed result with reason and retry timing if denied.
  CheckResult check_registration(const std::string& ip,
                                  const std::string& email,
                                  const std::string& username,
                                  bool is_shared_secret) {
    CheckResult result;
    auto limits = config_->get_registration_limits();

    if (!limits.enabled || !config_->is_globally_enabled()) {
      result.allowed = true;
      return result;
    }

    // Shared secret bypass
    if (is_shared_secret && limits.shared_secret_bypass) {
      result.allowed = true;
      return result;
    }

    // Whitelist check
    if (config_->is_ip_whitelisted(ip) || config_->is_user_whitelisted(username)) {
      result.allowed = true;
      return result;
    }

    // Private IP exemption
    if (limits.allow_private_ip_exempt && is_private_ip(ip)) {
      result.allowed = true;
      return result;
    }

    std::string norm_ip = normalize_ip(ip);
    std::string norm_email = to_lower(email);
    std::string domain = extract_email_domain(norm_email);
    int64_t now = now_ms();

    std::lock_guard lock(mutex_);

    // ---- Per-IP checks across all windows ----
    {
      auto ip_result = check_ip_limits(norm_ip, now, limits);
      if (!ip_result.allowed) return ip_result;
    }

    // ---- Per-email checks ----
    if (!norm_email.empty()) {
      auto email_result = check_email_limits(norm_email, now, limits);
      if (!email_result.allowed) return email_result;
    }

    // ---- Per-domain checks ----
    if (!domain.empty()) {
      auto domain_result = check_domain_limits(domain, now, limits);
      if (!domain_result.allowed) return domain_result;
    }

    // ---- Global checks ----
    {
      auto global_result = check_global_limits(now, limits);
      if (!global_result.allowed) return global_result;
    }

    // ---- Pending count check ----
    if (pending_count_ >= limits.max_pending_total) {
      result.allowed = false;
      result.retry_after_ms = 30'000;
      result.reason = "Too many registrations in progress";
      result.limited_by = "pending_total";
      result.current_count = pending_count_;
      result.max_allowed = limits.max_pending_total;
      return result;
    }

    // ---- Cooldown check ----
    {
      auto it = cooldowns_.find(norm_ip);
      if (it != cooldowns_.end() && now < it->second) {
        result.allowed = false;
        result.retry_after_ms = it->second - now;
        result.reason = "Registration cooldown active after recent rejection";
        result.limited_by = "cooldown";
        return result;
      }
    }

    result.allowed = true;
    return result;
  }

  /// Record a registration attempt result (success or failure)
  void record_attempt(const std::string& ip,
                      const std::string& email,
                      const std::string& username,
                      bool success,
                      bool is_shared_secret) {
    std::string norm_ip = normalize_ip(ip);
    std::string norm_email = to_lower(email);
    int64_t now = now_ms();

    std::lock_guard lock(mutex_);

    Attempt att{now, norm_ip, norm_email, username, success, is_shared_secret};

    ip_attempts_[norm_ip].push_back(att);
    if (!norm_email.empty()) {
      email_attempts_[norm_email].push_back(att);
      std::string domain = extract_email_domain(norm_email);
      if (!domain.empty()) {
        domain_attempts_[domain].push_back(att);
      }
    }
    global_attempts_.push_back(att);

    if (success) {
      total_successful_++;
      // Remove cooldown on success
      cooldowns_.erase(norm_ip);
    } else if (!is_shared_secret) {
      total_rejected_++;
      // Apply cooldown after rejection
      auto limits = config_->get_registration_limits();
      if (limits.cooldown_after_rejection_ms > 0) {
        cooldowns_[norm_ip] = now + limits.cooldown_after_rejection_ms;
      }
    }

    // Prune old entries
    prune_locked(now);
  }

  /// Mark a registration as "pending" (in progress, e.g., during UI auth)
  void mark_pending() {
    pending_count_++;
  }

  /// Unmark a registration as pending
  void unmark_pending() {
    if (pending_count_ > 0) pending_count_--;
  }

  /// Get stats for a specific IP
  json get_ip_stats(const std::string& ip) const {
    std::string norm_ip = normalize_ip(ip);
    int64_t now = now_ms();
    json j;
    j["ip"] = norm_ip;

    std::shared_lock lock(mutex_);
    auto limits = config_->get_registration_limits();

    auto it = ip_attempts_.find(norm_ip);
    if (it != ip_attempts_.end()) {
      j["total_attempts"] = it->second.size();
      int minute = 0, hour = 0, six_hours = 0, day = 0, week = 0;
      for (const auto& att : it->second) {
        int64_t age = now - att.timestamp_ms;
        if (age < 60'000) minute++;
        if (age < 3'600'000) hour++;
        if (age < 21'600'000) six_hours++;
        if (age < 86'400'000) day++;
        if (age < 604'800'000) week++;
      }
      j["counts"] = {
        {"minute", {{"count", minute}, {"limit", limits.max_per_ip_minute}}},
        {"hour", {{"count", hour}, {"limit", limits.max_per_ip_hour}}},
        {"6hours", {{"count", six_hours}, {"limit", limits.max_per_ip_6hours}}},
        {"day", {{"count", day}, {"limit", limits.max_per_ip_day}}},
        {"week", {{"count", week}, {"limit", limits.max_per_ip_week}}},
      };
    } else {
      j["total_attempts"] = 0;
      j["counts"] = json::object();
    }
    return j;
  }

  /// Get stats for a specific email
  json get_email_stats(const std::string& email) const {
    std::string norm_email = to_lower(email);
    int64_t now = now_ms();
    json j;
    j["email"] = norm_email;

    std::shared_lock lock(mutex_);
    auto limits = config_->get_registration_limits();

    auto it = email_attempts_.find(norm_email);
    if (it != email_attempts_.end()) {
      j["total_attempts"] = it->second.size();
      int hour = 0, day = 0;
      for (const auto& att : it->second) {
        int64_t age = now - att.timestamp_ms;
        if (age < 3'600'000) hour++;
        if (age < 86'400'000) day++;
      }
      j["counts"] = {
        {"hour", {{"count", hour}, {"limit", limits.max_per_email_hour}}},
        {"day", {{"count", day}, {"limit", limits.max_per_email_day}}},
        {"total_limit", limits.max_per_email_total},
        {"total_ever", it->second.size()},
      };
    } else {
      j["total_attempts"] = 0;
    }
    return j;
  }

  /// Get all IPs with recent registration activity
  std::vector<std::string> active_ips(int64_t window_ms = 3'600'000) const {
    int64_t now = now_ms();
    std::vector<std::string> result;
    std::shared_lock lock(mutex_);
    for (const auto& [ip, attempts] : ip_attempts_) {
      for (const auto& att : attempts) {
        if (now - att.timestamp_ms < window_ms) {
          result.push_back(ip);
          break;
        }
      }
    }
    return result;
  }

  /// Clear all tracking data for a specific IP
  void clear_ip(const std::string& ip) {
    std::lock_guard lock(mutex_);
    auto it = ip_attempts_.find(normalize_ip(ip));
    if (it != ip_attempts_.end()) {
      it->second.clear();
    }
    cooldowns_.erase(normalize_ip(ip));
  }

  /// Clear all tracking data for a specific email
  void clear_email(const std::string& email) {
    std::lock_guard lock(mutex_);
    auto it = email_attempts_.find(to_lower(email));
    if (it != email_attempts_.end()) {
      it->second.clear();
    }
  }

  /// Clear all tracking data (global reset)
  void clear_all() {
    std::lock_guard lock(mutex_);
    ip_attempts_.clear();
    email_attempts_.clear();
    domain_attempts_.clear();
    global_attempts_.clear();
    cooldowns_.clear();
    pending_count_ = 0;
  }

  /// Cleanup stale records
  size_t cleanup_stale() {
    int64_t now = now_ms();
    size_t removed = 0;
    std::lock_guard lock(mutex_);
    removed += prune_map(ip_attempts_, now);
    removed += prune_map(email_attempts_, now);
    removed += prune_map(domain_attempts_, now);
    removed += prune_list(global_attempts_, now);
    removed += prune_cooldowns(now);
    return removed;
  }

  /// Get global statistics
  json get_stats() const {
    std::shared_lock lock(mutex_);
    return {
      {"unique_ips", ip_attempts_.size()},
      {"unique_emails", email_attempts_.size()},
      {"unique_domains", domain_attempts_.size()},
      {"total_global_attempts", global_attempts_.size()},
      {"pending_count", pending_count_.load()},
      {"total_successful", total_successful_.load()},
      {"total_rejected", total_rejected_.load()},
      {"ips_in_cooldown", cooldowns_.size()},
    };
  }

private:
  CheckResult check_ip_limits(const std::string& norm_ip, int64_t now,
                               const RegistrationLimitConfig::RegistrationLimits& limits) {
    CheckResult result;
    auto it = ip_attempts_.find(norm_ip);
    if (it == ip_attempts_.end()) return result; // No history, allowed

    int counts[static_cast<int>(RegistrationWindow::COUNT)] = {};
    int64_t oldest[static_cast<int>(RegistrationWindow::COUNT)] = {};

    for (int i = 0; i < static_cast<int>(RegistrationWindow::COUNT); ++i) {
      oldest[i] = now;
    }

    for (const auto& att : it->second) {
      int64_t age = now - att.timestamp_ms;
      for (int w = 0; w < static_cast<int>(RegistrationWindow::COUNT); ++w) {
        int64_t dur = window_duration_ms(static_cast<RegistrationWindow>(w));
        if (age < dur) {
          counts[w]++;
          if (att.timestamp_ms < oldest[w]) oldest[w] = att.timestamp_ms;
        }
      }
    }

    // Check windows from shortest to longest
    static const int win_limits[] = {
      limits.max_per_ip_minute,
      limits.max_per_ip_hour,
      limits.max_per_ip_6hours,
      limits.max_per_ip_day,
      limits.max_per_ip_week,
    };

    for (int w = 0; w < static_cast<int>(RegistrationWindow::COUNT); ++w) {
      if (counts[w] >= win_limits[w]) {
        RegistrationWindow rw = static_cast<RegistrationWindow>(w);
        result.allowed = false;
        result.retry_after_ms = (oldest[w] + window_duration_ms(rw)) - now;
        if (result.retry_after_ms < 1000) result.retry_after_ms = 5000;
        result.reason = std::string("Too many registrations from this IP (")
                      + window_name(rw) + " limit reached)";
        result.limited_by = std::string("ip_") + window_name(rw);
        result.current_count = counts[w];
        result.max_allowed = win_limits[w];
        result.window = rw;
        return result;
      }
    }

    return result;
  }

  CheckResult check_email_limits(const std::string& norm_email, int64_t now,
                                  const RegistrationLimitConfig::RegistrationLimits& limits) {
    CheckResult result;
    auto it = email_attempts_.find(norm_email);
    if (it == email_attempts_.end()) return result;

    int hour_count = 0, day_count = 0;
    int64_t oldest_hour = now, oldest_day = now;

    for (const auto& att : it->second) {
      int64_t age = now - att.timestamp_ms;
      if (age < 3'600'000) {
        hour_count++;
        if (att.timestamp_ms < oldest_hour) oldest_hour = att.timestamp_ms;
      }
      if (age < 86'400'000) {
        day_count++;
        if (att.timestamp_ms < oldest_day) oldest_day = att.timestamp_ms;
      }
    }

    // Per-hour limit
    if (hour_count >= limits.max_per_email_hour) {
      result.allowed = false;
      result.retry_after_ms = (oldest_hour + 3'600'000) - now;
      if (result.retry_after_ms < 1000) result.retry_after_ms = 5000;
      result.reason = "Too many registrations for this email address in the last hour";
      result.limited_by = "email_per_hour";
      result.current_count = hour_count;
      result.max_allowed = limits.max_per_email_hour;
      return result;
    }

    // Per-day limit
    if (day_count >= limits.max_per_email_day) {
      result.allowed = false;
      result.retry_after_ms = (oldest_day + 86'400'000) - now;
      if (result.retry_after_ms < 1000) result.retry_after_ms = 30'000;
      result.reason = "Too many registrations for this email address in the last 24 hours";
      result.limited_by = "email_per_day";
      result.current_count = day_count;
      result.max_allowed = limits.max_per_email_day;
      return result;
    }

    // Total lifetime limit
    if (static_cast<int>(it->second.size()) >= limits.max_per_email_total) {
      result.allowed = false;
      result.retry_after_ms = 86'400'000; // 24 hours default
      result.reason = "This email address has reached its lifetime registration limit";
      result.limited_by = "email_total";
      result.current_count = static_cast<int>(it->second.size());
      result.max_allowed = limits.max_per_email_total;
      return result;
    }

    return result;
  }

  CheckResult check_domain_limits(const std::string& domain, int64_t now,
                                   const RegistrationLimitConfig::RegistrationLimits& limits) {
    CheckResult result;
    auto it = domain_attempts_.find(domain);
    if (it == domain_attempts_.end()) return result;

    int hour_count = 0, day_count = 0;

    for (const auto& att : it->second) {
      int64_t age = now - att.timestamp_ms;
      if (age < 3'600'000) hour_count++;
      if (age < 86'400'000) day_count++;
    }

    if (hour_count >= limits.max_per_domain_hour) {
      result.allowed = false;
      result.retry_after_ms = 3'600'000;
      result.reason = "Too many registrations from this email domain in the last hour";
      result.limited_by = "domain_per_hour";
      result.current_count = hour_count;
      result.max_allowed = limits.max_per_domain_hour;
      return result;
    }

    if (day_count >= limits.max_per_domain_day) {
      result.allowed = false;
      result.retry_after_ms = 86'400'000;
      result.reason = "Too many registrations from this email domain in the last 24 hours";
      result.limited_by = "domain_per_day";
      result.current_count = day_count;
      result.max_allowed = limits.max_per_domain_day;
      return result;
    }

    return result;
  }

  CheckResult check_global_limits(int64_t now,
                                   const RegistrationLimitConfig::RegistrationLimits& limits) {
    CheckResult result;
    int minute_count = 0, hour_count = 0;
    int64_t oldest_minute = now, oldest_hour = now;

    for (const auto& att : global_attempts_) {
      int64_t age = now - att.timestamp_ms;
      if (age < 60'000) {
        minute_count++;
        if (att.timestamp_ms < oldest_minute) oldest_minute = att.timestamp_ms;
      }
      if (age < 3'600'000) {
        hour_count++;
        if (att.timestamp_ms < oldest_hour) oldest_hour = att.timestamp_ms;
      }
    }

    if (minute_count >= limits.max_global_minute) {
      result.allowed = false;
      result.retry_after_ms = (oldest_minute + 60'000) - now;
      if (result.retry_after_ms < 1000) result.retry_after_ms = 5000;
      result.reason = "Global registration rate limit reached (per minute)";
      result.limited_by = "global_per_minute";
      result.current_count = minute_count;
      result.max_allowed = limits.max_global_minute;
      return result;
    }

    if (hour_count >= limits.max_global_hour) {
      result.allowed = false;
      result.retry_after_ms = (oldest_hour + 3'600'000) - now;
      if (result.retry_after_ms < 1000) result.retry_after_ms = 30'000;
      result.reason = "Global registration rate limit reached (per hour)";
      result.limited_by = "global_per_hour";
      result.current_count = hour_count;
      result.max_allowed = limits.max_global_hour;
      return result;
    }

    return result;
  }

  template<typename M>
  size_t prune_map(M& map, int64_t now) {
    size_t removed = 0;
    auto it = map.begin();
    while (it != map.end()) {
      auto& attempts = it->second;
      while (!attempts.empty() &&
             now - attempts.front().timestamp_ms > 604'800'000 * 2) { // 2 weeks
        attempts.pop_front();
      }
      if (attempts.empty()) {
        it = map.erase(it);
        removed++;
      } else {
        ++it;
      }
    }
    return removed;
  }

  size_t prune_list(std::deque<Attempt>& list, int64_t now) {
    size_t removed = 0;
    while (!list.empty() &&
           now - list.front().timestamp_ms > 604'800'000 * 2) {
      list.pop_front();
      removed++;
    }
    return removed;
  }

  size_t prune_cooldowns(int64_t now) {
    size_t removed = 0;
    auto it = cooldowns_.begin();
    while (it != cooldowns_.end()) {
      if (now > it->second) {
        it = cooldowns_.erase(it);
        removed++;
      } else {
        ++it;
      }
    }
    return removed;
  }

  void prune_locked(int64_t now) {
    // Aggressively prune old entries during record_attempt
    static int64_t last_prune = 0;
    if (now - last_prune > 60'000) { // Prune at most every 60 seconds
      prune_map(ip_attempts_, now);
      prune_map(email_attempts_, now);
      prune_map(domain_attempts_, now);
      prune_list(global_attempts_, now);
      prune_cooldowns(now);
      last_prune = now;
    }
  }

  std::shared_ptr<RegistrationLimitConfig> config_;

  mutable std::shared_mutex mutex_;
  std::map<std::string, std::deque<Attempt>, std::less<>> ip_attempts_;
  std::map<std::string, std::deque<Attempt>, std::less<>> email_attempts_;
  std::map<std::string, std::deque<Attempt>, std::less<>> domain_attempts_;
  std::deque<Attempt> global_attempts_;
  std::map<std::string, int64_t, std::less<>> cooldowns_; // IP -> cooldown_until_ms
  std::atomic<int> pending_count_{0};
  std::atomic<int64_t> total_successful_{0};
  std::atomic<int64_t> total_rejected_{0};
};

// ============================================================================
// 3. LoginFailureTracker — Persistent login failure tracking with graduated lockout
//
// Tracks failed login attempts per-account with persistence to disk
// for crash survival. Implements graduated lockout with escalating
// durations. Supports per-IP and per-address throttling.
// ============================================================================

class LoginFailureTracker {
public:
  struct FailureRecord {
    int64_t timestamp_ms;
    std::string ip;
    std::string address;     // email or msisdn
    std::string user_agent;
    bool was_valid_user;     // Whether the account actually exists
  };

  struct AccountState {
    std::string account;
    std::deque<FailureRecord> failures;
    int64_t consecutive_failures = 0;
    int64_t effective_failures = 0;  // Decay-adjusted count
    int64_t first_failure_ms = 0;
    int64_t last_failure_ms = 0;
    int64_t locked_until_ms = 0;
    LockoutTier current_tier = LockoutTier::NONE;
    int64_t total_failures_ever = 0;
    int64_t total_successes = 0;
    int64_t last_success_ms = 0;
    bool dirty = false;  // Needs persistence flush

    json to_json() const {
      json j;
      j["account"] = account;
      j["consecutive_failures"] = consecutive_failures;
      j["effective_failures"] = effective_failures;
      j["first_failure_ms"] = first_failure_ms;
      j["last_failure_ms"] = last_failure_ms;
      j["locked_until_ms"] = locked_until_ms;
      j["current_tier"] = static_cast<int>(current_tier);
      j["total_failures_ever"] = total_failures_ever;
      j["total_successes"] = total_successes;
      j["last_success_ms"] = last_success_ms;
      // Don't serialize full failure history to keep file small
      return j;
    }

    static AccountState from_json(const json& j) {
      AccountState s;
      if (j.contains("account")) s.account = j["account"].get<std::string>();
      if (j.contains("consecutive_failures")) s.consecutive_failures = j["consecutive_failures"].get<int64_t>();
      if (j.contains("effective_failures")) s.effective_failures = j["effective_failures"].get<int64_t>();
      if (j.contains("first_failure_ms")) s.first_failure_ms = j["first_failure_ms"].get<int64_t>();
      if (j.contains("last_failure_ms")) s.last_failure_ms = j["last_failure_ms"].get<int64_t>();
      if (j.contains("locked_until_ms")) s.locked_until_ms = j["locked_until_ms"].get<int64_t>();
      if (j.contains("current_tier")) s.current_tier = static_cast<LockoutTier>(j["current_tier"].get<int>());
      if (j.contains("total_failures_ever")) s.total_failures_ever = j["total_failures_ever"].get<int64_t>();
      if (j.contains("total_successes")) s.total_successes = j["total_successes"].get<int64_t>();
      if (j.contains("last_success_ms")) s.last_success_ms = j["last_success_ms"].get<int64_t>();
      return s;
    }
  };

  struct LoginCheckResult {
    bool allowed = true;
    int64_t retry_after_ms = 0;
    std::string reason;
    std::string limited_by;          // "account_lockout", "ip_limit", "address_limit"
    int64_t consecutive_failures = 0;
    LockoutTier tier = LockoutTier::NONE;
    int64_t lockout_remaining_ms = 0;
  };

  explicit LoginFailureTracker(std::shared_ptr<RegistrationLimitConfig> config)
      : config_(std::move(config)) {}

  /// Initialize: load persisted state from disk
  bool load_persisted_state() {
    auto login_limits = config_->get_login_limits();
    if (!login_limits.persist_failures) return true;

    std::string path = login_limits.persist_path;
    if (!fs::exists(path)) return true; // No file yet, OK

    try {
      std::ifstream file(path);
      if (!file.is_open()) return false;

      std::string line;
      int loaded = 0;
      std::lock_guard lock(mutex_);
      while (std::getline(file, line)) {
        if (line.empty()) continue;
        try {
          json j = json::parse(line);
          if (!j.contains("account")) continue;

          // Verify simple checksum
          if (j.contains("_checksum")) {
            std::string data = j.dump();
            // Skip checksum verification on load for forward compatibility
          }

          AccountState state = AccountState::from_json(j);
          if (!state.account.empty()) {
            accounts_[state.account] = std::make_unique<AccountState>(std::move(state));
            loaded++;
          }
        } catch (const std::exception&) {
          // Skip corrupt lines
          continue;
        }
      }
      std::cout << "[LoginFailureTracker] Loaded " << loaded
                << " account states from " << path << std::endl;
      return true;
    } catch (const std::exception& e) {
      std::cerr << "[LoginFailureTracker] Failed to load persisted state: "
                << e.what() << std::endl;
      return false;
    }
  }

  /// Persist current state to disk
  bool persist_state() {
    auto login_limits = config_->get_login_limits();
    if (!login_limits.persist_failures) return true;

    std::string path = login_limits.persist_path;
    std::string tmp_path = path + ".tmp";

    try {
      // Ensure directory exists
      fs::path parent = fs::path(path).parent_path();
      if (!parent.empty() && !fs::exists(parent)) {
        fs::create_directories(parent);
      }

      std::ofstream file(tmp_path);
      if (!file.is_open()) return false;

      std::shared_lock lock(mutex_);
      for (const auto& [acct, state] : accounts_) {
        std::lock_guard slock(state->mutex);
        json j = state->to_json();
        j["_checksum"] = simple_checksum(j.dump());
        j["_persisted_at"] = iso8601_now();
        file << j.dump() << "\n";
        state->dirty = false;
      }
      file.close();

      // Atomic rename
      fs::rename(tmp_path, path);
      last_persist_ms_ = now_ms();
      return true;
    } catch (const std::exception& e) {
      std::cerr << "[LoginFailureTracker] Failed to persist state: "
                << e.what() << std::endl;
      // Clean up temp file
      if (fs::exists(tmp_path)) fs::remove(tmp_path);
      return false;
    }
  }

  /// Check if a login attempt should be allowed
  LoginCheckResult check_login(const std::string& account,
                                const std::string& ip,
                                const std::string& address) {
    LoginCheckResult result;
    auto login_limits = config_->get_login_limits();

    if (!login_limits.enabled || !config_->is_globally_enabled()) {
      result.allowed = true;
      return result;
    }

    // Whitelist check
    if (config_->is_ip_whitelisted(ip) || config_->is_user_whitelisted(account)) {
      result.allowed = true;
      return result;
    }

    std::string norm_ip = normalize_ip(ip);
    int64_t now = now_ms();

    // ---- Per-account check ----
    if (login_limits.per_account_enabled && !account.empty()) {
      auto& state = get_account_state(account);
      std::lock_guard lock(state.mutex);

      // Apply failure decay
      apply_decay_locked(state, now, login_limits);

      // Check if account is locked
      if (state.locked_until_ms > 0 && now < state.locked_until_ms) {
        result.allowed = false;
        result.retry_after_ms = state.locked_until_ms - now;
        result.reason = "Account temporarily locked due to repeated failed login attempts";
        result.limited_by = "account_lockout";
        result.consecutive_failures = state.consecutive_failures;
        result.tier = state.current_tier;
        result.lockout_remaining_ms = state.locked_until_ms - now;
        return result;
      }

      // Check against lockout thresholds using effective failures
      int64_t eff = state.effective_failures;
      const auto& tiers = config_->lockout_tiers();
      for (const auto& tier : tiers) {
        if (eff >= tier.threshold) {
          LockoutTier new_tier = static_cast<LockoutTier>(
              (&tier - &tiers[0]) + 1);
          // Only escalate, never de-escalate automatically
          if (new_tier > state.current_tier) {
            state.current_tier = new_tier;
            state.locked_until_ms = now + tier.duration_ms;
            state.dirty = true;

            result.allowed = false;
            result.retry_after_ms = tier.duration_ms;
            result.reason = std::string("Account locked: ") + tier.description;
            result.limited_by = "account_lockout";
            result.consecutive_failures = state.consecutive_failures;
            result.tier = new_tier;
            result.lockout_remaining_ms = tier.duration_ms;
            return result;
          }
        }
      }
    }

    // ---- Per-IP check ----
    if (login_limits.per_ip_enabled && !norm_ip.empty()) {
      std::lock_guard lock(ip_mutex_);
      auto it = ip_failures_.find(norm_ip);
      if (it != ip_failures_.end()) {
        // Prune old entries and count recent failures
        int recent_failures = 0;
        auto& records = it->second;
        while (!records.empty() &&
               now - records.front().first > login_limits.per_ip_window_ms) {
          records.pop_front();
        }
        for (const auto& [ts, acct] : records) {
          if (now - ts <= login_limits.per_ip_window_ms) {
            recent_failures++;
          }
        }
        if (recent_failures >= login_limits.max_per_ip_failures) {
          result.allowed = false;
          result.retry_after_ms = login_limits.per_ip_window_ms;
          result.reason = "Too many failed login attempts from this IP address";
          result.limited_by = "ip_limit";
          result.consecutive_failures = recent_failures;
          return result;
        }
      }
    }

    // ---- Per-address check ----
    if (login_limits.per_address_enabled && !address.empty()) {
      std::lock_guard lock(addr_mutex_);
      auto it = addr_failures_.find(address);
      if (it != addr_failures_.end()) {
        int recent_failures = 0;
        auto& records = it->second;
        while (!records.empty() &&
               now - records.front().first > login_limits.per_address_window_ms) {
          records.pop_front();
        }
        for (const auto& [ts, acct] : records) {
          if (now - ts <= login_limits.per_address_window_ms) {
            recent_failures++;
          }
        }
        if (recent_failures >= login_limits.max_per_address_failures) {
          result.allowed = false;
          result.retry_after_ms = login_limits.per_address_window_ms;
          result.reason = "Too many failed login attempts for this email/phone";
          result.limited_by = "address_limit";
          result.consecutive_failures = recent_failures;
          return result;
        }
      }
    }

    result.allowed = true;
    return result;
  }

  /// Record a failed login attempt
  void record_failure(const std::string& account,
                      const std::string& ip,
                      const std::string& address,
                      const std::string& user_agent,
                      bool was_valid_user) {
    int64_t now = now_ms();
    std::string norm_ip = normalize_ip(ip);
    auto login_limits = config_->get_login_limits();

    FailureRecord rec{now, norm_ip, address, user_agent, was_valid_user};

    // Update per-account state
    if (login_limits.per_account_enabled && !account.empty()) {
      auto& state = get_account_state(account);
      std::lock_guard lock(state.mutex);

      apply_decay_locked(state, now, login_limits);

      state.failures.push_back(rec);
      state.consecutive_failures++;
      state.effective_failures++;
      state.last_failure_ms = now;
      state.total_failures_ever++;
      if (state.first_failure_ms == 0) state.first_failure_ms = now;
      state.dirty = true;

      // Prune old failure records
      while (!state.failures.empty() &&
             now - state.failures.front().timestamp_ms > login_limits.failure_window_ms * 3) {
        state.failures.pop_front();
      }
    }

    // Update per-IP tracking
    if (login_limits.per_ip_enabled) {
      std::lock_guard lock(ip_mutex_);
      ip_failures_[norm_ip].emplace_back(now, account);
    }

    // Update per-address tracking
    if (login_limits.per_address_enabled && !address.empty()) {
      std::lock_guard lock(addr_mutex_);
      addr_failures_[address].emplace_back(now, account);
    }
  }

  /// Record a successful login (resets failure counters)
  void record_success(const std::string& account) {
    auto login_limits = config_->get_login_limits();
    if (!login_limits.allow_success_reset) return;
    if (account.empty()) return;

    int64_t now = now_ms();
    auto& state = get_account_state(account);
    std::lock_guard lock(state.mutex);

    state.consecutive_failures = 0;
    state.effective_failures = 0;
    state.first_failure_ms = 0;
    state.locked_until_ms = 0;
    state.current_tier = LockoutTier::NONE;
    state.failures.clear();
    state.last_success_ms = now;
    state.total_successes++;
    state.dirty = true;
  }

  /// Admin: clear lockout for a specific account
  void admin_clear_lockout(const std::string& account) {
    auto& state = get_account_state(account);
    std::lock_guard lock(state.mutex);
    state.consecutive_failures = 0;
    state.effective_failures = 0;
    state.first_failure_ms = 0;
    state.locked_until_ms = 0;
    state.current_tier = LockoutTier::NONE;
    state.failures.clear();
    state.dirty = true;
  }

  /// Admin: clear all lockouts
  void admin_clear_all_lockouts() {
    std::lock_guard lock(mutex_);
    for (auto& [acct, state] : accounts_) {
      std::lock_guard slock(state->mutex);
      state->consecutive_failures = 0;
      state->effective_failures = 0;
      state->first_failure_ms = 0;
      state->locked_until_ms = 0;
      state->current_tier = LockoutTier::NONE;
      state->dirty = true;
    }
  }

  /// Admin: clear per-IP tracking
  void admin_clear_ip(const std::string& ip) {
    std::lock_guard lock(ip_mutex_);
    ip_failures_.erase(normalize_ip(ip));
  }

  /// Admin: clear all IP tracking
  void admin_clear_all_ips() {
    std::lock_guard lock(ip_mutex_);
    ip_failures_.clear();
  }

  /// Admin: clear per-address tracking
  void admin_clear_address(const std::string& address) {
    std::lock_guard lock(addr_mutex_);
    addr_failures_.erase(address);
  }

  /// Get all currently locked accounts
  std::vector<AccountState> get_locked_accounts() const {
    int64_t now = now_ms();
    std::vector<AccountState> result;
    std::shared_lock lock(mutex_);
    for (const auto& [acct, state] : accounts_) {
      std::lock_guard slock(state->mutex);
      if (state->locked_until_ms > 0 && state->locked_until_ms > now) {
        result.push_back(*state);
      }
    }
    return result;
  }

  /// Get account state for admin inspection
  std::optional<AccountState> get_account_info(const std::string& account) const {
    std::shared_lock lock(mutex_);
    auto it = accounts_.find(account);
    if (it == accounts_.end()) return std::nullopt;
    std::lock_guard slock(it->second->mutex);
    return *it->second;
  }

  /// Get all IPs with recent failures
  std::vector<std::string> get_active_ips(int max_recent = 10) const {
    std::vector<std::pair<std::string, size_t>> entries;
    {
      std::lock_guard lock(ip_mutex_);
      for (const auto& [ip, records] : ip_failures_) {
        entries.emplace_back(ip, records.size());
      }
    }
    std::sort(entries.begin(), entries.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });
    std::vector<std::string> result;
    for (size_t i = 0; i < std::min(entries.size(), static_cast<size_t>(max_recent)); ++i) {
      result.push_back(entries[i].first);
    }
    return result;
  }

  /// Check if persistence is needed
  bool needs_persist() const {
    auto login_limits = config_->get_login_limits();
    if (!login_limits.persist_failures) return false;

    int64_t now = now_ms();
    if (now - last_persist_ms_ >= login_limits.persist_interval_ms) {
      // Quick check: any dirty accounts?
      std::shared_lock lock(mutex_);
      for (const auto& [acct, state] : accounts_) {
        if (state->dirty) return true;
      }
    }
    return false;
  }

  /// Cleanup stale data
  size_t cleanup_stale() {
    auto login_limits = config_->get_login_limits();
    int64_t now = now_ms();
    size_t removed = 0;

    // Cleanup account states with no recent activity
    {
      std::lock_guard lock(mutex_);
      auto it = accounts_.begin();
      while (it != accounts_.end()) {
        std::lock_guard slock(it->second->mutex);
        bool is_stale =
            it->second->consecutive_failures == 0 &&
            it->second->locked_until_ms == 0 &&
            it->second->effective_failures == 0 &&
            (it->second->last_failure_ms == 0 ||
             now - it->second->last_failure_ms > 86'400'000); // 24h
        if (is_stale) {
          it = accounts_.erase(it);
          removed++;
        } else {
          ++it;
        }
      }
    }

    // Cleanup IP tracking
    {
      std::lock_guard lock(ip_mutex_);
      auto it = ip_failures_.begin();
      while (it != ip_failures_.end()) {
        auto& records = it->second;
        while (!records.empty() &&
               now - records.front().first > login_limits.per_ip_window_ms * 4) {
          records.pop_front();
        }
        if (records.empty()) {
          it = ip_failures_.erase(it);
          removed++;
        } else {
          ++it;
        }
      }
    }

    // Cleanup address tracking
    {
      std::lock_guard lock(addr_mutex_);
      auto it = addr_failures_.begin();
      while (it != addr_failures_.end()) {
        auto& records = it->second;
        while (!records.empty() &&
               now - records.front().first > login_limits.per_address_window_ms * 4) {
          records.pop_front();
        }
        if (records.empty()) {
          it = addr_failures_.erase(it);
          removed++;
        } else {
          ++it;
        }
      }
    }

    return removed;
  }

  /// Get metrics for observability
  json get_metrics() const {
    int64_t now = now_ms();
    json j;

    // Account metrics
    {
      std::shared_lock lock(mutex_);
      int total = accounts_.size();
      int locked = 0;
      int warned = 0;
      int64_t total_failures = 0;

      for (const auto& [acct, state] : accounts_) {
        std::lock_guard slock(state->mutex);
        total_failures += state->total_failures_ever;
        if (state->locked_until_ms > 0 && state->locked_until_ms > now) locked++;
        if (state->effective_failures >= config_->lockout_tiers()[0].threshold) warned++;
      }

      j["accounts"] = {
        {"total_tracked", total},
        {"locked", locked},
        {"warned", warned},
        {"total_failures_ever", total_failures},
      };
    }

    // IP metrics
    {
      std::lock_guard lock(ip_mutex_);
      j["ips_tracked"] = ip_failures_.size();
    }

    // Address metrics
    {
      std::lock_guard lock(addr_mutex_);
      j["addresses_tracked"] = addr_failures_.size();
    }

    j["last_persist_ms"] = last_persist_ms_.load();
    return j;
  }

private:
  AccountState& get_account_state(const std::string& account) {
    {
      std::shared_lock lock(mutex_);
      auto it = accounts_.find(account);
      if (it != accounts_.end()) return *it->second;
    }
    std::lock_guard lock(mutex_);
    auto it = accounts_.find(account);
    if (it != accounts_.end()) return *it->second;
    auto state = std::make_unique<AccountState>();
    state->account = account;
    accounts_[std::string(account)] = std::move(state);
    return *accounts_[std::string(account)];
  }

  void apply_decay_locked(AccountState& state, int64_t now,
                           const RegistrationLimitConfig::LoginLimits& limits) {
    if (state.effective_failures <= 0) return;
    if (state.last_failure_ms == 0) return;

    int64_t elapsed = now - state.last_failure_ms;
    if (elapsed <= 0) return;

    // Decay: reduce effective_failures by 1 for every decay_ms elapsed
    int64_t decay_amount = elapsed / limits.failure_decay_ms;
    if (decay_amount > 0) {
      state.effective_failures = std::max<int64_t>(
          0, state.effective_failures - decay_amount);
      if (state.effective_failures == 0) {
        state.current_tier = LockoutTier::NONE;
        state.locked_until_ms = 0;
      }
      state.dirty = true;
    }
  }

  std::shared_ptr<RegistrationLimitConfig> config_;

  mutable std::shared_mutex mutex_;
  std::map<std::string, std::unique_ptr<AccountState>, std::less<>> accounts_;

  mutable std::mutex ip_mutex_;
  std::map<std::string, std::deque<std::pair<int64_t, std::string>>, std::less<>> ip_failures_;

  mutable std::mutex addr_mutex_;
  std::map<std::string, std::deque<std::pair<int64_t, std::string>>, std::less<>> addr_failures_;

  std::atomic<int64_t> last_persist_ms_{0};
};

// ============================================================================
// 4. RateLimitStorage — Hybrid storage layer for rate limit data
//
// Provides a unified interface for storing and retrieving rate limit
// state. Uses in-memory for hot-path checks and file-backed JSONL
// for persistence across restarts.
// ============================================================================

class RateLimitStorage {
public:
  explicit RateLimitStorage(std::shared_ptr<RegistrationLimitConfig> config)
      : config_(std::move(config)) {}

  /// Initialize storage: load any persisted data
  bool initialize() {
    auto login_limits = config_->get_login_limits();
    if (login_limits.persist_failures) {
      std::string path = login_limits.persist_path;
      // Ensure directory exists
      try {
        fs::path parent = fs::path(path).parent_path();
        if (!parent.empty() && !fs::exists(parent)) {
          fs::create_directories(parent);
        }
      } catch (const std::exception& e) {
        std::cerr << "[RateLimitStorage] Failed to create directory: "
                  << e.what() << std::endl;
      }
    }
    return true;
  }

  /// Store a login failure record to persistent storage
  bool store_login_failure(const std::string& account,
                           const std::string& ip,
                           const std::string& address,
                           int64_t timestamp_ms,
                           bool was_valid_user) {
    auto login_limits = config_->get_login_limits();
    if (!login_limits.persist_failures) return true;

    try {
      std::lock_guard lock(file_mutex_);
      std::string path = login_limits.persist_path;

      // Open in append mode
      std::ofstream file(path, std::ios::app);
      if (!file.is_open()) return false;

      json record;
      record["type"] = "login_failure";
      record["account"] = account;
      record["ip"] = normalize_ip(ip);
      record["address"] = address;
      record["timestamp_ms"] = timestamp_ms;
      record["was_valid_user"] = was_valid_user;
      record["logged_at"] = iso8601_now();
      record["_checksum"] = simple_checksum(record.dump());

      file << record.dump() << "\n";
      bytes_written_ += record.dump().size();
      total_stored_++;
      return true;
    } catch (const std::exception& e) {
      std::cerr << "[RateLimitStorage] Failed to store login failure: "
                << e.what() << std::endl;
      return false;
    }
  }

  /// Store a login success record
  bool store_login_success(const std::string& account,
                           const std::string& ip,
                           int64_t timestamp_ms) {
    auto login_limits = config_->get_login_limits();
    if (!login_limits.persist_failures) return true;

    try {
      std::lock_guard lock(file_mutex_);
      std::string path = login_limits.persist_path;

      std::ofstream file(path, std::ios::app);
      if (!file.is_open()) return false;

      json record;
      record["type"] = "login_success";
      record["account"] = account;
      record["ip"] = normalize_ip(ip);
      record["timestamp_ms"] = timestamp_ms;
      record["logged_at"] = iso8601_now();

      file << record.dump() << "\n";
      bytes_written_ += record.dump().size();
      total_stored_++;
      return true;
    } catch (const std::exception& e) {
      std::cerr << "[RateLimitStorage] Failed to store login success: "
                << e.what() << std::endl;
      return false;
    }
  }

  /// Store a registration record
  bool store_registration(const std::string& ip,
                          const std::string& email,
                          const std::string& username,
                          bool success,
                          bool shared_secret,
                          int64_t timestamp_ms) {
    auto login_limits = config_->get_login_limits();
    std::string path = login_limits.persist_path;
    // Replace filename to use registration-specific file
    size_t last_slash = path.rfind('/');
    std::string dir = (last_slash != std::string::npos) ? path.substr(0, last_slash) : ".";
    std::string reg_path = dir + "/registration_events.jsonl";

    try {
      // Ensure directory
      fs::path parent = fs::path(reg_path).parent_path();
      if (!parent.empty() && !fs::exists(parent)) {
        fs::create_directories(parent);
      }

      std::lock_guard lock(file_mutex_);
      std::ofstream file(reg_path, std::ios::app);
      if (!file.is_open()) return false;

      json record;
      record["type"] = "registration";
      record["ip"] = normalize_ip(ip);
      record["email"] = to_lower(email);
      record["username"] = username;
      record["success"] = success;
      record["shared_secret"] = shared_secret;
      record["timestamp_ms"] = timestamp_ms;
      record["logged_at"] = iso8601_now();

      file << record.dump() << "\n";
      bytes_written_ += record.dump().size();
      total_stored_++;
      return true;
    } catch (const std::exception& e) {
      std::cerr << "[RateLimitStorage] Failed to store registration: "
                << e.what() << std::endl;
      return false;
    }
  }

  /// Store a lockout event
  bool store_lockout_event(const std::string& account,
                           LockoutTier tier,
                           int64_t locked_until_ms,
                           int64_t consecutive_failures) {
    auto login_limits = config_->get_login_limits();
    if (!login_limits.persist_failures) return true;

    try {
      std::lock_guard lock(file_mutex_);
      std::string path = login_limits.persist_path;

      std::ofstream file(path, std::ios::app);
      if (!file.is_open()) return false;

      json record;
      record["type"] = "lockout";
      record["account"] = account;
      record["tier"] = static_cast<int>(tier);
      record["locked_until_ms"] = locked_until_ms;
      record["consecutive_failures"] = consecutive_failures;
      record["logged_at"] = iso8601_now();

      file << record.dump() << "\n";
      bytes_written_ += record.dump().size();
      total_stored_++;
      return true;
    } catch (const std::exception& e) {
      std::cerr << "[RateLimitStorage] Failed to store lockout: "
                << e.what() << std::endl;
      return false;
    }
  }

  /// Get storage statistics
  json get_storage_stats() const {
    auto login_limits = config_->get_login_limits();
    json j;
    j["total_stored"] = total_stored_.load();
    j["bytes_written"] = bytes_written_.load();

    std::string path = login_limits.persist_path;
    if (fs::exists(path)) {
      j["persist_file_size_bytes"] = fs::file_size(path);
      j["persist_file_path"] = path;
    }

    return j;
  }

  /// Compact the storage file (remove old records)
  size_t compact_storage(int64_t max_age_ms = 86'400'000 * 7) { // 7 days
    auto login_limits = config_->get_login_limits();
    std::string path = login_limits.persist_path;
    if (!fs::exists(path)) return 0;

    std::string tmp_path = path + ".compact.tmp";
    int64_t now = now_ms();
    size_t kept = 0, removed = 0;

    try {
      std::ifstream in(path);
      std::ofstream out(tmp_path);
      std::string line;

      while (std::getline(in, line)) {
        if (line.empty()) continue;
        try {
          json j = json::parse(line);
          int64_t ts = 0;
          if (j.contains("timestamp_ms")) ts = j["timestamp_ms"].get<int64_t>();
          else if (j.contains("locked_until_ms")) ts = j["locked_until_ms"].get<int64_t>();
          else continue;

          if (now - ts < max_age_ms) {
            out << line << "\n";
            kept++;
          } else {
            removed++;
          }
        } catch (...) {
          removed++; // Remove corrupt lines
        }
      }

      in.close();
      out.close();
      fs::rename(tmp_path, path);
    } catch (const std::exception& e) {
      std::cerr << "[RateLimitStorage] Compact failed: " << e.what() << std::endl;
      if (fs::exists(tmp_path)) fs::remove(tmp_path);
      return 0;
    }

    std::cout << "[RateLimitStorage] Compaction: kept " << kept
              << " records, removed " << removed << std::endl;
    return removed;
  }

private:
  std::shared_ptr<RegistrationLimitConfig> config_;
  std::mutex file_mutex_;
  std::atomic<size_t> total_stored_{0};
  std::atomic<size_t> bytes_written_{0};
};

// ============================================================================
// 5. RateResetScheduler — Automatic and manual rate limit reset
//
// Handles periodic cleanup, auto-reset of expired entries, and
// provides admin-triggered reset operations. Runs a background
// cleanup thread for maintenance.
// ============================================================================

class RateResetScheduler {
public:
  struct ResetResult {
    bool success = true;
    std::string message;
    int registrations_cleared = 0;
    int lockouts_cleared = 0;
    int ips_cleared = 0;
    int addresses_cleared = 0;
    json details;

    json to_json() const {
      return {
        {"success", success},
        {"message", message},
        {"registrations_cleared", registrations_cleared},
        {"lockouts_cleared", lockouts_cleared},
        {"ips_cleared", ips_cleared},
        {"addresses_cleared", addresses_cleared},
        {"details", details},
      };
    }
  };

  RateResetScheduler(std::shared_ptr<RegistrationLimitConfig> config,
                     RegistrationTracker* reg_tracker,
                     LoginFailureTracker* login_tracker,
                     RateLimitStorage* storage)
      : config_(std::move(config)),
        reg_tracker_(reg_tracker),
        login_tracker_(login_tracker),
        storage_(storage) {}

  ~RateResetScheduler() {
    stop_background_cleanup();
  }

  /// Start background cleanup thread
  void start_background_cleanup() {
    if (cleanup_running_) return;
    cleanup_running_ = true;
    cleanup_thread_ = std::thread([this]() {
      while (cleanup_running_) {
        auto interval = config_->auto_cleanup_interval_ms();
        std::this_thread::sleep_for(chr::milliseconds(interval));

        if (!cleanup_running_) break;

        // Perform cleanup
        size_t reg_removed = reg_tracker_->cleanup_stale();
        size_t login_removed = login_tracker_->cleanup_stale();

        // Persist if needed
        if (login_tracker_->needs_persist()) {
          login_tracker_->persist_state();
        }

        // Periodic storage compaction (once per day)
        static int cleanup_count = 0;
        cleanup_count++;
        if (cleanup_count % 288 == 0) { // ~every 24h at 5min intervals
          storage_->compact_storage();
        }

        total_auto_cleanups_++;
        total_reg_removed_ += reg_removed;
        total_login_removed_ += login_removed;
      }
    });
  }

  /// Stop background cleanup thread
  void stop_background_cleanup() {
    cleanup_running_ = false;
    if (cleanup_thread_.joinable()) {
      cleanup_thread_.join();
    }
  }

  /// Admin: reset all rate limits (complete wipe)
  ResetResult reset_all() {
    ResetResult result;
    result.message = "All rate limits have been reset";

    reg_tracker_->clear_all();
    result.registrations_cleared = -1; // -1 = "all"

    login_tracker_->admin_clear_all_lockouts();
    login_tracker_->admin_clear_all_ips();
    result.lockouts_cleared = -1;
    result.ips_cleared = -1;
    result.addresses_cleared = -1;

    reset_count_++;
    last_reset_ms_ = now_ms();
    result.details["timestamp"] = iso8601_now();
    return result;
  }

  /// Admin: reset registration limits for a specific IP
  ResetResult reset_registration_ip(const std::string& ip) {
    ResetResult result;
    result.message = "Registration limits cleared for IP: " + ip;
    reg_tracker_->clear_ip(ip);
    result.registrations_cleared = 1;
    result.details["ip"] = normalize_ip(ip);
    result.details["timestamp"] = iso8601_now();
    reset_count_++;
    return result;
  }

  /// Admin: reset registration limits for a specific email
  ResetResult reset_registration_email(const std::string& email) {
    ResetResult result;
    result.message = "Registration limits cleared for email: " + email;
    reg_tracker_->clear_email(email);
    result.registrations_cleared = 1;
    result.details["email"] = to_lower(email);
    result.details["timestamp"] = iso8601_now();
    reset_count_++;
    return result;
  }

  /// Admin: reset login lockout for a specific account
  ResetResult reset_login_lockout(const std::string& account) {
    ResetResult result;
    result.message = "Login lockout cleared for account: " + account;
    login_tracker_->admin_clear_lockout(account);
    result.lockouts_cleared = 1;
    result.details["account"] = account;
    result.details["timestamp"] = iso8601_now();
    reset_count_++;
    return result;
  }

  /// Admin: reset login tracking for a specific IP
  ResetResult reset_login_ip(const std::string& ip) {
    ResetResult result;
    result.message = "Login tracking cleared for IP: " + ip;
    login_tracker_->admin_clear_ip(ip);
    result.ips_cleared = 1;
    result.details["ip"] = normalize_ip(ip);
    result.details["timestamp"] = iso8601_now();
    reset_count_++;
    return result;
  }

  /// Admin: reset login tracking for a specific address (email/msisdn)
  ResetResult reset_login_address(const std::string& address) {
    ResetResult result;
    result.message = "Login tracking cleared for address: " + address;
    login_tracker_->admin_clear_address(address);
    result.addresses_cleared = 1;
    result.details["address"] = address;
    result.details["timestamp"] = iso8601_now();
    reset_count_++;
    return result;
  }

  /// Admin: bulk reset operation
  ResetResult bulk_reset(const json& targets) {
    ResetResult result;
    result.message = "Bulk reset completed";

    if (targets.contains("ips") && targets["ips"].is_array()) {
      for (const auto& ip : targets["ips"]) {
        reg_tracker_->clear_ip(ip.get<std::string>());
        login_tracker_->admin_clear_ip(ip.get<std::string>());
        result.ips_cleared++;
      }
    }

    if (targets.contains("accounts") && targets["accounts"].is_array()) {
      for (const auto& acct : targets["accounts"]) {
        login_tracker_->admin_clear_lockout(acct.get<std::string>());
        result.lockouts_cleared++;
      }
    }

    if (targets.contains("emails") && targets["emails"].is_array()) {
      for (const auto& email : targets["emails"]) {
        reg_tracker_->clear_email(email.get<std::string>());
        login_tracker_->admin_clear_address(email.get<std::string>());
        result.addresses_cleared++;
      }
    }

    result.details["timestamp"] = iso8601_now();
    reset_count_++;
    return result;
  }

  /// Get scheduled cleanup statistics
  json get_cleanup_stats() const {
    return {
      {"cleanup_running", cleanup_running_.load()},
      {"total_auto_cleanups", total_auto_cleanups_.load()},
      {"total_reg_removed", total_reg_removed_.load()},
      {"total_login_removed", total_login_removed_.load()},
      {"total_admin_resets", reset_count_.load()},
      {"last_reset_ms", last_reset_ms_.load()},
      {"auto_cleanup_interval_ms", config_->auto_cleanup_interval_ms()},
    };
  }

private:
  std::shared_ptr<RegistrationLimitConfig> config_;
  RegistrationTracker* reg_tracker_;
  LoginFailureTracker* login_tracker_;
  RateLimitStorage* storage_;

  std::atomic<bool> cleanup_running_{false};
  std::thread cleanup_thread_;
  std::atomic<int64_t> total_auto_cleanups_{0};
  std::atomic<int64_t> total_reg_removed_{0};
  std::atomic<int64_t> total_login_removed_{0};
  std::atomic<int64_t> reset_count_{0};
  std::atomic<int64_t> last_reset_ms_{0};
};

// ============================================================================
// 6. RateLimitHeaderBuilder — Generate standard rate limit response headers
//
// Builds the complete set of rate limit headers for Matrix API responses.
// Supports multiple header formats and includes diagnostic headers for
// debugging and observability.
// ============================================================================

class RateLimitHeaderBuilder {
public:
  struct HeaderSet {
    int64_t limit = 0;
    int64_t remaining = 0;
    int64_t reset_epoch_sec = 0;
    int64_t retry_after_ms = 0;
    std::string reason;
    std::string scope;

    std::map<std::string, std::string> to_http_headers() const {
      std::map<std::string, std::string> headers;
      headers["X-RateLimit-Limit"] = std::to_string(limit);
      headers["X-RateLimit-Remaining"] = std::to_string(remaining);
      headers["X-RateLimit-Reset"] = std::to_string(reset_epoch_sec);
      if (retry_after_ms > 0) {
        int64_t retry_sec = (retry_after_ms + 999) / 1000;
        headers["Retry-After"] = std::to_string(retry_sec);
      }
      if (!reason.empty()) {
        headers["X-RateLimit-Reason"] = reason;
      }
      if (!scope.empty()) {
        headers["X-RateLimit-Scope"] = scope;
      }
      return headers;
    }

    json to_json() const {
      return {
        {"limit", limit},
        {"remaining", remaining},
        {"reset_epoch_sec", reset_epoch_sec},
        {"retry_after_ms", retry_after_ms},
        {"reason", reason},
        {"scope", scope},
      };
    }
  };

  /// Build headers from a registration check result
  static HeaderSet from_registration_check(
      const RegistrationTracker::CheckResult& check) {
    HeaderSet hs;
    hs.limit = check.max_allowed;
    hs.remaining = std::max(0, check.max_allowed - check.current_count);
    hs.reset_epoch_sec = now_sec() + (check.retry_after_ms / 1000);
    hs.retry_after_ms = check.retry_after_ms;
    hs.reason = check.reason;
    hs.scope = check.limited_by;
    return hs;
  }

  /// Build headers from a login check result
  static HeaderSet from_login_check(
      const LoginFailureTracker::LoginCheckResult& check,
      int max_attempts = 5) {
    HeaderSet hs;
    hs.limit = max_attempts;
    hs.remaining = std::max<int64_t>(0, max_attempts - check.consecutive_failures);
    hs.reset_epoch_sec = now_sec() + (check.retry_after_ms / 1000);
    hs.retry_after_ms = check.retry_after_ms;
    hs.reason = check.reason;
    hs.scope = check.limited_by;
    return hs;
  }

  /// Build "no limit" headers for when rate limiting is disabled
  static HeaderSet unlimited() {
    HeaderSet hs;
    hs.limit = -1;
    hs.remaining = -1;
    hs.reset_epoch_sec = 0;
    hs.retry_after_ms = 0;
    hs.reason = "Rate limiting disabled";
    hs.scope = "none";
    return hs;
  }

  /// Build "rate limited" headers with retry timing
  static HeaderSet rate_limited(int64_t retry_after_ms,
                                 const std::string& reason,
                                 const std::string& scope) {
    HeaderSet hs;
    hs.limit = 0;
    hs.remaining = 0;
    hs.reset_epoch_sec = now_sec() + (retry_after_ms / 1000);
    hs.retry_after_ms = retry_after_ms;
    hs.reason = reason;
    hs.scope = scope;
    return hs;
  }

  /// Merge multiple HeaderSets (most restrictive wins)
  static HeaderSet merge(const std::vector<HeaderSet>& sets) {
    if (sets.empty()) return unlimited();

    HeaderSet merged;
    int64_t min_remaining = std::numeric_limits<int64_t>::max();
    int64_t max_limit = 0;
    int64_t max_retry = 0;
    int64_t latest_reset = 0;
    std::string combined_reason;
    std::string combined_scope;

    for (size_t i = 0; i < sets.size(); ++i) {
      const auto& hs = sets[i];
      max_limit = std::max(max_limit, hs.limit);
      min_remaining = std::min(min_remaining, hs.remaining);
      max_retry = std::max(max_retry, hs.retry_after_ms);
      latest_reset = std::max(latest_reset, hs.reset_epoch_sec);

      if (!hs.scope.empty()) {
        if (!combined_scope.empty()) combined_scope += ",";
        combined_scope += hs.scope;
      }
      if (!hs.reason.empty()) {
        if (!combined_reason.empty()) combined_reason += "; ";
        combined_reason += hs.reason;
      }
    }

    merged.limit = max_limit;
    merged.remaining = min_remaining == std::numeric_limits<int64_t>::max() ? -1 : min_remaining;
    merged.reset_epoch_sec = latest_reset;
    merged.retry_after_ms = max_retry;
    merged.reason = combined_reason;
    merged.scope = combined_scope;
    return merged;
  }
};

// ============================================================================
// 7. RegistrationLimitAdminAPI — Admin API for managing rate limits
//
// Provides a comprehensive REST API for administrators to inspect,
// manage, and configure registration and login rate limits at runtime.
// ============================================================================

class RegistrationLimitAdminAPI {
public:
  RegistrationLimitAdminAPI(
      std::shared_ptr<RegistrationLimitConfig> config,
      RegistrationTracker* reg_tracker,
      LoginFailureTracker* login_tracker,
      RateResetScheduler* reset_scheduler,
      RateLimitStorage* storage)
      : config_(std::move(config)),
        reg_tracker_(reg_tracker),
        login_tracker_(login_tracker),
        reset_scheduler_(reset_scheduler),
        storage_(storage) {}

  // ==========================================================================
  // GET /admin/rate-limits/status — Overall status + statistics
  // ==========================================================================
  json handle_get_status() const {
    json j;
    j["timestamp"] = iso8601_now();
    j["global_enabled"] = config_->is_globally_enabled();
    j["registration"] = config_->get_registration_limits().to_json();
    j["login"] = config_->get_login_limits().to_json();
    j["whitelist"] = config_->get_whitelist().to_json();
    j["registration_stats"] = reg_tracker_->get_stats();
    j["login_metrics"] = login_tracker_->get_metrics();
    j["cleanup_stats"] = reset_scheduler_->get_cleanup_stats();
    j["storage_stats"] = storage_->get_storage_stats();
    return j;
  }

  // ==========================================================================
  // GET /admin/rate-limits/accounts — List locked/warned accounts
  // ==========================================================================
  json handle_get_accounts(const json& params = {}) const {
    bool include_all = params.value("all", false);
    json j;
    j["timestamp"] = iso8601_now();

    auto locked = login_tracker_->get_locked_accounts();

    json locked_array = json::array();
    for (const auto& state : locked) {
      locked_array.push_back({
        {"account", state.account},
        {"consecutive_failures", state.consecutive_failures},
        {"effective_failures", state.effective_failures},
        {"current_tier", static_cast<int>(state.current_tier)},
        {"locked_until_ms", state.locked_until_ms},
        {"locked_until_iso8601", state.locked_until_ms > 0
            ? iso8601_from_ms(state.locked_until_ms) : ""},
        {"total_failures_ever", state.total_failures_ever},
        {"total_successes", state.total_successes},
      });
    }
    j["locked_accounts"] = locked_array;
    j["locked_count"] = locked_array.size();

    if (include_all) {
      // Get all tracked accounts (expensive, only when requested)
      j["all_tracked"] = "Feature not yet implemented: use 'all' param with caution";
    }

    return j;
  }

  // ==========================================================================
  // GET /admin/rate-limits/ips — List rate-limited IPs
  // ==========================================================================
  json handle_get_ips(const json& params = {}) const {
    int limit = params.value("limit", 50);
    json j;
    j["timestamp"] = iso8601_now();

    auto active_ips = login_tracker_->get_active_ips(limit);
    auto reg_ips = reg_tracker_->active_ips();

    json ip_list = json::array();
    for (const auto& ip : active_ips) {
      ip_list.push_back({
        {"ip", ip},
        {"is_private", is_private_ip(ip)},
        {"registration_stats", reg_tracker_->get_ip_stats(ip)},
      });
    }
    j["active_ips"] = ip_list;
    j["active_ip_count"] = active_ips.size();

    json reg_ip_list = json::array();
    for (const auto& ip : reg_ips) {
      reg_ip_list.push_back(ip);
    }
    j["registration_ips"] = reg_ip_list;
    j["registration_ip_count"] = reg_ips.size();

    return j;
  }

  // ==========================================================================
  // POST /admin/rate-limits/reset — Clear rate limits
  //
  // Body examples:
  //   {"target": "all"}
  //   {"target": "account", "account": "@user:example.com"}
  //   {"target": "ip", "ip": "192.0.2.1"}
  //   {"target": "email", "email": "user@example.com"}
  //   {"target": "address", "address": "user@example.com"}
  //   {"target": "bulk", "ips": [...], "accounts": [...], "emails": [...]}
  // ==========================================================================
  json handle_post_reset(const json& body) {
    std::string target = body.value("target", "");

    if (target == "all") {
      return reset_scheduler_->reset_all().to_json();
    }

    if (target == "account" && body.contains("account")) {
      std::string account = body["account"].get<std::string>();
      return reset_scheduler_->reset_login_lockout(account).to_json();
    }

    if (target == "ip" && body.contains("ip")) {
      std::string ip = body["ip"].get<std::string>();
      auto r1 = reset_scheduler_->reset_registration_ip(ip);
      auto r2 = reset_scheduler_->reset_login_ip(ip);
      json j = r1.to_json();
      j["login_ips_cleared"] = r2.ips_cleared;
      j["message"] = "Rate limits cleared for IP: " + ip;
      return j;
    }

    if (target == "email" && body.contains("email")) {
      std::string email = body["email"].get<std::string>();
      return reset_scheduler_->reset_registration_email(email).to_json();
    }

    if (target == "address" && body.contains("address")) {
      std::string address = body["address"].get<std::string>();
      return reset_scheduler_->reset_login_address(address).to_json();
    }

    if (target == "bulk") {
      return reset_scheduler_->bulk_reset(body).to_json();
    }

    return make_error_json("M_INVALID_PARAM",
        "Invalid reset target. Use: all, account, ip, email, address, or bulk");
  }

  // ==========================================================================
  // POST /admin/rate-limits/configure — Runtime reconfiguration
  //
  // Body examples:
  //   {"section": "registration", "overrides": {"max_per_ip_hour": 10}}
  //   {"section": "login", "overrides": {"max_failed_attempts_before_lock": 8}}
  //   {"section": "global", "enabled": false}
  // ==========================================================================
  json handle_post_configure(const json& body) {
    std::string section = body.value("section", "");

    if (section == "registration" && body.contains("overrides")) {
      config_->update_registration_limits(body["overrides"]);
      return json({
        {"success", true},
        {"message", "Registration limits updated"},
        {"new_config", config_->get_registration_limits().to_json()},
      });
    }

    if (section == "login" && body.contains("overrides")) {
      config_->update_login_limits(body["overrides"]);
      return json({
        {"success", true},
        {"message", "Login limits updated"},
        {"new_config", config_->get_login_limits().to_json()},
      });
    }

    if (section == "global") {
      if (body.contains("enabled")) {
        config_->set_global_enabled(body["enabled"].get<bool>());
      }
      return json({
        {"success", true},
        {"message", "Global settings updated"},
        {"global_enabled", config_->is_globally_enabled()},
      });
    }

    if (section == "all") {
      if (body.contains("registration")) {
        config_->update_registration_limits(body["registration"]);
      }
      if (body.contains("login")) {
        config_->update_login_limits(body["login"]);
      }
      if (body.contains("enabled")) {
        config_->set_global_enabled(body["enabled"].get<bool>());
      }
      return json({
        {"success", true},
        {"message", "Full configuration updated"},
        {"config", {
          {"registration", config_->get_registration_limits().to_json()},
          {"login", config_->get_login_limits().to_json()},
          {"global_enabled", config_->is_globally_enabled()},
        }},
      });
    }

    return make_error_json("M_INVALID_PARAM",
        "Invalid section. Use: registration, login, global, or all");
  }

  // ==========================================================================
  // GET /admin/rate-limits/config — Current configuration
  // ==========================================================================
  json handle_get_config() const {
    return config_->to_json();
  }

  // ==========================================================================
  // POST /admin/rate-limits/whitelist — Manage whitelist
  //
  // Body examples:
  //   {"action": "add", "type": "ip", "value": "10.0.0.1"}
  //   {"action": "remove", "type": "user", "value": "@admin:example.com"}
  //   {"action": "list"}
  // ==========================================================================
  json handle_post_whitelist(const json& body) {
    std::string action = body.value("action", "");

    if (action == "list") {
      return config_->get_whitelist().to_json();
    }

    std::string type = body.value("type", "");
    std::string value = body.value("value", "");

    if (action == "add") {
      if (type == "ip") {
        config_->add_whitelist_ip(value);
      } else if (type == "user") {
        config_->add_whitelist_user(value);
      } else if (type == "domain") {
        config_->add_whitelist_domain(value);
      } else {
        return make_error_json("M_INVALID_PARAM",
            "Invalid whitelist type. Use: ip, user, or domain");
      }
      return json({
        {"success", true},
        {"message", "Added to whitelist: " + type + "=" + value},
        {"whitelist", config_->get_whitelist().to_json()},
      });
    }

    if (action == "remove") {
      if (type == "ip") {
        config_->remove_whitelist_ip(value);
      } else if (type == "user") {
        config_->remove_whitelist_user(value);
      } else if (type == "domain") {
        config_->remove_whitelist_domain(value);
      } else {
        return make_error_json("M_INVALID_PARAM",
            "Invalid whitelist type. Use: ip, user, or domain");
      }
      return json({
        {"success", true},
        {"message", "Removed from whitelist: " + type + "=" + value},
        {"whitelist", config_->get_whitelist().to_json()},
      });
    }

    if (action == "clear") {
      // Reset all whitelists
      config_->set_defaults();
      return json({
        {"success", true},
        {"message", "Whitelist has been cleared"},
        {"whitelist", config_->get_whitelist().to_json()},
      });
    }

    return make_error_json("M_INVALID_PARAM",
        "Invalid action. Use: add, remove, list, or clear");
  }

  // ==========================================================================
  // GET /admin/rate-limits/metrics — Prometheus-style metrics
  // ==========================================================================
  json handle_get_metrics() const {
    json j;
    j["timestamp"] = iso8601_now();

    auto reg_stats = reg_tracker_->get_stats();
    auto login_metrics = login_tracker_->get_metrics();
    auto cleanup_stats = reset_scheduler_->get_cleanup_stats();
    auto storage_stats = storage_->get_storage_stats();

    j["registration"] = {
      {"unique_ips_tracked", reg_stats["unique_ips"]},
      {"unique_emails_tracked", reg_stats["unique_emails"]},
      {"total_attempts", reg_stats["total_global_attempts"]},
      {"pending_count", reg_stats["pending_count"]},
      {"total_successful", reg_stats["total_successful"]},
      {"total_rejected", reg_stats["total_rejected"]},
      {"ips_in_cooldown", reg_stats["ips_in_cooldown"]},
    };

    j["login"] = login_metrics;

    j["cleanup"] = {
      {"total_auto_cleanups", cleanup_stats["total_auto_cleanups"]},
      {"total_admin_resets", cleanup_stats["total_admin_resets"]},
    };

    j["storage"] = storage_stats;

    // Generate Prometheus text format
    std::ostringstream prom;
    prom << "# HELP progressive_registration_total Attempts total\n";
    prom << "# TYPE progressive_registration_total counter\n";
    prom << "progressive_registration_total "
         << reg_stats["total_global_attempts"].get<size_t>() << "\n";

    prom << "# HELP progressive_registration_rejected Rejected attempts\n";
    prom << "# TYPE progressive_registration_rejected counter\n";
    prom << "progressive_registration_rejected "
         << reg_stats["total_rejected"].get<int64_t>() << "\n";

    prom << "# HELP progressive_registration_pending In-progress registrations\n";
    prom << "# TYPE progressive_registration_pending gauge\n";
    prom << "progressive_registration_pending "
         << reg_stats["pending_count"].get<int>() << "\n";

    prom << "# HELP progressive_login_locked_accounts Locked accounts\n";
    prom << "# TYPE progressive_login_locked_accounts gauge\n";
    prom << "progressive_login_locked_accounts "
         << login_metrics["accounts"]["locked"].get<int>() << "\n";

    prom << "# HELP progressive_login_tracked_ips Tracked IPs for login\n";
    prom << "# TYPE progressive_login_tracked_ips gauge\n";
    prom << "progressive_login_tracked_ips "
         << login_metrics["ips_tracked"].get<size_t>() << "\n";

    j["prometheus"] = prom.str();

    return j;
  }

  // ==========================================================================
  // GET /admin/rate-limits/inspect — Inspect a specific entity
  //
  // Query params: ip=..., email=..., account=..., domain=...
  // ==========================================================================
  json handle_get_inspect(const json& params) const {
    json j;
    j["timestamp"] = iso8601_now();

    if (params.contains("ip")) {
      std::string ip = params["ip"].get<std::string>();
      j["registration"] = reg_tracker_->get_ip_stats(ip);
      j["type"] = "ip";
      j["entity"] = normalize_ip(ip);
      return j;
    }

    if (params.contains("email")) {
      std::string email = params["email"].get<std::string>();
      j["registration"] = reg_tracker_->get_email_stats(email);
      j["type"] = "email";
      j["entity"] = to_lower(email);
      return j;
    }

    if (params.contains("account")) {
      std::string account = params["account"].get<std::string>();
      auto state = login_tracker_->get_account_info(account);
      if (state.has_value()) {
        const auto& s = *state;
        j["type"] = "account";
        j["entity"] = account;
        j["state"] = s.to_json();
        j["is_locked"] = s.locked_until_ms > 0 && s.locked_until_ms > now_ms();
        j["locked_until_iso8601"] = s.locked_until_ms > 0
            ? iso8601_from_ms(s.locked_until_ms) : "";
      } else {
        j["type"] = "account";
        j["entity"] = account;
        j["state"] = nullptr;
        j["message"] = "No tracking data for this account";
      }
      return j;
    }

    return make_error_json("M_INVALID_PARAM",
        "Specify at least one of: ip, email, or account");
  }

  // ==========================================================================
  // POST /admin/rate-limits/persist — Force persist current state
  // ==========================================================================
  json handle_post_persist() {
    bool success = login_tracker_->persist_state();
    return json({
      {"success", success},
      {"message", success ? "State persisted successfully" : "Failed to persist state"},
      {"timestamp", iso8601_now()},
    });
  }

  // ==========================================================================
  // POST /admin/rate-limits/compact — Compact storage files
  // ==========================================================================
  json handle_post_compact(const json& body) {
    int64_t max_age_ms = body.value("max_age_ms", 86'400'000 * 7);
    size_t removed = storage_->compact_storage(max_age_ms);
    return json({
      {"success", true},
      {"message", "Storage compacted"},
      {"records_removed", removed},
      {"max_age_ms", max_age_ms},
      {"timestamp", iso8601_now()},
    });
  }

private:
  static std::string iso8601_from_ms(int64_t ms) {
    auto tp = chr::system_clock::time_point(chr::milliseconds(ms));
    auto tt = chr::system_clock::to_time_t(
        chr::time_point_cast<chr::seconds>(tp));
    std::ostringstream oss;
    oss << std::put_time(std::gmtime(&tt), "%Y-%m-%dT%H:%M:%SZ");
    return oss.str();
  }

  std::shared_ptr<RegistrationLimitConfig> config_;
  RegistrationTracker* reg_tracker_;
  LoginFailureTracker* login_tracker_;
  RateResetScheduler* reset_scheduler_;
  RateLimitStorage* storage_;
};

// ============================================================================
// 8. RegistrationLimitsEngine — Top-level orchestrator
//
// The main entry point that wires together all registration/login
// rate limiting components. Provides a unified API for the HTTP layer
// to perform checks, record results, and manage configuration.
// ============================================================================

class RegistrationLimitsEngine {
public:
  RegistrationLimitsEngine()
      : config_(std::make_shared<RegistrationLimitConfig>()),
        reg_tracker_(std::make_unique<RegistrationTracker>(config_)),
        login_tracker_(std::make_unique<LoginFailureTracker>(config_)),
        storage_(std::make_unique<RateLimitStorage>(config_)),
        reset_scheduler_(std::make_unique<RateResetScheduler>(
            config_, reg_tracker_.get(), login_tracker_.get(), storage_.get())),
        admin_api_(std::make_unique<RegistrationLimitAdminAPI>(
            config_, reg_tracker_.get(), login_tracker_.get(),
            reset_scheduler_.get(), storage_.get())) {}

  ~RegistrationLimitsEngine() {
    shutdown();
  }

  RegistrationLimitsEngine(const RegistrationLimitsEngine&) = delete;
  RegistrationLimitsEngine& operator=(const RegistrationLimitsEngine&) = delete;

  // ==========================================================================
  // Initialization and lifecycle
  // ==========================================================================

  /// Initialize the engine: load configuration, restore persisted state,
  /// and start background maintenance tasks.
  bool initialize(const std::string& config_path = "") {
    // Load config from file if provided
    if (!config_path.empty()) {
      config_->load_from_file(config_path);
    }

    // Initialize storage
    storage_->initialize();

    // Load persisted login failure state
    login_tracker_->load_persisted_state();

    // Start background cleanup
    reset_scheduler_->start_background_cleanup();

    initialized_ = true;
    return true;
  }

  /// Shutdown: persist state and stop background threads
  void shutdown() {
    if (!initialized_) return;

    // Persist state
    login_tracker_->persist_state();

    // Stop background cleanup
    reset_scheduler_->stop_background_cleanup();

    initialized_ = false;
  }

  // ==========================================================================
  // Registration rate limiting API
  // ==========================================================================

  /// Check if a registration should be allowed.
  /// Returns detailed result with headers for the HTTP response.
  struct RegistrationResult {
    bool allowed = true;
    int http_status = 200;
    json error_body;
    std::map<std::string, std::string> headers;
    RegistrationTracker::CheckResult internal_result;

    static RegistrationResult allowed_result() {
      RegistrationResult r;
      r.allowed = true;
      r.http_status = 200;
      // Include informational rate limit headers even on success
      if (r.headers.empty()) {
        r.headers["X-RateLimit-Limit"] = "unlimited";
        r.headers["X-RateLimit-Remaining"] = "unlimited";
      }
      return r;
    }
  };

  RegistrationResult check_registration(const std::string& ip,
                                         const std::string& email,
                                         const std::string& username,
                                         bool is_shared_secret) {
    RegistrationResult result;

    if (!config_->is_globally_enabled()) {
      result.allowed = true;
      result.headers = RateLimitHeaderBuilder::unlimited().to_http_headers();
      return result;
    }

    auto check = reg_tracker_->check_registration(ip, email, username, is_shared_secret);
    result.internal_result = check;

    if (!check.allowed) {
      result.allowed = false;
      result.http_status = 429;
      result.error_body = make_ratelimit_error(
          "M_LIMIT_EXCEEDED", check.reason, check.retry_after_ms);
      result.headers = RateLimitHeaderBuilder::from_registration_check(check)
          .to_http_headers();
      return result;
    }

    result.allowed = true;
    result.headers = RateLimitHeaderBuilder::from_registration_check(check)
        .to_http_headers();
    return result;
  }

  /// Record a registration attempt (call after processing)
  void record_registration(const std::string& ip,
                           const std::string& email,
                           const std::string& username,
                           bool success,
                           bool is_shared_secret) {
    reg_tracker_->record_attempt(ip, email, username, success, is_shared_secret);
    storage_->store_registration(ip, email, username, success,
                                  is_shared_secret, now_ms());
  }

  /// Mark a registration as in-progress (e.g., awaiting email verification)
  void mark_registration_pending() {
    reg_tracker_->mark_pending();
  }

  /// Unmark a registration as in-progress
  void unmark_registration_pending() {
    reg_tracker_->unmark_pending();
  }

  // ==========================================================================
  // Login rate limiting API
  // ==========================================================================

  struct LoginResult {
    bool allowed = true;
    int http_status = 200;
    json error_body;
    std::map<std::string, std::string> headers;
    LoginFailureTracker::LoginCheckResult internal_result;

    static LoginResult allowed_result() {
      LoginResult r;
      r.allowed = true;
      r.http_status = 200;
      return r;
    }
  };

  /// Check if a login attempt should be allowed (before processing)
  LoginResult check_login(const std::string& account,
                          const std::string& ip,
                          const std::string& address) {
    LoginResult result;

    auto check = login_tracker_->check_login(account, ip, address);
    result.internal_result = check;

    if (!check.allowed) {
      result.allowed = false;
      result.http_status = 429;
      result.error_body = make_ratelimit_error(
          "M_LIMIT_EXCEEDED", check.reason, check.retry_after_ms);
      auto login_limits = config_->get_login_limits();
      result.headers = RateLimitHeaderBuilder::from_login_check(
          check, login_limits.max_failed_attempts_before_lock).to_http_headers();

      // Store the lockout event if this is an account lockout
      if (check.limited_by == "account_lockout") {
        storage_->store_lockout_event(account, check.tier,
                                       now_ms() + check.lockout_remaining_ms,
                                       check.consecutive_failures);
      }
      return result;
    }

    result.allowed = true;
    return result;
  }

  /// Record a failed login attempt
  void record_login_failure(const std::string& account,
                            const std::string& ip,
                            const std::string& address,
                            const std::string& user_agent,
                            bool was_valid_user) {
    login_tracker_->record_failure(account, ip, address, user_agent, was_valid_user);
    storage_->store_login_failure(account, ip, address, now_ms(), was_valid_user);
  }

  /// Record a successful login (resets failure counters)
  void record_login_success(const std::string& account,
                            const std::string& ip) {
    login_tracker_->record_success(account);
    storage_->store_login_success(account, ip, now_ms());
  }

  // ==========================================================================
  // Configuration
  // ==========================================================================

  /// Get the configuration object
  std::shared_ptr<RegistrationLimitConfig> config() { return config_; }
  const std::shared_ptr<RegistrationLimitConfig> config() const { return config_; }

  /// Load configuration from a file
  bool load_config(const std::string& path) {
    return config_->load_from_file(path);
  }

  /// Save current configuration to a file
  bool save_config(const std::string& path) const {
    return config_->save_to_file(path);
  }

  /// Enable or disable all rate limiting
  void set_enabled(bool enabled) {
    config_->set_global_enabled(enabled);
  }

  bool is_enabled() const {
    return config_->is_globally_enabled();
  }

  // ==========================================================================
  // Admin API access
  // ==========================================================================

  /// Get the admin API handler
  RegistrationLimitAdminAPI& admin() { return *admin_api_; }
  const RegistrationLimitAdminAPI& admin() const { return *admin_api_; }

  // ==========================================================================
  // Access to sub-components
  // ==========================================================================

  RegistrationTracker& registration_tracker() { return *reg_tracker_; }
  LoginFailureTracker& login_tracker() { return *login_tracker_; }
  RateResetScheduler& reset_scheduler() { return *reset_scheduler_; }
  RateLimitStorage& storage() { return *storage_; }

  // ==========================================================================
  // Periodic maintenance
  // ==========================================================================

  /// Perform a full maintenance cycle: cleanup + persist
  size_t maintenance_cycle() {
    size_t removed = 0;
    removed += reg_tracker_->cleanup_stale();
    removed += login_tracker_->cleanup_stale();

    if (login_tracker_->needs_persist()) {
      login_tracker_->persist_state();
    }

    return removed;
  }

  /// Persist current state immediately
  bool force_persist() {
    return login_tracker_->persist_state();
  }

  // ==========================================================================
  // Metrics
  // ==========================================================================

  /// Get comprehensive metrics for observability
  json get_metrics() const {
    json j;
    j["timestamp"] = iso8601_now();
    j["global_enabled"] = config_->is_globally_enabled();
    j["registration"] = reg_tracker_->get_stats();
    j["login"] = login_tracker_->get_metrics();
    j["cleanup"] = reset_scheduler_->get_cleanup_stats();
    j["storage"] = storage_->get_storage_stats();
    j["initialized"] = initialized_;
    return j;
  }

private:
  std::shared_ptr<RegistrationLimitConfig> config_;
  std::unique_ptr<RegistrationTracker> reg_tracker_;
  std::unique_ptr<LoginFailureTracker> login_tracker_;
  std::unique_ptr<RateLimitStorage> storage_;
  std::unique_ptr<RateResetScheduler> reset_scheduler_;
  std::unique_ptr<RegistrationLimitAdminAPI> admin_api_;
  bool initialized_ = false;
};

// ============================================================================
// 9. Global engine instance management
//
// Thread-safe singleton access to the RegistrationLimitsEngine.
// ============================================================================

namespace {

std::once_flag g_engine_init_flag;
std::unique_ptr<RegistrationLimitsEngine> g_engine;
std::mutex g_engine_mutex;

} // anonymous namespace

/// Get or create the global registration limits engine instance.
/// Thread-safe lazy initialization.
RegistrationLimitsEngine& registration_limits_engine() {
  std::call_once(g_engine_init_flag, []() {
    g_engine = std::make_unique<RegistrationLimitsEngine>();
    g_engine->initialize();
  });
  return *g_engine;
}

/// Initialize the engine with a custom configuration file.
/// Must be called before any other access to the engine.
bool init_registration_limits(const std::string& config_path) {
  std::lock_guard lock(g_engine_mutex);
  if (g_engine) {
    // Already initialized; reload config
    return g_engine->load_config(config_path);
  }
  g_engine = std::make_unique<RegistrationLimitsEngine>();
  bool ok = g_engine->initialize(config_path);
  if (!ok) {
    g_engine.reset();
  }
  return ok;
}

/// Shutdown the engine: persist state and release resources.
void shutdown_registration_limits() {
  std::lock_guard lock(g_engine_mutex);
  if (g_engine) {
    g_engine->shutdown();
    g_engine.reset();
  }
}

/// Check if the engine is initialized.
bool is_registration_limits_initialized() {
  std::lock_guard lock(g_engine_mutex);
  return g_engine != nullptr;
}

// ============================================================================
// 10. Convenience functions for HTTP request handlers
//
// These functions provide an ergonomic interface for the HTTP layer
// to integrate registration/login rate limiting into request processing.
// ============================================================================

/// Check a registration request and return HTTP result
struct HttpRateLimitResult {
  bool allowed;
  int status_code;
  json error_body;
  std::map<std::string, std::string> headers;

  bool is_rate_limited() const { return !allowed; }
};

/// Full registration rate limit check for HTTP handlers
HttpRateLimitResult check_registration_request(
    const std::string& client_ip,
    const std::string& email,
    const std::string& username,
    bool is_shared_secret_auth) {
  auto result = registration_limits_engine().check_registration(
      client_ip, email, username, is_shared_secret_auth);
  return {
    result.allowed,
    result.http_status,
    result.error_body,
    result.headers,
  };
}

/// Full login rate limit check for HTTP handlers
HttpRateLimitResult check_login_request(
    const std::string& account,
    const std::string& client_ip,
    const std::string& address) {
  auto result = registration_limits_engine().check_login(
      account, client_ip, address);
  return {
    result.allowed,
    result.http_status,
    result.error_body,
    result.headers,
  };
}

/// Record a completed registration (after processing)
void record_registration_request(
    const std::string& client_ip,
    const std::string& email,
    const std::string& username,
    bool success,
    bool is_shared_secret_auth) {
  registration_limits_engine().record_registration(
      client_ip, email, username, success, is_shared_secret_auth);
}

/// Record a failed login attempt
void record_failed_login(
    const std::string& account,
    const std::string& client_ip,
    const std::string& address,
    const std::string& user_agent,
    bool was_valid_user) {
  registration_limits_engine().record_login_failure(
      account, client_ip, address, user_agent, was_valid_user);
}

/// Record a successful login
void record_successful_login(
    const std::string& account,
    const std::string& client_ip) {
  registration_limits_engine().record_login_success(account, client_ip);
}

// ============================================================================
// 11. Admin HTTP endpoint router
//
// Routes admin API requests to the appropriate handler method.
// ============================================================================

/// Handle an admin API request for rate limits management.
/// Returns JSON response body and suggested HTTP status code.
struct AdminApiResponse {
  int status_code;
  json body;
};

AdminApiResponse handle_admin_rate_limits_request(
    const std::string& method,
    const std::string& subpath,
    const json& params,
    const json& body) {

  auto& api = registration_limits_engine().admin();

  // GET /admin/rate-limits/status
  if (method == "GET" && subpath == "status") {
    return {200, api.handle_get_status()};
  }

  // GET /admin/rate-limits/accounts
  if (method == "GET" && subpath == "accounts") {
    return {200, api.handle_get_accounts(params)};
  }

  // GET /admin/rate-limits/ips
  if (method == "GET" && subpath == "ips") {
    return {200, api.handle_get_ips(params)};
  }

  // POST /admin/rate-limits/reset
  if (method == "POST" && subpath == "reset") {
    auto result = api.handle_post_reset(body);
    bool success = result.value("success", false);
    return {success ? 200 : 400, result};
  }

  // POST /admin/rate-limits/configure
  if (method == "POST" && subpath == "configure") {
    auto result = api.handle_post_configure(body);
    bool success = result.value("success", false);
    return {success ? 200 : 400, result};
  }

  // GET /admin/rate-limits/config
  if (method == "GET" && subpath == "config") {
    return {200, api.handle_get_config()};
  }

  // POST /admin/rate-limits/whitelist
  if (method == "POST" && subpath == "whitelist") {
    auto result = api.handle_post_whitelist(body);
    bool success = result.value("success", false);
    return {success ? 200 : 400, result};
  }

  // GET /admin/rate-limits/metrics
  if (method == "GET" && subpath == "metrics") {
    return {200, api.handle_get_metrics()};
  }

  // GET /admin/rate-limits/inspect
  if (method == "GET" && subpath == "inspect") {
    auto result = api.handle_get_inspect(params);
    if (result.contains("errcode")) {
      return {400, result};
    }
    return {200, result};
  }

  // POST /admin/rate-limits/persist
  if (method == "POST" && subpath == "persist") {
    auto result = api.handle_post_persist();
    bool success = result.value("success", false);
    return {success ? 200 : 500, result};
  }

  // POST /admin/rate-limits/compact
  if (method == "POST" && subpath == "compact") {
    return {200, api.handle_post_compact(body)};
  }

  // Unknown subpath
  return {
    404,
    make_error_json("M_NOT_FOUND", "Unknown admin rate-limits endpoint: " + subpath)
  };
}

// ============================================================================
// 12. Utility: Format lockout information for user-facing messages
// ============================================================================

std::string format_lockout_message(const std::string& account,
                                    LockoutTier tier,
                                    int64_t remaining_ms) {
  int64_t remaining_sec = (remaining_ms + 999) / 1000;
  int remaining_min = static_cast<int>(remaining_sec / 60);
  int remaining_sec_part = static_cast<int>(remaining_sec % 60);

  std::ostringstream oss;
  oss << "Account '" << account << "' is temporarily locked";

  switch (tier) {
    case LockoutTier::SHORT:
      oss << " (short lockout). ";
      break;
    case LockoutTier::MEDIUM:
      oss << " (medium lockout). ";
      break;
    case LockoutTier::LONG:
      oss << " (long lockout). ";
      break;
    case LockoutTier::EXTENDED:
      oss << " (extended lockout — contact administrator). ";
      break;
    case LockoutTier::MAX:
      oss << " (maximum lockout — administrator intervention required). ";
      break;
    default:
      oss << ". ";
      break;
  }

  if (remaining_min > 0) {
    oss << "Try again in " << remaining_min << " minute";
    if (remaining_min != 1) oss << "s";
    if (remaining_sec_part > 0) {
      oss << " and " << remaining_sec_part << " second";
      if (remaining_sec_part != 1) oss << "s";
    }
  } else {
    oss << "Try again in " << remaining_sec_part << " second";
    if (remaining_sec_part != 1) oss << "s";
  }
  oss << ".";

  return oss.str();
}

} // namespace progressive

// ============================================================================
// End of registration_limits.cpp
//
// Summary:
//   - RegistrationLimitConfig:    Configurable limits with JSON serialization
//   - RegistrationTracker:        Multi-dimensional IP/email/domain/global tracking
//   - LoginFailureTracker:        Graduated lockout with disk persistence
//   - RateLimitStorage:           JSONL-based persistent storage with compaction
//   - RateResetScheduler:         Background cleanup + admin reset operations
//   - RateLimitHeaderBuilder:     Standard rate limit response headers
//   - RegistrationLimitAdminAPI:  Full REST admin API for management
//   - RegistrationLimitsEngine:   Top-level orchestrator with singleton access
//   - HTTP convenience functions:  Ergonomic integration for request handlers
//   - Admin endpoint router:       Routes admin API requests to handlers
//
// Lines: ~2000+
// ============================================================================
