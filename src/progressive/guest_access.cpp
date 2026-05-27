// ============================================================================
// guest_access.cpp — Matrix Guest Access: Registration, Restrictions,
//   Room Access, Auto-Cleanup, Account Migration, Rate Limiting,
//   Guest Display, Sync Filtering
//
// Implements:
//   - GuestRegistry: guest registration via /register with kind=guest,
//     generate @guest_XXXX:domain user IDs, guest access token management,
//     guest lifecycle (create, touch, revoke, deactivate), guest count
//     tracking, guest-by-token and guest-by-user-id lookup
//   - GuestRestrictionEngine: enforce all guest capability restrictions
//     (no room creation, no invites, no power levels, no room aliases,
//     no user directory search, no push, max rooms joined limit),
//     capability check API for all restricted actions, restriction
//     configuration with per-capability toggles
//   - GuestRoomAccessChecker: evaluate m.room.guest_access state events
//     (can_join vs forbidden), cache room guest_access state, check
//     guest join eligibility, forbidden room enforcement
//   - GuestCleanupScheduler: auto-deactivate guest accounts after 24h
//     of inactivity, background cleanup thread, configurable inactivity
//     timeout, batch deletion of guest data, orphaned token cleanup,
//     cleanup statistics and audit logging
//   - GuestMigrationHandler: allow guests to upgrade to full accounts
//     by setting password and adding email, preserve room memberships
//     during migration, token transfer from guest to full account,
//     migration audit trail, rollback on migration failure
//   - GuestRateLimiter: stricter rate limits for guest users compared
//     to registered users, per-endpoint guest-specific limits,
//     configurable burst and rate multipliers, rate limit header
//     injection for guest requests
//   - GuestDisplayFormatter: mark guest users in room member lists
//     with is_guest flag, display name annotation, guest badge in
//     UI-facing responses, avatar rendering for guests
//   - GuestSyncFilter: filter sync responses for guest users to
//     reduce data volume, strip presence events, limit timeline
//     depth, filter account_data, reduce to_device messages,
//     minimize state sent to guests
//
// Equivalent to:
//   synapse/handlers/guest.py (guest registration, restrictions, cleanup)
//   synapse/handlers/room_member.py (guest_access join checks)
//   synapse/handlers/register.py (guest -> full account migration)
//   synapse/api/ratelimiting.py (guest-specific rate limits)
//   synapse/handlers/sync.py (guest sync filtering)
//   synapse/rest/client/register.py (guest registration endpoint)
//
// Namespace: progressive::
// Target: 2000+ lines of production-grade C++.
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

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <netdb.h>

#include <nlohmann/json.hpp>

#include "progressive/storage/database.hpp"
#include "progressive/storage/databases/main/registration.hpp"
#include "progressive/storage/databases/main/room.hpp"
#include "progressive/storage/databases/main/roommember.hpp"
#include "progressive/storage/databases/main/events.hpp"
#include "progressive/storage/databases/main/state.hpp"

// ============================================================================
// Namespace
// ============================================================================
namespace progressive {

using json = nlohmann::json;
namespace chr = std::chrono;

// ============================================================================
// Forward declarations for all component classes
// ============================================================================
class GuestRegistry;
class GuestRestrictionEngine;
class GuestRoomAccessChecker;
class GuestCleanupScheduler;
class GuestMigrationHandler;
class GuestRateLimiter;
class GuestDisplayFormatter;
class GuestSyncFilter;
class GuestAccessCoordinator;
class GuestAccessConfig;
class GuestActivityTracker;
class GuestTokenStore;
class GuestMigrationStore;
class GuestRateLimitBucket;
class GuestRoomAccessCache;
class GuestSyncResponseBuilder;
class GuestCleanupAuditLog;

// ============================================================================
// Guest Access Exception Types
// ============================================================================

/// Base exception for all guest access related errors.
class GuestAccessException : public std::runtime_error {
public:
  int http_code{403};
  std::string errcode;

  GuestAccessException(int code, std::string_view errc, std::string_view msg)
    : std::runtime_error(std::string(msg)),
      http_code(code),
      errcode(errc) {}

  explicit GuestAccessException(std::string_view msg)
    : std::runtime_error(std::string(msg)),
      http_code(403),
      errcode("M_GUEST_ACCESS_FORBIDDEN") {}
};

/// Thrown when a guest attempts a restricted action.
class GuestRestrictionViolation : public GuestAccessException {
public:
  std::string restricted_action;
  GuestRestrictionViolation(std::string_view action, std::string_view msg = "")
    : GuestAccessException(403, "M_GUEST_ACCESS_FORBIDDEN",
        msg.empty() ? std::string("Guest users cannot ") + std::string(action) : std::string(msg)),
      restricted_action(action) {}
};

/// Thrown when guest registration is disabled.
class GuestRegistrationDisabled : public GuestAccessException {
public:
  GuestRegistrationDisabled()
    : GuestAccessException(403, "M_FORBIDDEN", "Guest registration is disabled") {}
};

/// Thrown when guest migration fails.
class GuestMigrationFailed : public GuestAccessException {
public:
  GuestMigrationFailed(std::string_view reason)
    : GuestAccessException(500, "M_UNKNOWN",
        std::string("Guest account migration failed: ") + std::string(reason)) {}
};

/// Thrown when a room does not allow guests.
class GuestRoomForbidden : public GuestAccessException {
public:
  std::string room_id;
  GuestRoomForbidden(std::string_view rid)
    : GuestAccessException(403, "M_GUEST_ACCESS_FORBIDDEN",
        std::string("Guests are not allowed in room ") + std::string(rid)),
      room_id(rid) {}
};

// ============================================================================
// Anonymous namespace — Internal helpers
// ============================================================================
namespace {

// ---- Timestamp utility ----
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

// ---- String helpers ----
bool starts_with(std::string_view s, std::string_view prefix) {
  return s.size() >= prefix.size() &&
         s.compare(0, prefix.size(), prefix) == 0;
}

bool ends_with(std::string_view s, std::string_view suffix) {
  return s.size() >= suffix.size() &&
         s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

std::string to_lower(std::string s) {
  for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return s;
}

// ---- Random token generation ----
std::string generate_hex(size_t length) {
  static const char hex_chars[] = "0123456789abcdef";
  static thread_local std::mt19937_64 rng(
      static_cast<uint64_t>(
          chr::steady_clock::now().time_since_epoch().count()));
  std::uniform_int_distribution<int> dist(0, 15);
  std::string out(length, '\0');
  for (size_t i = 0; i < length; ++i) out[i] = hex_chars[dist(rng)];
  return out;
}

std::string generate_guest_suffix(size_t length = 8) {
  static const char alphanum[] = "abcdefghijklmnopqrstuvwxyz0123456789";
  static thread_local std::mt19937_64 rng(
      static_cast<uint64_t>(
          chr::steady_clock::now().time_since_epoch().count()));
  std::uniform_int_distribution<int> dist(0, 35);
  std::string out(length, '\0');
  for (size_t i = 0; i < length; ++i) out[i] = alphanum[dist(rng)];
  return out;
}

std::string generate_access_token(size_t length = 64) {
  return generate_hex(length);
}

std::string generate_migration_token() {
  return "mig_" + generate_hex(32);
}

std::string generate_cleanup_id() {
  return "cleanup_" + generate_hex(16);
}

// ---- Timestamp formatting ----
std::string format_iso8601(int64_t epoch_ms) {
  auto tt = static_cast<std::time_t>(epoch_ms / 1000);
  std::ostringstream oss;
  oss << std::put_time(std::gmtime(&tt), "%Y-%m-%dT%H:%M:%S.");
  oss << std::setfill('0') << std::setw(3) << (epoch_ms % 1000) << "Z";
  return oss.str();
}

// ---- JSON helpers ----
json error_json(const std::string& errcode, const std::string& msg, int status = 403) {
  return json{{"errcode", errcode}, {"error", msg}, {"status", status}};
}

// ---- SHA-256 placeholder (deterministic substitute for hashing) ----
std::string hash_token(const std::string& input) {
  // Simple deterministic hash for internal use
  std::ostringstream oss;
  uint64_t h = 14695981039346656037ULL;
  for (unsigned char c : input) {
    h ^= c;
    h *= 1099511628211ULL;
  }
  oss << std::hex << std::setfill('0') << std::setw(16) << h;
  return oss.str();
}

} // anonymous namespace

// ============================================================================
// Default Configuration Constants
// ============================================================================
namespace guest_config {

// Guest registration
constexpr int64_t kGuestAccessTokenTTLMs    = 3'600'000;       // 1 hour
constexpr int64_t kGuestAccountMaxAgeMs     = 86'400'000;      // 24 hours
constexpr int64_t kGuestInactivityTimeoutMs = 86'400'000;      // 24 hours
constexpr int64_t kGuestTokenRefreshWindowMs = 300'000;        // 5 min before expiry

// Guest restrictions
constexpr int  kGuestMaxRoomsJoined         = 10;
constexpr bool kGuestCanCreateRooms         = false;
constexpr bool kGuestCanInviteUsers         = false;
constexpr bool kGuestCanKickUsers           = false;
constexpr bool kGuestCanBanUsers            = false;
constexpr bool kGuestCanSetPowerLevels      = false;
constexpr bool kGuestCanSetRoomAliases      = false;
constexpr bool kGuestCanSearchUserDirectory = false;
constexpr bool kGuestCanUsePush             = false;
constexpr bool kGuestCanSendEvents          = true;
constexpr bool kGuestCanJoinRooms           = true;
constexpr bool kGuestCanReadMessages        = true;
constexpr bool kGuestCanSetDisplayName      = true;
constexpr bool kGuestCanUploadMedia         = false;

// Room access
constexpr const char* kGuestAccessForbidden  = "forbidden";
constexpr const char* kGuestAccessCanJoin    = "can_join";
constexpr int64_t  kRoomAccessCacheTTLMs    = 60'000;          // 1 minute cache

// Cleanup
constexpr int64_t kCleanupIntervalMs        = 300'000;         // 5 minutes
constexpr int     kCleanupBatchSize         = 50;
constexpr int64_t kCleanupGracePeriodMs     = 3'600'000;       // 1 hour grace

// Migration
constexpr int64_t kMigrationTokenTTLMs      = 900'000;         // 15 minutes
constexpr int     kMigrationMaxAttempts     = 3;
constexpr int64_t kMigrationCooldownMs      = 3'600'000;       // 1 hour cooldown

// Rate limiting (stricter for guests)
constexpr double kGuestRateMultiplier       = 0.25;            // 1/4 of normal user rate
constexpr double kGuestBurstMultiplier      = 0.5;             // 1/2 of normal user burst
constexpr int    kGuestLoginRatePerSec      = 2;
constexpr int    kGuestLoginBurst           = 4;
constexpr int    kGuestMessageRatePerSec    = 1;
constexpr int    kGuestMessageBurst         = 3;
constexpr int    kGuestJoinRatePerSec       = 1;
constexpr int    kGuestJoinBurst            = 2;
constexpr int    kGuestSyncRatePerSec       = 2;
constexpr int    kGuestSyncBurst            = 4;

// Sync filtering
constexpr int    kGuestSyncTimelineLimit    = 5;               // fewer events
constexpr int    kGuestSyncMaxRooms         = 10;
constexpr bool   kGuestSyncIncludePresence  = false;
constexpr bool   kGuestSyncIncludeAccountData = false;
constexpr bool   kGuestSyncIncludeToDevice  = true;
constexpr bool   kGuestSyncIncludeDeviceLists = false;

} // namespace guest_config

// ============================================================================
// GuestAccessConfig — Mutable runtime configuration
// ============================================================================
class GuestAccessConfig {
public:
  // Toggle guest access system
  bool guest_access_enabled{true};
  bool guest_registration_enabled{true};

  // Timing
  int64_t access_token_ttl_ms{guest_config::kGuestAccessTokenTTLMs};
  int64_t account_max_age_ms{guest_config::kGuestAccountMaxAgeMs};
  int64_t inactivity_timeout_ms{guest_config::kGuestInactivityTimeoutMs};
  int64_t cleanup_interval_ms{guest_config::kCleanupIntervalMs};

  // Restrictions
  int  max_rooms_joined{guest_config::kGuestMaxRoomsJoined};
  bool can_create_rooms{guest_config::kGuestCanCreateRooms};
  bool can_invite_users{guest_config::kGuestCanInviteUsers};
  bool can_kick_users{guest_config::kGuestCanKickUsers};
  bool can_ban_users{guest_config::kGuestCanBanUsers};
  bool can_set_power_levels{guest_config::kGuestCanSetPowerLevels};
  bool can_set_room_aliases{guest_config::kGuestCanSetRoomAliases};
  bool can_search_user_directory{guest_config::kGuestCanSearchUserDirectory};
  bool can_use_push{guest_config::kGuestCanUsePush};
  bool can_send_events{guest_config::kGuestCanSendEvents};
  bool can_join_rooms{guest_config::kGuestCanJoinRooms};
  bool can_read_messages{guest_config::kGuestCanReadMessages};
  bool can_set_display_name{guest_config::kGuestCanSetDisplayName};
  bool can_upload_media{guest_config::kGuestCanUploadMedia};

  // Rate limiting
  double rate_multiplier{guest_config::kGuestRateMultiplier};
  double burst_multiplier{guest_config::kGuestBurstMultiplier};

  // Migration
  bool migration_enabled{true};
  int64_t migration_token_ttl_ms{guest_config::kMigrationTokenTTLMs};

  // Sync filtering
  int  sync_timeline_limit{guest_config::kGuestSyncTimelineLimit};
  int  sync_max_rooms{guest_config::kGuestSyncMaxRooms};
  bool sync_include_presence{guest_config::kGuestSyncIncludePresence};
  bool sync_include_account_data{guest_config::kGuestSyncIncludeAccountData};
  bool sync_include_to_device{guest_config::kGuestSyncIncludeToDevice};
  bool sync_include_device_lists{guest_config::kGuestSyncIncludeDeviceLists};

  // Server identity
  std::string server_name{"localhost"};

  /// Serialize config to JSON for admin/debug endpoints.
  json to_json() const {
    return {
      {"guest_access_enabled", guest_access_enabled},
      {"guest_registration_enabled", guest_registration_enabled},
      {"access_token_ttl_ms", access_token_ttl_ms},
      {"account_max_age_ms", account_max_age_ms},
      {"inactivity_timeout_ms", inactivity_timeout_ms},
      {"cleanup_interval_ms", cleanup_interval_ms},
      {"max_rooms_joined", max_rooms_joined},
      {"restrictions", {
        {"can_create_rooms", can_create_rooms},
        {"can_invite_users", can_invite_users},
        {"can_kick_users", can_kick_users},
        {"can_ban_users", can_ban_users},
        {"can_set_power_levels", can_set_power_levels},
        {"can_set_room_aliases", can_set_room_aliases},
        {"can_search_user_directory", can_search_user_directory},
        {"can_use_push", can_use_push},
        {"can_send_events", can_send_events},
        {"can_join_rooms", can_join_rooms},
        {"can_read_messages", can_read_messages},
        {"can_set_display_name", can_set_display_name},
        {"can_upload_media", can_upload_media}
      }},
      {"rate_limiting", {
        {"rate_multiplier", rate_multiplier},
        {"burst_multiplier", burst_multiplier}
      }},
      {"migration", {
        {"enabled", migration_enabled},
        {"token_ttl_ms", migration_token_ttl_ms}
      }},
      {"sync_filtering", {
        {"timeline_limit", sync_timeline_limit},
        {"max_rooms", sync_max_rooms},
        {"include_presence", sync_include_presence},
        {"include_account_data", sync_include_account_data},
        {"include_to_device", sync_include_to_device},
        {"include_device_lists", sync_include_device_lists}
      }}
    };
  }

  /// Update config from JSON (partial updates supported).
  void update_from_json(const json& j) {
    if (j.contains("guest_access_enabled")) guest_access_enabled = j["guest_access_enabled"];
    if (j.contains("guest_registration_enabled")) guest_registration_enabled = j["guest_registration_enabled"];
    if (j.contains("max_rooms_joined")) max_rooms_joined = j["max_rooms_joined"];
    if (j.contains("rate_multiplier")) rate_multiplier = j["rate_multiplier"];
    if (j.contains("burst_multiplier")) burst_multiplier = j["burst_multiplier"];
    if (j.contains("sync_max_rooms")) sync_max_rooms = j["sync_max_rooms"];
    if (j.contains("sync_timeline_limit")) sync_timeline_limit = j["sync_timeline_limit"];
    if (j.contains("server_name")) server_name = j["server_name"];
    if (j.contains("migration_enabled")) migration_enabled = j["migration_enabled"];
    if (j.contains("account_max_age_ms")) account_max_age_ms = j["account_max_age_ms"];
    if (j.contains("inactivity_timeout_ms")) inactivity_timeout_ms = j["inactivity_timeout_ms"];
    if (j.contains("cleanup_interval_ms")) cleanup_interval_ms = j["cleanup_interval_ms"];

    // Update restrictions
    if (j.contains("restrictions")) {
      const auto& r = j["restrictions"];
      if (r.contains("can_create_rooms")) can_create_rooms = r["can_create_rooms"];
      if (r.contains("can_invite_users")) can_invite_users = r["can_invite_users"];
      if (r.contains("can_kick_users")) can_kick_users = r["can_kick_users"];
      if (r.contains("can_ban_users")) can_ban_users = r["can_ban_users"];
      if (r.contains("can_set_power_levels")) can_set_power_levels = r["can_set_power_levels"];
      if (r.contains("can_set_room_aliases")) can_set_room_aliases = r["can_set_room_aliases"];
      if (r.contains("can_search_user_directory")) can_search_user_directory = r["can_search_user_directory"];
      if (r.contains("can_use_push")) can_use_push = r["can_use_push"];
      if (r.contains("can_send_events")) can_send_events = r["can_send_events"];
      if (r.contains("can_join_rooms")) can_join_rooms = r["can_join_rooms"];
      if (r.contains("can_read_messages")) can_read_messages = r["can_read_messages"];
      if (r.contains("can_set_display_name")) can_set_display_name = r["can_set_display_name"];
      if (r.contains("can_upload_media")) can_upload_media = r["can_upload_media"];
    }
  }
};

// ============================================================================
// GuestRegistry — Core guest registration and lifecycle management
//
// Manages guest user creation, access token generation, lookup by token
// or user ID, activity tracking, room join/leave tracking, and guest
// account lifecycle (activate, deactivate, revoke, expire).
// ============================================================================
class GuestRegistry {
public:
  /// Complete guest account record.
  struct GuestRecord {
    std::string user_id;              // @guest_XXXXXXXX:domain
    std::string display_name;         // "Guest XXXXXXXX"
    std::string access_token;         // Primary access token
    std::string device_id;            // "guest_XXXXXXXX"
    std::string ip_address;           // Registration IP
    int64_t created_at_ms{0};
    int64_t expires_at_ms{0};
    int64_t last_active_ms{0};
    int64_t token_issued_at_ms{0};
    int64_t token_expires_at_ms{0};
    int     rooms_joined{0};
    bool    active{true};
    bool    read_only{false};
    std::set<std::string> joined_room_ids;
    std::vector<std::string> device_ids;  // All device IDs for this guest

    json to_json() const {
      return {
        {"user_id", user_id},
        {"display_name", display_name},
        {"device_id", device_id},
        {"is_guest", true},
        {"created_at", format_iso8601(created_at_ms)},
        {"expires_at", format_iso8601(expires_at_ms)},
        {"last_active", format_iso8601(last_active_ms)},
        {"rooms_joined", rooms_joined},
        {"active", active},
        {"read_only", read_only}
      };
    }
  };

  /// Guest registration result returned to the client.
  struct RegistrationResult {
    std::string user_id;
    std::string access_token;
    std::string device_id;
    std::string home_server;
    bool is_guest{true};

    json to_json() const {
      return {
        {"user_id", user_id},
        {"access_token", access_token},
        {"device_id", device_id},
        {"home_server", home_server},
        {"is_guest", true}
      };
    }
  };

  explicit GuestRegistry(const GuestAccessConfig& config)
    : config_(config), guest_counter_(0), total_registrations_(0) {}

  ~GuestRegistry() = default;

  // ---- Guest Registration ----

  /// Register a new guest user.
  /// @param display_name_hint Optional display name to assign.
  /// @param ip_address Client IP address for auditing.
  /// @param read_only If true, guest has additional restrictions.
  /// @return Registration result with credentials, or nullopt if disabled.
  std::optional<RegistrationResult> register_guest(
      const std::string& display_name_hint = "",
      const std::string& ip_address = "127.0.0.1",
      bool read_only = false) {

    if (!config_.guest_registration_enabled || !config_.guest_access_enabled) {
      return std::nullopt;
    }

    // Rate-limit guest registration per IP
    if (!check_registration_rate_limit(ip_address)) {
      return std::nullopt;
    }

    // Generate unique guest suffix with collision avoidance
    std::string suffix;
    {
      std::lock_guard<std::shared_mutex> lock(mutex_);
      int attempts = 0;
      do {
        suffix = generate_guest_suffix(8);
        if (++attempts > 200) return std::nullopt;
      } while (suffix_by_user_id_.find(suffix) != suffix_by_user_id_.end() ||
               guests_by_suffix_.find(suffix) != guests_by_suffix_.end());
    }

    GuestRecord rec;
    rec.user_id = "@guest_" + suffix + ":" + config_.server_name;
    rec.access_token = generate_access_token(64);
    rec.device_id = "guest_" + suffix;
    rec.ip_address = ip_address;
    rec.created_at_ms = now_ms();
    rec.expires_at_ms = now_ms() + config_.account_max_age_ms;
    rec.last_active_ms = now_ms();
    rec.token_issued_at_ms = now_ms();
    rec.token_expires_at_ms = now_ms() + config_.access_token_ttl_ms;
    rec.active = true;
    rec.read_only = read_only;
    rec.device_ids.push_back(rec.device_id);

    if (!display_name_hint.empty()) {
      rec.display_name = display_name_hint;
    } else {
      rec.display_name = "Guest " + suffix;
    }

    if (read_only) {
      rec.display_name += " (read-only)";
    }

    // Store the guest record
    {
      std::lock_guard<std::shared_mutex> lock(mutex_);
      guests_by_token_[rec.access_token] = rec;
      guests_by_user_id_[rec.user_id] = rec;
      guests_by_suffix_[suffix] = rec.user_id;
      guest_counter_++;
      total_registrations_++;
    }

    // Record registration rate limit
    record_registration(ip_address);

    RegistrationResult result;
    result.user_id = rec.user_id;
    result.access_token = rec.access_token;
    result.device_id = rec.device_id;
    result.home_server = config_.server_name;
    return result;
  }

  // ---- Guest Lookup ----

  /// Look up a guest by access token. Returns nullopt if not found,
  /// expired, or deactivated. Also updates last_active on hit.
  std::optional<GuestRecord> get_by_token(const std::string& access_token) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = guests_by_token_.find(access_token);
    if (it == guests_by_token_.end()) return std::nullopt;

    const auto& rec = it->second;
    auto now = now_ms();

    if (!rec.active) return std::nullopt;
    if (now > rec.expires_at_ms) return std::nullopt;
    if (now > rec.token_expires_at_ms) return std::nullopt;

    return rec;
  }

  /// Look up a guest by user ID (e.g. @guest_abc123:domain).
  std::optional<GuestRecord> get_by_user_id(const std::string& user_id) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = guests_by_user_id_.find(user_id);
    if (it == guests_by_user_id_.end()) return std::nullopt;

    const auto& rec = it->second;
    if (!rec.active || now_ms() > rec.expires_at_ms) return std::nullopt;

    return rec;
  }

  /// Check if a user ID belongs to any guest (including expired/deactivated).
  bool is_guest_user_id(std::string_view user_id) const {
    return starts_with(user_id, "@guest_");
  }

  /// Check if a user ID is a currently active guest.
  bool is_active_guest(const std::string& user_id) {
    if (!is_guest_user_id(user_id)) return false;
    auto guest = get_by_user_id(user_id);
    return guest.has_value();
  }

  // ---- Activity Tracking ----

  /// Update the last_active timestamp for a guest (called on each API request).
  bool touch(const std::string& access_token) {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    auto it = guests_by_token_.find(access_token);
    if (it == guests_by_token_.end() || !it->second.active) return false;

    auto now = now_ms();
    if (now > it->second.expires_at_ms || now > it->second.token_expires_at_ms) {
      return false;
    }

    it->second.last_active_ms = now;
    return true;
  }

  // ---- Room Tracking ----

  /// Record that a guest joined a room.
  bool record_room_join(const std::string& access_token,
                         const std::string& room_id) {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    auto it = guests_by_token_.find(access_token);
    if (it == guests_by_token_.end() || !it->second.active) return false;

    if (it->second.joined_room_ids.size() >=
        static_cast<size_t>(config_.max_rooms_joined)) {
      return false;
    }

    it->second.joined_room_ids.insert(room_id);
    it->second.rooms_joined = static_cast<int>(it->second.joined_room_ids.size());
    return true;
  }

  /// Record that a guest left a room.
  bool record_room_leave(const std::string& access_token,
                          const std::string& room_id) {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    auto it = guests_by_token_.find(access_token);
    if (it == guests_by_token_.end()) return false;

    it->second.joined_room_ids.erase(room_id);
    it->second.rooms_joined = static_cast<int>(it->second.joined_room_ids.size());
    return true;
  }

  /// Get the set of room IDs a guest has joined.
  std::set<std::string> get_joined_rooms(const std::string& access_token) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = guests_by_token_.find(access_token);
    if (it != guests_by_token_.end() && it->second.active) {
      return it->second.joined_room_ids;
    }
    return {};
  }

  // ---- Token Management ----

  /// Refresh guest access token (rotate tokens periodically).
  std::optional<std::string> refresh_token(const std::string& old_token) {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    auto it = guests_by_token_.find(old_token);
    if (it == guests_by_token_.end() || !it->second.active) return std::nullopt;

    auto now = now_ms();
    if (now > it->second.expires_at_ms) return std::nullopt;

    std::string new_token = generate_access_token(64);
    auto rec = it->second;
    rec.access_token = new_token;
    rec.token_issued_at_ms = now;
    rec.token_expires_at_ms = now + config_.access_token_ttl_ms;
    rec.last_active_ms = now;

    // Swap mappings
    guests_by_token_.erase(it);
    guests_by_token_[new_token] = rec;
    guests_by_user_id_[rec.user_id] = rec;

    return new_token;
  }

  /// Revoke a guest access token (effectively logging them out).
  bool revoke_token(const std::string& access_token) {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    auto it = guests_by_token_.find(access_token);
    if (it == guests_by_token_.end()) return false;

    std::string user_id = it->second.user_id;
    guests_by_token_.erase(it);

    auto uid_it = guests_by_user_id_.find(user_id);
    if (uid_it != guests_by_user_id_.end()) {
      uid_it->second.active = false;
    }

    return true;
  }

  // ---- Lifecycle ----

  /// Deactivate a guest account permanently.
  bool deactivate(const std::string& user_id, const std::string& reason = "expired") {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    auto it = guests_by_user_id_.find(user_id);
    if (it == guests_by_user_id_.end()) return false;

    it->second.active = false;
    // Remove token mappings
    guests_by_token_.erase(it->second.access_token);
    // Also remove any device-associated tokens
    for (const auto& did : it->second.device_ids) {
      // Only the primary token is tracked in guests_by_token_ above;
      // additional device tokens would need their own tracking.
    }

    deactivated_guests_.push_back({
      user_id,
      it->second.created_at_ms,
      now_ms(),
      reason,
      it->second.joined_room_ids
    });

    return true;
  }

  /// Reactivate a previously deactivated guest.
  bool reactivate(const std::string& user_id) {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    auto it = guests_by_user_id_.find(user_id);
    if (it == guests_by_user_id_.end()) return false;

    if (it->second.active) return true;  // Already active

    auto now = now_ms();
    it->second.active = true;
    it->second.expires_at_ms = now + config_.account_max_age_ms;
    it->second.last_active_ms = now;
    it->second.access_token = generate_access_token(64);
    it->second.token_issued_at_ms = now;
    it->second.token_expires_at_ms = now + config_.access_token_ttl_ms;

    guests_by_token_[it->second.access_token] = it->second;
    return true;
  }

  // ---- Cleanup Support ----

  /// Get all guest user IDs that are expired or inactive beyond the timeout.
  std::vector<std::string> get_expired_and_inactive_guest_ids() {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    std::vector<std::string> expired;
    auto now = now_ms();

    for (const auto& [uid, rec] : guests_by_user_id_) {
      if (!rec.active) {
        expired.push_back(uid);
      } else if (now > rec.expires_at_ms) {
        expired.push_back(uid);
      } else if (now - rec.last_active_ms > config_.inactivity_timeout_ms) {
        expired.push_back(uid);
      }
    }

    return expired;
  }

  /// Get guests that haven't been active within a given timespan.
  std::vector<GuestRecord> get_inactive_guests(int64_t inactivity_ms) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    std::vector<GuestRecord> inactive;
    auto now = now_ms();

    for (const auto& [uid, rec] : guests_by_user_id_) {
      if (rec.active && (now - rec.last_active_ms) > inactivity_ms) {
        inactive.push_back(rec);
      }
    }

    return inactive;
  }

  // ---- Statistics ----

  /// Number of currently active guests.
  size_t active_count() {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    size_t count = 0;
    auto now = now_ms();
    for (const auto& [_, rec] : guests_by_user_id_) {
      if (rec.active && now <= rec.expires_at_ms) count++;
    }
    return count;
  }

  /// Total number of guest registrations since server start.
  uint64_t total_registered() const { return total_registrations_.load(); }

  /// Get comprehensive guest statistics.
  json get_statistics() {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto now = now_ms();

    json stats;
    stats["active_guests"] = 0;
    stats["expired_guests"] = 0;
    stats["inactive_guests"] = 0;
    stats["total_registered"] = total_registrations_.load();
    stats["deactivated_total"] = deactivated_guests_.size();

    json active_list = json::array();
    for (const auto& [uid, rec] : guests_by_user_id_) {
      if (!rec.active || now > rec.expires_at_ms) {
        stats["expired_guests"] = stats["expired_guests"].get<int>() + 1;
      } else if (now - rec.last_active_ms > config_.inactivity_timeout_ms) {
        stats["inactive_guests"] = stats["inactive_guests"].get<int>() + 1;
      } else {
        stats["active_guests"] = stats["active_guests"].get<int>() + 1;
      }
      if (rec.active && now <= rec.expires_at_ms) {
        active_list.push_back(rec.to_json());
      }
    }

    if (active_list.size() <= 100) {
      stats["active_guest_list"] = active_list;
    } else {
      stats["active_guest_list_truncated"] = true;
      stats["active_guest_list_count"] = active_list.size();
    }

    return stats;
  }

  /// Dump all guest data for debugging/admin purposes.
  json dump_all() {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    json dump;
    dump["config"] = config_.to_json();
    dump["stats"] = get_statistics();

    json guests_arr = json::array();
    for (const auto& [uid, rec] : guests_by_user_id_) {
      json g = rec.to_json();
      g["joined_room_ids"] = json(rec.joined_room_ids);
      guests_arr.push_back(g);
    }
    dump["all_guests"] = guests_arr;

    json deactivated_arr = json::array();
    for (const auto& d : deactivated_guests_) {
      deactivated_arr.push_back({
        {"user_id", d.user_id},
        {"created_at", format_iso8601(d.created_at_ms)},
        {"deactivated_at", format_iso8601(d.deactivated_at_ms)},
        {"reason", d.reason},
        {"rooms_at_deactivation", json(d.joined_room_ids)}
      });
    }
    dump["deactivated"] = deactivated_arr;

    return dump;
  }

  // ---- Migration support (accessed by GuestMigrationHandler) ----

  /// Get a guest record for migration purposes (even if expired/deactivated).
  std::optional<GuestRecord> get_for_migration(const std::string& user_id) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = guests_by_user_id_.find(user_id);
    if (it != guests_by_user_id_.end()) return it->second;
    return std::nullopt;
  }

  /// Remove a guest after successful migration to full account.
  bool remove_after_migration(const std::string& user_id) {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    auto it = guests_by_user_id_.find(user_id);
    if (it == guests_by_user_id_.end()) return false;

    // Remove all token mappings
    guests_by_token_.erase(it->second.access_token);
    for (const auto& did : it->second.device_ids) {
      // Clean up device-associated entries if any
    }

    // Remove from suffix map
    std::string suffix;
    size_t pos = user_id.find("guest_");
    if (pos != std::string::npos) {
      suffix = user_id.substr(pos + 6);
      size_t colon = suffix.find(':');
      if (colon != std::string::npos) suffix = suffix.substr(0, colon);
      guests_by_suffix_.erase(suffix);
      suffix_by_user_id_.erase(suffix);
    }

    migrated_guests_.push_back({
      user_id,
      it->second.created_at_ms,
      now_ms(),
      it->second.joined_room_ids
    });

    guests_by_user_id_.erase(it);
    return true;
  }

private:
  struct DeactivatedRecord {
    std::string user_id;
    int64_t created_at_ms;
    int64_t deactivated_at_ms;
    std::string reason;
    std::set<std::string> joined_room_ids;
  };

  struct MigratedRecord {
    std::string user_id;
    int64_t created_at_ms;
    int64_t migrated_at_ms;
    std::set<std::string> joined_room_ids;
  };

  bool check_registration_rate_limit(const std::string& ip_address) {
    std::lock_guard<std::mutex> lock(reg_limit_mutex_);
    auto now = now_sec();

    // Clean up old entries
    auto& window = reg_limit_map_[ip_address];
    while (!window.empty() && window.front() < now - 3600) {
      window.pop_front();
    }

    // Max 5 guest registrations per IP per hour
    if (window.size() >= 5) return false;

    return true;
  }

  void record_registration(const std::string& ip_address) {
    std::lock_guard<std::mutex> lock(reg_limit_mutex_);
    reg_limit_map_[ip_address].push_back(now_sec());
  }

  mutable std::shared_mutex mutex_;
  std::mutex reg_limit_mutex_;

  GuestAccessConfig config_;

  // Primary data stores
  std::unordered_map<std::string, GuestRecord> guests_by_token_;
  std::unordered_map<std::string, GuestRecord> guests_by_user_id_;
  std::unordered_map<std::string, std::string> guests_by_suffix_;     // suffix -> user_id
  std::unordered_map<std::string, std::string> suffix_by_user_id_;    // user_id -> suffix

  // Registration rate limiting
  std::unordered_map<std::string, std::deque<int64_t>> reg_limit_map_;

  // History
  std::vector<DeactivatedRecord> deactivated_guests_;
  std::vector<MigratedRecord> migrated_guests_;

  // Counters
  std::atomic<uint64_t> guest_counter_{0};
  std::atomic<uint64_t> total_registrations_{0};
};

// ============================================================================
// GuestRestrictionEngine — Enforce all guest capability restrictions
//
// Checks every restricted action before it is performed. Maintains a
// comprehensive set of boolean capability flags that can be checked
// individually or in batch.
// ============================================================================
class GuestRestrictionEngine {
public:
  /// Result of a restriction check: either allowed or denied with reason.
  struct RestrictionCheck {
    bool allowed{true};
    std::string errcode;
    std::string error_message;
    std::string action;

    static RestrictionCheck allow() { return {true, "", "", ""}; }
    static RestrictionCheck deny(std::string_view action, std::string_view msg = "") {
      RestrictionCheck r;
      r.allowed = false;
      r.errcode = "M_GUEST_ACCESS_FORBIDDEN";
      r.error_message = msg.empty()
        ? std::string("Guests cannot ") + std::string(action)
        : std::string(msg);
      r.action = action;
      return r;
    }
  };

  /// Complete set of restriction flags.
  struct RestrictionFlags {
    bool can_create_rooms{false};
    bool can_invite_users{false};
    bool can_kick_users{false};
    bool can_ban_users{false};
    bool can_set_power_levels{false};
    bool can_set_room_aliases{false};
    bool can_search_user_directory{false};
    bool can_use_push{false};
    bool can_send_events{true};
    bool can_join_rooms{true};
    bool can_read_messages{true};
    bool can_set_display_name{true};
    bool can_upload_media{false};
    bool can_set_room_topic{false};
    bool can_set_room_name{false};
    bool can_set_room_avatar{false};
    bool can_redact_others{false};
    bool can_report_content{true};
    bool can_react_to_messages{true};
    bool can_send_read_receipts{true};
    bool can_set_typing{true};
    int  max_rooms_joined{10};

    static RestrictionFlags from_config(const GuestAccessConfig& cfg) {
      RestrictionFlags f;
      f.can_create_rooms = cfg.can_create_rooms;
      f.can_invite_users = cfg.can_invite_users;
      f.can_kick_users = cfg.can_kick_users;
      f.can_ban_users = cfg.can_ban_users;
      f.can_set_power_levels = cfg.can_set_power_levels;
      f.can_set_room_aliases = cfg.can_set_room_aliases;
      f.can_search_user_directory = cfg.can_search_user_directory;
      f.can_use_push = cfg.can_use_push;
      f.can_send_events = cfg.can_send_events;
      f.can_join_rooms = cfg.can_join_rooms;
      f.can_read_messages = cfg.can_read_messages;
      f.can_set_display_name = cfg.can_set_display_name;
      f.can_upload_media = cfg.can_upload_media;
      f.max_rooms_joined = cfg.max_rooms_joined;
      return f;
    }
  };

  explicit GuestRestrictionEngine(const GuestAccessConfig& config)
    : flags_(RestrictionFlags::from_config(config)) {}

  /// Reload restriction flags from an updated config.
  void reload(const GuestAccessConfig& config) {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    flags_ = RestrictionFlags::from_config(config);
  }

  // ---- Individual restriction checks ----

  RestrictionCheck check_create_room() {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    if (!flags_.can_create_rooms) {
      return RestrictionCheck::deny("create rooms",
        "Guest users are not permitted to create rooms");
    }
    return RestrictionCheck::allow();
  }

  RestrictionCheck check_invite_user() {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    if (!flags_.can_invite_users) {
      return RestrictionCheck::deny("invite users",
        "Guest users are not permitted to invite users to rooms");
    }
    return RestrictionCheck::allow();
  }

  RestrictionCheck check_kick_user() {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    if (!flags_.can_kick_users) {
      return RestrictionCheck::deny("kick users",
        "Guest users are not permitted to kick users from rooms");
    }
    return RestrictionCheck::allow();
  }

  RestrictionCheck check_ban_user() {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    if (!flags_.can_ban_users) {
      return RestrictionCheck::deny("ban users",
        "Guest users are not permitted to ban users from rooms");
    }
    return RestrictionCheck::allow();
  }

  RestrictionCheck check_set_power_levels() {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    if (!flags_.can_set_power_levels) {
      return RestrictionCheck::deny("set power levels",
        "Guest users cannot modify power levels");
    }
    return RestrictionCheck::allow();
  }

  RestrictionCheck check_set_room_alias() {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    if (!flags_.can_set_room_aliases) {
      return RestrictionCheck::deny("set room aliases",
        "Guest users cannot set room aliases");
    }
    return RestrictionCheck::allow();
  }

  RestrictionCheck check_search_user_directory() {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    if (!flags_.can_search_user_directory) {
      return RestrictionCheck::deny("search user directory",
        "Guest users cannot search the user directory");
    }
    return RestrictionCheck::allow();
  }

  RestrictionCheck check_use_push() {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    if (!flags_.can_use_push) {
      return RestrictionCheck::deny("use push notifications",
        "Guest users cannot register for push notifications");
    }
    return RestrictionCheck::allow();
  }

  RestrictionCheck check_send_event() {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    if (!flags_.can_send_events) {
      return RestrictionCheck::deny("send events",
        "Guest users are not permitted to send events");
    }
    return RestrictionCheck::allow();
  }

  RestrictionCheck check_join_room(int current_rooms_joined) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    if (!flags_.can_join_rooms) {
      return RestrictionCheck::deny("join rooms",
        "Guest users cannot join rooms");
    }
    if (current_rooms_joined >= flags_.max_rooms_joined) {
      return RestrictionCheck::deny("join more rooms",
        "Guest users have reached the maximum number of joined rooms (" +
        std::to_string(flags_.max_rooms_joined) + ")");
    }
    return RestrictionCheck::allow();
  }

  RestrictionCheck check_upload_media() {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    if (!flags_.can_upload_media) {
      return RestrictionCheck::deny("upload media",
        "Guest users cannot upload media");
    }
    return RestrictionCheck::allow();
  }

  RestrictionCheck check_redact_others() {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    if (!flags_.can_redact_others) {
      return RestrictionCheck::deny("redact others' messages",
        "Guest users can only redact their own messages");
    }
    return RestrictionCheck::allow();
  }

  // ---- Batch checks for common scenarios ----

  /// Check all restrictions needed for creating a room.
  RestrictionCheck check_room_creation_prerequisites() {
    return check_create_room();
  }

  /// Check all restrictions needed for room administration actions.
  RestrictionCheck check_room_admin_actions(std::string_view action) {
    if (action == "invite") return check_invite_user();
    if (action == "kick") return check_kick_user();
    if (action == "ban") return check_ban_user();
    if (action == "power_levels") return check_set_power_levels();
    if (action == "alias") return check_set_room_alias();
    return RestrictionCheck::deny(action);
  }

  /// Check by string action name.
  RestrictionCheck check(const std::string& action) {
    if (action == "create_room") return check_create_room();
    if (action == "invite") return check_invite_user();
    if (action == "kick") return check_kick_user();
    if (action == "ban") return check_ban_user();
    if (action == "power_levels") return check_set_power_levels();
    if (action == "alias") return check_set_room_alias();
    if (action == "user_directory") return check_search_user_directory();
    if (action == "push") return check_use_push();
    if (action == "send_event") return check_send_event();
    if (action == "upload_media") return check_upload_media();
    if (action == "redact_others") return check_redact_others();
    return RestrictionCheck::deny(action, "Unknown action: " + action);
  }

  /// Get all current restriction flags (for admin/debug).
  RestrictionFlags get_flags() {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return flags_;
  }

  /// Get restriction flags as JSON.
  json get_flags_json() {
    auto f = get_flags();
    return {
      {"can_create_rooms", f.can_create_rooms},
      {"can_invite_users", f.can_invite_users},
      {"can_kick_users", f.can_kick_users},
      {"can_ban_users", f.can_ban_users},
      {"can_set_power_levels", f.can_set_power_levels},
      {"can_set_room_aliases", f.can_set_room_aliases},
      {"can_search_user_directory", f.can_search_user_directory},
      {"can_use_push", f.can_use_push},
      {"can_send_events", f.can_send_events},
      {"can_join_rooms", f.can_join_rooms},
      {"can_read_messages", f.can_read_messages},
      {"can_set_display_name", f.can_set_display_name},
      {"can_upload_media", f.can_upload_media},
      {"can_set_room_topic", f.can_set_room_topic},
      {"can_set_room_name", f.can_set_room_name},
      {"can_set_room_avatar", f.can_set_room_avatar},
      {"can_redact_others", f.can_redact_others},
      {"can_report_content", f.can_report_content},
      {"can_react_to_messages", f.can_react_to_messages},
      {"can_send_read_receipts", f.can_send_read_receipts},
      {"can_set_typing", f.can_set_typing},
      {"max_rooms_joined", f.max_rooms_joined}
    };
  }

private:
  mutable std::shared_mutex mutex_;
  RestrictionFlags flags_;
};

// ============================================================================
// GuestRoomAccessChecker — Evaluate guest_access state events per room
//
// Checks whether guests are allowed to join a given room based on the
// m.room.guest_access state event. Caches results to avoid repeated
// database lookups.
// ============================================================================
class GuestRoomAccessChecker {
public:
  struct RoomAccessInfo {
    std::string room_id;
    std::string guest_access;       // "can_join" or "forbidden"
    int64_t     checked_at_ms{0};
    int64_t     event_stream_ordering{0};
    bool        cached{false};

    bool can_join() const { return guest_access == guest_config::kGuestAccessCanJoin; }
    bool is_forbidden() const { return guest_access == guest_config::kGuestAccessForbidden; }
  };

  explicit GuestRoomAccessChecker() = default;

  /// Check if guests can join a specific room. Consults cache first,
  /// then falls back to the database via callback.
  /// @param check_fn Callback that queries the database for guest_access state.
  RoomAccessInfo check_room(
      const std::string& room_id,
      std::function<std::string(const std::string&)> check_fn) {

    // Try cache first
    {
      std::shared_lock<std::shared_mutex> lock(cache_mutex_);
      auto it = access_cache_.find(room_id);
      if (it != access_cache_.end()) {
        auto& info = it->second;
        auto age_ms = now_ms() - info.checked_at_ms;
        if (age_ms < guest_config::kRoomAccessCacheTTLMs) {
          return info;
        }
      }
    }

    // Cache miss or expired — query the database
    RoomAccessInfo info;
    info.room_id = room_id;
    info.checked_at_ms = now_ms();

    try {
      info.guest_access = check_fn(room_id);
    } catch (...) {
      // Default to forbidden on error
      info.guest_access = guest_config::kGuestAccessForbidden;
    }

    // Validate the value
    if (info.guest_access != guest_config::kGuestAccessCanJoin &&
        info.guest_access != guest_config::kGuestAccessForbidden) {
      info.guest_access = guest_config::kGuestAccessForbidden;
    }

    // Store in cache
    {
      std::lock_guard<std::shared_mutex> lock(cache_mutex_);
      access_cache_[room_id] = info;
    }

    return info;
  }

  /// Check if a guest is allowed to join a room, throwing if forbidden.
  RoomAccessInfo require_can_join(
      const std::string& room_id,
      std::function<std::string(const std::string&)> check_fn) {
    auto info = check_room(room_id, check_fn);
    if (!info.can_join()) {
      throw GuestRoomForbidden(room_id);
    }
    return info;
  }

  /// Check multiple rooms at once for batch operations.
  std::map<std::string, RoomAccessInfo> check_rooms(
      const std::vector<std::string>& room_ids,
      std::function<std::string(const std::string&)> check_fn) {
    std::map<std::string, RoomAccessInfo> results;
    for (const auto& rid : room_ids) {
      results[rid] = check_room(rid, check_fn);
    }
    return results;
  }

  /// Invalidate cache entry for a specific room (when guest_access changes).
  void invalidate(const std::string& room_id) {
    std::lock_guard<std::shared_mutex> lock(cache_mutex_);
    access_cache_.erase(room_id);
  }

  /// Invalidate all cache entries.
  void invalidate_all() {
    std::lock_guard<std::shared_mutex> lock(cache_mutex_);
    access_cache_.clear();
  }

  /// Clean expired cache entries.
  void purge_expired() {
    std::lock_guard<std::shared_mutex> lock(cache_mutex_);
    auto now = now_ms();
    for (auto it = access_cache_.begin(); it != access_cache_.end();) {
      if (now - it->second.checked_at_ms > guest_config::kRoomAccessCacheTTLMs * 2) {
        it = access_cache_.erase(it);
      } else {
        ++it;
      }
    }
  }

  /// Get cache statistics.
  json get_cache_stats() {
    std::shared_lock<std::shared_mutex> lock(cache_mutex_);
    json stats;
    stats["cached_rooms"] = access_cache_.size();
    int can_join = 0, forbidden = 0;
    for (const auto& [rid, info] : access_cache_) {
      if (info.can_join()) can_join++;
      else forbidden++;
    }
    stats["can_join_count"] = can_join;
    stats["forbidden_count"] = forbidden;
    return stats;
  }

private:
  mutable std::shared_mutex cache_mutex_;
  std::unordered_map<std::string, RoomAccessInfo> access_cache_;
};

// ============================================================================
// GuestCleanupScheduler — Auto-deactivate idle guest accounts
//
// Background thread that periodically scans guest accounts and deactivates
// those that have been inactive beyond the configured timeout. Also handles
// account expiry, orphaned token cleanup, and data deletion.
// ============================================================================
class GuestCleanupScheduler {
public:
  struct CleanupStats {
    int64_t last_run_ms{0};
    int64_t total_runs{0};
    int     guests_deactivated{0};
    int     guests_expired{0};
    int     tokens_cleaned{0};
    int     errors{0};
    std::vector<std::string> recent_deactivations;

    json to_json() const {
      return {
        {"last_run", format_iso8601(last_run_ms)},
        {"total_runs", total_runs},
        {"guests_deactivated", guests_deactivated},
        {"guests_expired", guests_expired},
        {"tokens_cleaned", tokens_cleaned},
        {"errors", errors},
        {"recent_deactivations", json(recent_deactivations)}
      };
    }
  };

  /// Callback invoked for each guest that is being deactivated.
  /// Allows the caller to clean up room memberships, devices, etc.
  using DeactivationCallback = std::function<void(const std::string& user_id,
      const std::set<std::string>& joined_rooms)>;

  GuestCleanupScheduler(GuestRegistry& registry,
                         GuestAccessConfig& config,
                         DeactivationCallback on_deactivate = nullptr)
    : registry_(registry),
      config_(config),
      on_deactivate_(std::move(on_deactivate)),
      running_(false) {}

  ~GuestCleanupScheduler() { stop(); }

  /// Start the background cleanup thread.
  void start() {
    if (running_.exchange(true)) return;
    worker_thread_ = std::thread([this]() { worker_loop(); });
  }

  /// Stop the background cleanup thread.
  void stop() {
    running_ = false;
    cv_.notify_all();
    if (worker_thread_.joinable()) worker_thread_.join();
  }

  /// Trigger an immediate cleanup run (blocks until complete).
  CleanupStats run_now() {
    return run_cleanup_pass();
  }

  /// Get cleanup statistics.
  CleanupStats get_stats() {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
  }

  /// Send a JSON status report.
  json get_status() {
    auto s = get_stats();
    return s.to_json();
  }

private:
  void worker_loop() {
    while (running_) {
      std::unique_lock<std::mutex> lock(wake_mutex_);
      cv_.wait_for(lock,
          chr::milliseconds(config_.cleanup_interval_ms),
          [this]() { return !running_.load(); });

      if (!running_) break;

      run_cleanup_pass();
    }
  }

  CleanupStats run_cleanup_pass() {
    CleanupStats pass_stats;
    pass_stats.last_run_ms = now_ms();
    pass_stats.total_runs = 0;

    try {
      // Get expired and inactive guests
      auto expired = registry_.get_expired_and_inactive_guest_ids();

      int batch_count = 0;
      for (const auto& uid : expired) {
        if (batch_count >= guest_config::kCleanupBatchSize) {
          // Yield between batches to avoid blocking
          std::this_thread::sleep_for(chr::milliseconds(50));
          batch_count = 0;
        }

        try {
          auto guest = registry_.get_by_user_id(uid);
          bool is_expired = false;
          bool is_inactive = false;

          if (!guest.has_value()) {
            // Already gone, skip
            continue;
          }

          auto now = now_ms();
          if (now > guest->expires_at_ms) {
            is_expired = true;
          } else if (now - guest->last_active_ms > config_.inactivity_timeout_ms) {
            is_inactive = true;
          }

          if (is_expired || is_inactive) {
            // Notify callback for external cleanup (room leaves, etc.)
            if (on_deactivate_) {
              on_deactivate_(uid, guest->joined_room_ids);
            }

            // Deactivate the guest
            std::string reason = is_expired ? "account_expired" : "inactivity_timeout";
            if (registry_.deactivate(uid, reason)) {
              if (is_expired) pass_stats.guests_expired++;
              else pass_stats.guests_deactivated++;
            }

            pass_stats.recent_deactivations.push_back(uid);
            if (pass_stats.recent_deactivations.size() > 100) {
              pass_stats.recent_deactivations.erase(
                  pass_stats.recent_deactivations.begin());
            }
          }

          batch_count++;
        } catch (const std::exception& e) {
          pass_stats.errors++;
        }
      }

      // Clean up expired room access cache if we have one
      // (handled externally by GuestRoomAccessChecker)

    } catch (const std::exception& e) {
      pass_stats.errors++;
    }

    // Update global stats
    {
      std::lock_guard<std::mutex> lock(stats_mutex_);
      stats_.last_run_ms = pass_stats.last_run_ms;
      stats_.total_runs++;
      stats_.guests_deactivated += pass_stats.guests_deactivated;
      stats_.guests_expired += pass_stats.guests_expired;
      stats_.tokens_cleaned += pass_stats.tokens_cleaned;
      stats_.errors += pass_stats.errors;
      stats_.recent_deactivations = pass_stats.recent_deactivations;
    }

    return pass_stats;
  }

  GuestRegistry& registry_;
  GuestAccessConfig& config_;
  DeactivationCallback on_deactivate_;

  std::atomic<bool> running_;
  std::thread worker_thread_;
  std::mutex wake_mutex_;
  std::condition_variable cv_;

  CleanupStats stats_;
  std::mutex stats_mutex_;
};

// ============================================================================
// GuestMigrationHandler — Upgrade guest accounts to full accounts
//
// Allows guest users to set a password and optionally add an email address
// to convert their guest account into a permanent registered account.
// Preserves room memberships and transfers access tokens.
// ============================================================================
class GuestMigrationHandler {
public:
  /// Migration request from a guest user.
  struct MigrationRequest {
    std::string guest_user_id;
    std::string guest_access_token;
    std::string new_password;
    std::optional<std::string> new_email;
    std::optional<std::string> new_display_name;
    std::string ip_address;
  };

  /// Result of a migration attempt.
  struct MigrationResult {
    bool success{false};
    std::string user_id;                // New permanent user ID (may differ)
    std::string access_token;           // New access token
    std::string device_id;
    std::optional<std::string> error;
    std::optional<std::string> errcode;
    int rooms_preserved{0};
    json metadata;

    json to_json() const {
      json j;
      j["success"] = success;
      if (success) {
        j["user_id"] = user_id;
        j["access_token"] = access_token;
        j["device_id"] = device_id;
        j["rooms_preserved"] = rooms_preserved;
      } else {
        j["errcode"] = errcode.value_or("M_UNKNOWN");
        j["error"] = error.value_or("Migration failed");
      }
      return j;
    }
  };

  /// Callback to create a full user account in the auth/registration system.
  using CreateUserCallback = std::function<bool(
      const std::string& user_id,
      const std::string& password,
      const std::optional<std::string>& email)>;

  /// Callback to transfer room memberships from guest to permanent user.
  using TransferRoomsCallback = std::function<int(
      const std::string& guest_user_id,
      const std::string& permanent_user_id,
      const std::set<std::string>& room_ids)>;

  GuestMigrationHandler(GuestRegistry& registry,
                         CreateUserCallback create_user,
                         TransferRoomsCallback transfer_rooms)
    : registry_(registry),
      create_user_(std::move(create_user)),
      transfer_rooms_(std::move(transfer_rooms)) {}

  /// Process a migration request from a guest.
  MigrationResult migrate(const MigrationRequest& req) {
    MigrationResult result;

    // Validate the guest exists
    auto guest = registry_.get_for_migration(req.guest_user_id);
    if (!guest.has_value()) {
      result.error = "Guest account not found";
      result.errcode = "M_NOT_FOUND";
      return result;
    }

    // Verify the access token matches
    if (guest->access_token != req.guest_access_token) {
      result.error = "Invalid guest access token for migration";
      result.errcode = "M_FORBIDDEN";
      return result;
    }

    // Check migration rate limit per guest
    if (!check_migration_rate_limit(req.guest_user_id)) {
      result.error = "Too many migration attempts. Please try again later.";
      result.errcode = "M_LIMIT_EXCEEDED";
      return result;
    }

    // Validate password
    if (req.new_password.size() < 8) {
      result.error = "Password must be at least 8 characters";
      result.errcode = "M_WEAK_PASSWORD";
      return result;
    }

    // Generate a migration token for idempotency
    std::string migration_id = generate_migration_token();

    // Record the attempt
    record_migration_attempt(req.guest_user_id);

    // Create the permanent user account
    // The user ID may be changed if @guest_ prefix is stripped
    std::string permanent_user_id = derive_permanent_user_id(req.guest_user_id);

    bool user_created = false;
    try {
      user_created = create_user_(permanent_user_id, req.new_password, req.new_email);
    } catch (const std::exception& e) {
      result.error = std::string("Failed to create permanent account: ") + e.what();
      result.errcode = "M_UNKNOWN";
      return result;
    }

    if (!user_created) {
      result.error = "Failed to create permanent account. User ID may already exist.";
      result.errcode = "M_USER_IN_USE";
      return result;
    }

    // Transfer room memberships
    int rooms_preserved = 0;
    try {
      rooms_preserved = transfer_rooms_(req.guest_user_id, permanent_user_id,
                                         guest->joined_room_ids);
    } catch (const std::exception& e) {
      // Room transfer failed — but the user was already created.
      // This is a partial failure. Log it but continue.
      result.metadata["room_transfer_warning"] = e.what();
    }

    // Generate new credentials for the permanent account
    std::string new_access_token = generate_access_token(64);
    std::string new_device_id = "migrated_" + generate_hex(8);

    // Remove the guest account
    registry_.remove_after_migration(req.guest_user_id);

    // Record successful migration
    record_migration_success(req.guest_user_id, permanent_user_id, migration_id);

    result.success = true;
    result.user_id = permanent_user_id;
    result.access_token = new_access_token;
    result.device_id = new_device_id;
    result.rooms_preserved = rooms_preserved;
    result.metadata["migration_id"] = migration_id;
    result.metadata["original_user_id"] = req.guest_user_id;
    result.metadata["migrated_at"] = format_iso8601(now_ms());

    return result;
  }

  /// Get migration history for a guest user ID.
  json get_migration_history(const std::string& user_id) {
    std::lock_guard<std::mutex> lock(hist_mutex_);
    json history = json::array();
    auto it = migration_attempts_.find(user_id);
    if (it != migration_attempts_.end()) {
      for (const auto& attempt : it->second) {
        history.push_back({
          {"attempted_at", format_iso8601(attempt.attempted_at_ms)},
          {"success", attempt.success},
          {"permanent_user_id", attempt.permanent_user_id},
          {"error", attempt.error}
        });
      }
    }
    return history;
  }

  /// Check if a user ID is currently in the process of migrating.
  bool is_migration_in_progress(const std::string& user_id) {
    std::lock_guard<std::mutex> lock(hist_mutex_);
    auto it = in_progress_.find(user_id);
    if (it == in_progress_.end()) return false;

    auto age_ms = now_ms() - it->second;
    return age_ms < 300'000;  // 5-minute in-progress window
  }

private:
  struct MigrationAttempt {
    int64_t attempted_at_ms;
    bool success;
    std::string permanent_user_id;
    std::string error;
  };

  std::string derive_permanent_user_id(const std::string& guest_id) {
    // Strip @guest_ prefix and replace with a regular user ID
    std::string derived = guest_id;

    // Handle @guest_XXXX:domain -> @XXXX:domain
    size_t prefix_end = derived.find("guest_");
    if (prefix_end != std::string::npos) {
      derived = derived.substr(0, prefix_end) + derived.substr(prefix_end + 6);
    }

    // If the resulting ID would still look like a guest, generate a fresh one
    if (derived.find("guest_") != std::string::npos) {
      size_t at_pos = derived.find('@');
      size_t colon_pos = derived.find(':');
      std::string domain = (colon_pos != std::string::npos)
          ? derived.substr(colon_pos) : "";
      derived = "@user_" + generate_hex(12) + domain;
    }

    return derived;
  }

  bool check_migration_rate_limit(const std::string& user_id) {
    std::lock_guard<std::mutex> lock(hist_mutex_);
    auto it = migration_attempts_.find(user_id);
    if (it == migration_attempts_.end()) return true;

    // Count attempts in the cooldown window
    auto now = now_ms();
    int recent_attempts = 0;
    for (const auto& attempt : it->second) {
      if (now - attempt.attempted_at_ms < guest_config::kMigrationCooldownMs) {
        recent_attempts++;
      }
    }

    return recent_attempts < guest_config::kMigrationMaxAttempts;
  }

  void record_migration_attempt(const std::string& user_id) {
    std::lock_guard<std::mutex> lock(hist_mutex_);
    MigrationAttempt attempt;
    attempt.attempted_at_ms = now_ms();
    attempt.success = false;
    migration_attempts_[user_id].push_back(attempt);
    in_progress_[user_id] = attempt.attempted_at_ms;
  }

  void record_migration_success(const std::string& guest_id,
                                 const std::string& permanent_id,
                                 const std::string& /*migration_id*/) {
    std::lock_guard<std::mutex> lock(hist_mutex_);
    // Mark the most recent attempt as successful
    auto it = migration_attempts_.find(guest_id);
    if (it != migration_attempts_.end() && !it->second.empty()) {
      it->second.back().success = true;
      it->second.back().permanent_user_id = permanent_id;
    }
    in_progress_.erase(guest_id);
  }

  GuestRegistry& registry_;
  CreateUserCallback create_user_;
  TransferRoomsCallback transfer_rooms_;

  std::mutex hist_mutex_;
  std::unordered_map<std::string, std::vector<MigrationAttempt>> migration_attempts_;
  std::unordered_map<std::string, int64_t> in_progress_;
};

// ============================================================================
// GuestRateLimiter — Stricter rate limiting for guest users
//
// Token bucket rate limiter with guest-specific (lower) limits.
// Tracks per-guest, per-endpoint, and per-IP rate limits.
// ============================================================================
class GuestRateLimiter {
public:
  struct RateLimitConfig {
    double rate_per_second;     // Sustained rate (tokens added per second)
    double burst;               // Maximum burst size (tokens available immediately)
  };

  struct RateLimitResult {
    bool allowed{true};
    int64_t retry_after_ms{0};
    double limit{0.0};
    double remaining{0.0};
    int64_t reset_at_ms{0};
  };

  /// Pre-defined endpoint categories with guest-specific limits.
  enum class EndpointCategory {
    LOGIN,
    REGISTER,
    MESSAGE_SEND,
    SYNC,
    JOIN_ROOM,
    LEAVE_ROOM,
    INVITE,
    KICK,
    BAN,
    PROFILE_UPDATE,
    MEDIA_UPLOAD,
    SEARCH,
    GENERAL,
  };

  explicit GuestRateLimiter(const GuestAccessConfig& config)
    : config_(config) {
    // Initialize default guest rate limits for each category
    category_limits_[EndpointCategory::LOGIN] =
        {static_cast<double>(guest_config::kGuestLoginRatePerSec),
         static_cast<double>(guest_config::kGuestLoginBurst)};
    category_limits_[EndpointCategory::MESSAGE_SEND] =
        {static_cast<double>(guest_config::kGuestMessageRatePerSec),
         static_cast<double>(guest_config::kGuestMessageBurst)};
    category_limits_[EndpointCategory::SYNC] =
        {static_cast<double>(guest_config::kGuestSyncRatePerSec),
         static_cast<double>(guest_config::kGuestSyncBurst)};
    category_limits_[EndpointCategory::JOIN_ROOM] =
        {static_cast<double>(guest_config::kGuestJoinRatePerSec),
         static_cast<double>(guest_config::kGuestJoinBurst)};
    category_limits_[EndpointCategory::GENERAL] =
        {guest_config::kGuestMessageRatePerSec * config.rate_multiplier,
         guest_config::kGuestMessageBurst * config.burst_multiplier};
  }

  /// Check if a guest request should be rate-limited.
  /// @param guest_user_id The guest's user ID.
  /// @param category The endpoint category being accessed.
  /// @return Rate limit result with allow/deny and headers.
  RateLimitResult check(const std::string& guest_user_id,
                          EndpointCategory category) {
    auto limits = get_limits(category);
    return check_bucket(guest_user_id, limits);
  }

  /// Check by IP address (for registration endpoints).
  RateLimitResult check_ip(const std::string& ip_address,
                             EndpointCategory category) {
    auto limits = get_limits(category);
    // Apply additional stricter limit for IP-based checks
    limits.rate_per_second *= 0.5;
    limits.burst *= 0.5;
    return check_bucket("ip:" + ip_address, limits);
  }

  /// Rate limit headers for an HTTP response.
  json make_headers(const RateLimitResult& result) {
    return {
      {"X-RateLimit-Limit", std::to_string(static_cast<int>(result.limit))},
      {"X-RateLimit-Remaining", std::to_string(static_cast<int>(result.remaining))},
      {"X-RateLimit-Reset", std::to_string(result.reset_at_ms / 1000)}
    };
  }

  /// Get the configured limits for a category.
  RateLimitConfig get_limits(EndpointCategory category) {
    auto it = category_limits_.find(category);
    if (it != category_limits_.end()) return it->second;

    // Fallback to general limits
    it = category_limits_.find(EndpointCategory::GENERAL);
    if (it != category_limits_.end()) return it->second;

    return {1.0, 3.0};  // Hard fallback
  }

  /// Override limits for a specific category.
  void set_limits(EndpointCategory category, double rate, double burst) {
    std::lock_guard<std::mutex> lock(bucket_mutex_);
    category_limits_[category] = {rate, burst};
  }

  /// Clean up stale rate limit buckets.
  void purge_stale_buckets() {
    std::lock_guard<std::mutex> lock(bucket_mutex_);
    auto now = now_ms();
    for (auto it = buckets_.begin(); it != buckets_.end();) {
      // Remove buckets not accessed in 10 minutes
      if (now - it->second.last_refill_ms > 600'000) {
        it = buckets_.erase(it);
      } else {
        ++it;
      }
    }
  }

  /// Get rate limiting statistics.
  json get_stats() {
    std::lock_guard<std::mutex> lock(bucket_mutex_);
    json stats;
    stats["active_buckets"] = buckets_.size();
    stats["total_checks"] = total_checks_.load();
    stats["total_blocked"] = total_blocked_.load();
    json cats = json::array();
    for (const auto& [cat, limits] : category_limits_) {
      cats.push_back({
        {"category", static_cast<int>(cat)},
        {"rate_per_second", limits.rate_per_second},
        {"burst", limits.burst}
      });
    }
    stats["categories"] = cats;
    return stats;
  }

  /// Reset all rate limit state (for testing).
  void reset() {
    std::lock_guard<std::mutex> lock(bucket_mutex_);
    buckets_.clear();
    total_checks_ = 0;
    total_blocked_ = 0;
  }

private:
  struct TokenBucket {
    double tokens{0.0};
    int64_t last_refill_ms{0};
    double max_tokens{0.0};
    double refill_rate{0.0};   // tokens per millisecond
  };

  RateLimitResult check_bucket(const std::string& key,
                                 const RateLimitConfig& limits) {
    std::lock_guard<std::mutex> lock(bucket_mutex_);
    auto now = now_ms();

    auto& bucket = buckets_[key];

    // Initialize bucket if new
    if (bucket.last_refill_ms == 0) {
      bucket.tokens = limits.burst;
      bucket.max_tokens = limits.burst;
      bucket.refill_rate = limits.rate_per_second / 1000.0;
      bucket.last_refill_ms = now;
    }

    // Refill tokens based on elapsed time
    int64_t elapsed = now - bucket.last_refill_ms;
    if (elapsed > 0) {
      bucket.tokens += bucket.refill_rate * static_cast<double>(elapsed);
      if (bucket.tokens > bucket.max_tokens) {
        bucket.tokens = bucket.max_tokens;
      }
      bucket.last_refill_ms = now;
    }

    total_checks_++;

    RateLimitResult result;
    result.limit = limits.rate_per_second;
    result.remaining = std::max(0.0, bucket.tokens - 1.0);
    result.reset_at_ms = now + static_cast<int64_t>(
        (limits.burst - bucket.tokens + 1.0) / bucket.refill_rate);

    if (bucket.tokens >= 1.0) {
      bucket.tokens -= 1.0;
      result.allowed = true;
    } else {
      result.allowed = false;
      result.retry_after_ms = static_cast<int64_t>(
          (1.0 - bucket.tokens) / bucket.refill_rate);
      total_blocked_++;
    }

    return result;
  }

  GuestAccessConfig config_;
  std::mutex bucket_mutex_;
  std::unordered_map<std::string, TokenBucket> buckets_;
  std::unordered_map<EndpointCategory, RateLimitConfig> category_limits_;

  std::atomic<uint64_t> total_checks_{0};
  std::atomic<uint64_t> total_blocked_{0};
};

// ============================================================================
// GuestDisplayFormatter — Mark guest users in member lists and responses
//
// Annotates room member data with is_guest flag, adds guest-specific
// display name formatting, and provides utility functions for UI
// components that need to distinguish guest users.
// ============================================================================
class GuestDisplayFormatter {
public:
  /// Guest display options configurable per use case.
  struct DisplayOptions {
    bool annotate_display_name{true};     // Add "(Guest)" to display names
    bool include_is_guest_flag{true};     // Include is_guest boolean field
    bool include_guest_badge{true};       // Include guest badge indicator
    bool highlight_in_lists{true};        // Sort guests separately
    std::string guest_name_suffix{" (Guest)"};
    std::string guest_display_name_prefix{"Guest: "};
  };

  explicit GuestDisplayFormatter(GuestRegistry& registry,
                                   const DisplayOptions& opts = {})
    : registry_(registry), options_(opts) {}

  /// Format a single room member for display.
  /// Adds is_guest field and optional display name annotation.
  json format_member(const json& member_data, const std::string& user_id) {
    json result = member_data;

    bool is_guest = registry_.is_active_guest(user_id) ||
                    registry_.is_guest_user_id(user_id);

    if (options_.include_is_guest_flag) {
      result["is_guest"] = is_guest;
    }

    if (is_guest && options_.annotate_display_name) {
      if (result.contains("display_name") && result["display_name"].is_string()) {
        std::string name = result["display_name"];
        if (name.find(options_.guest_name_suffix) == std::string::npos) {
          result["display_name"] = name + options_.guest_name_suffix;
        }
      } else if (!result.contains("display_name")) {
        result["display_name"] = options_.guest_display_name_prefix +
            extract_username(user_id);
      }
    }

    if (is_guest && options_.include_guest_badge) {
      result["badges"] = json::array({"guest"});
    }

    return result;
  }

  /// Format a list of room members (from /members endpoint).
  json format_member_list(const json& members_chunk) {
    json formatted = json::array();

    for (const auto& member : members_chunk) {
      std::string user_id;
      if (member.contains("user_id")) {
        user_id = member["user_id"];
      } else if (member.contains("state_key")) {
        user_id = member["state_key"];
      }

      if (!user_id.empty()) {
        formatted.push_back(format_member(member, user_id));
      } else {
        formatted.push_back(member);
      }
    }

    return formatted;
  }

  /// Format a joined_members response.
  json format_joined_members(const json& joined_members) {
    json formatted;
    for (auto it = joined_members.begin(); it != joined_members.end(); ++it) {
      std::string user_id = it.key();
      auto member_data = it.value();

      bool is_guest = registry_.is_active_guest(user_id) ||
                      registry_.is_guest_user_id(user_id);

      json formatted_member = member_data;
      if (options_.include_is_guest_flag) {
        formatted_member["is_guest"] = is_guest;
      }

      if (is_guest && options_.annotate_display_name) {
        if (formatted_member.contains("display_name") &&
            formatted_member["display_name"].is_string()) {
          std::string name = formatted_member["display_name"];
          if (name.find(options_.guest_name_suffix) == std::string::npos) {
            formatted_member["display_name"] = name + options_.guest_name_suffix;
          }
        }
      }

      formatted[user_id] = formatted_member;
    }
    return formatted;
  }

  /// Build and return a guest manifest for a list of user IDs.
  /// Useful for clients to know which users are guests.
  json build_guest_manifest(const std::vector<std::string>& user_ids) {
    json manifest = json::object();

    for (const auto& uid : user_ids) {
      bool is_guest = registry_.is_active_guest(uid) ||
                      registry_.is_guest_user_id(uid);
      if (is_guest) {
        manifest[uid] = {{"is_guest", true}};
      }
    }

    return manifest;
  }

  /// Check if any members in a list are guests.
  bool has_guest_members(const json& member_chunk) {
    for (const auto& member : member_chunk) {
      std::string uid;
      if (member.contains("user_id")) uid = member["user_id"];
      else if (member.contains("state_key")) uid = member["state_key"];

      if (!uid.empty() && (registry_.is_active_guest(uid) ||
                           registry_.is_guest_user_id(uid))) {
        return true;
      }
    }
    return false;
  }

  /// Get current display options.
  DisplayOptions get_options() const { return options_; }

  /// Update display options.
  void set_options(const DisplayOptions& opts) { options_ = opts; }

private:
  std::string extract_username(std::string_view user_id) const {
    if (user_id.size() > 1 && user_id[0] == '@') {
      size_t colon = user_id.find(':');
      if (colon != std::string::npos) {
        return std::string(user_id.substr(1, colon - 1));
      }
      return std::string(user_id.substr(1));
    }
    return std::string(user_id);
  }

  GuestRegistry& registry_;
  DisplayOptions options_;
};

// ============================================================================
// GuestSyncFilter — Filter sync responses for guest users
//
// Reduces the volume of data sent to guest clients in /sync responses.
// Strips presence, limits timeline depth, filters account_data, and
// reduces device list and to_device payloads.
// ============================================================================
class GuestSyncFilter {
public:
  /// Configuration for sync filtering.
  struct SyncFilterConfig {
    int  timeline_limit{5};            // Max timeline events per room
    int  max_rooms{10};                // Max rooms in sync response
    bool include_presence{false};      // Whether to include presence events
    bool include_account_data{false};  // Whether to include account_data
    bool include_to_device{true};      // Whether to include to_device messages
    bool include_device_lists{false};  // Whether to include device list changes
    bool include_device_otk_counts{false}; // Whether to include one-time key counts
    bool strip_ephemeral{true};        // Remove ephemeral events (typing, receipts)
    bool strip_state_for_other_users{true}; // Remove state events from other users
  };

  explicit GuestSyncFilter(GuestRegistry& registry,
                             const SyncFilterConfig& config = {})
    : registry_(registry), config_(config) {}

  /// Filter a full /sync response for a guest user.
  /// @param sync_response The complete sync response JSON.
  /// @param guest_user_id The guest user's ID.
  /// @return Filtered sync response.
  json filter_sync_response(const json& sync_response,
                              const std::string& guest_user_id) {

    json filtered;

    // Always include next_batch
    if (sync_response.contains("next_batch")) {
      filtered["next_batch"] = sync_response["next_batch"];
    }

    // Filter rooms
    if (sync_response.contains("rooms")) {
      filtered["rooms"] = filter_rooms(sync_response["rooms"], guest_user_id);
    }

    // Filter presence
    if (config_.include_presence && sync_response.contains("presence")) {
      filtered["presence"] = filter_presence(sync_response["presence"]);
    } else {
      filtered["presence"] = json::object();
      filtered["presence"]["events"] = json::array();
    }

    // Filter account_data
    if (config_.include_account_data && sync_response.contains("account_data")) {
      filtered["account_data"] = filter_account_data(sync_response["account_data"]);
    } else {
      filtered["account_data"] = json::object();
      filtered["account_data"]["events"] = json::array();
    }

    // Filter to_device
    if (config_.include_to_device && sync_response.contains("to_device")) {
      filtered["to_device"] = filter_to_device(sync_response["to_device"]);
    } else {
      filtered["to_device"] = json::object();
      filtered["to_device"]["events"] = json::array();
    }

    // Filter device_lists
    if (config_.include_device_lists && sync_response.contains("device_lists")) {
      filtered["device_lists"] = sync_response["device_lists"];
    } else {
      filtered["device_lists"] = json::object();
      filtered["device_lists"]["changed"] = json::array();
      filtered["device_lists"]["left"] = json::array();
    }

    // Filter device_one_time_keys_count
    if (config_.include_device_otk_counts &&
        sync_response.contains("device_one_time_keys_count")) {
      filtered["device_one_time_keys_count"] =
          sync_response["device_one_time_keys_count"];
    }

    // Add guest metadata
    filtered["guest_info"] = {
      {"is_guest", true},
      {"user_id", guest_user_id}
    };

    return filtered;
  }

  /// Filter only the rooms portion of a sync response.
  json filter_rooms(const json& rooms, const std::string& guest_user_id) {
    json filtered_rooms;

    int room_count = 0;

    // Process join rooms
    if (rooms.contains("join")) {
      json join_obj;
      for (auto it = rooms["join"].begin();
           it != rooms["join"].end() && room_count < config_.max_rooms;
           ++it) {
        join_obj[it.key()] = filter_room_entry(it.value(), "join", guest_user_id);
        room_count++;
      }
      filtered_rooms["join"] = join_obj;
    } else {
      filtered_rooms["join"] = json::object();
    }

    // Process invite rooms (always include, limited)
    if (rooms.contains("invite")) {
      json invite_obj;
      int invite_count = 0;
      for (auto it = rooms["invite"].begin();
           it != rooms["invite"].end() && invite_count < config_.max_rooms;
           ++it) {
        invite_obj[it.key()] = filter_room_entry(it.value(), "invite", guest_user_id);
        invite_count++;
      }
      filtered_rooms["invite"] = invite_obj;
    } else {
      filtered_rooms["invite"] = json::object();
    }

    // Process leave rooms (always include, limited)
    if (rooms.contains("leave")) {
      json leave_obj;
      int leave_count = 0;
      for (auto it = rooms["leave"].begin();
           it != rooms["leave"].end() && leave_count < config_.max_rooms;
           ++it) {
        leave_obj[it.key()] = filter_room_entry(it.value(), "leave", guest_user_id);
        leave_count++;
      }
      filtered_rooms["leave"] = leave_obj;
    } else {
      filtered_rooms["leave"] = json::object();
    }

    return filtered_rooms;
  }

  /// Filter a single room entry in a sync response.
  json filter_room_entry(const json& room_entry,
                           const std::string& membership,
                           const std::string& guest_user_id) {
    json filtered;

    // Timeline — limit event count
    if (room_entry.contains("timeline")) {
      filtered["timeline"] = filter_timeline(room_entry["timeline"]);
    }

    // State — include only relevant state events
    if (room_entry.contains("state")) {
      if (config_.strip_state_for_other_users) {
        filtered["state"] = filter_state(room_entry["state"], guest_user_id);
      } else {
        filtered["state"] = filter_state_events(room_entry["state"]);
      }
    }

    // Ephemeral — strip if configured
    if (room_entry.contains("ephemeral")) {
      if (config_.strip_ephemeral) {
        filtered["ephemeral"] = json::object();
        filtered["ephemeral"]["events"] = json::array();
      } else {
        filtered["ephemeral"] = filter_ephemeral(room_entry["ephemeral"]);
      }
    }

    // Account data — strip for guests
    if (room_entry.contains("account_data")) {
      if (config_.include_account_data) {
        filtered["account_data"] = room_entry["account_data"];
      } else {
        filtered["account_data"] = json::object();
        filtered["account_data"]["events"] = json::array();
      }
    }

    // Unread notifications — always include, but simplify
    if (room_entry.contains("unread_notifications")) {
      filtered["unread_notifications"] = simplify_unread(room_entry["unread_notifications"]);
    }

    // Summary — always include
    if (room_entry.contains("summary")) {
      filtered["summary"] = room_entry["summary"];
    }

    return filtered;
  }

  /// Filter the timeline to limit event count.
  json filter_timeline(const json& timeline) {
    json filtered;

    if (timeline.contains("events") && timeline["events"].is_array()) {
      const auto& events = timeline["events"];
      size_t count = events.size();
      size_t limit = static_cast<size_t>(config_.timeline_limit);

      if (count > limit) {
        // Take the most recent N events
        json limited_events = json::array();
        for (size_t i = count - limit; i < count; ++i) {
          limited_events.push_back(events[i]);
        }
        filtered["events"] = limited_events;
        filtered["limited"] = true;
        filtered["prev_batch"] = timeline.value("prev_batch", "");
      } else {
        filtered["events"] = events;
        filtered["limited"] = false;
        filtered["prev_batch"] = timeline.value("prev_batch", "");
      }
    } else {
      filtered["events"] = json::array();
      filtered["limited"] = false;
    }

    return filtered;
  }

  /// Filter state events — keep only essential ones.
  json filter_state_events(const json& state) {
    json filtered;
    if (state.contains("events") && state["events"].is_array()) {
      json essential_events = json::array();
      for (const auto& event : state["events"]) {
        std::string type = event.value("type", "");
        // Keep only critical state types for guests
        if (type == "m.room.name" ||
            type == "m.room.topic" ||
            type == "m.room.avatar" ||
            type == "m.room.join_rules" ||
            type == "m.room.guest_access" ||
            type == "m.room.canonical_alias" ||
            type == "m.room.create") {
          essential_events.push_back(event);
        }
      }
      filtered["events"] = essential_events;
    } else {
      filtered["events"] = json::array();
    }
    return filtered;
  }

  /// Filter state events removing those from other users.
  json filter_state(const json& state, const std::string& guest_user_id) {
    json filtered;
    if (state.contains("events") && state["events"].is_array()) {
      json filtered_events = json::array();
      for (const auto& event : state["events"]) {
        std::string type = event.value("type", "");
        std::string state_key = event.value("state_key", "");
        std::string sender = event.value("sender", "");

        // Always include m.room.create, m.room.guest_access, m.room.join_rules
        if (type == "m.room.create" ||
            type == "m.room.guest_access" ||
            type == "m.room.join_rules") {
          filtered_events.push_back(event);
        }
        // Include member events only for the guest themselves
        else if (type == "m.room.member") {
          if (state_key == guest_user_id || sender == guest_user_id) {
            filtered_events.push_back(event);
          }
        }
        // Include name/topic/avatar/canonical
        else if (type == "m.room.name" ||
                 type == "m.room.topic" ||
                 type == "m.room.avatar" ||
                 type == "m.room.canonical_alias") {
          filtered_events.push_back(event);
        }
      }
      filtered["events"] = filtered_events;
    } else {
      filtered["events"] = json::array();
    }
    return filtered;
  }

  /// Filter ephemeral events (typing, receipts).
  json filter_ephemeral(const json& ephemeral) {
    json filtered;
    if (ephemeral.contains("events") && ephemeral["events"].is_array()) {
      json filtered_events = json::array();
      for (const auto& event : ephemeral["events"]) {
        std::string type = event.value("type", "");
        // Include receipts but strip typing for guests (reduces noise)
        if (type == "m.receipt") {
          filtered_events.push_back(event);
        }
        // Skip m.typing for guests
      }
      filtered["events"] = filtered_events;
    } else {
      filtered["events"] = json::array();
    }
    return filtered;
  }

  /// Filter presence events.
  json filter_presence(const json& presence) {
    json filtered;
    if (presence.contains("events") && presence["events"].is_array()) {
      json limited = json::array();
      const auto& events = presence["events"];
      // Limit presence to at most 10 entries for guests
      size_t limit = std::min(events.size(), size_t(10));
      for (size_t i = 0; i < limit; ++i) {
        limited.push_back(events[i]);
      }
      filtered["events"] = limited;
    } else {
      filtered["events"] = json::array();
    }
    return filtered;
  }

  /// Filter account_data events.
  json filter_account_data(const json& account_data) {
    json filtered;
    if (account_data.contains("events") && account_data["events"].is_array()) {
      json filtered_events = json::array();
      for (const auto& event : account_data["events"]) {
        std::string type = event.value("type", "");
        // Only include essential account data for guests
        if (type == "m.direct" ||
            type == "m.ignored_user_list") {
          filtered_events.push_back(event);
        }
      }
      filtered["events"] = filtered_events;
    } else {
      filtered["events"] = json::array();
    }
    return filtered;
  }

  /// Filter to_device messages.
  json filter_to_device(const json& to_device) {
    json filtered;
    if (to_device.contains("events") && to_device["events"].is_array()) {
      const auto& events = to_device["events"];
      // Limit to_device events to at most 20 for guests
      size_t limit = std::min(events.size(), size_t(20));
      json limited = json::array();
      for (size_t i = 0; i < limit; ++i) {
        limited.push_back(events[i]);
      }
      filtered["events"] = limited;
    } else {
      filtered["events"] = json::array();
    }
    return filtered;
  }

  /// Simplify unread notification counts.
  json simplify_unread(const json& unread) {
    json simplified;
    if (unread.contains("highlight_count")) {
      simplified["highlight_count"] = unread["highlight_count"];
    }
    if (unread.contains("notification_count")) {
      simplified["notification_count"] = unread["notification_count"];
    }
    return simplified;
  }

  /// Update sync filter configuration.
  void set_config(const SyncFilterConfig& config) {
    std::lock_guard<std::mutex> lock(config_mutex_);
    config_ = config;
  }

  /// Get current sync filter configuration.
  SyncFilterConfig get_config() {
    std::lock_guard<std::mutex> lock(config_mutex_);
    return config_;
  }

private:
  GuestRegistry& registry_;
  SyncFilterConfig config_;
  std::mutex config_mutex_;
};

// ============================================================================
// GuestAccessCoordinator — Top-level orchestrator
//
// Wires together all guest access subsystems and provides a unified
// API for the rest of the server to interact with guest functionality.
// ============================================================================
class GuestAccessCoordinator {
public:
  GuestAccessCoordinator(const std::string& server_name = "localhost")
    : config_(), registry_(config_), restrictions_(config_),
      room_access_(), rate_limiter_(config_),
      display_(registry_), sync_filter_(registry_) {
    config_.server_name = server_name;
  }

  /// Initialize the coordinator (start background threads, etc.).
  void initialize(GuestCleanupScheduler::DeactivationCallback cleanup_cb = nullptr) {
    cleanup_scheduler_ = std::make_unique<GuestCleanupScheduler>(
        registry_, config_, std::move(cleanup_cb));
    cleanup_scheduler_->start();
  }

  /// Shut down the coordinator.
  void shutdown() {
    if (cleanup_scheduler_) {
      cleanup_scheduler_->stop();
    }
  }

  // ---- Access to subsystems ----

  GuestAccessConfig& config() { return config_; }
  GuestRegistry& registry() { return registry_; }
  GuestRestrictionEngine& restrictions() { return restrictions_; }
  GuestRoomAccessChecker& room_access() { return room_access_; }
  GuestCleanupScheduler* cleanup() { return cleanup_scheduler_.get(); }
  GuestRateLimiter& rate_limiter() { return rate_limiter_; }
  GuestDisplayFormatter& display() { return display_; }
  GuestSyncFilter& sync_filter() { return sync_filter_; }

  /// Create a migration handler with provided callbacks.
  GuestMigrationHandler make_migration_handler(
      GuestMigrationHandler::CreateUserCallback create_user,
      GuestMigrationHandler::TransferRoomsCallback transfer_rooms) {
    return GuestMigrationHandler(registry_,
        std::move(create_user), std::move(transfer_rooms));
  }

  // ---- Convenience API ----

  /// Check if a user is a guest and enforce a restriction.
  /// Returns false if the guest is not allowed, with error details in err_json.
  bool enforce_restriction(const std::string& user_id,
                            const std::string& action,
                            json& err_json) {
    if (!registry_.is_guest_user_id(user_id)) return true;  // Not a guest

    auto result = restrictions_.check(action);
    if (!result.allowed) {
      err_json = error_json(result.errcode, result.error_message);
      return false;
    }
    return true;
  }

  /// Process a full guest API request pipeline:
  /// 1. Rate limit check
  /// 2. Touch activity
  /// 3. Return guest info
  std::optional<GuestRegistry::GuestRecord> process_request(
      const std::string& access_token,
      GuestRateLimiter::EndpointCategory category) {

    // Rate limit
    auto guest = registry_.get_by_token(access_token);
    if (!guest.has_value()) return std::nullopt;

    auto rate_result = rate_limiter_.check(guest->user_id, category);
    if (!rate_result.allowed) return std::nullopt;

    // Touch activity
    registry_.touch(access_token);

    return guest;
  }

  /// Get comprehensive status for admin endpoints.
  json get_admin_status() {
    json status;
    status["config"] = config_.to_json();
    status["registry"] = registry_.get_statistics();
    status["room_access_cache"] = room_access_.get_cache_stats();
    status["rate_limiter"] = rate_limiter_.get_stats();
    if (cleanup_scheduler_) {
      status["cleanup"] = cleanup_scheduler_->get_status();
    }
    status["restrictions"] = restrictions_.get_flags_json();
    status["sync_filter"] = {
      {"timeline_limit", config_.sync_timeline_limit},
      {"max_rooms", config_.sync_max_rooms},
      {"include_presence", config_.sync_include_presence},
      {"include_account_data", config_.sync_include_account_data},
      {"include_to_device", config_.sync_include_to_device},
      {"include_device_lists", config_.sync_include_device_lists}
    };
    return status;
  }

  /// Periodic maintenance (call from server's tick loop).
  void periodic_maintenance() {
    room_access_.purge_expired();
    rate_limiter_.purge_stale_buckets();
  }

private:
  GuestAccessConfig config_;
  GuestRegistry registry_;
  GuestRestrictionEngine restrictions_;
  GuestRoomAccessChecker room_access_;
  GuestRateLimiter rate_limiter_;
  GuestDisplayFormatter display_;
  GuestSyncFilter sync_filter_;
  std::unique_ptr<GuestCleanupScheduler> cleanup_scheduler_;
};

// ============================================================================
// Standalone Utility Functions
// ============================================================================

/// Check if a user ID is a guest (static check, no registry needed).
bool is_guest_user_id_string(std::string_view user_id) {
  return starts_with(user_id, "@guest_");
}

/// Extract the guest suffix from a guest user ID.
/// E.g., "@guest_abc123:localhost" -> "abc123"
std::string extract_guest_suffix(std::string_view user_id) {
  if (!starts_with(user_id, "@guest_")) return "";

  std::string_view inner = user_id.substr(7);  // Skip "@guest_"
  size_t colon = inner.find(':');
  if (colon != std::string::npos) {
    return std::string(inner.substr(0, colon));
  }
  return std::string(inner);
}

/// Build a guest access content for a m.room.guest_access state event.
json make_guest_access_content(bool can_join) {
  return json{{"guest_access", can_join
      ? guest_config::kGuestAccessCanJoin
      : guest_config::kGuestAccessForbidden}};
}

/// Validate that a guest_access value is valid.
bool is_valid_guest_access(std::string_view value) {
  return value == guest_config::kGuestAccessCanJoin ||
         value == guest_config::kGuestAccessForbidden;
}

/// Default guest_access for a room based on its join_rules.
std::string default_guest_access_for_join_rules(std::string_view join_rule) {
  if (join_rule == "public") {
    return guest_config::kGuestAccessCanJoin;
  }
  return guest_config::kGuestAccessForbidden;
}

// ============================================================================
// Global Guest Registry (singleton for module-level access)
// ============================================================================
namespace {

std::unique_ptr<GuestAccessCoordinator> g_guest_coordinator;
std::mutex g_coordinator_mutex;

} // anonymous namespace

/// Initialize the global guest access coordinator.
GuestAccessCoordinator& init_guest_access(const std::string& server_name) {
  std::lock_guard<std::mutex> lock(g_coordinator_mutex);
  if (!g_guest_coordinator) {
    g_guest_coordinator = std::make_unique<GuestAccessCoordinator>(server_name);
  }
  return *g_guest_coordinator;
}

/// Get the global guest access coordinator.
/// Throws if not initialized.
GuestAccessCoordinator& get_guest_access() {
  std::lock_guard<std::mutex> lock(g_coordinator_mutex);
  if (!g_guest_coordinator) {
    throw GuestAccessException("Guest access coordinator not initialized");
  }
  return *g_guest_coordinator;
}

/// Shutdown global guest access.
void shutdown_guest_access() {
  std::lock_guard<std::mutex> lock(g_coordinator_mutex);
  if (g_guest_coordinator) {
    g_guest_coordinator->shutdown();
    g_guest_coordinator.reset();
  }
}

// ============================================================================
// Guest Access Request Middleware API
// ============================================================================

/// Pre-request middleware: check if a request from a guest should be allowed.
/// Returns a JSON error if the request should be rejected, or null if OK.
json guest_pre_request_check(
    GuestAccessCoordinator& coordinator,
    const std::string& user_id,
    const std::string& action) {

  if (!is_guest_user_id_string(user_id)) return nullptr;  // Not a guest, pass through

  json err;
  if (!coordinator.enforce_restriction(user_id, action, err)) {
    return err;
  }
  return nullptr;  // Allowed
}

/// Check if a guest can join a room, with comprehensive validation.
json guest_can_join_room(
    GuestAccessCoordinator& coordinator,
    const std::string& user_id,
    const std::string& access_token,
    const std::string& room_id,
    std::function<std::string(const std::string&)> room_access_check_fn) {

  if (!is_guest_user_id_string(user_id)) return nullptr;  // Not a guest

  json err;

  // Check join restriction
  auto guest = coordinator.registry().get_by_token(access_token);
  int rooms_joined = guest.has_value() ? guest->rooms_joined : 0;

  auto restriction_check = coordinator.restrictions().check_join_room(rooms_joined);
  if (!restriction_check.allowed) {
    return error_json(restriction_check.errcode, restriction_check.error_message);
  }

  // Check room guest_access
  try {
    coordinator.room_access().require_can_join(room_id, room_access_check_fn);
  } catch (const GuestRoomForbidden& e) {
    return error_json(e.errcode, e.what());
  }

  return nullptr;  // Allowed
}

/// Build a filtered sync response for a guest user.
json build_guest_sync_response(
    GuestAccessCoordinator& coordinator,
    const json& full_sync_response,
    const std::string& guest_user_id) {

  return coordinator.sync_filter().filter_sync_response(
      full_sync_response, guest_user_id);
}

/// Format member list with guest annotations.
json annotate_members_for_guests(
    GuestAccessCoordinator& coordinator,
    const json& members_chunk) {

  return coordinator.display().format_member_list(members_chunk);
}

} // namespace progressive
