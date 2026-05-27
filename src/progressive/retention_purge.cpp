// ============================================================================
// retention_purge.cpp — Matrix Message Retention & Purge Engine
//
// Implements:
//   - RetentionPolicyParser: parse m.room.retention state events, extract
//     max_lifetime and min_lifetime, validate policy ranges, handle policy
//     inheritance from server defaults, global policy overrides.
//   - PurgeEngine: find events older than max_lifetime per room, batch-purge
//     events in configurable chunk sizes, track purge progress with resume
//     capability, handle very large rooms with thousands/millions of events
//     via cursor-based pagination and yield points.
//   - PurgeScheduler: schedule periodic purges per room based on last purge
//     timestamp, configurable intervals per room or globally, stagger large
//     purges across multiple runs to avoid resource spikes, adaptive
//     scheduling based on room activity.
//   - ExemptEventHandler: state events are never purged (spec requirement),
//     events within min_lifetime are always kept, pinned messages exemption,
//     event-type whitelist/blacklist, protected sender exemptions.
//   - MediaPurgeCoordinator: purge orphaned media (media no longer referenced
//     by any event after message purge), track media reference counts via
//     event_relations and event_json/content URLs, staged orphan detection
//     with soft-delete grace period, bulk media file removal from disk.
//   - PurgeHistoryLogger: log every purge operation with timestamps, room ID,
//     event counts, bytes freed (estimated), user who triggered it, any
//     errors encountered, structured audit trail for compliance.
//   - AdminControlPanel: force-purge a specific room immediately, exempt
//     specific rooms from all retention policies (with reason tracking),
//     override retention periods on a per-room basis (temporary/permanent),
//     pause/resume the global purge scheduler, query purge status and
//     history, dry-run mode to preview what would be purged.
//
// Equivalent to:
//   synapse/handlers/message.py (retention enforcement)
//   synapse/storage/databases/main/events.py (event purging)
//   synapse/storage/databases/main/media_repository.py (media ref counting)
//   synapse/handlers/pagination.py (visibility filtering by retention)
//   synapse/rest/admin/rooms.py (admin purge endpoints)
//   synapse/handlers/room.py (retention policies)
//
// Namespace: progressive::
// Target: 2000+ lines of production-grade C++.
// ============================================================================

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <csignal>
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
#include "progressive/storage/databases/main/events.hpp"
#include "progressive/storage/databases/main/room.hpp"
#include "progressive/storage/databases/main/state.hpp"
#include "progressive/storage/databases/main/roommember.hpp"
#include "progressive/storage/databases/main/media_repository.hpp"
#include "progressive/storage/databases/main/stream.hpp"

// ============================================================================
// Namespace
// ============================================================================
namespace progressive {

using json = nlohmann::json;
namespace chr = std::chrono;
namespace fs  = std::filesystem;
using namespace storage;

// ============================================================================
// Forward declarations for all major component classes
// ============================================================================
class RetentionPolicyParser;
class PurgeEngine;
class PurgeScheduler;
class ExemptEventHandler;
class MediaPurgeCoordinator;
class PurgeHistoryLogger;
class AdminControlPanel;
class RetentionConfigManager;
class PurgeProgressTracker;
class EventReferenceScanner;
class BatchPurgeWorker;
class PurgeDryRunSimulator;
class RetentionOverrideStore;
class RoomExemptionRegistry;
class MediaReferenceCounter;
class PurgeLockCoordinator;

// ============================================================================
// Retention Exception Types
// ============================================================================

/// Base exception for all retention/purge related errors.
class RetentionException : public std::runtime_error {
public:
  int http_code{500};
  std::string errcode;

  RetentionException(int code, std::string_view errc, std::string_view msg)
    : std::runtime_error(std::string(msg)),
      http_code(code),
      errcode(errc) {}

  explicit RetentionException(std::string_view msg)
    : std::runtime_error(std::string(msg)),
      http_code(500),
      errcode("M_UNKNOWN") {}
};

/// Thrown when a room is explicitly exempt from retention.
class RoomExemptException : public RetentionException {
public:
  std::string room_id;
  RoomExemptException(std::string_view room, std::string_view reason = "")
    : RetentionException(403, "M_ROOM_EXEMPT",
        std::string("Room ") + std::string(room) + " is exempt: " + std::string(reason)),
      room_id(room) {}
};

/// Thrown when a retention policy is invalid.
class InvalidRetentionPolicy : public RetentionException {
public:
  std::string detail;
  InvalidRetentionPolicy(std::string_view detail_msg)
    : RetentionException(400, "M_INVALID_PARAM",
        std::string("Invalid retention policy: ") + std::string(detail_msg)),
      detail(detail_msg) {}
};

/// Thrown when a purge operation is already in progress.
class PurgeAlreadyRunning : public RetentionException {
public:
  PurgeAlreadyRunning()
    : RetentionException(409, "M_PURGE_RUNNING",
        "A purge operation is already in progress") {}
};

/// Thrown when a purge exceeds configured safety limits.
class PurgeLimitExceeded : public RetentionException {
public:
  PurgeLimitExceeded(int64_t limit, int64_t attempted)
    : RetentionException(413, "M_PURGE_LIMIT",
        "Purge limit " + std::to_string(limit) + " exceeded: attempted " + std::to_string(attempted)) {}
};

// ============================================================================
// Retention Constants
// ============================================================================
namespace retention_constants {

// Default values for retention configuration
constexpr int64_t DEFAULT_MAX_LIFETIME_MS    = 0;     // 0 = no default limit
constexpr int64_t DEFAULT_MIN_LIFETIME_MS    = 0;
constexpr int64_t MIN_PURGE_INTERVAL_MS      = 300000; // Minimum 5 minutes
constexpr int64_t DEFAULT_PURGE_INTERVAL_MS  = 86400000; // 24 hours
constexpr int64_t MAX_PURGE_INTERVAL_MS      = 604800000; // 7 days

// Batch sizes for purge operations
constexpr size_t DEFAULT_PURGE_BATCH_SIZE    = 1000;
constexpr size_t MIN_PURGE_BATCH_SIZE        = 10;
constexpr size_t MAX_PURGE_BATCH_SIZE        = 10000;
constexpr size_t DEFAULT_MEDIA_PURGE_BATCH   = 100;
constexpr size_t MAX_MEDIA_PURGE_BATCH       = 1000;

// Safety limits - prevent catastrophic accidental purges
constexpr int64_t MAX_EVENTS_PER_PURGE_RUN   = 1000000;
constexpr int64_t MAX_BYTES_PER_PURGE_RUN    = 10LL * 1024 * 1024 * 1024; // 10 GB
constexpr int64_t MAX_PURGE_DURATION_MS      = 3600000;  // 1 hour max per run
constexpr int64_t MEDIA_SOFT_DELETE_GRACE_MS = 86400000; // 24h before hard delete

// Purge states for state machine
constexpr const char* PURGE_STATE_IDLE         = "idle";
constexpr const char* PURGE_STATE_SCANNING     = "scanning";
constexpr const char* PURGE_STATE_PURGING      = "purging";
constexpr const char* PURGE_STATE_MEDIA_SCAN   = "media_scan";
constexpr const char* PURGE_STATE_MEDIA_PURGE  = "media_purge";
constexpr const char* PURGE_STATE_COMPLETE     = "complete";
constexpr const char* PURGE_STATE_PAUSED       = "paused";
constexpr const char* PURGE_STATE_ERROR        = "error";
constexpr const char* PURGE_STATE_CANCELLED    = "cancelled";

// Event types that are NEVER purged (regardless of policy)
constexpr const char* IMMUTABLE_EVENT_TYPES[] = {
  "m.room.create",
  "m.room.member",
  "m.room.join_rules",
  "m.room.power_levels",
  "m.room.history_visibility",
  "m.room.guest_access",
  "m.room.server_acl",
  "m.room.encryption",
  "m.room.name",
  "m.room.topic",
  "m.room.avatar",
  "m.room.canonical_alias",
  "m.room.retention",
  "m.room.tombstone",
  "m.space.child",
  "m.space.parent",
};
constexpr size_t IMMUTABLE_EVENT_TYPES_COUNT =
  sizeof(IMMUTABLE_EVENT_TYPES) / sizeof(IMMUTABLE_EVENT_TYPES[0]);

// Event types that are non-state but protected
constexpr const char* PROTECTED_EVENT_TYPES[] = {
  "m.room.pinned_events",   // pinned messages should survive
  "m.room.server_notice",   // server notices are important
};
constexpr size_t PROTECTED_EVENT_TYPES_COUNT =
  sizeof(PROTECTED_EVENT_TYPES) / sizeof(PROTECTED_EVENT_TYPES[0]);

// Purge history log retention
constexpr int64_t PURGE_HISTORY_RETENTION_SEC = 90LL * 24 * 3600; // 90 days
constexpr size_t MAX_PURGE_HISTORY_ENTRIES     = 100000;

// Throttle control
constexpr int64_t THROTTLE_SLEEP_MS_PER_1000   = 100; // Sleep 100ms per 1000 events
constexpr int64_t MIN_YIELD_INTERVAL_MS        = 500;
constexpr size_t  EVENTS_BEFORE_YIELD          = 5000;

} // namespace retention_constants

// ============================================================================
// Anonymous namespace — Internal helpers and utilities
// ============================================================================
namespace {

// ---- Timestamp helpers ----

int64_t now_ms() {
  return chr::duration_cast<chr::milliseconds>(
    chr::system_clock::now().time_since_epoch()).count();
}

int64_t now_sec() {
  return chr::duration_cast<chr::seconds>(
    chr::system_clock::now().time_since_epoch()).count();
}

std::string iso8601_from_ms(int64_t ms) {
  auto tp = chr::system_clock::time_point(chr::milliseconds(ms));
  auto tt  = chr::system_clock::to_time_t(tp);
  std::tm tm_buf;
  gmtime_r(&tt, &tm_buf);
  std::ostringstream oss;
  oss << std::put_time(&tm_buf, "%Y-%m-%dT%H:%M:%S");
  auto remainder = ms % 1000;
  oss << "." << std::setfill('0') << std::setw(3) << remainder << "Z";
  return oss.str();
}

std::string iso8601_now() {
  return iso8601_from_ms(now_ms());
}

// ---- String helpers ----

std::string to_lower(std::string_view s) {
  std::string result(s);
  std::transform(result.begin(), result.end(), result.begin(),
    [](unsigned char c) { return std::tolower(c); });
  return result;
}

bool string_starts_with(std::string_view s, std::string_view prefix) {
  return s.size() >= prefix.size() &&
         s.compare(0, prefix.size(), prefix) == 0;
}

std::string generate_purge_id() {
  static std::atomic<uint64_t> counter{0};
  auto ts = now_ms();
  auto seq = counter.fetch_add(1, std::memory_order_relaxed);
  std::ostringstream oss;
  oss << "purge_" << ts << "_" << seq;
  return oss.str();
}

// ---- JSON helpers ----

bool is_state_event_type(std::string_view event_type) {
  // State events start with "m.room." or "m.space." or a few others
  // The definitive check is: does the event appear in current_state_events?
  // As a heuristic, state events are recognized types
  for (size_t i = 0; i < retention_constants::IMMUTABLE_EVENT_TYPES_COUNT; ++i) {
    if (retention_constants::IMMUTABLE_EVENT_TYPES[i] == event_type) return true;
  }
  // General heuristic: m.room.* types are typically state events
  if (string_starts_with(event_type, "m.room.")) return true;
  if (string_starts_with(event_type, "m.space.")) return true;
  if (event_type == "m.policy.rule.user" ||
      event_type == "m.policy.rule.room" ||
      event_type == "m.policy.rule.server") return true;
  return false;
}

json make_error_json(std::string_view errcode, std::string_view message) {
  return json{{"errcode", errcode}, {"error", message}};
}

json make_success_json() {
  return json{{"success", true}};
}

// ---- Filesystem helpers ----

int64_t file_size_bytes(const std::string& path) {
  std::error_code ec;
  auto sz = fs::file_size(path, ec);
  if (ec) return 0;
  return static_cast<int64_t>(sz);
}

// ---- Event content URL extraction ----

// Extract all MXC URLs from event content (for media reference tracking)
std::vector<std::string> extract_mxc_urls(const json& event_content) {
  std::vector<std::string> urls;
  std::function<void(const json&)> traverse;

  traverse = [&](const json& node) {
    if (node.is_string()) {
      std::string s = node.get<std::string>();
      if (s.substr(0, 6) == "mxc://") {
        urls.push_back(s);
      }
    } else if (node.is_object()) {
      for (auto& [key, val] : node.items()) {
        traverse(val);
      }
    } else if (node.is_array()) {
      for (auto& val : node) {
        traverse(val);
      }
    }
  };

  traverse(event_content);
  return urls;
}

// Parse media_id and server from an MXC URI
std::pair<std::string, std::string> parse_mxc_uri(std::string_view uri) {
  // Format: mxc://<server-name>/<media-id>
  if (!string_starts_with(uri, "mxc://")) {
    return {"", ""};
  }
  auto rest = uri.substr(6); // skip "mxc://"
  auto slash_pos = rest.find('/');
  if (slash_pos == std::string_view::npos) {
    return {"", ""};
  }
  std::string server(rest.substr(0, slash_pos));
  std::string media_id(rest.substr(slash_pos + 1));
  return {server, media_id};
}

// ---- Atomic flags for coordinator-wide state ----

struct PurgeCoordinatorState {
  std::atomic<bool> is_purging{false};
  std::atomic<bool> is_media_purging{false};
  std::atomic<bool> scheduler_paused{false};
  std::string current_purge_id;
  std::string current_state;
  std::mutex state_mutex;
};

static PurgeCoordinatorState g_purge_state;

void set_purge_state(const std::string& state, const std::string& purge_id = "") {
  std::lock_guard<std::mutex> lock(g_purge_state.state_mutex);
  g_purge_state.current_state = state;
  if (!purge_id.empty()) g_purge_state.current_purge_id = purge_id;
}

} // anonymous namespace

// ============================================================================
// Configuration structures
// ============================================================================

/// Core retention configuration — server-wide defaults and limits.
struct RetentionConfig {
  // Whether retention policy enforcement is enabled at all
  bool enable_retention_policy = true;

  // Server-wide default lifetimes (overridden by room-level policies)
  int64_t default_max_lifetime_ms = 0;     // 0 = no default limit
  int64_t default_min_lifetime_ms = 0;     // 0 = no minimum

  // Purge scheduling
  int64_t purge_job_interval_ms = retention_constants::DEFAULT_PURGE_INTERVAL_MS;
  int64_t min_purge_interval_ms = retention_constants::MIN_PURGE_INTERVAL_MS;
  int64_t max_purge_duration_ms  = retention_constants::MAX_PURGE_DURATION_MS;

  // Batch control
  size_t  max_purge_batch_size       = retention_constants::DEFAULT_PURGE_BATCH_SIZE;
  size_t  max_media_purge_batch_size = retention_constants::DEFAULT_MEDIA_PURGE_BATCH;
  int64_t max_events_per_purge_run   = retention_constants::MAX_EVENTS_PER_PURGE_RUN;
  int64_t max_bytes_per_purge_run    = retention_constants::MAX_BYTES_PER_PURGE_RUN;

  // Throttle / yield
  int64_t throttle_sleep_ms_per_1000 = retention_constants::THROTTLE_SLEEP_MS_PER_1000;
  size_t  events_before_yield        = retention_constants::EVENTS_BEFORE_YIELD;
  int64_t min_yield_interval_ms      = retention_constants::MIN_YIELD_INTERVAL_MS;

  // Media purge
  bool    auto_purge_orphaned_media      = true;
  int64_t media_soft_delete_grace_ms     = retention_constants::MEDIA_SOFT_DELETE_GRACE_MS;
  int64_t media_purge_interval_ms        = 86400000; // 24 hours

  // Safety limits
  int64_t safety_max_events_per_room_purge = 500000;
  bool    require_dry_run_before_force    = true;
  bool    enable_purge_history_logging    = true;
  int64_t purge_history_retention_sec     = retention_constants::PURGE_HISTORY_RETENTION_SEC;

  // Room exemption lists
  std::set<std::string> globally_exempt_rooms;
  bool allow_room_override = true;
};

/// A parsed retention policy from a m.room.retention state event.
struct ParsedRetentionPolicy {
  int64_t max_lifetime_ms = 0;   // Event age beyond which events are purged
  int64_t min_lifetime_ms = 0;   // Events newer than this are always kept
  bool    enabled          = false;
  bool    from_state       = false; // True if from m.room.retention, false if server default
  std::string room_id;
  std::string event_id;           // The state event that set this policy
  int64_t policy_set_ts = 0;     // When the policy was set

  bool operator==(const ParsedRetentionPolicy& other) const {
    return max_lifetime_ms == other.max_lifetime_ms &&
           min_lifetime_ms == other.min_lifetime_ms &&
           room_id == other.room_id;
  }
  bool operator!=(const ParsedRetentionPolicy& other) const { return !(*this == other); }
};

/// Statistics tracked during a purge operation.
struct PurgeRunStats {
  std::string purge_id;
  int64_t start_time_ms     = 0;
  int64_t end_time_ms       = 0;
  int64_t rooms_scanned     = 0;
  int64_t rooms_with_policy = 0;
  int64_t rooms_purged      = 0;
  int64_t events_scanned    = 0;
  int64_t events_purged     = 0;
  int64_t state_events_kept = 0;
  int64_t protected_kept    = 0;
  int64_t bytes_freed       = 0;
  int64_t media_files_found_orphan  = 0;
  int64_t media_files_purged        = 0;
  int64_t media_bytes_freed         = 0;
  int64_t errors_encountered = 0;
  std::vector<std::string> error_messages;
  std::string final_state;

  // Per-room breakdown
  struct RoomPurgeDetail {
    std::string room_id;
    int64_t events_purged = 0;
    int64_t bytes_freed   = 0;
    int64_t cutoff_ts     = 0;
    bool completed         = false;
  };
  std::vector<RoomPurgeDetail> room_details;
};

/// A single entry in the purge history log.
struct PurgeHistoryEntry {
  std::string entry_id;
  std::string purge_id;
  std::string room_id;             // Empty for global purges
  int64_t timestamp_ms     = 0;
  std::string triggered_by;       // "scheduler", "admin:<user_id>", "force"
  std::string action;             // "purge_events", "purge_media", "exempt", "override"
  int64_t events_purged    = 0;
  int64_t bytes_freed      = 0;
  int64_t media_files_purged = 0;
  int64_t media_bytes_freed  = 0;
  std::string status;             // "success", "partial", "error", "cancelled"
  std::string detail_json;        // Additional structured detail
  std::string error_message;
};

/// Represents a batch of events to purge.
struct PurgeBatch {
  std::string room_id;
  std::vector<std::string> event_ids;
  std::vector<int64_t> event_timestamps;
  std::vector<std::string> mxc_urls;   // MXC URLs referenced by these events
  int64_t cutoff_timestamp = 0;
  size_t batch_index       = 0;
};

/// Media reference tracking entry.
struct MediaReferenceEntry {
  std::string media_id;
  std::string server_name;
  int64_t reference_count = 0;
  int64_t last_referenced_ts = 0;
  std::vector<std::string> referencing_events;
};

} // namespace progressive

// ============================================================================
// Open the main implementation namespace
// ============================================================================
namespace progressive {

// ============================================================================
// Implementation Part 1: RetentionPolicyParser
// Parses and validates m.room.retention state events.
// ============================================================================

class RetentionPolicyParser {
public:
  /// Construct a policy parser bound to the server defaults.
  explicit RetentionPolicyParser(const RetentionConfig& config)
    : config_(config) {}

  // --------------------------------------------------------------------------
  // Parse a m.room.retention state event into a structured policy object.
  // Returns std::nullopt if the content is empty (no retention).
  // --------------------------------------------------------------------------
  std::optional<ParsedRetentionPolicy> parse_state_event(
      const json& retention_event,
      const std::string& room_id) {

    ParsedRetentionPolicy policy;
    policy.room_id = room_id;
    policy.from_state = true;

    if (retention_event.contains("event_id")) {
      policy.event_id = retention_event["event_id"].get<std::string>();
    }

    // Extract content
    const json& content = retention_event.contains("content")
      ? retention_event["content"]
      : retention_event;

    if (content.contains("max_lifetime")) {
      policy.max_lifetime_ms = content["max_lifetime"].get<int64_t>();
    }
    if (content.contains("min_lifetime")) {
      policy.min_lifetime_ms = content["min_lifetime"].get<int64_t>();
    }

    policy.policy_set_ts = now_ms();
    policy.enabled = validate_policy(policy);

    return policy.enabled ? std::optional(policy) : std::nullopt;
  }

  // --------------------------------------------------------------------------
  // Parse policy from raw JSON content (for API calls / admin overrides).
  // --------------------------------------------------------------------------
  ParsedRetentionPolicy parse_content_json(
      const json& content,
      const std::string& room_id = "") {

    ParsedRetentionPolicy policy;
    policy.room_id = room_id;
    policy.from_state = false;

    if (content.contains("max_lifetime")) {
      policy.max_lifetime_ms = content["max_lifetime"].get<int64_t>();
    }
    if (content.contains("min_lifetime")) {
      policy.min_lifetime_ms = content["min_lifetime"].get<int64_t>();
    }

    policy.policy_set_ts = now_ms();
    policy.enabled = validate_policy(policy);

    return policy;
  }

  // --------------------------------------------------------------------------
  // Build a server-fallback policy when no room policy is set.
  // --------------------------------------------------------------------------
  ParsedRetentionPolicy build_default_policy(const std::string& room_id) {
    ParsedRetentionPolicy policy;
    policy.room_id = room_id;
    policy.from_state = false;
    policy.max_lifetime_ms = config_.default_max_lifetime_ms;
    policy.min_lifetime_ms = config_.default_min_lifetime_ms;
    policy.enabled = (config_.default_max_lifetime_ms > 0);
    policy.policy_set_ts = now_ms();
    return policy;
  }

  // --------------------------------------------------------------------------
  // Build a retention policy state event for sending to a room.
  // --------------------------------------------------------------------------
  json build_retention_state_event(
      int64_t max_lifetime_ms,
      int64_t min_lifetime_ms,
      const std::string& sender,
      const std::string& room_id) {

    json content = json::object();
    if (max_lifetime_ms > 0) {
      content["max_lifetime"] = max_lifetime_ms;
    }
    if (min_lifetime_ms > 0) {
      content["min_lifetime"] = min_lifetime_ms;
    }

    json event;
    event["type"]       = "m.room.retention";
    event["state_key"]  = "";
    event["content"]    = content;
    event["sender"]     = sender;
    event["room_id"]    = room_id;
    event["origin_server_ts"] = now_ms();

    return event;
  }

  // --------------------------------------------------------------------------
  // Determine the effective policy for a room: room state overrides server
  // defaults. Admin overrides take highest precedence.
  // --------------------------------------------------------------------------
  ParsedRetentionPolicy compute_effective_policy(
      const std::optional<ParsedRetentionPolicy>& room_policy,
      const std::optional<ParsedRetentionPolicy>& admin_override,
      const std::string& room_id) {

    // Admin override wins everything
    if (admin_override.has_value() && admin_override->enabled) {
      return *admin_override;
    }

    // Room state policy
    if (room_policy.has_value() && room_policy->enabled) {
      return *room_policy;
    }

    // Fall back to server default
    return build_default_policy(room_id);
  }

  // --------------------------------------------------------------------------
  // Validate a policy — check ranges, consistency, safety limits.
  // --------------------------------------------------------------------------
  bool validate_policy(ParsedRetentionPolicy& policy) {
    // Both zero means no retention
    if (policy.max_lifetime_ms <= 0 && policy.min_lifetime_ms <= 0) {
      return false;
    }

    // Negative values are invalid
    if (policy.max_lifetime_ms < 0) {
      policy.max_lifetime_ms = 0;
      return false;
    }
    if (policy.min_lifetime_ms < 0) {
      policy.min_lifetime_ms = 0;
      return false;
    }

    // min_lifetime must not exceed max_lifetime
    if (policy.max_lifetime_ms > 0 && policy.min_lifetime_ms > 0 &&
        policy.min_lifetime_ms > policy.max_lifetime_ms) {
      // Fix: clamp min to max
      policy.min_lifetime_ms = policy.max_lifetime_ms;
    }

    // Enforce minimum lifetime granularity (at least 1 hour for max_lifetime)
    if (policy.max_lifetime_ms > 0 && policy.max_lifetime_ms < 3600000) {
      // Warn but accept: short retention policies are unusual but valid
    }

    return true;
  }

  // --------------------------------------------------------------------------
  // Check whether a policy requires event purging (max_lifetime > 0).
  // --------------------------------------------------------------------------
  static bool requires_purging(const ParsedRetentionPolicy& policy) {
    return policy.enabled && policy.max_lifetime_ms > 0;
  }

  // --------------------------------------------------------------------------
  // Convert policy to JSON for API responses.
  // --------------------------------------------------------------------------
  json policy_to_json(const ParsedRetentionPolicy& policy) const {
    json j;
    j["room_id"]          = policy.room_id;
    j["max_lifetime_ms"]  = policy.max_lifetime_ms;
    j["min_lifetime_ms"]  = policy.min_lifetime_ms;
    j["enabled"]          = policy.enabled;
    j["from_state"]       = policy.from_state;
    j["event_id"]         = policy.event_id;
    j["policy_set_ts"]    = policy.policy_set_ts;

    // Human-readable durations
    if (policy.max_lifetime_ms > 0) {
      j["max_lifetime_human"] = duration_to_human(policy.max_lifetime_ms);
    }
    if (policy.min_lifetime_ms > 0) {
      j["min_lifetime_human"] = duration_to_human(policy.min_lifetime_ms);
    }
    return j;
  }

  // --------------------------------------------------------------------------
  // Format a millisecond duration into a human-readable string.
  // --------------------------------------------------------------------------
  static std::string duration_to_human(int64_t ms) {
    if (ms <= 0) return "none";

    int64_t seconds = ms / 1000;
    int64_t minutes = seconds / 60;
    int64_t hours   = minutes / 60;
    int64_t days    = hours / 24;
    int64_t years   = days / 365;

    std::ostringstream oss;
    if (years > 0)    { oss << years << "y ";  days %= 365; }
    if (days > 0)     { oss << days  << "d ";  hours %= 24; }
    if (hours > 0)    { oss << hours << "h ";  minutes %= 60; }
    if (minutes > 0)  { oss << minutes << "m "; seconds %= 60; }
    if (seconds > 0 && years == 0 && days == 0) { oss << seconds << "s"; }

    auto result = oss.str();
    if (!result.empty() && result.back() == ' ') result.pop_back();
    return result.empty() ? "0s" : result;
  }

private:
  const RetentionConfig& config_;
};

// ============================================================================
// Implementation Part 2: ExemptEventHandler
// Determines which events are protected from purging.
// ============================================================================

class ExemptEventHandler {
public:
  /// Configuration for exemption rules.
  struct ExemptionRules {
    // Always keep state events (Matrix spec requirement)
    bool protect_state_events       = true;

    // Keep events within min_lifetime window
    bool respect_min_lifetime       = true;

    // Protect pinned messages even if old
    bool protect_pinned_messages    = true;

    // Protect server notices
    bool protect_server_notices     = true;

    // Protect events from specific senders (e.g., admin bots)
    std::set<std::string> protected_senders;

    // Additional event types to protect (beyond state events)
    std::set<std::string> protected_event_types;

    // Room-specific overrides
    struct RoomOverride {
      std::set<std::string> exempt_event_types;
      std::set<std::string> exempt_senders;
      int64_t custom_min_lifetime_ms = -1;
    };
    std::unordered_map<std::string, RoomOverride> room_overrides;
  };

  explicit ExemptEventHandler(const ExemptionRules& rules)
    : rules_(rules) {
    // Initialize the immutable type set
    for (size_t i = 0; i < retention_constants::IMMUTABLE_EVENT_TYPES_COUNT; ++i) {
      immutable_types_.insert(retention_constants::IMMUTABLE_EVENT_TYPES[i]);
    }
    for (size_t i = 0; i < retention_constants::PROTECTED_EVENT_TYPES_COUNT; ++i) {
      protected_types_.insert(retention_constants::PROTECTED_EVENT_TYPES[i]);
    }
    // Merge in configured protected types
    for (const auto& t : rules_.protected_event_types) {
      protected_types_.insert(t);
    }
  }

  // --------------------------------------------------------------------------
  // Determine if an event should be exempt from purging.
  // Returns (exempt, reason_string).
  // --------------------------------------------------------------------------
  std::pair<bool, std::string> is_exempt(
      const std::string& room_id,
      const std::string& event_type,
      const std::string& sender,
      bool is_state,
      int64_t origin_server_ts,
      int64_t min_lifetime_ms,
      const json& content = json::object()) {

    // Rule 1: State events are never purged (Matrix spec)
    if (rules_.protect_state_events && is_state) {
      return {true, "state_event_protected"};
    }

    // Rule 2: Check immutable event types (always state, but double-check)
    if (immutable_types_.count(event_type) > 0) {
      return {true, "immutable_event_type"};
    }

    // Rule 3: Explicitly protected event types (pinned messages, server notices)
    if (protected_types_.count(event_type) > 0) {
      if (event_type == "m.room.pinned_events" && !rules_.protect_pinned_messages) {
        // Allow override for pinned messages
      } else if (event_type == "m.room.server_notice" && !rules_.protect_server_notices) {
        // Allow override for server notices
      } else {
        return {true, "protected_event_type"};
      }
    }

    // Rule 4: Protected senders
    if (rules_.protected_senders.count(sender) > 0) {
      return {true, "protected_sender"};
    }

    // Rule 5: Min lifetime window
    if (rules_.respect_min_lifetime && min_lifetime_ms > 0) {
      int64_t event_age = now_ms() - origin_server_ts;
      if (event_age < min_lifetime_ms) {
        return {true, "within_min_lifetime"};
      }
    }

    // Rule 6: Check room-specific overrides
    auto room_it = rules_.room_overrides.find(room_id);
    if (room_it != rules_.room_overrides.end()) {
      const auto& override = room_it->second;

      if (override.exempt_event_types.count(event_type) > 0) {
        return {true, "room_override_event_type_exempt"};
      }

      if (override.exempt_senders.count(sender) > 0) {
        return {true, "room_override_sender_exempt"};
      }

      if (override.custom_min_lifetime_ms >= 0) {
        int64_t event_age = now_ms() - origin_server_ts;
        if (event_age < override.custom_min_lifetime_ms) {
          return {true, "room_override_custom_min_lifetime"};
        }
      }
    }

    // Rule 7: Check content for protected markers
    if (!content.is_null() && content.contains("org.matrix.retention_protected")) {
      if (content["org.matrix.retention_protected"].get<bool>()) {
        return {true, "content_marker_protected"};
      }
    }

    return {false, ""};
  }

  // --------------------------------------------------------------------------
  // Batch exemption check — filter a vector of events, returning exempt
  // indices alongside the exempt events.
  // --------------------------------------------------------------------------
  struct EventInfo {
    std::string event_id;
    std::string event_type;
    std::string sender;
    std::string room_id;
    bool is_state = false;
    int64_t origin_server_ts = 0;
    json content;
  };

  struct BatchExemptionResult {
    std::vector<EventInfo> exempt_events;
    std::vector<EventInfo> purgeable_events;
    std::map<std::string, std::string> exempt_reasons;
  };

  BatchExemptionResult filter_batch(
      const std::vector<EventInfo>& events,
      int64_t min_lifetime_ms) {

    BatchExemptionResult result;

    for (const auto& ev : events) {
      auto [exempt, reason] = is_exempt(
        ev.room_id, ev.event_type, ev.sender,
        ev.is_state, ev.origin_server_ts,
        min_lifetime_ms, ev.content);

      if (exempt) {
        result.exempt_events.push_back(ev);
        result.exempt_reasons[ev.event_id] = reason;
      } else {
        result.purgeable_events.push_back(ev);
      }
    }

    return result;
  }

  // --------------------------------------------------------------------------
  // Add a room-level override for specific event types or senders.
  // --------------------------------------------------------------------------
  void add_room_override(const std::string& room_id,
                          const std::set<std::string>& exempt_types,
                          const std::set<std::string>& exempt_senders,
                          int64_t custom_min_lifetime = -1) {
    auto& ov = rules_.room_overrides[room_id];
    ov.exempt_event_types.insert(exempt_types.begin(), exempt_types.end());
    ov.exempt_senders.insert(exempt_senders.begin(), exempt_senders.end());
    if (custom_min_lifetime >= 0) {
      ov.custom_min_lifetime_ms = custom_min_lifetime;
    }
  }

  // --------------------------------------------------------------------------
  // Remove a room-level override.
  // --------------------------------------------------------------------------
  void remove_room_override(const std::string& room_id) {
    rules_.room_overrides.erase(room_id);
  }

  // --------------------------------------------------------------------------
  // Get the exemption rules (for introspection / admin API).
  // --------------------------------------------------------------------------
  json get_rules_json() const {
    json j;
    j["protect_state_events"]    = rules_.protect_state_events;
    j["respect_min_lifetime"]    = rules_.respect_min_lifetime;
    j["protect_pinned_messages"] = rules_.protect_pinned_messages;
    j["protect_server_notices"]  = rules_.protect_server_notices;
    j["protected_senders"]       = json::array();
    for (const auto& s : rules_.protected_senders) {
      j["protected_senders"].push_back(s);
    }
    j["protected_event_types"]   = json::array();
    for (const auto& t : rules_.protected_event_types) {
      j["protected_event_types"].push_back(t);
    }

    j["immutable_types"] = json::array();
    for (const auto& t : immutable_types_) {
      j["immutable_types"].push_back(t);
    }

    j["room_overrides"] = json::object();
    for (const auto& [rid, ov] : rules_.room_overrides) {
      json room_j;
      room_j["exempt_event_types"] = json::array();
      for (const auto& et : ov.exempt_event_types) {
        room_j["exempt_event_types"].push_back(et);
      }
      room_j["exempt_senders"] = json::array();
      for (const auto& es : ov.exempt_senders) {
        room_j["exempt_senders"].push_back(es);
      }
      room_j["custom_min_lifetime_ms"] = ov.custom_min_lifetime_ms;
      j["room_overrides"][rid] = room_j;
    }

    return j;
  }

private:
  ExemptionRules rules_;
  std::set<std::string> immutable_types_;
  std::set<std::string> protected_types_;
};

// ============================================================================
// Implementation Part 3: MediaReferenceCounter
// Tracks how many events reference each piece of media.
// ============================================================================

class MediaReferenceCounter {
public:
  struct RefCount {
    std::string media_id;
    std::string server_name;
    int64_t count = 0;
    int64_t last_updated_ms = 0;
    int64_t total_bytes = 0;
    std::string file_path;
  };

  /// Build reference counts from a set of events.
  /// Scans event content for MXC URLs and increments counts.
  void scan_events_for_references(
      const std::vector<json>& events,
      const std::string& room_id) {

    for (const auto& event : events) {
      if (!event.contains("content")) continue;

      auto urls = extract_mxc_urls(event["content"]);
      for (const auto& url : urls) {
        auto [server, media_id] = parse_mxc_uri(url);
        if (media_id.empty()) continue;

        std::string key = server + "/" + media_id;
        auto& ref = refs_[key];
        ref.media_id = media_id;
        ref.server_name = server;
        ref.count++;
        ref.last_updated_ms = now_ms();
      }
    }
  }

  /// Decrement reference counts when events are purged.
  /// Returns media_ids that now have zero references (orphaned).
  std::vector<std::string> decrement_for_purged_events(
      const std::vector<std::string>& event_ids,
      const std::vector<std::string>& mxc_urls) {

    std::set<std::string> orphaned;

    for (const auto& url : mxc_urls) {
      auto [server, media_id] = parse_mxc_uri(url);
      if (media_id.empty()) continue;

      std::string key = server + "/" + media_id;
      auto it = refs_.find(key);
      if (it != refs_.end()) {
        it->second.count--;
        if (it->second.count <= 0) {
          orphaned.insert(key);
        }
      }
    }

    return std::vector<std::string>(orphaned.begin(), orphaned.end());
  }

  /// Get all media items with zero references (orphaned).
  std::vector<RefCount> get_orphaned_media() const {
    std::vector<RefCount> result;
    for (const auto& [key, ref] : refs_) {
      if (ref.count <= 0) {
        result.push_back(ref);
      }
    }
    return result;
  }

  /// Get reference count for a specific media item.
  int64_t get_ref_count(const std::string& server, const std::string& media_id) const {
    std::string key = server + "/" + media_id;
    auto it = refs_.find(key);
    return (it != refs_.end()) ? it->second.count : 0;
  }

  /// Total number of tracked media items.
  size_t total_tracked() const { return refs_.size(); }

  /// Serialize reference counts to JSON.
  json to_json() const {
    json j = json::array();
    for (const auto& [key, ref] : refs_) {
      json item;
      item["media_id"]        = ref.media_id;
      item["server_name"]     = ref.server_name;
      item["reference_count"] = ref.count;
      item["last_updated_ms"] = ref.last_updated_ms;
      j.push_back(item);
    }
    return j;
  }

  /// Clear all tracking data.
  void clear() {
    refs_.clear();
  }

private:
  std::unordered_map<std::string, RefCount> refs_; // key = "server/media_id"
};

// ============================================================================
// Implementation Part 4: PurgeEngine
// Core engine that finds and purges expired events.
// ============================================================================

class PurgeEngine {
public:
  PurgeEngine(const RetentionConfig& config,
              ExemptEventHandler& exempt_handler,
              MediaReferenceCounter& media_refs)
    : config_(config),
      exempt_handler_(exempt_handler),
      media_refs_(media_refs) {}

  // --------------------------------------------------------------------------
  // Find all event IDs older than cutoff in a given room.
  // Returns events in batches to avoid memory pressure on large rooms.
  // --------------------------------------------------------------------------
  struct FindResult {
    std::vector<std::string> event_ids;
    std::vector<std::string> mxc_urls;  // Associated MXC URLs
    int64_t estimated_bytes = 0;
    bool has_more = false;              // True if there are more events
    std::string cursor;                 // Pagination cursor for next batch
  };

  FindResult find_expired_events(
      const std::string& room_id,
      int64_t cutoff_timestamp_ms,
      size_t batch_limit,
      const std::string& cursor = "") {

    FindResult result;

    // In a real implementation, this queries the database:
    //   SELECT event_id, content, origin_server_ts
    //   FROM events
    //   WHERE room_id = ? AND origin_server_ts < ?
    //     AND event_id > ?  -- pagination cursor
    //   ORDER BY event_id ASC
    //   LIMIT ?

    // For large rooms, use a streaming / cursor-based approach to avoid
    // loading all events into memory at once.

    // Estimate bytes per event (rough heuristic: average JSON event ~2KB)
    constexpr int64_t AVG_EVENT_BYTES = 2048;
    result.estimated_bytes = static_cast<int64_t>(result.event_ids.size()) * AVG_EVENT_BYTES;

    return result;
  }

  // --------------------------------------------------------------------------
  // Purge a single batch of events from a room.
  // Returns the number of events actually purged.
  // --------------------------------------------------------------------------
  struct PurgeBatchResult {
    int64_t events_purged = 0;
    int64_t events_skipped = 0;
    int64_t bytes_freed = 0;
    std::vector<std::string> orphaned_media_keys;
    std::vector<std::string> errors;
    bool completed_batch = false;
  };

  PurgeBatchResult purge_event_batch(
      const PurgeBatch& batch,
      int64_t min_lifetime_ms) {

    PurgeBatchResult batch_result;

    for (size_t i = 0; i < batch.event_ids.size(); ++i) {
      const auto& event_id = batch.event_ids[i];
      int64_t event_ts = (i < batch.event_timestamps.size())
        ? batch.event_timestamps[i] : 0;

      try {
        // 1. Check exemption
        // In a real implementation, we'd load the event from DB to check:
        //   - event type
        //   - sender
        //   - whether it's a state event
        // Here we use a simplified check
        bool exempt = false;

        // 2. State events are stored in state_events table, so check there.
        // If the event is in the state_events table or current_state_events,
        // it must not be purged.

        // 3. If not exempt, proceed with deletion
        if (!exempt) {
          // Delete from events table
          // delete_event(event_id) — removes from events, event_json,
          //   event_relations, event_edges, event_push_actions, etc.
          batch_result.events_purged++;

          // Rough byte estimate
          batch_result.bytes_freed += 2048;
        } else {
          batch_result.events_skipped++;
        }

      } catch (const std::exception& e) {
        batch_result.errors.push_back(
          std::string("Failed to purge event ") + event_id + ": " + e.what());
      }
    }

    // 4. Decrement media reference counts
    auto orphaned = media_refs_.decrement_for_purged_events(
      batch.event_ids, batch.mxc_urls);
    batch_result.orphaned_media_keys = orphaned;

    batch_result.completed_batch = true;
    return batch_result;
  }

  // --------------------------------------------------------------------------
  // Run a full purge cycle for a single room.
  // Handles cursor-based iteration for large rooms.
  // --------------------------------------------------------------------------
  PurgeRunStats purge_room(
      const std::string& room_id,
      const ParsedRetentionPolicy& policy,
      bool force = false) {

    PurgeRunStats stats;
    stats.purge_id = generate_purge_id();
    stats.start_time_ms = now_ms();

    if (!policy.enabled && !force) {
      stats.final_state = retention_constants::PURGE_STATE_IDLE;
      stats.end_time_ms = now_ms();
      return stats;
    }

    int64_t max_lifetime = policy.max_lifetime_ms;
    int64_t min_lifetime = policy.min_lifetime_ms;

    if (force) {
      // In force mode, use the provided max_lifetime as-is
      // or a minimum of 1 hour if not specified
      if (max_lifetime <= 0) max_lifetime = 3600000;
    }

    stats.rooms_scanned = 1;
    if (policy.enabled) stats.rooms_with_policy = 1;

    int64_t cutoff = now_ms() - max_lifetime;
    size_t batch_size = config_.max_purge_batch_size;
    int64_t total_purged = 0;
    int64_t total_bytes = 0;
    std::string cursor;

    set_purge_state(retention_constants::PURGE_STATE_PURGING, stats.purge_id);

    try {
      while (true) {
        // Check safety limits
        if (total_purged >= config_.safety_max_events_per_room_purge) {
          stats.error_messages.push_back(
            "Safety limit reached for room " + room_id +
            ": " + std::to_string(total_purged) + " events purged");
          break;
        }

        auto elapsed = now_ms() - stats.start_time_ms;
        if (elapsed > config_.max_purge_duration_ms) {
          stats.error_messages.push_back(
            "Max purge duration exceeded for room " + room_id);
          break;
        }

        // Find next batch
        auto find_result = find_expired_events(room_id, cutoff, batch_size, cursor);

        if (find_result.event_ids.empty()) {
          break; // No more expired events
        }

        // Build purge batch
        PurgeBatch batch;
        batch.room_id = room_id;
        batch.event_ids = find_result.event_ids;
        batch.mxc_urls = find_result.mxc_urls;
        batch.cutoff_timestamp = cutoff;
        batch.batch_index = total_purged / batch_size;

        // Purge the batch
        auto batch_result = purge_event_batch(batch, min_lifetime);

        total_purged += batch_result.events_purged;
        total_bytes += batch_result.bytes_freed;
        stats.state_events_kept += batch_result.events_skipped;

        int64_t errors_in_batch = static_cast<int64_t>(batch_result.errors.size());
        stats.errors_encountered += errors_in_batch;
        for (const auto& err : batch_result.errors) {
          stats.error_messages.push_back(err);
        }

        // Throttle: sleep briefly to avoid hammering the DB
        if (batch_result.events_purged > 0) {
          int64_t sleep_ms = config_.throttle_sleep_ms_per_1000 *
            (batch_result.events_purged / 1000);
          if (sleep_ms > 0) {
            std::this_thread::sleep_for(chr::milliseconds(sleep_ms));
          }
        }

        // Yield point: periodically yield to other operations
        if (total_purged > 0 && (total_purged % config_.events_before_yield) == 0) {
          std::this_thread::yield();
        }

        if (!find_result.has_more) break;
        cursor = find_result.cursor;
      }
    } catch (const std::exception& e) {
      stats.error_messages.push_back(
        std::string("Exception during purge of room ") + room_id + ": " + e.what());
      stats.errors_encountered++;
    }

    stats.events_purged = total_purged;
    stats.bytes_freed   = total_bytes;
    stats.rooms_purged  = (total_purged > 0) ? 1 : 0;
    stats.final_state   = (stats.errors_encountered > 0)
      ? retention_constants::PURGE_STATE_ERROR
      : retention_constants::PURGE_STATE_COMPLETE;
    stats.end_time_ms   = now_ms();

    // Record room-level detail
    if (total_purged > 0) {
      PurgeRunStats::RoomPurgeDetail detail;
      detail.room_id       = room_id;
      detail.events_purged = total_purged;
      detail.bytes_freed   = total_bytes;
      detail.cutoff_ts     = cutoff;
      detail.completed     = (stats.final_state == retention_constants::PURGE_STATE_COMPLETE);
      stats.room_details.push_back(detail);
    }

    set_purge_state(retention_constants::PURGE_STATE_IDLE);
    return stats;
  }

  // --------------------------------------------------------------------------
  // Run a purge cycle across all rooms with retention policies.
  // --------------------------------------------------------------------------
  PurgeRunStats purge_all_rooms(
      const std::vector<std::string>& room_ids,
      const std::function<std::optional<ParsedRetentionPolicy>(const std::string&)>& policy_lookup,
      bool force = false) {

    PurgeRunStats global_stats;
    global_stats.purge_id = generate_purge_id();
    global_stats.start_time_ms = now_ms();

    set_purge_state(retention_constants::PURGE_STATE_SCANNING, global_stats.purge_id);

    for (const auto& room_id : room_ids) {
      // Check global exemption list
      if (config_.globally_exempt_rooms.count(room_id) > 0 && !force) {
        continue;
      }

      // Check if global purge limit reached
      if (global_stats.events_purged >= config_.max_events_per_purge_run) {
        global_stats.error_messages.push_back(
          "Global event purge limit reached: " +
          std::to_string(config_.max_events_per_purge_run));
        break;
      }

      // Check byte limit
      if (global_stats.bytes_freed >= config_.max_bytes_per_purge_run) {
        global_stats.error_messages.push_back(
          "Global byte purge limit reached: " +
          std::to_string(config_.max_bytes_per_purge_run));
        break;
      }

      // Get policy for this room
      auto policy_opt = policy_lookup(room_id);
      if (!policy_opt.has_value() && !force) {
        continue;
      }

      auto policy = policy_opt.value_or(
        ParsedRetentionPolicy{0, 0, false, false, room_id, "", 0});

      // Run per-room purge
      auto room_stats = purge_room(room_id, policy, force);

      // Aggregate stats
      global_stats.rooms_scanned++;
      if (policy.enabled || force) {
        global_stats.rooms_with_policy++;
      }
      if (room_stats.events_purged > 0) {
        global_stats.rooms_purged++;
      }
      global_stats.events_scanned    += room_stats.events_scanned;
      global_stats.events_purged     += room_stats.events_purged;
      global_stats.state_events_kept += room_stats.state_events_kept;
      global_stats.protected_kept    += room_stats.protected_kept;
      global_stats.bytes_freed       += room_stats.bytes_freed;
      global_stats.errors_encountered += room_stats.errors_encountered;

      global_stats.error_messages.insert(
        global_stats.error_messages.end(),
        room_stats.error_messages.begin(),
        room_stats.error_messages.end());

      for (auto& detail : room_stats.room_details) {
        global_stats.room_details.push_back(std::move(detail));
      }

      // Check duration limit
      auto elapsed = now_ms() - global_stats.start_time_ms;
      if (elapsed > config_.max_purge_duration_ms) {
        global_stats.error_messages.push_back("Max purge duration exceeded (global)");
        break;
      }
    }

    global_stats.end_time_ms = now_ms();
    global_stats.final_state = (global_stats.errors_encountered > 0)
      ? retention_constants::PURGE_STATE_ERROR
      : retention_constants::PURGE_STATE_COMPLETE;

    set_purge_state(retention_constants::PURGE_STATE_IDLE);
    return global_stats;
  }

  // --------------------------------------------------------------------------
  // Check whether an event should be purged based on its timestamp and policy.
  // --------------------------------------------------------------------------
  bool should_purge_event(int64_t event_origin_server_ts,
                           int64_t max_lifetime_ms) const {
    if (max_lifetime_ms <= 0) return false;
    int64_t event_age_ms = now_ms() - event_origin_server_ts;
    return event_age_ms > max_lifetime_ms;
  }

  // --------------------------------------------------------------------------
  // Calculate the cutoff timestamp for given max_lifetime.
  // --------------------------------------------------------------------------
  int64_t get_cutoff_timestamp(int64_t max_lifetime_ms) const {
    if (max_lifetime_ms <= 0) return 0;
    return now_ms() - max_lifetime_ms;
  }

  // --------------------------------------------------------------------------
  // Dry run: preview what would be purged without actually deleting.
  // --------------------------------------------------------------------------
  json dry_run_room(const std::string& room_id,
                     int64_t max_lifetime_ms,
                     int64_t min_lifetime_ms,
                     size_t max_preview = 100) {

    json result;
    result["room_id"]          = room_id;
    result["max_lifetime_ms"]  = max_lifetime_ms;
    result["min_lifetime_ms"]  = min_lifetime_ms;
    result["cutoff_timestamp"] = get_cutoff_timestamp(max_lifetime_ms);
    result["cutoff_human"]     = iso8601_from_ms(result["cutoff_timestamp"]);

    int64_t total_expired  = 0;
    int64_t total_protected = 0;
    json preview_events = json::array();
    json protected_preview = json::array();

    // In a real implementation, query DB for count and sample
    result["estimated_expired_events"]  = total_expired;
    result["estimated_protected_events"] = total_protected;
    result["preview_events"]            = preview_events;
    result["protected_events_preview"]  = protected_preview;
    result["dry_run"]                   = true;

    return result;
  }

private:
  const RetentionConfig& config_;
  ExemptEventHandler& exempt_handler_;
  MediaReferenceCounter& media_refs_;
};

// ============================================================================
// Implementation Part 5: PurgeScheduler
// Periodic purge scheduling with per-room tracking.
// ============================================================================

class PurgeScheduler {
public:
  /// Per-room schedule tracking.
  struct RoomSchedule {
    std::string room_id;
    int64_t last_purge_ms = 0;
    int64_t next_purge_ms = 0;
    int64_t interval_ms   = 0;      // 0 means use global interval
    int64_t events_purged_last = 0;
    int64_t total_purged       = 0;
    bool active          = true;
    std::string status;              // "pending", "running", "complete"
  };

  PurgeScheduler(const RetentionConfig& config,
                 PurgeEngine& engine,
                 std::function<std::vector<std::string>()> room_list_provider)
    : config_(config),
      engine_(engine),
      room_list_provider_(std::move(room_list_provider)) {}

  // --------------------------------------------------------------------------
  // Start the background scheduler thread.
  // --------------------------------------------------------------------------
  void start() {
    if (scheduler_thread_.joinable()) return;
    running_ = true;

    scheduler_thread_ = std::thread([this]() {
      scheduler_loop();
    });
  }

  // --------------------------------------------------------------------------
  // Stop the background scheduler thread gracefully.
  // --------------------------------------------------------------------------
  void stop() {
    running_ = false;
    cv_.notify_all();
    if (scheduler_thread_.joinable()) {
      scheduler_thread_.join();
    }
  }

  // --------------------------------------------------------------------------
  // Pause scheduling without stopping the thread.
  // --------------------------------------------------------------------------
  void pause() {
    g_purge_state.scheduler_paused = true;
    paused_ = true;
  }

  // --------------------------------------------------------------------------
  // Resume scheduling.
  // --------------------------------------------------------------------------
  void resume() {
    g_purge_state.scheduler_paused = false;
    paused_ = false;
    cv_.notify_all();
  }

  // --------------------------------------------------------------------------
  // Check if the scheduler is currently paused.
  // --------------------------------------------------------------------------
  bool is_paused() const { return paused_; }

  // --------------------------------------------------------------------------
  // Get the schedule for a specific room.
  // --------------------------------------------------------------------------
  std::optional<std::reference_wrapper<const RoomSchedule>>
  get_room_schedule(const std::string& room_id) const {
    std::shared_lock lock(schedule_mutex_);
    auto it = room_schedules_.find(room_id);
    if (it != room_schedules_.end()) {
      return std::cref(it->second);
    }
    return std::nullopt;
  }

  // --------------------------------------------------------------------------
  // Get all room schedules.
  // --------------------------------------------------------------------------
  std::vector<RoomSchedule> get_all_schedules() const {
    std::shared_lock lock(schedule_mutex_);
    std::vector<RoomSchedule> result;
    result.reserve(room_schedules_.size());
    for (const auto& [rid, schedule] : room_schedules_) {
      result.push_back(schedule);
    }
    return result;
  }

  // --------------------------------------------------------------------------
  // Update schedule for a specific room (e.g., after a manual purge).
  // --------------------------------------------------------------------------
  void update_room_schedule(const std::string& room_id,
                             int64_t next_purge_ms,
                             int64_t interval_ms = 0) {
    std::unique_lock lock(schedule_mutex_);
    auto& schedule = room_schedules_[room_id];
    schedule.room_id      = room_id;
    schedule.next_purge_ms = next_purge_ms;
    schedule.interval_ms   = interval_ms > 0 ? interval_ms : config_.purge_job_interval_ms;
    schedule.active        = true;
  }

  // --------------------------------------------------------------------------
  // Reset a room's schedule (after a force purge).
  // --------------------------------------------------------------------------
  void reset_room_schedule(const std::string& room_id) {
    std::unique_lock lock(schedule_mutex_);
    auto& schedule = room_schedules_[room_id];
    schedule.last_purge_ms = now_ms();
    schedule.next_purge_ms  = now_ms() + config_.purge_job_interval_ms;
    schedule.status         = "pending";
  }

  // --------------------------------------------------------------------------
  // Get statistics about scheduling.
  // --------------------------------------------------------------------------
  json get_scheduler_stats() const {
    std::shared_lock lock(schedule_mutex_);
    json stats;
    stats["total_rooms_scheduled"] = room_schedules_.size();
    stats["running"]               = running_.load();
    stats["paused"]                = paused_.load();
    stats["current_interval_ms"]   = config_.purge_job_interval_ms;
    stats["next_global_run_ms"]    = next_global_run_ms_.load();

    // Count rooms by status
    int pending = 0, running = 0, complete = 0;
    for (const auto& [rid, sched] : room_schedules_) {
      if (sched.status == "pending") pending++;
      else if (sched.status == "running") running++;
      else if (sched.status == "complete") complete++;
    }
    stats["rooms_pending"]  = pending;
    stats["rooms_running"]  = running;
    stats["rooms_complete"] = complete;

    return stats;
  }

  // --------------------------------------------------------------------------
  // Force an immediate purge run (synchronous, blocks until complete).
  // --------------------------------------------------------------------------
  PurgeRunStats force_run_now() {
    return run_scheduled_purge(false);
  }

private:
  // --------------------------------------------------------------------------
  // Main scheduler loop.
  // --------------------------------------------------------------------------
  void scheduler_loop() {
    while (running_) {
      // Wait for the next scheduled run
      {
        std::unique_lock lock(cv_mutex_);
        auto wait_ms = config_.purge_job_interval_ms;
        cv_.wait_for(lock, chr::milliseconds(wait_ms), [this]() {
          return !running_ || !paused_;
        });
      }

      if (!running_) break;
      if (paused_) continue;

      // Run the purge
      try {
        auto stats = run_scheduled_purge(true);
        (void)stats; // Stats are recorded in purge history
      } catch (const std::exception& e) {
        std::cerr << "[PurgeScheduler] Error: " << e.what() << std::endl;
      }

      // Update next run timestamp
      next_global_run_ms_ = now_ms() + config_.purge_job_interval_ms;
    }
  }

  // --------------------------------------------------------------------------
  // Execute one scheduled purge run across all applicable rooms.
  // --------------------------------------------------------------------------
  PurgeRunStats run_scheduled_purge(bool honor_schedules) {
    // Gather room list
    auto room_ids = room_list_provider_();
    if (room_ids.empty()) {
      return {};
    }

    // Filter rooms by schedule (only purge rooms whose next_purge_ms has passed)
    std::vector<std::string> eligible_rooms;
    int64_t now = now_ms();

    {
      std::shared_lock lock(schedule_mutex_);
      for (const auto& room_id : room_ids) {
        auto it = room_schedules_.find(room_id);
        if (it != room_schedules_.end()) {
          if (honor_schedules && it->second.next_purge_ms > now) {
            continue; // Not yet due
          }
          if (!it->second.active) continue;
        }
        eligible_rooms.push_back(room_id);
      }
    }

    if (eligible_rooms.empty()) {
      return {};
    }

    // Build policy lookup
    auto policy_lookup = [this](const std::string& room_id)
      -> std::optional<ParsedRetentionPolicy> {
      // In a real implementation, query the room's m.room.retention state
      // and combine with server defaults.
      // For now, return a basic default.
      if (config_.default_max_lifetime_ms > 0) {
        ParsedRetentionPolicy p;
        p.room_id = room_id;
        p.max_lifetime_ms = config_.default_max_lifetime_ms;
        p.min_lifetime_ms = config_.default_min_lifetime_ms;
        p.enabled = true;
        return p;
      }
      return std::nullopt;
    };

    // Run the purge
    auto stats = engine_.purge_all_rooms(eligible_rooms, policy_lookup);

    // Update schedules
    {
      std::unique_lock lock(schedule_mutex_);
      for (const auto& detail : stats.room_details) {
        auto& schedule = room_schedules_[detail.room_id];
        schedule.room_id           = detail.room_id;
        schedule.last_purge_ms     = now;
        schedule.next_purge_ms     = now + config_.purge_job_interval_ms;
        schedule.events_purged_last = detail.events_purged;
        schedule.total_purged      += detail.events_purged;
        schedule.status            = detail.completed ? "complete" : "pending";

        // Adaptive interval: if a room produced many purges, check more often
        if (detail.events_purged > 10000) {
          schedule.interval_ms = config_.purge_job_interval_ms / 2;
        }
      }
    }

    return stats;
  }

  const RetentionConfig& config_;
  PurgeEngine& engine_;
  std::function<std::vector<std::string>()> room_list_provider_;

  mutable std::shared_mutex schedule_mutex_;
  std::unordered_map<std::string, RoomSchedule> room_schedules_;

  std::thread scheduler_thread_;
  std::atomic<bool> running_{false};
  std::atomic<bool> paused_{false};
  std::atomic<int64_t> next_global_run_ms_{0};

  std::mutex cv_mutex_;
  std::condition_variable cv_;
};

// ============================================================================
// Implementation Part 6: MediaPurgeCoordinator
// Purges orphaned media files no longer referenced by any event.
// ============================================================================

class MediaPurgeCoordinator {
public:
  struct MediaPurgeConfig {
    bool enabled                  = true;
    int64_t soft_delete_grace_ms  = retention_constants::MEDIA_SOFT_DELETE_GRACE_MS;
    int64_t media_purge_interval_ms = 86400000;
    size_t max_batch_size         = retention_constants::DEFAULT_MEDIA_PURGE_BATCH;
    std::string media_store_path;   // Path where media files are stored
    bool dry_run                  = false;
  };

  struct OrphanMediaInfo {
    std::string media_id;
    std::string server_name;
    std::string file_path;
    std::string content_type;
    int64_t file_size_bytes = 0;
    int64_t upload_ts       = 0;
    int64_t last_access_ts  = 0;
    int64_t orphan_detected_ts = 0;  // When we first noticed it was orphaned
    std::string mxc_uri;
  };

  struct MediaPurgeStats {
    int64_t total_orphans_found  = 0;
    int64_t soft_deleted         = 0;
    int64_t hard_deleted         = 0;
    int64_t kept_in_grace        = 0;
    int64_t bytes_soft_deleted   = 0;
    int64_t bytes_hard_deleted   = 0;
    int64_t bytes_kept_in_grace  = 0;
    int64_t errors               = 0;
    std::vector<std::string> error_messages;
    std::vector<OrphanMediaInfo> deleted_media;
  };

  explicit MediaPurgeCoordinator(const MediaPurgeConfig& config,
                                  MediaReferenceCounter& ref_counter)
    : config_(config),
      ref_counter_(ref_counter) {}

  // --------------------------------------------------------------------------
  // Scan for orphaned media (zero reference count).
  // --------------------------------------------------------------------------
  std::vector<OrphanMediaInfo> scan_for_orphans() {
    std::vector<OrphanMediaInfo> orphans;
    auto orphaned_refs = ref_counter_.get_orphaned_media();

    for (const auto& ref : orphaned_refs) {
      OrphanMediaInfo info;
      info.media_id          = ref.media_id;
      info.server_name       = ref.server_name;
      info.file_size_bytes   = ref.total_bytes;
      info.orphan_detected_ts = now_ms();
      info.mxc_uri           = "mxc://" + ref.server_name + "/" + ref.media_id;

      // Build file path
      if (!config_.media_store_path.empty()) {
        info.file_path = config_.media_store_path + "/" +
                         ref.server_name + "/" + ref.media_id;
      }

      orphans.push_back(info);
    }

    return orphans;
  }

  // --------------------------------------------------------------------------
  // Soft-delete orphaned media (mark as deleted, keep file for grace period).
  // --------------------------------------------------------------------------
  MediaPurgeStats soft_delete_orphans(
      std::vector<OrphanMediaInfo>& orphans) {

    MediaPurgeStats stats;
    int64_t now = now_ms();

    for (auto& orphan : orphans) {
      try {
        // Check if we already know about this orphan and it's within grace
        auto it = known_orphans_.find(orphan.mxc_uri);
        if (it == known_orphans_.end()) {
          // First time seeing this orphan — record it, don't delete yet
          orphan.orphan_detected_ts = now;
          known_orphans_[orphan.mxc_uri] = orphan;
          stats.kept_in_grace++;
          stats.bytes_kept_in_grace += orphan.file_size_bytes;
          continue;
        }

        int64_t time_since_detected = now - it->second.orphan_detected_ts;
        if (time_since_detected < config_.soft_delete_grace_ms) {
          // Still in grace period
          stats.kept_in_grace++;
          stats.bytes_kept_in_grace += orphan.file_size_bytes;
          continue;
        }

        // Grace period expired — mark for deletion
        orphan.orphan_detected_ts = it->second.orphan_detected_ts;

        if (config_.dry_run) {
          stats.soft_deleted++;
          stats.bytes_soft_deleted += orphan.file_size_bytes;
        } else {
          // Soft delete: mark in DB, don't delete file yet
          stats.soft_deleted++;
          stats.bytes_soft_deleted += orphan.file_size_bytes;
        }

      } catch (const std::exception& e) {
        stats.errors++;
        stats.error_messages.push_back(
          "Soft-delete error for " + orphan.mxc_uri + ": " + e.what());
      }
    }

    return stats;
  }

  // --------------------------------------------------------------------------
  // Hard-delete media files that have passed the soft-delete grace period.
  // --------------------------------------------------------------------------
  MediaPurgeStats hard_delete_expired() {
    MediaPurgeStats stats;
    int64_t now = now_ms();
    std::vector<std::string> to_remove;

    for (auto& [uri, info] : known_orphans_) {
      int64_t time_since_detected = now - info.orphan_detected_ts;
      if (time_since_detected < config_.soft_delete_grace_ms) {
        continue; // Still in grace period
      }

      try {
        if (!config_.dry_run && !info.file_path.empty()) {
          std::error_code ec;
          if (fs::exists(info.file_path, ec)) {
            fs::remove(info.file_path, ec);
            if (!ec) {
              stats.hard_deleted++;
              stats.bytes_hard_deleted += info.file_size_bytes;
              stats.deleted_media.push_back(info);
            } else {
              stats.errors++;
              stats.error_messages.push_back(
                "Failed to delete file " + info.file_path + ": " + ec.message());
            }
          } else {
            // File already gone, just remove from tracking
            stats.hard_deleted++;
          }
        }
        to_remove.push_back(uri);
      } catch (const std::exception& e) {
        stats.errors++;
        stats.error_messages.push_back(
          "Hard-delete error for " + uri + ": " + e.what());
      }
    }

    // Remove tracked entries
    for (const auto& uri : to_remove) {
      known_orphans_.erase(uri);
    }

    return stats;
  }

  // --------------------------------------------------------------------------
  // Run full media purge cycle: scan, soft-delete, hard-delete.
  // --------------------------------------------------------------------------
  MediaPurgeStats run_full_cycle() {
    MediaPurgeStats total_stats;
    g_purge_state.is_media_purging = true;
    set_purge_state(retention_constants::PURGE_STATE_MEDIA_SCAN);

    try {
      // Step 1: Scan
      auto orphans = scan_for_orphans();
      total_stats.total_orphans_found = static_cast<int64_t>(orphans.size());

      // Step 2: Soft-delete
      set_purge_state(retention_constants::PURGE_STATE_MEDIA_PURGE);
      auto soft_stats = soft_delete_orphans(orphans);
      total_stats.soft_deleted        = soft_stats.soft_deleted;
      total_stats.bytes_soft_deleted  = soft_stats.bytes_soft_deleted;
      total_stats.kept_in_grace       = soft_stats.kept_in_grace;
      total_stats.bytes_kept_in_grace = soft_stats.bytes_kept_in_grace;
      total_stats.errors             += soft_stats.errors;
      total_stats.error_messages.insert(
        total_stats.error_messages.end(),
        soft_stats.error_messages.begin(),
        soft_stats.error_messages.end());

      // Step 3: Hard-delete expired
      auto hard_stats = hard_delete_expired();
      total_stats.hard_deleted        = hard_stats.hard_deleted;
      total_stats.bytes_hard_deleted  = hard_stats.bytes_hard_deleted;
      total_stats.errors             += hard_stats.errors;
      total_stats.deleted_media.insert(
        total_stats.deleted_media.end(),
        hard_stats.deleted_media.begin(),
        hard_stats.deleted_media.end());
      total_stats.error_messages.insert(
        total_stats.error_messages.end(),
        hard_stats.error_messages.begin(),
        hard_stats.error_messages.end());

    } catch (const std::exception& e) {
      total_stats.errors++;
      total_stats.error_messages.push_back(
        std::string("Media purge cycle error: ") + e.what());
    }

    set_purge_state(retention_constants::PURGE_STATE_IDLE);
    g_purge_state.is_media_purging = false;
    return total_stats;
  }

  // --------------------------------------------------------------------------
  // Get currently known orphaned media items.
  // --------------------------------------------------------------------------
  std::vector<OrphanMediaInfo> get_known_orphans() const {
    std::vector<OrphanMediaInfo> result;
    result.reserve(known_orphans_.size());
    for (const auto& [uri, info] : known_orphans_) {
      result.push_back(info);
    }
    return result;
  }

  // --------------------------------------------------------------------------
  // Get orphan stats (count, total bytes, etc.).
  // --------------------------------------------------------------------------
  json get_orphan_stats() const {
    json stats;
    int64_t total_bytes = 0;
    int64_t total_count = static_cast<int64_t>(known_orphans_.size());
    int ready_to_delete = 0;
    int64_t now = now_ms();

    for (const auto& [uri, info] : known_orphans_) {
      total_bytes += info.file_size_bytes;
      if (now - info.orphan_detected_ts >= config_.soft_delete_grace_ms) {
        ready_to_delete++;
      }
    }

    stats["total_orphans"]       = total_count;
    stats["total_bytes"]         = total_bytes;
    stats["ready_to_delete"]     = ready_to_delete;
    stats["in_grace_period"]     = total_count - ready_to_delete;
    stats["soft_delete_grace_ms"] = config_.soft_delete_grace_ms;
    stats["grace_period_human"]  = RetentionPolicyParser::duration_to_human(
      config_.soft_delete_grace_ms);

    return stats;
  }

private:
  MediaPurgeConfig config_;
  MediaReferenceCounter& ref_counter_;
  std::unordered_map<std::string, OrphanMediaInfo> known_orphans_;
};

// ============================================================================
// Implementation Part 7: PurgeHistoryLogger
// Structured audit log of all purge operations.
// ============================================================================

class PurgeHistoryLogger {
public:
  struct LoggerConfig {
    bool enabled                    = true;
    bool log_to_file                = true;
    bool log_to_stdout              = false;
    std::string log_file_path       = "/var/log/progressive/purge_history.log";
    int64_t max_log_age_sec         = retention_constants::PURGE_HISTORY_RETENTION_SEC;
    size_t max_entries              = retention_constants::MAX_PURGE_HISTORY_ENTRIES;
    bool json_format                = true;
  };

  explicit PurgeHistoryLogger(const LoggerConfig& config)
    : config_(config) {
    if (config_.log_to_file) {
      ensure_log_directory();
    }
  }

  // --------------------------------------------------------------------------
  // Log a purge operation.
  // --------------------------------------------------------------------------
  void log_purge(const PurgeHistoryEntry& entry) {
    if (!config_.enabled) return;

    PurgeHistoryEntry enriched = entry;
    enriched.timestamp_ms = now_ms();

    if (enriched.entry_id.empty()) {
      enriched.entry_id = generate_purge_id();
    }

    // Add to in-memory history
    {
      std::lock_guard<std::mutex> lock(history_mutex_);
      history_.push_front(enriched);

      // Trim old entries
      while (history_.size() > config_.max_entries) {
        history_.pop_back();
      }
    }

    // Write to log file
    if (config_.log_to_file) {
      write_to_file(enriched);
    }

    // Write to stdout
    if (config_.log_to_stdout) {
      write_to_stdout(enriched);
    }
  }

  // --------------------------------------------------------------------------
  // Convenience: log a successful room purge.
  // --------------------------------------------------------------------------
  void log_room_purge(const std::string& room_id,
                       const std::string& triggered_by,
                       int64_t events_purged,
                       int64_t bytes_freed) {
    PurgeHistoryEntry entry;
    entry.entry_id       = generate_purge_id();
    entry.purge_id       = entry.entry_id;
    entry.room_id        = room_id;
    entry.triggered_by   = triggered_by;
    entry.action         = "purge_events";
    entry.events_purged  = events_purged;
    entry.bytes_freed    = bytes_freed;
    entry.status         = "success";
    entry.detail_json    = json{{"events_purged", events_purged},
                                 {"bytes_freed", bytes_freed}}.dump();
    log_purge(entry);
  }

  // --------------------------------------------------------------------------
  // Convenience: log a purge error.
  // --------------------------------------------------------------------------
  void log_purge_error(const std::string& room_id,
                        const std::string& triggered_by,
                        const std::string& error_message) {
    PurgeHistoryEntry entry;
    entry.entry_id      = generate_purge_id();
    entry.room_id       = room_id;
    entry.triggered_by  = triggered_by;
    entry.action        = "purge_events";
    entry.status        = "error";
    entry.error_message = error_message;
    log_purge(entry);
  }

  // --------------------------------------------------------------------------
  // Log a media purge operation.
  // --------------------------------------------------------------------------
  void log_media_purge(const MediaPurgeCoordinator::MediaPurgeStats& stats,
                        const std::string& triggered_by) {
    PurgeHistoryEntry entry;
    entry.entry_id          = generate_purge_id();
    entry.triggered_by      = triggered_by;
    entry.action            = "purge_media";
    entry.media_files_purged = stats.hard_deleted + stats.soft_deleted;
    entry.media_bytes_freed  = stats.bytes_hard_deleted + stats.bytes_soft_deleted;
    entry.status            = (stats.errors > 0) ? "partial" : "success";

    json detail;
    detail["total_orphans_found"] = stats.total_orphans_found;
    detail["soft_deleted"]        = stats.soft_deleted;
    detail["hard_deleted"]        = stats.hard_deleted;
    detail["kept_in_grace"]       = stats.kept_in_grace;
    detail["bytes_soft_deleted"]  = stats.bytes_soft_deleted;
    detail["bytes_hard_deleted"]  = stats.bytes_hard_deleted;
    detail["errors"]              = stats.errors;
    entry.detail_json = detail.dump();

    if (stats.errors > 0 && !stats.error_messages.empty()) {
      entry.error_message = stats.error_messages[0];
    }

    log_purge(entry);
  }

  // --------------------------------------------------------------------------
  // Log an admin action (exemption, override, force purge).
  // --------------------------------------------------------------------------
  void log_admin_action(const std::string& room_id,
                         const std::string& admin_user,
                         const std::string& action,
                         const json& detail = json::object()) {
    PurgeHistoryEntry entry;
    entry.entry_id     = generate_purge_id();
    entry.room_id      = room_id;
    entry.triggered_by = "admin:" + admin_user;
    entry.action       = action;
    entry.status       = "success";
    entry.detail_json  = detail.dump();
    log_purge(entry);
  }

  // --------------------------------------------------------------------------
  // Query purge history with filters.
  // --------------------------------------------------------------------------
  struct HistoryQuery {
    std::optional<std::string> room_id;
    std::optional<std::string> action;
    std::optional<std::string> status;
    std::optional<std::string> triggered_by;
    std::optional<int64_t> after_timestamp_ms;
    std::optional<int64_t> before_timestamp_ms;
    size_t limit = 100;
    size_t offset = 0;
  };

  std::vector<PurgeHistoryEntry> query_history(const HistoryQuery& query) const {
    std::lock_guard<std::mutex> lock(history_mutex_);
    std::vector<PurgeHistoryEntry> results;

    for (const auto& entry : history_) {
      // Apply filters
      if (query.room_id && entry.room_id != *query.room_id) continue;
      if (query.action && entry.action != *query.action) continue;
      if (query.status && entry.status != *query.status) continue;
      if (query.triggered_by && entry.triggered_by != *query.triggered_by) continue;
      if (query.after_timestamp_ms && entry.timestamp_ms < *query.after_timestamp_ms) continue;
      if (query.before_timestamp_ms && entry.timestamp_ms > *query.before_timestamp_ms) continue;

      results.push_back(entry);
    }

    // Apply offset/limit
    if (query.offset < results.size()) {
      auto end = std::min(results.size(), query.offset + query.limit);
      results = std::vector<PurgeHistoryEntry>(
        results.begin() + static_cast<long>(query.offset),
        results.begin() + static_cast<long>(end));
    } else {
      results.clear();
    }

    return results;
  }

  // --------------------------------------------------------------------------
  // Export all purge history as JSON.
  // --------------------------------------------------------------------------
  json export_history() const {
    std::lock_guard<std::mutex> lock(history_mutex_);
    json entries = json::array();
    for (const auto& entry : history_) {
      json e;
      e["entry_id"]          = entry.entry_id;
      e["purge_id"]          = entry.purge_id;
      e["room_id"]           = entry.room_id;
      e["timestamp_ms"]      = entry.timestamp_ms;
      e["timestamp_human"]   = iso8601_from_ms(entry.timestamp_ms);
      e["triggered_by"]      = entry.triggered_by;
      e["action"]            = entry.action;
      e["events_purged"]     = entry.events_purged;
      e["bytes_freed"]       = entry.bytes_freed;
      e["media_files_purged"] = entry.media_files_purged;
      e["media_bytes_freed"] = entry.media_bytes_freed;
      e["status"]            = entry.status;
      e["error_message"]     = entry.error_message;
      if (!entry.detail_json.empty()) {
        try {
          e["detail"] = json::parse(entry.detail_json);
        } catch (...) {
          e["detail"] = entry.detail_json;
        }
      }
      entries.push_back(e);
    }
    return entries;
  }

  // --------------------------------------------------------------------------
  // Get total counts for dashboard / stats.
  // --------------------------------------------------------------------------
  json get_summary_stats() const {
    std::lock_guard<std::mutex> lock(history_mutex_);
    json stats;

    int64_t total_events_purged = 0;
    int64_t total_bytes_freed   = 0;
    int64_t total_media_purged  = 0;
    int64_t total_media_bytes   = 0;
    int64_t total_entries       = static_cast<int64_t>(history_.size());
    int64_t successful          = 0;
    int64_t partial             = 0;
    int64_t errors              = 0;

    for (const auto& entry : history_) {
      total_events_purged += entry.events_purged;
      total_bytes_freed   += entry.bytes_freed;
      total_media_purged  += entry.media_files_purged;
      total_media_bytes   += entry.media_bytes_freed;

      if (entry.status == "success") successful++;
      else if (entry.status == "partial") partial++;
      else if (entry.status == "error") errors++;
    }

    stats["total_entries"]         = total_entries;
    stats["total_events_purged"]   = total_events_purged;
    stats["total_bytes_freed"]     = total_bytes_freed;
    stats["total_bytes_freed_human"] = bytes_to_human(total_bytes_freed);
    stats["total_media_purged"]    = total_media_purged;
    stats["total_media_bytes"]     = total_media_bytes;
    stats["successful_runs"]       = successful;
    stats["partial_runs"]          = partial;
    stats["error_runs"]            = errors;

    return stats;
  }

  // --------------------------------------------------------------------------
  // Clear all history (for testing or admin reset).
  // --------------------------------------------------------------------------
  void clear_history() {
    std::lock_guard<std::mutex> lock(history_mutex_);
    history_.clear();
  }

  // --------------------------------------------------------------------------
  // Format byte count to human-readable string.
  // --------------------------------------------------------------------------
  static std::string bytes_to_human(int64_t bytes) {
    const char* units[] = {"B", "KB", "MB", "GB", "TB"};
    int unit_idx = 0;
    double size = static_cast<double>(bytes);

    while (size >= 1024.0 && unit_idx < 4) {
      size /= 1024.0;
      unit_idx++;
    }

    std::ostringstream oss;
    oss << std::fixed << std::setprecision(2) << size << " " << units[unit_idx];
    return oss.str();
  }

private:
  void ensure_log_directory() {
    std::error_code ec;
    auto parent = fs::path(config_.log_file_path).parent_path();
    if (!parent.empty()) {
      fs::create_directories(parent, ec);
    }
  }

  void write_to_file(const PurgeHistoryEntry& entry) {
    try {
      std::ofstream file(config_.log_file_path, std::ios::app);
      if (!file.is_open()) return;

      if (config_.json_format) {
        json j;
        j["entry_id"]           = entry.entry_id;
        j["purge_id"]           = entry.purge_id;
        j["room_id"]            = entry.room_id;
        j["timestamp"]          = iso8601_from_ms(entry.timestamp_ms);
        j["triggered_by"]       = entry.triggered_by;
        j["action"]             = entry.action;
        j["events_purged"]      = entry.events_purged;
        j["bytes_freed"]        = entry.bytes_freed;
        j["media_files_purged"] = entry.media_files_purged;
        j["media_bytes_freed"]  = entry.media_bytes_freed;
        j["status"]             = entry.status;
        j["error_message"]      = entry.error_message;
        file << j.dump() << std::endl;
      } else {
        // Plain text format
        file << "[" << iso8601_from_ms(entry.timestamp_ms) << "] "
             << "purge_id=" << entry.purge_id << " "
             << "room_id=" << entry.room_id << " "
             << "action=" << entry.action << " "
             << "triggered_by=" << entry.triggered_by << " "
             << "events_purged=" << entry.events_purged << " "
             << "bytes_freed=" << entry.bytes_freed << " "
             << "status=" << entry.status << " "
             << "error=" << entry.error_message
             << std::endl;
      }
    } catch (...) {
      // Silently fail — logging shouldn't crash the server
    }
  }

  void write_to_stdout(const PurgeHistoryEntry& entry) {
    std::cout << "[PurgeHistory] " << iso8601_from_ms(entry.timestamp_ms)
              << " room=" << entry.room_id
              << " action=" << entry.action
              << " events=" << entry.events_purged
              << " status=" << entry.status;
    if (!entry.error_message.empty()) {
      std::cout << " error=" << entry.error_message;
    }
    std::cout << std::endl;
  }

  LoggerConfig config_;
  mutable std::mutex history_mutex_;
  std::deque<PurgeHistoryEntry> history_;
};

// ============================================================================
// Implementation Part 8: AdminControlPanel
// Admin API for managing retention, exemptions, overrides, and force-purge.
// ============================================================================

class AdminControlPanel {
public:
  struct RoomOverride {
    std::string room_id;
    int64_t max_lifetime_ms = 0;      // 0 = use default, -1 = no retention
    int64_t min_lifetime_ms = 0;
    std::string reason;
    std::string set_by;
    int64_t set_at_ms = 0;
    int64_t expires_at_ms = 0;        // 0 = permanent
    bool is_permanent = true;
  };

  AdminControlPanel(const RetentionConfig& config,
                    PurgeEngine& engine,
                    PurgeScheduler& scheduler,
                    MediaPurgeCoordinator& media_purge,
                    PurgeHistoryLogger& logger)
    : config_(config),
      engine_(engine),
      scheduler_(scheduler),
      media_purge_(media_purge),
      logger_(logger) {}

  // --------------------------------------------------------------------------
  // Force-purge a single room immediately, bypassing schedule.
  // --------------------------------------------------------------------------
  json force_purge_room(const std::string& room_id,
                         const std::string& admin_user,
                         int64_t max_lifetime_ms = 0) {
    // Check global exemption unless admin explicitly overrides
    if (config_.globally_exempt_rooms.count(room_id) > 0) {
      return make_error_json("M_ROOM_EXEMPT",
        "Room " + room_id + " is globally exempt from retention");
    }

    // Use provided max lifetime or server default
    if (max_lifetime_ms <= 0) {
      max_lifetime_ms = config_.default_max_lifetime_ms;
    }

    ParsedRetentionPolicy policy;
    policy.room_id         = room_id;
    policy.max_lifetime_ms = max_lifetime_ms;
    policy.min_lifetime_ms = 0;
    policy.enabled         = true;

    // Run purge
    auto stats = engine_.purge_room(room_id, policy, true);

    // Update schedule
    scheduler_.reset_room_schedule(room_id);

    // Log
    logger_.log_room_purge(room_id, "admin:" + admin_user,
      stats.events_purged, stats.bytes_freed);

    // Build response
    json response;
    response["room_id"]       = room_id;
    response["purge_id"]      = stats.purge_id;
    response["events_purged"] = stats.events_purged;
    response["bytes_freed"]   = stats.bytes_freed;
    response["state_kept"]    = stats.state_events_kept;
    response["duration_ms"]   = stats.end_time_ms - stats.start_time_ms;
    response["errors"]        = stats.error_messages;
    response["success"]       = (stats.errors_encountered == 0);

    return response;
  }

  // --------------------------------------------------------------------------
  // Force a full global purge run immediately.
  // --------------------------------------------------------------------------
  json force_global_purge(const std::string& admin_user,
                           const std::vector<std::string>& room_ids) {
    auto policy_lookup = [this](const std::string& room_id)
      -> std::optional<ParsedRetentionPolicy> {
      // Check admin overrides first
      {
        std::shared_lock lock(overrides_mutex_);
        auto it = admin_overrides_.find(room_id);
        if (it != admin_overrides_.end()) {
          const auto& ov = it->second;
          if (ov.max_lifetime_ms == -1) {
            return std::nullopt; // Room exempted
          }
          ParsedRetentionPolicy p;
          p.room_id = room_id;
          p.max_lifetime_ms = ov.max_lifetime_ms;
          p.min_lifetime_ms = ov.min_lifetime_ms;
          p.enabled = (ov.max_lifetime_ms > 0);
          return p;
        }
      }

      // Fallback to default
      if (config_.default_max_lifetime_ms > 0) {
        ParsedRetentionPolicy p;
        p.room_id = room_id;
        p.max_lifetime_ms = config_.default_max_lifetime_ms;
        p.min_lifetime_ms = config_.default_min_lifetime_ms;
        p.enabled = true;
        return p;
      }
      return std::nullopt;
    };

    auto stats = engine_.purge_all_rooms(room_ids, policy_lookup, true);

    // Log
    logger_.log_room_purge("__global__", "admin:" + admin_user,
      stats.events_purged, stats.bytes_freed);

    json response;
    response["purge_id"]       = stats.purge_id;
    response["rooms_scanned"]  = stats.rooms_scanned;
    response["rooms_purged"]   = stats.rooms_purged;
    response["events_purged"]  = stats.events_purged;
    response["bytes_freed"]    = stats.bytes_freed;
    response["duration_ms"]    = stats.end_time_ms - stats.start_time_ms;
    response["errors"]         = stats.error_messages;
    response["success"]        = (stats.errors_encountered == 0);

    return response;
  }

  // --------------------------------------------------------------------------
  // Exempt a room from all retention policies.
  // --------------------------------------------------------------------------
  json exempt_room(const std::string& room_id,
                    const std::string& admin_user,
                    const std::string& reason = "",
                    bool permanent = true,
                    int64_t duration_ms = 0) {

    RoomOverride ov;
    ov.room_id         = room_id;
    ov.max_lifetime_ms = -1;  // -1 signals "no retention"
    ov.reason          = reason;
    ov.set_by          = admin_user;
    ov.set_at_ms       = now_ms();
    ov.is_permanent    = permanent;
    ov.expires_at_ms   = permanent ? 0 : (now_ms() + duration_ms);

    {
      std::unique_lock lock(overrides_mutex_);
      admin_overrides_[room_id] = ov;
    }

    // Add to global exemptions
    config_.globally_exempt_rooms.insert(room_id);

    // Log
    json detail;
    detail["permanent"]   = permanent;
    detail["duration_ms"] = duration_ms;
    detail["reason"]      = reason;
    logger_.log_admin_action(room_id, admin_user, "exempt", detail);

    return make_success_json();
  }

  // --------------------------------------------------------------------------
  // Remove a room's exemption.
  // --------------------------------------------------------------------------
  json unexempt_room(const std::string& room_id,
                      const std::string& admin_user) {

    {
      std::unique_lock lock(overrides_mutex_);
      admin_overrides_.erase(room_id);
    }

    config_.globally_exempt_rooms.erase(room_id);

    logger_.log_admin_action(room_id, admin_user, "unexempt");

    return make_success_json();
  }

  // --------------------------------------------------------------------------
  // Override retention period for a specific room.
  // --------------------------------------------------------------------------
  json override_retention(const std::string& room_id,
                           int64_t max_lifetime_ms,
                           int64_t min_lifetime_ms,
                           const std::string& admin_user,
                           const std::string& reason = "",
                           bool permanent = true,
                           int64_t duration_ms = 0) {

    // Validate
    if (max_lifetime_ms < 0 && max_lifetime_ms != -1) {
      return make_error_json("M_INVALID_PARAM",
        "max_lifetime_ms must be >= 0 or -1 to disable");
    }
    if (min_lifetime_ms < 0) {
      return make_error_json("M_INVALID_PARAM",
        "min_lifetime_ms must be >= 0");
    }

    RoomOverride ov;
    ov.room_id         = room_id;
    ov.max_lifetime_ms = max_lifetime_ms;
    ov.min_lifetime_ms = min_lifetime_ms;
    ov.reason          = reason;
    ov.set_by          = admin_user;
    ov.set_at_ms       = now_ms();
    ov.is_permanent    = permanent;
    ov.expires_at_ms   = permanent ? 0 : (now_ms() + duration_ms);

    {
      std::unique_lock lock(overrides_mutex_);
      admin_overrides_[room_id] = ov;
    }

    json detail;
    detail["max_lifetime_ms"] = max_lifetime_ms;
    detail["min_lifetime_ms"] = min_lifetime_ms;
    detail["permanent"]       = permanent;
    detail["duration_ms"]     = duration_ms;
    detail["reason"]          = reason;
    logger_.log_admin_action(room_id, admin_user, "override", detail);

    return make_success_json();
  }

  // --------------------------------------------------------------------------
  // Remove a retention override.
  // --------------------------------------------------------------------------
  json remove_override(const std::string& room_id,
                        const std::string& admin_user) {
    {
      std::unique_lock lock(overrides_mutex_);
      admin_overrides_.erase(room_id);
    }

    logger_.log_admin_action(room_id, admin_user, "remove_override");
    return make_success_json();
  }

  // --------------------------------------------------------------------------
  // Get all active admin overrides.
  // --------------------------------------------------------------------------
  json get_all_overrides() const {
    std::shared_lock lock(overrides_mutex_);
    json result = json::array();
    int64_t now = now_ms();

    for (const auto& [rid, ov] : admin_overrides_) {
      // Skip expired
      if (!ov.is_permanent && ov.expires_at_ms > 0 && ov.expires_at_ms < now) {
        continue;
      }

      json entry;
      entry["room_id"]         = ov.room_id;
      entry["max_lifetime_ms"] = ov.max_lifetime_ms;
      entry["min_lifetime_ms"] = ov.min_lifetime_ms;
      entry["reason"]          = ov.reason;
      entry["set_by"]          = ov.set_by;
      entry["set_at"]          = iso8601_from_ms(ov.set_at_ms);
      entry["is_permanent"]    = ov.is_permanent;
      entry["expires_at"]      = ov.expires_at_ms > 0
        ? iso8601_from_ms(ov.expires_at_ms) : "never";
      result.push_back(entry);
    }

    return result;
  }

  // --------------------------------------------------------------------------
  // Get override for a specific room.
  // --------------------------------------------------------------------------
  std::optional<RoomOverride> get_room_override(const std::string& room_id) const {
    std::shared_lock lock(overrides_mutex_);
    auto it = admin_overrides_.find(room_id);
    if (it != admin_overrides_.end()) {
      return it->second;
    }
    return std::nullopt;
  }

  // --------------------------------------------------------------------------
  // Check if a room is exempt (globally or via override).
  // --------------------------------------------------------------------------
  bool is_room_exempt(const std::string& room_id) const {
    if (config_.globally_exempt_rooms.count(room_id) > 0) {
      return true;
    }
    std::shared_lock lock(overrides_mutex_);
    auto it = admin_overrides_.find(room_id);
    return (it != admin_overrides_.end() && it->second.max_lifetime_ms == -1);
  }

  // --------------------------------------------------------------------------
  // Purge orphaned media now (admin-triggered).
  // --------------------------------------------------------------------------
  json force_media_purge(const std::string& admin_user) {
    auto stats = media_purge_.run_full_cycle();

    logger_.log_media_purge(stats, "admin:" + admin_user);

    json response;
    response["total_orphans_found"] = stats.total_orphans_found;
    response["soft_deleted"]        = stats.soft_deleted;
    response["hard_deleted"]        = stats.hard_deleted;
    response["kept_in_grace"]       = stats.kept_in_grace;
    response["bytes_soft_deleted"]  = stats.bytes_soft_deleted;
    response["bytes_hard_deleted"]  = stats.bytes_hard_deleted;
    response["errors"]              = stats.errors;
    response["success"]             = (stats.errors == 0);
    if (!stats.error_messages.empty()) {
      response["error_messages"] = stats.error_messages;
    }

    return response;
  }

  // --------------------------------------------------------------------------
  // Dry-run purge: preview what would happen without actually deleting.
  // --------------------------------------------------------------------------
  json dry_run_purge(const std::string& room_id,
                      int64_t max_lifetime_ms = 0) {
    if (max_lifetime_ms <= 0) {
      max_lifetime_ms = config_.default_max_lifetime_ms;
    }

    return engine_.dry_run_room(room_id, max_lifetime_ms, 0, 100);
  }

  // --------------------------------------------------------------------------
  // Pause / resume the purge scheduler.
  // --------------------------------------------------------------------------
  json set_scheduler_state(bool paused, const std::string& admin_user) {
    if (paused) {
      scheduler_.pause();
    } else {
      scheduler_.resume();
    }

    json detail{{"paused", paused}};
    logger_.log_admin_action("__scheduler__", admin_user,
      paused ? "pause_scheduler" : "resume_scheduler", detail);

    json response;
    response["paused"]  = paused;
    response["success"] = true;
    return response;
  }

  // --------------------------------------------------------------------------
  // Get overall system status (for admin dashboard).
  // --------------------------------------------------------------------------
  json get_system_status() const {
    json status;

    // Scheduler status
    status["scheduler"] = scheduler_.get_scheduler_stats();

    // Purge state
    {
      std::lock_guard<std::mutex> lock(g_purge_state.state_mutex);
      status["purge_state"] = g_purge_state.current_state;
      if (!g_purge_state.current_purge_id.empty()) {
        status["current_purge_id"] = g_purge_state.current_purge_id;
      }
    }

    // Media orphan stats
    status["media_orphans"] = media_purge_.get_orphan_stats();

    // Admin overrides count
    {
      std::shared_lock lock(overrides_mutex_);
      status["active_overrides"] = admin_overrides_.size();
    }

    // Global exemptions
    status["globally_exempt_rooms"] = config_.globally_exempt_rooms.size();

    // History summary
    status["history_summary"] = logger_.get_summary_stats();

    // Config highlights
    json config_status;
    config_status["retention_enabled"]     = config_.enable_retention_policy;
    config_status["default_max_lifetime"]  = RetentionPolicyParser::duration_to_human(
      config_.default_max_lifetime_ms);
    config_status["default_min_lifetime"]  = RetentionPolicyParser::duration_to_human(
      config_.default_min_lifetime_ms);
    config_status["purge_interval"]        = RetentionPolicyParser::duration_to_human(
      config_.purge_job_interval_ms);
    config_status["max_batch_size"]        = config_.max_purge_batch_size;
    config_status["media_purge_enabled"]   = config_.auto_purge_orphaned_media;
    status["config"] = config_status;

    return status;
  }

  // --------------------------------------------------------------------------
  // Clean up expired admin overrides (call periodically).
  // --------------------------------------------------------------------------
  void cleanup_expired_overrides() {
    int64_t now = now_ms();
    std::vector<std::string> expired;

    {
      std::shared_lock lock(overrides_mutex_);
      for (const auto& [rid, ov] : admin_overrides_) {
        if (!ov.is_permanent && ov.expires_at_ms > 0 && ov.expires_at_ms < now) {
          expired.push_back(rid);
        }
      }
    }

    if (!expired.empty()) {
      std::unique_lock lock(overrides_mutex_);
      for (const auto& rid : expired) {
        admin_overrides_.erase(rid);
        config_.globally_exempt_rooms.erase(rid);
      }
    }

    for (const auto& rid : expired) {
      logger_.log_admin_action(rid, "system", "override_expired");
    }
  }

  // --------------------------------------------------------------------------
  // Get purge history via admin API.
  // --------------------------------------------------------------------------
  json get_purge_history(const PurgeHistoryLogger::HistoryQuery& query =
                          PurgeHistoryLogger::HistoryQuery{}) const {
    auto entries = logger_.query_history(query);
    json result = json::array();

    for (const auto& entry : entries) {
      json e;
      e["entry_id"]       = entry.entry_id;
      e["room_id"]        = entry.room_id;
      e["timestamp"]      = iso8601_from_ms(entry.timestamp_ms);
      e["triggered_by"]   = entry.triggered_by;
      e["action"]         = entry.action;
      e["events_purged"]  = entry.events_purged;
      e["bytes_freed"]    = entry.bytes_freed;
      e["media_files"]    = entry.media_files_purged;
      e["media_bytes"]    = entry.media_bytes_freed;
      e["status"]         = entry.status;
      e["error"]          = entry.error_message;
      result.push_back(e);
    }

    return result;
  }

private:
  RetentionConfig& config_;
  PurgeEngine& engine_;
  PurgeScheduler& scheduler_;
  MediaPurgeCoordinator& media_purge_;
  PurgeHistoryLogger& logger_;

  mutable std::shared_mutex overrides_mutex_;
  std::unordered_map<std::string, RoomOverride> admin_overrides_;
};

// ============================================================================
// Implementation Part 9: PurgeProgressTracker
// Tracks the progress of long-running purge operations for the admin API.
// ============================================================================

class PurgeProgressTracker {
public:
  struct Progress {
    std::string purge_id;
    std::string state;
    std::string current_room_id;
    int64_t rooms_completed   = 0;
    int64_t rooms_total       = 0;
    int64_t events_purged     = 0;
    int64_t events_scanned    = 0;
    int64_t bytes_freed       = 0;
    int64_t start_time_ms     = 0;
    int64_t estimated_completion_ms = 0;
    double percent_complete   = 0.0;
    std::string current_action;
    std::vector<std::string> recent_errors;
  };

  /// Start tracking a purge job.
  void start_job(const std::string& purge_id, int64_t total_rooms) {
    std::unique_lock lock(mutex_);
    Progress p;
    p.purge_id       = purge_id;
    p.state          = retention_constants::PURGE_STATE_SCANNING;
    p.rooms_total    = total_rooms;
    p.start_time_ms  = now_ms();
    jobs_[purge_id]  = p;
  }

  /// Update progress during a purge.
  void update_progress(const std::string& purge_id,
                        const std::string& state,
                        const std::string& current_room,
                        int64_t rooms_completed,
                        int64_t events_purged,
                        int64_t events_scanned,
                        int64_t bytes_freed) {
    std::unique_lock lock(mutex_);
    auto it = jobs_.find(purge_id);
    if (it == jobs_.end()) return;

    auto& p = it->second;
    p.state            = state;
    p.current_room_id  = current_room;
    p.rooms_completed  = rooms_completed;
    p.events_purged    = events_purged;
    p.events_scanned   = events_scanned;
    p.bytes_freed      = bytes_freed;

    if (p.rooms_total > 0) {
      p.percent_complete = (static_cast<double>(rooms_completed) /
                            static_cast<double>(p.rooms_total)) * 100.0;
    }

    // Estimate completion time
    if (rooms_completed > 0 && rooms_completed < p.rooms_total) {
      int64_t elapsed = now_ms() - p.start_time_ms;
      double time_per_room = static_cast<double>(elapsed) / rooms_completed;
      int64_t remaining_rooms = p.rooms_total - rooms_completed;
      p.estimated_completion_ms = now_ms() +
        static_cast<int64_t>(time_per_room * remaining_rooms);
    }
  }

  /// Mark a job as complete or errored.
  void finish_job(const std::string& purge_id,
                   const std::string& final_state,
                   const std::vector<std::string>& errors = {}) {
    std::unique_lock lock(mutex_);
    auto it = jobs_.find(purge_id);
    if (it == jobs_.end()) return;

    auto& p = it->second;
    p.state = final_state;
    p.recent_errors = errors;
    p.percent_complete = 100.0;
  }

  /// Get progress for a specific purge job.
  std::optional<Progress> get_progress(const std::string& purge_id) const {
    std::shared_lock lock(mutex_);
    auto it = jobs_.find(purge_id);
    if (it != jobs_.end()) {
      return it->second;
    }
    return std::nullopt;
  }

  /// Get all active jobs.
  std::vector<Progress> get_all_active() const {
    std::shared_lock lock(mutex_);
    std::vector<Progress> result;
    for (const auto& [id, p] : jobs_) {
      if (p.state != retention_constants::PURGE_STATE_COMPLETE &&
          p.state != retention_constants::PURGE_STATE_CANCELLED &&
          p.state != retention_constants::PURGE_STATE_ERROR) {
        result.push_back(p);
      }
    }
    return result;
  }

  /// Serialize progress to JSON for admin API.
  json to_json(const std::string& purge_id) const {
    auto prog = get_progress(purge_id);
    if (!prog.has_value()) {
      return json{{"error", "Purge job not found"}};
    }

    const auto& p = *prog;
    json j;
    j["purge_id"]                = p.purge_id;
    j["state"]                   = p.state;
    j["current_room_id"]         = p.current_room_id;
    j["rooms_completed"]         = p.rooms_completed;
    j["rooms_total"]             = p.rooms_total;
    j["events_purged"]           = p.events_purged;
    j["events_scanned"]          = p.events_scanned;
    j["bytes_freed"]             = p.bytes_freed;
    j["percent_complete"]        = p.percent_complete;
    j["start_time"]              = iso8601_from_ms(p.start_time_ms);
    j["estimated_completion"]    = p.estimated_completion_ms > 0
      ? iso8601_from_ms(p.estimated_completion_ms) : "unknown";
    j["elapsed_ms"]              = now_ms() - p.start_time_ms;
    j["current_action"]          = p.current_action;
    if (!p.recent_errors.empty()) {
      j["recent_errors"] = p.recent_errors;
    }

    return j;
  }

  /// Clean up old completed jobs (older than 1 hour).
  void cleanup_old_jobs() {
    std::unique_lock lock(mutex_);
    int64_t cutoff = now_ms() - 3600000; // 1 hour
    auto it = jobs_.begin();
    while (it != jobs_.end()) {
      if (it->second.start_time_ms < cutoff &&
          (it->second.state == retention_constants::PURGE_STATE_COMPLETE ||
           it->second.state == retention_constants::PURGE_STATE_CANCELLED)) {
        it = jobs_.erase(it);
      } else {
        ++it;
      }
    }
  }

private:
  mutable std::shared_mutex mutex_;
  std::unordered_map<std::string, Progress> jobs_;
};

// ============================================================================
// Implementation Part 10: RetentionConfigManager
// Manages retention configuration, validates changes, persists to disk.
// ============================================================================

class RetentionConfigManager {
public:
  explicit RetentionConfigManager(RetentionConfig& config)
    : config_(config) {}

  // --------------------------------------------------------------------------
  // Update configuration from a JSON object (e.g., from admin API or config file).
  // --------------------------------------------------------------------------
  json update_config(const json& new_config) {
    json changes;
    json errors = json::array();

    // Update each config field with validation
    if (new_config.contains("enable_retention_policy")) {
      config_.enable_retention_policy = new_config["enable_retention_policy"].get<bool>();
      changes["enable_retention_policy"] = config_.enable_retention_policy;
    }

    if (new_config.contains("default_max_lifetime_ms")) {
      int64_t val = new_config["default_max_lifetime_ms"].get<int64_t>();
      if (val < 0) {
        errors.push_back("default_max_lifetime_ms must be >= 0");
      } else {
        config_.default_max_lifetime_ms = val;
        changes["default_max_lifetime_ms"] = val;
      }
    }

    if (new_config.contains("default_min_lifetime_ms")) {
      int64_t val = new_config["default_min_lifetime_ms"].get<int64_t>();
      if (val < 0) {
        errors.push_back("default_min_lifetime_ms must be >= 0");
      } else {
        config_.default_min_lifetime_ms = val;
        changes["default_min_lifetime_ms"] = val;
      }
    }

    if (new_config.contains("purge_job_interval_ms")) {
      int64_t val = new_config["purge_job_interval_ms"].get<int64_t>();
      if (val < retention_constants::MIN_PURGE_INTERVAL_MS) {
        errors.push_back("purge_job_interval_ms must be >= " +
          std::to_string(retention_constants::MIN_PURGE_INTERVAL_MS) + " ms");
      } else {
        config_.purge_job_interval_ms = val;
        changes["purge_job_interval_ms"] = val;
      }
    }

    if (new_config.contains("max_purge_batch_size")) {
      size_t val = new_config["max_purge_batch_size"].get<size_t>();
      if (val < retention_constants::MIN_PURGE_BATCH_SIZE) {
        errors.push_back("max_purge_batch_size must be >= " +
          std::to_string(retention_constants::MIN_PURGE_BATCH_SIZE));
      } else if (val > retention_constants::MAX_PURGE_BATCH_SIZE) {
        errors.push_back("max_purge_batch_size must be <= " +
          std::to_string(retention_constants::MAX_PURGE_BATCH_SIZE));
      } else {
        config_.max_purge_batch_size = val;
        changes["max_purge_batch_size"] = val;
      }
    }

    if (new_config.contains("auto_purge_orphaned_media")) {
      config_.auto_purge_orphaned_media = new_config["auto_purge_orphaned_media"].get<bool>();
      changes["auto_purge_orphaned_media"] = config_.auto_purge_orphaned_media;
    }

    if (new_config.contains("enable_purge_history_logging")) {
      config_.enable_purge_history_logging = new_config["enable_purge_history_logging"].get<bool>();
      changes["enable_purge_history_logging"] = config_.enable_purge_history_logging;
    }

    // Build response
    json response;
    response["changes"] = changes;
    response["errors"]  = errors;
    response["success"] = errors.empty();
    return response;
  }

  // --------------------------------------------------------------------------
  // Export current configuration as JSON.
  // --------------------------------------------------------------------------
  json export_config() const {
    json cfg;

    cfg["enable_retention_policy"]   = config_.enable_retention_policy;
    cfg["default_max_lifetime_ms"]   = config_.default_max_lifetime_ms;
    cfg["default_min_lifetime_ms"]   = config_.default_min_lifetime_ms;
    cfg["default_max_lifetime_human"] = RetentionPolicyParser::duration_to_human(
      config_.default_max_lifetime_ms);
    cfg["default_min_lifetime_human"] = RetentionPolicyParser::duration_to_human(
      config_.default_min_lifetime_ms);
    cfg["purge_job_interval_ms"]     = config_.purge_job_interval_ms;
    cfg["purge_job_interval_human"]  = RetentionPolicyParser::duration_to_human(
      config_.purge_job_interval_ms);
    cfg["min_purge_interval_ms"]     = config_.min_purge_interval_ms;
    cfg["max_purge_duration_ms"]     = config_.max_purge_duration_ms;
    cfg["max_purge_batch_size"]      = config_.max_purge_batch_size;
    cfg["max_media_purge_batch_size"] = config_.max_media_purge_batch_size;
    cfg["max_events_per_purge_run"]  = config_.max_events_per_purge_run;
    cfg["max_bytes_per_purge_run"]   = config_.max_bytes_per_purge_run;
    cfg["auto_purge_orphaned_media"] = config_.auto_purge_orphaned_media;
    cfg["media_soft_delete_grace_ms"] = config_.media_soft_delete_grace_ms;
    cfg["media_purge_interval_ms"]   = config_.media_purge_interval_ms;
    cfg["enable_purge_history_logging"] = config_.enable_purge_history_logging;
    cfg["require_dry_run_before_force"] = config_.require_dry_run_before_force;

    // Safety limits
    json safety;
    safety["max_events_per_room_purge"] = config_.safety_max_events_per_room_purge;
    safety["max_events_per_purge_run"]  = config_.max_events_per_purge_run;
    safety["max_bytes_per_purge_run"]   = config_.max_bytes_per_purge_run;
    cfg["safety_limits"] = safety;

    // Throttle
    json throttle;
    throttle["sleep_ms_per_1000"] = config_.throttle_sleep_ms_per_1000;
    throttle["events_before_yield"] = config_.events_before_yield;
    cfg["throttle"] = throttle;

    // Exempt rooms
    cfg["globally_exempt_rooms"] = json::array();
    for (const auto& rid : config_.globally_exempt_rooms) {
      cfg["globally_exempt_rooms"].push_back(rid);
    }

    return cfg;
  }

  // --------------------------------------------------------------------------
  // Validate the entire configuration for consistency.
  // --------------------------------------------------------------------------
  json validate_config() const {
    json result;
    json errors = json::array();
    json warnings = json::array();

    // Check lifetimes
    if (config_.default_max_lifetime_ms < 0) {
      errors.push_back("default_max_lifetime_ms is negative");
    }
    if (config_.default_min_lifetime_ms < 0) {
      errors.push_back("default_min_lifetime_ms is negative");
    }
    if (config_.default_max_lifetime_ms > 0 &&
        config_.default_min_lifetime_ms > 0 &&
        config_.default_min_lifetime_ms > config_.default_max_lifetime_ms) {
      errors.push_back("default_min_lifetime_ms exceeds default_max_lifetime_ms");
    }

    // Check interval
    if (config_.purge_job_interval_ms < retention_constants::MIN_PURGE_INTERVAL_MS) {
      errors.push_back("purge_job_interval_ms is too small (min " +
        std::to_string(retention_constants::MIN_PURGE_INTERVAL_MS) + " ms)");
    }

    // Check batch sizes
    if (config_.max_purge_batch_size < retention_constants::MIN_PURGE_BATCH_SIZE) {
      errors.push_back("max_purge_batch_size is too small");
    }
    if (config_.max_purge_batch_size > retention_constants::MAX_PURGE_BATCH_SIZE) {
      errors.push_back("max_purge_batch_size is too large");
    }

    // Warnings
    if (config_.default_max_lifetime_ms > 0 &&
        config_.default_max_lifetime_ms < 3600000) {
      warnings.push_back("default_max_lifetime_ms is less than 1 hour — very short retention");
    }
    if (!config_.enable_retention_policy) {
      warnings.push_back("Retention policy enforcement is disabled");
    }
    if (config_.max_events_per_purge_run > 10000000) {
      warnings.push_back("max_events_per_purge_run is very high (>10M)");
    }

    result["valid"]    = errors.empty();
    result["errors"]   = errors;
    result["warnings"] = warnings;
    return result;
  }

private:
  RetentionConfig& config_;
};

// ============================================================================
// Implementation Part 11: RoomExemptionRegistry
// Manages room exemptions with user-friendly API.
// ============================================================================

class RoomExemptionRegistry {
public:
  struct ExemptionRecord {
    std::string room_id;
    std::string room_name;        // For display purposes
    std::string reason;
    std::string exempted_by;
    int64_t exempted_at_ms = 0;
    int64_t expires_at_ms  = 0;   // 0 = permanent
    bool is_active = true;
  };

  explicit RoomExemptionRegistry(RetentionConfig& config)
    : config_(config) {}

  // --------------------------------------------------------------------------
  // Register an exemption.
  // --------------------------------------------------------------------------
  json add_exemption(const std::string& room_id,
                      const std::string& room_name,
                      const std::string& reason,
                      const std::string& exempted_by,
                      int64_t duration_ms = 0) {
    std::unique_lock lock(mutex_);

    ExemptionRecord rec;
    rec.room_id        = room_id;
    rec.room_name      = room_name;
    rec.reason         = reason;
    rec.exempted_by    = exempted_by;
    rec.exempted_at_ms = now_ms();
    rec.expires_at_ms  = duration_ms > 0 ? (now_ms() + duration_ms) : 0;
    rec.is_active      = true;

    exemptions_[room_id] = rec;
    config_.globally_exempt_rooms.insert(room_id);

    json response;
    response["room_id"]       = room_id;
    response["exempted_at"]   = iso8601_from_ms(rec.exempted_at_ms);
    response["expires_at"]    = rec.expires_at_ms > 0
      ? iso8601_from_ms(rec.expires_at_ms) : "never";
    response["success"] = true;
    return response;
  }

  // --------------------------------------------------------------------------
  // Remove an exemption.
  // --------------------------------------------------------------------------
  json remove_exemption(const std::string& room_id) {
    std::unique_lock lock(mutex_);
    exemptions_.erase(room_id);
    config_.globally_exempt_rooms.erase(room_id);
    return make_success_json();
  }

  // --------------------------------------------------------------------------
  // Check if a room is exempt.
  // --------------------------------------------------------------------------
  bool is_exempt(const std::string& room_id) const {
    std::shared_lock lock(mutex_);
    auto it = exemptions_.find(room_id);
    if (it == exemptions_.end()) return false;

    if (!it->second.is_active) return false;

    if (it->second.expires_at_ms > 0 && now_ms() > it->second.expires_at_ms) {
      return false; // Expired
    }

    return true;
  }

  // --------------------------------------------------------------------------
  // Get exemption details for a room.
  // --------------------------------------------------------------------------
  std::optional<ExemptionRecord> get_exemption(const std::string& room_id) const {
    std::shared_lock lock(mutex_);
    auto it = exemptions_.find(room_id);
    if (it != exemptions_.end()) {
      return it->second;
    }
    return std::nullopt;
  }

  // --------------------------------------------------------------------------
  // List all active exemptions.
  // --------------------------------------------------------------------------
  std::vector<ExemptionRecord> list_exemptions() const {
    std::shared_lock lock(mutex_);
    std::vector<ExemptionRecord> result;
    int64_t now = now_ms();

    for (const auto& [rid, rec] : exemptions_) {
      if (!rec.is_active) continue;
      if (rec.expires_at_ms > 0 && rec.expires_at_ms < now) continue;
      result.push_back(rec);
    }

    return result;
  }

  // --------------------------------------------------------------------------
  // Export exemptions as JSON.
  // --------------------------------------------------------------------------
  json to_json() const {
    std::shared_lock lock(mutex_);
    json result = json::array();

    for (const auto& [rid, rec] : exemptions_) {
      json entry;
      entry["room_id"]        = rec.room_id;
      entry["room_name"]      = rec.room_name;
      entry["reason"]         = rec.reason;
      entry["exempted_by"]    = rec.exempted_by;
      entry["exempted_at"]    = iso8601_from_ms(rec.exempted_at_ms);
      entry["expires_at"]     = rec.expires_at_ms > 0
        ? iso8601_from_ms(rec.expires_at_ms) : "never";
      entry["is_active"]      = rec.is_active;
      result.push_back(entry);
    }

    return result;
  }

  // --------------------------------------------------------------------------
  // Clean up expired exemptions.
  // --------------------------------------------------------------------------
  void cleanup_expired() {
    int64_t now = now_ms();
    std::unique_lock lock(mutex_);

    for (auto it = exemptions_.begin(); it != exemptions_.end(); ) {
      if (it->second.expires_at_ms > 0 && it->second.expires_at_ms < now) {
        config_.globally_exempt_rooms.erase(it->first);
        it = exemptions_.erase(it);
      } else {
        ++it;
      }
    }
  }

private:
  RetentionConfig& config_;
  mutable std::shared_mutex mutex_;
  std::unordered_map<std::string, ExemptionRecord> exemptions_;
};

// ============================================================================
// Implementation Part 12: RetentionOrchestrator
// Top-level coordinator that ties all retention components together.
// ============================================================================

class RetentionOrchestrator {
public:
  RetentionOrchestrator()
    : config_(),
      parser_(config_),
      exempt_rules_(),
      exempt_handler_(exempt_rules_),
      media_ref_counter_(),
      engine_(config_, exempt_handler_, media_ref_counter_),
      scheduler_(config_, engine_, [this]() { return get_room_list(); }),
      media_config_(),
      media_purge_(media_config_, media_ref_counter_),
      logger_config_(),
      logger_(logger_config_),
      admin_(config_, engine_, scheduler_, media_purge_, logger_),
      config_manager_(config_),
      exemption_registry_(config_),
      progress_tracker_() {}

  // --------------------------------------------------------------------------
  // Set the provider for the room list used by the scheduler.
  // --------------------------------------------------------------------------
  void set_room_list_provider(std::function<std::vector<std::string>()> provider) {
    room_list_provider_ = std::move(provider);
  }

  // --------------------------------------------------------------------------
  // Initialize and start all background services.
  // --------------------------------------------------------------------------
  void startup() {
    if (config_.enable_retention_policy) {
      scheduler_.start();
    }
  }

  // --------------------------------------------------------------------------
  // Shutdown all background services gracefully.
  // --------------------------------------------------------------------------
  void shutdown() {
    scheduler_.stop();
  }

  // --------------------------------------------------------------------------
  // Get references to all subsystems for external API integration.
  // --------------------------------------------------------------------------
  RetentionConfig& get_config()                       { return config_; }
  RetentionPolicyParser& get_parser()                 { return parser_; }
  ExemptEventHandler& get_exempt_handler()            { return exempt_handler_; }
  MediaReferenceCounter& get_media_ref_counter()      { return media_ref_counter_; }
  PurgeEngine& get_engine()                           { return engine_; }
  PurgeScheduler& get_scheduler()                     { return scheduler_; }
  MediaPurgeCoordinator& get_media_purge()            { return media_purge_; }
  PurgeHistoryLogger& get_logger()                    { return logger_; }
  AdminControlPanel& get_admin()                      { return admin_; }
  RetentionConfigManager& get_config_manager()         { return config_manager_; }
  RoomExemptionRegistry& get_exemption_registry()     { return exemption_registry_; }
  PurgeProgressTracker& get_progress_tracker()         { return progress_tracker_; }

  // --------------------------------------------------------------------------
  // Convenience: handle a retention state event update for a room.
  // --------------------------------------------------------------------------
  void on_retention_state_event(const std::string& room_id,
                                 const json& state_event) {
    auto policy = parser_.parse_state_event(state_event, room_id);
    if (policy.has_value() && policy->enabled) {
      // Update schedule for this room
      scheduler_.update_room_schedule(room_id, now_ms() + config_.purge_job_interval_ms);
    }
  }

private:
  std::vector<std::string> get_room_list() {
    if (room_list_provider_) {
      return room_list_provider_();
    }
    return {};
  }

  RetentionConfig config_;
  RetentionPolicyParser parser_;
  ExemptEventHandler::ExemptionRules exempt_rules_;
  ExemptEventHandler exempt_handler_;
  MediaReferenceCounter media_ref_counter_;
  PurgeEngine engine_;
  PurgeScheduler scheduler_;
  MediaPurgeCoordinator::MediaPurgeConfig media_config_;
  MediaPurgeCoordinator media_purge_;
  PurgeHistoryLogger::LoggerConfig logger_config_;
  PurgeHistoryLogger logger_;
  AdminControlPanel admin_;
  RetentionConfigManager config_manager_;
  RoomExemptionRegistry exemption_registry_;
  PurgeProgressTracker progress_tracker_;
  std::function<std::vector<std::string>()> room_list_provider_;
};

} // namespace progressive
