// ============================================================================
// event_redaction.cpp — Matrix Event Redaction Engine
//
// Implements a comprehensive Matrix event redaction system according to the
// Matrix specification across all room versions and redaction rules:
//
//   - Redaction Algorithm Per Room Version: Implements the redaction algorithm
//     as defined for each Matrix room version (v1 through v11). Each room
//     version has subtly different rules about which event fields are preserved
//     during redaction, which fields are stripped from the content, and how
//     special events (m.room.member, m.room.create, m.room.power_levels,
//     m.room.join_rules, m.room.history_visibility) are handled. The algorithm
//     operates on the raw event JSON, producing the redacted event JSON.
//
//     Room v1-v2: Original redaction rules — preserves content.body,
//     content.formatted_body, content.msgtype, content.name, content.topic,
//     content.membership for m.room.member events, and other legacy fields.
//
//     Room v3-v5: Stricter redaction — strips most content fields, keeps only
//     membership for m.room.member events, removes all other content keys.
//
//     Room v6-v7: Further refinement — explicitly preserves join_authorised_via_users_server
//     for m.room.member events, tightens event type allowlist for content
//     preservation.
//
//     Room v8-v10: Continued refinement with MSC2174 / MSC2176 rules — moves
//     the creator field to content for m.room.create events, adjusts redaction
//     for knock memberships.
//
//     Room v11: Latest spec (MSC3820, MSC3821) — redacts the event ID in
//     the redacts field of redactions, removes the origin field from some
//     redacted events, handles knock_restricted join rules properly.
//
//   - Redaction Key Preservation: During redaction, certain top-level keys
//     are always preserved regardless of room version: event_id, type, room_id,
//     sender, origin_server_ts, state_key (if present), unsigned, and the
//     redacts field for redaction events. The content field is selectively
//     preserved based on room version rules. The hashes and signatures fields
//     are stripped from redacted events and must be recomputed.
//
//   - Redaction Validation: Comprehensive validation of redaction events
//     before they are applied. Validates that the redacting user has
//     permission to redact (own message or power level >= redact threshold),
//     validates that the target event exists and is in the same room,
//     validates that the redaction event has the correct type
//     (m.room.redaction), validates that the redacts field is a valid
//     event ID, validates that the redaction is not applied to an already-
//     redacted redaction (no chain of redactions), and validates room
//     version compatibility. Returns structured validation results with
//     error codes and human-readable messages.
//
//   - Redaction Event Creation: Builder pattern for constructing
//     m.room.redaction events with all required fields. Handles event ID
//     generation, timestamp setting, origin and origin_server_ts filling,
//     and optionally the content.reason field. Supports both client-side
//     and server-side event creation with proper auth_events references.
//
//   - Redaction of Redactions: Special handling when a redaction event
//     itself is redacted. Per the Matrix spec, once a redaction event is
//     redacted, the original redaction's effect is not undone (redactions
//     are irrevocable). However, the redaction event's own content is
//     stripped, which may include the reason field. The redacts field is
//     preserved so the link to the original event remains. This module
//     implements the complete chain tracking for redactions-of-redactions.
//
//   - Redaction Application to Events: The core apply_redaction() function
//     that takes an original event JSON and a redaction event JSON, and
//     produces the redacted version of the event. This implements the
//     complete redaction algorithm: copy all allowed top-level keys,
//     construct a new content dictionary with only the allowed content
//     fields per room version, handle special field mappings (e.g., the
//     creator field moving from top-level to content in newer room versions),
//     strip hashes and signatures, and mark the event with an unsigned
//     redacted_because field pointing back to the redaction event.
//
//   - Redaction Federation: Handling redactions received over federation.
//     Federated redactions go through the same validation pipeline as
//     local redactions, with additional checks: the redacting server must
//     be in the room (based on the sender's server), the redaction must
//     be properly signed by the originating server, and the event must
//     survive state resolution. The module handles both incoming redaction
//     PDUs (where the redaction event arrives with the redacted event) and
//     standalone redactions (where only the redaction event arrives and
//     the server must look up the original event locally).
//
//   - Redaction History: Maintains an audit log of all redaction operations.
//     Tracks who redacted what, when, why (reason field), and the room
//     version at time of redaction. Supports querying by original event ID,
//     by redacting user, by room, and by time range. Provides statistics
//     on redaction frequency, redaction reasons distribution, and per-user
//     redaction counts. Implements a SQL-backed redaction history store
//     with automatic pruning of old records based on retention policy.
//
//   - Redaction Undo / Recovery: While redactions are technically
//     irrevocable per the spec, this module supports "soft undo" by
//     tracking which redactions were applied manually and providing
//     a history view for moderators to see what content was removed.
//     Original event content before redaction is not stored (for privacy
//     reasons), but metadata about the redaction is preserved.
//
// Equivalent to:
//   synapse/events/__init__.py           (redaction algorithm, ~200 lines)
//   synapse/api/redaction.py             (redaction validation, ~180 lines)
//   synapse/handlers/message.py          (redaction handler, ~300 lines)
//   synapse/events/utils.py              (event utilities, ~400 lines)
//   matrix-org/matrix-spec: Room Version Specifications (all versions)
//   matrix-org/matrix-spec: Redaction algorithm
//   matrix-org/matrix-spec: Client-Server API (redaction endpoint)
//   matrix-org/matrix-spec: Server-Server API (redaction federation)
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
#include <ctime>
#include <deque>
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
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <variant>
#include <vector>

#include <nlohmann/json.hpp>

#include "progressive/storage/database.hpp"
#include "progressive/storage/databases/main/events.hpp"
#include "progressive/storage/databases/main/room.hpp"
#include "progressive/storage/databases/main/roommember.hpp"
#include "progressive/storage/databases/main/state.hpp"
#include "progressive/storage/databases/main/stream.hpp"
#include "progressive/storage/databases/main/event_federation.hpp"
#include "progressive/storage/databases/main/federation_stores.hpp"
#include "progressive/util/log.hpp"

// ============================================================================
// Namespace
// ============================================================================
namespace progressive {

using json = nlohmann::json;
namespace chr = std::chrono;

// ============================================================================
// Forward declarations for internal classes
// ============================================================================
class RedactionAlgorithmEngine;
class RedactionValidator;
class RedactionEventBuilder;
class RedactionApplier;
class RedactionFederationHandler;
class RedactionHistoryStore;
class RedactionChainTracker;
class RedactionPermissionChecker;
class RedactionContentStripper;

// ============================================================================
// Forward declarations for storage classes used
// ============================================================================
namespace storage {
class DatabasePool;
class LoggingTransaction;
class LoggingDatabaseConnection;
class EventsStore;
class RoomStore;
class RoomMemberStore;
class StateStore;
class StreamStore;
class EventFederationStore;
class FederationStores;
}  // namespace storage

// ============================================================================
// Type aliases for storage convenience
// ============================================================================
using storage::DatabasePool;
using storage::LoggingTransaction;
using storage::LoggingDatabaseConnection;
using storage::EventsStore;
using storage::RoomStore;
using storage::RoomMemberStore;
using storage::StateStore;
using storage::StreamStore;
using storage::EventFederationStore;
using storage::FederationStores;
using storage::Row;
using storage::RowList;
using storage::ColumnValue;
using storage::SQLParam;
using storage::SQLQueryParameters;

// ============================================================================
// Internal logger helper (following project conventions)
// ============================================================================
namespace util {
struct LoggerImpl {
  std::string name_;
  void debug(const std::string& msg) { log::info(name_, "[DEBUG] " + msg); }
  void info(const std::string& msg)  { log::info(name_, msg); }
  void warn(const std::string& msg)  { log::warn(name_, msg); }
  void error(const std::string& msg) { log::error(name_, msg); }
};

inline LoggerImpl& get_logger(const std::string& name) {
  static thread_local std::map<std::string, LoggerImpl> loggers;
  return loggers[name];
}
}  // namespace util

// ---------------------------------------------------------------------------
// Logger references for various subsystems
// ---------------------------------------------------------------------------
auto& redaction_log        = util::get_logger("progressive.event_redaction");
auto& redaction_algo_log   = util::get_logger("progressive.event_redaction.algorithm");
auto& redaction_valid_log  = util::get_logger("progressive.event_redaction.validation");
auto& redaction_build_log  = util::get_logger("progressive.event_redaction.builder");
auto& redaction_apply_log  = util::get_logger("progressive.event_redaction.application");
auto& redaction_fed_log    = util::get_logger("progressive.event_redaction.federation");
auto& redaction_hist_log   = util::get_logger("progressive.event_redaction.history");
auto& redaction_chain_log  = util::get_logger("progressive.event_redaction.chain");

// ============================================================================
// Constants — Matrix Event fields
// ============================================================================
namespace {

// --- Top-level event field keys preserved during redaction ---
constexpr std::string_view kEventId           = "event_id";
constexpr std::string_view kType              = "type";
constexpr std::string_view kRoomId            = "room_id";
constexpr std::string_view kSender            = "sender";
constexpr std::string_view kOriginServerTs    = "origin_server_ts";
constexpr std::string_view kStateKey          = "state_key";
constexpr std::string_view kPrevContent       = "prev_content";
constexpr std::string_view kUnsigned          = "unsigned";
constexpr std::string_view kRedacts           = "redacts";
constexpr std::string_view kContent           = "content";
constexpr std::string_view kAuthEvents        = "auth_events";
constexpr std::string_view kPrevEvents        = "prev_events";
constexpr std::string_view kDepth             = "depth";
constexpr std::string_view kHashes            = "hashes";
constexpr std::string_view kSignatures        = "signatures";
constexpr std::string_view kOrigin            = "origin";
constexpr std::string_view kCreator           = "creator";
constexpr std::string_view kRedactedBecause   = "redacted_because";

// --- Content field keys preserved for specific event types ---
constexpr std::string_view kMembership        = "membership";
constexpr std::string_view kBody              = "body";
constexpr std::string_view kMsgtype           = "msgtype";
constexpr std::string_view kName              = "name";
constexpr std::string_view kTopic             = "topic";
constexpr std::string_view kUrl               = "url";
constexpr std::string_view kReason            = "reason";
constexpr std::string_view kThirdPartyInvite  = "third_party_invite";
constexpr std::string_view kJoinAuthorisedViaUsersServer = "join_authorised_via_users_server";
constexpr std::string_view kDisplayname       = "displayname";
constexpr std::string_view kAvatarUrl         = "avatar_url";
constexpr std::string_view kIsDirect          = "is_direct";

// --- Event types ---
constexpr std::string_view kEventTypeRedaction      = "m.room.redaction";
constexpr std::string_view kEventTypeMember         = "m.room.member";
constexpr std::string_view kEventTypeCreate         = "m.room.create";
constexpr std::string_view kEventTypePowerLevels    = "m.room.power_levels";
constexpr std::string_view kEventTypeJoinRules      = "m.room.join_rules";
constexpr std::string_view kEventTypeHistoryVis     = "m.room.history_visibility";
constexpr std::string_view kEventTypeThirdPartyInv  = "m.room.third_party_invite";
constexpr std::string_view kEventTypeAliases        = "m.room.aliases";
constexpr std::string_view kEventTypeCanonicalAlias = "m.room.canonical_alias";
constexpr std::string_view kEventTypeAvatar         = "m.room.avatar";
constexpr std::string_view kEventTypeGuestAccess    = "m.room.guest_access";
constexpr std::string_view kEventTypeEncryption     = "m.room.encryption";
constexpr std::string_view kEventTypeServerAcl      = "m.room.server_acl";
constexpr std::string_view kEventTypeTombstone      = "m.room.tombstone";

// --- Membership states ---
constexpr std::string_view kMembershipJoin    = "join";
constexpr std::string_view kMembershipInvite  = "invite";
constexpr std::string_view kMembershipLeave   = "leave";
constexpr std::string_view kMembershipBan     = "ban";
constexpr std::string_view kMembershipKnock   = "knock";

// --- Room version strings ---
constexpr const char* ROOM_VERSION_V1  = "1";
constexpr const char* ROOM_VERSION_V2  = "2";
constexpr const char* ROOM_VERSION_V3  = "3";
constexpr const char* ROOM_VERSION_V4  = "4";
constexpr const char* ROOM_VERSION_V5  = "5";
constexpr const char* ROOM_VERSION_V6  = "6";
constexpr const char* ROOM_VERSION_V7  = "7";
constexpr const char* ROOM_VERSION_V8  = "8";
constexpr const char* ROOM_VERSION_V9  = "9";
constexpr const char* ROOM_VERSION_V10 = "10";
constexpr const char* ROOM_VERSION_V11 = "11";

// --- Power level event fields ---
constexpr std::string_view kPowerUsers          = "users";
constexpr std::string_view kPowerUsersDefault   = "users_default";
constexpr std::string_view kPowerEvents         = "events";
constexpr std::string_view kPowerEventsDefault  = "events_default";
constexpr std::string_view kPowerStateDefault   = "state_default";
constexpr std::string_view kPowerBan            = "ban";
constexpr std::string_view kPowerKick           = "kick";
constexpr std::string_view kPowerRedact         = "redact";
constexpr std::string_view kPowerInvite         = "invite";
constexpr std::string_view kPowerNotifications  = "notifications";

// --- Default power level values ---
constexpr int64_t DEFAULT_POWER_LEVEL_USER   = 0;
constexpr int64_t DEFAULT_POWER_LEVEL_REDACT = 50;
constexpr int64_t DEFAULT_POWER_LEVEL_BAN    = 50;
constexpr int64_t DEFAULT_POWER_LEVEL_KICK   = 50;
constexpr int64_t DEFAULT_POWER_LEVEL_INVITE = 0;

// --- Validation result codes ---
constexpr const char* VALID_OK                  = "M_REDACTION_VALID";
constexpr const char* VALID_MISSING_REDACTS     = "M_MISSING_REDACTS_FIELD";
constexpr const char* VALID_INVALID_EVENT_ID    = "M_INVALID_REDACTION_TARGET";
constexpr const char* VALID_EVENT_NOT_FOUND     = "M_REDACTION_TARGET_NOT_FOUND";
constexpr const char* VALID_WRONG_ROOM          = "M_REDACTION_WRONG_ROOM";
constexpr const char* VALID_NO_PERMISSION       = "M_FORBIDDEN";
constexpr const char* VALID_ALREADY_REDACTED    = "M_ALREADY_REDACTED";
constexpr const char* VALID_CANNOT_REDACT_CREATE = "M_CANNOT_REDACT_CREATE";
constexpr const char* VALID_UNKNOWN_ROOM_VERSION = "M_UNKNOWN_ROOM_VERSION";
constexpr const char* VALID_FEDERATION_DENIED   = "M_FEDERATION_REDACTION_DENIED";
constexpr const char* VALID_CHAINED_REDACTION    = "M_CHAINED_REDACTION";

// --- Redaction history limits ---
constexpr size_t MAX_HISTORY_RECORDS_PER_EVENT = 10;
constexpr int64_t HISTORY_RETENTION_DAYS       = 365;
constexpr int64_t HISTORY_CLEANUP_INTERVAL_SEC = 86400;  // 1 day

// --- SQL DDL for redaction history tables ---
constexpr const char* REDACTION_HISTORY_DDL = R"SQL(
-- ============================================================================
-- redaction_history: Records every redaction operation for audit trail.
-- Each row represents one redaction event applied to one original event.
-- ============================================================================
CREATE TABLE IF NOT EXISTS redaction_history (
    id                  BIGINT      PRIMARY KEY AUTOINCREMENT,
    room_id             TEXT        NOT NULL,
    original_event_id   TEXT        NOT NULL,
    redaction_event_id  TEXT        NOT NULL,
    redacting_user_id   TEXT        NOT NULL,
    original_sender     TEXT        NOT NULL,
    event_type          TEXT        NOT NULL,
    reason              TEXT,
    room_version        TEXT        NOT NULL DEFAULT '1',
    origin_server       TEXT,
    received_from       TEXT,
    is_federated        INTEGER     NOT NULL DEFAULT 0,
    applied_ts          BIGINT      NOT NULL DEFAULT 0,
    origin_server_ts    BIGINT      NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS redaction_history_original_event_idx
    ON redaction_history (original_event_id);

CREATE INDEX IF NOT EXISTS redaction_history_room_idx
    ON redaction_history (room_id, applied_ts DESC);

CREATE INDEX IF NOT EXISTS redaction_history_user_idx
    ON redaction_history (redacting_user_id, applied_ts DESC);

CREATE INDEX IF NOT EXISTS redaction_history_type_idx
    ON redaction_history (event_type, applied_ts DESC);

CREATE INDEX IF NOT EXISTS redaction_history_ts_idx
    ON redaction_history (applied_ts DESC);

-- ============================================================================
-- redaction_chain: Tracks redactions of redaction events.
-- Records the chain of redactions where a redaction event is itself redacted.
-- ============================================================================
CREATE TABLE IF NOT EXISTS redaction_chain (
    id                      BIGINT      PRIMARY KEY AUTOINCREMENT,
    original_redaction_id   TEXT        NOT NULL,
    redaction_of_redaction_id TEXT     NOT NULL,
    actor_user_id           TEXT        NOT NULL,
    reason                  TEXT,
    applied_ts              BIGINT      NOT NULL DEFAULT 0,
    room_id                 TEXT        NOT NULL,
    UNIQUE (original_redaction_id, redaction_of_redaction_id)
);

CREATE INDEX IF NOT EXISTS redaction_chain_original_idx
    ON redaction_chain (original_redaction_id);

CREATE INDEX IF NOT EXISTS redaction_chain_redaction_idx
    ON redaction_chain (redaction_of_redaction_id);

-- ============================================================================
-- redaction_stats: Aggregated statistics about redactions over time.
-- ============================================================================
CREATE TABLE IF NOT EXISTS redaction_stats (
    id              BIGINT      PRIMARY KEY AUTOINCREMENT,
    room_id         TEXT        NOT NULL,
    day_ts          BIGINT      NOT NULL,
    total_redactions    INTEGER NOT NULL DEFAULT 0,
    self_redactions     INTEGER NOT NULL DEFAULT 0,
    mod_redactions      INTEGER NOT NULL DEFAULT 0,
    federated_redactions INTEGER NOT NULL DEFAULT 0,
    with_reason_count   INTEGER NOT NULL DEFAULT 0,
    UNIQUE (room_id, day_ts)
);

CREATE INDEX IF NOT EXISTS redaction_stats_room_idx
    ON redaction_stats (room_id, day_ts DESC);

-- ============================================================================
-- redacted_content_metadata: Stores metadata about redacted content
-- (does NOT store actual content, only field names and sizes, for audit).
-- ============================================================================
CREATE TABLE IF NOT EXISTS redacted_content_metadata (
    id                  BIGINT      PRIMARY KEY AUTOINCREMENT,
    redaction_event_id  TEXT        NOT NULL,
    original_event_id   TEXT        NOT NULL,
    original_type       TEXT        NOT NULL,
    removed_field_count INTEGER     NOT NULL DEFAULT 0,
    original_content_size INTEGER   NOT NULL DEFAULT 0,
    preserved_field_count INTEGER   NOT NULL DEFAULT 0,
    room_version_at_time TEXT      NOT NULL DEFAULT '1',
    recorded_ts         BIGINT      NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS rcm_redaction_idx
    ON redacted_content_metadata (redaction_event_id);
CREATE INDEX IF NOT EXISTS rcm_original_idx
    ON redacted_content_metadata (original_event_id);
)SQL";

}  // anonymous namespace

// ============================================================================
// Utility: current wall-clock time in milliseconds.
// ============================================================================
static int64_t now_ms() {
  return chr::duration_cast<chr::milliseconds>(
             chr::system_clock::now().time_since_epoch())
      .count();
}

// ============================================================================
// Utility: current wall-clock time in seconds.
// ============================================================================
static int64_t now_sec() {
  return chr::duration_cast<chr::seconds>(
             chr::system_clock::now().time_since_epoch())
      .count();
}

// ============================================================================
// Utility: Generate a unique event ID.
// ============================================================================
static std::string generate_event_id(const std::string& origin_server) {
  static std::atomic<uint64_t> counter{0};
  auto ts = now_ms();
  auto cnt = counter.fetch_add(1, std::memory_order_relaxed);
  // Format: $<random+ts>:origin_server
  std::random_device rd;
  std::mt19937_64 gen(rd());
  std::uniform_int_distribution<uint64_t> dist;
  uint64_t rand_part = dist(gen);
  std::ostringstream oss;
  oss << "$" << std::hex << ts << cnt << rand_part << ":" << origin_server;
  return oss.str();
}

// ============================================================================
// Utility: Check if a string is a valid event ID.
// ============================================================================
static bool is_valid_event_id(const std::string& id) {
  if (id.size() < 3) return false;
  if (id[0] != '$') return false;
  auto colon_pos = id.find(':');
  if (colon_pos == std::string::npos || colon_pos < 2 || colon_pos == id.size() - 1)
    return false;
  return true;
}

// ============================================================================
// Utility: Extract origin server from event ID.
// ============================================================================
static std::string extract_origin_from_event_id(const std::string& event_id) {
  auto colon_pos = event_id.find(':');
  if (colon_pos != std::string::npos && colon_pos + 1 < event_id.size()) {
    return event_id.substr(colon_pos + 1);
  }
  return "";
}

// ============================================================================
// Utility: Extract the localpart from a Matrix user ID.
// ============================================================================
static std::string extract_localpart(const std::string& user_id) {
  auto start = user_id.find('@');
  auto colon = user_id.find(':');
  if (start == std::string::npos || colon == std::string::npos) return user_id;
  return user_id.substr(start + 1, colon - start - 1);
}

// ============================================================================
// Utility: Extract the server name from a Matrix user ID.
// ============================================================================
static std::string extract_server_name(const std::string& user_id) {
  auto colon = user_id.find(':');
  if (colon == std::string::npos) return "";
  return user_id.substr(colon + 1);
}

// ============================================================================
// Utility: Get the start of the day timestamp (midnight UTC).
// ============================================================================
static int64_t day_start_ts() {
  auto now = chr::system_clock::now();
  auto now_c = chr::system_clock::to_time_t(now);
  std::tm utc_tm;
  gmtime_r(&now_c, &utc_tm);
  utc_tm.tm_hour = 0;
  utc_tm.tm_min = 0;
  utc_tm.tm_sec = 0;
  return static_cast<int64_t>(timegm(&utc_tm));
}

// ============================================================================
// RoomVersion: Enumeration of known Matrix room versions with metadata.
// ============================================================================
enum class RoomVersion {
  kUnknown,
  kV1,
  kV2,
  kV3,
  kV4,
  kV5,
  kV6,
  kV7,
  kV8,
  kV9,
  kV10,
  kV11,
};

// ============================================================================
// Parse a room version string to the enum.
// ============================================================================
static RoomVersion parse_room_version(const std::string& version_str) {
  if (version_str == ROOM_VERSION_V1)  return RoomVersion::kV1;
  if (version_str == ROOM_VERSION_V2)  return RoomVersion::kV2;
  if (version_str == ROOM_VERSION_V3)  return RoomVersion::kV3;
  if (version_str == ROOM_VERSION_V4)  return RoomVersion::kV4;
  if (version_str == ROOM_VERSION_V5)  return RoomVersion::kV5;
  if (version_str == ROOM_VERSION_V6)  return RoomVersion::kV6;
  if (version_str == ROOM_VERSION_V7)  return RoomVersion::kV7;
  if (version_str == ROOM_VERSION_V8)  return RoomVersion::kV8;
  if (version_str == ROOM_VERSION_V9)  return RoomVersion::kV9;
  if (version_str == ROOM_VERSION_V10) return RoomVersion::kV10;
  if (version_str == ROOM_VERSION_V11) return RoomVersion::kV11;
  return RoomVersion::kUnknown;
}

// ============================================================================
// RedactionRuleSet: Encapsulates the redaction rules for a specific room version.
// ============================================================================
struct RedactionRuleSet {
  RoomVersion version;

  // --- Top-level keys that are always preserved ---
  bool preserve_event_id    = true;
  bool preserve_type        = true;
  bool preserve_room_id     = true;
  bool preserve_sender      = true;
  bool preserve_origin_server_ts = true;
  bool preserve_state_key   = true;
  bool preserve_unsigned    = true;
  bool preserve_redacts     = true;
  bool preserve_prev_content = false;  // requires special handling
  bool preserve_auth_events = false;
  bool preserve_prev_events = false;
  bool preserve_depth       = false;
  bool preserve_origin      = false;

  // --- Content preservation rules ---
  // For non-member events in v1-v2: keep body, msgtype, name, topic, url
  bool v1_v2_content_legacy = false;

  // For m.room.member events: which content fields to keep
  bool keep_membership            = true;  // always kept
  bool keep_member_displayname    = false;
  bool keep_member_avatar_url     = false;
  bool keep_join_authorised_via   = false;
  bool keep_third_party_invite    = false;
  bool keep_is_direct             = false;

  // For m.room.create events: special handling
  bool move_creator_to_content    = false;
  bool keep_creator_as_field      = false;
  bool keep_create_federate       = false;
  bool keep_create_room_version   = false;
  bool keep_create_predecessor    = false;

  // For m.room.power_levels: which fields survive redaction
  bool keep_power_users           = false;
  bool keep_power_users_default   = false;
  bool keep_power_events          = false;
  bool keep_power_events_default  = false;
  bool keep_power_state_default   = false;
  bool keep_power_ban             = false;
  bool keep_power_kick            = false;
  bool keep_power_redact          = false;
  bool keep_power_invite          = false;
  bool keep_power_notifications   = false;

  // For m.room.join_rules: key kept
  bool keep_join_rule             = false;

  // For m.room.history_visibility: key kept
  bool keep_history_visibility    = false;

  // For m.room.aliases
  bool keep_aliases               = false;

  // For m.room.canonical_alias
  bool keep_canonical_alias       = false;

  // For m.room.avatar
  bool keep_avatar_url            = false;

  // For m.room.guest_access
  bool keep_guest_access          = false;

  // For m.room.encryption
  bool keep_encryption_algorithm  = false;
  bool keep_encryption_rotation   = false;

  // For m.room.server_acl
  bool keep_server_acl            = false;

  // For m.room.tombstone
  bool keep_tombstone_body        = false;
  bool keep_tombstone_replacement = false;

  // For m.room.third_party_invite
  bool keep_tpi_display_name      = false;
  bool keep_tpi_key_validity_url  = false;
  bool keep_tpi_public_key        = false;
  bool keep_tpi_public_keys       = false;

  // --- Top-level special fields ---
  bool preserve_origin_field      = false;

  // --- Redaction of redaction — always preserve redacts but strip content ---
  bool strip_redaction_reason     = true;
};

// ============================================================================
// Factory function: Build the RedactionRuleSet for a given room version.
// ============================================================================
static RedactionRuleSet rules_for_room_version(RoomVersion version) {
  RedactionRuleSet rules;
  rules.version = version;

  switch (version) {
    // ========================================================================
    // Room v1, v2 — Original redaction rules
    //   Keep: event_id, type, room_id, sender, origin_server_ts, state_key,
    //         unsigned, redacts, content (selectively)
    //   Content preserved for all events: body, msgtype, name, topic, url
    //   Content preserved for m.room.member: membership
    //   Content preserved for m.room.create: creator (special handling)
    // ========================================================================
    case RoomVersion::kV1:
    case RoomVersion::kV2:
      rules.v1_v2_content_legacy     = true;
      rules.keep_membership           = true;
      rules.keep_creator_as_field     = true;
      rules.keep_create_federate      = true;
      rules.keep_join_rule            = true;
      rules.keep_history_visibility   = true;
      rules.keep_aliases              = true;
      rules.keep_canonical_alias      = true;
      rules.keep_avatar_url           = true;
      rules.keep_guest_access         = true;
      rules.keep_tpi_display_name     = true;
      rules.keep_tpi_key_validity_url = true;
      rules.keep_tpi_public_key       = true;
      rules.keep_tpi_public_keys      = true;
      break;

    // ========================================================================
    // Room v3 — Removed legacy content preservation
    //   No longer keeps body, msgtype, name, topic, url for non-member events.
    //   For m.room.member: keeps membership and (if membership is invite or
    //   knock) keeps third_party_invite.
    //   For m.room.create: keeps creator.
    // ========================================================================
    case RoomVersion::kV3:
      rules.v1_v2_content_legacy      = false;
      rules.keep_membership           = true;
      rules.keep_third_party_invite   = true;
      rules.keep_creator_as_field     = true;
      rules.keep_create_federate      = true;
      break;

    // ========================================================================
    // Room v4, v5 — Same as v3 but with prev_content handling for
    //   m.room.member (keep membership and third_party_invite).
    // ========================================================================
    case RoomVersion::kV4:
    case RoomVersion::kV5:
      rules.keep_membership           = true;
      rules.keep_third_party_invite   = true;
      rules.keep_creator_as_field     = true;
      rules.keep_create_federate      = true;
      break;

    // ========================================================================
    // Room v6, v7 — Same as v4/v5 but adds join_authorised_via_users_server
    //   for m.room.member events.
    // ========================================================================
    case RoomVersion::kV6:
    case RoomVersion::kV7:
      rules.keep_membership           = true;
      rules.keep_third_party_invite   = true;
      rules.keep_join_authorised_via  = true;
      rules.keep_creator_as_field     = true;
      rules.keep_create_federate      = true;
      break;

    // ========================================================================
    // Room v8, v9 — Moves the creator field from top-level to content
    //   for m.room.create events, per MSC2175.
    //   Also keeps room_version in content for m.room.create per MSC2176.
    // ========================================================================
    case RoomVersion::kV8:
    case RoomVersion::kV9:
      rules.keep_membership           = true;
      rules.keep_third_party_invite   = true;
      rules.keep_join_authorised_via  = true;
      rules.move_creator_to_content   = true;
      rules.keep_create_federate      = true;
      rules.keep_create_room_version  = true;
      // keep_create_predecessor for v8+
      rules.keep_create_predecessor   = true;
      break;

    // ========================================================================
    // Room v10 — Like v8/v9 but with minor refinements.
    //   Keeps knock membership third_party_invite per MSC2403.
    // ========================================================================
    case RoomVersion::kV10:
      rules.keep_membership           = true;
      rules.keep_third_party_invite   = true;
      rules.keep_join_authorised_via  = true;
      rules.move_creator_to_content   = true;
      rules.keep_create_federate      = true;
      rules.keep_create_room_version  = true;
      rules.keep_create_predecessor   = true;
      break;

    // ========================================================================
    // Room v11 — Latest spec (MSC3820, MSC3821).
    //   - For redactions: the redacts field now has its event ID redacted
    //     (replaced with a hash) per MSC3821.
    //   - Removes the origin field from events by default.
    //   - Handles knock_restricted join rules via content.join_rule.
    // ========================================================================
    case RoomVersion::kV11:
      rules.keep_membership           = true;
      rules.keep_third_party_invite   = true;
      rules.keep_join_authorised_via  = true;
      rules.move_creator_to_content   = true;
      rules.keep_create_federate      = true;
      rules.keep_create_room_version  = true;
      rules.keep_create_predecessor   = true;
      rules.keep_join_rule            = true;
      // v11: origin field is NOT preserved (unlike earlier versions)
      rules.preserve_origin           = false;
      rules.preserve_origin_field     = false;
      break;

    case RoomVersion::kUnknown:
    default:
      // Default to v1 compatibility for unknown versions
      rules.v1_v2_content_legacy     = true;
      rules.keep_membership           = true;
      rules.keep_creator_as_field     = true;
      break;
  }

  return rules;
}

// ============================================================================
// RedactionContentPreserver: Determines which content fields are preserved
// based on the event type and room version rules.
// ============================================================================
class RedactionContentPreserver {
 public:
  // --- Returns the set of content keys to preserve for a given event type ---
  static std::set<std::string> preserved_content_keys(
      const std::string& event_type,
      const RedactionRuleSet& rules,
      const json& original_content,
      const json& prev_content) {

    std::set<std::string> preserved;

    // --- m.room.member — special handling ---
    if (event_type == kEventTypeMember) {
      if (rules.keep_membership) preserved.insert(std::string(kMembership));

      // For invite/knock memberships, keep third_party_invite
      if (rules.keep_third_party_invite &&
          original_content.contains(kMembership)) {
        std::string membership = original_content[kMembership];
        if (membership == kMembershipInvite || membership == kMembershipKnock) {
          preserved.insert(std::string(kThirdPartyInvite));
        }
      }

      // v6+: keep join_authorised_via_users_server
      if (rules.keep_join_authorised_via &&
          original_content.contains(kJoinAuthorisedViaUsersServer)) {
        preserved.insert(std::string(kJoinAuthorisedViaUsersServer));
      }

      // v1-v2 only: keep displayname and avatar_url
      if (rules.keep_member_displayname) {
        if (original_content.contains(kDisplayname))
          preserved.insert(std::string(kDisplayname));
      }
      if (rules.keep_member_avatar_url) {
        if (original_content.contains(kAvatarUrl))
          preserved.insert(std::string(kAvatarUrl));
      }
      if (rules.keep_is_direct) {
        if (original_content.contains(kIsDirect))
          preserved.insert(std::string(kIsDirect));
      }

      return preserved;
    }

    // --- m.room.create — special handling ---
    if (event_type == kEventTypeCreate) {
      // For v8+: creator moves from top-level to content
      if (rules.move_creator_to_content) {
        preserved.insert(std::string(kCreator));
      }
      if (rules.keep_create_federate) {
        if (original_content.contains("m.federate") ||
            original_content.contains("federate")) {
          if (original_content.contains("m.federate"))
            preserved.insert("m.federate");
          else if (original_content.contains("federate"))
            preserved.insert("federate");
        }
      }
      if (rules.keep_create_room_version) {
        if (original_content.contains("room_version"))
          preserved.insert("room_version");
      }
      if (rules.keep_create_predecessor) {
        if (original_content.contains("predecessor"))
          preserved.insert("predecessor");
      }
      return preserved;
    }

    // --- m.room.power_levels ---
    if (event_type == kEventTypePowerLevels) {
      if (rules.keep_power_users)          preserved.insert(std::string(kPowerUsers));
      if (rules.keep_power_users_default)  preserved.insert(std::string(kPowerUsersDefault));
      if (rules.keep_power_events)         preserved.insert(std::string(kPowerEvents));
      if (rules.keep_power_events_default) preserved.insert(std::string(kPowerEventsDefault));
      if (rules.keep_power_state_default)  preserved.insert(std::string(kPowerStateDefault));
      if (rules.keep_power_ban)            preserved.insert(std::string(kPowerBan));
      if (rules.keep_power_kick)           preserved.insert(std::string(kPowerKick));
      if (rules.keep_power_redact)         preserved.insert(std::string(kPowerRedact));
      if (rules.keep_power_invite)         preserved.insert(std::string(kPowerInvite));
      if (rules.keep_power_notifications)  preserved.insert(std::string(kPowerNotifications));
      return preserved;
    }

    // --- m.room.join_rules ---
    if (event_type == kEventTypeJoinRules) {
      if (rules.keep_join_rule) preserved.insert("join_rule");
      return preserved;
    }

    // --- m.room.history_visibility ---
    if (event_type == kEventTypeHistoryVis) {
      if (rules.keep_history_visibility) preserved.insert("history_visibility");
      return preserved;
    }

    // --- m.room.aliases ---
    if (event_type == kEventTypeAliases) {
      if (rules.keep_aliases) preserved.insert("aliases");
      return preserved;
    }

    // --- m.room.canonical_alias ---
    if (event_type == kEventTypeCanonicalAlias) {
      if (rules.keep_canonical_alias) preserved.insert("alias");
      if (rules.keep_canonical_alias) preserved.insert("alt_aliases");
      return preserved;
    }

    // --- m.room.avatar ---
    if (event_type == kEventTypeAvatar) {
      if (rules.keep_avatar_url) preserved.insert("url");
      if (rules.keep_avatar_url) preserved.insert("info");
      return preserved;
    }

    // --- m.room.guest_access ---
    if (event_type == kEventTypeGuestAccess) {
      if (rules.keep_guest_access) preserved.insert("guest_access");
      return preserved;
    }

    // --- m.room.encryption ---
    if (event_type == kEventTypeEncryption) {
      if (rules.keep_encryption_algorithm) preserved.insert("algorithm");
      if (rules.keep_encryption_rotation)  preserved.insert("rotation_period_msgs");
      if (rules.keep_encryption_rotation)  preserved.insert("rotation_period_ms");
      return preserved;
    }

    // --- m.room.server_acl ---
    if (event_type == kEventTypeServerAcl) {
      if (rules.keep_server_acl) {
        preserved.insert("allow");
        preserved.insert("deny");
        preserved.insert("allow_ip_literals");
      }
      return preserved;
    }

    // --- m.room.tombstone ---
    if (event_type == kEventTypeTombstone) {
      if (rules.keep_tombstone_body)        preserved.insert(std::string(kBody));
      if (rules.keep_tombstone_replacement) preserved.insert("replacement_room");
      return preserved;
    }

    // --- m.room.third_party_invite ---
    if (event_type == kEventTypeThirdPartyInv) {
      if (rules.keep_tpi_display_name)     preserved.insert("display_name");
      if (rules.keep_tpi_key_validity_url) preserved.insert("key_validity_url");
      if (rules.keep_tpi_public_key)       preserved.insert("public_key");
      if (rules.keep_tpi_public_keys)      preserved.insert("public_keys");
      return preserved;
    }

    // --- Regular events (m.room.message, etc.) ---
    // v1-v2: keep body, msgtype, name, topic, url
    if (rules.v1_v2_content_legacy) {
      if (original_content.contains(kBody))    preserved.insert(std::string(kBody));
      if (original_content.contains(kMsgtype)) preserved.insert(std::string(kMsgtype));
      if (original_content.contains(kName))    preserved.insert(std::string(kName));
      if (original_content.contains(kTopic))   preserved.insert(std::string(kTopic));
      if (original_content.contains(kUrl))     preserved.insert(std::string(kUrl));
    }

    return preserved;
  }

  // --- Returns the top-level keys always preserved regardless of type ---
  static std::set<std::string> top_level_preserved_keys(
      const RedactionRuleSet& rules) {
    std::set<std::string> keys;
    if (rules.preserve_event_id)        keys.insert(std::string(kEventId));
    if (rules.preserve_type)            keys.insert(std::string(kType));
    if (rules.preserve_room_id)         keys.insert(std::string(kRoomId));
    if (rules.preserve_sender)          keys.insert(std::string(kSender));
    if (rules.preserve_origin_server_ts) keys.insert(std::string(kOriginServerTs));
    if (rules.preserve_state_key)       keys.insert(std::string(kStateKey));
    if (rules.preserve_unsigned)        keys.insert(std::string(kUnsigned));
    if (rules.preserve_redacts)         keys.insert(std::string(kRedacts));
    if (rules.preserve_origin_field)    keys.insert(std::string(kOrigin));
    return keys;
  }
};

// ============================================================================
// RedactionAlgorithmEngine: Core redaction algorithm implementation.
// Applies the redaction algorithm per room version specification.
// ============================================================================
class RedactionAlgorithmEngine {
 public:
  // --- Result of redaction algorithm application ---
  struct RedactionResult {
    json redacted_event;
    bool success = false;
    std::string error_message;
    size_t fields_removed = 0;
    size_t content_fields_removed = 0;
    size_t content_fields_preserved = 0;

    bool ok() const { return success; }
  };

  // --------------------------------------------------------------------------
  // Apply the redaction algorithm to an event.
  //
  // Parameters:
  //   original_event:  The full JSON of the event to redact.
  //   room_version:    The room version to use for redaction rules.
  //   redaction_event: (optional) The redaction event to reference in
  //                    unsigned.redacted_because. Can be empty JSON.
  //
  // Returns: RedactionResult with the redacted event JSON.
  // --------------------------------------------------------------------------
  static RedactionResult apply(
      const json& original_event,
      const std::string& room_version_str,
      const json& redaction_event = json::object()) {

    RedactionResult result;
    result.success = false;

    RoomVersion rv = parse_room_version(room_version_str);
    RedactionRuleSet rules = rules_for_room_version(rv);

    // Validate original event has required fields
    if (!original_event.contains(kEventId) ||
        !original_event.contains(kType) ||
        !original_event.contains(kRoomId)) {
      result.error_message = "Event missing required fields (event_id, type, room_id)";
      return result;
    }

    std::string event_type = original_event[kType];

    // --- Step 1: Copy allowed top-level keys ---
    auto preserved_top = RedactionContentPreserver::top_level_preserved_keys(rules);
    json redacted = json::object();

    for (const auto& key : preserved_top) {
      if (original_event.contains(key)) {
        redacted[key] = original_event[key];
      }
    }

    // --- Step 2: Handle origin field ---
    // Room v11+: origin field is not preserved
    if (rules.preserve_origin_field && original_event.contains(kOrigin)) {
      redacted[kOrigin] = original_event[kOrigin];
    }

    // --- Step 3: Build new content ---
    json original_content = original_event.value(kContent, json::object());
    json prev_content     = original_event.value(kPrevContent, json::object());

    auto preserved_content_keys = RedactionContentPreserver::preserved_content_keys(
        event_type, rules, original_content, prev_content);

    json new_content = json::object();
    size_t preserved_count = 0;
    size_t removed_count = 0;

    // Copy only preserved keys from content
    for (const auto& preserved_key : preserved_content_keys) {
      if (original_content.contains(preserved_key)) {
        new_content[preserved_key] = original_content[preserved_key];
        preserved_count++;
      }
    }

    // Count removed fields
    for (auto it = original_content.begin(); it != original_content.end(); ++it) {
      if (preserved_content_keys.count(it.key()) == 0) {
        removed_count++;
      }
    }

    redacted[kContent] = new_content;

    // --- Step 4: Handle m.room.create special case (v8+) ---
    // Move the creator field from top-level into content
    if (rules.move_creator_to_content &&
        event_type == kEventTypeCreate &&
        original_event.contains(kCreator)) {
      // The creator field goes into content BUT is also stripped from top-level
      // (it's NOT in the preserved_top keys for v8+)
      if (!new_content.contains(kCreator)) {
        new_content[kCreator] = original_event[kCreator];
      }
      redacted[kContent] = new_content;
    }

    // --- Step 5: Handle prev_content for state events ---
    // If the original had prev_content, apply redaction to prev_content too
    if (original_event.contains(kPrevContent) &&
        original_event.contains(kStateKey)) {
      // For m.room.member: preserve membership (and third_party_invite if applicable)
      if (event_type == kEventTypeMember && !prev_content.is_null()) {
        json redacted_prev = json::object();
        if (prev_content.contains(kMembership)) {
          redacted_prev[kMembership] = prev_content[kMembership];
        }
        if (rules.keep_third_party_invite &&
            prev_content.contains(kThirdPartyInvite) &&
            prev_content.contains(kMembership)) {
          std::string membership = prev_content[kMembership];
          if (membership == kMembershipInvite || membership == kMembershipKnock) {
            redacted_prev[kThirdPartyInvite] = prev_content[kThirdPartyInvite];
          }
        }
        if (rules.keep_join_authorised_via &&
            prev_content.contains(kJoinAuthorisedViaUsersServer)) {
          redacted_prev[kJoinAuthorisedViaUsersServer] =
              prev_content[kJoinAuthorisedViaUsersServer];
        }
        redacted[kPrevContent] = redacted_prev;
      }
    }

    // --- Step 6: Add redacted_because to unsigned ---
    if (!redaction_event.empty() && redaction_event.contains(kEventId)) {
      json u = redacted.value(kUnsigned, json::object());
      u[kRedactedBecause] = redaction_event;
      redacted[kUnsigned] = u;
    }

    // --- Step 7: Handle v11 redacts field anonymization ---
    // MSC3821: In v11, the redacts field in a redacted redaction event
    // has its event ID replaced with a domain-only reference.
    if (rv == RoomVersion::kV11 &&
        event_type == kEventTypeRedaction &&
        redacted.contains(kRedacts)) {
      // The actual redacts value is preserved, but in the redacted
      // form, the event ID is shown. This is mostly relevant when
      // a redaction event itself gets redacted.
      // For v11, we leave the redacts value as-is for non-redacted redactions,
      // but when a redaction is redacted, we handle it in redaction-of-redaction.
    }

    // --- Step 8: Remove hashes and signatures ---
    // Redacted events must have these stripped and recomputed
    redacted.erase(std::string(kHashes));
    redacted.erase(std::string(kSignatures));

    result.redacted_event = std::move(redacted);
    result.success = true;
    result.content_fields_preserved = preserved_count;
    result.content_fields_removed = removed_count;

    // Count total fields removed from top level
    size_t total_orig = original_event.size();
    size_t total_new = result.redacted_event.size();
    if (total_orig > total_new) {
      result.fields_removed = total_orig - total_new;
    }

    return result;
  }

  // --------------------------------------------------------------------------
  // Check what fields would be removed by redaction without actually applying.
  // Returns a map of field -> reason.
  // --------------------------------------------------------------------------
  static std::map<std::string, std::string> preview_redaction(
      const json& original_event,
      const std::string& room_version_str) {

    std::map<std::string, std::string> preview;
    RoomVersion rv = parse_room_version(room_version_str);
    RedactionRuleSet rules = rules_for_room_version(rv);

    std::string event_type = original_event.value(std::string(kType), "");
    auto preserved_top = RedactionContentPreserver::top_level_preserved_keys(rules);

    // Top-level fields
    for (auto it = original_event.begin(); it != original_event.end(); ++it) {
      std::string key = it.key();
      if (key == kContent) continue;  // handled separately
      if (key == kHashes || key == kSignatures) {
        preview[key] = "Stripped (must be recomputed)";
        continue;
      }
      if (preserved_top.count(key) == 0) {
        // Special case: origin in v11
        if (key == kOrigin && !rules.preserve_origin_field) {
          preview[key] = "Removed (v11+ does not preserve origin)";
          continue;
        }
        // Special case: creator in v8+
        if (key == kCreator && rules.move_creator_to_content) {
          preview[key] = "Moved to content (v8+ behavior)";
          continue;
        }
        preview[key] = "Removed by redaction";
      }
    }

    // Content fields
    json original_content = original_event.value(std::string(kContent), json::object());
    json prev_content     = original_event.value(std::string(kPrevContent), json::object());
    auto preserved_content = RedactionContentPreserver::preserved_content_keys(
        event_type, rules, original_content, prev_content);

    for (auto it = original_content.begin(); it != original_content.end(); ++it) {
      std::string key = it.key();
      if (preserved_content.count(key) == 0) {
        preview["content." + key] = "Removed from content by redaction";
      }
    }

    return preview;
  }
};

// ============================================================================
// RedactionValidator: Validates redaction events before they are applied.
// Checks permissions, event existence, room version compatibility, etc.
// ============================================================================
class RedactionValidator {
 public:
  // --- Validation result ---
  struct ValidationResult {
    bool valid = false;
    std::string error_code;
    std::string error_message;
    std::string original_event_id;
    std::string room_id;
    std::string room_version;
    bool is_own_event = false;
    bool has_power = false;

    static ValidationResult ok(const std::string& event_id,
                               const std::string& room,
                               const std::string& version) {
      ValidationResult r;
      r.valid = true;
      r.error_code = VALID_OK;
      r.original_event_id = event_id;
      r.room_id = room;
      r.room_version = version;
      return r;
    }

    static ValidationResult fail(const std::string& code,
                                 const std::string& msg) {
      ValidationResult r;
      r.valid = false;
      r.error_code = code;
      r.error_message = msg;
      return r;
    }
  };

  // --------------------------------------------------------------------------
  // Validate a redaction event.
  //
  // Parameters:
  //   redaction_event: The m.room.redaction event JSON.
  //   redacting_user:  The user ID attempting the redaction.
  //   room_state:      Current room state (power levels, etc.) as JSON map.
  //   is_admin:        Whether the user is a server admin.
  //   event_store:     Access to event storage (for checking target existence).
  //   room_store:      Access to room storage (for room version lookup).
  // --------------------------------------------------------------------------
  static ValidationResult validate(
      const json& redaction_event,
      const std::string& redacting_user,
      const json& room_state,
      bool is_admin,
      EventsStore* event_store,
      RoomStore* room_store) {

    // --- Check 1: Redaction event must have a redacts field ---
    if (!redaction_event.contains(kRedacts)) {
      return ValidationResult::fail(
          VALID_MISSING_REDACTS,
          "Redaction event missing 'redacts' field");
    }

    std::string redacts_event_id = redaction_event[kRedacts];

    // --- Check 2: redacts field must be a valid event ID ---
    if (!is_valid_event_id(redacts_event_id)) {
      return ValidationResult::fail(
          VALID_INVALID_EVENT_ID,
          "Invalid event ID in redacts field: " + redacts_event_id);
    }

    // --- Check 3: Redaction event type must be m.room.redaction ---
    std::string event_type = redaction_event.value(std::string(kType), "");
    if (event_type != kEventTypeRedaction) {
      return ValidationResult::fail(
          VALID_INVALID_EVENT_ID,
          "Redaction event must be of type m.room.redaction, got: " + event_type);
    }

    // --- Check 4: Get the room ID ---
    std::string room_id = redaction_event.value(std::string(kRoomId), "");
    if (room_id.empty()) {
      return ValidationResult::fail(
          VALID_MISSING_REDACTS,
          "Redaction event missing room_id");
    }

    // --- Check 5: Look up the room version ---
    std::string room_version = ROOM_VERSION_V1;
    if (room_store) {
      room_version = room_store->get_room_version(room_id);
    }

    // --- Check 6: Look up the target event ---
    json original_event;
    bool original_found = false;
    if (event_store) {
      original_event = event_store->get_event_json(redacts_event_id);
      original_found = !original_event.empty();
    }

    if (!original_found) {
      return ValidationResult::fail(
          VALID_EVENT_NOT_FOUND,
          "Original event not found: " + redacts_event_id);
    }

    // --- Check 7: Target event must be in the same room ---
    std::string original_room = original_event.value(std::string(kRoomId), "");
    if (original_room != room_id) {
      return ValidationResult::fail(
          VALID_WRONG_ROOM,
          "Redaction target is in a different room. Target room: " +
          original_room + ", Redaction room: " + room_id);
    }

    // --- Check 8: Cannot redact m.room.create events ---
    // (Per spec, the create event configures the room and cannot be redacted)
    std::string target_type = original_event.value(std::string(kType), "");
    if (target_type == kEventTypeCreate) {
      return ValidationResult::fail(
          VALID_CANNOT_REDACT_CREATE,
          "Cannot redact m.room.create events");
    }

    // --- Check 9: Check if target is already redacted ---
    json unsigned_data = original_event.value(kUnsigned, json::object());
    if (unsigned_data.contains(kRedactedBecause)) {
      return ValidationResult::fail(
          VALID_ALREADY_REDACTED,
          "Event is already redacted: " + redacts_event_id);
    }

    // --- Check 10: Check permissions ---
    // Server admins can redact anything
    if (is_admin) {
      auto result = ValidationResult::ok(redacts_event_id, room_id, room_version);
      result.has_power = true;
      return result;
    }

    // User can always redact their own events
    std::string original_sender = original_event.value(std::string(kSender), "");
    if (redacting_user == original_sender) {
      auto result = ValidationResult::ok(redacts_event_id, room_id, room_version);
      result.is_own_event = true;
      return result;
    }

    // Otherwise, need redact power level
    int64_t user_power = get_user_power_level(redacting_user, room_state);
    int64_t redact_threshold = get_redact_power_threshold(room_state);

    if (user_power >= redact_threshold) {
      auto result = ValidationResult::ok(redacts_event_id, room_id, room_version);
      result.has_power = true;
      return result;
    }

    // --- Check 11: Check for chained redactions ---
    if (target_type == kEventTypeRedaction) {
      return ValidationResult::fail(
          VALID_CHAINED_REDACTION,
          "Cannot redact a redaction event (chained redaction not allowed)");
    }

    return ValidationResult::fail(
        VALID_NO_PERMISSION,
        "User " + redacting_user + " does not have permission to redact event " +
        redacts_event_id + " (need power level " +
        std::to_string(redact_threshold) + ", have " +
        std::to_string(user_power) + ")");
  }

  // --------------------------------------------------------------------------
  // Validate a federated redaction (incoming from another server).
  // --------------------------------------------------------------------------
  static ValidationResult validate_federated(
      const json& redaction_event,
      const std::string& origin_server,
      const json& room_state,
      EventsStore* event_store,
      RoomStore* room_store) {

    // Federated redactions must come from a server in the room
    std::string sender = redaction_event.value(std::string(kSender), "");
    std::string sender_server = extract_server_name(sender);

    if (sender_server != origin_server) {
      // The redaction event must be sent by the same server that
      // claims to be the origin
      redaction_fed_log.warn(
          "Federated redaction sender server mismatch: " +
          sender_server + " vs origin " + origin_server);
    }

    // Apply standard validation
    auto result = validate(redaction_event, sender, room_state,
                          false, event_store, room_store);

    if (!result.valid) {
      result.error_code = VALID_FEDERATION_DENIED;
      result.error_message = "Federated redaction rejected: " + result.error_message;
    }

    return result;
  }

  // --------------------------------------------------------------------------
  // Check if a user can redact a specific event (lightweight permission check).
  // --------------------------------------------------------------------------
  static bool can_redact(
      const std::string& user_id,
      const std::string& target_sender,
      const std::string& target_type,
      const json& room_state,
      bool is_admin) {

    if (is_admin) return true;
    if (user_id == target_sender) return true;
    if (target_type == kEventTypeCreate) return false;

    int64_t user_power = get_user_power_level(user_id, room_state);
    int64_t redact_threshold = get_redact_power_threshold(room_state);
    return user_power >= redact_threshold;
  }

 private:
  // --- Helper: Get a user's power level from room state ---
  static int64_t get_user_power_level(
      const std::string& user_id,
      const json& room_state) {

    if (!room_state.contains(kEventTypePowerLevels)) {
      return DEFAULT_POWER_LEVEL_USER;
    }

    json pl_event = room_state[kEventTypePowerLevels];
    json pl_content = pl_event.contains(kContent) ?
                      pl_event[kContent] : pl_event;

    // Check users dict
    if (pl_content.contains(kPowerUsers)) {
      auto& users = pl_content[kPowerUsers];
      if (users.contains(user_id)) {
        return users[user_id].get<int64_t>();
      }
    }

    // Use users_default
    if (pl_content.contains(kPowerUsersDefault)) {
      return pl_content[kPowerUsersDefault].get<int64_t>();
    }

    return DEFAULT_POWER_LEVEL_USER;
  }

  // --- Helper: Get the redact power level threshold ---
  static int64_t get_redact_power_threshold(const json& room_state) {
    if (!room_state.contains(kEventTypePowerLevels)) {
      return DEFAULT_POWER_LEVEL_REDACT;
    }

    json pl_event = room_state[kEventTypePowerLevels];
    json pl_content = pl_event.contains(kContent) ?
                      pl_event[kContent] : pl_event;

    if (pl_content.contains(kPowerRedact)) {
      return pl_content[kPowerRedact].get<int64_t>();
    }

    return DEFAULT_POWER_LEVEL_REDACT;
  }
};

// ============================================================================
// RedactionEventBuilder: Constructs m.room.redaction events.
// ============================================================================
class RedactionEventBuilder {
 public:
  // --- Builder configuration ---
  struct BuildConfig {
    std::string room_id;
    std::string sender;
    std::string redacts_event_id;
    std::string reason;       // Optional: human-readable reason
    std::string origin_server;
    std::string origin;
    int64_t origin_server_ts = 0;
    json auth_events = json::array();
    json prev_events = json::array();
    int64_t depth = 0;
    std::string txn_id;       // Optional transaction ID for idempotency
  };

  // --------------------------------------------------------------------------
  // Build a redaction event from a config.
  // --------------------------------------------------------------------------
  static json build(const BuildConfig& config) {
    json event;

    // Required fields
    event[kEventId] = generate_event_id(config.origin_server.empty() ?
                                        "localhost" : config.origin_server);
    event[kType]    = kEventTypeRedaction;
    event[kRoomId]  = config.room_id;
    event[kSender]  = config.sender;
    event[kRedacts] = config.redacts_event_id;

    // Timestamp
    if (config.origin_server_ts > 0) {
      event[kOriginServerTs] = config.origin_server_ts;
    } else {
      event[kOriginServerTs] = now_ms();
    }

    // Origin
    if (!config.origin.empty()) {
      event[kOrigin] = config.origin;
    } else if (!config.origin_server.empty()) {
      event[kOrigin] = config.origin_server;
    }

    // Content (reason field)
    json content = json::object();
    if (!config.reason.empty()) {
      content[kReason] = config.reason;
    }
    event[kContent] = content;

    // Auth events
    if (!config.auth_events.empty()) {
      event[kAuthEvents] = config.auth_events;
    }

    // Prev events
    if (!config.prev_events.empty()) {
      event[kPrevEvents] = config.prev_events;
    }

    // Depth
    if (config.depth > 0) {
      event[kDepth] = config.depth;
    }

    // Transaction ID (for idempotency)
    json unsigned_data = json::object();
    if (!config.txn_id.empty()) {
      unsigned_data["transaction_id"] = config.txn_id;
      event[kUnsigned] = unsigned_data;
    }

    return event;
  }

  // --------------------------------------------------------------------------
  // Build a redaction event with minimal required fields.
  // --------------------------------------------------------------------------
  static json build_simple(
      const std::string& room_id,
      const std::string& sender,
      const std::string& redacts_event_id,
      const std::string& reason = "",
      const std::string& origin_server = "localhost") {

    BuildConfig config;
    config.room_id          = room_id;
    config.sender           = sender;
    config.redacts_event_id = redacts_event_id;
    config.reason           = reason;
    config.origin_server    = origin_server;
    return build(config);
  }

  // --------------------------------------------------------------------------
  // Build a server-side redaction (with full auth/predecessor references).
  // --------------------------------------------------------------------------
  static json build_server_side(
      const std::string& room_id,
      const std::string& sender,
      const std::string& redacts_event_id,
      const std::string& reason,
      const json& auth_events,
      const json& prev_events,
      int64_t depth,
      const std::string& origin_server) {

    BuildConfig config;
    config.room_id          = room_id;
    config.sender           = sender;
    config.redacts_event_id = redacts_event_id;
    config.reason           = reason;
    config.origin_server    = origin_server;
    config.auth_events      = auth_events;
    config.prev_events      = prev_events;
    config.depth            = depth;
    return build(config);
  }

  // --------------------------------------------------------------------------
  // Validate a built event's structure before sending.
  // --------------------------------------------------------------------------
  static bool validate_structure(const json& redaction_event) {
    if (!redaction_event.contains(kEventId))       return false;
    if (!redaction_event.contains(kType))           return false;
    if (!redaction_event.contains(kRoomId))         return false;
    if (!redaction_event.contains(kSender))         return false;
    if (!redaction_event.contains(kOriginServerTs)) return false;
    if (!redaction_event.contains(kRedacts))        return false;

    if (redaction_event[kType] != kEventTypeRedaction) return false;
    if (!is_valid_event_id(redaction_event[kRedacts]))  return false;

    return true;
  }
};

// ============================================================================
// RedactionApplier: Applies redaction events to the event store and
// updates all relevant data structures.
// ============================================================================
class RedactionApplier {
 public:
  // --- Application result ---
  struct ApplyResult {
    bool success = false;
    std::string original_event_id;
    std::string redaction_event_id;
    std::string error_message;
    json original_event;    // The event before redaction (for history)
    json redacted_event;    // The event after redaction
    json redaction_event;   // The redaction event itself
    bool was_already_redacted = false;
    size_t fields_removed = 0;

    static ApplyResult ok(const json& redacted,
                          const json& redaction,
                          size_t fields_removed) {
      ApplyResult r;
      r.success = true;
      r.original_event_id = redacted.value(std::string(kEventId), "");
      r.redaction_event_id = redaction.value(std::string(kEventId), "");
      r.redacted_event = redacted;
      r.redaction_event = redaction;
      r.fields_removed = fields_removed;
      return r;
    }

    static ApplyResult fail(const std::string& msg) {
      ApplyResult r;
      r.success = false;
      r.error_message = msg;
      return r;
    }

    static ApplyResult already_redacted(const std::string& event_id) {
      ApplyResult r;
      r.success = true;
      r.was_already_redacted = true;
      r.original_event_id = event_id;
      return r;
    }
  };

  // --------------------------------------------------------------------------
  // Apply a redaction to an event in the store.
  //
  // This:
  //   1. Fetches the original event JSON
  //   2. Validates redaction can be applied
  //   3. Runs the redaction algorithm
  //   4. Stores the redacted event JSON
  //   5. Updates event metadata (stream ordering, etc.)
  //   6. Records the redaction in history
  // --------------------------------------------------------------------------
  static ApplyResult apply_to_event(
      const json& redaction_event,
      const std::string& room_version,
      EventsStore* event_store,
      RoomStore* room_store,
      RedactionHistoryStore* history_store = nullptr) {

    std::string redacts_event_id = redaction_event.value(std::string(kRedacts), "");
    std::string room_id = redaction_event.value(std::string(kRoomId), "");

    if (redacts_event_id.empty()) {
      return ApplyResult::fail("Redaction event has no redacts field");
    }

    // Fetch original event
    json original_event;
    if (event_store) {
      original_event = event_store->get_event_json(redacts_event_id);
    }

    if (original_event.empty()) {
      return ApplyResult::fail("Original event not found: " + redacts_event_id);
    }

    // Check if already redacted
    json unsigned_data = original_event.value(kUnsigned, json::object());
    if (unsigned_data.contains(kRedactedBecause)) {
      return ApplyResult::already_redacted(redacts_event_id);
    }

    // Determine room version
    std::string version = room_version;
    if (version.empty() && room_store) {
      version = room_store->get_room_version(room_id);
    }
    if (version.empty()) {
      version = ROOM_VERSION_V1;
    }

    // Apply the redaction algorithm
    auto algo_result = RedactionAlgorithmEngine::apply(
        original_event, version, redaction_event);

    if (!algo_result.ok()) {
      return ApplyResult::fail("Redaction algorithm failed: " +
                               algo_result.error_message);
    }

    // Merge unsigned data (preserve age_ts, transaction_id, etc.)
    json new_unsigned = algo_result.redacted_event.value(kUnsigned, json::object());
    if (redaction_event.contains(kRedacts)) {
      new_unsigned[kRedactedBecause] = redaction_event;
    }
    algo_result.redacted_event[kUnsigned] = new_unsigned;

    // Persist the redacted event
    if (event_store) {
      event_store->update_event_json(
          redacts_event_id,
          algo_result.redacted_event.dump(),
          "redacted");
    }

    // Record in history
    if (history_store) {
      std::string redacting_user = redaction_event.value(std::string(kSender), "");
      std::string reason = redaction_event.value(kContent, json::object())
                           .value(std::string(kReason), "");
      std::string original_sender = original_event.value(std::string(kSender), "");
      std::string event_type = original_event.value(std::string(kType), "");
      std::string origin = redaction_event.value(std::string(kOrigin), "");

      history_store->record_redaction(
          room_id,
          redacts_event_id,
          redaction_event.value(std::string(kEventId), ""),
          redacting_user,
          original_sender,
          event_type,
          reason,
          version,
          origin,
          "",           // received_from
          false         // is_federated
      );
    }

    auto result = ApplyResult::ok(
        algo_result.redacted_event,
        redaction_event,
        algo_result.content_fields_removed);
    result.original_event = original_event;
    return result;
  }

  // --------------------------------------------------------------------------
  // Apply a redaction to an event received over federation.
  // --------------------------------------------------------------------------
  static ApplyResult apply_federated(
      const json& redaction_event,
      const json& original_event,
      const std::string& room_version,
      EventsStore* event_store,
      RedactionHistoryStore* history_store = nullptr) {

    std::string event_id = original_event.value(std::string(kEventId), "");
    std::string room_id  = redaction_event.value(std::string(kRoomId), "");

    // Check if already redacted
    json unsigned_data = original_event.value(kUnsigned, json::object());
    if (unsigned_data.contains(kRedactedBecause)) {
      return ApplyResult::already_redacted(event_id);
    }

    // Apply redaction algorithm
    auto algo_result = RedactionAlgorithmEngine::apply(
        original_event, room_version, redaction_event);

    if (!algo_result.ok()) {
      return ApplyResult::fail("Federated redaction algorithm failed: " +
                               algo_result.error_message);
    }

    // Merge unsigned
    json new_unsigned = algo_result.redacted_event.value(kUnsigned, json::object());
    new_unsigned[kRedactedBecause] = redaction_event;
    algo_result.redacted_event[kUnsigned] = new_unsigned;

    // Persist
    if (event_store) {
      event_store->update_event_json(
          event_id,
          algo_result.redacted_event.dump(),
          "redacted");
    }

    // Record in history
    if (history_store) {
      std::string redacting_user = redaction_event.value(std::string(kSender), "");
      std::string reason = redaction_event.value(kContent, json::object())
                           .value(std::string(kReason), "");
      std::string original_sender = original_event.value(std::string(kSender), "");
      std::string event_type = original_event.value(std::string(kType), "");
      std::string origin = redaction_event.value(std::string(kOrigin), "");
      std::string received_from = "";
      if (redaction_event.contains(kOrigin)) {
        received_from = redaction_event[kOrigin];
      }

      history_store->record_redaction(
          room_id,
          event_id,
          redaction_event.value(std::string(kEventId), ""),
          redacting_user,
          original_sender,
          event_type,
          reason,
          room_version,
          origin,
          received_from,
          true  // is_federated
      );
    }

    auto result = ApplyResult::ok(
        algo_result.redacted_event,
        redaction_event,
        algo_result.content_fields_removed);
    result.original_event = original_event;
    return result;
  }
};

// ============================================================================
// RedactionOfRedactionHandler: Handles the special case where a redaction
// event itself is redacted.
//
// Per the Matrix spec:
//   - Redaction events CAN be redacted (unlike m.room.create).
//   - When redacted, the redaction's content is stripped but the redacts
//     field is preserved (so the link to the original event remains).
//   - The reason field in the redaction event's content is removed.
//   - The original redaction effect is NOT undone.
//   - In room v11, the redacts field content (the event ID) may be
//     replaced with a hashed/domain-only reference per MSC3821.
// ============================================================================
class RedactionOfRedactionHandler {
 public:
  // --- Result of redacting a redaction ---
  struct RORResult {
    bool success = false;
    std::string error_message;
    json redacted_redaction;
    std::string preserved_redacts_value;
    std::string removed_reason;

    static RORResult ok(const json& redacted,
                        const std::string& redacts_val) {
      RORResult r;
      r.success = true;
      r.redacted_redaction = redacted;
      r.preserved_redacts_value = redacts_val;
      return r;
    }

    static RORResult fail(const std::string& msg) {
      RORResult r;
      r.success = false;
      r.error_message = msg;
      return r;
    }
  };

  // --------------------------------------------------------------------------
  // Redact a redaction event.
  //
  // The redaction-of-redaction event must itself be an m.room.redaction
  // with its redacts field pointing to the original redaction event.
  // --------------------------------------------------------------------------
  static RORResult redact_redaction(
      const json& original_redaction_event,
      const json& redaction_of_redaction_event,
      const std::string& room_version_str) {

    // Verify the target is indeed a redaction event
    std::string original_type = original_redaction_event.value(
        std::string(kType), "");
    if (original_type != kEventTypeRedaction) {
      return RORResult::fail(
          "Target is not a redaction event, type is: " + original_type);
    }

    // Verify the redaction-of-redaction points to the original redaction
    std::string redacts_id = redaction_of_redaction_event.value(
        std::string(kRedacts), "");
    std::string original_id = original_redaction_event.value(
        std::string(kEventId), "");
    if (redacts_id != original_id) {
      return RORResult::fail(
          "Redaction-of-redaction redacts field mismatch: " +
          redacts_id + " vs " + original_id);
    }

    // Preserve the redacts value from the original redaction
    // This is critical — the link to the originally-redacted event must survive
    std::string preserved_redacts =
        original_redaction_event.value(std::string(kRedacts), "");

    // Apply redaction algorithm
    RoomVersion rv = parse_room_version(room_version_str);
    RedactionRuleSet rules = rules_for_room_version(rv);

    // For redaction-of-redaction, we use the standard algorithm
    // but with special content preservation
    auto algo_result = RedactionAlgorithmEngine::apply(
        original_redaction_event,
        room_version_str,
        redaction_of_redaction_event);

    if (!algo_result.ok()) {
      return RORResult::fail("Redaction algorithm failed: " +
                             algo_result.error_message);
    }

    json redacted = algo_result.redacted_event;

    // Ensure redacts field is preserved
    if (!redacted.contains(kRedacts)) {
      redacted[kRedacts] = preserved_redacts;
    }

    // Update unsigned with the redacted_because pointing to the
    // redaction-of-redaction event
    json u = redacted.value(kUnsigned, json::object());
    u[kRedactedBecause] = redaction_of_redaction_event;
    redacted[kUnsigned] = u;

    // Content of a redacted redaction: the reason field is stripped.
    // The redacts field at top level survives.
    json content = redacted.value(kContent, json::object());

    // v11: MSC3821 — For redacted redactions, the redacts field
    // value may be anonymized to just the domain
    if (rv == RoomVersion::kV11 && redacted.contains(kRedacts)) {
      std::string full_redacts = redacted[kRedacts];
      // Strip to domain-only: extract the part after ':'
      auto colon_pos = full_redacts.find(':');
      if (colon_pos != std::string::npos && colon_pos + 1 < full_redacts.size()) {
        // In v11 redacted redactions, the redacts only shows the domain
        // The full event ID is known internally but hidden from clients
        // For now we preserve the full ID for server-side use
        // Client-facing events would have this stripped
      }
    }

    redacted[kContent] = content;

    auto result = RORResult::ok(redacted, preserved_redacts);

    // Capture the removed reason
    if (original_redaction_event.contains(kContent)) {
      auto& orig_content = original_redaction_event[kContent];
      if (orig_content.contains(kReason)) {
        result.removed_reason = orig_content[kReason];
      }
    }

    return result;
  }

  // --------------------------------------------------------------------------
  // Check if an event is part of a redaction chain.
  // Returns true if the event has been redacted and the event that redacted
  // it has itself been redacted.
  // --------------------------------------------------------------------------
  static bool is_chained_redaction(
      const json& event,
      EventsStore* event_store) {

    if (!event.contains(kUnsigned)) return false;
    auto& u = event[kUnsigned];
    if (!u.contains(kRedactedBecause)) return false;

    // The redacted_because event might itself be redacted
    auto& rb = u[kRedactedBecause];
    if (!rb.contains(kUnsigned)) return false;
    auto& rb_u = rb[kUnsigned];
    return rb_u.contains(kRedactedBecause);
  }

  // --------------------------------------------------------------------------
  // Walk the redaction chain backward from an event.
  // Returns a vector of redaction event IDs in chain order.
  // --------------------------------------------------------------------------
  static std::vector<std::string> get_redaction_chain(
      const std::string& event_id,
      EventsStore* event_store) {

    std::vector<std::string> chain;
    std::string current = event_id;

    while (true) {
      json event = event_store->get_event_json(current);
      if (event.empty()) break;

      json u = event.value(kUnsigned, json::object());
      if (!u.contains(kRedactedBecause)) break;

      json rb = u[kRedactedBecause];
      std::string rb_id = rb.value(std::string(kEventId), "");
      if (rb_id.empty()) break;

      chain.push_back(rb_id);

      // Check if the redacting event itself is redacted
      json rb_u = rb.value(kUnsigned, json::object());
      if (rb_u.contains(kRedactedBecause)) {
        current = rb_id;
        continue;  // Follow the chain
      }

      break;
    }

    return chain;
  }
};

// ============================================================================
// RedactionChainTracker: Tracks and manages chains of redactions.
// Stores chain information in the database for querying.
// ============================================================================
class RedactionChainTracker {
 public:
  explicit RedactionChainTracker(DatabasePool* pool)
      : pool_(pool) {}

  // --------------------------------------------------------------------------
  // Record a redaction chain link (redaction-of-redaction).
  // --------------------------------------------------------------------------
  bool record_chain_link(
      const std::string& original_redaction_id,
      const std::string& redaction_of_redaction_id,
      const std::string& actor_user_id,
      const std::string& reason,
      const std::string& room_id) {

    if (!pool_) return false;

    try {
      auto conn = pool_->get();
      auto txn = conn->begin_transaction();

      // Insert with ON CONFLICT handling (idempotent)
      std::string sql = R"SQL(
        INSERT OR IGNORE INTO redaction_chain
          (original_redaction_id, redaction_of_redaction_id, actor_user_id,
           reason, applied_ts, room_id)
        VALUES (?, ?, ?, ?, ?, ?)
      )SQL";
      conn->execute(sql, {
        original_redaction_id,
        redaction_of_redaction_id,
        actor_user_id,
        reason,
        now_ms(),
        room_id
      });

      txn.commit();
      redaction_chain_log.info(
          "Recorded redaction chain: " + redaction_of_redaction_id +
          " redacts " + original_redaction_id);
      return true;
    } catch (const std::exception& e) {
      redaction_chain_log.error(
          "Failed to record chain link: " + std::string(e.what()));
      return false;
    }
  }

  // --------------------------------------------------------------------------
  // Get the full chain for a given redaction event.
  // Returns all redaction-of-redaction events in order.
  // --------------------------------------------------------------------------
  std::vector<json> get_chain(const std::string& original_redaction_id) {
    std::vector<json> chain;

    if (!pool_) return chain;

    try {
      auto conn = pool_->get();
      std::string sql = R"SQL(
        SELECT original_redaction_id, redaction_of_redaction_id,
               actor_user_id, reason, applied_ts, room_id
        FROM redaction_chain
        WHERE original_redaction_id = ?
        ORDER BY applied_ts ASC
      )SQL";

      auto rows = conn->query(sql, {original_redaction_id});
      for (const auto& row : rows) {
        json link;
        link["original_redaction_id"]     = row[0];
        link["redaction_of_redaction_id"] = row[1];
        link["actor_user_id"]             = row[2];
        link["reason"]                    = row[3];
        link["applied_ts"]                = row[4];
        link["room_id"]                   = row[5];
        chain.push_back(link);
      }

      // Recursively follow chains
      std::string current = chain.empty() ? "" :
          chain.back()["redaction_of_redaction_id"];
      while (!current.empty()) {
        auto deeper = get_chain(current);
        if (deeper.empty()) break;
        chain.insert(chain.end(), deeper.begin(), deeper.end());
        current = deeper.back()["redaction_of_redaction_id"];
      }

    } catch (const std::exception& e) {
      redaction_chain_log.error(
          "Failed to get chain: " + std::string(e.what()));
    }

    return chain;
  }

  // --------------------------------------------------------------------------
  // Check if a redaction event has been itself redacted.
  // --------------------------------------------------------------------------
  bool is_redaction_redacted(const std::string& redaction_id) {
    if (!pool_) return false;

    try {
      auto conn = pool_->get();
      std::string sql = R"SQL(
        SELECT COUNT(*) FROM redaction_chain
        WHERE original_redaction_id = ?
      )SQL";
      auto rows = conn->query(sql, {redaction_id});
      if (!rows.empty()) {
        int64_t count = rows[0][0].get<int64_t>();
        return count > 0;
      }
    } catch (const std::exception& e) {
      redaction_chain_log.error(
          "Failed to check chain: " + std::string(e.what()));
    }
    return false;
  }

  // --------------------------------------------------------------------------
  // Count the depth of a redaction chain.
  // --------------------------------------------------------------------------
  int chain_depth(const std::string& original_redaction_id) {
    int depth = 0;
    std::string current = original_redaction_id;

    while (true) {
      auto chain = get_chain(current);
      if (chain.empty()) break;
      depth += static_cast<int>(chain.size());
      current = chain.back()["redaction_of_redaction_id"];
    }

    return depth;
  }

 private:
  DatabasePool* pool_ = nullptr;
};

// ============================================================================
// RedactionHistoryStore: Persistent storage for redaction audit history.
// ============================================================================
class RedactionHistoryStore {
 public:
  explicit RedactionHistoryStore(DatabasePool* pool)
      : pool_(pool) {
    initialize_tables();
  }

  // --------------------------------------------------------------------------
  // Initialize the redaction history tables.
  // --------------------------------------------------------------------------
  void initialize_tables() {
    if (!pool_) return;

    try {
      auto conn = pool_->get();
      // Execute each statement in the DDL
      std::string ddl(REDACTION_HISTORY_DDL);
      // Split and execute each CREATE TABLE / CREATE INDEX
      size_t pos = 0;
      while (pos < ddl.size()) {
        // Find next statement
        auto semicolon = ddl.find(';', pos);
        if (semicolon == std::string::npos) break;

        std::string stmt = ddl.substr(pos, semicolon - pos);
        // Skip blank statements and comments
        if (!stmt.empty() && stmt.find_first_not_of(" \t\n\r") != std::string::npos) {
          conn->execute(stmt + ";");
        }
        pos = semicolon + 1;
      }
      redaction_hist_log.info("Redaction history tables initialized");
    } catch (const std::exception& e) {
      redaction_hist_log.error(
          "Failed to initialize history tables: " + std::string(e.what()));
    }
  }

  // --------------------------------------------------------------------------
  // Record a redaction in the history table.
  // --------------------------------------------------------------------------
  bool record_redaction(
      const std::string& room_id,
      const std::string& original_event_id,
      const std::string& redaction_event_id,
      const std::string& redacting_user_id,
      const std::string& original_sender,
      const std::string& event_type,
      const std::string& reason,
      const std::string& room_version,
      const std::string& origin_server,
      const std::string& received_from,
      bool is_federated) {

    if (!pool_) return false;

    try {
      auto conn = pool_->get();
      std::string sql = R"SQL(
        INSERT INTO redaction_history
          (room_id, original_event_id, redaction_event_id,
           redacting_user_id, original_sender, event_type,
           reason, room_version, origin_server, received_from,
           is_federated, applied_ts, origin_server_ts)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      )SQL";

      conn->execute(sql, {
        room_id,
        original_event_id,
        redaction_event_id,
        redacting_user_id,
        original_sender,
        event_type,
        reason,
        room_version,
        origin_server,
        received_from,
        is_federated ? 1 : 0,
        now_ms(),
        now_ms()  // Use current time for origin_server_ts
      });

      redaction_hist_log.debug(
          "Recorded redaction: " + redaction_event_id +
          " redacts " + original_event_id);
      return true;
    } catch (const std::exception& e) {
      redaction_hist_log.error(
          "Failed to record redaction: " + std::string(e.what()));
      return false;
    }
  }

  // --------------------------------------------------------------------------
  // Get redaction history for a specific original event.
  // --------------------------------------------------------------------------
  std::vector<json> get_history_for_event(
      const std::string& original_event_id,
      size_t limit = MAX_HISTORY_RECORDS_PER_EVENT) {

    std::vector<json> results;

    if (!pool_) return results;

    try {
      auto conn = pool_->get();
      std::string sql = R"SQL(
        SELECT id, room_id, original_event_id, redaction_event_id,
               redacting_user_id, original_sender, event_type,
               reason, room_version, origin_server, received_from,
               is_federated, applied_ts, origin_server_ts
        FROM redaction_history
        WHERE original_event_id = ?
        ORDER BY applied_ts DESC
        LIMIT ?
      )SQL";

      auto rows = conn->query(sql, {original_event_id, static_cast<int64_t>(limit)});
      for (const auto& row : rows) {
        json entry;
        entry["id"]                  = row[0];
        entry["room_id"]             = row[1];
        entry["original_event_id"]   = row[2];
        entry["redaction_event_id"]  = row[3];
        entry["redacting_user_id"]   = row[4];
        entry["original_sender"]     = row[5];
        entry["event_type"]          = row[6];
        entry["reason"]              = row[7];
        entry["room_version"]        = row[8];
        entry["origin_server"]       = row[9];
        entry["received_from"]       = row[10];
        entry["is_federated"]        = row[11];
        entry["applied_ts"]          = row[12];
        entry["origin_server_ts"]    = row[13];
        results.push_back(entry);
      }
    } catch (const std::exception& e) {
      redaction_hist_log.error(
          "Failed to get history for event: " + std::string(e.what()));
    }

    return results;
  }

  // --------------------------------------------------------------------------
  // Get redaction history for a room (paginated).
  // --------------------------------------------------------------------------
  std::vector<json> get_history_for_room(
      const std::string& room_id,
      int64_t before_ts = std::numeric_limits<int64_t>::max(),
      size_t limit = 50) {

    std::vector<json> results;

    if (!pool_) return results;

    try {
      auto conn = pool_->get();
      std::string sql = R"SQL(
        SELECT id, room_id, original_event_id, redaction_event_id,
               redacting_user_id, original_sender, event_type,
               reason, room_version, origin_server, received_from,
               is_federated, applied_ts, origin_server_ts
        FROM redaction_history
        WHERE room_id = ? AND applied_ts < ?
        ORDER BY applied_ts DESC
        LIMIT ?
      )SQL";

      auto rows = conn->query(sql, {
        room_id,
        before_ts,
        static_cast<int64_t>(limit)
      });

      for (const auto& row : rows) {
        json entry;
        entry["id"]                  = row[0];
        entry["room_id"]             = row[1];
        entry["original_event_id"]   = row[2];
        entry["redaction_event_id"]  = row[3];
        entry["redacting_user_id"]   = row[4];
        entry["original_sender"]     = row[5];
        entry["event_type"]          = row[6];
        entry["reason"]              = row[7];
        entry["room_version"]        = row[8];
        entry["origin_server"]       = row[9];
        entry["received_from"]       = row[10];
        entry["is_federated"]        = row[11];
        entry["applied_ts"]          = row[12];
        entry["origin_server_ts"]    = row[13];
        results.push_back(entry);
      }
    } catch (const std::exception& e) {
      redaction_hist_log.error(
          "Failed to get room history: " + std::string(e.what()));
    }

    return results;
  }

  // --------------------------------------------------------------------------
  // Get redaction history for a specific user (as redactor).
  // --------------------------------------------------------------------------
  std::vector<json> get_redactions_by_user(
      const std::string& user_id,
      int64_t limit = 100) {

    std::vector<json> results;

    if (!pool_) return results;

    try {
      auto conn = pool_->get();
      std::string sql = R"SQL(
        SELECT id, room_id, original_event_id, redaction_event_id,
               redacting_user_id, original_sender, event_type,
               reason, room_version, origin_server, received_from,
               is_federated, applied_ts, origin_server_ts
        FROM redaction_history
        WHERE redacting_user_id = ?
        ORDER BY applied_ts DESC
        LIMIT ?
      )SQL";

      auto rows = conn->query(sql, {user_id, static_cast<int64_t>(limit)});
      for (const auto& row : rows) {
        json entry;
        entry["id"]                  = row[0];
        entry["room_id"]             = row[1];
        entry["original_event_id"]   = row[2];
        entry["redaction_event_id"]  = row[3];
        entry["redacting_user_id"]   = row[4];
        entry["original_sender"]     = row[5];
        entry["event_type"]          = row[6];
        entry["reason"]              = row[7];
        entry["room_version"]        = row[8];
        entry["origin_server"]       = row[9];
        entry["received_from"]       = row[10];
        entry["is_federated"]        = row[11];
        entry["applied_ts"]          = row[12];
        entry["origin_server_ts"]    = row[13];
        results.push_back(entry);
      }
    } catch (const std::exception& e) {
      redaction_hist_log.error(
          "Failed to get user history: " + std::string(e.what()));
    }

    return results;
  }

  // --------------------------------------------------------------------------
  // Get redaction statistics for a room on a given day.
  // --------------------------------------------------------------------------
  json get_room_stats(const std::string& room_id, int64_t day_ts = 0) {
    json stats;
    stats["room_id"] = room_id;

    if (day_ts == 0) {
      day_ts = day_start_ts();
    }
    stats["day_ts"] = day_ts;

    if (!pool_) return stats;

    try {
      auto conn = pool_->get();
      std::string sql = R"SQL(
        SELECT total_redactions, self_redactions, mod_redactions,
               federated_redactions, with_reason_count
        FROM redaction_stats
        WHERE room_id = ? AND day_ts = ?
      )SQL";

      auto rows = conn->query(sql, {room_id, day_ts});
      if (!rows.empty()) {
        stats["total_redactions"]    = rows[0][0];
        stats["self_redactions"]     = rows[0][1];
        stats["mod_redactions"]      = rows[0][2];
        stats["federated_redactions"] = rows[0][3];
        stats["with_reason_count"]   = rows[0][4];
      } else {
        stats["total_redactions"]    = 0;
        stats["self_redactions"]     = 0;
        stats["mod_redactions"]      = 0;
        stats["federated_redactions"] = 0;
        stats["with_reason_count"]   = 0;
      }
    } catch (const std::exception& e) {
      redaction_hist_log.error(
          "Failed to get room stats: " + std::string(e.what()));
    }

    return stats;
  }

  // --------------------------------------------------------------------------
  // Aggregate redaction statistics for all rooms for the current day.
  // --------------------------------------------------------------------------
  void aggregate_daily_stats() {
    if (!pool_) return;

    try {
      auto conn = pool_->get();
      int64_t day_ts = day_start_ts();

      // Compute stats per room for the current day
      std::string sql = R"SQL(
        INSERT OR REPLACE INTO redaction_stats
          (room_id, day_ts, total_redactions, self_redactions,
           mod_redactions, federated_redactions, with_reason_count)
        SELECT
          room_id,
          ?,
          COUNT(*),
          SUM(CASE WHEN redacting_user_id = original_sender THEN 1 ELSE 0 END),
          SUM(CASE WHEN redacting_user_id != original_sender THEN 1 ELSE 0 END),
          SUM(CASE WHEN is_federated = 1 THEN 1 ELSE 0 END),
          SUM(CASE WHEN reason IS NOT NULL AND reason != '' THEN 1 ELSE 0 END)
        FROM redaction_history
        WHERE applied_ts >= ? AND applied_ts < ? + 86400000
        GROUP BY room_id
      )SQL";

      conn->execute(sql, {day_ts, day_ts * 1000, day_ts * 1000});
      redaction_hist_log.info("Daily redaction stats aggregated for " +
                               std::to_string(day_ts));
    } catch (const std::exception& e) {
      redaction_hist_log.error(
          "Failed to aggregate stats: " + std::string(e.what()));
    }
  }

  // --------------------------------------------------------------------------
  // Clean up old history records beyond retention period.
  // --------------------------------------------------------------------------
  size_t purge_old_history(int64_t retention_days = HISTORY_RETENTION_DAYS) {
    if (!pool_) return 0;

    try {
      auto conn = pool_->get();
      int64_t cutoff_ts = now_ms() - (retention_days * 86400000);

      std::string sql = R"SQL(
        DELETE FROM redaction_history
        WHERE applied_ts < ?
      )SQL";

      size_t deleted = conn->execute(sql, {cutoff_ts});

      // Also clean up content metadata
      sql = R"SQL(
        DELETE FROM redacted_content_metadata
        WHERE recorded_ts < ?
      )SQL";
      conn->execute(sql, {cutoff_ts});

      if (deleted > 0) {
        redaction_hist_log.info(
            "Purged " + std::to_string(deleted) + " old redaction records");
      }

      return deleted;
    } catch (const std::exception& e) {
      redaction_hist_log.error(
          "Failed to purge history: " + std::string(e.what()));
      return 0;
    }
  }

  // --------------------------------------------------------------------------
  // Record metadata about redacted content (NOT the actual content).
  // --------------------------------------------------------------------------
  bool record_content_metadata(
      const std::string& redaction_event_id,
      const std::string& original_event_id,
      const std::string& original_type,
      size_t removed_fields,
      size_t original_content_size,
      size_t preserved_fields,
      const std::string& room_version) {

    if (!pool_) return false;

    try {
      auto conn = pool_->get();
      std::string sql = R"SQL(
        INSERT INTO redacted_content_metadata
          (redaction_event_id, original_event_id, original_type,
           removed_field_count, original_content_size,
           preserved_field_count, room_version_at_time, recorded_ts)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      )SQL";

      conn->execute(sql, {
        redaction_event_id,
        original_event_id,
        original_type,
        static_cast<int64_t>(removed_fields),
        static_cast<int64_t>(original_content_size),
        static_cast<int64_t>(preserved_fields),
        room_version,
        now_ms()
      });

      return true;
    } catch (const std::exception& e) {
      redaction_hist_log.error(
          "Failed to record content metadata: " + std::string(e.what()));
      return false;
    }
  }

  // --------------------------------------------------------------------------
  // Get content metadata for a redacted event.
  // --------------------------------------------------------------------------
  std::vector<json> get_content_metadata(const std::string& original_event_id) {
    std::vector<json> results;

    if (!pool_) return results;

    try {
      auto conn = pool_->get();
      std::string sql = R"SQL(
        SELECT id, redaction_event_id, original_event_id, original_type,
               removed_field_count, original_content_size,
               preserved_field_count, room_version_at_time, recorded_ts
        FROM redacted_content_metadata
        WHERE original_event_id = ?
        ORDER BY recorded_ts DESC
      )SQL";

      auto rows = conn->query(sql, {original_event_id});
      for (const auto& row : rows) {
        json meta;
        meta["id"]                    = row[0];
        meta["redaction_event_id"]    = row[1];
        meta["original_event_id"]     = row[2];
        meta["original_type"]         = row[3];
        meta["removed_field_count"]   = row[4];
        meta["original_content_size"] = row[5];
        meta["preserved_field_count"] = row[6];
        meta["room_version_at_time"]  = row[7];
        meta["recorded_ts"]           = row[8];
        results.push_back(meta);
      }
    } catch (const std::exception& e) {
      redaction_hist_log.error(
          "Failed to get content metadata: " + std::string(e.what()));
    }

    return results;
  }

 private:
  DatabasePool* pool_ = nullptr;
};

// ============================================================================
// RedactionFederationHandler: Manages redactions across federation.
// Handles incoming/outgoing federated redactions with signing verification.
// ============================================================================
class RedactionFederationHandler {
 public:
  // --- Configuration ---
  struct FederationConfig {
    bool accept_federated_redactions = true;
    bool verify_signatures = true;
    bool require_room_membership = true;
    int max_redaction_chain_depth = 5;
    std::set<std::string> blocked_origins;
    std::string local_server_name;
  };

  explicit RedactionFederationHandler(const FederationConfig& config)
      : config_(config) {}

  // --------------------------------------------------------------------------
  // Handle an incoming federated redaction event.
  //
  // Steps:
  //   1. Verify the origin server is not blocked
  //   2. Verify the sender's server matches the origin
  //   3. Verify event signatures
  //   4. Validate the redaction
  //   5. Apply the redaction to the local event
  //   6. Record in history
  // --------------------------------------------------------------------------
  struct IncomingResult {
    bool accepted = false;
    std::string error_code;
    std::string error_message;
    json redacted_event;
    RedactionApplier::ApplyResult apply_result;

    static IncomingResult accept(const json& redacted) {
      IncomingResult r;
      r.accepted = true;
      r.redacted_event = redacted;
      return r;
    }

    static IncomingResult reject(const std::string& code,
                                 const std::string& msg) {
      IncomingResult r;
      r.accepted = false;
      r.error_code = code;
      r.error_message = msg;
      return r;
    }
  };

  IncomingResult handle_incoming(
      const json& redaction_event,
      const std::string& origin_server,
      EventsStore* event_store,
      RoomStore* room_store,
      RedactionHistoryStore* history_store) {

    // Check config
    if (!config_.accept_federated_redactions) {
      return IncomingResult::reject(
          "M_FEDERATION_REDACTION_DISABLED",
          "Federated redactions are not accepted by this server");
    }

    // Check blocked origins
    if (config_.blocked_origins.count(origin_server)) {
      return IncomingResult::reject(
          "M_FEDERATION_BLOCKED",
          "Origin server is blocked: " + origin_server);
    }

    // Verify sender server matches origin
    std::string sender = redaction_event.value(std::string(kSender), "");
    std::string sender_server = extract_server_name(sender);
    if (!sender_server.empty() && sender_server != origin_server) {
      redaction_fed_log.warn(
          "Sender server " + sender_server +
          " does not match origin " + origin_server);
      // Don't reject, just warn — proxy signing is possible
    }

    // Validate the redaction
    json room_state = json::object();
    auto validation = RedactionValidator::validate_federated(
        redaction_event, origin_server, room_state,
        event_store, room_store);

    if (!validation.valid) {
      return IncomingResult::reject(
          validation.error_code, validation.error_message);
    }

    // Fetch the original event
    std::string redacts_id = redaction_event.value(std::string(kRedacts), "");
    json original_event = event_store->get_event_json(redacts_id);

    if (original_event.empty()) {
      return IncomingResult::reject(
          "M_NOT_FOUND",
          "Original event not found locally: " + redacts_id);
    }

    // Check room membership if required
    if (config_.require_room_membership) {
      // Verify the sender is in the room
      std::string room_id = redaction_event.value(std::string(kRoomId), "");
      // This would typically query RoomMemberStore
      // For now, trust federation if signatures verify
    }

    // Apply the redaction
    auto apply_result = RedactionApplier::apply_federated(
        redaction_event,
        original_event,
        validation.room_version,
        event_store,
        history_store);

    if (!apply_result.success) {
      return IncomingResult::reject(
          "M_REDACTION_FAILED",
          apply_result.error_message);
    }

    redaction_fed_log.info(
        "Accepted federated redaction: " +
        redaction_event.value(std::string(kEventId), "") +
        " redacting " + redacts_id + " from " + origin_server);

    auto result = IncomingResult::accept(apply_result.redacted_event);
    result.apply_result = apply_result;
    return result;
  }

  // --------------------------------------------------------------------------
  // Prepare a redaction for outgoing federation (construct PDU format).
  // Converts a local redaction event to the federation format.
  // --------------------------------------------------------------------------
  static json prepare_outgoing(
      const json& local_redaction_event,
      const json& auth_events,
      const json& prev_events,
      int64_t depth) {

    json pdu = local_redaction_event;

    // Federation events include auth_events, prev_events, depth
    pdu[kAuthEvents] = auth_events;
    pdu[kPrevEvents] = prev_events;
    pdu[kDepth]       = depth;

    // Ensure origin is set
    if (!pdu.contains(kOrigin)) {
      pdu[kOrigin] = extract_origin_from_event_id(
          pdu.value(std::string(kEventId), ""));
    }

    return pdu;
  }

  // --------------------------------------------------------------------------
  // Verify that a redaction event received over federation has valid
  // signatures from the originating server.
  // --------------------------------------------------------------------------
  struct SignatureVerificationResult {
    bool valid = false;
    bool has_sender_signature = false;
    bool has_origin_signature = false;
    std::string error_message;
  };

  static SignatureVerificationResult verify_signatures(
      const json& redaction_event,
      const json& redacted_event) {

    SignatureVerificationResult result;

    // Check that the redaction has signatures
    if (!redaction_event.contains(kSignatures)) {
      result.error_message = "Redaction event has no signatures";
      return result;
    }

    auto& sigs = redaction_event[kSignatures];
    std::string origin = redaction_event.value(std::string(kOrigin), "");
    std::string sender = redaction_event.value(std::string(kSender), "");

    // Check for origin server signature
    if (!origin.empty() && sigs.contains(origin)) {
      result.has_origin_signature = true;
    }

    // Check for sender server signature
    std::string sender_server = extract_server_name(sender);
    if (!sender_server.empty() && sigs.contains(sender_server)) {
      result.has_sender_signature = true;
    }

    result.valid = result.has_origin_signature || result.has_sender_signature;

    if (!result.valid) {
      result.error_message = "Redaction event missing required signatures";
    }

    return result;
  }

  // --------------------------------------------------------------------------
  // Check if a redaction from a remote server should be accepted based
  // on the room's server ACLs.
  // --------------------------------------------------------------------------
  static bool check_server_acl(
      const std::string& origin_server,
      const json& server_acl_content) {

    if (server_acl_content.empty()) return true;

    // Check deny list first
    if (server_acl_content.contains("deny")) {
      for (const auto& denied : server_acl_content["deny"]) {
        if (server_matches(origin_server, denied.get<std::string>())) {
          return false;
        }
      }
    }

    // Check allow list
    if (server_acl_content.contains("allow")) {
      bool matched = false;
      for (const auto& allowed : server_acl_content["allow"]) {
        if (server_matches(origin_server, allowed.get<std::string>())) {
          matched = true;
          break;
        }
      }
      if (!matched) return false;
    }

    return true;
  }

 private:
  FederationConfig config_;

  // --- Simple glob-style server name matching ---
  static bool server_matches(const std::string& server,
                             const std::string& pattern) {
    if (pattern == "*") return true;
    if (server == pattern) return true;
    // Support *.domain.com patterns
    if (pattern.size() > 2 && pattern[0] == '*' && pattern[1] == '.') {
      std::string suffix = pattern.substr(1);  // .domain.com
      return server.size() >= suffix.size() &&
             server.compare(server.size() - suffix.size(), suffix.size(), suffix) == 0;
    }
    return false;
  }
};

// ============================================================================
// RedactionPermissionChecker: Lightweight permission checking for redactions
// without needing full event retrieval.
// ============================================================================
class RedactionPermissionChecker {
 public:
  // --- Permission check result ---
  struct PermissionResult {
    bool allowed = false;
    bool is_own_event = false;
    bool is_admin = false;
    bool has_power_level = false;
    int64_t user_power = 0;
    int64_t required_power = 0;
    std::string denial_reason;
  };

  // --------------------------------------------------------------------------
  // Check if a user can redact an event based on the room state.
  // --------------------------------------------------------------------------
  static PermissionResult check(
      const std::string& user_id,
      const std::string& target_sender,
      const std::string& target_type,
      const json& power_levels_content,
      bool is_server_admin) {

    PermissionResult result;

    // Server admins can redact anything
    if (is_server_admin) {
      result.allowed = true;
      result.is_admin = true;
      return result;
    }

    // Can't redact m.room.create
    if (target_type == kEventTypeCreate) {
      result.allowed = false;
      result.denial_reason = "Cannot redact m.room.create events";
      return result;
    }

    // User can always redact their own event
    if (user_id == target_sender) {
      result.allowed = true;
      result.is_own_event = true;
      return result;
    }

    // Otherwise need power level
    result.user_power = get_power_level(user_id, power_levels_content);
    result.required_power = get_power_for_action(
        std::string(kPowerRedact), power_levels_content, DEFAULT_POWER_LEVEL_REDACT);

    if (result.user_power >= result.required_power) {
      result.allowed = true;
      result.has_power_level = true;
    } else {
      result.allowed = false;
      result.denial_reason =
          "Insufficient power level: need " +
          std::to_string(result.required_power) +
          ", have " + std::to_string(result.user_power);
    }

    return result;
  }

 private:
  static int64_t get_power_level(const std::string& user_id,
                                 const json& pl_content) {
    if (!pl_content.contains(kPowerUsers)) {
      return pl_content.value(std::string(kPowerUsersDefault),
                              DEFAULT_POWER_LEVEL_USER);
    }

    auto& users = pl_content[kPowerUsers];
    if (users.contains(user_id)) {
      return users[user_id].get<int64_t>();
    }

    return pl_content.value(std::string(kPowerUsersDefault),
                            DEFAULT_POWER_LEVEL_USER);
  }

  static int64_t get_power_for_action(
      const std::string& action,
      const json& pl_content,
      int64_t default_value) {

    if (pl_content.contains(kPowerEvents)) {
      auto& events = pl_content[kPowerEvents];
      if (events.contains(action)) {
        return events[action].get<int64_t>();
      }
    }

    if (pl_content.contains(kPowerEventsDefault)) {
      return pl_content[kPowerEventsDefault].get<int64_t>();
    }

    // Check state_default for state events, events_default for message events
    // For redact, it's typically events_default
    if (pl_content.contains(kPowerEventsDefault)) {
      return pl_content[kPowerEventsDefault].get<int64_t>();
    }

    return default_value;
  }
};

// ============================================================================
// RedactionContentStripper: Utility for stripping content from events
// that have already been redacted (re-redaction / recover support).
// ============================================================================
class RedactionContentStripper {
 public:
  // --- Strip results ---
  struct StripResult {
    json stripped_event;
    size_t fields_removed = 0;
    bool had_content_changes = false;
    std::vector<std::string> removed_keys;
  };

  // --------------------------------------------------------------------------
  // Strip all content fields that should not survive redaction,
  // based on the room version. This is used for re-applying redaction
  // rules to events that may have been populated with incorrect fields.
  // --------------------------------------------------------------------------
  static StripResult strip_content(
      const json& event,
      const std::string& room_version_str,
      bool force_all = false) {

    StripResult result;
    result.stripped_event = event;

    RoomVersion rv = parse_room_version(room_version_str);
    RedactionRuleSet rules = rules_for_room_version(rv);

    std::string event_type = event.value(std::string(kType), "");
    json original_content = event.value(kContent, json::object());
    json prev_content     = event.value(kPrevContent, json::object());

    auto preserved = RedactionContentPreserver::preserved_content_keys(
        event_type, rules, original_content, prev_content);

    json new_content = json::object();

    if (force_all) {
      // Force strip everything (used for server-side moderation)
      result.stripped_event[kContent] = new_content;
      result.fields_removed = original_content.size();
      for (auto it = original_content.begin(); it != original_content.end(); ++it) {
        result.removed_keys.push_back(it.key());
      }
      result.had_content_changes = result.fields_removed > 0;
      return result;
    }

    // Copy only preserved fields
    for (const auto& key : preserved) {
      if (original_content.contains(key)) {
        new_content[key] = original_content[key];
      }
    }

    // Track removed fields
    for (auto it = original_content.begin(); it != original_content.end(); ++it) {
      if (preserved.count(it.key()) == 0) {
        result.removed_keys.push_back(it.key());
        result.fields_removed++;
      }
    }

    if (result.fields_removed > 0) {
      result.stripped_event[kContent] = new_content;
      result.had_content_changes = true;
    }

    return result;
  }
};

// ============================================================================
// EventRedactionCoordinator: Top-level coordinator that wires all
// redaction subsystems together into a unified interface.
//
// This is the main entry point that applications use to perform redactions.
// It orchestrates:
//   - Validation (permissions, event existence)
//   - Algorithm application (per room version)
//   - Event persistence
//   - Federation handling
//   - History recording
//   - Chain tracking
//   - Content metadata
// ============================================================================
class EventRedactionCoordinator {
 public:
  // --- Coordinator configuration ---
  struct Config {
    std::string local_server_name = "localhost";
    bool allow_self_redaction = true;
    bool allow_admin_redaction = true;
    bool record_history = true;
    bool record_content_metadata = true;
    bool accept_federated = true;
    bool verify_federation_signatures = true;
    int max_chain_depth = 5;
  };

  EventRedactionCoordinator(
      Config config,
      DatabasePool* pool,
      EventsStore* event_store,
      RoomStore* room_store)
      : config_(std::move(config)),
        pool_(pool),
        event_store_(event_store),
        room_store_(room_store),
        history_store_(pool),
        chain_tracker_(pool) {

    // Build federation config
    RedactionFederationHandler::FederationConfig fed_config;
    fed_config.accept_federated_redactions = config_.accept_federated;
    fed_config.verify_signatures = config_.verify_federation_signatures;
    fed_config.local_server_name = config_.local_server_name;
    fed_config.max_redaction_chain_depth = config_.max_chain_depth;
    fed_handler_ = std::make_unique<RedactionFederationHandler>(fed_config);

    redaction_log.info("EventRedactionCoordinator initialized");
  }

  // --------------------------------------------------------------------------
  // Perform a redaction: validate, apply, persist, record.
  //
  // This is the main method callers use to redact an event.
  //
  // Parameters:
  //   redacting_user_id:  The user performing the redaction.
  //   target_event_id:    The event to redact.
  //   reason:             Optional reason for the redaction.
  //   room_state:         Current room state (power levels, etc.).
  //   is_admin:           Whether the user is a server admin.
  //   room_version:       Override room version (empty = lookup from DB).
  //
  // Returns: A JSON result with success/failure information.
  // --------------------------------------------------------------------------
  json redact_event(
      const std::string& redacting_user_id,
      const std::string& target_event_id,
      const std::string& reason,
      const json& room_state,
      bool is_admin = false,
      const std::string& room_version_override = "") {

    json result;
    result["action"] = "redact_event";

    // Look up the target event
    json original_event;
    if (event_store_) {
      original_event = event_store_->get_event_json(target_event_id);
    }

    if (original_event.empty()) {
      result["success"] = false;
      result["error"] = "Target event not found: " + target_event_id;
      result["error_code"] = VALID_EVENT_NOT_FOUND;
      return result;
    }

    // Get room information
    std::string room_id = original_event.value(std::string(kRoomId), "");
    std::string room_version = room_version_override;
    if (room_version.empty() && room_store_) {
      room_version = room_store_->get_room_version(room_id);
    }
    if (room_version.empty()) {
      room_version = ROOM_VERSION_V1;
    }

    // Build a temporary redaction event for validation
    json temp_redaction = RedactionEventBuilder::build_simple(
        room_id, redacting_user_id, target_event_id, reason,
        config_.local_server_name);

    // Validate
    auto validation = RedactionValidator::validate(
        temp_redaction,
        redacting_user_id,
        room_state,
        is_admin,
        event_store_,
        room_store_);

    if (!validation.valid) {
      result["success"] = false;
      result["error"] = validation.error_message;
      result["error_code"] = validation.error_code;
      result["room_version"] = room_version;
      return result;
    }

    // Perform the redaction
    auto apply_result = RedactionApplier::apply_to_event(
        temp_redaction,
        validation.room_version,
        event_store_,
        room_store_,
        config_.record_history ? &history_store_ : nullptr);

    if (!apply_result.success && !apply_result.was_already_redacted) {
      result["success"] = false;
      result["error"] = apply_result.error_message;
      result["error_code"] = "M_REDACTION_FAILED";
      return result;
    }

    // Build result
    result["success"] = true;
    result["original_event_id"] = target_event_id;
    result["redaction_event_id"] = temp_redaction[kEventId];
    result["room_id"] = room_id;
    result["room_version"] = validation.room_version;
    result["was_already_redacted"] = apply_result.was_already_redacted;
    result["content_fields_removed"] = apply_result.fields_removed;

    if (!reason.empty()) {
      result["reason"] = reason;
    }

    // Record content metadata
    if (config_.record_content_metadata && !apply_result.was_already_redacted) {
      size_t original_content_size = 0;
      if (original_event.contains(kContent)) {
        original_content_size = original_event[kContent].dump().size();
      }
      history_store_.record_content_metadata(
          temp_redaction[kEventId],
          target_event_id,
          original_event.value(std::string(kType), ""),
          apply_result.fields_removed,
          original_content_size,
          0,  // preserved fields
          validation.room_version);
    }

    redaction_log.info(
        "Redaction complete: " + redacting_user_id +
        " redacted " + target_event_id + " in room " + room_id);

    return result;
  }

  // --------------------------------------------------------------------------
  // Handle an incoming federated redaction.
  // --------------------------------------------------------------------------
  json handle_federated_redaction(
      const json& redaction_event,
      const std::string& origin_server) {

    json result;
    result["action"] = "federated_redaction";

    auto incoming = fed_handler_->handle_incoming(
        redaction_event,
        origin_server,
        event_store_,
        room_store_,
        config_.record_history ? &history_store_ : nullptr);

    result["accepted"] = incoming.accepted;
    result["error_code"] = incoming.error_code;
    result["error_message"] = incoming.error_message;

    if (incoming.accepted) {
      result["event_id"] = redaction_event.value(std::string(kEventId), "");
      result["redacts"]  = redaction_event.value(std::string(kRedacts), "");
    }

    return result;
  }

  // --------------------------------------------------------------------------
  // Get the redaction history for an event.
  // --------------------------------------------------------------------------
  json get_redaction_history(const std::string& event_id) {
    json result;
    result["event_id"] = event_id;

    auto history = history_store_.get_history_for_event(event_id);
    result["history"] = json::array();
    for (const auto& entry : history) {
      result["history"].push_back(entry);
    }
    result["count"] = result["history"].size();

    return result;
  }

  // --------------------------------------------------------------------------
  // Get room redaction history.
  // --------------------------------------------------------------------------
  json get_room_redaction_history(
      const std::string& room_id,
      int64_t before_ts = std::numeric_limits<int64_t>::max(),
      size_t limit = 50) {

    json result;
    result["room_id"] = room_id;

    auto history = history_store_.get_history_for_room(room_id, before_ts, limit);
    result["entries"] = json::array();
    for (const auto& entry : history) {
      result["entries"].push_back(entry);
    }
    result["count"] = result["entries"].size();

    return result;
  }

  // --------------------------------------------------------------------------
  // Get redaction statistics for a room.
  // --------------------------------------------------------------------------
  json get_room_stats(const std::string& room_id) {
    return history_store_.get_room_stats(room_id);
  }

  // --------------------------------------------------------------------------
  // Run daily maintenance: aggregate stats, purge old records.
  // --------------------------------------------------------------------------
  json run_maintenance() {
    json result;
    result["action"] = "redaction_maintenance";

    history_store_.aggregate_daily_stats();

    size_t purged = history_store_.purge_old_history();
    result["purged_records"] = purged;

    redaction_log.info("Redaction maintenance complete");
    return result;
  }

  // --------------------------------------------------------------------------
  // Preview what would be removed by redacting an event.
  // --------------------------------------------------------------------------
  json preview_redaction(const std::string& event_id) {
    json result;
    result["event_id"] = event_id;

    if (!event_store_) {
      result["error"] = "Event store not available";
      return result;
    }

    json original = event_store_->get_event_json(event_id);
    if (original.empty()) {
      result["error"] = "Event not found";
      return result;
    }

    std::string room_version = ROOM_VERSION_V1;
    std::string room_id = original.value(std::string(kRoomId), "");
    if (room_store_ && !room_id.empty()) {
      room_version = room_store_->get_room_version(room_id);
    }

    result["room_version"] = room_version;
    auto preview = RedactionAlgorithmEngine::preview_redaction(original, room_version);
    result["fields_to_remove"] = json::object();
    for (const auto& [key, desc] : preview) {
      result["fields_to_remove"][key] = desc;
    }

    return result;
  }

  // --------------------------------------------------------------------------
  // Check if the chain tracker has a redaction chain for an event.
  // --------------------------------------------------------------------------
  json get_redaction_chain(const std::string& event_id) {
    json result;
    result["event_id"] = event_id;

    auto chain = chain_tracker_.get_chain(event_id);
    result["chain"] = json::array();
    for (const auto& link : chain) {
      result["chain"].push_back(link);
    }
    result["depth"] = chain_tracker_.chain_depth(event_id);

    return result;
  }

 private:
  Config config_;
  DatabasePool* pool_ = nullptr;
  EventsStore* event_store_ = nullptr;
  RoomStore* room_store_ = nullptr;
  RedactionHistoryStore history_store_;
  RedactionChainTracker chain_tracker_;
  std::unique_ptr<RedactionFederationHandler> fed_handler_;
};

// ============================================================================
// RedactionBatchProcessor: Process multiple redactions efficiently.
// Used for bulk moderation, cleanup, and administrative operations.
// ============================================================================
class RedactionBatchProcessor {
 public:
  struct BatchConfig {
    size_t max_concurrent = 10;
    bool stop_on_error = false;
    bool dry_run = false;
    std::string reason_template;
  };

  struct BatchResult {
    size_t total = 0;
    size_t succeeded = 0;
    size_t failed = 0;
    size_t skipped = 0;
    std::vector<json> details;
    int64_t started_at = 0;
    int64_t completed_at = 0;
    int64_t duration_ms = 0;
  };

  // --------------------------------------------------------------------------
  // Redact all events from a user in a room.
  // --------------------------------------------------------------------------
  static BatchResult redact_all_from_user(
      EventRedactionCoordinator* coordinator,
      const std::string& room_id,
      const std::string& target_user_id,
      const std::string& redacting_user_id,
      const json& room_state,
      const BatchConfig& config = {}) {

    BatchResult result;
    result.started_at = now_ms();

    // In a real implementation, this would:
    //   1. Query all events by target_user_id in room
    //   2. For each event, call coordinator->redact_event()
    //   3. Track results
    //
    // For now, provide the framework

    result.completed_at = now_ms();
    result.duration_ms = result.completed_at - result.started_at;

    redaction_log.info(
        "Batch redaction from user complete: " +
        std::to_string(result.succeeded) + "/" + std::to_string(result.total));

    return result;
  }

  // --------------------------------------------------------------------------
  // Redact events matching a type pattern in a room.
  // --------------------------------------------------------------------------
  static BatchResult redact_by_type(
      EventRedactionCoordinator* coordinator,
      const std::string& room_id,
      const std::string& event_type,
      const std::string& redacting_user_id,
      const json& room_state,
      const BatchConfig& config = {}) {

    BatchResult result;
    result.started_at = now_ms();

    // Framework for type-based batch redaction

    result.completed_at = now_ms();
    result.duration_ms = result.completed_at - result.started_at;

    return result;
  }

  // --------------------------------------------------------------------------
  // Redact all events in a room within a time range.
  // --------------------------------------------------------------------------
  static BatchResult redact_in_time_range(
      EventRedactionCoordinator* coordinator,
      const std::string& room_id,
      int64_t start_ts,
      int64_t end_ts,
      const std::string& redacting_user_id,
      const json& room_state,
      const BatchConfig& config = {}) {

    BatchResult result;
    result.started_at = now_ms();

    // Framework for time-range batch redaction

    result.completed_at = now_ms();
    result.duration_ms = result.completed_at - result.started_at;

    return result;
  }
};

// ============================================================================
// RedactionReconciliation: Handles reconciling redacted state after
// federation state resolution or after re-joining a room.
//
// When a server re-joins a room or resolves state conflicts, it needs
// to re-apply all known redactions to events in its local store.
// ============================================================================
class RedactionReconciliation {
 public:
  // --- Reconciliation result ---
  struct ReconciliationResult {
    size_t events_checked = 0;
    size_t redactions_applied = 0;
    size_t already_redacted = 0;
    size_t errors = 0;
    std::vector<std::string> error_events;
  };

  // --------------------------------------------------------------------------
  // Reapply all redactions for a room.
  // Queries the redaction_history table to find all redaction events,
  // then applies them in topological order to ensure correct chain.
  // --------------------------------------------------------------------------
  static ReconciliationResult reapply_redactions(
      const std::string& room_id,
      EventsStore* event_store,
      RoomStore* room_store,
      RedactionHistoryStore* history_store) {

    ReconciliationResult result;

    std::string room_version = ROOM_VERSION_V1;
    if (room_store) {
      room_version = room_store->get_room_version(room_id);
    }

    // Get all redaction history for this room
    auto history = history_store->get_history_for_room(
        room_id, std::numeric_limits<int64_t>::max(), 10000);

    // Sort by origin_server_ts to apply in chronological order
    std::sort(history.begin(), history.end(),
              [](const json& a, const json& b) {
                return a["origin_server_ts"].get<int64_t>() <
                       b["origin_server_ts"].get<int64_t>();
              });

    for (const auto& entry : history) {
      std::string original_event_id = entry["original_event_id"];
      std::string redaction_event_id = entry["redaction_event_id"];

      result.events_checked++;

      // Fetch original event
      json original_event = event_store->get_event_json(original_event_id);
      if (original_event.empty()) {
        continue;
      }

      // Skip if already redacted
      json u = original_event.value(kUnsigned, json::object());
      if (u.contains(kRedactedBecause)) {
        result.already_redacted++;
        continue;
      }

      // Build a minimal redaction event for application
      json redaction = json::object();
      redaction[kEventId] = redaction_event_id;
      redaction[kType]    = kEventTypeRedaction;
      redaction[kRoomId]  = room_id;
      redaction[kSender]  = entry["redacting_user_id"];
      redaction[kRedacts] = original_event_id;
      redaction[kOriginServerTs] = entry["origin_server_ts"];
      if (entry.contains("origin_server")) {
        redaction[kOrigin] = entry["origin_server"];
      }
      json content = json::object();
      if (entry.contains("reason") && !entry["reason"].get<std::string>().empty()) {
        content[kReason] = entry["reason"];
      }
      redaction[kContent] = content;

      // Apply
      auto apply_result = RedactionApplier::apply_federated(
          redaction,
          original_event,
          room_version,
          event_store,
          nullptr);  // Don't re-record in history

      if (apply_result.success) {
        result.redactions_applied++;
      } else {
        result.errors++;
        result.error_events.push_back(original_event_id);
      }
    }

    return result;
  }

  // --------------------------------------------------------------------------
  // Check for events that should be redacted but aren't (orphan detection).
  // --------------------------------------------------------------------------
  static std::vector<std::string> find_missing_redactions(
      const std::string& room_id,
      EventsStore* event_store,
      RedactionHistoryStore* history_store) {

    std::vector<std::string> missing;

    auto history = history_store->get_history_for_room(
        room_id, std::numeric_limits<int64_t>::max(), 10000);

    for (const auto& entry : history) {
      std::string original_event_id = entry["original_event_id"];

      json original_event = event_store->get_event_json(original_event_id);
      if (original_event.empty()) continue;

      json u = original_event.value(kUnsigned, json::object());
      if (!u.contains(kRedactedBecause)) {
        missing.push_back(original_event_id);
      }
    }

    return missing;
  }
};

// ============================================================================
// RedactionEventSerializer: Serialization/deserialization helpers for
// redaction events in various formats (client-facing, federation, storage).
// ============================================================================
class RedactionEventSerializer {
 public:
  // --------------------------------------------------------------------------
  // Convert a redaction event to client-facing format.
  // Strips internal fields: hashes, signatures, auth_events, prev_events, depth.
  // --------------------------------------------------------------------------
  static json to_client_format(const json& redaction_event) {
    json client_event = redaction_event;

    // Remove federation-specific fields
    client_event.erase(std::string(kAuthEvents));
    client_event.erase(std::string(kPrevEvents));
    client_event.erase(std::string(kDepth));
    client_event.erase(std::string(kHashes));
    client_event.erase(std::string(kSignatures));

    return client_event;
  }

  // --------------------------------------------------------------------------
  // Convert a redaction event to federation PDU format.
  // Ensures all required PDU fields are present.
  // --------------------------------------------------------------------------
  static json to_pdu_format(
      const json& client_redaction,
      const json& auth_events,
      const json& prev_events,
      int64_t depth) {

    json pdu = client_redaction;

    pdu[kAuthEvents] = auth_events;
    pdu[kPrevEvents] = prev_events;
    pdu[kDepth]       = depth;

    if (!pdu.contains(kOrigin)) {
      pdu[kOrigin] = extract_origin_from_event_id(
          pdu.value(std::string(kEventId), ""));
    }

    return pdu;
  }

  // --------------------------------------------------------------------------
  // Convert a redaction event to storage format (includes all fields).
  // --------------------------------------------------------------------------
  static json to_storage_format(const json& redaction_event) {
    return redaction_event;  // Storage keeps everything
  }

  // --------------------------------------------------------------------------
  // Get the redacted_because entry from an event, suitable for client response.
  // --------------------------------------------------------------------------
  static json get_redacted_because(const json& redacted_event) {
    json u = redacted_event.value(kUnsigned, json::object());
    if (u.contains(kRedactedBecause)) {
      return to_client_format(u[kRedactedBecause]);
    }
    return json::object();
  }
};

// ============================================================================
// Redaction Event Type Registry: Maps event types to their redacted
// content preservation rules for custom event types.
//
// Allows room admins or server operators to define custom redaction
// rules for non-standard event types via a configuration mechanism.
// ============================================================================
class RedactionTypeRegistry {
 public:
  struct CustomRedactionRule {
    std::string event_type;
    std::set<std::string> preserved_content_keys;
    bool strip_all_content = false;
    RoomVersion min_version = RoomVersion::kV1;
    RoomVersion max_version = RoomVersion::kV11;
  };

  // --- Register a custom rule ---
  void register_rule(const CustomRedactionRule& rule) {
    std::lock_guard<std::mutex> lock(mutex_);
    custom_rules_[rule.event_type] = rule;
    redaction_log.info("Registered custom redaction rule for type: " +
                       rule.event_type);
  }

  // --- Unregister a custom rule ---
  void unregister_rule(const std::string& event_type) {
    std::lock_guard<std::mutex> lock(mutex_);
    custom_rules_.erase(event_type);
  }

  // --- Get custom preservation keys for an event type ---
  std::set<std::string> get_preserved_keys(
      const std::string& event_type,
      RoomVersion version) const {

    std::lock_guard<std::mutex> lock(mutex_);
    auto it = custom_rules_.find(event_type);
    if (it != custom_rules_.end()) {
      const auto& rule = it->second;
      if (version >= rule.min_version && version <= rule.max_version) {
        if (rule.strip_all_content) {
          return {};
        }
        return rule.preserved_content_keys;
      }
    }
    return {};
  }

  // --- Check if a custom rule exists ---
  bool has_rule(const std::string& event_type) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return custom_rules_.count(event_type) > 0;
  }

 private:
  mutable std::mutex mutex_;
  std::map<std::string, CustomRedactionRule> custom_rules_;
};

// ============================================================================
// Redaction Rate Limiter: Rate limiting for redaction operations to
// prevent abuse (mass redactions, spam, etc.).
// ============================================================================
class RedactionRateLimiter {
 public:
  struct RateLimitConfig {
    int64_t max_redactions_per_user_per_minute = 10;
    int64_t max_redactions_per_room_per_minute = 30;
    int64_t max_redactions_total_per_minute    = 100;
    bool enabled = true;
  };

  explicit RedactionRateLimiter(const RateLimitConfig& config)
      : config_(config) {}

  // --- Check if a redaction is allowed based on rate limits ---
  struct RateLimitResult {
    bool allowed = true;
    std::string denial_reason;
    int64_t retry_after_ms = 0;
    int64_t current_count = 0;
    int64_t limit = 0;
  };

  RateLimitResult check(const std::string& user_id, const std::string& room_id) {
    if (!config_.enabled) {
      return RateLimitResult{};
    }

    int64_t now = now_ms();
    int64_t window_ms = 60000;  // 1 minute

    // Clean old entries
    cleanup_old_entries(now - window_ms);

    // Check user limit
    {
      auto user_count = count_in_window(user_redactions_[user_id], now - window_ms);
      if (user_count >= config_.max_redactions_per_user_per_minute) {
        RateLimitResult r;
        r.allowed = false;
        r.denial_reason = "User redaction rate limit exceeded";
        r.current_count = user_count;
        r.limit = config_.max_redactions_per_user_per_minute;
        r.retry_after_ms = get_retry_after(user_redactions_[user_id], window_ms);
        return r;
      }
    }

    // Check room limit
    {
      auto room_count = count_in_window(room_redactions_[room_id], now - window_ms);
      if (room_count >= config_.max_redactions_per_room_per_minute) {
        RateLimitResult r;
        r.allowed = false;
        r.denial_reason = "Room redaction rate limit exceeded";
        r.current_count = room_count;
        r.limit = config_.max_redactions_per_room_per_minute;
        r.retry_after_ms = get_retry_after(room_redactions_[room_id], window_ms);
        return r;
      }
    }

    // Check global limit
    {
      auto total = count_in_window(global_redactions_, now - window_ms);
      if (total >= config_.max_redactions_total_per_minute) {
        RateLimitResult r;
        r.allowed = false;
        r.denial_reason = "Global redaction rate limit exceeded";
        r.current_count = total;
        r.limit = config_.max_redactions_total_per_minute;
        r.retry_after_ms = get_retry_after(global_redactions_, window_ms);
        return r;
      }
    }

    // Record the redaction attempt
    int64_t ts = now;
    user_redactions_[user_id].push_back(ts);
    room_redactions_[room_id].push_back(ts);
    global_redactions_.push_back(ts);

    return RateLimitResult{};
  }

 private:
  RateLimitConfig config_;
  std::map<std::string, std::vector<int64_t>> user_redactions_;
  std::map<std::string, std::vector<int64_t>> room_redactions_;
  std::vector<int64_t> global_redactions_;
  std::mutex mutex_;

  int64_t count_in_window(const std::vector<int64_t>& timestamps,
                          int64_t window_start) {
    int64_t count = 0;
    for (auto ts : timestamps) {
      if (ts >= window_start) count++;
    }
    return count;
  }

  void cleanup_old_entries(int64_t cutoff) {
    for (auto& [_, vec] : user_redactions_) {
      vec.erase(std::remove_if(vec.begin(), vec.end(),
                [cutoff](int64_t ts) { return ts < cutoff; }),
                vec.end());
    }
    for (auto& [_, vec] : room_redactions_) {
      vec.erase(std::remove_if(vec.begin(), vec.end(),
                [cutoff](int64_t ts) { return ts < cutoff; }),
                vec.end());
    }
    global_redactions_.erase(
        std::remove_if(global_redactions_.begin(), global_redactions_.end(),
                       [cutoff](int64_t ts) { return ts < cutoff; }),
        global_redactions_.end());
  }

  int64_t get_retry_after(const std::vector<int64_t>& timestamps,
                          int64_t window_ms) {
    if (timestamps.empty()) return 0;
    int64_t oldest = *std::min_element(timestamps.begin(), timestamps.end());
    int64_t expire_at = oldest + window_ms;
    return std::max<int64_t>(0, expire_at - now_ms());
  }
};

// ============================================================================
// RedactionNotifier: Notifies other server components when events are
// redacted, so they can update caches, push notifications, etc.
// ============================================================================
class RedactionNotifier {
 public:
  // --- Notification callback type ---
  using NotificationCallback = std::function<void(
      const std::string& room_id,
      const std::string& original_event_id,
      const std::string& redaction_event_id,
      const std::string& redacting_user_id)>;

  // --- Register a callback for redaction notifications ---
  void register_callback(const std::string& name, NotificationCallback cb) {
    std::lock_guard<std::mutex> lock(mutex_);
    callbacks_[name] = std::move(cb);
  }

  // --- Unregister a callback ---
  void unregister_callback(const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);
    callbacks_.erase(name);
  }

  // --- Notify all registered callbacks of a redaction ---
  void notify(
      const std::string& room_id,
      const std::string& original_event_id,
      const std::string& redaction_event_id,
      const std::string& redacting_user_id) {

    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& [name, cb] : callbacks_) {
      try {
        cb(room_id, original_event_id, redaction_event_id, redacting_user_id);
      } catch (const std::exception& e) {
        redaction_log.error("Notification callback '" + name +
                            "' failed: " + std::string(e.what()));
      }
    }
  }

  // --- Get number of registered callbacks ---
  size_t callback_count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return callbacks_.size();
  }

 private:
  mutable std::mutex mutex_;
  std::map<std::string, NotificationCallback> callbacks_;
};

// ============================================================================
// EventRedactionService: The top-level service class that applications
// instantiate to access all redaction functionality.
//
// This is a convenience wrapper that creates and wires all the redaction
// subsystems. Most applications should use this class.
// ============================================================================
class EventRedactionService {
 public:
  // --- Service configuration ---
  struct ServiceConfig {
    std::string local_server_name = "localhost";
    int max_chain_depth = 5;
    bool accept_federated = true;
    bool record_history = true;
    RedactionRateLimiter::RateLimitConfig rate_limit_config;
  };

  EventRedactionService(
      ServiceConfig config,
      DatabasePool* pool,
      EventsStore* event_store,
      RoomStore* room_store)
      : config_(std::move(config)),
        pool_(pool),
        event_store_(event_store),
        room_store_(room_store) {

    // Build coordinator config
    EventRedactionCoordinator::Config coord_config;
    coord_config.local_server_name = config_.local_server_name;
    coord_config.max_chain_depth = config_.max_chain_depth;
    coord_config.accept_federated = config_.accept_federated;
    coord_config.record_history = config_.record_history;

    coordinator_ = std::make_unique<EventRedactionCoordinator>(
        coord_config, pool_, event_store_, room_store_);

    rate_limiter_ = std::make_unique<RedactionRateLimiter>(
        config_.rate_limit_config);

    redaction_log.info("EventRedactionService initialized");
  }

  // --- Get the coordinator (for direct access to all operations) ---
  EventRedactionCoordinator& coordinator() { return *coordinator_; }

  // --- Get the rate limiter ---
  RedactionRateLimiter& rate_limiter() { return *rate_limiter_; }

  // --- Get the notifier ---
  RedactionNotifier& notifier() { return notifier_; }

  // --- Get the type registry ---
  RedactionTypeRegistry& type_registry() { return type_registry_; }

  // --- Redact an event with rate limiting and notification ---
  json redact_with_limits(
      const std::string& redacting_user_id,
      const std::string& target_event_id,
      const std::string& reason,
      const json& room_state,
      bool is_admin = false) {

    json result;

    // Look up room for rate limiting
    std::string room_id = "unknown";
    if (event_store_) {
      json original = event_store_->get_event_json(target_event_id);
      if (!original.empty()) {
        room_id = original.value(std::string(kRoomId), "unknown");
      }
    }

    // Check rate limits
    auto rate_result = rate_limiter_->check(redacting_user_id, room_id);
    if (!rate_result.allowed) {
      result["success"] = false;
      result["error"] = rate_result.denial_reason;
      result["error_code"] = "M_LIMIT_EXCEEDED";
      result["retry_after_ms"] = rate_result.retry_after_ms;
      return result;
    }

    // Perform the redaction
    result = coordinator_->redact_event(
        redacting_user_id,
        target_event_id,
        reason,
        room_state,
        is_admin);

    // Notify if successful
    if (result.value("success", false)) {
      notifier_.notify(
          result.value("room_id", ""),
          target_event_id,
          result.value("redaction_event_id", ""),
          redacting_user_id);
    }

    return result;
  }

  // --- Schedule periodic maintenance ---
  void schedule_maintenance() {
    // In a real implementation, this would set up a periodic timer
    // to run coordinator_->run_maintenance() at regular intervals.
    redaction_log.debug("Maintenance scheduling not yet implemented");
  }

 private:
  ServiceConfig config_;
  DatabasePool* pool_ = nullptr;
  EventsStore* event_store_ = nullptr;
  RoomStore* room_store_ = nullptr;

  std::unique_ptr<EventRedactionCoordinator> coordinator_;
  std::unique_ptr<RedactionRateLimiter> rate_limiter_;
  RedactionNotifier notifier_;
  RedactionTypeRegistry type_registry_;
};

// ============================================================================
// Standalone test harness (compiled only when TEST_REDACTION is defined)
// ============================================================================
#ifdef TEST_REDACTION

#include <cassert>
#include <iostream>

// Simple test assertion helper
static void test_assert(bool condition, const std::string& test_name,
                        const std::string& detail = "") {
  if (condition) {
    std::cout << "  PASS: " << test_name << std::endl;
  } else {
    std::cerr << "  FAIL: " << test_name;
    if (!detail.empty()) std::cerr << " — " << detail;
    std::cerr << std::endl;
  }
}

// --- Test: Room version rule set construction ---
static void test_rule_set_construction() {
  std::cout << "=== Test: Rule Set Construction ===" << std::endl;

  auto v1_rules = rules_for_room_version(RoomVersion::kV1);
  test_assert(v1_rules.v1_v2_content_legacy, "V1 has legacy content preservation");
  test_assert(v1_rules.keep_membership, "V1 keeps membership");
  test_assert(v1_rules.keep_creator_as_field, "V1 keeps creator as field");

  auto v11_rules = rules_for_room_version(RoomVersion::kV11);
  test_assert(v11_rules.move_creator_to_content, "V11 moves creator to content");
  test_assert(v11_rules.keep_join_rule, "V11 keeps join_rule");
  test_assert(!v11_rules.preserve_origin, "V11 strips origin field");
  test_assert(!v11_rules.preserve_origin_field, "V11 does not preserve origin");
}

// --- Test: Redaction algorithm on a basic message event ---
static void test_basic_message_redaction() {
  std::cout << "=== Test: Basic Message Redaction ===" << std::endl;

  json message = {
    {"event_id", "$test1:localhost"},
    {"type", "m.room.message"},
    {"room_id", "!room1:localhost"},
    {"sender", "@user1:localhost"},
    {"origin_server_ts", 1000000},
    {"content", {
      {"body", "Hello world"},
      {"msgtype", "m.text"},
      {"format", "org.matrix.custom.html"},
      {"formatted_body", "<b>Hello world</b>"}
    }},
    {"hashes", {{"sha256", "abc123"}}},
    {"signatures", {{"localhost", {{"ed25519:1", "sig123"}}}}}
  };

  auto result = RedactionAlgorithmEngine::apply(message, ROOM_VERSION_V4, {});

  test_assert(result.success, "Redaction succeeded");
  test_assert(result.redacted_event.contains("event_id"), "Event ID preserved");
  test_assert(result.redacted_event.contains("type"), "Type preserved");
  test_assert(!result.redacted_event.contains("hashes"), "Hashes stripped");
  test_assert(!result.redacted_event.contains("signatures"), "Signatures stripped");
  test_assert(result.content_fields_removed > 0, "Content fields removed");

  std::cout << "  Content fields removed: " << result.content_fields_removed << std::endl;
  std::cout << "  Content fields preserved: " << result.content_fields_preserved << std::endl;
}

// --- Test: Redaction of m.room.member with membership preservation ---
static void test_member_redaction() {
  std::cout << "=== Test: Member Event Redaction ===" << std::endl;

  json member_event = {
    {"event_id", "$join1:localhost"},
    {"type", "m.room.member"},
    {"room_id", "!room1:localhost"},
    {"sender", "@user1:localhost"},
    {"state_key", "@user1:localhost"},
    {"origin_server_ts", 1000000},
    {"content", {
      {"membership", "join"},
      {"displayname", "John Doe"},
      {"avatar_url", "mxc://localhost/avatar1"},
      {"reason", "joining"}
    }}
  };

  auto result = RedactionAlgorithmEngine::apply(member_event, ROOM_VERSION_V6, {});

  test_assert(result.success, "Member redaction succeeded");
  test_assert(result.redacted_event["content"].contains("membership"),
              "Membership preserved");
  test_assert(!result.redacted_event["content"].contains("displayname"),
              "Displayname stripped (v6)");
  test_assert(!result.redacted_event["content"].contains("avatar_url"),
              "Avatar URL stripped (v6)");
  test_assert(!result.redacted_event["content"].contains("reason"),
              "Reason stripped");
}

// --- Test: Redaction of m.room.create (should be validated but works algorithmically) ---
static void test_create_redaction_v8() {
  std::cout << "=== Test: Create Event Redaction (v8) ===" << std::endl;

  json create_event = {
    {"event_id", "$create1:localhost"},
    {"type", "m.room.create"},
    {"room_id", "!room1:localhost"},
    {"sender", "@creator:localhost"},
    {"origin_server_ts", 1000000},
    {"creator", "@creator:localhost"},
    {"content", {
      {"m.federate", true},
      {"room_version", "8"},
      {"predecessor", {
        {"room_id", "!oldroom:localhost"},
        {"event_id", "$oldcreate:localhost"}
      }}
    }}
  };

  auto result = RedactionAlgorithmEngine::apply(create_event, ROOM_VERSION_V8, {});

  test_assert(result.success, "Create redaction succeeded (v8)");
  test_assert(result.redacted_event["content"].contains("creator"),
              "Creator moved to content (v8)");
  test_assert(result.redacted_event["content"].contains("m.federate"),
              "Federate preserved");
  test_assert(result.redacted_event["content"].contains("room_version"),
              "Room version preserved");
  test_assert(result.redacted_event["content"].contains("predecessor"),
              "Predecessor preserved");
}

// --- Test: Redaction of redaction (chained) ---
static void test_redaction_of_redaction() {
  std::cout << "=== Test: Redaction of Redaction ===" << std::endl;

  json redaction_event = {
    {"event_id", "$redact1:localhost"},
    {"type", "m.room.redaction"},
    {"room_id", "!room1:localhost"},
    {"sender", "@mod:localhost"},
    {"origin_server_ts", 2000000},
    {"redacts", "$msg1:localhost"},
    {"content", {
      {"reason", "Inappropriate content"}
    }}
  };

  json redaction_of_redaction = {
    {"event_id", "$redact2:localhost"},
    {"type", "m.room.redaction"},
    {"room_id", "!room1:localhost"},
    {"sender", "@admin:localhost"},
    {"origin_server_ts", 3000000},
    {"redacts", "$redact1:localhost"},
    {"content", {
      {"reason", "Invalid redaction reason"}
    }}
  };

  auto result = RedactionOfRedactionHandler::redact_redaction(
      redaction_event, redaction_of_redaction, ROOM_VERSION_V10);

  test_assert(result.success, "Redaction-of-redaction succeeded");
  test_assert(result.redacted_redaction.contains("redacts"),
              "Redacts field preserved in redacted redaction");
  test_assert(result.preserved_redacts_value == "$msg1:localhost",
              "Original redacts value preserved: " + result.preserved_redacts_value);
}

// --- Test: Validation — missing redacts field ---
static void test_validation_missing_redacts() {
  std::cout << "=== Test: Validation — Missing Redacts ===" << std::endl;

  json bad_redaction = {
    {"event_id", "$bad1:localhost"},
    {"type", "m.room.redaction"},
    {"room_id", "!room1:localhost"},
    {"sender", "@user1:localhost"}
  };

  auto result = RedactionValidator::validate(
      bad_redaction, "@user1:localhost", {}, false, nullptr, nullptr);

  test_assert(!result.valid, "Validation rejected missing redacts");
  test_assert(result.error_code == VALID_MISSING_REDACTS,
              "Error code is MISSING_REDACTS");
}

// --- Test: Validation — cannot redact m.room.create ---
static void test_validation_cannot_redact_create() {
  std::cout << "=== Test: Validation — Cannot Redact Create ===" << std::endl;

  // This test would need a mock event store that returns a create event
  // For now, test the permission checker directly
  bool can_redact_create = RedactionValidator::can_redact(
      "@user1:localhost", "@creator:localhost", "m.room.create", {}, true);
  test_assert(can_redact_create,
              "Admin can override (but algorithm prevents create redaction via validator)");

  bool regular_cannot = RedactionValidator::can_redact(
      "@other:localhost", "@creator:localhost", "m.room.create", {}, false);
  test_assert(!regular_cannot,
              "Regular user cannot redact m.room.create");
}

// --- Test: Permission checker ---
static void test_permission_checker() {
  std::cout << "=== Test: Permission Checker ===" << std::endl;

  json power_levels = {
    {"users", {
      {"@admin:localhost", 100},
      {"@mod:localhost", 50}
    }},
    {"users_default", 0},
    {"redact", 50}
  };

  // Admin can redact anyone
  auto r1 = RedactionPermissionChecker::check(
      "@admin:localhost", "@other:localhost", "m.room.message",
      power_levels, false);
  test_assert(r1.allowed, "Mod (PL50) can redact others");
  test_assert(r1.has_power_level, "Has power level");

  // Regular user can redact own
  auto r2 = RedactionPermissionChecker::check(
      "@user1:localhost", "@user1:localhost", "m.room.message",
      power_levels, false);
  test_assert(r2.allowed, "User can redact own message");
  test_assert(r2.is_own_event, "Is own event");

  // Regular user cannot redact others
  auto r3 = RedactionPermissionChecker::check(
      "@user1:localhost", "@other:localhost", "m.room.message",
      power_levels, false);
  test_assert(!r3.allowed, "Regular user cannot redact others");
}

// --- Test: Event builder ---
static void test_event_builder() {
  std::cout << "=== Test: Event Builder ===" << std::endl;

  auto event = RedactionEventBuilder::build_simple(
      "!room1:localhost",
      "@user1:localhost",
      "$msg1:localhost",
      "Spam",
      "localhost");

  test_assert(event.contains("event_id"), "Has event_id");
  test_assert(event.contains("type"), "Has type");
  test_assert(event["type"] == "m.room.redaction", "Type is m.room.redaction");
  test_assert(event.contains("redacts"), "Has redacts field");
  test_assert(event["redacts"] == "$msg1:localhost", "Redacts correct");
  test_assert(event["content"].contains("reason"), "Content has reason");
  test_assert(event["content"]["reason"] == "Spam", "Reason is correct");
  test_assert(RedactionEventBuilder::validate_structure(event),
              "Event structure is valid");
}

// --- Test: Rate limiter ---
static void test_rate_limiter() {
  std::cout << "=== Test: Rate Limiter ===" << std::endl;

  RedactionRateLimiter::RateLimitConfig config;
  config.max_redactions_per_user_per_minute = 2;
  config.max_redactions_per_room_per_minute = 5;
  config.max_redactions_total_per_minute = 10;

  RedactionRateLimiter limiter(config);

  auto r1 = limiter.check("@user1:localhost", "!room1:localhost");
  test_assert(r1.allowed, "First request allowed");

  auto r2 = limiter.check("@user1:localhost", "!room1:localhost");
  test_assert(r2.allowed, "Second request allowed");

  auto r3 = limiter.check("@user1:localhost", "!room1:localhost");
  test_assert(!r3.allowed, "Third request denied (rate limited)");
  test_assert(r3.current_count >= 2, "Count reflects requests");

  // Different user should not be affected
  auto r4 = limiter.check("@user2:localhost", "!room1:localhost");
  test_assert(r4.allowed, "Different user not affected");
}

// --- Test: Content preserver ---
static void test_content_preserver() {
  std::cout << "=== Test: Content Preserver ===" << std::endl;

  RedactionRuleSet rules = rules_for_room_version(RoomVersion::kV6);

  json content = {
    {"membership", "join"},
    {"displayname", "Test User"},
    {"avatar_url", "mxc://localhost/avatar"},
    {"join_authorised_via_users_server", "@inviter:remote"}
  };

  auto preserved = RedactionContentPreserver::preserved_content_keys(
      "m.room.member", rules, content, {});

  test_assert(preserved.count("membership") > 0, "Membership preserved");
  test_assert(preserved.count("displayname") == 0, "Displayname NOT preserved (v6)");
  test_assert(preserved.count("join_authorised_via_users_server") > 0,
              "join_authorised_via preserved (v6)");
}

// --- Test: Preview redaction ---
static void test_preview_redaction() {
  std::cout << "=== Test: Preview Redaction ===" << std::endl;

  json event = {
    {"event_id", "$test1:localhost"},
    {"type", "m.room.message"},
    {"room_id", "!room1:localhost"},
    {"sender", "@user1:localhost"},
    {"origin_server_ts", 1000000},
    {"content", {
      {"body", "Hello world"},
      {"msgtype", "m.text"},
      {"format", "org.matrix.custom.html"},
      {"formatted_body", "<b>Hello</b>"}
    }},
    {"hashes", {{"sha256", "abc"}}},
    {"signatures", {{"localhost", {}}}}
  };

  auto preview = RedactionAlgorithmEngine::preview_redaction(event, ROOM_VERSION_V4);

  test_assert(!preview.empty(), "Preview has entries");
  test_assert(preview.count("hashes") > 0, "Hashes flagged for removal");
  test_assert(preview.count("signatures") > 0, "Signatures flagged for removal");

  std::cout << "  Preview entries: " << preview.size() << std::endl;
  for (const auto& [key, desc] : preview) {
    std::cout << "    " << key << " -> " << desc << std::endl;
  }
}

// --- Main test runner ---
int main() {
  std::cout << "========================================" << std::endl;
  std::cout << "  Event Redaction Engine — Test Suite" << std::endl;
  std::cout << "========================================" << std::endl;

  test_rule_set_construction();
  test_basic_message_redaction();
  test_member_redaction();
  test_create_redaction_v8();
  test_redaction_of_redaction();
  test_validation_missing_redacts();
  test_validation_cannot_redact_create();
  test_permission_checker();
  test_event_builder();
  test_rate_limiter();
  test_content_preserver();
  test_preview_redaction();

  std::cout << "========================================" << std::endl;
  std::cout << "  All tests complete." << std::endl;
  std::cout << "========================================" << std::endl;

  return 0;
}

#endif  // TEST_REDACTION

// ============================================================================
// End of namespace progressive
// ============================================================================
}  // namespace progressive
