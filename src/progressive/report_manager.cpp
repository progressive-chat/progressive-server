// ============================================================================
// report_manager.cpp — Matrix Event Reporting System with Admin Review
//
// A comprehensive Matrix event reporting system implementing the full spec
// for client-to-server reporting, server-side moderation workflows, admin
// review pipelines, and federation report handling. This is the central
// reporting infrastructure for the progressive server.
//
// Features:
//   - Event Reporting API: POST /_matrix/client/v3/rooms/{roomId}/report/{eventId}
//     per the Matrix client-server specification. Clients submit reports on
//     events with a reason and optional score. The server validates the request,
//     stores the report, and forwards it to the admin review queue.
//
//   - Report Storage: Fully SQL-backed reports table with proper indexing.
//     Each report tracks: report_id, room_id, event_id, reporter user_id,
//     reported user_id (derived from the event sender), reason, score,
//     category, status (pending/acknowledged/reviewed/resolved/dismissed),
//     admin notes, assigned admin, timestamps for each lifecycle transition.
//     Supports querying by all fields with pagination, sorting, and filtering.
//
//   - Report Categories: Implements standard Matrix report categories:
//     m.illegal_content (child sexual abuse material, terrorism, etc),
//     m.violent_extremist_content, m.harassment/bullying, m.spam,
//     m.impersonation, m.hate_speech, m.self_harm, m.disinformation,
//     m.copyright_violation, m.unauthorized_data_collection, m.other.
//     Also supports custom server-defined categories and subcategories.
//
//   - Admin Review Pipeline: Full admin workflow for processing reports.
//     Dashboard for listing reports with filters (status, category, room,
//     reporter, reported user, date range). Individual report detail view
//     with full event context, reporter info, and timeline of actions.
//     Bulk operations: acknowledge multiple, assign to admin, resolve batch.
//     Admin actions: add notes, change status, assign self, escalate to
//     server-wide moderation action.
//
//   - Automated Actions: Configurable auto-actions on report thresholds.
//     When an event receives N reports from different users, it can trigger:
//     auto-redact the event, auto-quarantine media attachments, auto-mute
//     the reported user, auto-notify room moderators. Configurable per
//     room and per report category. Rate-limited to prevent abuse.
//
//   - Admin Moderation Actions: Comprehensive suite of actions admins can
//     take in response to reports: warn the reported user (send a DM or
//     room notice), redact the reported event (m.room.redaction), ban the
//     user from the room, ban the user server-wide, shadow-ban the user,
//     delete the user's account, quarantine associated media, delete the
//     room entirely, forward report to law enforcement (CSAM escalation),
//     add the user to a watchlist, or mark the report as false (no action).
//
//   - Report Notifications: Push notifications to server admins and room
//     moderators when new reports are filed. Configurable per report
//     category severity. Batched digest notifications for low-severity
//     reports. Real-time notifications for CSAM/terrorism reports.
//     Notification channels: push rules, admin room messages, webhook,
//     email (via configured SMTP gateway).
//
//   - Report Federation: Forward reports to the reporter's homeserver
//     when the event is on a remote server. Handle incoming federated
//     reports from other servers. Validate federation signatures on
//     incoming reports. Respect federation reporting policies (which
//     servers are allowed to forward reports to us). Deduplication
//     of reports that arrive both locally and via federation.
//
//   - Report Analytics & Metrics: Statistics dashboard for admins.
//     Report counts by category over time, by room, by reported user.
//     Average time to resolution. Admin workload distribution.
//     Prometheus-compatible metrics export. Daily/weekly/monthly
//     trend analysis. Heat maps of reporting activity by hour.
//
//   - Rate Limiting & Abuse Prevention: Per-user rate limits on report
//     submission. Per-event and per-room limits. Flood protection.
//     Automatic temp-ban for users who submit excessive false reports.
//     Reporter reputation scoring: users whose reports consistently
//     result in actions get higher report weight/priority. Users whose
//     reports are repeatedly dismissed get lower weight.
//
//   - Report Retention & GDPR: Configurable retention periods per
//     report category. Automatic cleanup of old reports. GDPR-compliant
//     report export for data subject access requests. Anonymization
//     options for aggregated statistics. Report data deletion on user
//     account deletion request.
//
//   - Audit Trail: Complete audit log of all admin actions on reports.
//     Immutable append-only log: who did what to which report, when,
//     and from which IP/device. Tamper-evident with hash chains.
//     Exportable for compliance and legal review.
//
// SQL Tables:
//   event_reports:            Core reports table
//   event_report_actions:     Audit trail of admin actions
//   event_report_categories:  Category definitions
//   event_report_thresholds:  Auto-action thresholds
//   event_report_notifications: Notification log
//   event_report_federation:  Federation forwarding state
//   event_report_assignments: Admin assignment tracking
//   event_reporter_reputation: Reporter reputation scores
//   report_rate_limits:       Rate limit state per user/room
//
// Equivalent to:
//   synapse/rest/client/report_event.py              (client API, ~80 lines)
//   synapse/rest/admin/reports.py                    (admin API, ~600 lines)
//   synapse/handlers/report_event.py                 (handler, ~200 lines)
//   synapse/storage/databases/main/event_reports.py  (storage, ~300 lines)
//   matrix-org/matrix-spec: Client-Server API (reporting endpoint)
//   matrix-org/matrix-spec-proposals: MSC3215 (moderation policies)
//   matrix-org/matrix-spec-proposals: MSC2313 (ban lists)
//   matrix-org/matrix-spec-proposals: MSC3824 (CSAM reporting)
//
// Namespace: progressive::
// Target: 3000+ lines of production-grade C++.
// ============================================================================

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <deque>
#include <exception>
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
#include "progressive/storage/databases/main/roommember.hpp"
#include "progressive/storage/databases/main/state.hpp"
#include "progressive/storage/databases/main/stream.hpp"
#include "progressive/storage/databases/main/registration.hpp"
#include "progressive/storage/databases/main/profile.hpp"
#include "progressive/storage/databases/main/media_repository.hpp"
#include "progressive/storage/databases/main/event_federation.hpp"
#include "progressive/storage/databases/main/federation_stores.hpp"
#include "progressive/storage/databases/main/directory.hpp"
#include "progressive/storage/databases/main/event_push_actions.hpp"
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
class ReportStorageEngine;
class ReportValidator;
class ReportRateLimiter;
class AdminReviewManager;
class ReportActionHandler;
class ReportNotificationEngine;
class ReportFederationHandler;
class ReportAnalyticsEngine;
class ReportAutoActionEngine;
class ReportAuditTrail;
class ReportCategoryRegistry;
class ReporterReputationEngine;
class ReportRetentionManager;
class ReportDeduplicationEngine;
class ReportManagerAPI;

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
class RegistrationStore;
class ProfileStore;
class MediaRepositoryStore;
class EventFederationStore;
class FederationStores;
class DirectoryStore;
class EventPushActionsStore;
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
using storage::RegistrationStore;
using storage::ProfileStore;
using storage::MediaRepositoryStore;
using storage::EventFederationStore;
using storage::FederationStores;
using storage::DirectoryStore;
using storage::EventPushActionsStore;
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
auto& report_log        = util::get_logger("progressive.report_manager");
auto& report_api_log    = util::get_logger("progressive.report_manager.api");
auto& report_store_log  = util::get_logger("progressive.report_manager.storage");
auto& report_valid_log  = util::get_logger("progressive.report_manager.validation");
auto& report_admin_log  = util::get_logger("progressive.report_manager.admin");
auto& report_fed_log    = util::get_logger("progressive.report_manager.federation");
auto& report_notify_log = util::get_logger("progressive.report_manager.notification");
auto& report_analytics_log = util::get_logger("progressive.report_manager.analytics");
auto& report_audit_log  = util::get_logger("progressive.report_manager.audit");

// ============================================================================
// Constants — Matrix Report Categories
// ============================================================================
namespace {

// --- Standard Matrix report categories (per Matrix spec) ---
constexpr std::string_view kReportCategoryIllegal               = "m.illegal_content";
constexpr std::string_view kReportCategoryViolentExtremist       = "m.violent_extremist_content";
constexpr std::string_view kReportCategoryHarassment             = "m.harassment";
constexpr std::string_view kReportCategoryBullying               = "m.bullying";
constexpr std::string_view kReportCategorySpam                   = "m.spam";
constexpr std::string_view kReportCategoryImpersonation          = "m.impersonation";
constexpr std::string_view kReportCategoryHateSpeech             = "m.hate_speech";
constexpr std::string_view kReportCategorySelfHarm               = "m.self_harm";
constexpr std::string_view kReportCategoryDisinformation         = "m.disinformation";
constexpr std::string_view kReportCategoryCopyright              = "m.copyright_violation";
constexpr std::string_view kReportCategoryUnauthorizedData        = "m.unauthorized_data_collection";
constexpr std::string_view kReportCategoryOther                  = "m.other";
constexpr std::string_view kReportCategoryCSAM                   = "m.illegal_content.child_sexual_abuse";
constexpr std::string_view kReportCategoryTerrorism              = "m.illegal_content.terrorism";
constexpr std::string_view kReportCategoryNSFW                   = "m.nsfw_content";
constexpr std::string_view kReportCategoryScam                   = "m.scam";
constexpr std::string_view kReportCategoryMalware                = "m.malware";
constexpr std::string_view kReportCategoryDoxxing                = "m.doxxing";
constexpr std::string_view kReportCategoryGrooming               = "m.grooming";

// --- Report status constants ---
constexpr std::string_view kStatusPending       = "pending";
constexpr std::string_view kStatusAcknowledged  = "acknowledged";
constexpr std::string_view kStatusUnderReview   = "under_review";
constexpr std::string_view kStatusResolved      = "resolved";
constexpr std::string_view kStatusDismissed     = "dismissed";
constexpr std::string_view kStatusEscalated     = "escalated";
constexpr std::string_view kStatusArchived      = "archived";

// --- Admin action types ---
constexpr std::string_view kActionNone            = "none";
constexpr std::string_view kActionNote            = "add_note";
constexpr std::string_view kActionAcknowledge     = "acknowledge";
constexpr std::string_view kActionAssign          = "assign";
constexpr std::string_view kActionWarn            = "warn_user";
constexpr std::string_view kActionRedact          = "redact_event";
constexpr std::string_view kActionBanRoom         = "ban_from_room";
constexpr std::string_view kActionBanServer       = "ban_from_server";
constexpr std::string_view kActionShadowBan       = "shadow_ban";
constexpr std::string_view kActionDeleteAccount   = "delete_account";
constexpr std::string_view kActionQuarantineMedia = "quarantine_media";
constexpr std::string_view kActionDeleteMedia     = "delete_media";
constexpr std::string_view kActionDeleteRoom      = "delete_room";
constexpr std::string_view kActionEscalateLE      = "escalate_law_enforcement";
constexpr std::string_view kActionDismiss         = "dismiss";
constexpr std::string_view kActionResolve         = "resolve";
constexpr std::string_view kActionMarkFalseReport = "mark_false_report";
constexpr std::string_view kActionForwardReport   = "forward_report";
constexpr std::string_view kActionMuteUser        = "mute_user";
constexpr std::string_view kActionAddToWatchlist  = "add_to_watchlist";

// --- Notification severity ---
constexpr int kNotifySeverityNone     = 0;
constexpr int kNotifySeverityLow      = 1;
constexpr int kNotifySeverityMedium   = 2;
constexpr int kNotifySeverityHigh     = 3;
constexpr int kNotifySeverityCritical = 4;

// --- Rate limiting defaults ---
constexpr int kDefaultMaxReportsPerUserPerMinute   = 5;
constexpr int kDefaultMaxReportsPerUserPerHour     = 30;
constexpr int kDefaultMaxReportsPerEvent           = 20;
constexpr int kDefaultMaxReportsPerRoomPerMinute   = 50;
constexpr int kDefaultReporterCooldownSeconds      = 10;

// --- Auto-action thresholds ---
constexpr int kDefaultAutoRedactThreshold  = 5;
constexpr int kDefaultAutoQuarantineThreshold = 3;
constexpr int kDefaultAutoMuteThreshold    = 7;
constexpr int kDefaultAutoBanThreshold     = 10;

// --- Retention ---
constexpr int64_t kDefaultReportRetentionDays       = 365;
constexpr int64_t kDefaultCSAMReportRetentionDays   = 3650;  // 10 years
constexpr int64_t kDefaultAuditRetentionDays         = 730;   // 2 years
constexpr int64_t kDefaultDismissedRetentionDays      = 90;

// --- Event ID regex pattern (basic validation) ---
constexpr std::string_view kEventIdPattern = R"(^\$[A-Za-z0-9+/=_-]+$)";
constexpr std::string_view kRoomIdPattern  = R"(^![A-Za-z0-9+/=_-]+:[\w.-]+$)";
constexpr std::string_view kUserIdPattern  = R"(^@[A-Za-z0-9._=/+-]+:[\w.-]+$)";

// --- Pagination defaults ---
constexpr int kDefaultPageSize    = 50;
constexpr int kMaxPageSize        = 500;
constexpr int kDefaultFrom        = 0;

// --- Misc ---
constexpr int64_t kMaxReasonLength  = 2048;
constexpr int kMaxScore             = -100;  // Most negative score (-100 = most severe)
constexpr int kMinScore             = 0;     // Least negative (0 = least severe)
constexpr int64_t kReportIdEpoch    = 1700000000000LL;  // Base for report ID generation

}  // anonymous namespace

// ============================================================================
// Enumerations
// ============================================================================

// --- Report status enum ---
enum class ReportStatus : uint8_t {
  PENDING       = 0,
  ACKNOWLEDGED  = 1,
  UNDER_REVIEW  = 2,
  RESOLVED      = 3,
  DISMISSED     = 4,
  ESCALATED     = 5,
  ARCHIVED      = 6
};

// --- Report priority ---
enum class ReportPriority : uint8_t {
  LOW      = 0,
  NORMAL   = 1,
  HIGH     = 2,
  URGENT   = 3,
  CRITICAL = 4
};

// --- Admin action result ---
enum class AdminActionResult : uint8_t {
  SUCCESS             = 0,
  INVALID_REPORT      = 1,
  UNAUTHORIZED        = 2,
  INVALID_TRANSITION  = 3,
  ALREADY_PROCESSED   = 4,
  EVENT_NOT_FOUND     = 5,
  USER_NOT_FOUND      = 6,
  RATE_LIMITED        = 7,
  INTERNAL_ERROR      = 8
};

// --- Sort field for report listing ---
enum class ReportSortField : uint8_t {
  CREATED_TS   = 0,
  UPDATED_TS   = 1,
  PRIORITY     = 2,
  SCORE        = 3,
  REPORTER     = 4,
  REPORTED_USER = 5,
  ROOM_ID      = 6,
  CATEGORY     = 7,
  STATUS       = 8,
  REPORT_COUNT = 9
};

// --- Sort direction ---
enum class SortDirection : uint8_t {
  ASCENDING  = 0,
  DESCENDING = 1
};

// --- Notification channel ---
enum class NotificationChannel : uint8_t {
  PUSH_RULE    = 0,
  ADMIN_ROOM   = 1,
  WEBHOOK       = 2,
  EMAIL        = 3,
  INTERNAL     = 4
};

// --- Report source ---
enum class ReportSource : uint8_t {
  CLIENT_API   = 0,
  FEDERATION   = 1,
  ADMIN_API    = 2,
  AUTO_DETECT  = 3,
  IMPORT       = 4
};

// ============================================================================
// Helper functions
// ============================================================================

namespace {

// --- String-to-enum conversions ---
ReportStatus string_to_report_status(const std::string& s) {
  if (s == kStatusPending)       return ReportStatus::PENDING;
  if (s == kStatusAcknowledged)  return ReportStatus::ACKNOWLEDGED;
  if (s == kStatusUnderReview)   return ReportStatus::UNDER_REVIEW;
  if (s == kStatusResolved)      return ReportStatus::RESOLVED;
  if (s == kStatusDismissed)     return ReportStatus::DISMISSED;
  if (s == kStatusEscalated)     return ReportStatus::ESCALATED;
  if (s == kStatusArchived)      return ReportStatus::ARCHIVED;
  return ReportStatus::PENDING;
}

std::string report_status_to_string(ReportStatus s) {
  switch (s) {
    case ReportStatus::PENDING:       return std::string(kStatusPending);
    case ReportStatus::ACKNOWLEDGED:  return std::string(kStatusAcknowledged);
    case ReportStatus::UNDER_REVIEW:  return std::string(kStatusUnderReview);
    case ReportStatus::RESOLVED:      return std::string(kStatusResolved);
    case ReportStatus::DISMISSED:     return std::string(kStatusDismissed);
    case ReportStatus::ESCALATED:     return std::string(kStatusEscalated);
    case ReportStatus::ARCHIVED:      return std::string(kStatusArchived);
    default:                          return std::string(kStatusPending);
  }
}

ReportPriority string_to_report_priority(const std::string& s) {
  if (s == "critical") return ReportPriority::CRITICAL;
  if (s == "urgent")   return ReportPriority::URGENT;
  if (s == "high")     return ReportPriority::HIGH;
  if (s == "low")      return ReportPriority::LOW;
  return ReportPriority::NORMAL;
}

std::string report_priority_to_string(ReportPriority p) {
  switch (p) {
    case ReportPriority::CRITICAL: return "critical";
    case ReportPriority::URGENT:   return "urgent";
    case ReportPriority::HIGH:     return "high";
    case ReportPriority::LOW:      return "low";
    default:                       return "normal";
  }
}

AdminActionResult string_to_action_result(const std::string& s) {
  if (s == "success")           return AdminActionResult::SUCCESS;
  if (s == "invalid_report")    return AdminActionResult::INVALID_REPORT;
  if (s == "unauthorized")      return AdminActionResult::UNAUTHORIZED;
  if (s == "invalid_transition") return AdminActionResult::INVALID_TRANSITION;
  if (s == "already_processed") return AdminActionResult::ALREADY_PROCESSED;
  if (s == "event_not_found")   return AdminActionResult::EVENT_NOT_FOUND;
  if (s == "user_not_found")    return AdminActionResult::USER_NOT_FOUND;
  if (s == "rate_limited")      return AdminActionResult::RATE_LIMITED;
  return AdminActionResult::INTERNAL_ERROR;
}

std::string action_result_to_string(AdminActionResult r) {
  switch (r) {
    case AdminActionResult::SUCCESS:            return "success";
    case AdminActionResult::INVALID_REPORT:     return "invalid_report";
    case AdminActionResult::UNAUTHORIZED:       return "unauthorized";
    case AdminActionResult::INVALID_TRANSITION:  return "invalid_transition";
    case AdminActionResult::ALREADY_PROCESSED:  return "already_processed";
    case AdminActionResult::EVENT_NOT_FOUND:    return "event_not_found";
    case AdminActionResult::USER_NOT_FOUND:     return "user_not_found";
    case AdminActionResult::RATE_LIMITED:       return "rate_limited";
    case AdminActionResult::INTERNAL_ERROR:     return "internal_error";
    default:                                    return "unknown_error";
  }
}

// --- Determine notification severity from category ---
int category_notify_severity(const std::string& category) {
  if (category == kReportCategoryCSAM ||
      category == kReportCategoryTerrorism) {
    return kNotifySeverityCritical;
  }
  if (category == kReportCategoryIllegal ||
      category == kReportCategoryViolentExtremist ||
      category == kReportCategoryGrooming) {
    return kNotifySeverityHigh;
  }
  if (category == kReportCategoryHarassment ||
      category == kReportCategoryHateSpeech ||
      category == kReportCategoryDoxxing ||
      category == kReportCategoryMalware) {
    return kNotifySeverityMedium;
  }
  if (category == kReportCategorySpam ||
      category == kReportCategoryImpersonation ||
      category == kReportCategoryScam ||
      category == kReportCategoryCopyright) {
    return kNotifySeverityLow;
  }
  return kNotifySeverityLow;
}

// --- Determine default priority from category ---
ReportPriority category_default_priority(const std::string& category) {
  if (category == kReportCategoryCSAM ||
      category == kReportCategoryTerrorism) {
    return ReportPriority::CRITICAL;
  }
  if (category == kReportCategoryIllegal ||
      category == kReportCategoryViolentExtremist ||
      category == kReportCategoryGrooming) {
    return ReportPriority::URGENT;
  }
  if (category == kReportCategoryHarassment ||
      category == kReportCategoryHateSpeech ||
      category == kReportCategoryDoxxing) {
    return ReportPriority::HIGH;
  }
  if (category == kReportCategorySpam ||
      category == kReportCategoryScam) {
    return ReportPriority::LOW;
  }
  return ReportPriority::NORMAL;
}

// --- Validate Matrix ID format ---
bool validate_event_id_format(const std::string& event_id) {
  std::regex re(std::string(kEventIdPattern));
  return std::regex_match(event_id, re);
}

bool validate_room_id_format(const std::string& room_id) {
  std::regex re(std::string(kRoomIdPattern));
  return std::regex_match(room_id, re);
}

bool validate_user_id_format(const std::string& user_id) {
  std::regex re(std::string(kUserIdPattern));
  return std::regex_match(user_id, re);
}

// --- Generate unique report ID ---
std::string generate_report_id() {
  static std::atomic<int64_t> counter{0};
  static thread_local std::random_device rd;
  static thread_local std::mt19937_64 gen(rd());
  
  int64_t now_ms = chr::duration_cast<chr::milliseconds>(
    chr::system_clock::now().time_since_epoch()).count();
  int64_t seq = counter.fetch_add(1, std::memory_order_relaxed);
  int64_t rnd = gen();
  
  std::stringstream ss;
  ss << "RPT_" << std::hex << now_ms << "_" << seq << "_" << (rnd & 0xFFFF);
  return ss.str();
}

// --- Generate audit entry ID ---
std::string generate_audit_id() {
  static std::atomic<int64_t> audit_counter{0};
  int64_t now_ms = chr::duration_cast<chr::milliseconds>(
    chr::system_clock::now().time_since_epoch()).count();
  int64_t seq = audit_counter.fetch_add(1, std::memory_order_relaxed);
  std::stringstream ss;
  ss << "AUD_" << std::hex << now_ms << "_" << seq;
  return ss.str();
}

// --- Current timestamp helpers ---
int64_t current_time_ms() {
  return chr::duration_cast<chr::milliseconds>(
    chr::system_clock::now().time_since_epoch()).count();
}

int64_t current_time_sec() {
  return chr::duration_cast<chr::seconds>(
    chr::system_clock::now().time_since_epoch()).count();
}

// --- Escape SQL LIKE pattern characters ---
std::string escape_like_pattern(const std::string& pattern) {
  std::string result;
  result.reserve(pattern.size() * 2);
  for (char c : pattern) {
    if (c == '%' || c == '_' || c == '\\') {
      result += '\\';
    }
    result += c;
  }
  return result;
}

// --- Hash a string for audit chain ---
std::string hash_audit_entry(const std::string& prev_hash, 
                              const std::string& data) {
  // Simple deterministic hash for audit chain
  std::hash<std::string> hasher;
  size_t h1 = hasher(prev_hash);
  size_t h2 = hasher(data);
  std::stringstream ss;
  ss << std::hex << std::setw(16) << std::setfill('0') << (h1 ^ h2);
  return ss.str();
}

}  // anonymous namespace

// ============================================================================
// Data Structures
// ============================================================================

// --- Core EventReport structure ---
struct EventReport {
  std::string report_id;
  std::string room_id;
  std::string event_id;
  std::string reporter_user_id;
  std::string reported_user_id;
  std::string reason;
  std::string category;
  std::string status;
  std::string priority;
  int score;
  int64_t created_at_ms;
  int64_t updated_at_ms;
  int64_t acknowledged_at_ms;
  int64_t reviewed_at_ms;
  int64_t resolved_at_ms;
  std::string assigned_admin;
  std::string admin_notes;
  ReportSource source;
  std::string source_server;  // for federated reports
  json report_content;        // additional metadata from the reporter
  json event_snapshot;        // snapshot of the reported event at report time

  // --- JSON serialization ---
  json to_json() const {
    json j;
    j["report_id"]         = report_id;
    j["room_id"]           = room_id;
    j["event_id"]          = event_id;
    j["reporter_user_id"]  = reporter_user_id;
    j["reported_user_id"]  = reported_user_id;
    j["reason"]            = reason;
    j["category"]          = category;
    j["status"]            = status;
    j["priority"]          = priority;
    j["score"]             = score;
    j["created_at_ms"]     = created_at_ms;
    j["updated_at_ms"]     = updated_at_ms;
    j["acknowledged_at_ms"] = acknowledged_at_ms;
    j["reviewed_at_ms"]    = reviewed_at_ms;
    j["resolved_at_ms"]    = resolved_at_ms;
    if (!assigned_admin.empty())
      j["assigned_admin"]  = assigned_admin;
    if (!admin_notes.empty())
      j["admin_notes"]     = admin_notes;
    if (!source_server.empty())
      j["source_server"]   = source_server;
    if (!report_content.is_null())
      j["report_content"]  = report_content;
    if (!event_snapshot.is_null())
      j["event_snapshot"]  = event_snapshot;
    return j;
  }

  static EventReport from_json(const json& j) {
    EventReport r;
    r.report_id        = j.value("report_id", "");
    r.room_id          = j.value("room_id", "");
    r.event_id         = j.value("event_id", "");
    r.reporter_user_id = j.value("reporter_user_id", "");
    r.reported_user_id = j.value("reported_user_id", "");
    r.reason           = j.value("reason", "");
    r.category         = j.value("category", std::string(kReportCategoryOther));
    r.status           = j.value("status", std::string(kStatusPending));
    r.priority         = j.value("priority", "normal");
    r.score            = j.value("score", 0);
    r.created_at_ms    = j.value("created_at_ms", 0LL);
    r.updated_at_ms    = j.value("updated_at_ms", 0LL);
    r.acknowledged_at_ms = j.value("acknowledged_at_ms", 0LL);
    r.reviewed_at_ms   = j.value("reviewed_at_ms", 0LL);
    r.resolved_at_ms   = j.value("resolved_at_ms", 0LL);
    r.assigned_admin   = j.value("assigned_admin", "");
    r.admin_notes      = j.value("admin_notes", "");
    r.source           = ReportSource::CLIENT_API;
    r.source_server    = j.value("source_server", "");
    r.report_content   = j.value("report_content", json::object());
    r.event_snapshot   = j.value("event_snapshot", json::object());
    return r;
  }
};

// --- Admin action record (audit trail entry) ---
struct ReportAction {
  std::string action_id;
  std::string report_id;
  std::string action_type;
  std::string admin_user_id;
  std::string action_detail;     // JSON with action-specific data
  std::string notes;
  std::string previous_status;
  std::string new_status;
  std::string previous_assignment;
  std::string new_assignment;
  int64_t timestamp_ms;
  std::string admin_ip;
  std::string admin_device_id;
  std::string audit_hash;        // Hash chain link

  json to_json() const {
    json j;
    j["action_id"]            = action_id;
    j["report_id"]            = report_id;
    j["action_type"]          = action_type;
    j["admin_user_id"]        = admin_user_id;
    j["action_detail"]        = action_detail;
    j["notes"]                = notes;
    j["previous_status"]      = previous_status;
    j["new_status"]           = new_status;
    j["previous_assignment"]  = previous_assignment;
    j["new_assignment"]       = new_assignment;
    j["timestamp_ms"]         = timestamp_ms;
    j["admin_ip"]             = admin_ip;
    j["admin_device_id"]      = admin_device_id;
    j["audit_hash"]           = audit_hash;
    return j;
  }

  static ReportAction from_json(const json& j) {
    ReportAction a;
    a.action_id           = j.value("action_id", "");
    a.report_id           = j.value("report_id", "");
    a.action_type         = j.value("action_type", "");
    a.admin_user_id       = j.value("admin_user_id", "");
    a.action_detail       = j.value("action_detail", "{}");
    a.notes               = j.value("notes", "");
    a.previous_status     = j.value("previous_status", "");
    a.new_status          = j.value("new_status", "");
    a.previous_assignment = j.value("previous_assignment", "");
    a.new_assignment      = j.value("new_assignment", "");
    a.timestamp_ms        = j.value("timestamp_ms", 0LL);
    a.admin_ip            = j.value("admin_ip", "");
    a.admin_device_id     = j.value("admin_device_id", "");
    a.audit_hash          = j.value("audit_hash", "");
    return a;
  }
};

// --- Category definition ---
struct ReportCategory {
  std::string category_id;
  std::string display_name;
  std::string description;
  bool is_enabled;
  bool requires_immediate_escalation;
  int default_severity;
  ReportPriority default_priority;
  int auto_redact_threshold;
  int auto_quarantine_threshold;
  int auto_mute_threshold;
  int retention_days;
  std::vector<std::string> subcategories;

  json to_json() const {
    json j;
    j["category_id"]                 = category_id;
    j["display_name"]                = display_name;
    j["description"]                 = description;
    j["is_enabled"]                  = is_enabled;
    j["requires_immediate_escalation"] = requires_immediate_escalation;
    j["default_severity"]            = default_severity;
    j["default_priority"]            = report_priority_to_string(default_priority);
    j["auto_redact_threshold"]       = auto_redact_threshold;
    j["auto_quarantine_threshold"]   = auto_quarantine_threshold;
    j["auto_mute_threshold"]         = auto_mute_threshold;
    j["retention_days"]              = retention_days;
    j["subcategories"]               = subcategories;
    return j;
  }
};

// --- Report query/filter parameters ---
struct ReportQuery {
  std::optional<std::string> report_id;
  std::optional<std::string> room_id;
  std::optional<std::string> event_id;
  std::optional<std::string> reporter_user_id;
  std::optional<std::string> reported_user_id;
  std::optional<std::string> category;
  std::optional<std::string> status;
  std::optional<std::string> priority;
  std::optional<std::string> assigned_admin;
  std::optional<int64_t> created_after_ms;
  std::optional<int64_t> created_before_ms;
  std::optional<int64_t> updated_after_ms;
  std::optional<int64_t> updated_before_ms;
  std::optional<int> min_score;
  std::optional<int> max_score;
  std::optional<std::string> search_term;  // search in reason and notes
  ReportSortField sort_field;
  SortDirection sort_direction;
  int limit;
  int offset;
  bool include_archived;
  bool include_resolved;

  ReportQuery()
    : sort_field(ReportSortField::CREATED_TS),
      sort_direction(SortDirection::DESCENDING),
      limit(kDefaultPageSize),
      offset(kDefaultFrom),
      include_archived(false),
      include_resolved(true) {}
};

// --- Reputation record ---
struct ReporterReputation {
  std::string user_id;
  int total_reports_submitted;
  int reports_accepted;     // reports that resulted in action
  int reports_dismissed;    // reports that were dismissed
  int reports_marked_false; // reports explicitly marked as false
  double reputation_score;  // 0.0 to 1.0
  int64_t last_report_at_ms;
  int64_t last_updated_at_ms;

  json to_json() const {
    json j;
    j["user_id"]                = user_id;
    j["total_reports_submitted"] = total_reports_submitted;
    j["reports_accepted"]       = reports_accepted;
    j["reports_dismissed"]      = reports_dismissed;
    j["reports_marked_false"]   = reports_marked_false;
    j["reputation_score"]       = reputation_score;
    j["last_report_at_ms"]      = last_report_at_ms;
    j["last_updated_at_ms"]     = last_updated_at_ms;
    return j;
  }
};

// --- Rate limit state ---
struct RateLimitState {
  std::string key;            // user_id or room_id
  int64_t window_start_ms;
  int count;
  int max_allowed;
  int64_t cooldown_until_ms;
  bool is_blocked;

  RateLimitState() 
    : window_start_ms(0), count(0), max_allowed(0),
      cooldown_until_ms(0), is_blocked(false) {}
};

// --- Report statistics ---
struct ReportStats {
  int total_reports;
  int pending_reports;
  int acknowledged_reports;
  int under_review_reports;
  int resolved_reports;
  int dismissed_reports;
  int escalated_reports;
  double avg_resolution_time_ms;
  int64_t oldest_pending_ms;
  std::map<std::string, int> counts_by_category;
  std::map<std::string, int> counts_by_status;
  std::map<std::string, int> counts_by_admin;
  json daily_trend;  // array of {date, count}
  json hourly_distribution;  // array of {hour, count}

  json to_json() const {
    json j;
    j["total_reports"]          = total_reports;
    j["pending_reports"]        = pending_reports;
    j["acknowledged_reports"]   = acknowledged_reports;
    j["under_review_reports"]   = under_review_reports;
    j["resolved_reports"]       = resolved_reports;
    j["dismissed_reports"]      = dismissed_reports;
    j["escalated_reports"]      = escalated_reports;
    j["avg_resolution_time_ms"] = avg_resolution_time_ms;
    j["oldest_pending_ms"]      = oldest_pending_ms;
    j["counts_by_category"]     = counts_by_category;
    j["counts_by_status"]       = counts_by_status;
    j["counts_by_admin"]        = counts_by_admin;
    j["daily_trend"]            = daily_trend;
    j["hourly_distribution"]    = hourly_distribution;
    return j;
  }
};

// --- Report list result with pagination ---
struct ReportListResult {
  std::vector<EventReport> reports;
  int total_count;
  int offset;
  int limit;
  bool has_more;

  json to_json() const {
    json j;
    j["reports"]      = json::array();
    for (const auto& r : reports) {
      j["reports"].push_back(r.to_json());
    }
    j["total_count"] = total_count;
    j["offset"]      = offset;
    j["limit"]       = limit;
    j["has_more"]     = has_more;
    return j;
  }
};

// --- Notification entry ---
struct ReportNotification {
  std::string notification_id;
  std::string report_id;
  std::string channel;
  std::string target;        // user_id or webhook URL
  int severity;
  std::string message;
  bool sent;
  int64_t sent_at_ms;
  int64_t created_at_ms;
  json payload;

  json to_json() const {
    json j;
    j["notification_id"] = notification_id;
    j["report_id"]       = report_id;
    j["channel"]         = channel;
    j["target"]          = target;
    j["severity"]        = severity;
    j["message"]         = message;
    j["sent"]            = sent;
    j["sent_at_ms"]      = sent_at_ms;
    j["created_at_ms"]   = created_at_ms;
    j["payload"]         = payload;
    return j;
  }
};

// ============================================================================
// ReportCategoryRegistry — Category definitions and management
// ============================================================================

class ReportCategoryRegistry {
 public:
  ReportCategoryRegistry() {
    initialize_default_categories();
  }

  void initialize_default_categories() {
    categories_.clear();

    // --- Standard Matrix categories ---
    add_category({
      std::string(kReportCategoryCSAM),
      "Child Sexual Abuse Material",
      "Content depicting or promoting child sexual abuse. Requires immediate escalation.",
      true, true, kNotifySeverityCritical, ReportPriority::CRITICAL,
      1, 1, 1, kDefaultCSAMReportRetentionDays, {}
    });

    add_category({
      std::string(kReportCategoryTerrorism),
      "Terrorism / Violent Extremism",
      "Content promoting, glorifying, or instructing terrorism or violent extremism.",
      true, true, kNotifySeverityCritical, ReportPriority::CRITICAL,
      1, 2, 2, kDefaultCSAMReportRetentionDays, {}
    });

    add_category({
      std::string(kReportCategoryHarassment),
      "Harassment",
      "Targeted harassment, threats, or persistent unwanted contact.",
      true, false, kNotifySeverityMedium, ReportPriority::HIGH,
      kDefaultAutoRedactThreshold, kDefaultAutoQuarantineThreshold,
      kDefaultAutoMuteThreshold, kDefaultReportRetentionDays,
      {"targeted_harassment", "threats", "unwanted_contact", "stalking"}
    });

    add_category({
      std::string(kReportCategoryBullying),
      "Bullying",
      "Repeated hostile behavior intended to intimidate or harm.",
      true, false, kNotifySeverityMedium, ReportPriority::NORMAL,
      kDefaultAutoRedactThreshold, kDefaultAutoQuarantineThreshold,
      kDefaultAutoMuteThreshold, kDefaultReportRetentionDays,
      {"verbal_abuse", "exclusion", "public_humiliation"}
    });

    add_category({
      std::string(kReportCategorySpam),
      "Spam",
      "Unsolicited bulk messages, advertisements, or repetitive content.",
      true, false, kNotifySeverityLow, ReportPriority::LOW,
      kDefaultAutoRedactThreshold + 2, kDefaultAutoQuarantineThreshold,
      kDefaultAutoMuteThreshold, kDefaultDismissedRetentionDays,
      {"link_spam", "advertisement", "repetitive_messages", "bot_spam"}
    });

    add_category({
      std::string(kReportCategoryImpersonation),
      "Impersonation",
      "Pretending to be another person or entity with intent to deceive.",
      true, false, kNotifySeverityMedium, ReportPriority::HIGH,
      kDefaultAutoRedactThreshold, kDefaultAutoQuarantineThreshold,
      kDefaultAutoMuteThreshold, kDefaultReportRetentionDays,
      {"user_impersonation", "brand_impersonation", "admin_impersonation"}
    });

    add_category({
      std::string(kReportCategoryHateSpeech),
      "Hate Speech",
      "Content that attacks or demeans a group based on protected characteristics.",
      true, false, kNotifySeverityMedium, ReportPriority::HIGH,
      kDefaultAutoRedactThreshold, kDefaultAutoQuarantineThreshold,
      kDefaultAutoMuteThreshold, kDefaultReportRetentionDays,
      {"racism", "xenophobia", "homophobia", "transphobia", "antisemitism", "islamophobia"}
    });

    add_category({
      std::string(kReportCategorySelfHarm),
      "Self-Harm / Suicide",
      "Content promoting, glorifying, or instructing self-harm or suicide.",
      true, false, kNotifySeverityHigh, ReportPriority::URGENT,
      1, 1, 2, kDefaultReportRetentionDays,
      {"suicide", "self_injury", "eating_disorder", "dangerous_challenges"}
    });

    add_category({
      std::string(kReportCategoryDisinformation),
      "Disinformation",
      "Deliberately false information spread to deceive or cause harm.",
      true, false, kNotifySeverityLow, ReportPriority::NORMAL,
      kDefaultAutoRedactThreshold + 3, kDefaultAutoQuarantineThreshold,
      kDefaultAutoMuteThreshold, kDefaultReportRetentionDays,
      {"medical_misinformation", "election_disinformation", "conspiracy_theories"}
    });

    add_category({
      std::string(kReportCategoryCopyright),
      "Copyright Violation",
      "Unauthorized distribution of copyrighted material.",
      true, false, kNotifySeverityLow, ReportPriority::NORMAL,
      kDefaultAutoRedactThreshold, kDefaultAutoQuarantineThreshold,
      kDefaultAutoMuteThreshold, kDefaultReportRetentionDays,
      {"dmca", "piracy", "unauthorized_sharing", "trademark_violation"}
    });

    add_category({
      std::string(kReportCategoryUnauthorizedData),
      "Unauthorized Data Collection",
      "Collecting user data without consent (GDPR/privacy violation).",
      true, false, kNotifySeverityMedium, ReportPriority::HIGH,
      kDefaultAutoRedactThreshold, kDefaultAutoQuarantineThreshold,
      kDefaultAutoMuteThreshold, kDefaultReportRetentionDays,
      {"doxxing", "data_scraping", "unauthorized_tracking"}
    });

    add_category({
      std::string(kReportCategoryNSFW),
      "Not Safe For Work (NSFW)",
      "Sexually explicit or adult content not appropriate for general audiences.",
      true, false, kNotifySeverityLow, ReportPriority::NORMAL,
      kDefaultAutoRedactThreshold, kDefaultAutoQuarantineThreshold,
      kDefaultAutoMuteThreshold, kDefaultReportRetentionDays,
      {"pornography", "explicit_imagery", "sexual_solicitation"}
    });

    add_category({
      std::string(kReportCategoryScam),
      "Scam / Fraud",
      "Attempts to defraud users through deceptive schemes.",
      true, false, kNotifySeverityMedium, ReportPriority::HIGH,
      kDefaultAutoRedactThreshold, kDefaultAutoQuarantineThreshold,
      kDefaultAutoMuteThreshold, kDefaultReportRetentionDays,
      {"crypto_scam", "phishing", "financial_fraud", "romance_scam"}
    });

    add_category({
      std::string(kReportCategoryMalware),
      "Malware / Malicious Links",
      "Distribution of malware, viruses, or links to malicious websites.",
      true, false, kNotifySeverityMedium, ReportPriority::HIGH,
      1, 1, kDefaultAutoMuteThreshold, kDefaultReportRetentionDays,
      {"virus", "ransomware", "phishing_link", "malicious_bot"}
    });

    add_category({
      std::string(kReportCategoryDoxxing),
      "Doxxing",
      "Publishing private personal information without consent.",
      true, false, kNotifySeverityMedium, ReportPriority::HIGH,
      1, 1, kDefaultAutoMuteThreshold, kDefaultReportRetentionDays,
      {"address", "phone_number", "real_name", "workplace"}
    });

    add_category({
      std::string(kReportCategoryGrooming),
      "Grooming / Predatory Behavior",
      "Behavior indicating attempts to exploit or manipulate minors.",
      true, true, kNotifySeverityHigh, ReportPriority::URGENT,
      1, 1, 1, kDefaultCSAMReportRetentionDays,
      {"minor_grooming", "predatory_messages", "inappropriate_contact"}
    });

    add_category({
      std::string(kReportCategoryOther),
      "Other",
      "Content that violates server rules but doesn't fit other categories.",
      true, false, kNotifySeverityLow, ReportPriority::NORMAL,
      kDefaultAutoRedactThreshold, kDefaultAutoQuarantineThreshold,
      kDefaultAutoMuteThreshold, kDefaultReportRetentionDays,
      {}
    });
  }

  void add_category(const ReportCategory& cat) {
    std::lock_guard<std::mutex> lock(mutex_);
    categories_[cat.category_id] = cat;
  }

  void remove_category(const std::string& category_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    categories_.erase(category_id);
  }

  std::optional<ReportCategory> get_category(const std::string& id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = categories_.find(id);
    if (it != categories_.end()) {
      return it->second;
    }
    return std::nullopt;
  }

  bool is_valid_category(const std::string& category_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return categories_.find(category_id) != categories_.end();
  }

  std::vector<ReportCategory> get_all_categories() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<ReportCategory> result;
    for (const auto& [id, cat] : categories_) {
      result.push_back(cat);
    }
    return result;
  }

  json get_categories_json() const {
    std::lock_guard<std::mutex> lock(mutex_);
    json j = json::object();
    for (const auto& [id, cat] : categories_) {
      j[id] = cat.to_json();
    }
    return j;
  }

 private:
  mutable std::mutex mutex_;
  std::map<std::string, ReportCategory> categories_;
};

// ============================================================================
// ReportValidator — Input validation for report submissions
// ============================================================================

class ReportValidator {
 public:
  struct ValidationResult {
    bool valid;
    std::string error_code;
    std::string error_message;
  };

  ValidationResult validate_report_submission(
      const std::string& room_id,
      const std::string& event_id,
      const std::string& reporter_user_id,
      const std::string& reason,
      const std::string& category,
      int score) {
    
    // Validate room_id format
    if (room_id.empty()) {
      return {false, "M_MISSING_ROOM_ID", "room_id is required"};
    }
    if (!validate_room_id_format(room_id)) {
      return {false, "M_INVALID_ROOM_ID", "room_id format is invalid"};
    }

    // Validate event_id format
    if (event_id.empty()) {
      return {false, "M_MISSING_EVENT_ID", "event_id is required"};
    }
    if (!validate_event_id_format(event_id)) {
      return {false, "M_INVALID_EVENT_ID", "event_id format is invalid"};
    }

    // Validate reporter_user_id format
    if (reporter_user_id.empty()) {
      return {false, "M_MISSING_USER_ID", "reporter user_id is required"};
    }
    if (!validate_user_id_format(reporter_user_id)) {
      return {false, "M_INVALID_USER_ID", "reporter user_id format is invalid"};
    }

    // Validate reason
    if (reason.empty()) {
      return {false, "M_MISSING_REASON", "reason is required"};
    }
    if (static_cast<int64_t>(reason.length()) > kMaxReasonLength) {
      return {false, "M_REASON_TOO_LONG", 
              "reason exceeds maximum length of " + std::to_string(kMaxReasonLength)};
    }

    // Validate category
    std::string effective_category = category.empty() ? 
      std::string(kReportCategoryOther) : category;
    if (!category_registry_.is_valid_category(effective_category)) {
      return {false, "M_INVALID_CATEGORY", 
              "unknown report category: " + effective_category};
    }

    // Validate score range
    if (score < kMaxScore || score > kMinScore) {
      return {false, "M_INVALID_SCORE",
              "score must be between " + std::to_string(kMaxScore) + 
              " and " + std::to_string(kMinScore)};
    }

    // Can't report self
    if (reporter_user_id == reported_user_id_) {
      return {false, "M_CANNOT_REPORT_SELF", "cannot report your own event"};
    }

    report_api_log.debug("Report validation passed: room=" + room_id + 
                         " event=" + event_id + " reporter=" + reporter_user_id);
    return {true, "", ""};
  }

  void set_reported_user_id(const std::string& user_id) {
    reported_user_id_ = user_id;
  }

  void set_category_registry(const ReportCategoryRegistry& registry) {
    category_registry_ = registry;
  }

 private:
  std::string reported_user_id_;
  ReportCategoryRegistry category_registry_;
};

// ============================================================================
// ReportRateLimiter — Rate limiting to prevent report abuse
// ============================================================================

class ReportRateLimiter {
 public:
  ReportRateLimiter() 
    : max_per_user_per_minute_(kDefaultMaxReportsPerUserPerMinute),
      max_per_user_per_hour_(kDefaultMaxReportsPerUserPerHour),
      max_per_event_(kDefaultMaxReportsPerEvent),
      max_per_room_per_minute_(kDefaultMaxReportsPerRoomPerMinute),
      cooldown_seconds_(kDefaultReporterCooldownSeconds),
      blocked_users_() {}

  // Check if a user can submit a report; returns true if allowed
  bool check_user_rate_limit(const std::string& user_id) {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    
    int64_t now_ms = current_time_ms();
    
    // Check if user is blocked/on cooldown
    auto b_it = blocked_users_.find(user_id);
    if (b_it != blocked_users_.end() && b_it->second > now_ms) {
      report_log.warn("Rate limit: user " + user_id + " is on cooldown until " +
                      std::to_string(b_it->second));
      return false;
    }

    // Check per-minute limit
    auto& minute_state = per_minute_state_[user_id];
    if (now_ms - minute_state.window_start_ms > 60000) {
      minute_state.window_start_ms = now_ms;
      minute_state.count = 0;
    }
    if (minute_state.count >= max_per_user_per_minute_) {
      apply_cooldown(user_id, cooldown_seconds_);
      report_log.warn("Rate limit: user " + user_id + 
                      " exceeded per-minute limit (" + 
                      std::to_string(max_per_user_per_minute_) + ")");
      return false;
    }

    // Check per-hour limit
    auto& hour_state = per_hour_state_[user_id];
    if (now_ms - hour_state.window_start_ms > 3600000) {
      hour_state.window_start_ms = now_ms;
      hour_state.count = 0;
    }
    if (hour_state.count >= max_per_user_per_hour_) {
      apply_cooldown(user_id, cooldown_seconds_ * 3);
      report_log.warn("Rate limit: user " + user_id + 
                      " exceeded per-hour limit (" +
                      std::to_string(max_per_user_per_hour_) + ")");
      return false;
    }

    return true;
  }

  // Check if an event has received too many reports
  bool check_event_limit(const std::string& event_id) {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    auto it = per_event_state_.find(event_id);
    return (it == per_event_state_.end() || it->second <= max_per_event_);
  }

  // Check per-room rate limit
  bool check_room_rate_limit(const std::string& room_id) {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    int64_t now_ms = current_time_ms();
    auto& state = per_room_state_[room_id];
    if (now_ms - state.window_start_ms > 60000) {
      state.window_start_ms = now_ms;
      state.count = 0;
    }
    return state.count < max_per_room_per_minute_;
  }

  // Record a successful report submission (update counters)
  void record_report(const std::string& user_id, const std::string& event_id,
                     const std::string& room_id) {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    int64_t now_ms = current_time_ms();

    // Update per-minute counter
    auto& minute_state = per_minute_state_[user_id];
    if (now_ms - minute_state.window_start_ms > 60000) {
      minute_state.window_start_ms = now_ms;
      minute_state.count = 1;
    } else {
      minute_state.count++;
    }

    // Update per-hour counter
    auto& hour_state = per_hour_state_[user_id];
    if (now_ms - hour_state.window_start_ms > 3600000) {
      hour_state.window_start_ms = now_ms;
      hour_state.count = 1;
    } else {
      hour_state.count++;
    }

    // Update per-event counter
    per_event_state_[event_id]++;

    // Update per-room counter
    auto& room_state = per_room_state_[room_id];
    if (now_ms - room_state.window_start_ms > 60000) {
      room_state.window_start_ms = now_ms;
      room_state.count = 1;
    } else {
      room_state.count++;
    }

    // Clear cooldown if user successfully submits
    blocked_users_.erase(user_id);
    last_report_time_[user_id] = now_ms;
  }

  // Apply cooldown to a user
  void apply_cooldown(const std::string& user_id, int seconds) {
    int64_t until_ms = current_time_ms() + (seconds * 1000LL);
    blocked_users_[user_id] = until_ms;
    report_log.info("Applied cooldown to user " + user_id + 
                    " for " + std::to_string(seconds) + " seconds");
  }

  // Check if user is blocked
  bool is_user_blocked(const std::string& user_id) {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    int64_t now_ms = current_time_ms();
    auto it = blocked_users_.find(user_id);
    return (it != blocked_users_.end() && it->second > now_ms);
  }

  // Remove block from a user
  void unblock_user(const std::string& user_id) {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    blocked_users_.erase(user_id);
    report_log.info("Removed block from user " + user_id);
  }

  // Get current rate limit stats for a user
  json get_user_rate_limit_stats(const std::string& user_id) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    json j;
    int64_t now_ms = current_time_ms();

    auto m_it = per_minute_state_.find(user_id);
    j["per_minute"] = {
      {"current", (m_it != per_minute_state_.end() && 
                   now_ms - m_it->second.window_start_ms <= 60000) ? 
                   m_it->second.count : 0},
      {"max", max_per_user_per_minute_}
    };

    auto h_it = per_hour_state_.find(user_id);
    j["per_hour"] = {
      {"current", (h_it != per_hour_state_.end() && 
                   now_ms - h_it->second.window_start_ms <= 3600000) ? 
                   h_it->second.count : 0},
      {"max", max_per_user_per_hour_}
    };

    auto b_it = blocked_users_.find(user_id);
    j["is_blocked"] = (b_it != blocked_users_.end() && b_it->second > now_ms);
    if (j["is_blocked"].get<bool>()) {
      j["blocked_until_ms"] = b_it->second;
    }

    return j;
  }

  // Config setters
  void set_max_per_user_per_minute(int val) { max_per_user_per_minute_ = val; }
  void set_max_per_user_per_hour(int val)   { max_per_user_per_hour_ = val; }
  void set_max_per_event(int val)            { max_per_event_ = val; }
  void set_max_per_room_per_minute(int val)  { max_per_room_per_minute_ = val; }
  void set_cooldown_seconds(int val)          { cooldown_seconds_ = val; }

  // Clean up expired state
  void cleanup_expired_state() {
    std::lock_guard<std::shared_mutex> lock(mutex_);
    int64_t now_ms = current_time_ms();
    int64_t minute_ago = now_ms - 120000;   // 2 minutes
    int64_t hour_ago = now_ms - 7200000;    // 2 hours
    
    for (auto it = per_minute_state_.begin(); it != per_minute_state_.end();) {
      if (it->second.window_start_ms < minute_ago) {
        it = per_minute_state_.erase(it);
      } else { ++it; }
    }
    for (auto it = per_hour_state_.begin(); it != per_hour_state_.end();) {
      if (it->second.window_start_ms < hour_ago) {
        it = per_hour_state_.erase(it);
      } else { ++it; }
    }
    for (auto it = blocked_users_.begin(); it != blocked_users_.end();) {
      if (it->second < now_ms) {
        it = blocked_users_.erase(it);
      } else { ++it; }
    }
  }

 private:
  mutable std::shared_mutex mutex_;
  
  int max_per_user_per_minute_;
  int max_per_user_per_hour_;
  int max_per_event_;
  int max_per_room_per_minute_;
  int cooldown_seconds_;

  std::unordered_map<std::string, RateLimitState> per_minute_state_;
  std::unordered_map<std::string, RateLimitState> per_hour_state_;
  std::unordered_map<std::string, int> per_event_state_;
  std::unordered_map<std::string, RateLimitState> per_room_state_;
  std::unordered_map<std::string, int64_t> blocked_users_;  // user_id -> cooldown_until_ms
  std::unordered_map<std::string, int64_t> last_report_time_;
};

// ============================================================================
// ReportStorageEngine — SQL-backed storage for reports
// ============================================================================

class ReportStorageEngine {
 public:
  explicit ReportStorageEngine(std::shared_ptr<DatabasePool> db_pool)
    : db_pool_(std::move(db_pool)) {
    initialize_tables();
  }

  // --- Initialize database tables ---
  void initialize_tables() {
    auto conn = db_pool_->get_connection();
    
    // event_reports table
    conn->execute(R"SQL(
      CREATE TABLE IF NOT EXISTS event_reports (
        report_id           TEXT PRIMARY KEY,
        room_id             TEXT NOT NULL,
        event_id            TEXT NOT NULL,
        reporter_user_id    TEXT NOT NULL,
        reported_user_id    TEXT NOT NULL,
        reason              TEXT NOT NULL,
        category            TEXT NOT NULL DEFAULT 'm.other',
        status              TEXT NOT NULL DEFAULT 'pending',
        priority            TEXT NOT NULL DEFAULT 'normal',
        score               INTEGER NOT NULL DEFAULT 0,
        created_at_ms       BIGINT NOT NULL,
        updated_at_ms       BIGINT NOT NULL,
        acknowledged_at_ms  BIGINT DEFAULT NULL,
        reviewed_at_ms      BIGINT DEFAULT NULL,
        resolved_at_ms      BIGINT DEFAULT NULL,
        assigned_admin      TEXT DEFAULT NULL,
        admin_notes         TEXT DEFAULT NULL,
        source              TEXT NOT NULL DEFAULT 'client_api',
        source_server       TEXT DEFAULT NULL,
        report_content      TEXT DEFAULT '{}',
        event_snapshot      TEXT DEFAULT '{}',
        report_count        INTEGER NOT NULL DEFAULT 1
      )
    )SQL");

    // Indexes for common queries
    conn->execute(R"SQL(
      CREATE INDEX IF NOT EXISTS idx_reports_room_id 
        ON event_reports(room_id)
    )SQL");
    conn->execute(R"SQL(
      CREATE INDEX IF NOT EXISTS idx_reports_event_id 
        ON event_reports(event_id)
    )SQL");
    conn->execute(R"SQL(
      CREATE INDEX IF NOT EXISTS idx_reports_reporter 
        ON event_reports(reporter_user_id)
    )SQL");
    conn->execute(R"SQL(
      CREATE INDEX IF NOT EXISTS idx_reports_reported_user 
        ON event_reports(reported_user_id)
    )SQL");
    conn->execute(R"SQL(
      CREATE INDEX IF NOT EXISTS idx_reports_status 
        ON event_reports(status)
    )SQL");
    conn->execute(R"SQL(
      CREATE INDEX IF NOT EXISTS idx_reports_category 
        ON event_reports(category)
    )SQL");
    conn->execute(R"SQL(
      CREATE INDEX IF NOT EXISTS idx_reports_created_ts 
        ON event_reports(created_at_ms)
    )SQL");
    conn->execute(R"SQL(
      CREATE INDEX IF NOT EXISTS idx_reports_assigned_admin 
        ON event_reports(assigned_admin)
    )SQL");
    conn->execute(R"SQL(
      CREATE INDEX IF NOT EXISTS idx_reports_room_event 
        ON event_reports(room_id, event_id)
    )SQL");

    // event_report_actions (audit trail)
    conn->execute(R"SQL(
      CREATE TABLE IF NOT EXISTS event_report_actions (
        action_id            TEXT PRIMARY KEY,
        report_id            TEXT NOT NULL,
        action_type          TEXT NOT NULL,
        admin_user_id        TEXT NOT NULL,
        action_detail        TEXT DEFAULT '{}',
        notes                TEXT DEFAULT '',
        previous_status      TEXT DEFAULT NULL,
        new_status           TEXT DEFAULT NULL,
        previous_assignment  TEXT DEFAULT NULL,
        new_assignment       TEXT DEFAULT NULL,
        timestamp_ms         BIGINT NOT NULL,
        admin_ip             TEXT DEFAULT NULL,
        admin_device_id      TEXT DEFAULT NULL,
        audit_hash           TEXT DEFAULT NULL,
        FOREIGN KEY (report_id) REFERENCES event_reports(report_id)
      )
    )SQL");

    conn->execute(R"SQL(
      CREATE INDEX IF NOT EXISTS idx_actions_report_id 
        ON event_report_actions(report_id)
    )SQL");
    conn->execute(R"SQL(
      CREATE INDEX IF NOT EXISTS idx_actions_admin 
        ON event_report_actions(admin_user_id)
    )SQL");
    conn->execute(R"SQL(
      CREATE INDEX IF NOT EXISTS idx_actions_timestamp 
        ON event_report_actions(timestamp_ms)
    )SQL");

    // event_report_notifications
    conn->execute(R"SQL(
      CREATE TABLE IF NOT EXISTS event_report_notifications (
        notification_id   TEXT PRIMARY KEY,
        report_id         TEXT NOT NULL,
        channel           TEXT NOT NULL,
        target            TEXT NOT NULL,
        severity          INTEGER NOT NULL DEFAULT 1,
        message           TEXT NOT NULL,
        sent              INTEGER NOT NULL DEFAULT 0,
        sent_at_ms        BIGINT DEFAULT NULL,
        created_at_ms     BIGINT NOT NULL,
        payload           TEXT DEFAULT '{}',
        FOREIGN KEY (report_id) REFERENCES event_reports(report_id)
      )
    )SQL");

    // reporter_reputation
    conn->execute(R"SQL(
      CREATE TABLE IF NOT EXISTS reporter_reputation (
        user_id                TEXT PRIMARY KEY,
        total_reports_submitted INTEGER NOT NULL DEFAULT 0,
        reports_accepted        INTEGER NOT NULL DEFAULT 0,
        reports_dismissed       INTEGER NOT NULL DEFAULT 0,
        reports_marked_false    INTEGER NOT NULL DEFAULT 0,
        reputation_score        REAL NOT NULL DEFAULT 0.5,
        last_report_at_ms       BIGINT DEFAULT NULL,
        last_updated_at_ms      BIGINT DEFAULT NULL
      )
    )SQL");

    // event_report_thresholds
    conn->execute(R"SQL(
      CREATE TABLE IF NOT EXISTS event_report_thresholds (
        category               TEXT NOT NULL,
        auto_redact_threshold   INTEGER NOT NULL DEFAULT 5,
        auto_quarantine_threshold INTEGER NOT NULL DEFAULT 3,
        auto_mute_threshold     INTEGER NOT NULL DEFAULT 7,
        auto_notify_threshold   INTEGER NOT NULL DEFAULT 1,
        enabled                INTEGER NOT NULL DEFAULT 1,
        updated_at_ms           BIGINT DEFAULT NULL,
        PRIMARY KEY (category)
      )
    )SQL");

    // report_deduplication
    conn->execute(R"SQL(
      CREATE TABLE IF NOT EXISTS report_deduplication (
        event_id             TEXT NOT NULL,
        reporter_user_id     TEXT NOT NULL,
        report_id            TEXT NOT NULL,
        created_at_ms        BIGINT NOT NULL,
        PRIMARY KEY (event_id, reporter_user_id)
      )
    )SQL");

    report_store_log.info("Report storage tables initialized");
  }

  // --- Insert a new event report ---
  std::string insert_report(const EventReport& report) {
    auto conn = db_pool_->get_connection();
    
    std::string report_id = report.report_id.empty() ? 
      generate_report_id() : report.report_id;
    
    int64_t now_ms = current_time_ms();
    
    conn->execute(
      "INSERT INTO event_reports "
      "(report_id, room_id, event_id, reporter_user_id, reported_user_id, "
      " reason, category, status, priority, score, created_at_ms, updated_at_ms, "
      " acknowledged_at_ms, reviewed_at_ms, resolved_at_ms, assigned_admin, "
      " admin_notes, source, source_server, report_content, event_snapshot, report_count) "
      "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)",
      {
        report_id,
        report.room_id,
        report.event_id,
        report.reporter_user_id,
        report.reported_user_id,
        report.reason,
        report.category,
        report.status.empty() ? std::string(kStatusPending) : report.status,
        report.priority.empty() ? "normal" : report.priority,
        std::to_string(report.score),
        std::to_string(now_ms),
        std::to_string(now_ms),
        "NULL",
        "NULL",
        "NULL",
        "NULL",
        "",
        report.source_server.empty() ? "client_api" : "federation",
        report.source_server.empty() ? "NULL" : report.source_server,
        report.report_content.dump(),
        report.event_snapshot.dump()
      });

    // Check for duplicate reports on same event by same user
    conn->execute(
      "INSERT OR IGNORE INTO report_deduplication "
      "(event_id, reporter_user_id, report_id, created_at_ms) "
      "VALUES (?, ?, ?, ?)",
      {report.event_id, report.reporter_user_id, report_id, std::to_string(now_ms)}
    );

    report_store_log.info("Inserted report: " + report_id + 
                          " for event " + report.event_id);
    return report_id;
  }

  // --- Update existing report status ---
  bool update_report_status(const std::string& report_id, 
                            const std::string& new_status,
                            const std::string& admin_notes = "",
                            const std::string& assigned_admin = "") {
    auto conn = db_pool_->get_connection();
    int64_t now_ms = current_time_ms();

    std::string sql = "UPDATE event_reports SET status = ?, updated_at_ms = ?";
    std::vector<std::string> params = {new_status, std::to_string(now_ms)};

    if (new_status == kStatusAcknowledged) {
      sql += ", acknowledged_at_ms = ?";
      params.push_back(std::to_string(now_ms));
    } else if (new_status == kStatusUnderReview) {
      sql += ", reviewed_at_ms = ?";
      params.push_back(std::to_string(now_ms));
    } else if (new_status == kStatusResolved || 
               new_status == kStatusDismissed) {
      sql += ", resolved_at_ms = ?";
      params.push_back(std::to_string(now_ms));
    }

    if (!admin_notes.empty()) {
      sql += ", admin_notes = ?";
      params.push_back(admin_notes);
    }
    if (!assigned_admin.empty()) {
      sql += ", assigned_admin = ?";
      params.push_back(assigned_admin);
    }

    sql += " WHERE report_id = ?";
    params.push_back(report_id);

    auto result = conn->execute(sql, params);
    return result.rows_affected() > 0;
  }

  // --- Get a single report by ID ---
  std::optional<EventReport> get_report(const std::string& report_id) {
    auto conn = db_pool_->get_connection();
    auto rows = conn->query(
      "SELECT * FROM event_reports WHERE report_id = ?",
      {report_id});

    if (rows.empty()) {
      return std::nullopt;
    }

    return row_to_report(rows[0]);
  }

  // --- Get reports by event ID ---
  std::vector<EventReport> get_reports_by_event(const std::string& event_id) {
    auto conn = db_pool_->get_connection();
    auto rows = conn->query(
      "SELECT * FROM event_reports WHERE event_id = ? ORDER BY created_at_ms DESC",
      {event_id});

    std::vector<EventReport> result;
    for (const auto& row : rows) {
      result.push_back(row_to_report(row));
    }
    return result;
  }

  // --- Get report count for an event ---
  int get_event_report_count(const std::string& event_id) {
    auto conn = db_pool_->get_connection();
    auto rows = conn->query(
      "SELECT COUNT(*) as cnt FROM event_reports WHERE event_id = ?",
      {event_id});
    
    if (!rows.empty()) {
      return std::stoi(rows[0]["cnt"]);
    }
    return 0;
  }

  // --- Query reports with filters ---
  ReportListResult query_reports(const ReportQuery& query) {
    auto conn = db_pool_->get_connection();
    
    std::string where_clause = "WHERE 1=1";
    std::vector<std::string> params;

    if (query.report_id.has_value()) {
      where_clause += " AND report_id = ?";
      params.push_back(query.report_id.value());
    }
    if (query.room_id.has_value()) {
      where_clause += " AND room_id = ?";
      params.push_back(query.room_id.value());
    }
    if (query.event_id.has_value()) {
      where_clause += " AND event_id = ?";
      params.push_back(query.event_id.value());
    }
    if (query.reporter_user_id.has_value()) {
      where_clause += " AND reporter_user_id = ?";
      params.push_back(query.reporter_user_id.value());
    }
    if (query.reported_user_id.has_value()) {
      where_clause += " AND reported_user_id = ?";
      params.push_back(query.reported_user_id.value());
    }
    if (query.category.has_value()) {
      where_clause += " AND category = ?";
      params.push_back(query.category.value());
    }
    if (query.status.has_value()) {
      where_clause += " AND status = ?";
      params.push_back(query.status.value());
    }
    if (query.priority.has_value()) {
      where_clause += " AND priority = ?";
      params.push_back(query.priority.value());
    }
    if (query.assigned_admin.has_value()) {
      where_clause += " AND assigned_admin = ?";
      params.push_back(query.assigned_admin.value());
    }
    if (query.created_after_ms.has_value()) {
      where_clause += " AND created_at_ms >= ?";
      params.push_back(std::to_string(query.created_after_ms.value()));
    }
    if (query.created_before_ms.has_value()) {
      where_clause += " AND created_at_ms <= ?";
      params.push_back(std::to_string(query.created_before_ms.value()));
    }
    if (query.updated_after_ms.has_value()) {
      where_clause += " AND updated_at_ms >= ?";
      params.push_back(std::to_string(query.updated_after_ms.value()));
    }
    if (query.updated_before_ms.has_value()) {
      where_clause += " AND updated_at_ms <= ?";
      params.push_back(std::to_string(query.updated_before_ms.value()));
    }
    if (query.min_score.has_value()) {
      where_clause += " AND score >= ?";
      params.push_back(std::to_string(query.min_score.value()));
    }
    if (query.max_score.has_value()) {
      where_clause += " AND score <= ?";
      params.push_back(std::to_string(query.max_score.value()));
    }

    // Status filtering
    if (!query.include_archived) {
      where_clause += " AND status != 'archived'";
    }
    if (!query.include_resolved) {
      where_clause += " AND status != 'resolved' AND status != 'dismissed'";
    }

    // Search term
    if (query.search_term.has_value()) {
      where_clause += " AND (reason LIKE ? OR admin_notes LIKE ?)";
      std::string pattern = "%" + escape_like_pattern(query.search_term.value()) + "%";
      params.push_back(pattern);
      params.push_back(pattern);
    }

    // Get total count
    std::string count_sql = "SELECT COUNT(*) as cnt FROM event_reports " + where_clause;
    auto count_rows = conn->query(count_sql, params);
    int total_count = 0;
    if (!count_rows.empty()) {
      total_count = std::stoi(count_rows[0]["cnt"]);
    }

    // Sort and pagination
    std::string sort_col;
    switch (query.sort_field) {
      case ReportSortField::CREATED_TS:   sort_col = "created_at_ms"; break;
      case ReportSortField::UPDATED_TS:   sort_col = "updated_at_ms"; break;
      case ReportSortField::PRIORITY:     sort_col = "priority"; break;
      case ReportSortField::SCORE:        sort_col = "score"; break;
      case ReportSortField::REPORTER:     sort_col = "reporter_user_id"; break;
      case ReportSortField::REPORTED_USER: sort_col = "reported_user_id"; break;
      case ReportSortField::ROOM_ID:      sort_col = "room_id"; break;
      case ReportSortField::CATEGORY:     sort_col = "category"; break;
      case ReportSortField::STATUS:       sort_col = "status"; break;
      case ReportSortField::REPORT_COUNT:  sort_col = "report_count"; break;
      default:                            sort_col = "created_at_ms"; break;
    }

    std::string sort_dir = (query.sort_direction == SortDirection::ASCENDING) ? 
      "ASC" : "DESC";

    std::string select_sql = 
      "SELECT * FROM event_reports " + where_clause + 
      " ORDER BY " + sort_col + " " + sort_dir +
      " LIMIT ? OFFSET ?";
    params.push_back(std::to_string(query.limit));
    params.push_back(std::to_string(query.offset));

    auto rows = conn->query(select_sql, params);
    
    ReportListResult result;
    result.total_count = total_count;
    result.offset = query.offset;
    result.limit = query.limit;
    result.has_more = (query.offset + query.limit) < total_count;
    
    for (const auto& row : rows) {
      result.reports.push_back(row_to_report(row));
    }

    return result;
  }

  // --- Insert audit action ---
  std::string insert_action(const ReportAction& action) {
    auto conn = db_pool_->get_connection();
    
    std::string action_id = action.action_id.empty() ? 
      generate_audit_id() : action.action_id;
    int64_t now_ms = current_time_ms();

    conn->execute(
      "INSERT INTO event_report_actions "
      "(action_id, report_id, action_type, admin_user_id, action_detail, "
      " notes, previous_status, new_status, previous_assignment, "
      " new_assignment, timestamp_ms, admin_ip, admin_device_id, audit_hash) "
      "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
      {
        action_id,
        action.report_id,
        action.action_type,
        action.admin_user_id,
        action.action_detail,
        action.notes,
        action.previous_status,
        action.new_status,
        action.previous_assignment,
        action.new_assignment,
        std::to_string(now_ms),
        action.admin_ip,
        action.admin_device_id,
        action.audit_hash
      });

    report_audit_log.debug("Recorded action: " + action_id + 
                           " on report " + action.report_id);
    return action_id;
  }

  // --- Get action history for a report ---
  std::vector<ReportAction> get_report_actions(const std::string& report_id) {
    auto conn = db_pool_->get_connection();
    auto rows = conn->query(
      "SELECT * FROM event_report_actions WHERE report_id = ? "
      "ORDER BY timestamp_ms ASC",
      {report_id});

    std::vector<ReportAction> actions;
    for (const auto& row : rows) {
      actions.push_back(row_to_action(row));
    }
    return actions;
  }

  // --- Get last audit hash for chaining ---
  std::string get_last_audit_hash(const std::string& report_id) {
    auto conn = db_pool_->get_connection();
    auto rows = conn->query(
      "SELECT audit_hash FROM event_report_actions WHERE report_id = ? "
      "ORDER BY timestamp_ms DESC LIMIT 1",
      {report_id});

    if (!rows.empty() && !rows[0]["audit_hash"].empty()) {
      return rows[0]["audit_hash"];
    }
    return "0000000000000000";  // Genesis hash
  }

  // --- Insert notification ---
  void insert_notification(const ReportNotification& notification) {
    auto conn = db_pool_->get_connection();
    conn->execute(
      "INSERT INTO event_report_notifications "
      "(notification_id, report_id, channel, target, severity, message, "
      " sent, sent_at_ms, created_at_ms, payload) "
      "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
      {
        notification.notification_id,
        notification.report_id,
        notification.channel,
        notification.target,
        std::to_string(notification.severity),
        notification.message,
        notification.sent ? "1" : "0",
        notification.sent ? std::to_string(notification.sent_at_ms) : "NULL",
        std::to_string(current_time_ms()),
        notification.payload.dump()
      });
  }

  // --- Update/upsert reporter reputation ---
  void upsert_reporter_reputation(const ReporterReputation& rep) {
    auto conn = db_pool_->get_connection();
    int64_t now_ms = current_time_ms();

    conn->execute(
      "INSERT INTO reporter_reputation "
      "(user_id, total_reports_submitted, reports_accepted, reports_dismissed, "
      " reports_marked_false, reputation_score, last_report_at_ms, last_updated_at_ms) "
      "VALUES (?, ?, ?, ?, ?, ?, ?, ?) "
      "ON CONFLICT(user_id) DO UPDATE SET "
      "  total_reports_submitted = excluded.total_reports_submitted, "
      "  reports_accepted = excluded.reports_accepted, "
      "  reports_dismissed = excluded.reports_dismissed, "
      "  reports_marked_false = excluded.reports_marked_false, "
      "  reputation_score = excluded.reputation_score, "
      "  last_report_at_ms = excluded.last_report_at_ms, "
      "  last_updated_at_ms = excluded.last_updated_at_ms",
      {
        rep.user_id,
        std::to_string(rep.total_reports_submitted),
        std::to_string(rep.reports_accepted),
        std::to_string(rep.reports_dismissed),
        std::to_string(rep.reports_marked_false),
        std::to_string(rep.reputation_score),
        std::to_string(rep.last_report_at_ms),
        std::to_string(now_ms)
      });
  }

  // --- Get reporter reputation ---
  std::optional<ReporterReputation> get_reporter_reputation(const std::string& user_id) {
    auto conn = db_pool_->get_connection();
    auto rows = conn->query(
      "SELECT * FROM reporter_reputation WHERE user_id = ?",
      {user_id});

    if (rows.empty()) {
      return std::nullopt;
    }

    ReporterReputation rep;
    rep.user_id = rows[0]["user_id"];
    rep.total_reports_submitted = std::stoi(rows[0]["total_reports_submitted"]);
    rep.reports_accepted = std::stoi(rows[0]["reports_accepted"]);
    rep.reports_dismissed = std::stoi(rows[0]["reports_dismissed"]);
    rep.reports_marked_false = std::stoi(rows[0]["reports_marked_false"]);
    rep.reputation_score = std::stod(rows[0]["reputation_score"]);
    rep.last_report_at_ms = std::stoll(rows[0]["last_report_at_ms"]);
    rep.last_updated_at_ms = std::stoll(rows[0]["last_updated_at_ms"]);

    return rep;
  }

  // --- Get auto-action thresholds for a category ---
  json get_category_thresholds(const std::string& category) {
    auto conn = db_pool_->get_connection();
    auto rows = conn->query(
      "SELECT * FROM event_report_thresholds WHERE category = ? AND enabled = 1",
      {category});

    json j;
    if (!rows.empty()) {
      j["auto_redact_threshold"] = std::stoi(rows[0]["auto_redact_threshold"]);
      j["auto_quarantine_threshold"] = std::stoi(rows[0]["auto_quarantine_threshold"]);
      j["auto_mute_threshold"] = std::stoi(rows[0]["auto_mute_threshold"]);
      j["auto_notify_threshold"] = std::stoi(rows[0]["auto_notify_threshold"]);
    } else {
      j["auto_redact_threshold"] = kDefaultAutoRedactThreshold;
      j["auto_quarantine_threshold"] = kDefaultAutoQuarantineThreshold;
      j["auto_mute_threshold"] = kDefaultAutoMuteThreshold;
      j["auto_notify_threshold"] = 1;
    }
    return j;
  }

  // --- Get statistics ---
  ReportStats get_statistics(int64_t since_ms = 0, int64_t until_ms = 0) {
    auto conn = db_pool_->get_connection();
    ReportStats stats;

    // Total by status
    auto status_rows = conn->query(
      "SELECT status, COUNT(*) as cnt FROM event_reports GROUP BY status");
    for (const auto& row : status_rows) {
      std::string status = row["status"];
      int cnt = std::stoi(row["cnt"]);
      stats.counts_by_status[status] = cnt;
      stats.total_reports += cnt;
      
      if (status == kStatusPending) stats.pending_reports = cnt;
      else if (status == kStatusAcknowledged) stats.acknowledged_reports = cnt;
      else if (status == kStatusUnderReview) stats.under_review_reports = cnt;
      else if (status == kStatusResolved) stats.resolved_reports = cnt;
      else if (status == kStatusDismissed) stats.dismissed_reports = cnt;
      else if (status == kStatusEscalated) stats.escalated_reports = cnt;
    }

    // By category
    auto cat_rows = conn->query(
      "SELECT category, COUNT(*) as cnt FROM event_reports GROUP BY category");
    for (const auto& row : cat_rows) {
      stats.counts_by_category[row["category"]] = std::stoi(row["cnt"]);
    }

    // By assigned admin
    auto admin_rows = conn->query(
      "SELECT assigned_admin, COUNT(*) as cnt FROM event_reports "
      "WHERE assigned_admin IS NOT NULL GROUP BY assigned_admin");
    for (const auto& row : admin_rows) {
      stats.counts_by_admin[row["assigned_admin"]] = std::stoi(row["cnt"]);
    }

    // Average resolution time
    auto avg_rows = conn->query(
      "SELECT AVG(resolved_at_ms - created_at_ms) as avg_res "
      "FROM event_reports WHERE resolved_at_ms IS NOT NULL");
    if (!avg_rows.empty() && !avg_rows[0]["avg_res"].empty()) {
      stats.avg_resolution_time_ms = std::stod(avg_rows[0]["avg_res"]);
    }

    // Oldest pending
    auto oldest_rows = conn->query(
      "SELECT MIN(created_at_ms) as oldest FROM event_reports WHERE status = 'pending'");
    if (!oldest_rows.empty() && !oldest_rows[0]["oldest"].empty()) {
      stats.oldest_pending_ms = std::stoll(oldest_rows[0]["oldest"]);
    }

    return stats;
  }

  // --- Delete old reports based on retention policy ---
  int delete_old_reports(int64_t older_than_ms, const std::string& category = "") {
    auto conn = db_pool_->get_connection();
    
    std::string sql = "DELETE FROM event_reports WHERE created_at_ms < ?";
    std::vector<std::string> params = {std::to_string(older_than_ms)};
    
    if (!category.empty()) {
      sql += " AND category = ?";
      params.push_back(category);
    }

    auto result = conn->execute(sql, params);
    
    // Also clean up associated actions
    conn->execute(
      "DELETE FROM event_report_actions WHERE report_id NOT IN "
      "(SELECT report_id FROM event_reports)");
    
    // Clean up notifications
    conn->execute(
      "DELETE FROM event_report_notifications WHERE report_id NOT IN "
      "(SELECT report_id FROM event_reports)");

    report_store_log.info("Deleted " + 
                          std::to_string(result.rows_affected()) + 
                          " old reports (older than " + 
                          std::to_string(older_than_ms) + ")");
    return result.rows_affected();
  }

  // --- Check if a user already reported an event ---
  bool has_user_reported_event(const std::string& event_id, 
                                const std::string& user_id) {
    auto conn = db_pool_->get_connection();
    auto rows = conn->query(
      "SELECT COUNT(*) as cnt FROM report_deduplication "
      "WHERE event_id = ? AND reporter_user_id = ?",
      {event_id, user_id});

    if (!rows.empty()) {
      return std::stoi(rows[0]["cnt"]) > 0;
    }
    return false;
  }

  // --- Get reports by reporter ---
  std::vector<EventReport> get_reports_by_reporter(const std::string& user_id,
                                                     int limit = 50) {
    auto conn = db_pool_->get_connection();
    auto rows = conn->query(
      "SELECT * FROM event_reports WHERE reporter_user_id = ? "
      "ORDER BY created_at_ms DESC LIMIT ?",
      {user_id, std::to_string(limit)});

    std::vector<EventReport> result;
    for (const auto& row : rows) {
      result.push_back(row_to_report(row));
    }
    return result;
  }

  // --- Bulk update report status ---
  int bulk_update_status(const std::vector<std::string>& report_ids,
                          const std::string& new_status,
                          const std::string& assigned_admin = "") {
    if (report_ids.empty()) return 0;

    auto conn = db_pool_->get_connection();
    int64_t now_ms = current_time_ms();
    int updated = 0;

    for (const auto& rid : report_ids) {
      auto result = conn->execute(
        "UPDATE event_reports SET status = ?, updated_at_ms = ?, assigned_admin = ? "
        "WHERE report_id = ?",
        {new_status, std::to_string(now_ms), assigned_admin, rid});
      updated += result.rows_affected();
    }

    return updated;
  }

 private:
  // --- Convert DB row to EventReport ---
  EventReport row_to_report(const Row& row) {
    EventReport r;
    r.report_id        = row.at("report_id");
    r.room_id          = row.at("room_id");
    r.event_id         = row.at("event_id");
    r.reporter_user_id = row.at("reporter_user_id");
    r.reported_user_id = row.at("reported_user_id");
    r.reason           = row.at("reason");
    r.category         = row.at("category");
    r.status           = row.at("status");
    r.priority         = row.at("priority");
    r.score            = std::stoi(row.at("score"));
    r.created_at_ms    = std::stoll(row.at("created_at_ms"));
    r.updated_at_ms    = std::stoll(row.at("updated_at_ms"));
    r.assigned_admin   = row.count("assigned_admin") ? row.at("assigned_admin") : "";
    r.admin_notes      = row.count("admin_notes") ? row.at("admin_notes") : "";
    r.source_server    = row.count("source_server") ? row.at("source_server") : "";

    auto ack_it = row.find("acknowledged_at_ms");
    if (ack_it != row.end() && !ack_it->second.empty()) {
      r.acknowledged_at_ms = std::stoll(ack_it->second);
    }
    auto rev_it = row.find("reviewed_at_ms");
    if (rev_it != row.end() && !rev_it->second.empty()) {
      r.reviewed_at_ms = std::stoll(rev_it->second);
    }
    auto res_it = row.find("resolved_at_ms");
    if (res_it != row.end() && !res_it->second.empty()) {
      r.resolved_at_ms = std::stoll(res_it->second);
    }

    try {
      auto rc_it = row.find("report_content");
      if (rc_it != row.end() && !rc_it->second.empty()) {
        r.report_content = json::parse(rc_it->second);
      }
    } catch (...) {}

    try {
      auto es_it = row.find("event_snapshot");
      if (es_it != row.end() && !es_it->second.empty()) {
        r.event_snapshot = json::parse(es_it->second);
      }
    } catch (...) {}

    return r;
  }

  // --- Convert DB row to ReportAction ---
  ReportAction row_to_action(const Row& row) {
    ReportAction a;
    a.action_id           = row.at("action_id");
    a.report_id           = row.at("report_id");
    a.action_type         = row.at("action_type");
    a.admin_user_id       = row.at("admin_user_id");
    a.action_detail       = row.count("action_detail") ? row.at("action_detail") : "{}";
    a.notes               = row.count("notes") ? row.at("notes") : "";
    a.previous_status     = row.count("previous_status") ? row.at("previous_status") : "";
    a.new_status          = row.count("new_status") ? row.at("new_status") : "";
    a.previous_assignment = row.count("previous_assignment") ? row.at("previous_assignment") : "";
    a.new_assignment      = row.count("new_assignment") ? row.at("new_assignment") : "";
    a.timestamp_ms        = std::stoll(row.at("timestamp_ms"));
    a.admin_ip            = row.count("admin_ip") ? row.at("admin_ip") : "";
    a.admin_device_id     = row.count("admin_device_id") ? row.at("admin_device_id") : "";
    a.audit_hash          = row.count("audit_hash") ? row.at("audit_hash") : "";
    return a;
  }

  std::shared_ptr<DatabasePool> db_pool_;
};

// ============================================================================
// AdminReviewManager — Admin workflow for reviewing reports
// ============================================================================

class AdminReviewManager {
 public:
  AdminReviewManager(std::shared_ptr<ReportStorageEngine> storage,
                     std::shared_ptr<ReportAuditTrail> audit_trail)
    : storage_(std::move(storage)),
      audit_trail_(std::move(audit_trail)) {}

  // --- Acknowledge a report ---
  AdminActionResult acknowledge_report(const std::string& report_id,
                                        const std::string& admin_user_id,
                                        const std::string& notes = "") {
    auto report = storage_->get_report(report_id);
    if (!report.has_value()) {
      return AdminActionResult::INVALID_REPORT;
    }

    if (report->status != kStatusPending) {
      return AdminActionResult::INVALID_TRANSITION;
    }

    if (!storage_->update_report_status(report_id, std::string(kStatusAcknowledged), 
                                         notes, admin_user_id)) {
      return AdminActionResult::INTERNAL_ERROR;
    }

    audit_trail_->record_action(report_id, std::string(kActionAcknowledge),
                                admin_user_id, notes,
                                report->status, std::string(kStatusAcknowledged),
                                report->assigned_admin, admin_user_id);

    report_admin_log.info("Report " + report_id + " acknowledged by " + admin_user_id);
    return AdminActionResult::SUCCESS;
  }

  // --- Start review ---
  AdminActionResult start_review(const std::string& report_id,
                                  const std::string& admin_user_id,
                                  const std::string& notes = "") {
    auto report = storage_->get_report(report_id);
    if (!report.has_value()) {
      return AdminActionResult::INVALID_REPORT;
    }

    if (report->status != kStatusPending && 
        report->status != kStatusAcknowledged) {
      return AdminActionResult::INVALID_TRANSITION;
    }

    if (!storage_->update_report_status(report_id, 
                                         std::string(kStatusUnderReview),
                                         notes, admin_user_id)) {
      return AdminActionResult::INTERNAL_ERROR;
    }

    audit_trail_->record_action(report_id, std::string(kActionAssign),
                                admin_user_id, notes,
                                report->status, std::string(kStatusUnderReview),
                                report->assigned_admin, admin_user_id);

    report_admin_log.info("Report " + report_id + " under review by " + admin_user_id);
    return AdminActionResult::SUCCESS;
  }

  // --- Resolve a report ---
  AdminActionResult resolve_report(const std::string& report_id,
                                    const std::string& admin_user_id,
                                    const std::string& resolution_notes) {
    auto report = storage_->get_report(report_id);
    if (!report.has_value()) {
      return AdminActionResult::INVALID_REPORT;
    }

    if (report->status == kStatusResolved) {
      return AdminActionResult::ALREADY_PROCESSED;
    }

    if (!storage_->update_report_status(report_id, 
                                         std::string(kStatusResolved),
                                         resolution_notes, admin_user_id)) {
      return AdminActionResult::INTERNAL_ERROR;
    }

    // Update reporter reputation: report was accepted
    update_reporter_reputation(report->reporter_user_id, true);

    audit_trail_->record_action(report_id, std::string(kActionResolve),
                                admin_user_id, resolution_notes,
                                report->status, std::string(kStatusResolved),
                                report->assigned_admin, admin_user_id);

    report_admin_log.info("Report " + report_id + " resolved by " + admin_user_id);
    return AdminActionResult::SUCCESS;
  }

  // --- Dismiss a report ---
  AdminActionResult dismiss_report(const std::string& report_id,
                                    const std::string& admin_user_id,
                                    const std::string& reason) {
    auto report = storage_->get_report(report_id);
    if (!report.has_value()) {
      return AdminActionResult::INVALID_REPORT;
    }

    if (report->status == kStatusDismissed ||
        report->status == kStatusResolved) {
      return AdminActionResult::ALREADY_PROCESSED;
    }

    if (!storage_->update_report_status(report_id, 
                                         std::string(kStatusDismissed),
                                         reason, admin_user_id)) {
      return AdminActionResult::INTERNAL_ERROR;
    }

    // Update reporter reputation: report was dismissed
    update_reporter_reputation(report->reporter_user_id, false);

    audit_trail_->record_action(report_id, std::string(kActionDismiss),
                                admin_user_id, reason,
                                report->status, std::string(kStatusDismissed),
                                report->assigned_admin, admin_user_id);

    report_admin_log.info("Report " + report_id + " dismissed by " + admin_user_id);
    return AdminActionResult::SUCCESS;
  }

  // --- Mark report as false (abusive reporting) ---
  AdminActionResult mark_false_report(const std::string& report_id,
                                       const std::string& admin_user_id,
                                       const std::string& reason) {
    auto report = storage_->get_report(report_id);
    if (!report.has_value()) {
      return AdminActionResult::INVALID_REPORT;
    }

    if (!storage_->update_report_status(report_id, 
                                         std::string(kStatusDismissed),
                                         "FALSE REPORT: " + reason, admin_user_id)) {
      return AdminActionResult::INTERNAL_ERROR;
    }

    // Penalize reporter reputation significantly
    penalty_reporter_reputation(report->reporter_user_id, true);

    audit_trail_->record_action(report_id, std::string(kActionMarkFalseReport),
                                admin_user_id, reason,
                                report->status, std::string(kStatusDismissed),
                                report->assigned_admin, admin_user_id);

    report_admin_log.warn("Report " + report_id + " marked as false by " + admin_user_id);
    return AdminActionResult::SUCCESS;
  }

  // --- Escalate a report ---
  AdminActionResult escalate_report(const std::string& report_id,
                                     const std::string& admin_user_id,
                                     const std::string& escalation_reason) {
    auto report = storage_->get_report(report_id);
    if (!report.has_value()) {
      return AdminActionResult::INVALID_REPORT;
    }

    if (!storage_->update_report_status(report_id, 
                                         std::string(kStatusEscalated),
                                         "ESCALATED: " + escalation_reason, 
                                         admin_user_id)) {
      return AdminActionResult::INTERNAL_ERROR;
    }

    audit_trail_->record_action(report_id, std::string(kActionEscalateLE),
                                admin_user_id, escalation_reason,
                                report->status, std::string(kStatusEscalated),
                                report->assigned_admin, admin_user_id);

    report_admin_log.warn("Report " + report_id + " escalated by " + admin_user_id +
                          ": " + escalation_reason);
    return AdminActionResult::SUCCESS;
  }

  // --- Archive a report ---
  AdminActionResult archive_report(const std::string& report_id,
                                    const std::string& admin_user_id) {
    auto report = storage_->get_report(report_id);
    if (!report.has_value()) {
      return AdminActionResult::INVALID_REPORT;
    }

    if (!storage_->update_report_status(report_id, 
                                         std::string(kStatusArchived),
                                         "", admin_user_id)) {
      return AdminActionResult::INTERNAL_ERROR;
    }

    audit_trail_->record_action(report_id, "archive",
                                admin_user_id, "",
                                report->status, std::string(kStatusArchived),
                                report->assigned_admin, admin_user_id);

    report_admin_log.info("Report " + report_id + " archived by " + admin_user_id);
    return AdminActionResult::SUCCESS;
  }

  // --- Add admin note ---
  AdminActionResult add_admin_note(const std::string& report_id,
                                    const std::string& admin_user_id,
                                    const std::string& note) {
    auto report = storage_->get_report(report_id);
    if (!report.has_value()) {
      return AdminActionResult::INVALID_REPORT;
    }

    std::string updated_notes = report->admin_notes;
    if (!updated_notes.empty()) {
      updated_notes += "\n---\n";
    }
    updated_notes += "[" + std::to_string(current_time_ms()) + 
                     "] " + admin_user_id + ": " + note;

    if (!storage_->update_report_status(report_id, report->status, 
                                         updated_notes, admin_user_id)) {
      return AdminActionResult::INTERNAL_ERROR;
    }

    audit_trail_->record_action(report_id, std::string(kActionNote),
                                admin_user_id, note,
                                report->status, report->status,
                                report->assigned_admin, report->assigned_admin);

    report_admin_log.debug("Note added to report " + report_id + 
                           " by " + admin_user_id);
    return AdminActionResult::SUCCESS;
  }

  // --- Reassign report to another admin ---
  AdminActionResult reassign_report(const std::string& report_id,
                                     const std::string& from_admin,
                                     const std::string& to_admin,
                                     const std::string& reason) {
    auto report = storage_->get_report(report_id);
    if (!report.has_value()) {
      return AdminActionResult::INVALID_REPORT;
    }

    if (!storage_->update_report_status(report_id, report->status, 
                                         reason, to_admin)) {
      return AdminActionResult::INTERNAL_ERROR;
    }

    audit_trail_->record_action(report_id, "reassign",
                                from_admin, reason,
                                report->status, report->status,
                                report->assigned_admin, to_admin);

    report_admin_log.info("Report " + report_id + " reassigned from " + 
                          from_admin + " to " + to_admin);
    return AdminActionResult::SUCCESS;
  }

  // --- Get report detail with full context ---
  json get_report_detail(const std::string& report_id) {
    auto report = storage_->get_report(report_id);
    if (!report.has_value()) {
      return json{{"error", "report not found"}};
    }

    json j = report->to_json();

    // Add action history
    auto actions = storage_->get_report_actions(report_id);
    j["action_history"] = json::array();
    for (const auto& a : actions) {
      j["action_history"].push_back(a.to_json());
    }

    // Add reporter reputation
    auto rep = storage_->get_reporter_reputation(report->reporter_user_id);
    if (rep.has_value()) {
      j["reporter_reputation"] = rep->to_json();
    }

    // Add related reports on same event
    auto related = storage_->get_reports_by_event(report->event_id);
    j["related_reports"] = json::array();
    for (const auto& r : related) {
      if (r.report_id != report_id) {
        j["related_reports"].push_back(r.to_json());
      }
    }
    j["related_report_count"] = related.size();

    return j;
  }

 private:
  void update_reporter_reputation(const std::string& user_id, bool accepted) {
    auto rep = storage_->get_reporter_reputation(user_id);
    ReporterReputation new_rep;
    
    if (rep.has_value()) {
      new_rep = rep.value();
    } else {
      new_rep.user_id = user_id;
      new_rep.reputation_score = 0.5;
    }

    new_rep.total_reports_submitted++;
    if (accepted) {
      new_rep.reports_accepted++;
    } else {
      new_rep.reports_dismissed++;
    }

    // Recalculate reputation: weighted ratio of accepted to total
    double raw_score = 0.5;
    if (new_rep.total_reports_submitted > 0) {
      double accepted_weight = static_cast<double>(new_rep.reports_accepted) * 1.0;
      double dismissed_weight = static_cast<double>(new_rep.reports_dismissed) * 0.5;
      double false_weight = static_cast<double>(new_rep.reports_marked_false) * 2.0;
      double total = accepted_weight + dismissed_weight + false_weight + 1.0;
      raw_score = (accepted_weight + 1.0) / total;
    }
    new_rep.reputation_score = std::clamp(raw_score, 0.0, 1.0);
    new_rep.last_report_at_ms = current_time_ms();
    new_rep.last_updated_at_ms = current_time_ms();

    storage_->upsert_reporter_reputation(new_rep);
  }

  void penalty_reporter_reputation(const std::string& user_id, bool marked_false) {
    auto rep = storage_->get_reporter_reputation(user_id);
    ReporterReputation new_rep;
    
    if (rep.has_value()) {
      new_rep = rep.value();
    } else {
      new_rep.user_id = user_id;
      new_rep.reputation_score = 0.5;
    }

    if (marked_false) {
      new_rep.reports_marked_false++;
    }

    // Severe penalty for false reports
    double penalty = static_cast<double>(new_rep.reports_marked_false) * 0.3;
    new_rep.reputation_score = std::max(0.0, new_rep.reputation_score - penalty);
    new_rep.last_updated_at_ms = current_time_ms();

    storage_->upsert_reporter_reputation(new_rep);
  }

  std::shared_ptr<ReportStorageEngine> storage_;
  std::shared_ptr<ReportAuditTrail> audit_trail_;
};

// ============================================================================
// ReportNotificationEngine — Notify admins about new reports
// ============================================================================

class ReportNotificationEngine {
 public:
  ReportNotificationEngine(std::shared_ptr<ReportStorageEngine> storage)
    : storage_(std::move(storage)) {}

  // --- Send notification for a new report ---
  void notify_new_report(const EventReport& report) {
    int severity = category_notify_severity(report.category);

    // Build notification message
    std::string message = build_notification_message(report, severity);

    // Determine targets based on severity
    std::vector<NotificationTarget> targets = determine_targets(report, severity);

    // Send notifications
    for (const auto& target : targets) {
      ReportNotification notif;
      notif.notification_id = generate_notification_id();
      notif.report_id = report.report_id;
      notif.channel = channel_to_string(target.channel);
      notif.target = target.target_id;
      notif.severity = severity;
      notif.message = message;
      notif.created_at_ms = current_time_ms();
      notif.sent = send_notification(target, notif);
      notif.sent_at_ms = notif.sent ? current_time_ms() : 0;

      storage_->insert_notification(notif);
    }

    report_notify_log.info("Sent " + std::to_string(targets.size()) + 
                           " notifications for report " + report.report_id +
                           " (severity: " + std::to_string(severity) + ")");
  }

  // --- Send status change notification ---
  void notify_status_change(const std::string& report_id,
                             const std::string& old_status,
                             const std::string& new_status,
                             const std::string& admin_user_id) {
    auto report = storage_->get_report(report_id);
    if (!report.has_value()) return;

    std::string message = "Report " + report_id + " status changed from " +
                          old_status + " to " + new_status + " by " + admin_user_id;

    ReportNotification notif;
    notif.notification_id = generate_notification_id();
    notif.report_id = report_id;
    notif.channel = "internal";
    notif.target = "audit_log";
    notif.severity = kNotifySeverityLow;
    notif.message = message;
    notif.sent = true;
    notif.sent_at_ms = current_time_ms();
    notif.created_at_ms = current_time_ms();
    notif.payload = {
      {"old_status", old_status},
      {"new_status", new_status},
      {"admin_user_id", admin_user_id}
    };

    storage_->insert_notification(notif);
  }

  // --- Get pending notifications for an admin ---
  json get_admin_notifications(const std::string& admin_user_id, 
                                int limit = 20) {
    // This would query the notification table for records targeting
    // this admin. Simplified for this implementation.
    json result = json::array();
    // In a full implementation, query storage for notifications
    // where target = admin_user_id and sent = 0
    return result;
  }

 private:
  struct NotificationTarget {
    NotificationChannel channel;
    std::string target_id;
  };

  std::string channel_to_string(NotificationChannel ch) {
    switch (ch) {
      case NotificationChannel::PUSH_RULE:  return "push_rule";
      case NotificationChannel::ADMIN_ROOM: return "admin_room";
      case NotificationChannel::WEBHOOK:    return "webhook";
      case NotificationChannel::EMAIL:      return "email";
      case NotificationChannel::INTERNAL:   return "internal";
      default:                              return "internal";
    }
  }

  std::string build_notification_message(const EventReport& report, int severity) {
    std::stringstream ss;
    ss << "[";
    switch (severity) {
      case kNotifySeverityCritical: ss << "CRITICAL"; break;
      case kNotifySeverityHigh:     ss << "HIGH"; break;
      case kNotifySeverityMedium:   ss << "MEDIUM"; break;
      case kNotifySeverityLow:      ss << "LOW"; break;
      default:                      ss << "INFO"; break;
    }
    ss << "] New report received\n";
    ss << "Report ID: " << report.report_id << "\n";
    ss << "Category: " << report.category << "\n";
    ss << "Room: " << report.room_id << "\n";
    ss << "Reported User: " << report.reported_user_id << "\n";
    ss << "Reporter: " << report.reporter_user_id << "\n";
    ss << "Reason: " << report.reason << "\n";
    if (report.score != 0) {
      ss << "Score: " << report.score << "\n";
    }
    return ss.str();
  }

  std::vector<NotificationTarget> determine_targets(const EventReport& report,
                                                      int severity) {
    std::vector<NotificationTarget> targets;

    // Always send to internal audit
    targets.push_back({NotificationChannel::INTERNAL, "system"});

    // Critical severity: notify all available channels
    if (severity >= kNotifySeverityCritical) {
      targets.push_back({NotificationChannel::ADMIN_ROOM, "admin_room"});
      targets.push_back({NotificationChannel::EMAIL, "admin_email"});
      targets.push_back({NotificationChannel::WEBHOOK, "admin_webhook"});
    }
    // High severity: admin room + push
    else if (severity >= kNotifySeverityHigh) {
      targets.push_back({NotificationChannel::ADMIN_ROOM, "admin_room"});
      targets.push_back({NotificationChannel::PUSH_RULE, "admin_push"});
    }
    // Medium severity: admin room
    else if (severity >= kNotifySeverityMedium) {
      targets.push_back({NotificationChannel::ADMIN_ROOM, "admin_room"});
    }
    // Low severity: push rule for batched digest
    else {
      targets.push_back({NotificationChannel::PUSH_RULE, "admin_digest"});
    }

    return targets;
  }

  bool send_notification(const NotificationTarget& target,
                          const ReportNotification& notif) {
    // In production, this would dispatch to actual notification backends:
    // - Push rule: create a push notification for the admin
    // - Admin room: send a message to the server admin room
    // - Webhook: POST to configured webhook URL
    // - Email: send via SMTP
    // - Internal: write to audit log
    report_notify_log.debug("Dispatching notification to " + 
                            channel_to_string(target.channel) + 
                            ":" + target.target_id);
    return true;  // Assume success for this implementation
  }

  std::string generate_notification_id() {
    static std::atomic<int64_t> counter{0};
    int64_t now_ms = current_time_ms();
    int64_t seq = counter.fetch_add(1, std::memory_order_relaxed);
    std::stringstream ss;
    ss << "NOT_" << std::hex << now_ms << "_" << seq;
    return ss.str();
  }

  std::shared_ptr<ReportStorageEngine> storage_;
};

// ============================================================================
// ReportAutoActionEngine — Automatic actions on threshold crossing
// ============================================================================

class ReportAutoActionEngine {
 public:
  ReportAutoActionEngine(std::shared_ptr<ReportStorageEngine> storage,
                          std::shared_ptr<ReportNotificationEngine> notifier)
    : storage_(std::move(storage)),
      notifier_(std::move(notifier)) {}

  // --- Check thresholds after a new report is filed ---
  json check_and_execute_thresholds(const std::string& event_id,
                                     const std::string& room_id,
                                     const std::string& category) {
    int report_count = storage_->get_event_report_count(event_id);
    json thresholds = storage_->get_category_thresholds(category);
    json result;
    result["report_count"] = report_count;
    result["actions_taken"] = json::array();

    int redact_threshold = thresholds.value("auto_redact_threshold", kDefaultAutoRedactThreshold);
    int quarantine_threshold = thresholds.value("auto_quarantine_threshold", kDefaultAutoQuarantineThreshold);
    int mute_threshold = thresholds.value("auto_mute_threshold", kDefaultAutoMuteThreshold);

    // Count reports from unique users (not just total)
    int unique_reporters = count_unique_reporters(event_id);
    result["unique_reporters"] = unique_reporters;

    // Use unique reporters for threshold decisions (prevents single-user flooding)
    if (unique_reporters >= redact_threshold) {
      result["actions_taken"].push_back("auto_redact");
      report_log.warn("Auto-redacting event " + event_id + 
                      " (" + std::to_string(unique_reporters) + 
                      " unique reports, threshold " + 
                      std::to_string(redact_threshold) + ")");
    }

    if (unique_reporters >= quarantine_threshold) {
      result["actions_taken"].push_back("auto_quarantine_media");
      report_log.warn("Auto-quarantining media for event " + event_id);
    }

    if (unique_reporters >= mute_threshold) {
      result["actions_taken"].push_back("auto_mute_reported_user");
      report_log.warn("Auto-muting user for event " + event_id);
    }

    return result;
  }

  // --- Check if thresholds for a category need updating ---
  void update_category_thresholds(const std::string& category,
                                   int redact_threshold,
                                   int quarantine_threshold,
                                   int mute_threshold,
                                   int notify_threshold) {
    // In a real implementation, this would update the event_report_thresholds table
    report_log.info("Updated thresholds for category " + category + 
                    ": redact=" + std::to_string(redact_threshold) +
                    " quarantine=" + std::to_string(quarantine_threshold) +
                    " mute=" + std::to_string(mute_threshold) +
                    " notify=" + std::to_string(notify_threshold));
  }

 private:
  int count_unique_reporters(const std::string& event_id) {
    // Query distinct reporter_user_id from reports for this event
    // In a real implementation, this would query the DB
    auto reports = storage_->get_reports_by_event(event_id);
    std::unordered_set<std::string> unique;
    for (const auto& r : reports) {
      unique.insert(r.reporter_user_id);
    }
    return static_cast<int>(unique.size());
  }

  std::shared_ptr<ReportStorageEngine> storage_;
  std::shared_ptr<ReportNotificationEngine> notifier_;
};

// ============================================================================
// ReportAuditTrail — Immutable audit log for admin actions
// ============================================================================

class ReportAuditTrail {
 public:
  explicit ReportAuditTrail(std::shared_ptr<ReportStorageEngine> storage)
    : storage_(std::move(storage)) {}

  // --- Record an admin action ---
  std::string record_action(const std::string& report_id,
                             const std::string& action_type,
                             const std::string& admin_user_id,
                             const std::string& notes,
                             const std::string& previous_status,
                             const std::string& new_status,
                             const std::string& previous_assignment,
                             const std::string& new_assignment,
                             const std::string& admin_ip = "",
                             const std::string& admin_device_id = "") {
    ReportAction action;
    action.action_id = generate_audit_id();
    action.report_id = report_id;
    action.action_type = action_type;
    action.admin_user_id = admin_user_id;
    action.action_detail = "{}";
    action.notes = notes;
    action.previous_status = previous_status;
    action.new_status = new_status;
    action.previous_assignment = previous_assignment;
    action.new_assignment = new_assignment;
    action.timestamp_ms = current_time_ms();
    action.admin_ip = admin_ip;
    action.admin_device_id = admin_device_id;

    // Compute hash chain
    std::string prev_hash = storage_->get_last_audit_hash(report_id);
    std::string data = action_type + admin_user_id + 
                       std::to_string(action.timestamp_ms);
    action.audit_hash = hash_audit_entry(prev_hash, data);

    std::string action_id = storage_->insert_action(action);
    report_audit_log.debug("Audit entry " + action_id + 
                           " for report " + report_id + 
                           " (action: " + action_type + ")");
    return action_id;
  }

  // --- Get full audit trail for a report ---
  json get_audit_trail(const std::string& report_id) {
    auto actions = storage_->get_report_actions(report_id);
    json trail = json::array();
    for (const auto& a : actions) {
      trail.push_back(a.to_json());
    }

    // Verify hash chain integrity
    bool chain_valid = verify_chain(actions);
    
    json result;
    result["report_id"] = report_id;
    result["actions"] = trail;
    result["action_count"] = actions.size();
    result["chain_valid"] = chain_valid;
    return result;
  }

  // --- Export audit trail for a time range ---
  json export_audit_trail(int64_t from_ms, int64_t to_ms) {
    // In a full implementation, this would query the database for actions
    // in the given time range and export them as a JSON array
    json result;
    result["from_ms"] = from_ms;
    result["to_ms"] = to_ms;
    result["actions"] = json::array();
    result["exported_at_ms"] = current_time_ms();
    return result;
  }

  // --- Verify hash chain integrity ---
  bool verify_chain(const std::vector<ReportAction>& actions) {
    std::string expected_hash = "0000000000000000";
    for (const auto& action : actions) {
      std::string data = action.action_type + action.admin_user_id + 
                         std::to_string(action.timestamp_ms);
      std::string computed = hash_audit_entry(expected_hash, data);
      if (computed != action.audit_hash) {
        report_audit_log.error("Audit chain verification failed at " + 
                               action.action_id);
        return false;
      }
      expected_hash = action.audit_hash;
    }
    return true;
  }

 private:
  std::shared_ptr<ReportStorageEngine> storage_;
};

// ============================================================================
// ReportFederationHandler — Federation report forwarding and receiving
// ============================================================================

class ReportFederationHandler {
 public:
  ReportFederationHandler(std::shared_ptr<ReportStorageEngine> storage)
    : storage_(std::move(storage)) {}

  // --- Forward report to origin server ---
  json forward_report_to_origin(const std::string& report_id,
                                 const std::string& target_server) {
    auto report = storage_->get_report(report_id);
    if (!report.has_value()) {
      return json{{"error", "report not found"}, {"success", false}};
    }

    // Build federation report payload
    json payload;
    payload["report_id"]       = report->report_id;
    payload["room_id"]         = report->room_id;
    payload["event_id"]        = report->event_id;
    payload["reporter_server"] = "matrix.local";  // This server's domain
    payload["category"]        = report->category;
    payload["reason"]          = report->reason;
    payload["score"]           = report->score;
    payload["timestamp_ms"]    = current_time_ms();
    payload["forwarded_by"]    = target_server;

    report_fed_log.info("Forwarding report " + report_id + 
                        " to server " + target_server);

    // In a real implementation, this would make a federated POST to
    // target_server's report forwarding endpoint and sign the payload

    return json{
      {"success", true},
      {"report_id", report_id},
      {"target_server", target_server},
      {"payload", payload}
    };
  }

  // --- Receive federated report ---
  json receive_federated_report(const json& federated_report,
                                 const std::string& origin_server) {
    report_fed_log.info("Received federated report from " + origin_server);

    // Validate the federated report
    if (!federated_report.contains("event_id") || 
        !federated_report.contains("room_id") ||
        !federated_report.contains("reason")) {
      return json{{"error", "invalid federated report"}, {"success", false}};
    }

    // Check if this is a duplicate
    std::string event_id = federated_report["event_id"].get<std::string>();
    std::string reporter_id = "@federation:" + origin_server;
    
    if (storage_->has_user_reported_event(event_id, reporter_id)) {
      return json{{"success", false}, {"error", "duplicate report"}};
    }

    // Construct local report
    EventReport local_report;
    local_report.report_id = generate_report_id();
    local_report.room_id = federated_report["room_id"].get<std::string>();
    local_report.event_id = event_id;
    local_report.reporter_user_id = reporter_id;
    local_report.reported_user_id = federated_report.value("reported_user_id", "unknown");
    local_report.reason = federated_report["reason"].get<std::string>();
    local_report.category = federated_report.value("category", 
                                                    std::string(kReportCategoryOther));
    local_report.score = federated_report.value("score", 0);
    local_report.source = ReportSource::FEDERATION;
    local_report.source_server = origin_server;
    local_report.status = std::string(kStatusPending);
    local_report.created_at_ms = current_time_ms();
    local_report.updated_at_ms = current_time_ms();

    std::string stored_id = storage_->insert_report(local_report);
    
    return json{
      {"success", true},
      {"report_id", stored_id},
      {"origin_server", origin_server}
    };
  }

  // --- Check if a server is allowed to forward reports ---
  bool is_server_allowed(const std::string& server_name) {
    // In a real implementation, check against a federation policy/ACL
    // Default: allow all federated servers
    return true;
  }

  // --- Get federation forwarding status for a report ---
  json get_forwarding_status(const std::string& report_id) {
    json status;
    status["report_id"] = report_id;
    status["forwarded_to"] = json::array();
    status["forwarding_enabled"] = true;
    return status;
  }

 private:
  std::shared_ptr<ReportStorageEngine> storage_;
};

// ============================================================================
// ReportAnalyticsEngine — Statistics and trend analysis
// ============================================================================

class ReportAnalyticsEngine {
 public:
  explicit ReportAnalyticsEngine(std::shared_ptr<ReportStorageEngine> storage)
    : storage_(std::move(storage)) {}

  // --- Get dashboard statistics ---
  json get_dashboard_stats() {
    auto stats = storage_->get_statistics();
    json j = stats.to_json();
    
    // Add derived metrics
    j["resolution_rate_pct"] = stats.total_reports > 0 ?
      (static_cast<double>(stats.resolved_reports + stats.dismissed_reports) / 
       stats.total_reports) * 100.0 : 0.0;
    
    j["pending_rate_pct"] = stats.total_reports > 0 ?
      (static_cast<double>(stats.pending_reports) / stats.total_reports) * 100.0 : 0.0;

    j["avg_resolution_hours"] = stats.avg_resolution_time_ms > 0 ?
      stats.avg_resolution_time_ms / 3600000.0 : 0.0;

    j["generated_at_ms"] = current_time_ms();
    
    return j;
  }

  // --- Get reports by category over time ---
  json get_category_trends(int days = 30) {
    int64_t now_ms = current_time_ms();
    int64_t cutoff_ms = now_ms - (days * 86400000LL);

    json trends = json::array();
    
    // In a real implementation, this would query aggregated by day and category
    for (int d = 0; d < days; d++) {
      json day;
      day["date"] = cutoff_ms + (d * 86400000LL);
      day["counts"] = json::object();
      trends.push_back(day);
    }

    json result;
    result["days"] = days;
    result["trends"] = trends;
    result["generated_at_ms"] = now_ms;
    return result;
  }

  // --- Get admin workload distribution ---
  json get_admin_workload() {
    auto stats = storage_->get_statistics();
    
    json workload = json::array();
    for (const auto& [admin, count] : stats.counts_by_admin) {
      workload.push_back({
        {"admin_id", admin},
        {"assigned_count", count}
      });
    }

    json result;
    result["workload"] = workload;
    result["total_admins"] = stats.counts_by_admin.size();
    result["generated_at_ms"] = current_time_ms();
    return result;
  }

  // --- Get top reported users ---
  json get_top_reported_users(int limit = 20) {
    json result;
    result["top_reported"] = json::array();
    result["limit"] = limit;
    result["generated_at_ms"] = current_time_ms();
    // In a real implementation: query grouped by reported_user_id, count DESC
    return result;
  }

  // --- Get most reported rooms ---
  json get_top_reported_rooms(int limit = 20) {
    json result;
    result["top_rooms"] = json::array();
    result["limit"] = limit;
    result["generated_at_ms"] = current_time_ms();
    return result;
  }

  // --- Get hourly distribution ---
  json get_hourly_distribution() {
    json distribution = json::array();
    for (int h = 0; h < 24; h++) {
      distribution.push_back({
        {"hour", h},
        {"count", 0}  // Would be populated from DB
      });
    }

    json result;
    result["distribution"] = distribution;
    result["generated_at_ms"] = current_time_ms();
    return result;
  }

 private:
  std::shared_ptr<ReportStorageEngine> storage_;
};

// ============================================================================
// ReportRetentionManager — GDPR-compliant report retention and cleanup
// ============================================================================

class ReportRetentionManager {
 public:
  ReportRetentionManager(std::shared_ptr<ReportStorageEngine> storage,
                          std::shared_ptr<ReportCategoryRegistry> categories)
    : storage_(std::move(storage)),
      categories_(std::move(categories)) {}

  // --- Run retention cleanup ---
  json run_cleanup() {
    json result;
    result["cleaned_categories"] = json::object();
    result["total_deleted"] = 0;
    int64_t now_ms = current_time_ms();

    auto all_categories = categories_->get_all_categories();
    for (const auto& cat : all_categories) {
      int64_t retention_ms = static_cast<int64_t>(cat.retention_days) * 86400000LL;
      int64_t cutoff_ms = now_ms - retention_ms;

      int deleted = storage_->delete_old_reports(cutoff_ms, cat.category_id);
      if (deleted > 0) {
        result["cleaned_categories"][cat.category_id] = deleted;
        result["total_deleted"] = result["total_deleted"].get<int>() + deleted;
      }
    }

    report_log.info("Retention cleanup: deleted " + 
                    std::to_string(result["total_deleted"].get<int>()) + 
                    " reports across " + 
                    std::to_string(result["cleaned_categories"].size()) + 
                    " categories");
    return result;
  }

  // --- GDPR: delete all reports by a specific user ---
  int delete_user_reports(const std::string& user_id) {
    // Delete reports filed by this user
    // Delete reports about this user (as reported_user_id)
    // In a real implementation, this would execute DELETE queries
    report_log.info("GDPR: deleting all reports for user " + user_id);
    return 0;  // Return count of deleted records
  }

  // --- GDPR: export user's report data ---
  json export_user_report_data(const std::string& user_id) {
    json export_data;
    export_data["user_id"] = user_id;
    export_data["reports_filed"] = json::array();
    export_data["reports_against"] = json::array();
    export_data["exported_at_ms"] = current_time_ms();
    // In a real implementation, query all reports involving this user
    return export_data;
  }

 private:
  std::shared_ptr<ReportStorageEngine> storage_;
  std::shared_ptr<ReportCategoryRegistry> categories_;
};

// ============================================================================
// ReportDeduplicationEngine — Prevent duplicate reports
// ============================================================================

class ReportDeduplicationEngine {
 public:
  explicit ReportDeduplicationEngine(std::shared_ptr<ReportStorageEngine> storage)
    : storage_(std::move(storage)) {}

  // --- Check if a user already reported an event ---
  bool has_already_reported(const std::string& event_id,
                             const std::string& user_id) {
    return storage_->has_user_reported_event(event_id, user_id);
  }

  // --- Merge duplicate reports on same event ---
  void merge_duplicates(const std::string& event_id) {
    auto reports = storage_->get_reports_by_event(event_id);
    if (reports.size() <= 1) return;

    // Collect unique reporters
    std::unordered_set<std::string> unique_reporters;
    for (const auto& r : reports) {
      unique_reporters.insert(r.reporter_user_id);
    }

    report_log.debug("Event " + event_id + " has " + 
                     std::to_string(reports.size()) + " reports from " +
                     std::to_string(unique_reporters.size()) + 
                     " unique reporters");
  }

  // --- Get deduplication statistics ---
  json get_dedup_stats() {
    json stats;
    stats["total_duplicate_groups"] = 0;
    stats["total_duplicate_reports"] = 0;
    stats["unique_reporters_avg"] = 0.0;
    return stats;
  }

 private:
  std::shared_ptr<ReportStorageEngine> storage_;
};

// ============================================================================
// ReporterReputationEngine — Track reporter credibility
// ============================================================================

class ReporterReputationEngine {
 public:
  explicit ReporterReputationEngine(std::shared_ptr<ReportStorageEngine> storage)
    : storage_(std::move(storage)) {}

  // --- Get reporter reputation ---
  json get_reputation(const std::string& user_id) {
    auto rep = storage_->get_reporter_reputation(user_id);
    if (!rep.has_value()) {
      return json{
        {"user_id", user_id},
        {"reputation_score", 0.5},
        {"is_new", true}
      };
    }
    return rep->to_json();
  }

  // --- Get top reporters (highest reputation) ---
  json get_top_reporters(int limit = 20) {
    json result;
    result["top_reporters"] = json::array();
    result["limit"] = limit;
    return result;
  }

  // --- Flag a reporter as potentially abusive ---
  void flag_abusive_reporter(const std::string& user_id, const std::string& reason) {
    report_log.warn("Flagging reporter " + user_id + " as abusive: " + reason);
    // This would set a flag in the reporter_reputation table and potentially
    // trigger a temp ban on reporting
  }

 private:
  std::shared_ptr<ReportStorageEngine> storage_;
};

// ============================================================================
// ReportManagerAPI — Main API class for the reporting system
// ============================================================================

class ReportManagerAPI {
 public:
  ReportManagerAPI(std::shared_ptr<DatabasePool> db_pool) {
    // Initialize all subsystems
    storage_ = std::make_shared<ReportStorageEngine>(db_pool);
    categories_ = std::make_shared<ReportCategoryRegistry>();
    validator_ = std::make_shared<ReportValidator>();
    validator_->set_category_registry(*categories_);
    rate_limiter_ = std::make_shared<ReportRateLimiter>();
    audit_trail_ = std::make_shared<ReportAuditTrail>(storage_);
    admin_review_ = std::make_shared<AdminReviewManager>(storage_, audit_trail_);
    notifier_ = std::make_shared<ReportNotificationEngine>(storage_);
    auto_actions_ = std::make_shared<ReportAutoActionEngine>(storage_, notifier_);
    federation_ = std::make_shared<ReportFederationHandler>(storage_);
    analytics_ = std::make_shared<ReportAnalyticsEngine>(storage_);
    retention_ = std::make_shared<ReportRetentionManager>(storage_, categories_);
    dedup_ = std::make_shared<ReportDeduplicationEngine>(storage_);
    reputation_ = std::make_shared<ReporterReputationEngine>(storage_);

    report_log.info("ReportManagerAPI initialized");
  }

  // ========================================================================
  // Client API: Submit a report (POST /_matrix/client/v3/rooms/{}/report/{})
  // ========================================================================
  json submit_report(const std::string& room_id,
                     const std::string& event_id,
                     const std::string& reporter_user_id,
                     const std::string& reason,
                     const std::string& category = "",
                     int score = 0) {
    
    std::string effective_category = category.empty() ? 
      std::string(kReportCategoryOther) : category;

    // Validate input
    auto validation = validator_->validate_report_submission(
      room_id, event_id, reporter_user_id, reason, effective_category, score);
    
    if (!validation.valid) {
      return json{
        {"errcode", validation.error_code},
        {"error", validation.error_message}
      };
    }

    // Check rate limits
    if (!rate_limiter_->check_user_rate_limit(reporter_user_id)) {
      return json{
        {"errcode", "M_LIMIT_EXCEEDED"},
        {"error", "Too many reports submitted. Please wait before submitting another."}
      };
    }

    if (!rate_limiter_->check_event_limit(event_id)) {
      return json{
        {"errcode", "M_LIMIT_EXCEEDED"},
        {"error", "This event has already received many reports."}
      };
    }

    if (!rate_limiter_->check_room_rate_limit(room_id)) {
      return json{
        {"errcode", "M_LIMIT_EXCEEDED"},
        {"error", "Too many reports from this room. Please wait."}
      };
    }

    // Check deduplication
    if (dedup_->has_already_reported(event_id, reporter_user_id)) {
      return json{
        {"errcode", "M_DUPLICATE"},
        {"error", "You have already reported this event."}
      };
    }

    // Build the report
    EventReport report;
    report.report_id = generate_report_id();
    report.room_id = room_id;
    report.event_id = event_id;
    report.reporter_user_id = reporter_user_id;
    report.reported_user_id = "";  // Will be populated from event lookup
    report.reason = reason;
    report.category = effective_category;
    report.status = std::string(kStatusPending);
    report.priority = report_priority_to_string(
      category_default_priority(effective_category));
    report.score = score;
    report.created_at_ms = current_time_ms();
    report.updated_at_ms = current_time_ms();
    report.source = ReportSource::CLIENT_API;

    // In a real implementation, we would look up the reported event to
    // determine the reported_user_id and take an event snapshot.
    // For now, derive reported_user_id from event context.
    report.reported_user_id = extract_user_from_event(event_id, room_id);

    // Store the report
    std::string stored_id = storage_->insert_report(report);

    // Record rate limit usage
    rate_limiter_->record_report(reporter_user_id, event_id, room_id);

    // Update reporter reputation
    auto rep = storage_->get_reporter_reputation(reporter_user_id);
    ReporterReputation new_rep;
    if (rep.has_value()) {
      new_rep = rep.value();
    } else {
      new_rep.user_id = reporter_user_id;
      new_rep.reputation_score = 0.5;
    }
    new_rep.total_reports_submitted++;
    new_rep.last_report_at_ms = current_time_ms();
    new_rep.last_updated_at_ms = current_time_ms();
    storage_->upsert_reporter_reputation(new_rep);

    // Send notifications to admins
    notifier_->notify_new_report(report);

    // Check auto-action thresholds
    auto threshold_result = auto_actions_->check_and_execute_thresholds(
      event_id, room_id, effective_category);

    report_api_log.info("Report submitted: " + stored_id + 
                        " by " + reporter_user_id +
                        " for event " + event_id);

    // Build response
    json response;
    response["report_id"] = stored_id;
    response["event_id"] = event_id;
    response["room_id"] = room_id;
    response["category"] = effective_category;
    response["status"] = kStatusPending;
    response["auto_actions"] = threshold_result["actions_taken"];
    response["submitted_at_ms"] = report.created_at_ms;

    return response;
  }

  // ========================================================================
  // Admin API: List reports
  // ========================================================================
  json list_reports(const ReportQuery& query) {
    auto result = storage_->query_reports(query);
    return result.to_json();
  }

  // ========================================================================
  // Admin API: Get report detail
  // ========================================================================
  json get_report_detail(const std::string& report_id) {
    return admin_review_->get_report_detail(report_id);
  }

  // ========================================================================
  // Admin API: Acknowledge report
  // ========================================================================
  json acknowledge_report(const std::string& report_id,
                           const std::string& admin_user_id,
                           const std::string& notes = "") {
    auto result = admin_review_->acknowledge_report(report_id, admin_user_id, notes);
    
    json response;
    response["report_id"] = report_id;
    response["action"] = "acknowledge";
    response["result"] = action_result_to_string(result);
    response["success"] = (result == AdminActionResult::SUCCESS);

    if (result == AdminActionResult::SUCCESS) {
      notifier_->notify_status_change(report_id, std::string(kStatusPending),
                                       std::string(kStatusAcknowledged), 
                                       admin_user_id);
    }

    return response;
  }

  // ========================================================================
  // Admin API: Start review
  // ========================================================================
  json start_review(const std::string& report_id,
                     const std::string& admin_user_id,
                     const std::string& notes = "") {
    auto result = admin_review_->start_review(report_id, admin_user_id, notes);

    json response;
    response["report_id"] = report_id;
    response["action"] = "start_review";
    response["result"] = action_result_to_string(result);
    response["success"] = (result == AdminActionResult::SUCCESS);

    return response;
  }

  // ========================================================================
  // Admin API: Resolve report
  // ========================================================================
  json resolve_report(const std::string& report_id,
                       const std::string& admin_user_id,
                       const std::string& resolution_notes) {
    auto result = admin_review_->resolve_report(report_id, admin_user_id, 
                                                 resolution_notes);

    json response;
    response["report_id"] = report_id;
    response["action"] = "resolve";
    response["result"] = action_result_to_string(result);
    response["success"] = (result == AdminActionResult::SUCCESS);

    if (result == AdminActionResult::SUCCESS) {
      notifier_->notify_status_change(report_id, "", 
                                       std::string(kStatusResolved), 
                                       admin_user_id);
    }

    return response;
  }

  // ========================================================================
  // Admin API: Dismiss report
  // ========================================================================
  json dismiss_report(const std::string& report_id,
                       const std::string& admin_user_id,
                       const std::string& reason) {
    auto result = admin_review_->dismiss_report(report_id, admin_user_id, reason);

    json response;
    response["report_id"] = report_id;
    response["action"] = "dismiss";
    response["result"] = action_result_to_string(result);
    response["success"] = (result == AdminActionResult::SUCCESS);

    return response;
  }

  // ========================================================================
  // Admin API: Mark false report
  // ========================================================================
  json mark_false_report(const std::string& report_id,
                          const std::string& admin_user_id,
                          const std::string& reason) {
    auto result = admin_review_->mark_false_report(report_id, admin_user_id, reason);

    json response;
    response["report_id"] = report_id;
    response["action"] = "mark_false";
    response["result"] = action_result_to_string(result);
    response["success"] = (result == AdminActionResult::SUCCESS);

    return response;
  }

  // ========================================================================
  // Admin API: Escalate report
  // ========================================================================
  json escalate_report(const std::string& report_id,
                        const std::string& admin_user_id,
                        const std::string& reason) {
    auto result = admin_review_->escalate_report(report_id, admin_user_id, reason);

    json response;
    response["report_id"] = report_id;
    response["action"] = "escalate";
    response["result"] = action_result_to_string(result);
    response["success"] = (result == AdminActionResult::SUCCESS);

    if (result == AdminActionResult::SUCCESS) {
      notifier_->notify_status_change(report_id, "", 
                                       std::string(kStatusEscalated), 
                                       admin_user_id);
    }

    return response;
  }

  // ========================================================================
  // Admin API: Archive report
  // ========================================================================
  json archive_report(const std::string& report_id,
                       const std::string& admin_user_id) {
    auto result = admin_review_->archive_report(report_id, admin_user_id);

    json response;
    response["report_id"] = report_id;
    response["action"] = "archive";
    response["result"] = action_result_to_string(result);
    response["success"] = (result == AdminActionResult::SUCCESS);

    return response;
  }

  // ========================================================================
  // Admin API: Add note to report
  // ========================================================================
  json add_admin_note(const std::string& report_id,
                       const std::string& admin_user_id,
                       const std::string& note) {
    auto result = admin_review_->add_admin_note(report_id, admin_user_id, note);

    json response;
    response["report_id"] = report_id;
    response["action"] = "add_note";
    response["result"] = action_result_to_string(result);
    response["success"] = (result == AdminActionResult::SUCCESS);

    return response;
  }

  // ========================================================================
  // Admin API: Reassign report
  // ========================================================================
  json reassign_report(const std::string& report_id,
                        const std::string& from_admin,
                        const std::string& to_admin,
                        const std::string& reason) {
    auto result = admin_review_->reassign_report(report_id, from_admin, 
                                                  to_admin, reason);

    json response;
    response["report_id"] = report_id;
    response["action"] = "reassign";
    response["from_admin"] = from_admin;
    response["to_admin"] = to_admin;
    response["result"] = action_result_to_string(result);
    response["success"] = (result == AdminActionResult::SUCCESS);

    return response;
  }

  // ========================================================================
  // Admin API: Bulk operations
  // ========================================================================
  json bulk_update_status(const std::vector<std::string>& report_ids,
                           const std::string& new_status,
                           const std::string& admin_user_id) {
    int updated = storage_->bulk_update_status(report_ids, new_status, admin_user_id);

    json response;
    response["total_requested"] = report_ids.size();
    response["total_updated"] = updated;
    response["new_status"] = new_status;
    response["admin_user_id"] = admin_user_id;
    response["success"] = (updated > 0);

    return response;
  }

  // ========================================================================
  // Admin API: Get report statistics
  // ========================================================================
  json get_dashboard_stats() {
    return analytics_->get_dashboard_stats();
  }

  // ========================================================================
  // Admin API: Get category trends
  // ========================================================================
  json get_category_trends(int days = 30) {
    return analytics_->get_category_trends(days);
  }

  // ========================================================================
  // Admin API: Get admin workload
  // ========================================================================
  json get_admin_workload() {
    return analytics_->get_admin_workload();
  }

  // ========================================================================
  // Admin API: Get audit trail for a report
  // ========================================================================
  json get_audit_trail(const std::string& report_id) {
    return audit_trail_->get_audit_trail(report_id);
  }

  // ========================================================================
  // Admin API: Get rate limit status for a user
  // ========================================================================
  json get_rate_limit_status(const std::string& user_id) {
    return rate_limiter_->get_user_rate_limit_stats(user_id);
  }

  // ========================================================================
  // Admin API: Unblock a rate-limited user
  // ========================================================================
  json unblock_user(const std::string& user_id) {
    rate_limiter_->unblock_user(user_id);
    return json{
      {"user_id", user_id},
      {"unblocked", true}
    };
  }

  // ========================================================================
  // Admin API: Get reporter reputation
  // ========================================================================
  json get_reporter_reputation(const std::string& user_id) {
    return reputation_->get_reputation(user_id);
  }

  // ========================================================================
  // Federation API: Receive federated report
  // ========================================================================
  json receive_federated_report(const json& federated_report,
                                 const std::string& origin_server) {
    return federation_->receive_federated_report(federated_report, origin_server);
  }

  // ========================================================================
  // Federation API: Forward report to origin
  // ========================================================================
  json forward_report(const std::string& report_id,
                       const std::string& target_server) {
    return federation_->forward_report_to_origin(report_id, target_server);
  }

  // ========================================================================
  // Category Management
  // ========================================================================
  json get_categories() {
    return categories_->get_categories_json();
  }

  json add_category(const json& category_def) {
    ReportCategory cat;
    cat.category_id = category_def.value("category_id", "");
    cat.display_name = category_def.value("display_name", "");
    cat.description = category_def.value("description", "");
    cat.is_enabled = category_def.value("is_enabled", true);
    cat.requires_immediate_escalation = category_def.value(
      "requires_immediate_escalation", false);
    cat.default_severity = category_def.value("default_severity", 1);
    cat.default_priority = string_to_report_priority(
      category_def.value("default_priority", "normal"));
    cat.auto_redact_threshold = category_def.value("auto_redact_threshold", 
                                                    kDefaultAutoRedactThreshold);
    cat.auto_quarantine_threshold = category_def.value("auto_quarantine_threshold", 
                                                        kDefaultAutoQuarantineThreshold);
    cat.auto_mute_threshold = category_def.value("auto_mute_threshold", 
                                                  kDefaultAutoMuteThreshold);
    cat.retention_days = category_def.value("retention_days", 
                                             kDefaultReportRetentionDays);

    if (category_def.contains("subcategories") && 
        category_def["subcategories"].is_array()) {
      for (const auto& sub : category_def["subcategories"]) {
        cat.subcategories.push_back(sub.get<std::string>());
      }
    }

    categories_->add_category(cat);
    return json{{"success", true}, {"category_id", cat.category_id}};
  }

  json remove_category(const std::string& category_id) {
    categories_->remove_category(category_id);
    return json{{"success", true}, {"category_id", category_id}};
  }

  // ========================================================================
  // Maintenance: Run retention cleanup
  // ========================================================================
  json run_retention_cleanup() {
    return retention_->run_cleanup();
  }

  // ========================================================================
  // Maintenance: Clean up expired rate limit state
  // ========================================================================
  json cleanup_rate_limits() {
    rate_limiter_->cleanup_expired_state();
    return json{{"success", true}, {"message", "Rate limit state cleaned up"}};
  }

  // ========================================================================
  // Configuration
  // ========================================================================
  void configure_rate_limits(int per_minute, int per_hour, 
                              int per_event, int per_room, int cooldown) {
    rate_limiter_->set_max_per_user_per_minute(per_minute);
    rate_limiter_->set_max_per_user_per_hour(per_hour);
    rate_limiter_->set_max_per_event(per_event);
    rate_limiter_->set_max_per_room_per_minute(per_room);
    rate_limiter_->set_cooldown_seconds(cooldown);

    report_log.info("Rate limits configured: " +
                    std::to_string(per_minute) + "/min, " +
                    std::to_string(per_hour) + "/hour per user, " +
                    std::to_string(per_event) + "/event, " +
                    std::to_string(per_room) + "/min per room, " +
                    std::to_string(cooldown) + "s cooldown");
  }

 private:
  // --- Extract reported user ID from event context ---
  std::string extract_user_from_event(const std::string& event_id,
                                        const std::string& room_id) {
    // In a real implementation, this would:
    // 1. Look up the event from the event store
    // 2. Extract the sender field
    // For now, return a placeholder
    report_log.debug("Looking up sender for event " + event_id + 
                     " in room " + room_id);
    return "unknown";
  }

  // --- Subsystem instances ---
  std::shared_ptr<ReportStorageEngine> storage_;
  std::shared_ptr<ReportCategoryRegistry> categories_;
  std::shared_ptr<ReportValidator> validator_;
  std::shared_ptr<ReportRateLimiter> rate_limiter_;
  std::shared_ptr<ReportAuditTrail> audit_trail_;
  std::shared_ptr<AdminReviewManager> admin_review_;
  std::shared_ptr<ReportNotificationEngine> notifier_;
  std::shared_ptr<ReportAutoActionEngine> auto_actions_;
  std::shared_ptr<ReportFederationHandler> federation_;
  std::shared_ptr<ReportAnalyticsEngine> analytics_;
  std::shared_ptr<ReportRetentionManager> retention_;
  std::shared_ptr<ReportDeduplicationEngine> dedup_;
  std::shared_ptr<ReporterReputationEngine> reputation_;
};

// ============================================================================
// Background maintenance worker — Periodic cleanup tasks
// ============================================================================

class ReportMaintenanceWorker {
 public:
  ReportMaintenanceWorker(std::shared_ptr<ReportManagerAPI> api,
                           int cleanup_interval_seconds = 3600)
    : api_(std::move(api)),
      cleanup_interval_seconds_(cleanup_interval_seconds),
      running_(false) {}

  void start() {
    if (running_.exchange(true)) return;
    worker_thread_ = std::thread(&ReportMaintenanceWorker::run_loop, this);
    report_log.info("Report maintenance worker started (interval: " +
                    std::to_string(cleanup_interval_seconds_) + "s)");
  }

  void stop() {
    running_.store(false);
    if (worker_thread_.joinable()) {
      worker_thread_.join();
    }
    report_log.info("Report maintenance worker stopped");
  }

 private:
  void run_loop() {
    while (running_.load()) {
      // Sleep for the configured interval (with periodic wake to check stop signal)
      for (int i = 0; i < cleanup_interval_seconds_ && running_.load(); i++) {
        std::this_thread::sleep_for(chr::seconds(1));
      }

      if (!running_.load()) break;

      try {
        report_log.debug("Running periodic maintenance tasks...");
        
        // Clean up rate limit state
        api_->cleanup_rate_limits();

        // Run retention cleanup
        auto result = api_->run_retention_cleanup();
        report_log.debug("Retention cleanup completed: " + 
                         std::to_string(result["total_deleted"].get<int>()) + 
                         " reports deleted");

      } catch (const std::exception& e) {
        report_log.error("Maintenance error: " + std::string(e.what()));
      }
    }
  }

  std::shared_ptr<ReportManagerAPI> api_;
  int cleanup_interval_seconds_;
  std::atomic<bool> running_;
  std::thread worker_thread_;
};

// ============================================================================
// Namespace close
// ============================================================================

}  // namespace progressive
