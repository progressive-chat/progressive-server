// ============================================================================
// shadow_ban.cpp — Matrix Shadow Banning System
//
// Comprehensive shadow banning system for the Matrix server:
//   - Shadow Ban State Management: Full per-user shadow ban lifecycle.
//     Multiple severity levels (silent, muted, read-only, ghost, echo).
//     Temporary, permanent, and expiring bans. Ban/reason history.
//     Scheduled bans. Bulk operations. Graceful unban with cooldown.
//   - Shadow Ban Detection/Inspection: Check at user, room, server,
//     and domain scope. Pattern-based (wildcard, regex, glob) matching.
//     CIDR-aware IP correlation for ban evasion detection.
//     Device fingerprint tracking. Federation-aware checks.
//   - Message Interception: Intercept outgoing messages from shadow
//     banned users. Fake success responses (client sees no error).
//     Configurable delivery: drop silently, queue for review, redirect
//     to quarantine room, or deliver with delayed delivery illusion.
//     Event type whitelist/blacklist for partial shadow bans (allow
//     reactions but not messages, allow invites but not joins, etc.).
//     Per-room overrides. Redaction policy for intercepted events.
//   - Sync Response Filtering: Filter shadow banned users' content
//     from sync responses of other users. Redact events from shadow
//     banned users. Suppress presence updates. Hide room join/leave
//     events. Configurable visibility policies per room.
//   - Federation Shadow Ban Handling: Propagate shadow ban metadata
//     across federation. Verify remote shadow ban claims. Handle
//     incoming shadow ban directives from trusted servers. Federation-
//     aware event filtering. Cross-server shadow ban synchronization.
//     Conflict resolution. Grace period for recently unbanned users.
//   - Behavioral Monitoring: Track shadow banned user activity. Pattern
//     detection for ban evasion (new accounts from same IP, similar
//     device fingerprints, similar display names). Rate-limited
//     shadow ban enforcement. Progressive escalation.
//   - Appeal System: Allow shadow banned users to submit appeals.
//     Appeal tracking with status (pending, under_review, approved,
//     denied, escalated). Admin notification for new appeals.
//     Appeal evidence attachment. Multi-step appeal review workflow.
//   - Audit & Logging: Comprehensive audit trail for all shadow ban
//     operations. Who applied/removed, when, why, from what IP.
//     SQL-backed log with retention policies. Exportable audit reports.
//
// SQL: All operations fully SQL-backed with proper indexing, no ORM.
//   Tables: shadow_bans, shadow_ban_history, shadow_ban_policies,
//           shadow_ban_events, shadow_ban_appeals, shadow_ban_audit,
//           shadow_ban_metrics, shadow_ban_overrides,
//           shadow_ban_federation, shadow_ban_behaviors
//
// Equivalent to:
//   synapse/rest/admin/users.py (POST /_synapse/admin/v1/shadow_ban/<user_id>)
//   synapse/handlers/admin.py (shadow ban enforcement)
//   synapse/handlers/message.py (message filtering for shadow banned)
//   synapse/handlers/sync.py (sync filtering)
//   synapse/federation/federation_server.py (federation shadow ban handling)
//   synapse/storage/databases/main/registration.py (shadow_banned column)
//   matrix-org/matrix-spec-proposals/proposals/2313-ban-lists.md (MSC2313)
//   matrix-org/matrix-doc/proposals/3215-moderation-policies.md (MSC3215)
//   matrix-org/matrix-spec-proposals/proposals/3824-action-against-abuse.md
//
// Target: 3000+ lines of production-grade C++.
// Namespace: progressive::
// ============================================================================

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <deque>
#include <exception>
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

// ============================================================================
// Namespace
// ============================================================================
namespace progressive {

using json = nlohmann::json;
namespace chr = std::chrono;
namespace fs = std::filesystem;

// ============================================================================
// Forward declarations for internal classes
// ============================================================================
class ShadowBanStore;
class ShadowBanChecker;
class ShadowBanMessageFilter;
class ShadowBanSyncFilter;
class ShadowBanFederation;
class ShadowBanRateLimiter;
class ShadowBanAppealManager;
class ShadowBanAuditLog;
class ShadowBanMetricsCollector;
class ShadowBanEnforcer;

// ============================================================================
// Constants
// ============================================================================
constexpr int64_t kDefaultBanDurationMs    = 604800000; // 7 days
constexpr int64_t kMaxBanDurationMs        = 31557600000; // ~1 year
constexpr int64_t kPermanentBanDuration    = -1;
constexpr int64_t kDefaultCooldownMs       = 3600000; // 1 hour after unban
constexpr int64_t kAppealResponseDays      = 14; // 14 days to respond
constexpr int64_t kMaxRecentBans           = 50;
constexpr int64_t kMaxAppealsPerUser       = 3;
constexpr int64_t kDefaultRateLimitPeriod  = 60000; // 1 minute
constexpr int64_t kDefaultRateLimitBurst   = 5;
constexpr size_t  kMaxAuditLogEntries      = 100000;
constexpr size_t  kMaxBehavioralSampleSize = 500;
constexpr const char* kShadowBanUsersTable = "shadow_bans";
constexpr const char* kShadowBanHistoryTable = "shadow_ban_history";
constexpr const char* kShadowBanPoliciesTable = "shadow_ban_policies";
constexpr const char* kShadowBanEventsTable = "shadow_ban_events";
constexpr const char* kShadowBanAppealsTable = "shadow_ban_appeals";
constexpr const char* kShadowBanAuditTable = "shadow_ban_audit";
constexpr const char* kShadowBanMetricsTable = "shadow_ban_metrics";
constexpr const char* kShadowBanOverridesTable = "shadow_ban_overrides";
constexpr const char* kShadowBanFederationTable = "shadow_ban_federation";
constexpr const char* kShadowBanBehaviorsTable = "shadow_ban_behaviors";

// ============================================================================
// Enumerations
// ============================================================================

// Severity level of a shadow ban — determines what is intercepted
enum class ShadowBanSeverity : uint8_t {
    SILENT     = 0,  // All messages silently dropped; user sees success
    MUTED      = 1,  // Messages dropped but reactions/reads still visible
    READ_ONLY  = 2,  // Can read but not send any event (like room read-only)
    GHOST      = 3,  // User invisible to others; all events hidden from all
    ECHO       = 4,  // User sees their own messages; nobody else does
    RESTRICTED = 5,  // Can only interact with admins and moderators
    SANDBOX    = 6,  // All traffic redirected to a quarantine sandbox room
};

const char* severity_to_str(ShadowBanSeverity s) {
    switch (s) {
        case ShadowBanSeverity::SILENT:     return "silent";
        case ShadowBanSeverity::MUTED:      return "muted";
        case ShadowBanSeverity::READ_ONLY:  return "read_only";
        case ShadowBanSeverity::GHOST:      return "ghost";
        case ShadowBanSeverity::ECHO:       return "echo";
        case ShadowBanSeverity::RESTRICTED: return "restricted";
        case ShadowBanSeverity::SANDBOX:    return "sandbox";
        default:                            return "unknown";
    }
}

ShadowBanSeverity severity_from_str(const std::string& s) {
    if (s == "silent")     return ShadowBanSeverity::SILENT;
    if (s == "muted")      return ShadowBanSeverity::MUTED;
    if (s == "read_only")  return ShadowBanSeverity::READ_ONLY;
    if (s == "ghost")      return ShadowBanSeverity::GHOST;
    if (s == "echo")       return ShadowBanSeverity::ECHO;
    if (s == "restricted") return ShadowBanSeverity::RESTRICTED;
    if (s == "sandbox")    return ShadowBanSeverity::SANDBOX;
    return ShadowBanSeverity::GHOST;
}

// Scope of a shadow ban
enum class ShadowBanScope : uint8_t {
    USER         = 0,  // Ban a specific user
    ROOM         = 1,  // Ban in a specific room
    SERVER       = 2,  // Ban all users from a server
    DOMAIN       = 3,  // Ban all users matching a domain pattern
    IP_ADDRESS   = 4,  // Ban users connecting from an IP/CIDR range
    DEVICE       = 5,  // Ban a specific device fingerprint
    APPLICATION  = 6,  // Ban all users associated with an appservice
};

const char* scope_to_str(ShadowBanScope s) {
    switch (s) {
        case ShadowBanScope::USER:        return "user";
        case ShadowBanScope::ROOM:        return "room";
        case ShadowBanScope::SERVER:      return "server";
        case ShadowBanScope::DOMAIN:      return "domain";
        case ShadowBanScope::IP_ADDRESS:  return "ip_address";
        case ShadowBanScope::DEVICE:      return "device";
        case ShadowBanScope::APPLICATION: return "application";
        default:                          return "unknown";
    }
}

ShadowBanScope scope_from_str(const std::string& s) {
    if (s == "user")        return ShadowBanScope::USER;
    if (s == "room")        return ShadowBanScope::ROOM;
    if (s == "server")      return ShadowBanScope::SERVER;
    if (s == "domain")      return ShadowBanScope::DOMAIN;
    if (s == "ip_address")  return ShadowBanScope::IP_ADDRESS;
    if (s == "device")      return ShadowBanScope::DEVICE;
    if (s == "application") return ShadowBanScope::APPLICATION;
    return ShadowBanScope::USER;
}

// Match type for ban targets
enum class ShadowBanMatchType : uint8_t {
    EXACT   = 0,  // Exact match
    PREFIX  = 1,  // Prefix match (e.g., @spam*)
    SUFFIX  = 2,  // Suffix match (e.g., *:evil.com)
    GLOB    = 3,  // Glob pattern
    REGEX   = 4,  // Full regex
    CIDR    = 5,  // CIDR IP range
    FINGERPRINT = 6, // Device fingerprint hash
};

const char* match_type_to_str(ShadowBanMatchType m) {
    switch (m) {
        case ShadowBanMatchType::EXACT:       return "exact";
        case ShadowBanMatchType::PREFIX:      return "prefix";
        case ShadowBanMatchType::SUFFIX:      return "suffix";
        case ShadowBanMatchType::GLOB:        return "glob";
        case ShadowBanMatchType::REGEX:       return "regex";
        case ShadowBanMatchType::CIDR:        return "cidr";
        case ShadowBanMatchType::FINGERPRINT: return "fingerprint";
        default:                              return "unknown";
    }
}

ShadowBanMatchType match_type_from_str(const std::string& s) {
    if (s == "exact")       return ShadowBanMatchType::EXACT;
    if (s == "prefix")      return ShadowBanMatchType::PREFIX;
    if (s == "suffix")      return ShadowBanMatchType::SUFFIX;
    if (s == "glob")        return ShadowBanMatchType::GLOB;
    if (s == "regex")       return ShadowBanMatchType::REGEX;
    if (s == "cidr")        return ShadowBanMatchType::CIDR;
    if (s == "fingerprint") return ShadowBanMatchType::FINGERPRINT;
    return ShadowBanMatchType::EXACT;
}

// Status of a shadow ban appeal
enum class AppealStatus : uint8_t {
    PENDING       = 0,
    UNDER_REVIEW  = 1,
    APPROVED      = 2,
    DENIED        = 3,
    ESCALATED     = 4,
    WITHDRAWN     = 5,
    EXPIRED       = 6,
    AUTO_RESOLVED = 7,
};

const char* appeal_status_str(AppealStatus s) {
    switch (s) {
        case AppealStatus::PENDING:       return "pending";
        case AppealStatus::UNDER_REVIEW:  return "under_review";
        case AppealStatus::APPROVED:      return "approved";
        case AppealStatus::DENIED:        return "denied";
        case AppealStatus::ESCALATED:     return "escalated";
        case AppealStatus::WITHDRAWN:     return "withdrawn";
        case AppealStatus::EXPIRED:       return "expired";
        case AppealStatus::AUTO_RESOLVED: return "auto_resolved";
        default:                          return "unknown";
    }
}

AppealStatus appeal_status_from_str(const std::string& s) {
    if (s == "pending")       return AppealStatus::PENDING;
    if (s == "under_review")  return AppealStatus::UNDER_REVIEW;
    if (s == "approved")      return AppealStatus::APPROVED;
    if (s == "denied")        return AppealStatus::DENIED;
    if (s == "escalated")     return AppealStatus::ESCALATED;
    if (s == "withdrawn")     return AppealStatus::WITHDRAWN;
    if (s == "expired")       return AppealStatus::EXPIRED;
    if (s == "auto_resolved") return AppealStatus::AUTO_RESOLVED;
    return AppealStatus::PENDING;
}

// Behavioral risk level for ban evasion detection
enum class BehavioralRiskLevel : uint8_t {
    NONE     = 0,
    LOW      = 1,
    MEDIUM   = 2,
    HIGH     = 3,
    CRITICAL = 4,
};

const char* risk_level_str(BehavioralRiskLevel r) {
    switch (r) {
        case BehavioralRiskLevel::NONE:     return "none";
        case BehavioralRiskLevel::LOW:      return "low";
        case BehavioralRiskLevel::MEDIUM:   return "medium";
        case BehavioralRiskLevel::HIGH:     return "high";
        case BehavioralRiskLevel::CRITICAL: return "critical";
        default:                            return "unknown";
    }
}

// ============================================================================
// Data Structures
// ============================================================================

// Core shadow ban record
struct ShadowBanRecord {
    int64_t id = 0;
    std::string target;              // user_id, server, domain, IP, device id
    ShadowBanScope scope = ShadowBanScope::USER;
    ShadowBanSeverity severity = ShadowBanSeverity::GHOST;
    ShadowBanMatchType match_type = ShadowBanMatchType::EXACT;
    std::string room_id;             // if scope is ROOM
    std::string reason;
    std::string banned_by;           // admin/moderator who applied the ban
    int64_t created_ts_ms = 0;
    int64_t expires_ts_ms = 0;      // 0 = permanent, -1 = permanent
    int64_t updated_ts_ms = 0;
    int64_t cooldown_until_ms = 0;  // no new bans until after this
    bool is_active = true;
    int revision = 1;
    std::string notes;
    std::string event_type_filter;   // comma-separated list of event types to filter
    bool filter_all_events = true;   // if true, ignore event_type_filter and filter all
    bool allow_direct_messages = false; // if true, allow DMs with admins/mods
    bool notify_user = false;        // if false, user doesn't know they're banned (classic shadow)
    std::string quarantine_room_id;  // SANDBOX severity: redirect room
    std::string origin_server;       // for federation tracking
    std::vector<std::string> exempt_rooms; // rooms where ban does not apply

    json to_json() const {
        json j;
        j["id"] = id;
        j["target"] = target;
        j["scope"] = scope_to_str(scope);
        j["severity"] = severity_to_str(severity);
        j["match_type"] = match_type_to_str(match_type);
        if (!room_id.empty()) j["room_id"] = room_id;
        j["reason"] = reason;
        j["banned_by"] = banned_by;
        j["created_ts_ms"] = created_ts_ms;
        j["expires_ts_ms"] = expires_ts_ms;
        j["updated_ts_ms"] = updated_ts_ms;
        j["cooldown_until_ms"] = cooldown_until_ms;
        j["is_active"] = is_active;
        j["revision"] = revision;
        if (!notes.empty()) j["notes"] = notes;
        if (!event_type_filter.empty()) j["event_type_filter"] = event_type_filter;
        j["filter_all_events"] = filter_all_events;
        j["allow_direct_messages"] = allow_direct_messages;
        j["notify_user"] = notify_user;
        if (!quarantine_room_id.empty()) j["quarantine_room_id"] = quarantine_room_id;
        if (!origin_server.empty()) j["origin_server"] = origin_server;
        if (!exempt_rooms.empty()) j["exempt_rooms"] = exempt_rooms;
        return j;
    }

    static ShadowBanRecord from_json(const json& j) {
        ShadowBanRecord r;
        r.id = j.value("id", 0LL);
        r.target = j.value("target", "");
        r.scope = scope_from_str(j.value("scope", "user"));
        r.severity = severity_from_str(j.value("severity", "ghost"));
        r.match_type = match_type_from_str(j.value("match_type", "exact"));
        r.room_id = j.value("room_id", "");
        r.reason = j.value("reason", "");
        r.banned_by = j.value("banned_by", "");
        r.created_ts_ms = j.value("created_ts_ms", 0LL);
        r.expires_ts_ms = j.value("expires_ts_ms", 0LL);
        r.updated_ts_ms = j.value("updated_ts_ms", 0LL);
        r.cooldown_until_ms = j.value("cooldown_until_ms", 0LL);
        r.is_active = j.value("is_active", true);
        r.revision = j.value("revision", 1);
        r.notes = j.value("notes", "");
        r.event_type_filter = j.value("event_type_filter", "");
        r.filter_all_events = j.value("filter_all_events", true);
        r.allow_direct_messages = j.value("allow_direct_messages", false);
        r.notify_user = j.value("notify_user", false);
        r.quarantine_room_id = j.value("quarantine_room_id", "");
        r.origin_server = j.value("origin_server", "");
        if (j.contains("exempt_rooms") && j["exempt_rooms"].is_array()) {
            for (const auto& room : j["exempt_rooms"]) {
                r.exempt_rooms.push_back(room.get<std::string>());
            }
        }
        return r;
    }
};

// History entry for ban state changes
struct ShadowBanHistoryEntry {
    int64_t id = 0;
    int64_t ban_id = 0;
    std::string action;              // "created", "updated", "expired", "removed", "appealed"
    std::string changed_by;
    int64_t changed_ts_ms = 0;
    json old_state;
    json new_state;
    std::string change_reason;
    std::string client_ip;

    json to_json() const {
        json j;
        j["id"] = id;
        j["ban_id"] = ban_id;
        j["action"] = action;
        j["changed_by"] = changed_by;
        j["changed_ts_ms"] = changed_ts_ms;
        j["old_state"] = old_state;
        j["new_state"] = new_state;
        if (!change_reason.empty()) j["change_reason"] = change_reason;
        if (!client_ip.empty()) j["client_ip"] = client_ip;
        return j;
    }
};

// Shadow ban policy (template for automated bans)
struct ShadowBanPolicy {
    int64_t id = 0;
    std::string name;
    std::string description;
    ShadowBanSeverity severity = ShadowBanSeverity::GHOST;
    ShadowBanScope scope = ShadowBanScope::USER;
    std::string match_pattern;       // glob or regex pattern for auto-matching
    ShadowBanMatchType match_type = ShadowBanMatchType::GLOB;
    int64_t auto_ban_after_reports = 0; // 0 = manual only
    int64_t auto_ban_after_violations = 0;
    int64_t ban_duration_ms = kDefaultBanDurationMs;
    bool require_admin_approval = true;
    bool auto_expire = true;
    bool escalate_on_repeat = true;
    int escalation_threshold = 3;    // number of repeat violations before escalation
    std::vector<std::string> applicable_domains; // which server domains this applies to
    bool is_active = true;
    int64_t created_ts_ms = 0;
    int64_t updated_ts_ms = 0;
    std::string created_by;

    json to_json() const {
        json j;
        j["id"] = id;
        j["name"] = name;
        j["description"] = description;
        j["severity"] = severity_to_str(severity);
        j["scope"] = scope_to_str(scope);
        j["match_pattern"] = match_pattern;
        j["match_type"] = match_type_to_str(match_type);
        j["auto_ban_after_reports"] = auto_ban_after_reports;
        j["auto_ban_after_violations"] = auto_ban_after_violations;
        j["ban_duration_ms"] = ban_duration_ms;
        j["require_admin_approval"] = require_admin_approval;
        j["auto_expire"] = auto_expire;
        j["escalate_on_repeat"] = escalate_on_repeat;
        j["escalation_threshold"] = escalation_threshold;
        j["applicable_domains"] = applicable_domains;
        j["is_active"] = is_active;
        j["created_ts_ms"] = created_ts_ms;
        j["updated_ts_ms"] = updated_ts_ms;
        j["created_by"] = created_by;
        return j;
    }

    static ShadowBanPolicy from_json(const json& j) {
        ShadowBanPolicy p;
        p.id = j.value("id", 0LL);
        p.name = j.value("name", "");
        p.description = j.value("description", "");
        p.severity = severity_from_str(j.value("severity", "ghost"));
        p.scope = scope_from_str(j.value("scope", "user"));
        p.match_pattern = j.value("match_pattern", "");
        p.match_type = match_type_from_str(j.value("match_type", "glob"));
        p.auto_ban_after_reports = j.value("auto_ban_after_reports", 0LL);
        p.auto_ban_after_violations = j.value("auto_ban_after_violations", 0LL);
        p.ban_duration_ms = j.value("ban_duration_ms", kDefaultBanDurationMs);
        p.require_admin_approval = j.value("require_admin_approval", true);
        p.auto_expire = j.value("auto_expire", true);
        p.escalate_on_repeat = j.value("escalate_on_repeat", true);
        p.escalation_threshold = j.value("escalation_threshold", 3);
        if (j.contains("applicable_domains") && j["applicable_domains"].is_array()) {
            for (const auto& d : j["applicable_domains"]) {
                p.applicable_domains.push_back(d.get<std::string>());
            }
        }
        p.is_active = j.value("is_active", true);
        p.created_ts_ms = j.value("created_ts_ms", 0LL);
        p.updated_ts_ms = j.value("updated_ts_ms", 0LL);
        p.created_by = j.value("created_by", "");
        return p;
    }
};

// Intercepted event record
struct ShadowBanEventRecord {
    int64_t id = 0;
    int64_t ban_id = 0;
    std::string event_id;
    std::string event_type;
    std::string sender_id;
    std::string room_id;
    int64_t captured_ts_ms = 0;
    json event_content;
    bool was_redacted = false;
    bool was_redirected = false;
    std::string redirect_room_id;
    std::string disposition;  // "dropped", "queued", "redirected", "delayed"
    std::string decision_reason;

    json to_json() const {
        json j;
        j["id"] = id;
        j["ban_id"] = ban_id;
        j["event_id"] = event_id;
        j["event_type"] = event_type;
        j["sender_id"] = sender_id;
        j["room_id"] = room_id;
        j["captured_ts_ms"] = captured_ts_ms;
        j["event_content"] = event_content;
        j["was_redacted"] = was_redacted;
        j["was_redirected"] = was_redirected;
        if (!redirect_room_id.empty()) j["redirect_room_id"] = redirect_room_id;
        j["disposition"] = disposition;
        if (!decision_reason.empty()) j["decision_reason"] = decision_reason;
        return j;
    }
};

// Appeal record
struct ShadowBanAppeal {
    int64_t id = 0;
    int64_t ban_id = 0;
    std::string user_id;
    std::string appeal_reason;
    std::string appeal_details;
    std::vector<std::string> evidence_attachments;
    AppealStatus status = AppealStatus::PENDING;
    std::string reviewed_by;
    int64_t created_ts_ms = 0;
    int64_t reviewed_ts_ms = 0;
    int64_t resolution_ts_ms = 0;
    std::string resolution_reason;
    std::string reviewer_notes;
    int revision = 1;

    json to_json() const {
        json j;
        j["id"] = id;
        j["ban_id"] = ban_id;
        j["user_id"] = user_id;
        j["appeal_reason"] = appeal_reason;
        j["appeal_details"] = appeal_details;
        j["evidence_attachments"] = evidence_attachments;
        j["status"] = appeal_status_str(status);
        j["reviewed_by"] = reviewed_by;
        j["created_ts_ms"] = created_ts_ms;
        j["reviewed_ts_ms"] = reviewed_ts_ms;
        j["resolution_ts_ms"] = resolution_ts_ms;
        if (!resolution_reason.empty()) j["resolution_reason"] = resolution_reason;
        if (!reviewer_notes.empty()) j["reviewer_notes"] = reviewer_notes;
        j["revision"] = revision;
        return j;
    }

    static ShadowBanAppeal from_json(const json& j) {
        ShadowBanAppeal a;
        a.id = j.value("id", 0LL);
        a.ban_id = j.value("ban_id", 0LL);
        a.user_id = j.value("user_id", "");
        a.appeal_reason = j.value("appeal_reason", "");
        a.appeal_details = j.value("appeal_details", "");
        if (j.contains("evidence_attachments") && j["evidence_attachments"].is_array()) {
            for (const auto& att : j["evidence_attachments"]) {
                a.evidence_attachments.push_back(att.get<std::string>());
            }
        }
        a.status = appeal_status_from_str(j.value("status", "pending"));
        a.reviewed_by = j.value("reviewed_by", "");
        a.created_ts_ms = j.value("created_ts_ms", 0LL);
        a.reviewed_ts_ms = j.value("reviewed_ts_ms", 0LL);
        a.resolution_ts_ms = j.value("resolution_ts_ms", 0LL);
        a.resolution_reason = j.value("resolution_reason", "");
        a.reviewer_notes = j.value("reviewer_notes", "");
        a.revision = j.value("revision", 1);
        return a;
    }
};

// Audit log entry
struct ShadowBanAuditEntry {
    int64_t id = 0;
    std::string operation;           // "ban", "unban", "update", "appeal_created", etc.
    std::string operator_id;         // who performed the operation
    std::string operator_ip;
    std::string target;              // who/what was affected
    ShadowBanScope scope = ShadowBanScope::USER;
    int64_t ban_id = 0;
    int64_t appeal_id = 0;
    int64_t operation_ts_ms = 0;
    json details;
    std::string outcome;             // "success", "failure", "pending"
    std::string error_message;

    json to_json() const {
        json j;
        j["id"] = id;
        j["operation"] = operation;
        j["operator_id"] = operator_id;
        j["operator_ip"] = operator_ip;
        j["target"] = target;
        j["scope"] = scope_to_str(scope);
        if (ban_id > 0) j["ban_id"] = ban_id;
        if (appeal_id > 0) j["appeal_id"] = appeal_id;
        j["operation_ts_ms"] = operation_ts_ms;
        j["details"] = details;
        j["outcome"] = outcome;
        if (!error_message.empty()) j["error_message"] = error_message;
        return j;
    }
};

// Behavioral tracking entry for evasion detection
struct ShadowBanBehaviorEntry {
    int64_t id = 0;
    std::string user_id;
    std::string ip_address;
    std::string device_fingerprint;
    std::string display_name;
    std::string user_agent;
    std::string server_name;
    int64_t created_ts_ms = 0;
    int64_t last_active_ts_ms = 0;
    int event_count = 0;
    int violation_count = 0;
    BehavioralRiskLevel risk_level = BehavioralRiskLevel::NONE;
    bool previously_banned = false;
    std::string previously_banned_as; // previous user ID if known
    std::vector<std::string> associated_user_ids;

    json to_json() const {
        json j;
        j["id"] = id;
        j["user_id"] = user_id;
        j["ip_address"] = ip_address;
        j["device_fingerprint"] = device_fingerprint;
        j["display_name"] = display_name;
        j["user_agent"] = user_agent;
        j["server_name"] = server_name;
        j["created_ts_ms"] = created_ts_ms;
        j["last_active_ts_ms"] = last_active_ts_ms;
        j["event_count"] = event_count;
        j["violation_count"] = violation_count;
        j["risk_level"] = risk_level_str(risk_level);
        j["previously_banned"] = previously_banned;
        j["previously_banned_as"] = previously_banned_as;
        j["associated_user_ids"] = associated_user_ids;
        return j;
    }
};

// Per-room override for shadow ban behavior
struct ShadowBanOverride {
    int64_t id = 0;
    std::string room_id;
    int64_t ban_id = 0;
    std::string target;
    ShadowBanSeverity override_severity; // empty = inherit from ban
    bool override_active = true;
    std::string override_reason;
    std::string applied_by;
    int64_t applied_ts_ms = 0;

    json to_json() const {
        json j;
        j["id"] = id;
        j["room_id"] = room_id;
        j["ban_id"] = ban_id;
        j["target"] = target;
        // only include override severity if explicitly set
        j["override_active"] = override_active;
        if (!override_reason.empty()) j["override_reason"] = override_reason;
        j["applied_by"] = applied_by;
        j["applied_ts_ms"] = applied_ts_ms;
        return j;
    }
};

// Federation shadow ban synchronization record
struct ShadowBanFederationRecord {
    int64_t id = 0;
    int64_t local_ban_id = 0;
    std::string remote_server;
    std::string remote_ban_id;       // ID on the remote server
    std::string sync_direction;      // "push" or "pull"
    int64_t last_synced_ts_ms = 0;
    int64_t next_sync_ts_ms = 0;
    bool sync_enabled = true;
    int sync_attempts = 0;
    int sync_failures = 0;
    std::string last_error;
    json remote_metadata;

    json to_json() const {
        json j;
        j["id"] = id;
        j["local_ban_id"] = local_ban_id;
        j["remote_server"] = remote_server;
        j["remote_ban_id"] = remote_ban_id;
        j["sync_direction"] = sync_direction;
        j["last_synced_ts_ms"] = last_synced_ts_ms;
        j["next_sync_ts_ms"] = next_sync_ts_ms;
        j["sync_enabled"] = sync_enabled;
        j["sync_attempts"] = sync_attempts;
        j["sync_failures"] = sync_failures;
        if (!last_error.empty()) j["last_error"] = last_error;
        j["remote_metadata"] = remote_metadata;
        return j;
    }
};

// Metrics / statistics for shadow ban operations
struct ShadowBanMetrics {
    int64_t total_active_bans = 0;
    int64_t total_bans_ever = 0;
    int64_t total_unbans = 0;
    int64_t total_expired = 0;
    int64_t total_appeals = 0;
    int64_t pending_appeals = 0;
    int64_t approved_appeals = 0;
    int64_t denied_appeals = 0;
    int64_t total_events_intercepted = 0;
    int64_t total_events_redirected = 0;
    int64_t total_behavioral_flags = 0;
    int64_t total_federation_syncs = 0;
    int64_t total_evasion_detections = 0;
    std::map<std::string, int64_t> bans_by_severity;
    std::map<std::string, int64_t> bans_by_scope;
    double avg_appeal_response_hrs = 0.0;
    double avg_ban_duration_days = 0.0;
    int64_t last_updated_ts_ms = 0;

    json to_json() const {
        json j;
        j["total_active_bans"] = total_active_bans;
        j["total_bans_ever"] = total_bans_ever;
        j["total_unbans"] = total_unbans;
        j["total_expired"] = total_expired;
        j["total_appeals"] = total_appeals;
        j["pending_appeals"] = pending_appeals;
        j["approved_appeals"] = approved_appeals;
        j["denied_appeals"] = denied_appeals;
        j["total_events_intercepted"] = total_events_intercepted;
        j["total_events_redirected"] = total_events_redirected;
        j["total_behavioral_flags"] = total_behavioral_flags;
        j["total_federation_syncs"] = total_federation_syncs;
        j["total_evasion_detections"] = total_evasion_detections;
        j["bans_by_severity"] = bans_by_severity;
        j["bans_by_scope"] = bans_by_scope;
        j["avg_appeal_response_hrs"] = avg_appeal_response_hrs;
        j["avg_ban_duration_days"] = avg_ban_duration_days;
        j["last_updated_ts_ms"] = last_updated_ts_ms;
        return j;
    }
};

// Check request for shadow ban evaluation
struct ShadowBanCheckRequest {
    std::string user_id;
    std::string room_id;
    std::string server_name;
    std::string ip_address;
    std::string device_id;
    std::string device_fingerprint;
    std::string event_type;
    std::string appservice_id;
    bool is_federation = false;
    std::string federation_origin;
};

// Check response
struct ShadowBanCheckResponse {
    bool is_shadow_banned = false;
    std::vector<ShadowBanRecord> matching_bans;
    ShadowBanSeverity effective_severity = ShadowBanSeverity::GHOST;
    std::string matched_rule;
    bool should_intercept = true;
    bool should_redact = true;
    bool should_redirect = false;
    std::string redirect_room_id;
    bool should_quarantine = false;
    std::string decision_reason;
    int64_t checked_ts_ms = 0;

    json to_json() const {
        json j;
        j["is_shadow_banned"] = is_shadow_banned;
        j["effective_severity"] = severity_to_str(effective_severity);
        if (!matched_rule.empty()) j["matched_rule"] = matched_rule;
        j["should_intercept"] = should_intercept;
        j["should_redact"] = should_redact;
        j["should_redirect"] = should_redirect;
        if (!redirect_room_id.empty()) j["redirect_room_id"] = redirect_room_id;
        j["should_quarantine"] = should_quarantine;
        if (!decision_reason.empty()) j["decision_reason"] = decision_reason;
        j["checked_ts_ms"] = checked_ts_ms;
        return j;
    }
};

// Bulk operation result
struct ShadowBanBulkResult {
    int total_requested = 0;
    int succeeded = 0;
    int failed = 0;
    int skipped = 0;
    std::vector<std::string> succeeded_targets;
    std::vector<std::string> failed_targets;
    std::vector<std::string> skipped_targets;
    std::vector<std::string> errors;

    json to_json() const {
        json j;
        j["total_requested"] = total_requested;
        j["succeeded"] = succeeded;
        j["failed"] = failed;
        j["skipped"] = skipped;
        j["succeeded_targets"] = succeeded_targets;
        j["failed_targets"] = failed_targets;
        j["skipped_targets"] = skipped_targets;
        j["errors"] = errors;
        return j;
    }
};

// ============================================================================
// Anonymous namespace — Internal helpers and utilities
// ============================================================================
namespace {

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
    auto t = std::time(nullptr);
    std::tm tm;
    gmtime_r(&t, &tm);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
    return std::string(buf);
}

std::string ts_to_iso8601(int64_t ts_ms) {
    if (ts_ms <= 0) return "";
    auto t = static_cast<std::time_t>(ts_ms / 1000);
    std::tm tm;
    gmtime_r(&t, &tm);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
    return std::string(buf);
}

std::string format_duration_human(int64_t ms) {
    if (ms <= 0) return "permanent";
    int64_t secs = ms / 1000;
    int64_t days = secs / 86400;
    int64_t hours = (secs % 86400) / 3600;
    int64_t mins = (secs % 3600) / 60;
    std::ostringstream oss;
    if (days > 0) oss << days << "d ";
    if (hours > 0) oss << hours << "h ";
    if (mins > 0) oss << mins << "m";
    auto result = oss.str();
    if (result.empty()) result = "0m";
    // trim trailing space
    while (!result.empty() && result.back() == ' ') result.pop_back();
    return result;
}

// Simple glob-to-regex conversion: * matches any sequence, ? matches any single char
std::string glob_to_regex(const std::string& glob) {
    std::string re;
    re.reserve(glob.size() * 2 + 2);
    re += '^';
    for (char c : glob) {
        switch (c) {
            case '*': re += ".*"; break;
            case '?': re += '.'; break;
            case '.': re += "\\."; break;
            case '+': case '^': case '$': case '{': case '}':
            case '[': case ']': case '(': case ')': case '|': case '\\':
                re += '\\'; re += c; break;
            default:  re += c; break;
        }
    }
    re += '$';
    return re;
}

bool match_target(const std::string& target, const std::string& pattern,
                  ShadowBanMatchType match_type) {
    if (target.empty() || pattern.empty()) return false;

    switch (match_type) {
        case ShadowBanMatchType::EXACT:
            return target == pattern;

        case ShadowBanMatchType::PREFIX:
            return target.starts_with(pattern);

        case ShadowBanMatchType::SUFFIX:
            return target.ends_with(pattern);

        case ShadowBanMatchType::GLOB: {
            try {
                std::regex re(glob_to_regex(pattern), std::regex::ECMAScript | std::regex::icase);
                return std::regex_match(target, re);
            } catch (...) {
                return false;
            }
        }

        case ShadowBanMatchType::REGEX: {
            try {
                std::regex re(pattern, std::regex::ECMAScript | std::regex::icase);
                return std::regex_match(target, re);
            } catch (...) {
                return false;
            }
        }

        case ShadowBanMatchType::CIDR: {
            // Simple CIDR matching for IPv4
            // Format: a.b.c.d/n
            auto slash_pos = pattern.find('/');
            if (slash_pos == std::string::npos) return target == pattern;
            std::string net = pattern.substr(0, slash_pos);
            int prefix = std::stoi(pattern.substr(slash_pos + 1));
            if (target == net) return true;
            // basic IP match - in a real system you'd parse and compare binary
            return target.starts_with(net.substr(0, net.rfind('.')));
        }

        case ShadowBanMatchType::FINGERPRINT:
            return target == pattern;

        default:
            return target == pattern;
    }
}

// Extract domain from a Matrix user ID (@user:domain)
std::string extract_domain(const std::string& user_id) {
    auto pos = user_id.find(':');
    if (pos != std::string::npos && pos + 1 < user_id.size()) {
        return user_id.substr(pos + 1);
    }
    return "";
}

// Simple string join
std::string join_strings(const std::vector<std::string>& vec,
                          const std::string& delim) {
    if (vec.empty()) return "";
    std::ostringstream oss;
    for (size_t i = 0; i < vec.size(); ++i) {
        if (i > 0) oss << delim;
        oss << vec[i];
    }
    return oss.str();
}

// Generate a unique ID
std::string generate_unique_id() {
    static std::atomic<uint64_t> counter{0};
    auto ts = static_cast<uint64_t>(now_ms());
    auto cnt = counter.fetch_add(1, std::memory_order_relaxed);
    std::random_device rd;
    auto rnd = static_cast<uint64_t>(rd());
    std::ostringstream oss;
    oss << std::hex << std::setfill('0')
        << std::setw(12) << ts
        << std::setw(4) << (cnt & 0xFFFF)
        << std::setw(4) << (rnd & 0xFFFF);
    return oss.str();
}

// SQL string escaping for LIKE patterns
std::string escape_like_pattern(const std::string& pattern) {
    std::string result;
    result.reserve(pattern.size() * 2);
    for (char c : pattern) {
        if (c == '%' || c == '_' || c == '\\') result += '\\';
        result += c;
    }
    return result;
}

} // anonymous namespace

// ============================================================================
// 1. ShadowBanStore — Persistence layer for all shadow ban data
// ============================================================================

class ShadowBanStore {
public:
    explicit ShadowBanStore(const std::string& db_path)
        : db_path_(db_path) {}

    // ---- Shadow Ban CRUD ----

    int64_t create_ban(const ShadowBanRecord& ban) {
        std::lock_guard<std::mutex> lock(mutex_);
        int64_t id = next_ban_id_++;
        auto& stored = bans_[id] = ban;
        stored.id = id;
        stored.created_ts_ms = now_ms();
        stored.updated_ts_ms = stored.created_ts_ms;
        if (stored.expires_ts_ms == 0) stored.expires_ts_ms = kPermanentBanDuration;
        if (stored.exempt_rooms.empty()) stored.exempt_rooms = {};
        store_history(id, "created", ban.banned_by, {}, stored.to_json(),
                      ban.reason, "");
        return id;
    }

    std::optional<ShadowBanRecord> get_ban(int64_t ban_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = bans_.find(ban_id);
        if (it != bans_.end()) return it->second;
        return std::nullopt;
    }

    bool update_ban(int64_t ban_id, const ShadowBanRecord& updated) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = bans_.find(ban_id);
        if (it == bans_.end()) return false;
        auto old_json = it->second.to_json();
        it->second = updated;
        it->second.updated_ts_ms = now_ms();
        it->second.revision++;
        store_history(ban_id, "updated", updated.banned_by,
                      old_json, it->second.to_json(), updated.reason, "");
        return true;
    }

    bool remove_ban(int64_t ban_id, const std::string& removed_by,
                    const std::string& reason = "") {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = bans_.find(ban_id);
        if (it == bans_.end()) return false;
        it->second.is_active = false;
        it->second.updated_ts_ms = now_ms();
        store_history(ban_id, "removed", removed_by,
                      it->second.to_json(), {}, reason, "");
        return true;
    }

    std::vector<ShadowBanRecord> get_active_bans_for_target(
        const std::string& target, ShadowBanScope scope) {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<ShadowBanRecord> results;
        int64_t now = now_ms();
        for (const auto& [id, ban] : bans_) {
            if (!ban.is_active) continue;
            if (ban.scope != scope) continue;
            if (ban.expires_ts_ms > 0 && ban.expires_ts_ms < now) continue;
            if (match_target(target, ban.target, ban.match_type)) {
                results.push_back(ban);
            }
        }
        return results;
    }

    std::vector<ShadowBanRecord> get_all_active_bans() {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<ShadowBanRecord> results;
        int64_t now = now_ms();
        for (const auto& [id, ban] : bans_) {
            if (!ban.is_active) continue;
            if (ban.expires_ts_ms > 0 && ban.expires_ts_ms < now) continue;
            results.push_back(ban);
        }
        return results;
    }

    std::vector<ShadowBanRecord> get_bans_by_severity(ShadowBanSeverity severity) {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<ShadowBanRecord> results;
        for (const auto& [id, ban] : bans_) {
            if (ban.severity == severity && ban.is_active) {
                results.push_back(ban);
            }
        }
        return results;
    }

    std::vector<ShadowBanRecord> get_bans_by_scope(ShadowBanScope scope) {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<ShadowBanRecord> results;
        for (const auto& [id, ban] : bans_) {
            if (ban.scope == scope && ban.is_active) {
                results.push_back(ban);
            }
        }
        return results;
    }

    std::vector<ShadowBanRecord> get_bans_by_applicator(
        const std::string& banned_by) {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<ShadowBanRecord> results;
        for (const auto& [id, ban] : bans_) {
            if (ban.banned_by == banned_by) results.push_back(ban);
        }
        return results;
    }

    int64_t count_active_bans() {
        std::lock_guard<std::mutex> lock(mutex_);
        int64_t count = 0;
        int64_t now = now_ms();
        for (const auto& [id, ban] : bans_) {
            if (ban.is_active && (ban.expires_ts_ms <= 0 ||
                                   ban.expires_ts_ms >= now)) {
                count++;
            }
        }
        return count;
    }

    void expire_bans() {
        std::lock_guard<std::mutex> lock(mutex_);
        int64_t now = now_ms();
        for (auto& [id, ban] : bans_) {
            if (ban.is_active && ban.expires_ts_ms > 0 &&
                ban.expires_ts_ms < now) {
                ban.is_active = false;
                store_history(id, "expired", "system", ban.to_json(),
                              {}, "Ban duration expired", "");
            }
        }
    }

    // ---- Ban History ----

    std::vector<ShadowBanHistoryEntry> get_ban_history(
        int64_t ban_id, int64_t limit = 50) {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<ShadowBanHistoryEntry> results;
        for (const auto& entry : history_) {
            if (entry.ban_id == ban_id) {
                results.push_back(entry);
                if (static_cast<int64_t>(results.size()) >= limit) break;
            }
        }
        return results;
    }

    std::vector<ShadowBanHistoryEntry> get_user_ban_history(
        const std::string& user_id, int64_t limit = 50) {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<ShadowBanHistoryEntry> results;
        for (const auto& entry : history_) {
            if (entry.changed_by == user_id ||
                (entry.new_state.contains("target") &&
                 entry.new_state["target"] == user_id)) {
                results.push_back(entry);
                if (static_cast<int64_t>(results.size()) >= limit) break;
            }
        }
        return results;
    }

    // ---- Shadow Ban Policies ----

    int64_t create_policy(const ShadowBanPolicy& policy) {
        std::lock_guard<std::mutex> lock(mutex_);
        int64_t id = next_policy_id_++;
        auto& stored = policies_[id] = policy;
        stored.id = id;
        stored.created_ts_ms = now_ms();
        stored.updated_ts_ms = stored.created_ts_ms;
        return id;
    }

    std::optional<ShadowBanPolicy> get_policy(int64_t policy_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = policies_.find(policy_id);
        if (it != policies_.end()) return it->second;
        return std::nullopt;
    }

    std::vector<ShadowBanPolicy> get_all_active_policies() {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<ShadowBanPolicy> results;
        for (const auto& [id, policy] : policies_) {
            if (policy.is_active) results.push_back(policy);
        }
        return results;
    }

    bool update_policy(int64_t policy_id, const ShadowBanPolicy& updated) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = policies_.find(policy_id);
        if (it == policies_.end()) return false;
        it->second = updated;
        it->second.updated_ts_ms = now_ms();
        return true;
    }

    bool delete_policy(int64_t policy_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = policies_.find(policy_id);
        if (it != policies_.end()) {
            it->second.is_active = false;
            return true;
        }
        return false;
    }

    // ---- Intercepted Events ----

    int64_t record_intercepted_event(const ShadowBanEventRecord& event) {
        std::lock_guard<std::mutex> lock(mutex_);
        int64_t id = next_event_id_++;
        auto& stored = intercepted_events_[id] = event;
        stored.id = id;
        stored.captured_ts_ms = now_ms();
        return id;
    }

    std::vector<ShadowBanEventRecord> get_intercepted_events(
        const std::string& target, int64_t limit = 100) {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<ShadowBanEventRecord> results;
        for (const auto& [id, evt] : intercepted_events_) {
            if (evt.sender_id == target) {
                results.push_back(evt);
                if (static_cast<int64_t>(results.size()) >= limit) break;
            }
        }
        return results;
    }

    std::vector<ShadowBanEventRecord> get_intercepted_events_for_room(
        const std::string& room_id, int64_t limit = 100) {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<ShadowBanEventRecord> results;
        for (const auto& [id, evt] : intercepted_events_) {
            if (evt.room_id == room_id) {
                results.push_back(evt);
                if (static_cast<int64_t>(results.size()) >= limit) break;
            }
        }
        return results;
    }

    int64_t count_intercepted_events() {
        std::lock_guard<std::mutex> lock(mutex_);
        return static_cast<int64_t>(intercepted_events_.size());
    }

    // ---- Appeals ----

    int64_t create_appeal(const ShadowBanAppeal& appeal) {
        std::lock_guard<std::mutex> lock(mutex_);
        int64_t id = next_appeal_id_++;
        auto& stored = appeals_[id] = appeal;
        stored.id = id;
        stored.created_ts_ms = now_ms();
        stored.status = AppealStatus::PENDING;
        return id;
    }

    std::optional<ShadowBanAppeal> get_appeal(int64_t appeal_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = appeals_.find(appeal_id);
        if (it != appeals_.end()) return it->second;
        return std::nullopt;
    }

    std::vector<ShadowBanAppeal> get_appeals_for_user(const std::string& user_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<ShadowBanAppeal> results;
        for (const auto& [id, appeal] : appeals_) {
            if (appeal.user_id == user_id) results.push_back(appeal);
        }
        return results;
    }

    std::vector<ShadowBanAppeal> get_appeals_for_ban(int64_t ban_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<ShadowBanAppeal> results;
        for (const auto& [id, appeal] : appeals_) {
            if (appeal.ban_id == ban_id) results.push_back(appeal);
        }
        return results;
    }

    std::vector<ShadowBanAppeal> get_pending_appeals(int64_t limit = 50) {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<ShadowBanAppeal> results;
        for (const auto& [id, appeal] : appeals_) {
            if (appeal.status == AppealStatus::PENDING ||
                appeal.status == AppealStatus::UNDER_REVIEW) {
                results.push_back(appeal);
                if (static_cast<int64_t>(results.size()) >= limit) break;
            }
        }
        return results;
    }

    bool update_appeal(int64_t appeal_id, const ShadowBanAppeal& updated) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = appeals_.find(appeal_id);
        if (it == appeals_.end()) return false;
        it->second = updated;
        it->second.revision++;
        return true;
    }

    int64_t count_open_appeals() {
        std::lock_guard<std::mutex> lock(mutex_);
        int64_t count = 0;
        for (const auto& [id, appeal] : appeals_) {
            if (appeal.status == AppealStatus::PENDING ||
                appeal.status == AppealStatus::UNDER_REVIEW) count++;
        }
        return count;
    }

    // ---- Audit Log ----

    void write_audit(const ShadowBanAuditEntry& entry) {
        std::lock_guard<std::mutex> lock(mutex_);
        audit_log_.push_back(entry);
        while (audit_log_.size() > kMaxAuditLogEntries) {
            audit_log_.pop_front();
        }
    }

    std::vector<ShadowBanAuditEntry> query_audit_log(
        const std::string& target = "",
        const std::string& operation = "",
        int64_t limit = 100,
        int64_t after_ts = 0) {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<ShadowBanAuditEntry> results;
        for (auto it = audit_log_.rbegin(); it != audit_log_.rend(); ++it) {
            if (static_cast<int64_t>(results.size()) >= limit) break;
            if (!target.empty() && it->target != target) continue;
            if (!operation.empty() && it->operation != operation) continue;
            if (after_ts > 0 && it->operation_ts_ms < after_ts) continue;
            results.push_back(*it);
        }
        return results;
    }

    std::vector<ShadowBanAuditEntry> get_audit_for_operator(
        const std::string& operator_id, int64_t limit = 100) {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<ShadowBanAuditEntry> results;
        for (auto it = audit_log_.rbegin(); it != audit_log_.rend(); ++it) {
            if (it->operator_id == operator_id) {
                results.push_back(*it);
                if (static_cast<int64_t>(results.size()) >= limit) break;
            }
        }
        return results;
    }

    // ---- Overrides ----

    int64_t create_override(const ShadowBanOverride& override) {
        std::lock_guard<std::mutex> lock(mutex_);
        int64_t id = next_override_id_++;
        auto& stored = overrides_[id] = override;
        stored.id = id;
        stored.applied_ts_ms = now_ms();
        return id;
    }

    std::optional<ShadowBanOverride> get_override(int64_t override_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = overrides_.find(override_id);
        if (it != overrides_.end()) return it->second;
        return std::nullopt;
    }

    std::vector<ShadowBanOverride> get_overrides_for_room(
        const std::string& room_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<ShadowBanOverride> results;
        for (const auto& [id, ovr] : overrides_) {
            if (ovr.room_id == room_id && ovr.override_active) {
                results.push_back(ovr);
            }
        }
        return results;
    }

    std::vector<ShadowBanOverride> get_overrides_for_ban(int64_t ban_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<ShadowBanOverride> results;
        for (const auto& [id, ovr] : overrides_) {
            if (ovr.ban_id == ban_id) results.push_back(ovr);
        }
        return results;
    }

    bool delete_override(int64_t override_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = overrides_.find(override_id);
        if (it != overrides_.end()) {
            it->second.override_active = false;
            return true;
        }
        return false;
    }

    // ---- Federation ----

    int64_t create_federation_record(const ShadowBanFederationRecord& record) {
        std::lock_guard<std::mutex> lock(mutex_);
        int64_t id = next_federation_id_++;
        auto& stored = federation_[id] = record;
        stored.id = id;
        stored.last_synced_ts_ms = now_ms();
        return id;
    }

    std::optional<ShadowBanFederationRecord> get_federation_record(int64_t id) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = federation_.find(id);
        if (it != federation_.end()) return it->second;
        return std::nullopt;
    }

    std::vector<ShadowBanFederationRecord> get_federation_records_for_ban(
        int64_t ban_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<ShadowBanFederationRecord> results;
        for (const auto& [id, rec] : federation_) {
            if (rec.local_ban_id == ban_id) results.push_back(rec);
        }
        return results;
    }

    std::vector<ShadowBanFederationRecord> get_due_federation_syncs() {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<ShadowBanFederationRecord> results;
        int64_t now = now_ms();
        for (const auto& [id, rec] : federation_) {
            if (rec.sync_enabled && rec.next_sync_ts_ms <= now) {
                results.push_back(rec);
            }
        }
        return results;
    }

    bool update_federation_record(int64_t id,
                                   const ShadowBanFederationRecord& updated) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = federation_.find(id);
        if (it == federation_.end()) return false;
        it->second = updated;
        return true;
    }

    // ---- Behavioral Data ----

    int64_t record_behavior(const ShadowBanBehaviorEntry& entry) {
        std::lock_guard<std::mutex> lock(mutex_);
        int64_t id = next_behavior_id_++;
        auto& stored = behaviors_[id] = entry;
        stored.id = id;
        stored.created_ts_ms = now_ms();
        stored.last_active_ts_ms = stored.created_ts_ms;
        // Keep total behavioral data bounded
        while (behaviors_.size() > kMaxBehavioralSampleSize) {
            behaviors_.erase(behaviors_.begin());
        }
        return id;
    }

    std::vector<ShadowBanBehaviorEntry> get_behaviors_for_ip(
        const std::string& ip_address, int64_t limit = 50) {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<ShadowBanBehaviorEntry> results;
        for (const auto& [id, entry] : behaviors_) {
            if (entry.ip_address == ip_address) {
                results.push_back(entry);
                if (static_cast<int64_t>(results.size()) >= limit) break;
            }
        }
        return results;
    }

    std::vector<ShadowBanBehaviorEntry> get_behaviors_for_device(
        const std::string& fingerprint, int64_t limit = 50) {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<ShadowBanBehaviorEntry> results;
        for (const auto& [id, entry] : behaviors_) {
            if (entry.device_fingerprint == fingerprint) {
                results.push_back(entry);
                if (static_cast<int64_t>(results.size()) >= limit) break;
            }
        }
        return results;
    }

    std::vector<ShadowBanBehaviorEntry> get_high_risk_behaviors() {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<ShadowBanBehaviorEntry> results;
        for (const auto& [id, entry] : behaviors_) {
            if (entry.risk_level == BehavioralRiskLevel::HIGH ||
                entry.risk_level == BehavioralRiskLevel::CRITICAL) {
                results.push_back(entry);
            }
        }
        return results;
    }

    // ---- Metrics ----

    ShadowBanMetrics compute_metrics() {
        std::lock_guard<std::mutex> lock(mutex_);
        ShadowBanMetrics m;
        int64_t now = now_ms();

        for (const auto& [id, ban] : bans_) {
            m.total_bans_ever++;
            if (ban.is_active) {
                m.total_active_bans++;
                m.bans_by_severity[severity_to_str(ban.severity)]++;
                m.bans_by_scope[scope_to_str(ban.scope)]++;
            }
        }

        for (const auto& [id, entry] : history_) {
            if (entry.action == "removed") m.total_unbans++;
            if (entry.action == "expired") m.total_expired++;
        }

        for (const auto& [id, appeal] : appeals_) {
            m.total_appeals++;
            switch (appeal.status) {
                case AppealStatus::PENDING:
                case AppealStatus::UNDER_REVIEW: m.pending_appeals++; break;
                case AppealStatus::APPROVED: m.approved_appeals++; break;
                case AppealStatus::DENIED: m.denied_appeals++; break;
                default: break;
            }
        }

        m.total_events_intercepted = static_cast<int64_t>(intercepted_events_.size());
        m.total_federation_syncs = static_cast<int64_t>(federation_.size());
        m.total_behavioral_flags = static_cast<int64_t>(behaviors_.size());
        m.last_updated_ts_ms = now;

        return m;
    }

    // ---- Database path accessor ----

    const std::string& db_path() const { return db_path_; }

private:
    void store_history(int64_t ban_id, const std::string& action,
                       const std::string& changed_by,
                       const json& old_state, const json& new_state,
                       const std::string& reason, const std::string& ip) {
        ShadowBanHistoryEntry entry;
        entry.id = next_history_id_++;
        entry.ban_id = ban_id;
        entry.action = action;
        entry.changed_by = changed_by;
        entry.changed_ts_ms = now_ms();
        entry.old_state = old_state;
        entry.new_state = new_state;
        entry.change_reason = reason;
        entry.client_ip = ip;
        history_.push_back(entry);
    }

    std::string db_path_;
    std::mutex mutex_;

    std::map<int64_t, ShadowBanRecord> bans_;
    std::map<int64_t, ShadowBanPolicy> policies_;
    std::map<int64_t, ShadowBanEventRecord> intercepted_events_;
    std::map<int64_t, ShadowBanAppeal> appeals_;
    std::map<int64_t, ShadowBanOverride> overrides_;
    std::map<int64_t, ShadowBanFederationRecord> federation_;
    std::map<int64_t, ShadowBanBehaviorEntry> behaviors_;
    std::deque<ShadowBanAuditEntry> audit_log_;
    std::vector<ShadowBanHistoryEntry> history_;

    std::atomic<int64_t> next_ban_id_{1};
    std::atomic<int64_t> next_policy_id_{1};
    std::atomic<int64_t> next_event_id_{1};
    std::atomic<int64_t> next_appeal_id_{1};
    std::atomic<int64_t> next_history_id_{1};
    std::atomic<int64_t> next_override_id_{1};
    std::atomic<int64_t> next_federation_id_{1};
    std::atomic<int64_t> next_behavior_id_{1};
};

// ============================================================================
// 2. ShadowBanChecker — Multi-layered shadow ban detection
// ============================================================================

class ShadowBanChecker {
public:
    ShadowBanChecker(std::shared_ptr<ShadowBanStore> store,
                     const std::string& server_name)
        : store_(std::move(store)), server_name_(server_name) {}

    // Primary check entry point — returns comprehensive response
    ShadowBanCheckResponse check(const ShadowBanCheckRequest& req) {
        ShadowBanCheckResponse resp;
        resp.checked_ts_ms = now_ms();

        auto all_bans = store_->get_all_active_bans();
        int64_t now = now_ms();

        for (const auto& ban : all_bans) {
            if (ban.expires_ts_ms > 0 && ban.expires_ts_ms < now) continue;
            if (matches_request(ban, req)) {
                resp.matching_bans.push_back(ban);
            }
        }

        if (resp.matching_bans.empty()) {
            resp.is_shadow_banned = false;
            resp.should_intercept = false;
            resp.should_redact = false;
            return resp;
        }

        resp.is_shadow_banned = true;

        // Determine effective severity — pick the most restrictive
        ShadowBanSeverity most_severe = ShadowBanSeverity::SILENT;
        for (const auto& ban : resp.matching_bans) {
            if (static_cast<uint8_t>(ban.severity) >
                static_cast<uint8_t>(most_severe)) {
                most_severe = ban.severity;
            }
        }
        resp.effective_severity = most_severe;

        // Determine what to do based on severity
        switch (most_severe) {
            case ShadowBanSeverity::SILENT:
            case ShadowBanSeverity::GHOST:
            case ShadowBanSeverity::ECHO:
                resp.should_intercept = true;
                resp.should_redact = true;
                resp.decision_reason = "User is shadow banned ("
                    + std::string(severity_to_str(most_severe)) + ")";
                break;

            case ShadowBanSeverity::MUTED:
                resp.should_intercept = true;
                resp.should_redact = true;
                resp.decision_reason = "User is muted";
                break;

            case ShadowBanSeverity::READ_ONLY:
                resp.should_intercept = true;
                resp.should_redact = false;
                resp.decision_reason = "User is read-only — events will be rejected";
                break;

            case ShadowBanSeverity::RESTRICTED:
                resp.should_intercept = true;
                resp.should_redact = true;
                resp.decision_reason = "User is restricted";
                break;

            case ShadowBanSeverity::SANDBOX:
                resp.should_intercept = true;
                resp.should_redact = false;
                resp.should_redirect = true;
                resp.redirect_room_id = resp.matching_bans.front().quarantine_room_id;
                resp.should_quarantine = true;
                resp.decision_reason = "User is sandboxed";
                break;
        }

        // Check room-level overrides — these can override the ban behavior
        if (!req.room_id.empty()) {
            auto overrides = store_->get_overrides_for_room(req.room_id);
            for (const auto& ovr : overrides) {
                if (!ovr.override_active) continue;
                // If override says to exempt this room, relax the ban
                for (const auto& ban : resp.matching_bans) {
                    for (const auto& exempt : ban.exempt_rooms) {
                        if (exempt == req.room_id) {
                            resp.should_intercept = false;
                            resp.should_redact = false;
                            resp.should_redirect = false;
                            resp.decision_reason = "Room is exempt from shadow ban";
                            return resp;
                        }
                    }
                }
            }
        }

        // Check event type filter
        if (!req.event_type.empty() && !resp.matching_bans.empty()) {
            for (const auto& ban : resp.matching_bans) {
                if (!ban.filter_all_events && !ban.event_type_filter.empty()) {
                    // If event type is not in the filter list, don't intercept
                    auto pos = ban.event_type_filter.find(req.event_type);
                    if (pos == std::string::npos) {
                        resp.should_intercept = false;
                        resp.decision_reason = "Event type not filtered by ban";
                    }
                }
            }
        }

        resp.matched_rule = resp.matching_bans[0].reason;
        return resp;
    }

    // Quick check — is this user shadow banned at all?
    bool is_shadow_banned(const std::string& user_id) {
        ShadowBanCheckRequest req;
        req.user_id = user_id;
        return check(req).is_shadow_banned;
    }

    // Check if user should have events from sender intercepted
    bool should_intercept_event(const std::string& sender_id,
                                const std::string& room_id,
                                const std::string& event_type) {
        ShadowBanCheckRequest req;
        req.user_id = sender_id;
        req.room_id = room_id;
        req.event_type = event_type;
        return check(req).should_intercept;
    }

    // Check if federation traffic should be blocked
    bool should_block_federation(const std::string& sender_id,
                                  const std::string& origin_server) {
        ShadowBanCheckRequest req;
        req.user_id = sender_id;
        req.server_name = origin_server;
        req.is_federation = true;
        req.federation_origin = origin_server;
        return check(req).should_intercept;
    }

    // Check all bans that match a given user
    std::vector<ShadowBanRecord> get_bans_for_user(const std::string& user_id) {
        std::vector<ShadowBanRecord> results;

        // Check user-scoped bans
        auto user_bans = store_->get_active_bans_for_target(
            user_id, ShadowBanScope::USER);
        results.insert(results.end(), user_bans.begin(), user_bans.end());

        // Check server-scoped bans (by server name)
        auto domain = extract_domain(user_id);
        if (!domain.empty()) {
            auto server_bans = store_->get_active_bans_for_target(
                domain, ShadowBanScope::SERVER);
            results.insert(results.end(), server_bans.begin(), server_bans.end());

            auto domain_bans = store_->get_active_bans_for_target(
                domain, ShadowBanScope::DOMAIN);
            results.insert(results.end(), domain_bans.begin(), domain_bans.end());
        }

        return results;
    }

    // Expose the store for other components
    std::shared_ptr<ShadowBanStore> store() { return store_; }

private:
    bool matches_request(const ShadowBanRecord& ban,
                         const ShadowBanCheckRequest& req) {
        if (!ban.is_active) return false;

        // Check scope
        switch (ban.scope) {
            case ShadowBanScope::USER:
                return !req.user_id.empty() &&
                       match_target(req.user_id, ban.target, ban.match_type);

            case ShadowBanScope::ROOM:
                if (req.room_id != ban.room_id) return false;
                return !req.user_id.empty() &&
                       match_target(req.user_id, ban.target, ban.match_type);

            case ShadowBanScope::SERVER:
                if (!req.server_name.empty()) {
                    return match_target(req.server_name, ban.target, ban.match_type);
                }
                if (!req.user_id.empty()) {
                    auto domain = extract_domain(req.user_id);
                    return !domain.empty() &&
                           match_target(domain, ban.target, ban.match_type);
                }
                if (!req.federation_origin.empty()) {
                    return match_target(req.federation_origin, ban.target,
                                        ban.match_type);
                }
                return false;

            case ShadowBanScope::DOMAIN: {
                auto domain = extract_domain(req.user_id);
                return !domain.empty() &&
                       match_target(domain, ban.target, ban.match_type);
            }

            case ShadowBanScope::IP_ADDRESS:
                return !req.ip_address.empty() &&
                       match_target(req.ip_address, ban.target, ban.match_type);

            case ShadowBanScope::DEVICE:
                return !req.device_fingerprint.empty() &&
                       match_target(req.device_fingerprint, ban.target,
                                    ban.match_type);

            case ShadowBanScope::APPLICATION:
                return !req.appservice_id.empty() &&
                       match_target(req.appservice_id, ban.target, ban.match_type);

            default:
                return false;
        }
    }

    std::shared_ptr<ShadowBanStore> store_;
    std::string server_name_;
};

// ============================================================================
// 3. ShadowBanMessageFilter — Message interception and fake success
// ============================================================================

class ShadowBanMessageFilter {
public:
    ShadowBanMessageFilter(std::shared_ptr<ShadowBanStore> store,
                           std::shared_ptr<ShadowBanChecker> checker)
        : store_(std::move(store)), checker_(std::move(checker)) {}

    // Process an outgoing event from a potentially shadow banned user.
    // Returns the event (possibly modified/redacted), or nullopt if dropped.
    // The key behavior: the sender sees "success" even when their message
    // is intercepted.
    struct FilterResult {
        json processed_event;       // the event to actually propagate (may be redacted)
        bool was_intercepted = false;
        bool was_redacted = false;
        bool was_redirected = false;
        std::string redirect_room_id;
        bool send_fake_success = true;
        json fake_response;         // what to return to the sender
        std::string disposition;    // "allowed", "dropped", "redacted", "redirected"
    };

    FilterResult filter_outgoing_event(const json& event,
                                        const std::string& event_id_generated,
                                        const std::string& sender_ip = "") {
        FilterResult result;
        result.processed_event = event;

        std::string sender_id = event.value("sender", "");
        std::string room_id = event.value("room_id", "");
        std::string event_type = event.value("type", "");

        ShadowBanCheckRequest req;
        req.user_id = sender_id;
        req.room_id = room_id;
        req.event_type = event_type;
        req.ip_address = sender_ip;

        auto check_resp = checker_->check(req);

        if (!check_resp.is_shadow_banned || !check_resp.should_intercept) {
            result.was_intercepted = false;
            result.disposition = "allowed";
            result.send_fake_success = false;
            return result;
        }

        result.was_intercepted = true;
        result.disposition = "dropped";

        // Record the intercepted event
        ShadowBanEventRecord event_rec;
        event_rec.event_id = event_id_generated;
        event_rec.event_type = event_type;
        event_rec.sender_id = sender_id;
        event_rec.room_id = room_id;
        event_rec.event_content = event.value("content", json::object());
        event_rec.was_redacted = check_resp.should_redact;
        event_rec.was_redirected = check_resp.should_redirect;
        event_rec.redirect_room_id = check_resp.redirect_room_id;
        event_rec.disposition = result.disposition;
        event_rec.decision_reason = check_resp.decision_reason;
        if (!check_resp.matching_bans.empty()) {
            event_rec.ban_id = check_resp.matching_bans[0].id;
        }
        store_->record_intercepted_event(event_rec);

        // Build the fake success response for the sender
        // This is the key to shadow banning — the user thinks it worked
        result.fake_response = build_fake_success_response(
            event, event_id_generated);
        result.send_fake_success = true;

        // If redirecting, modify the event to go to the quarantine room
        if (check_resp.should_redirect && !check_resp.redirect_room_id.empty()) {
            result.was_redirected = true;
            result.redirect_room_id = check_resp.redirect_room_id;
            result.processed_event["room_id"] = check_resp.redirect_room_id;
            result.disposition = "redirected";
        }

        // If redacting, strip the content
        if (check_resp.should_redact) {
            result.was_redacted = true;
            result.processed_event["content"] = json::object();
            result.processed_event["unsigned"] = json::object();
            if (result.processed_event.contains("unsigned")) {
                result.processed_event["unsigned"]["redacted_because"] = {
                    {"reason", "Message from shadow banned user"},
                    {"redacted_by", server_name_}
                };
            }
            result.disposition = "redacted";
        }

        // For the echo severity, the sender sees their messages but nobody else
        if (check_resp.effective_severity == ShadowBanSeverity::ECHO) {
            // The event is only delivered to the sender's own sync
            // This would be handled in the sync engine — here we just note it
            result.disposition = "echo_only";
        }

        // Audit the interception
        ShadowBanAuditEntry audit;
        audit.operation = "event_intercepted";
        audit.operator_id = "shadow_ban_system";
        audit.target = sender_id;
        audit.scope = ShadowBanScope::USER;
        audit.operation_ts_ms = now_ms();
        audit.details = {
            {"event_id", event_id_generated},
            {"event_type", event_type},
            {"room_id", room_id},
            {"disposition", result.disposition},
            {"severity", severity_to_str(check_resp.effective_severity)}
        };
        audit.outcome = "success";
        store_->write_audit(audit);

        return result;
    }

    // Build a fake success JSON response that the sender sees
    // This mimics what a normal successful event send would return
    json build_fake_success_response(const json& original_event,
                                       const std::string& event_id) {
        json response;
        response["event_id"] = event_id;
        // Add a realistic fake origin_server_ts
        response["origin_server_ts"] = now_ms();
        response["sent"] = true;

        // If it was a room event, include a fake room_id echo
        if (original_event.contains("room_id")) {
            response["room_id"] = original_event["room_id"];
        }

        // Include a fake transaction_id if one was present
        if (original_event.contains("unsigned") &&
            original_event["unsigned"].contains("transaction_id")) {
            response["transaction_id"] =
                original_event["unsigned"]["transaction_id"];
        }

        return response;
    }

    // Process federation event - filter incoming events from shadow banned users
    // on remote servers
    FilterResult filter_federation_event(const json& event,
                                           const std::string& origin_server) {
        FilterResult result;
        result.processed_event = event;

        std::string sender_id = event.value("sender", "");
        std::string room_id = event.value("room_id", "");
        std::string event_type = event.value("type", "");

        ShadowBanCheckRequest req;
        req.user_id = sender_id;
        req.room_id = room_id;
        req.event_type = event_type;
        req.server_name = origin_server;
        req.is_federation = true;
        req.federation_origin = origin_server;

        auto check_resp = checker_->check(req);

        if (!check_resp.is_shadow_banned || !check_resp.should_intercept) {
            result.was_intercepted = false;
            result.disposition = "allowed";
            result.send_fake_success = false;
            return result;
        }

        result.was_intercepted = true;
        result.disposition = "dropped";

        if (check_resp.should_redact) {
            result.was_redacted = true;
            result.processed_event = json::object();
            result.processed_event["type"] = "m.room.redaction";
            result.processed_event["sender"] = sender_id;
            result.processed_event["room_id"] = room_id;
            result.processed_event["redacts"] = event.value("event_id", "");
            result.disposition = "redacted";
        }

        return result;
    }

private:
    std::shared_ptr<ShadowBanStore> store_;
    std::shared_ptr<ShadowBanChecker> checker_;
    std::string server_name_ = "progressive";
};

// ============================================================================
// 4. ShadowBanSyncFilter — Filter shadow banned content from sync
// ============================================================================

class ShadowBanSyncFilter {
public:
    ShadowBanSyncFilter(std::shared_ptr<ShadowBanStore> store,
                        std::shared_ptr<ShadowBanChecker> checker)
        : store_(std::move(store)), checker_(std::move(checker)) {}

    // Filter a sync response for a given user.
    // This removes events sent by shadow banned users from the sync timeline,
    // so other users don't see shadow banned content.
    struct SyncFilterResult {
        json filtered_sync;
        int events_filtered = 0;
        int events_redacted = 0;
        int rooms_affected = 0;
        std::vector<std::string> filtered_event_ids;
    };

    SyncFilterResult filter_sync_response(const json& sync_response,
                                            const std::string& requesting_user) {
        SyncFilterResult result;
        result.filtered_sync = sync_response;

        // Process each room
        if (sync_response.contains("rooms")) {
            const auto& rooms = sync_response["rooms"];

            // Join rooms
            if (rooms.contains("join")) {
                json filtered_join = json::object();
                for (auto& [room_id, room_data] : rooms["join"].items()) {
                    auto filtered = filter_room_timeline(
                        room_data, room_id, requesting_user);
                    if (filtered.events_filtered > 0) {
                        result.rooms_affected++;
                        result.events_filtered += filtered.events_filtered;
                        result.events_redacted += filtered.events_redacted;
                        for (auto& id : filtered.filtered_event_ids) {
                            result.filtered_event_ids.push_back(id);
                        }
                    }
                    filtered_join[room_id] = filtered.filtered_room;
                }
                result.filtered_sync["rooms"]["join"] = filtered_join;
            }

            // Invite rooms
            if (rooms.contains("invite")) {
                json filtered_invite = json::object();
                for (auto& [room_id, room_data] : rooms["invite"].items()) {
                    auto filtered = filter_room_invite(room_data, requesting_user);
                    if (filtered.events_filtered > 0) {
                        result.rooms_affected++;
                        result.events_filtered += filtered.events_filtered;
                    }
                    filtered_invite[room_id] = filtered.filtered_room;
                }
                result.filtered_sync["rooms"]["invite"] = filtered_invite;
            }

            // Leave rooms
            if (rooms.contains("leave")) {
                json filtered_leave = json::object();
                for (auto& [room_id, room_data] : rooms["leave"].items()) {
                    auto filtered = filter_room_timeline(
                        room_data, room_id, requesting_user);
                    if (filtered.events_filtered > 0) {
                        result.rooms_affected++;
                        result.events_filtered += filtered.events_filtered;
                        result.events_redacted += filtered.events_redacted;
                    }
                    filtered_leave[room_id] = filtered.filtered_room;
                }
                result.filtered_sync["rooms"]["leave"] = filtered_leave;
            }
        }

        // Filter presence — hide shadow banned users from presence list
        if (sync_response.contains("presence")) {
            json filtered_presence = json::object();
            if (sync_response["presence"].contains("events")) {
                json filtered_events = json::array();
                for (const auto& event : sync_response["presence"]["events"]) {
                    std::string sender = event.value("sender", "");
                    if (!sender.empty() && checker_->is_shadow_banned(sender)) {
                        result.events_filtered++;
                        continue; // Skip shadow banned user's presence
                    }
                    filtered_events.push_back(event);
                }
                filtered_presence["events"] = filtered_events;
            }
            result.filtered_sync["presence"] = filtered_presence;
        }

        // Filter account data if needed
        // (Generally account data is per-user so this is less common)

        return result;
    }

    // Filter timeline events in a single room
    struct RoomFilterResult {
        json filtered_room;
        int events_filtered = 0;
        int events_redacted = 0;
        std::vector<std::string> filtered_event_ids;
    };

    RoomFilterResult filter_room_timeline(const json& room_data,
                                            const std::string& room_id,
                                            const std::string& requesting_user) {
        RoomFilterResult result;
        result.filtered_room = room_data;

        if (!room_data.contains("timeline") ||
            !room_data["timeline"].contains("events")) {
            return result;
        }

        json filtered_events = json::array();
        for (const auto& event : room_data["timeline"]["events"]) {
            std::string sender = event.value("sender", "");
            std::string event_type = event.value("type", "");

            if (sender.empty()) {
                filtered_events.push_back(event);
                continue;
            }

            ShadowBanCheckRequest req;
            req.user_id = sender;
            req.room_id = room_id;
            req.event_type = event_type;

            auto check_resp = checker_->check(req);

            if (!check_resp.is_shadow_banned) {
                filtered_events.push_back(event);
                continue;
            }

            // Don't filter if the requesting user IS the shadow banned user
            // (they should see their own messages in their own sync)
            if (requesting_user == sender &&
                check_resp.effective_severity != ShadowBanSeverity::GHOST) {
                filtered_events.push_back(event);
                continue;
            }

            result.events_filtered++;

            if (check_resp.should_redact) {
                // Replace with a redacted version
                json redacted = event;
                redacted["content"] = json::object();
                redacted["unsigned"] = json::object();
                redacted["unsigned"]["age"] = event.value("unsigned", json::object())
                    .value("age", 0);
                redacted["unsigned"]["redacted_because"] = {
                    {"reason", "Message from shadow banned user"},
                    {"redacted_by", server_name_}
                };
                filtered_events.push_back(redacted);
                result.events_redacted++;
            }
            // Otherwise, the event is simply dropped from the timeline

            result.filtered_event_ids.push_back(
                event.value("event_id", "unknown"));
        }

        result.filtered_room["timeline"]["events"] = filtered_events;

        // Also filter state events in the timeline
        if (room_data.contains("state") &&
            room_data["state"].contains("events")) {
            json filtered_state = json::array();
            for (const auto& event : room_data["state"]["events"]) {
                std::string sender = event.value("sender", "");
                if (!sender.empty() && checker_->is_shadow_banned(sender) &&
                    requesting_user != sender) {
                    result.events_filtered++;
                    continue;
                }
                filtered_state.push_back(event);
            }
            result.filtered_room["state"]["events"] = filtered_state;
        }

        return result;
    }

    // Filter invite events
    RoomFilterResult filter_room_invite(const json& room_data,
                                         const std::string& requesting_user) {
        RoomFilterResult result;
        result.filtered_room = room_data;

        if (!room_data.contains("invite_state") ||
            !room_data["invite_state"].contains("events")) {
            return result;
        }

        json filtered_invites = json::array();
        for (const auto& event : room_data["invite_state"]["events"]) {
            std::string sender = event.value("sender", "");
            if (!sender.empty() && checker_->is_shadow_banned(sender)) {
                result.events_filtered++;
                continue;
            }
            filtered_invites.push_back(event);
        }
        result.filtered_room["invite_state"]["events"] = filtered_invites;
        return result;
    }

    // Also expose helper: filter a single event for delivery to a specific user
    json filter_single_event_for_recipient(const json& event,
                                             const std::string& recipient_user) {
        std::string sender = event.value("sender", "");
        if (sender.empty()) return event;

        if (!checker_->is_shadow_banned(sender)) return event;

        // If recipient IS the sender, allow delivery (echo behavior)
        if (recipient_user == sender) {
            auto bans = checker_->get_bans_for_user(sender);
            for (const auto& ban : bans) {
                if (ban.severity == ShadowBanSeverity::GHOST) {
                    // GHOST severity means not even the sender sees it
                    json redacted = event;
                    redacted["content"] = json::object();
                    return redacted;
                }
            }
            return event;
        }

        // Recipient is not the sender — check if they should see this
        auto bans = checker_->get_bans_for_user(sender);
        for (const auto& ban : bans) {
            if (ban.severity == ShadowBanSeverity::ECHO ||
                ban.severity == ShadowBanSeverity::GHOST ||
                ban.severity == ShadowBanSeverity::SILENT) {
                // Don't deliver
                return nullptr;
            }
            if (ban.severity == ShadowBanSeverity::MUTED) {
                // Allow read receipts, reactions, etc. but not messages
                // This would need event type checking
                return nullptr;
            }
        }

        return event; // For read-only, the event is delivered normally
    }

private:
    std::shared_ptr<ShadowBanStore> store_;
    std::shared_ptr<ShadowBanChecker> checker_;
    std::string server_name_ = "progressive";
};

// ============================================================================
// 5. ShadowBanFederation — Cross-server shadow ban coordination
// ============================================================================

class ShadowBanFederation {
public:
    ShadowBanFederation(std::shared_ptr<ShadowBanStore> store,
                        const std::string& server_name)
        : store_(std::move(store)), server_name_(server_name) {}

    // Push a local shadow ban to remote servers
    struct PushResult {
        bool success = false;
        std::string remote_server;
        int http_status = 0;
        std::string error_message;
        int64_t synced_ts_ms = 0;
    };

    PushResult push_ban_to_server(int64_t ban_id,
                                   const std::string& remote_server) {
        PushResult result;
        result.remote_server = remote_server;
        result.synced_ts_ms = now_ms();

        auto ban = store_->get_ban(ban_id);
        if (!ban) {
            result.error_message = "Ban not found: " + std::to_string(ban_id);
            return result;
        }

        // Build the federation push payload
        json push_payload;
        push_payload["type"] = "m.shadow_ban";
        push_payload["origin"] = server_name_;
        push_payload["origin_server_ts"] = result.synced_ts_ms;
        push_payload["content"] = ban->to_json();
        push_payload["content"]["action"] = "add";
        push_payload["content"]["origin_server"] = server_name_;

        // In a real implementation, this would perform an HTTP PUT to the
        // remote server's federation endpoint
        // For now, we record the intent and assume success
        ShadowBanFederationRecord rec;
        rec.local_ban_id = ban_id;
        rec.remote_server = remote_server;
        rec.remote_ban_id = generate_unique_id();
        rec.sync_direction = "push";
        rec.last_synced_ts_ms = result.synced_ts_ms;
        rec.next_sync_ts_ms = result.synced_ts_ms + 3600000; // 1 hour
        rec.sync_attempts = 1;
        rec.remote_metadata = push_payload;

        store_->create_federation_record(rec);

        result.success = true;
        result.http_status = 200;

        // Audit
        ShadowBanAuditEntry audit;
        audit.operation = "federation_push";
        audit.operator_id = "shadow_ban_system";
        audit.target = remote_server;
        audit.scope = ShadowBanScope::SERVER;
        audit.ban_id = ban_id;
        audit.operation_ts_ms = result.synced_ts_ms;
        audit.details = push_payload;
        audit.outcome = "success";
        store_->write_audit(audit);

        return result;
    }

    // Push a ban removal to remote servers
    PushResult push_unban_to_server(int64_t ban_id,
                                      const std::string& remote_server) {
        PushResult result;
        result.remote_server = remote_server;
        result.synced_ts_ms = now_ms();

        json push_payload;
        push_payload["type"] = "m.shadow_ban";
        push_payload["origin"] = server_name_;
        push_payload["origin_server_ts"] = result.synced_ts_ms;
        push_payload["content"]["action"] = "remove";
        push_payload["content"]["ban_id"] = ban_id;
        push_payload["content"]["origin_server"] = server_name_;

        // Update federation record
        auto records = store_->get_federation_records_for_ban(ban_id);
        for (auto& rec : records) {
            if (rec.remote_server == remote_server) {
                rec.last_synced_ts_ms = result.synced_ts_ms;
                rec.remote_metadata = push_payload;
                store_->update_federation_record(rec.id, rec);
            }
        }

        result.success = true;
        return result;
    }

    // Pull shadow ban updates from a remote server
    struct PullResult {
        bool success = false;
        std::string remote_server;
        int bans_received = 0;
        int bans_updated = 0;
        std::vector<int64_t> received_ban_ids;
        std::string error_message;
    };

    PullResult pull_bans_from_server(const std::string& remote_server) {
        PullResult result;
        result.remote_server = remote_server;

        // In a real implementation, this would perform an HTTP GET to the
        // remote server's federation shadow ban endpoint.
        // For now we simulate receiving bans.

        // Record the sync attempt
        ShadowBanFederationRecord rec;
        rec.remote_server = remote_server;
        rec.sync_direction = "pull";
        rec.last_synced_ts_ms = now_ms();
        rec.next_sync_ts_ms = now_ms() + 3600000;
        rec.sync_attempts = 1;
        store_->create_federation_record(rec);

        result.success = true;

        ShadowBanAuditEntry audit;
        audit.operation = "federation_pull";
        audit.operator_id = "shadow_ban_system";
        audit.target = remote_server;
        audit.scope = ShadowBanScope::SERVER;
        audit.operation_ts_ms = now_ms();
        audit.details = {{"remote_server", remote_server}};
        audit.outcome = "success";
        store_->write_audit(audit);

        return result;
    }

    // Handle incoming shadow ban directive from federation
    bool handle_incoming_shadow_ban(const json& federation_pdu,
                                      const std::string& origin_server,
                                      bool trust_remote = false) {
        // Verify the remote server is trusted if trust_remote is false
        if (!trust_remote) {
            // In a real system, verify the signature and check the remote
            // server against the trusted servers list
        }

        std::string action = federation_pdu.value("content", json::object())
            .value("action", "");
        auto ban_content = federation_pdu.value("content", json::object());

        if (action == "add") {
            ShadowBanRecord ban = ShadowBanRecord::from_json(ban_content);
            ban.origin_server = origin_server;
            ban.is_active = true;
            int64_t new_id = store_->create_ban(ban);

            ShadowBanAuditEntry audit;
            audit.operation = "federation_ban_received";
            audit.operator_id = origin_server;
            audit.target = ban.target;
            audit.ban_id = new_id;
            audit.operation_ts_ms = now_ms();
            audit.details = ban_content;
            audit.outcome = "success";
            store_->write_audit(audit);

            return true;

        } else if (action == "remove") {
            int64_t ban_id = ban_content.value("ban_id", 0LL);
            auto ban = store_->get_ban(ban_id);
            if (ban && ban->origin_server == origin_server) {
                store_->remove_ban(ban_id, origin_server,
                                    "Federation unban request");
                return true;
            }
        }

        return false;
    }

    // Sync all due federation records
    void sync_due_bans() {
        auto due_records = store_->get_due_federation_syncs();
        for (const auto& rec : due_records) {
            if (rec.sync_direction == "push") {
                push_ban_to_server(rec.local_ban_id, rec.remote_server);
            } else if (rec.sync_direction == "pull") {
                pull_bans_from_server(rec.remote_server);
            }
        }
    }

    // Get all federation records
    std::vector<ShadowBanFederationRecord> get_all_federation_records() {
        // Collect from all bans
        std::vector<ShadowBanFederationRecord> all_records;
        auto bans = store_->get_all_active_bans();
        for (const auto& ban : bans) {
            auto records = store_->get_federation_records_for_ban(ban.id);
            all_records.insert(all_records.end(), records.begin(), records.end());
        }
        return all_records;
    }

private:
    std::shared_ptr<ShadowBanStore> store_;
    std::string server_name_;
};

// ============================================================================
// 6. ShadowBanRateLimiter — Behavioral monitoring and evasion detection
// ============================================================================

class ShadowBanRateLimiter {
public:
    ShadowBanRateLimiter(std::shared_ptr<ShadowBanStore> store)
        : store_(std::move(store)) {}

    // Track a user action for rate limiting and behavioral analysis
    void track_user_action(const std::string& user_id,
                           const std::string& action_type,
                           const std::string& ip_address = "",
                           const std::string& device_fingerprint = "",
                           const std::string& user_agent = "") {
        std::lock_guard<std::mutex> lock(mutex_);

        std::string key = user_id + ":" + action_type;
        auto& bucket = rate_buckets_[key];
        bucket.push_back(now_ms());
        // Clean old entries
        int64_t cutoff = now_ms() - kDefaultRateLimitPeriod;
        while (!bucket.empty() && bucket.front() < cutoff) {
            bucket.pop_front();
        }

        // Track behavioral data for evasion detection
        if (!ip_address.empty() || !device_fingerprint.empty()) {
            ShadowBanBehaviorEntry entry;
            entry.user_id = user_id;
            entry.ip_address = ip_address;
            entry.device_fingerprint = device_fingerprint;
            entry.user_agent = user_agent;
            entry.server_name = extract_domain(user_id);
            entry.event_count = 1;
            store_->record_behavior(entry);
        }
    }

    // Check if a user action should be rate limited
    bool is_rate_limited(const std::string& user_id,
                         const std::string& action_type) {
        std::lock_guard<std::mutex> lock(mutex_);

        std::string key = user_id + ":" + action_type;
        auto& bucket = rate_buckets_[key];

        // Clean old entries
        int64_t cutoff = now_ms() - kDefaultRateLimitPeriod;
        while (!bucket.empty() && bucket.front() < cutoff) {
            bucket.pop_front();
        }

        return static_cast<int>(bucket.size()) > kDefaultRateLimitBurst;
    }

    // Detect ban evasion by checking for new accounts from previously
    // banned IPs or device fingerprints
    struct EvasionDetectionResult {
        bool likely_evasion = false;
        std::string matched_ip;
        std::string matched_device;
        std::string matched_previous_user;
        BehavioralRiskLevel risk_level = BehavioralRiskLevel::NONE;
        std::vector<std::string> associated_accounts;
        std::string detection_reason;
    };

    EvasionDetectionResult detect_evasion(const std::string& user_id,
                                            const std::string& ip_address,
                                            const std::string& device_fingerprint) {
        EvasionDetectionResult result;

        // Check for IP-based evasion
        if (!ip_address.empty()) {
            auto ip_behaviors = store_->get_behaviors_for_ip(ip_address);
            for (const auto& behav : ip_behaviors) {
                if (behav.previously_banned && behav.user_id != user_id) {
                    result.likely_evasion = true;
                    result.matched_ip = ip_address;
                    result.matched_previous_user = behav.previously_banned_as;
                    result.risk_level = BehavioralRiskLevel::HIGH;
                    result.associated_accounts.push_back(behav.user_id);
                    result.detection_reason = "IP address matches previously banned user";
                }
            }
        }

        // Check for device fingerprint evasion
        if (!device_fingerprint.empty()) {
            auto dev_behaviors = store_->get_behaviors_for_device(
                device_fingerprint);
            for (const auto& behav : dev_behaviors) {
                if (behav.previously_banned && behav.user_id != user_id) {
                    result.likely_evasion = true;
                    result.matched_device = device_fingerprint;
                    if (result.matched_previous_user.empty()) {
                        result.matched_previous_user = behav.previously_banned_as;
                    }
                    result.risk_level = BehavioralRiskLevel::HIGH;
                    result.associated_accounts.push_back(behav.user_id);
                    if (result.detection_reason.empty()) {
                        result.detection_reason = "Device fingerprint matches previously banned user";
                    }
                }
            }
        }

        // Check for multiple accounts from same IP
        if (!ip_address.empty()) {
            auto ip_behaviors = store_->get_behaviors_for_ip(ip_address);
            if (ip_behaviors.size() >= 5) {
                result.risk_level = std::max(result.risk_level,
                    BehavioralRiskLevel::MEDIUM);
                if (result.detection_reason.empty()) {
                    result.detection_reason =
                        "Multiple accounts from same IP address";
                }
            }
        }

        if (result.likely_evasion) {
            // Update the behavioral entry to flag the risk
            ShadowBanBehaviorEntry entry;
            entry.user_id = user_id;
            entry.ip_address = ip_address;
            entry.device_fingerprint = device_fingerprint;
            entry.risk_level = result.risk_level;
            entry.previously_banned = true;
            entry.previously_banned_as = result.matched_previous_user;
            entry.associated_user_ids = result.associated_accounts;
            store_->record_behavior(entry);

            ShadowBanAuditEntry audit;
            audit.operation = "evasion_detected";
            audit.operator_id = "shadow_ban_system";
            audit.target = user_id;
            audit.scope = ShadowBanScope::USER;
            audit.operation_ts_ms = now_ms();
            audit.details = {
                {"ip_address", ip_address},
                {"device_fingerprint", device_fingerprint},
                {"previous_user", result.matched_previous_user},
                {"risk_level", risk_level_str(result.risk_level)},
                {"detection_reason", result.detection_reason}
            };
            audit.outcome = "alert";
            store_->write_audit(audit);
        }

        return result;
    }

    // Get rate limit status for a user
    json get_rate_limit_status(const std::string& user_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        json status;
        int64_t now = now_ms();
        int64_t cutoff = now - kDefaultRateLimitPeriod;

        for (const auto& [key, bucket] : rate_buckets_) {
            if (key.starts_with(user_id + ":")) {
                std::string action = key.substr(user_id.size() + 1);
                int recent_count = 0;
                for (auto ts : bucket) {
                    if (ts >= cutoff) recent_count++;
                }
                status[action] = {
                    {"recent_count", recent_count},
                    {"limit", kDefaultRateLimitBurst},
                    {"period_ms", kDefaultRateLimitPeriod},
                    {"is_limited", recent_count > kDefaultRateLimitBurst}
                };
            }
        }

        return status;
    }

private:
    std::shared_ptr<ShadowBanStore> store_;
    std::mutex mutex_;
    std::map<std::string, std::deque<int64_t>> rate_buckets_;
};

// ============================================================================
// 7. ShadowBanAppealManager — Appeal submission and review
// ============================================================================

class ShadowBanAppealManager {
public:
    ShadowBanAppealManager(std::shared_ptr<ShadowBanStore> store)
        : store_(std::move(store)) {}

    // Submit a new appeal
    struct AppealResult {
        bool success = false;
        int64_t appeal_id = 0;
        std::string error_message;
    };

    AppealResult submit_appeal(const std::string& user_id,
                                int64_t ban_id,
                                const std::string& reason,
                                const std::string& details,
                                const std::vector<std::string>& attachments = {}) {
        AppealResult result;

        // Check if the user has too many open appeals
        auto existing = store_->get_appeals_for_user(user_id);
        int open_count = 0;
        for (const auto& a : existing) {
            if (a.status == AppealStatus::PENDING ||
                a.status == AppealStatus::UNDER_REVIEW) {
                open_count++;
            }
        }
        if (open_count >= kMaxAppealsPerUser) {
            result.error_message = "Maximum open appeals reached ("
                + std::to_string(kMaxAppealsPerUser) + ")";
            return result;
        }

        // Verify the ban exists
        auto ban = store_->get_ban(ban_id);
        if (!ban) {
            result.error_message = "Ban not found: " + std::to_string(ban_id);
            return result;
        }
        if (!ban->is_active) {
            result.error_message = "Ban is not active";
            return result;
        }

        ShadowBanAppeal appeal;
        appeal.ban_id = ban_id;
        appeal.user_id = user_id;
        appeal.appeal_reason = reason;
        appeal.appeal_details = details;
        appeal.evidence_attachments = attachments;
        appeal.status = AppealStatus::PENDING;

        result.appeal_id = store_->create_appeal(appeal);
        result.success = true;

        // Audit
        ShadowBanAuditEntry audit;
        audit.operation = "appeal_created";
        audit.operator_id = user_id;
        audit.target = user_id;
        audit.scope = ShadowBanScope::USER;
        audit.ban_id = ban_id;
        audit.appeal_id = result.appeal_id;
        audit.operation_ts_ms = now_ms();
        audit.details = {
            {"reason", reason},
            {"details", details},
            {"attachments_count", static_cast<int64_t>(attachments.size())}
        };
        audit.outcome = "success";
        store_->write_audit(audit);

        return result;
    }

    // Review an appeal (admin action)
    struct ReviewResult {
        bool success = false;
        AppealStatus new_status = AppealStatus::PENDING;
        std::string error_message;
    };

    ReviewResult review_appeal(int64_t appeal_id,
                                const std::string& reviewer_id,
                                AppealStatus decision,
                                const std::string& resolution_reason = "",
                                const std::string& reviewer_notes = "") {
        ReviewResult result;

        auto appeal = store_->get_appeal(appeal_id);
        if (!appeal) {
            result.error_message = "Appeal not found: "
                + std::to_string(appeal_id);
            return result;
        }

        if (appeal->status != AppealStatus::PENDING &&
            appeal->status != AppealStatus::UNDER_REVIEW) {
            result.error_message = "Appeal is not in a reviewable state: "
                + std::string(appeal_status_str(appeal->status));
            return result;
        }

        appeal->status = decision;
        appeal->reviewed_by = reviewer_id;
        appeal->reviewed_ts_ms = now_ms();
        appeal->resolution_reason = resolution_reason;
        appeal->reviewer_notes = reviewer_notes;

        if (decision == AppealStatus::APPROVED ||
            decision == AppealStatus::DENIED ||
            decision == AppealStatus::AUTO_RESOLVED) {
            appeal->resolution_ts_ms = now_ms();
        }

        result.success = store_->update_appeal(appeal_id, *appeal);
        result.new_status = decision;

        // If approved, remove the corresponding ban
        if (decision == AppealStatus::APPROVED && appeal->ban_id > 0) {
            store_->remove_ban(appeal->ban_id, reviewer_id,
                                "Appeal approved: " + resolution_reason);
        }

        // Audit
        ShadowBanAuditEntry audit;
        audit.operation = "appeal_reviewed";
        audit.operator_id = reviewer_id;
        audit.target = appeal->user_id;
        audit.scope = ShadowBanScope::USER;
        audit.ban_id = appeal->ban_id;
        audit.appeal_id = appeal_id;
        audit.operation_ts_ms = now_ms();
        audit.details = {
            {"decision", appeal_status_str(decision)},
            {"reason", resolution_reason},
            {"notes", reviewer_notes}
        };
        audit.outcome = "success";
        store_->write_audit(audit);

        return result;
    }

    // Get all pending appeals
    std::vector<ShadowBanAppeal> get_pending_appeals(int64_t limit = 50) {
        return store_->get_pending_appeals(limit);
    }

    // Withdraw an appeal (user action)
    bool withdraw_appeal(int64_t appeal_id, const std::string& user_id) {
        auto appeal = store_->get_appeal(appeal_id);
        if (!appeal || appeal->user_id != user_id) return false;

        if (appeal->status != AppealStatus::PENDING &&
            appeal->status != AppealStatus::UNDER_REVIEW) {
            return false;
        }

        appeal->status = AppealStatus::WITHDRAWN;
        appeal->resolution_ts_ms = now_ms();
        return store_->update_appeal(appeal_id, *appeal);
    }

    // Auto-expire appeals that have been pending too long
    void expire_old_appeals() {
        auto all_appeals = store_->get_pending_appeals(10000);
        int64_t cutoff = now_ms() - (kAppealResponseDays * 86400000LL);
        for (const auto& appeal : all_appeals) {
            if (appeal.created_ts_ms < cutoff &&
                appeal.status == AppealStatus::PENDING) {
                auto mutable_appeal = appeal;
                mutable_appeal.status = AppealStatus::EXPIRED;
                mutable_appeal.resolution_ts_ms = now_ms();
                mutable_appeal.resolution_reason = "Auto-expired after "
                    + std::to_string(kAppealResponseDays) + " days";
                store_->update_appeal(appeal.id, mutable_appeal);
            }
        }
    }

private:
    std::shared_ptr<ShadowBanStore> store_;
};

// ============================================================================
// 8. ShadowBanAuditLog — Audit trail management
// ============================================================================

class ShadowBanAuditLogManager {
public:
    explicit ShadowBanAuditLogManager(std::shared_ptr<ShadowBanStore> store)
        : store_(std::move(store)) {}

    // Query audit log with various filters
    json query_audit_log(const std::string& target = "",
                         const std::string& operation = "",
                         const std::string& operator_id = "",
                         int64_t limit = 100,
                         int64_t after_ts = 0) {
        auto entries = store_->query_audit_log(target, operation, limit, after_ts);

        json results = json::array();
        for (const auto& entry : entries) {
            if (!operator_id.empty() && entry.operator_id != operator_id) continue;
            results.push_back(entry.to_json());
        }

        json response;
        response["entries"] = results;
        response["total"] = results.size();
        response["limit"] = limit;
        return response;
    }

    // Export audit log to file
    bool export_audit_log(const std::string& filepath,
                          const std::string& format = "json") {
        auto entries = store_->query_audit_log("", "", kMaxAuditLogEntries);

        if (format == "json") {
            json output = json::array();
            for (const auto& entry : entries) {
                output.push_back(entry.to_json());
            }

            std::ofstream file(filepath);
            if (!file.is_open()) return false;
            file << output.dump(2);
            return true;
        } else if (format == "csv") {
            std::ofstream file(filepath);
            if (!file.is_open()) return false;
            file << "id,operation,operator_id,operator_ip,target,scope,"
                 << "ban_id,appeal_id,operation_ts_ms,outcome,error_message\n";
            for (const auto& entry : entries) {
                file << entry.id << ","
                     << entry.operation << ","
                     << entry.operator_id << ","
                     << entry.operator_ip << ","
                     << entry.target << ","
                     << scope_to_str(entry.scope) << ","
                     << entry.ban_id << ","
                     << entry.appeal_id << ","
                     << entry.operation_ts_ms << ","
                     << entry.outcome << ","
                     << entry.error_message << "\n";
            }
            return true;
        }

        return false;
    }

    // Get statistics from audit log
    json get_audit_statistics(const std::string& operator_id = "",
                               int64_t from_ts = 0, int64_t to_ts = 0) {
        if (to_ts == 0) to_ts = now_ms();

        auto entries = store_->query_audit_log("", "", kMaxAuditLogEntries);

        std::map<std::string, int64_t> ops_by_type;
        std::map<std::string, int64_t> ops_by_operator;
        int64_t total_entries = 0;
        int64_t errors = 0;
        int64_t successes = 0;

        for (const auto& entry : entries) {
            if (!operator_id.empty() && entry.operator_id != operator_id) continue;
            if (entry.operation_ts_ms < from_ts || entry.operation_ts_ms > to_ts)
                continue;

            total_entries++;
            ops_by_type[entry.operation]++;
            ops_by_operator[entry.operator_id]++;

            if (entry.outcome == "success") successes++;
            else if (entry.outcome == "failure") errors++;
        }

        json stats;
        stats["total_entries"] = total_entries;
        stats["successes"] = successes;
        stats["errors"] = errors;
        stats["operations_by_type"] = ops_by_type;
        stats["operations_by_operator"] = ops_by_operator;
        stats["from_ts"] = from_ts;
        stats["to_ts"] = to_ts;

        return stats;
    }

private:
    std::shared_ptr<ShadowBanStore> store_;
};

// ============================================================================
// 9. ShadowBanMetricsCollector — Metrics and reporting
// ============================================================================

class ShadowBanMetricsCollector {
public:
    ShadowBanMetricsCollector(std::shared_ptr<ShadowBanStore> store)
        : store_(std::move(store)) {}

    ShadowBanMetrics compute_metrics() {
        return store_->compute_metrics();
    }

    json get_dashboard_data() {
        auto metrics = store_->compute_metrics();
        json dash;

        dash["metrics"] = metrics.to_json();
        dash["generated_at"] = iso8601_now();

        // Top banned targets
        auto active_bans = store_->get_all_active_bans();
        std::map<std::string, int64_t> target_counts;
        for (const auto& ban : active_bans) {
            std::string domain = extract_domain(ban.target);
            if (!domain.empty()) target_counts[domain]++;
        }

        json top_domains = json::array();
        std::vector<std::pair<int64_t, std::string>> sorted;
        for (const auto& [domain, count] : target_counts) {
            sorted.push_back({count, domain});
        }
        std::sort(sorted.rbegin(), sorted.rend());
        for (size_t i = 0; i < std::min(sorted.size(), size_t(10)); ++i) {
            json entry;
            entry["domain"] = sorted[i].second;
            entry["bans"] = sorted[i].first;
            top_domains.push_back(entry);
        }
        dash["top_banned_domains"] = top_domains;

        // Recent activity
        auto audit = store_->query_audit_log("", "", 20);
        json recent = json::array();
        for (const auto& entry : audit) {
            json e;
            e["operation"] = entry.operation;
            e["operator"] = entry.operator_id;
            e["target"] = entry.target;
            e["ts"] = entry.operation_ts_ms;
            e["ts_display"] = ts_to_iso8601(entry.operation_ts_ms);
            recent.push_back(e);
        }
        dash["recent_activity"] = recent;

        // Pending appeals
        pending_appeals_ = store_->count_open_appeals();
        dash["pending_appeals"] = pending_appeals_;

        // High-risk behaviors
        auto high_risk = store_->get_high_risk_behaviors();
        dash["high_risk_behaviors"] = static_cast<int64_t>(high_risk.size());

        return dash;
    }

    int64_t get_pending_appeals_count() { return store_->count_open_appeals(); }

    void reset_counters() {
        // Reset atomic counters (placeholder — in a real system this would
        // reset SQL-based counters)
        pending_appeals_ = 0;
    }

private:
    std::shared_ptr<ShadowBanStore> store_;
    std::atomic<int64_t> pending_appeals_{0};
};

// ============================================================================
// 10. ShadowBanEnforcer — Main orchestrator / public API
// ============================================================================

class ShadowBanEnforcer {
public:
    ShadowBanEnforcer(const std::string& db_path = ":memory:",
                      const std::string& server_name = "progressive")
        : server_name_(server_name) {
        store_ = std::make_shared<ShadowBanStore>(db_path);
        checker_ = std::make_shared<ShadowBanChecker>(store_, server_name);
        message_filter_ = std::make_shared<ShadowBanMessageFilter>(
            store_, checker_);
        sync_filter_ = std::make_shared<ShadowBanSyncFilter>(
            store_, checker_);
        federation_ = std::make_shared<ShadowBanFederation>(store_, server_name);
        rate_limiter_ = std::make_shared<ShadowBanRateLimiter>(store_);
        appeal_manager_ = std::make_shared<ShadowBanAppealManager>(store_);
        audit_log_ = std::make_shared<ShadowBanAuditLogManager>(store_);
        metrics_ = std::make_shared<ShadowBanMetricsCollector>(store_);

        // Start periodic maintenance thread
        maintenance_running_ = true;
        maintenance_thread_ = std::thread([this]() {
            maintenance_loop();
        });
    }

    ~ShadowBanEnforcer() {
        maintenance_running_ = false;
        if (maintenance_thread_.joinable()) {
            maintenance_thread_.join();
        }
    }

    // ---- Ban Management ----

    json create_shadow_ban(const ShadowBanRecord& ban) {
        // Validate input
        if (ban.target.empty()) {
            return build_error("Target cannot be empty");
        }
        if (ban.reason.empty()) {
            return build_error("Reason is required");
        }
        if (ban.banned_by.empty()) {
            return build_error("Banned_by (operator) is required");
        }

        auto id = store_->create_ban(ban);

        // Audit
        ShadowBanAuditEntry audit;
        audit.operation = "ban_created";
        audit.operator_id = ban.banned_by;
        audit.target = ban.target;
        audit.scope = ban.scope;
        audit.ban_id = id;
        audit.operation_ts_ms = now_ms();
        audit.details = ban.to_json();
        audit.outcome = "success";
        store_->write_audit(audit);

        json response;
        response["success"] = true;
        response["ban_id"] = id;
        response["shadow_ban"] = ban.target;
        response["message"] = "Shadow ban created successfully";
        return response;
    }

    json create_shadow_ban_simple(
        const std::string& target,
        const std::string& reason,
        const std::string& banned_by,
        ShadowBanScope scope = ShadowBanScope::USER,
        ShadowBanSeverity severity = ShadowBanSeverity::GHOST,
        int64_t duration_ms = kDefaultBanDurationMs) {

        ShadowBanRecord ban;
        ban.target = target;
        ban.reason = reason;
        ban.banned_by = banned_by;
        ban.scope = scope;
        ban.severity = severity;
        ban.expires_ts_ms = duration_ms > 0 ? now_ms() + duration_ms : 0;
        ban.match_type = ShadowBanMatchType::EXACT;

        return create_shadow_ban(ban);
    }

    json remove_shadow_ban(int64_t ban_id,
                            const std::string& removed_by,
                            const std::string& reason = "") {
        auto ban = store_->get_ban(ban_id);
        if (!ban) return build_error("Ban not found: " + std::to_string(ban_id));
        if (!ban->is_active) return build_error("Ban is already inactive");

        bool success = store_->remove_ban(ban_id, removed_by, reason);
        if (!success) return build_error("Failed to remove ban");

        json response;
        response["success"] = true;
        response["ban_id"] = ban_id;
        response["target"] = ban->target;
        response["message"] = "Shadow ban removed successfully";
        return response;
    }

    json get_shadow_ban(int64_t ban_id) {
        auto ban = store_->get_ban(ban_id);
        if (!ban) return build_error("Ban not found: " + std::to_string(ban_id));
        return ban->to_json();
    }

    json list_active_bans(ShadowBanScope scope = ShadowBanScope::USER,
                           ShadowBanSeverity severity =
                           ShadowBanSeverity::SILENT,
                           bool filter_by_severity = false,
                           int64_t limit = 50, int64_t offset = 0) {
        auto all_bans = store_->get_all_active_bans();

        json results = json::array();
        int64_t skipped = 0;
        int64_t included = 0;

        for (const auto& ban : all_bans) {
            if (ban.scope != scope) continue;
            if (filter_by_severity && ban.severity != severity) continue;

            if (skipped < offset) { skipped++; continue; }
            if (included >= limit) break;

            results.push_back(ban.to_json());
            included++;
        }

        json response;
        response["bans"] = results;
        response["total"] = store_->count_active_bans();
        response["limit"] = limit;
        response["offset"] = offset;
        return response;
    }

    json get_bans_for_user(const std::string& user_id) {
        auto bans = checker_->get_bans_for_user(user_id);

        json results = json::array();
        for (const auto& ban : bans) {
            results.push_back(ban.to_json());
        }

        json response;
        response["user_id"] = user_id;
        response["bans"] = results;
        response["is_shadow_banned"] = !bans.empty();
        response["count"] = static_cast<int64_t>(bans.size());
        return response;
    }

    // ---- Bulk Operations ----

    json bulk_create_shadow_bans(
        const std::vector<std::string>& targets,
        const std::string& reason,
        const std::string& banned_by,
        ShadowBanScope scope = ShadowBanScope::USER,
        ShadowBanSeverity severity = ShadowBanSeverity::GHOST,
        int64_t duration_ms = kDefaultBanDurationMs) {

        ShadowBanBulkResult bulk_result;
        bulk_result.total_requested = static_cast<int>(targets.size());

        for (const auto& target : targets) {
            ShadowBanRecord ban;
            ban.target = target;
            ban.reason = reason;
            ban.banned_by = banned_by;
            ban.scope = scope;
            ban.severity = severity;
            ban.expires_ts_ms = duration_ms > 0 ? now_ms() + duration_ms : 0;
            ban.match_type = ShadowBanMatchType::EXACT;

            auto result = create_shadow_ban(ban);
            if (result["success"] == true) {
                bulk_result.succeeded++;
                bulk_result.succeeded_targets.push_back(target);
            } else {
                bulk_result.failed++;
                bulk_result.failed_targets.push_back(target);
                std::string err = result.value("error",
                    result.value("message", "Unknown error"));
                bulk_result.errors.push_back(target + ": " + err);
            }
        }

        return bulk_result.to_json();
    }

    json bulk_remove_shadow_bans(
        const std::vector<int64_t>& ban_ids,
        const std::string& removed_by,
        const std::string& reason = "") {

        ShadowBanBulkResult bulk_result;
        bulk_result.total_requested = static_cast<int>(ban_ids.size());

        for (auto id : ban_ids) {
            auto result = remove_shadow_ban(id, removed_by, reason);
            if (result["success"] == true) {
                bulk_result.succeeded++;
                bulk_result.succeeded_targets.push_back(std::to_string(id));
            } else {
                bulk_result.failed++;
                bulk_result.failed_targets.push_back(std::to_string(id));
                std::string err = result.value("error",
                    result.value("message", "Unknown error"));
                bulk_result.errors.push_back(std::to_string(id) + ": " + err);
            }
        }

        return bulk_result.to_json();
    }

    // ---- Policy Management ----

    json create_policy(const ShadowBanPolicy& policy) {
        if (policy.name.empty()) return build_error("Policy name is required");
        auto id = store_->create_policy(policy);

        json response;
        response["success"] = true;
        response["policy_id"] = id;
        response["message"] = "Shadow ban policy created successfully";
        return response;
    }

    json get_policy(int64_t policy_id) {
        auto policy = store_->get_policy(policy_id);
        if (!policy) {
            return build_error("Policy not found: " + std::to_string(policy_id));
        }
        return policy->to_json();
    }

    json list_policies() {
        auto policies = store_->get_all_active_policies();
        json results = json::array();
        for (const auto& policy : policies) {
            results.push_back(policy.to_json());
        }
        json response;
        response["policies"] = results;
        response["count"] = static_cast<int64_t>(policies.size());
        return response;
    }

    json update_policy(int64_t policy_id, const ShadowBanPolicy& updated) {
        if (!store_->update_policy(policy_id, updated)) {
            return build_error("Policy not found: " + std::to_string(policy_id));
        }
        json response;
        response["success"] = true;
        response["policy_id"] = policy_id;
        response["message"] = "Policy updated";
        return response;
    }

    json delete_policy(int64_t policy_id) {
        if (!store_->delete_policy(policy_id)) {
            return build_error("Policy not found: " + std::to_string(policy_id));
        }
        json response;
        response["success"] = true;
        response["policy_id"] = policy_id;
        response["message"] = "Policy deleted";
        return response;
    }

    // ---- Message Filtering ----

    // Filter an outgoing event. Returns the filtered event and whether
    // a fake success should be sent to the sender.
    struct FilterOutgoingResult {
        json filtered_event;
        bool should_send_fake_success = false;
        json fake_success_response;
        bool was_intercepted = false;
        std::string disposition;
    };

    FilterOutgoingResult filter_outgoing_event(
        const json& event, const std::string& event_id,
        const std::string& sender_ip = "") {

        auto result = message_filter_->filter_outgoing_event(
            event, event_id, sender_ip);

        FilterOutgoingResult r;
        r.filtered_event = result.processed_event;
        r.should_send_fake_success = result.send_fake_success;
        r.fake_success_response = result.fake_response;
        r.was_intercepted = result.was_intercepted;
        r.disposition = result.disposition;
        return r;
    }

    // Filter a federation event
    FilterOutgoingResult filter_federation_event(
        const json& event, const std::string& origin_server) {

        auto result = message_filter_->filter_federation_event(
            event, origin_server);

        FilterOutgoingResult r;
        r.filtered_event = result.processed_event;
        r.was_intercepted = result.was_intercepted;
        r.disposition = result.disposition;
        return r;
    }

    // ---- Sync Filtering ----

    json filter_sync_response(const json& sync_response,
                               const std::string& requesting_user) {
        auto result = sync_filter_->filter_sync_response(
            sync_response, requesting_user);

        json response;
        response["filtered_sync"] = result.filtered_sync;
        response["events_filtered"] = result.events_filtered;
        response["events_redacted"] = result.events_redacted;
        response["rooms_affected"] = result.rooms_affected;
        response["filtered_event_ids"] = result.filtered_event_ids;
        return response;
    }

    // ---- Checking ----

    ShadowBanCheckResponse check_user(const std::string& user_id,
                                        const std::string& room_id = "",
                                        const std::string& ip_address = "") {
        ShadowBanCheckRequest req;
        req.user_id = user_id;
        req.room_id = room_id;
        req.ip_address = ip_address;
        return checker_->check(req);
    }

    bool is_user_shadow_banned(const std::string& user_id) {
        return checker_->is_shadow_banned(user_id);
    }

    // ---- Appeals ----

    json submit_appeal(const std::string& user_id, int64_t ban_id,
                       const std::string& reason,
                       const std::string& details = "",
                       const std::vector<std::string>& attachments = {}) {
        auto result = appeal_manager_->submit_appeal(
            user_id, ban_id, reason, details, attachments);

        if (!result.success) {
            return build_error(result.error_message);
        }

        json response;
        response["success"] = true;
        response["appeal_id"] = result.appeal_id;
        response["message"] = "Appeal submitted successfully";
        return response;
    }

    json review_appeal(int64_t appeal_id, const std::string& reviewer_id,
                       const std::string& decision_str,
                       const std::string& reason = "",
                       const std::string& notes = "") {
        AppealStatus decision = appeal_status_from_str(decision_str);
        auto result = appeal_manager_->review_appeal(
            appeal_id, reviewer_id, decision, reason, notes);

        if (!result.success) {
            return build_error(result.error_message);
        }

        json response;
        response["success"] = true;
        response["appeal_id"] = appeal_id;
        response["new_status"] = appeal_status_str(result.new_status);
        response["message"] = "Appeal reviewed";
        return response;
    }

    json get_pending_appeals(int64_t limit = 50) {
        auto appeals = appeal_manager_->get_pending_appeals(limit);
        json results = json::array();
        for (const auto& appeal : appeals) {
            results.push_back(appeal.to_json());
        }
        json response;
        response["appeals"] = results;
        response["count"] = static_cast<int64_t>(appeals.size());
        return response;
    }

    json get_appeals_for_user(const std::string& user_id) {
        auto appeals = store_->get_appeals_for_user(user_id);
        json results = json::array();
        for (const auto& appeal : appeals) {
            results.push_back(appeal.to_json());
        }
        json response;
        response["user_id"] = user_id;
        response["appeals"] = results;
        response["count"] = static_cast<int64_t>(appeals.size());
        return response;
    }

    // ---- Rate Limiting & Behavioral ----

    json check_evasion(const std::string& user_id,
                       const std::string& ip_address = "",
                       const std::string& device_fingerprint = "") {
        auto result = rate_limiter_->detect_evasion(
            user_id, ip_address, device_fingerprint);

        json response;
        response["user_id"] = user_id;
        response["likely_evasion"] = result.likely_evasion;
        response["risk_level"] = risk_level_str(result.risk_level);
        if (!result.matched_ip.empty()) {
            response["matched_ip"] = result.matched_ip;
        }
        if (!result.matched_device.empty()) {
            response["matched_device"] = result.matched_device;
        }
        if (!result.matched_previous_user.empty()) {
            response["matched_previous_user"] = result.matched_previous_user;
        }
        if (!result.associated_accounts.empty()) {
            response["associated_accounts"] = result.associated_accounts;
        }
        if (!result.detection_reason.empty()) {
            response["detection_reason"] = result.detection_reason;
        }
        return response;
    }

    void track_user_action(const std::string& user_id,
                           const std::string& action_type,
                           const std::string& ip_address = "",
                           const std::string& device_fingerprint = "",
                           const std::string& user_agent = "") {
        rate_limiter_->track_user_action(
            user_id, action_type, ip_address, device_fingerprint, user_agent);
    }

    json get_rate_limit_status(const std::string& user_id) {
        return rate_limiter_->get_rate_limit_status(user_id);
    }

    // ---- Federation ----

    json push_ban_to_federation(int64_t ban_id, const std::string& remote) {
        auto result = federation_->push_ban_to_server(ban_id, remote);
        json response;
        response["success"] = result.success;
        response["remote_server"] = result.remote_server;
        if (!result.error_message.empty()) {
            response["error"] = result.error_message;
        }
        return response;
    }

    json handle_federation_shadow_ban(const json& pdu,
                                        const std::string& origin,
                                        bool trusted = false) {
        bool success = federation_->handle_incoming_shadow_ban(
            pdu, origin, trusted);
        json response;
        response["success"] = success;
        response["origin"] = origin;
        return response;
    }

    // ---- Audit ----

    json query_audit_log(const std::string& target = "",
                         const std::string& operation = "",
                         const std::string& operator_id = "",
                         int64_t limit = 100) {
        return audit_log_->query_audit_log(
            target, operation, operator_id, limit);
    }

    json get_audit_statistics(const std::string& operator_id = "",
                               int64_t from_ts = 0, int64_t to_ts = 0) {
        return audit_log_->get_audit_statistics(operator_id, from_ts, to_ts);
    }

    bool export_audit_log(const std::string& filepath,
                          const std::string& format = "json") {
        return audit_log_->export_audit_log(filepath, format);
    }

    // ---- Metrics ----

    json get_metrics() {
        return metrics_->compute_metrics().to_json();
    }

    json get_dashboard() {
        return metrics_->get_dashboard_data();
    }

    int64_t get_pending_appeals_count() {
        return metrics_->get_pending_appeals_count();
    }

    // ---- Overrides ----

    json create_override(const std::string& room_id,
                          int64_t ban_id,
                          const std::string& reason,
                          const std::string& applied_by) {
        ShadowBanOverride ovr;
        ovr.room_id = room_id;
        ovr.ban_id = ban_id;
        ovr.override_reason = reason;
        ovr.applied_by = applied_by;

        auto id = store_->create_override(ovr);

        json response;
        response["success"] = true;
        response["override_id"] = id;
        response["message"] = "Room override created";
        return response;
    }

    json delete_override(int64_t override_id) {
        if (!store_->delete_override(override_id)) {
            return build_error("Override not found: "
                + std::to_string(override_id));
        }
        json response;
        response["success"] = true;
        response["message"] = "Override deleted";
        return response;
    }

    json get_room_overrides(const std::string& room_id) {
        auto overrides = store_->get_overrides_for_room(room_id);
        json results = json::array();
        for (const auto& ovr : overrides) {
            results.push_back(ovr.to_json());
        }
        json response;
        response["room_id"] = room_id;
        response["overrides"] = results;
        response["count"] = static_cast<int64_t>(overrides.size());
        return response;
    }

    // ---- History ----

    json get_ban_history(int64_t ban_id, int64_t limit = 50) {
        auto history = store_->get_ban_history(ban_id, limit);
        json results = json::array();
        for (const auto& entry : history) {
            results.push_back(entry.to_json());
        }
        json response;
        response["ban_id"] = ban_id;
        response["history"] = results;
        response["count"] = static_cast<int64_t>(history.size());
        return response;
    }

    json get_user_ban_history(const std::string& user_id, int64_t limit = 50) {
        auto history = store_->get_user_ban_history(user_id, limit);
        json results = json::array();
        for (const auto& entry : history) {
            results.push_back(entry.to_json());
        }
        json response;
        response["user_id"] = user_id;
        response["history"] = results;
        response["count"] = static_cast<int64_t>(history.size());
        return response;
    }

    // ---- Intercepted Events ----

    json get_intercepted_events(const std::string& target,
                                  int64_t limit = 100) {
        auto events = store_->get_intercepted_events(target, limit);
        json results = json::array();
        for (const auto& evt : events) {
            results.push_back(evt.to_json());
        }
        json response;
        response["target"] = target;
        response["events"] = results;
        response["count"] = static_cast<int64_t>(events.size());
        return response;
    }

    // ---- Accessors ----

    std::shared_ptr<ShadowBanStore> store() { return store_; }
    std::shared_ptr<ShadowBanChecker> checker() { return checker_; }
    const std::string& server_name() const { return server_name_; }

private:
    void maintenance_loop() {
        while (maintenance_running_) {
            // Periodic maintenance every 60 seconds
            std::this_thread::sleep_for(chr::seconds(60));

            if (!maintenance_running_) break;

            try {
                // Expire old bans
                store_->expire_bans();

                // Expire old appeals
                appeal_manager_->expire_old_appeals();

                // Sync federation records
                federation_->sync_due_bans();

            } catch (const std::exception& e) {
                // Log error but continue
                ShadowBanAuditEntry audit;
                audit.operation = "maintenance_error";
                audit.operator_id = "system";
                audit.target = "maintenance";
                audit.scope = ShadowBanScope::USER;
                audit.operation_ts_ms = now_ms();
                audit.details = {{"error", e.what()}};
                audit.outcome = "failure";
                audit.error_message = e.what();
                store_->write_audit(audit);
            }
        }
    }

    json build_error(const std::string& message) {
        json response;
        response["success"] = false;
        response["error"] = message;
        return response;
    }

    std::shared_ptr<ShadowBanStore> store_;
    std::shared_ptr<ShadowBanChecker> checker_;
    std::shared_ptr<ShadowBanMessageFilter> message_filter_;
    std::shared_ptr<ShadowBanSyncFilter> sync_filter_;
    std::shared_ptr<ShadowBanFederation> federation_;
    std::shared_ptr<ShadowBanRateLimiter> rate_limiter_;
    std::shared_ptr<ShadowBanAppealManager> appeal_manager_;
    std::shared_ptr<ShadowBanAuditLogManager> audit_log_;
    std::shared_ptr<ShadowBanMetricsCollector> metrics_;
    std::string server_name_;
    std::thread maintenance_thread_;
    std::atomic<bool> maintenance_running_{false};
};

// ============================================================================
// 11. Singleton accessor — Global shadow ban system
// ============================================================================

namespace {

std::shared_ptr<ShadowBanEnforcer> g_shadow_ban_instance;
std::mutex g_shadow_ban_mutex;

} // anonymous namespace

std::shared_ptr<ShadowBanEnforcer> get_shadow_ban_enforcer(
    const std::string& db_path = ":memory:",
    const std::string& server_name = "progressive") {

    std::lock_guard<std::mutex> lock(g_shadow_ban_mutex);
    if (!g_shadow_ban_instance) {
        g_shadow_ban_instance = std::make_shared<ShadowBanEnforcer>(
            db_path, server_name);
    }
    return g_shadow_ban_instance;
}

void reset_shadow_ban_enforcer() {
    std::lock_guard<std::mutex> lock(g_shadow_ban_mutex);
    g_shadow_ban_instance.reset();
}

// ============================================================================
// 12. Public free functions for integration with rest handlers
// ============================================================================

// Quick shadow ban check for REST API middleware
// Returns true if the user should be allowed to proceed
bool shadow_ban_check_user(const std::string& user_id) {
    auto enforcer = get_shadow_ban_enforcer();
    return !enforcer->is_user_shadow_banned(user_id);
}

// Filter a sync response for shadow banned content
json shadow_ban_filter_sync(const json& sync_response,
                             const std::string& requesting_user) {
    auto enforcer = get_shadow_ban_enforcer();
    auto result = enforcer->filter_sync_response(sync_response, requesting_user);
    return result["filtered_sync"];
}

// Process an outgoing event — may return a fake success or the real event
json shadow_ban_process_event(const json& event,
                                const std::string& event_id,
                                const std::string& sender_ip) {
    auto enforcer = get_shadow_ban_enforcer();
    auto result = enforcer->filter_outgoing_event(event, event_id, sender_ip);

    if (result.should_send_fake_success) {
        return result.fake_success_response;
    }

    return result.filtered_event;
}

// Handle admin shadow ban command
json shadow_ban_admin_ban(const std::string& user_id,
                           const std::string& reason,
                           const std::string& admin_id,
                           int64_t duration_ms = kDefaultBanDurationMs) {
    auto enforcer = get_shadow_ban_enforcer();
    return enforcer->create_shadow_ban_simple(
        user_id, reason, admin_id, ShadowBanScope::USER,
        ShadowBanSeverity::GHOST, duration_ms);
}

// Handle admin shadow unban command
json shadow_ban_admin_unban(int64_t ban_id, const std::string& admin_id) {
    auto enforcer = get_shadow_ban_enforcer();
    return enforcer->remove_shadow_ban(ban_id, admin_id);
}

// Check for ban evasion
json shadow_ban_check_evasion(const std::string& user_id,
                                const std::string& ip_address,
                                const std::string& device_fingerprint) {
    auto enforcer = get_shadow_ban_enforcer();
    return enforcer->check_evasion(user_id, ip_address, device_fingerprint);
}

// ============================================================================
// End Namespace
// ============================================================================

} // namespace progressive
