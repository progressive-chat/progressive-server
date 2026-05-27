// ============================================================================
// ignored_users.cpp — Matrix Ignored Users Management
//
// Comprehensive ignored users system for the Matrix server:
//   - Add/Remove/Check Ignored Users: Per-user ignore list with full CRUD.
//     Support for exact user ID match, domain-wide ignores, and wildcard
//     patterns. Toggle ignore status, set expiration, add notes.
//   - Ignored User List Management: List all ignored users for a given
//     user, paginated listing, search/filter by user ID pattern, sort by
//     date or user ID. Import/export ignore lists. Bulk operations.
//   - Invite Blocking: Automatically block invites from ignored users.
//     Configurable per-user invite rejection policy. Auto-respond with
//     rejection reason. Track blocked invites for audit.
//   - Message Filtering: Filter incoming messages from ignored users.
//     Per-room overrides. Allow mentions bypass. Filter event types (m.room.message,
//     m.reaction, m.room.encrypted). Redact policy for ignored messages.
//     Configurable delivery: drop, quarantine, or flag.
//   - Federation Ignored User Handling: Propagate ignore lists across
//     federation. Verify remote ignore claims. Handle incoming ignore
//     directives. Federation-aware invite rejection. Cross-server
//     ignored user synchronization. Conflict resolution.
//
// SQL: All operations fully SQL-backed with proper indexing, no ORM.
//   Tables: ignored_users, ignored_users_invites,
//           ignored_users_messages, ignored_users_federation,
//           ignored_users_audit, ignored_users_overrides,
//           ignored_users_imports
//
// Equivalent to:
//   synapse/storage/databases/main/account_data.py
//     (ignored_users account data type)
//   synapse/handlers/room_member.py (invite rejection for ignored users)
//   synapse/handlers/message.py (message filtering)
//   synapse/federation/federation_server.py (federation handling)
//   matrix-org/matrix-spec/blob/main/data/api/client-server/definitions/
//     ignored_users_list.yaml
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
class IgnoredUsersStore;
class IgnoredUserManager;
class InviteBlocker;
class MessageFilter;
class FederationIgnoredUsers;
class IgnoredUsersAuditor;
class IgnoredUsersImportExport;
class IgnoredUsersMetrics;
class IgnoredUsersCoordinator;

// ============================================================================
// Enums and Constants
// ============================================================================

// The match type for ignored user patterns
enum class IgnoreMatchType : uint8_t {
    EXACT         = 0,  // Exact user ID match (@user:server)
    DOMAIN        = 1,  // Ignore entire domain (*:server)
    WILDCARD      = 2,  // Wildcard pattern (@user:*)
    REGEX         = 3,  // Regex pattern match
    LOCALPART     = 4   // Ignore by localpart only
};

const char* ignore_match_type_str(IgnoreMatchType t) {
    switch (t) {
        case IgnoreMatchType::EXACT:     return "exact";
        case IgnoreMatchType::DOMAIN:    return "domain";
        case IgnoreMatchType::WILDCARD:  return "wildcard";
        case IgnoreMatchType::REGEX:     return "regex";
        case IgnoreMatchType::LOCALPART: return "localpart";
        default:                         return "unknown";
    }
}

IgnoreMatchType ignore_match_type_from_str(const std::string& s) {
    if (s == "exact")     return IgnoreMatchType::EXACT;
    if (s == "domain")    return IgnoreMatchType::DOMAIN;
    if (s == "wildcard")  return IgnoreMatchType::WILDCARD;
    if (s == "regex")     return IgnoreMatchType::REGEX;
    if (s == "localpart") return IgnoreMatchType::LOCALPART;
    return IgnoreMatchType::EXACT;
}

// Invite handling policy for ignored users
enum class IgnoreInvitePolicy : uint8_t {
    BLOCK_SILENTLY = 0,  // Silently reject, no notification
    BLOCK_AND_LOG  = 1,  // Reject and log, but don't notify
    BLOCK_AND_NOTIFY = 2, // Reject and notify the blocker
    ALLOW_INVITES  = 3   // Allow invites even from ignored users
};

const char* ignore_invite_policy_str(IgnoreInvitePolicy p) {
    switch (p) {
        case IgnoreInvitePolicy::BLOCK_SILENTLY:  return "block_silently";
        case IgnoreInvitePolicy::BLOCK_AND_LOG:   return "block_and_log";
        case IgnoreInvitePolicy::BLOCK_AND_NOTIFY: return "block_and_notify";
        case IgnoreInvitePolicy::ALLOW_INVITES:   return "allow_invites";
        default:                                   return "unknown";
    }
}

IgnoreInvitePolicy ignore_invite_policy_from_str(const std::string& s) {
    if (s == "block_silently")   return IgnoreInvitePolicy::BLOCK_SILENTLY;
    if (s == "block_and_log")    return IgnoreInvitePolicy::BLOCK_AND_LOG;
    if (s == "block_and_notify")  return IgnoreInvitePolicy::BLOCK_AND_NOTIFY;
    if (s == "allow_invites")    return IgnoreInvitePolicy::ALLOW_INVITES;
    return IgnoreInvitePolicy::BLOCK_SILENTLY;
}

// Message delivery policy for ignored users
enum class IgnoreMessagePolicy : uint8_t {
    DROP          = 0,  // Completely drop the message
    QUARANTINE    = 1,  // Store but don't deliver to client
    FLAG          = 2,  // Deliver with ignored_user flag
    DELIVER_ALL   = 3   // Deliver all messages normally
};

const char* ignore_message_policy_str(IgnoreMessagePolicy p) {
    switch (p) {
        case IgnoreMessagePolicy::DROP:       return "drop";
        case IgnoreMessagePolicy::QUARANTINE: return "quarantine";
        case IgnoreMessagePolicy::FLAG:       return "flag";
        case IgnoreMessagePolicy::DELIVER_ALL: return "deliver_all";
        default:                               return "unknown";
    }
}

IgnoreMessagePolicy ignore_message_policy_from_str(const std::string& s) {
    if (s == "drop")        return IgnoreMessagePolicy::DROP;
    if (s == "quarantine")  return IgnoreMessagePolicy::QUARANTINE;
    if (s == "flag")        return IgnoreMessagePolicy::FLAG;
    if (s == "deliver_all") return IgnoreMessagePolicy::DELIVER_ALL;
    return IgnoreMessagePolicy::DROP;
}

// Federation ignore propagation direction
enum class FederationIgnoreDirection : uint8_t {
    OUTBOUND = 0,  // We are pushing our ignore list to remote
    INBOUND  = 1,  // We are receiving ignore list from remote
    BIDIRECTIONAL = 2
};

const char* federation_ignore_direction_str(FederationIgnoreDirection d) {
    switch (d) {
        case FederationIgnoreDirection::OUTBOUND:      return "outbound";
        case FederationIgnoreDirection::INBOUND:       return "inbound";
        case FederationIgnoreDirection::BIDIRECTIONAL: return "bidirectional";
        default:                                        return "unknown";
    }
}

FederationIgnoreDirection federation_ignore_direction_from_str(const std::string& s) {
    if (s == "outbound")      return FederationIgnoreDirection::OUTBOUND;
    if (s == "inbound")       return FederationIgnoreDirection::INBOUND;
    if (s == "bidirectional") return FederationIgnoreDirection::BIDIRECTIONAL;
    return FederationIgnoreDirection::BIDIRECTIONAL;
}

// Status of a federation ignore sync
enum class FederationIgnoreSyncStatus : uint8_t {
    PENDING     = 0,
    IN_PROGRESS = 1,
    SYNCED      = 2,
    FAILED      = 3,
    CONFLICT    = 4,
    EXPIRED     = 5
};

const char* fed_ignore_sync_status_str(FederationIgnoreSyncStatus s) {
    switch (s) {
        case FederationIgnoreSyncStatus::PENDING:     return "pending";
        case FederationIgnoreSyncStatus::IN_PROGRESS: return "in_progress";
        case FederationIgnoreSyncStatus::SYNCED:      return "synced";
        case FederationIgnoreSyncStatus::FAILED:      return "failed";
        case FederationIgnoreSyncStatus::CONFLICT:    return "conflict";
        case FederationIgnoreSyncStatus::EXPIRED:     return "expired";
        default:                                       return "unknown";
    }
}

FederationIgnoreSyncStatus fed_ignore_sync_status_from_str(const std::string& s) {
    if (s == "pending")      return FederationIgnoreSyncStatus::PENDING;
    if (s == "in_progress")  return FederationIgnoreSyncStatus::IN_PROGRESS;
    if (s == "synced")       return FederationIgnoreSyncStatus::SYNCED;
    if (s == "failed")       return FederationIgnoreSyncStatus::FAILED;
    if (s == "conflict")     return FederationIgnoreSyncStatus::CONFLICT;
    if (s == "expired")      return FederationIgnoreSyncStatus::EXPIRED;
    return FederationIgnoreSyncStatus::PENDING;
}

// Audit action types
enum class IgnoreAuditAction : uint8_t {
    IGNORE_ADDED    = 0,
    IGNORE_REMOVED  = 1,
    IGNORE_UPDATED  = 2,
    IGNORE_EXPIRED  = 3,
    INVITE_BLOCKED  = 4,
    MESSAGE_DROPPED = 5,
    MESSAGE_FLAGGED = 6,
    FED_SYNC_PUSH   = 7,
    FED_SYNC_PULL   = 8,
    LIST_IMPORTED   = 9,
    LIST_EXPORTED   = 10,
    BULK_OPERATION  = 11
};

const char* ignore_audit_action_str(IgnoreAuditAction a) {
    switch (a) {
        case IgnoreAuditAction::IGNORE_ADDED:    return "ignore_added";
        case IgnoreAuditAction::IGNORE_REMOVED:  return "ignore_removed";
        case IgnoreAuditAction::IGNORE_UPDATED:  return "ignore_updated";
        case IgnoreAuditAction::IGNORE_EXPIRED:  return "ignore_expired";
        case IgnoreAuditAction::INVITE_BLOCKED:  return "invite_blocked";
        case IgnoreAuditAction::MESSAGE_DROPPED: return "message_dropped";
        case IgnoreAuditAction::MESSAGE_FLAGGED: return "message_flagged";
        case IgnoreAuditAction::FED_SYNC_PUSH:   return "fed_sync_push";
        case IgnoreAuditAction::FED_SYNC_PULL:   return "fed_sync_pull";
        case IgnoreAuditAction::LIST_IMPORTED:   return "list_imported";
        case IgnoreAuditAction::LIST_EXPORTED:   return "list_exported";
        case IgnoreAuditAction::BULK_OPERATION:  return "bulk_operation";
        default:                                  return "unknown";
    }
}

// ============================================================================
// Storage forward declaration helpers
// ============================================================================
namespace storage {
class DatabasePool;
class LoggingTransaction;
} // namespace storage

using storage::DatabasePool;
using storage::LoggingTransaction;

// ============================================================================
// Ignored User data structures
// ============================================================================

struct IgnoredUserEntry {
    int64_t id = 0;
    std::string ignorer_user_id;   // Who is doing the ignoring
    std::string ignored_user_id;   // Who is being ignored (or pattern)
    IgnoreMatchType match_type = IgnoreMatchType::EXACT;
    std::string reason;
    int64_t ignored_ts = 0;
    int64_t expires_ts = 0;        // 0 = never expires
    bool is_active = true;
    IgnoreInvitePolicy invite_policy = IgnoreInvitePolicy::BLOCK_SILENTLY;
    IgnoreMessagePolicy message_policy = IgnoreMessagePolicy::DROP;
    std::string notes;
    std::string import_source;

    json to_json() const {
        json j;
        j["id"] = id;
        j["ignorer_user_id"] = ignorer_user_id;
        j["ignored_user_id"] = ignored_user_id;
        j["match_type"] = ignore_match_type_str(match_type);
        j["reason"] = reason;
        j["ignored_ts"] = ignored_ts;
        j["expires_ts"] = expires_ts;
        j["is_active"] = is_active;
        j["invite_policy"] = ignore_invite_policy_str(invite_policy);
        j["message_policy"] = ignore_message_policy_str(message_policy);
        j["notes"] = notes;
        if (!import_source.empty()) j["import_source"] = import_source;
        return j;
    }
};

struct IgnoreInviteBlockEntry {
    int64_t id = 0;
    std::string ignorer_user_id;
    std::string ignored_user_id;
    std::string room_id;
    std::string event_id;
    int64_t blocked_ts = 0;
    std::string rejection_reason;
    std::string policy_applied;
    bool notified = false;

    json to_json() const {
        json j;
        j["id"] = id;
        j["ignorer_user_id"] = ignorer_user_id;
        j["ignored_user_id"] = ignored_user_id;
        j["room_id"] = room_id;
        j["event_id"] = event_id;
        j["blocked_ts"] = blocked_ts;
        j["rejection_reason"] = rejection_reason;
        j["policy_applied"] = policy_applied;
        j["notified"] = notified;
        return j;
    }
};

struct IgnoreMessageFilterEntry {
    int64_t id = 0;
    std::string ignorer_user_id;
    std::string ignored_user_id;
    std::string room_id;
    std::string event_id;
    std::string event_type;
    int64_t filtered_ts = 0;
    IgnoreMessagePolicy action = IgnoreMessagePolicy::DROP;
    bool is_mention = false;
    bool delivered = false;
    std::string quarantine_id;

    json to_json() const {
        json j;
        j["id"] = id;
        j["ignorer_user_id"] = ignorer_user_id;
        j["ignored_user_id"] = ignored_user_id;
        j["room_id"] = room_id;
        j["event_id"] = event_id;
        j["event_type"] = event_type;
        j["filtered_ts"] = filtered_ts;
        j["action"] = ignore_message_policy_str(action);
        j["is_mention"] = is_mention;
        j["delivered"] = delivered;
        if (!quarantine_id.empty()) j["quarantine_id"] = quarantine_id;
        return j;
    }
};

struct FederationIgnoredUserEntry {
    int64_t id = 0;
    std::string origin_server;       // Server that originated the ignore
    std::string target_server;       // Server where the ignore applies
    std::string ignorer_user_id;
    std::string ignored_user_id;
    IgnoreMatchType match_type = IgnoreMatchType::EXACT;
    FederationIgnoreDirection direction = FederationIgnoreDirection::BIDIRECTIONAL;
    FederationIgnoreSyncStatus sync_status = FederationIgnoreSyncStatus::PENDING;
    int64_t created_ts = 0;
    int64_t synced_ts = 0;
    int64_t expires_ts = 0;
    bool is_active = true;
    std::string reason;
    std::string sync_id;
    int retry_count = 0;
    int64_t last_retry_ts = 0;

    json to_json() const {
        json j;
        j["id"] = id;
        j["origin_server"] = origin_server;
        j["target_server"] = target_server;
        j["ignorer_user_id"] = ignorer_user_id;
        j["ignored_user_id"] = ignored_user_id;
        j["match_type"] = ignore_match_type_str(match_type);
        j["direction"] = federation_ignore_direction_str(direction);
        j["sync_status"] = fed_ignore_sync_status_str(sync_status);
        j["created_ts"] = created_ts;
        j["synced_ts"] = synced_ts;
        j["expires_ts"] = expires_ts;
        j["is_active"] = is_active;
        j["reason"] = reason;
        j["sync_id"] = sync_id;
        j["retry_count"] = retry_count;
        j["last_retry_ts"] = last_retry_ts;
        return j;
    }
};

struct IgnoreAuditEntry {
    int64_t id = 0;
    IgnoreAuditAction action = IgnoreAuditAction::IGNORE_ADDED;
    std::string actor_user_id;
    std::string target_user_id;
    std::string details;
    int64_t action_ts = 0;
    std::string ip_address;
    std::string server_name;
    json metadata;

    json to_json() const {
        json j;
        j["id"] = id;
        j["action"] = ignore_audit_action_str(action);
        j["actor_user_id"] = actor_user_id;
        j["target_user_id"] = target_user_id;
        j["details"] = details;
        j["action_ts"] = action_ts;
        j["ip_address"] = ip_address;
        j["server_name"] = server_name;
        j["metadata"] = metadata;
        return j;
    }
};

struct IgnoreRoomOverride {
    int64_t id = 0;
    std::string ignorer_user_id;
    std::string ignored_user_id;
    std::string room_id;
    bool allow_messages = false;     // Override: allow messages in this room
    bool allow_invites = false;      // Override: allow invites in this room
    std::string reason;
    int64_t set_ts = 0;
    int64_t expires_ts = 0;
    bool is_active = true;

    json to_json() const {
        json j;
        j["id"] = id;
        j["ignorer_user_id"] = ignorer_user_id;
        j["ignored_user_id"] = ignored_user_id;
        j["room_id"] = room_id;
        j["allow_messages"] = allow_messages;
        j["allow_invites"] = allow_invites;
        j["reason"] = reason;
        j["set_ts"] = set_ts;
        j["expires_ts"] = expires_ts;
        j["is_active"] = is_active;
        return j;
    }
};

struct IgnoreImportEntry {
    int64_t id = 0;
    std::string import_id;
    std::string source_type;  // "json", "csv", "federation"
    std::string source;
    std::string imported_by;
    int64_t imported_ts = 0;
    int entry_count = 0;
    int error_count = 0;
    std::string status;  // "completed", "partial", "failed"
    json metadata;

    json to_json() const {
        json j;
        j["id"] = id;
        j["import_id"] = import_id;
        j["source_type"] = source_type;
        j["source"] = source;
        j["imported_by"] = imported_by;
        j["imported_ts"] = imported_ts;
        j["entry_count"] = entry_count;
        j["error_count"] = error_count;
        j["status"] = status;
        j["metadata"] = metadata;
        return j;
    }
};

// Ignore check result
struct IgnoreCheckResult {
    bool is_ignored = false;
    std::string matched_pattern;
    int64_t entry_id = 0;
    IgnoreInvitePolicy invite_policy = IgnoreInvitePolicy::BLOCK_SILENTLY;
    IgnoreMessagePolicy message_policy = IgnoreMessagePolicy::DROP;
    std::string reason;
    bool has_room_override = false;
    IgnoreRoomOverride room_override;
    int64_t checked_ts = 0;

    json to_json() const {
        json j;
        j["is_ignored"] = is_ignored;
        j["matched_pattern"] = matched_pattern;
        j["entry_id"] = entry_id;
        j["invite_policy"] = ignore_invite_policy_str(invite_policy);
        j["message_policy"] = ignore_message_policy_str(message_policy);
        j["reason"] = reason;
        j["has_room_override"] = has_room_override;
        j["checked_ts"] = checked_ts;
        return j;
    }
};

// Ignored user statistics
struct IgnoredUsersStats {
    int64_t total_ignore_entries = 0;
    int64_t active_ignore_entries = 0;
    int64_t total_ignored_unique_users = 0;
    int64_t total_invites_blocked = 0;
    int64_t total_messages_filtered = 0;
    int64_t total_federation_syncs = 0;
    int64_t total_imports = 0;
    int64_t total_audit_entries = 0;
    int64_t last_maintenance_ts = 0;

    json to_json() const {
        json j;
        j["total_ignore_entries"] = total_ignore_entries;
        j["active_ignore_entries"] = active_ignore_entries;
        j["total_ignored_unique_users"] = total_ignored_unique_users;
        j["total_invites_blocked"] = total_invites_blocked;
        j["total_messages_filtered"] = total_messages_filtered;
        j["total_federation_syncs"] = total_federation_syncs;
        j["total_imports"] = total_imports;
        j["total_audit_entries"] = total_audit_entries;
        j["last_maintenance_ts"] = last_maintenance_ts;
        return j;
    }
};

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

std::string iso8601_now() {
    auto t = std::time(nullptr);
    std::tm tm;
    gmtime_r(&t, &tm);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
    return std::string(buf);
}

std::string ts_to_iso8601(int64_t ms) {
    auto t = static_cast<std::time_t>(ms / 1000);
    std::tm tm;
    gmtime_r(&t, &tm);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
    return std::string(buf);
}

// ---- String helpers ----

std::string to_lower(const std::string& s) {
    std::string r = s;
    std::transform(r.begin(), r.end(), r.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return r;
}

std::string trim(const std::string& s) {
    auto start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    auto end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

std::vector<std::string> split(const std::string& str, char delim) {
    std::vector<std::string> result;
    std::istringstream iss(str);
    std::string item;
    while (std::getline(iss, item, delim)) {
        if (!item.empty()) result.push_back(trim(item));
    }
    return result;
}

std::string join(const std::vector<std::string>& parts, const std::string& delim) {
    if (parts.empty()) return "";
    std::string result = parts[0];
    for (size_t i = 1; i < parts.size(); ++i) {
        result += delim + parts[i];
    }
    return result;
}

bool starts_with(const std::string& s, const std::string& prefix) {
    return s.size() >= prefix.size() &&
           s.compare(0, prefix.size(), prefix) == 0;
}

bool ends_with(const std::string& s, const std::string& suffix) {
    return s.size() >= suffix.size() &&
           s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

// Extract server name from user ID (@user:server)
std::string extract_server_from_user_id(const std::string& user_id) {
    auto pos = user_id.find(':');
    if (pos != std::string::npos && pos > 0 && user_id[0] == '@') {
        return user_id.substr(pos + 1);
    }
    return "";
}

// Extract localpart from user ID (@user:server)
std::string extract_localpart_from_user_id(const std::string& user_id) {
    if (user_id.empty() || user_id[0] != '@') return "";
    auto pos = user_id.find(':');
    if (pos != std::string::npos) {
        return user_id.substr(1, pos - 1);
    }
    return user_id.substr(1);
}

// Check if a domain matches a glob pattern
bool glob_match(const std::string& pattern, const std::string& subject) {
    size_t pi = 0, si = 0;
    size_t pstar = std::string::npos, sstar = 0;
    while (si < subject.size()) {
        if (pi < pattern.size() && (pattern[pi] == '?' ||
            pattern[pi] == subject[si])) {
            ++pi; ++si;
        } else if (pi < pattern.size() && pattern[pi] == '*') {
            pstar = pi;
            sstar = si + 1;
            ++pi;
        } else if (pstar != std::string::npos) {
            pi = pstar + 1;
            si = sstar++;
        } else {
            return false;
        }
    }
    while (pi < pattern.size() && pattern[pi] == '*') ++pi;
    return pi == pattern.size();
}

bool user_id_matches(const std::string& target_user_id,
                     const std::string& pattern_user_id,
                     IgnoreMatchType match_type) {
    switch (match_type) {
        case IgnoreMatchType::EXACT:
            return target_user_id == pattern_user_id;
        case IgnoreMatchType::DOMAIN: {
            // pattern like "*:target.com" or just "target.com"
            std::string domain = pattern_user_id;
            if (starts_with(domain, "*:")) {
                domain = domain.substr(2);
            }
            return extract_server_from_user_id(target_user_id) == domain;
        }
        case IgnoreMatchType::WILDCARD:
            return glob_match(pattern_user_id, target_user_id);
        case IgnoreMatchType::REGEX:
            try {
                std::regex re(pattern_user_id);
                return std::regex_match(target_user_id, re);
            } catch (...) {
                return false;
            }
        case IgnoreMatchType::LOCALPART:
            return extract_localpart_from_user_id(target_user_id) ==
                   extract_localpart_from_user_id(pattern_user_id);
        default:
            return target_user_id == pattern_user_id;
    }
}

// ---- Random ID generation ----

std::string random_string(size_t length) {
    static const char charset[] =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    thread_local std::mt19937 rng(
        static_cast<unsigned>(chr::steady_clock::now().time_since_epoch().count() ^
        std::hash<std::thread::id>{}(std::this_thread::get_id())));
    std::uniform_int_distribution<> dist(0, sizeof(charset) - 2);
    std::string result;
    result.reserve(length);
    for (size_t i = 0; i < length; ++i) {
        result += charset[dist(rng)];
    }
    return result;
}

std::string random_hex(size_t length) {
    static const char hex_chars[] = "0123456789abcdef";
    thread_local std::mt19937 rng(
        static_cast<unsigned>(chr::steady_clock::now().time_since_epoch().count()));
    std::uniform_int_distribution<> dist(0, 15);
    std::string result;
    result.reserve(length);
    for (size_t i = 0; i < length; ++i) {
        result += hex_chars[dist(rng)];
    }
    return result;
}

std::string generate_sync_id() {
    return "sync_" + random_hex(12) + "_" + std::to_string(now_ms());
}

std::string generate_import_id() {
    return "import_" + random_hex(8) + "_" + std::to_string(now_sec());
}

std::string generate_quarantine_id() {
    return "quar_" + random_hex(16);
}

// ---- Database row helpers ----

std::string row_get_str(const std::unique_ptr<storage::Row>& row, int col,
                         const std::string& default_val = "") {
    if (!row || row->is_null(col)) return default_val;
    return row->get<std::string>(col);
}

int64_t row_get_int(const std::unique_ptr<storage::Row>& row, int col,
                     int64_t default_val = 0) {
    if (!row || row->is_null(col)) return default_val;
    return row->get<int64_t>(col);
}

bool row_get_bool(const std::unique_ptr<storage::Row>& row, int col,
                   bool default_val = false) {
    if (!row || row->is_null(col)) return default_val;
    return row->get<int64_t>(col) != 0;
}

IgnoredUserEntry row_to_ignored_user(const std::unique_ptr<storage::Row>& row) {
    IgnoredUserEntry entry;
    if (!row) return entry;
    entry.id = row_get_int(row, 0);
    entry.ignorer_user_id = row_get_str(row, 1);
    entry.ignored_user_id = row_get_str(row, 2);
    entry.match_type = static_cast<IgnoreMatchType>(row_get_int(row, 3));
    entry.reason = row_get_str(row, 4);
    entry.ignored_ts = row_get_int(row, 5);
    entry.expires_ts = row_get_int(row, 6);
    entry.is_active = row_get_bool(row, 7);
    entry.invite_policy = static_cast<IgnoreInvitePolicy>(row_get_int(row, 8));
    entry.message_policy = static_cast<IgnoreMessagePolicy>(row_get_int(row, 9));
    entry.notes = row_get_str(row, 10);
    entry.import_source = row_get_str(row, 11);
    return entry;
}

IgnoreInviteBlockEntry row_to_invite_block(const std::unique_ptr<storage::Row>& row) {
    IgnoreInviteBlockEntry entry;
    if (!row) return entry;
    entry.id = row_get_int(row, 0);
    entry.ignorer_user_id = row_get_str(row, 1);
    entry.ignored_user_id = row_get_str(row, 2);
    entry.room_id = row_get_str(row, 3);
    entry.event_id = row_get_str(row, 4);
    entry.blocked_ts = row_get_int(row, 5);
    entry.rejection_reason = row_get_str(row, 6);
    entry.policy_applied = row_get_str(row, 7);
    entry.notified = row_get_bool(row, 8);
    return entry;
}

IgnoreMessageFilterEntry row_to_message_filter(const std::unique_ptr<storage::Row>& row) {
    IgnoreMessageFilterEntry entry;
    if (!row) return entry;
    entry.id = row_get_int(row, 0);
    entry.ignorer_user_id = row_get_str(row, 1);
    entry.ignored_user_id = row_get_str(row, 2);
    entry.room_id = row_get_str(row, 3);
    entry.event_id = row_get_str(row, 4);
    entry.event_type = row_get_str(row, 5);
    entry.filtered_ts = row_get_int(row, 6);
    entry.action = static_cast<IgnoreMessagePolicy>(row_get_int(row, 7));
    entry.is_mention = row_get_bool(row, 8);
    entry.delivered = row_get_bool(row, 9);
    entry.quarantine_id = row_get_str(row, 10);
    return entry;
}

FederationIgnoredUserEntry row_to_fed_ignored_user(const std::unique_ptr<storage::Row>& row) {
    FederationIgnoredUserEntry entry;
    if (!row) return entry;
    entry.id = row_get_int(row, 0);
    entry.origin_server = row_get_str(row, 1);
    entry.target_server = row_get_str(row, 2);
    entry.ignorer_user_id = row_get_str(row, 3);
    entry.ignored_user_id = row_get_str(row, 4);
    entry.match_type = static_cast<IgnoreMatchType>(row_get_int(row, 5));
    entry.direction = static_cast<FederationIgnoreDirection>(row_get_int(row, 6));
    entry.sync_status = static_cast<FederationIgnoreSyncStatus>(row_get_int(row, 7));
    entry.created_ts = row_get_int(row, 8);
    entry.synced_ts = row_get_int(row, 9);
    entry.expires_ts = row_get_int(row, 10);
    entry.is_active = row_get_bool(row, 11);
    entry.reason = row_get_str(row, 12);
    entry.sync_id = row_get_str(row, 13);
    entry.retry_count = static_cast<int>(row_get_int(row, 14));
    entry.last_retry_ts = row_get_int(row, 15);
    return entry;
}

IgnoreAuditEntry row_to_audit_entry(const std::unique_ptr<storage::Row>& row) {
    IgnoreAuditEntry entry;
    if (!row) return entry;
    entry.id = row_get_int(row, 0);
    entry.action = static_cast<IgnoreAuditAction>(row_get_int(row, 1));
    entry.actor_user_id = row_get_str(row, 2);
    entry.target_user_id = row_get_str(row, 3);
    entry.details = row_get_str(row, 4);
    entry.action_ts = row_get_int(row, 5);
    entry.ip_address = row_get_str(row, 6);
    entry.server_name = row_get_str(row, 7);
    try {
        std::string meta_str = row_get_str(row, 8, "{}");
        entry.metadata = json::parse(meta_str);
    } catch (...) {
        entry.metadata = json::object();
    }
    return entry;
}

IgnoreRoomOverride row_to_room_override(const std::unique_ptr<storage::Row>& row) {
    IgnoreRoomOverride entry;
    if (!row) return entry;
    entry.id = row_get_int(row, 0);
    entry.ignorer_user_id = row_get_str(row, 1);
    entry.ignored_user_id = row_get_str(row, 2);
    entry.room_id = row_get_str(row, 3);
    entry.allow_messages = row_get_bool(row, 4);
    entry.allow_invites = row_get_bool(row, 5);
    entry.reason = row_get_str(row, 6);
    entry.set_ts = row_get_int(row, 7);
    entry.expires_ts = row_get_int(row, 8);
    entry.is_active = row_get_bool(row, 9);
    return entry;
}

IgnoreImportEntry row_to_import_entry(const std::unique_ptr<storage::Row>& row) {
    IgnoreImportEntry entry;
    if (!row) return entry;
    entry.id = row_get_int(row, 0);
    entry.import_id = row_get_str(row, 1);
    entry.source_type = row_get_str(row, 2);
    entry.source = row_get_str(row, 3);
    entry.imported_by = row_get_str(row, 4);
    entry.imported_ts = row_get_int(row, 5);
    entry.entry_count = static_cast<int>(row_get_int(row, 6));
    entry.error_count = static_cast<int>(row_get_int(row, 7));
    entry.status = row_get_str(row, 8);
    try {
        std::string meta_str = row_get_str(row, 9, "{}");
        entry.metadata = json::parse(meta_str);
    } catch (...) {
        entry.metadata = json::object();
    }
    return entry;
}

// ---- Logger helper ----

class IgnoreLogger {
public:
    explicit IgnoreLogger(const std::string& name) : name_(name) {}
    void info(const std::string& msg)  const { log_msg("INFO", msg); }
    void warn(const std::string& msg)  const { log_msg("WARN", msg); }
    void error(const std::string& msg) const { log_msg("ERROR", msg); }
    void debug(const std::string& msg) const { log_msg("DEBUG", msg); }
private:
    std::string name_;
    void log_msg(const std::string& level, const std::string& msg) const {
        std::cerr << "[" << iso8601_now() << "] [" << level << "] ["
                  << name_ << "] " << msg << std::endl;
    }
};

} // anonymous namespace

// ============================================================================
// 1. IgnoredUsersStore — SQL DDL and CRUD for all ignore-related tables
// ============================================================================

class IgnoredUsersStore {
public:
    explicit IgnoredUsersStore(DatabasePool& db, IgnoreLogger& logger)
        : db_(db), logger_(logger) {}

    // ---------- DDL ----------
    static void create_tables(LoggingTransaction& txn) {
        // Core ignored users table
        txn.execute(R"SQL(
            CREATE TABLE IF NOT EXISTS ignored_users (
                id BIGINT NOT NULL PRIMARY KEY AUTOINCREMENT,
                ignorer_user_id TEXT NOT NULL,
                ignored_user_id TEXT NOT NULL,
                match_type INTEGER NOT NULL DEFAULT 0,
                reason TEXT NOT NULL DEFAULT '',
                ignored_ts BIGINT NOT NULL,
                expires_ts BIGINT NOT NULL DEFAULT 0,
                is_active INTEGER NOT NULL DEFAULT 1,
                invite_policy INTEGER NOT NULL DEFAULT 0,
                message_policy INTEGER NOT NULL DEFAULT 0,
                notes TEXT NOT NULL DEFAULT '',
                import_source TEXT NOT NULL DEFAULT ''
            );
        )SQL");

        txn.execute(R"SQL(
            CREATE UNIQUE INDEX IF NOT EXISTS ignored_users_ignorer_ignored_idx
                ON ignored_users (ignorer_user_id, ignored_user_id);
        )SQL");

        txn.execute(R"SQL(
            CREATE INDEX IF NOT EXISTS ignored_users_ignorer_idx
                ON ignored_users (ignorer_user_id, is_active);
        )SQL");

        txn.execute(R"SQL(
            CREATE INDEX IF NOT EXISTS ignored_users_ignored_idx
                ON ignored_users (ignored_user_id, is_active);
        )SQL");

        txn.execute(R"SQL(
            CREATE INDEX IF NOT EXISTS ignored_users_match_type_idx
                ON ignored_users (match_type, is_active);
        )SQL");

        txn.execute(R"SQL(
            CREATE INDEX IF NOT EXISTS ignored_users_expires_idx
                ON ignored_users (is_active, expires_ts);
        )SQL");

        // Blocked invite tracking table
        txn.execute(R"SQL(
            CREATE TABLE IF NOT EXISTS ignored_users_invites (
                id BIGINT NOT NULL PRIMARY KEY AUTOINCREMENT,
                ignorer_user_id TEXT NOT NULL,
                ignored_user_id TEXT NOT NULL,
                room_id TEXT NOT NULL DEFAULT '',
                event_id TEXT NOT NULL DEFAULT '',
                blocked_ts BIGINT NOT NULL,
                rejection_reason TEXT NOT NULL DEFAULT '',
                policy_applied TEXT NOT NULL DEFAULT '',
                notified INTEGER NOT NULL DEFAULT 0
            );
        )SQL");

        txn.execute(R"SQL(
            CREATE INDEX IF NOT EXISTS ignored_users_invites_ignorer_idx
                ON ignored_users_invites (ignorer_user_id, blocked_ts);
        )SQL");

        txn.execute(R"SQL(
            CREATE INDEX IF NOT EXISTS ignored_users_invites_ignored_idx
                ON ignored_users_invites (ignored_user_id, blocked_ts);
        )SQL");

        txn.execute(R"SQL(
            CREATE INDEX IF NOT EXISTS ignored_users_invites_room_idx
                ON ignored_users_invites (room_id, blocked_ts);
        )SQL");

        // Filtered messages tracking table
        txn.execute(R"SQL(
            CREATE TABLE IF NOT EXISTS ignored_users_messages (
                id BIGINT NOT NULL PRIMARY KEY AUTOINCREMENT,
                ignorer_user_id TEXT NOT NULL,
                ignored_user_id TEXT NOT NULL,
                room_id TEXT NOT NULL DEFAULT '',
                event_id TEXT NOT NULL DEFAULT '',
                event_type TEXT NOT NULL DEFAULT '',
                filtered_ts BIGINT NOT NULL,
                action INTEGER NOT NULL DEFAULT 0,
                is_mention INTEGER NOT NULL DEFAULT 0,
                delivered INTEGER NOT NULL DEFAULT 0,
                quarantine_id TEXT NOT NULL DEFAULT ''
            );
        )SQL");

        txn.execute(R"SQL(
            CREATE INDEX IF NOT EXISTS ignored_users_messages_ignorer_idx
                ON ignored_users_messages (ignorer_user_id, filtered_ts);
        )SQL");

        txn.execute(R"SQL(
            CREATE INDEX IF NOT EXISTS ignored_users_messages_ignored_idx
                ON ignored_users_messages (ignored_user_id, filtered_ts);
        )SQL");

        txn.execute(R"SQL(
            CREATE INDEX IF NOT EXISTS ignored_users_messages_room_idx
                ON ignored_users_messages (room_id, filtered_ts);
        )SQL");

        txn.execute(R"SQL(
            CREATE INDEX IF NOT EXISTS ignored_users_messages_quarantine_idx
                ON ignored_users_messages (quarantine_id);
        )SQL");

        // Federation ignored users table
        txn.execute(R"SQL(
            CREATE TABLE IF NOT EXISTS ignored_users_federation (
                id BIGINT NOT NULL PRIMARY KEY AUTOINCREMENT,
                origin_server TEXT NOT NULL,
                target_server TEXT NOT NULL DEFAULT '',
                ignorer_user_id TEXT NOT NULL,
                ignored_user_id TEXT NOT NULL,
                match_type INTEGER NOT NULL DEFAULT 0,
                direction INTEGER NOT NULL DEFAULT 2,
                sync_status INTEGER NOT NULL DEFAULT 0,
                created_ts BIGINT NOT NULL,
                synced_ts BIGINT NOT NULL DEFAULT 0,
                expires_ts BIGINT NOT NULL DEFAULT 0,
                is_active INTEGER NOT NULL DEFAULT 1,
                reason TEXT NOT NULL DEFAULT '',
                sync_id TEXT NOT NULL DEFAULT '',
                retry_count INTEGER NOT NULL DEFAULT 0,
                last_retry_ts BIGINT NOT NULL DEFAULT 0
            );
        )SQL");

        txn.execute(R"SQL(
            CREATE INDEX IF NOT EXISTS ignored_users_fed_origin_idx
                ON ignored_users_federation (origin_server, sync_status);
        )SQL");

        txn.execute(R"SQL(
            CREATE INDEX IF NOT EXISTS ignored_users_fed_target_idx
                ON ignored_users_federation (target_server, sync_status);
        )SQL");

        txn.execute(R"SQL(
            CREATE INDEX IF NOT EXISTS ignored_users_fed_sync_id_idx
                ON ignored_users_federation (sync_id);
        )SQL");

        txn.execute(R"SQL(
            CREATE INDEX IF NOT EXISTS ignored_users_fed_status_idx
                ON ignored_users_federation (sync_status, last_retry_ts);
        )SQL");

        txn.execute(R"SQL(
            CREATE INDEX IF NOT EXISTS ignored_users_fed_user_pair_idx
                ON ignored_users_federation (ignorer_user_id, ignored_user_id, is_active);
        )SQL");

        // Audit log table
        txn.execute(R"SQL(
            CREATE TABLE IF NOT EXISTS ignored_users_audit (
                id BIGINT NOT NULL PRIMARY KEY AUTOINCREMENT,
                action INTEGER NOT NULL DEFAULT 0,
                actor_user_id TEXT NOT NULL DEFAULT '',
                target_user_id TEXT NOT NULL DEFAULT '',
                details TEXT NOT NULL DEFAULT '',
                action_ts BIGINT NOT NULL,
                ip_address TEXT NOT NULL DEFAULT '',
                server_name TEXT NOT NULL DEFAULT '',
                metadata TEXT NOT NULL DEFAULT '{}'
            );
        )SQL");

        txn.execute(R"SQL(
            CREATE INDEX IF NOT EXISTS ignored_users_audit_actor_idx
                ON ignored_users_audit (actor_user_id, action_ts);
        )SQL");

        txn.execute(R"SQL(
            CREATE INDEX IF NOT EXISTS ignored_users_audit_target_idx
                ON ignored_users_audit (target_user_id, action_ts);
        )SQL");

        txn.execute(R"SQL(
            CREATE INDEX IF NOT EXISTS ignored_users_audit_action_idx
                ON ignored_users_audit (action, action_ts);
        )SQL");

        txn.execute(R"SQL(
            CREATE INDEX IF NOT EXISTS ignored_users_audit_ts_idx
                ON ignored_users_audit (action_ts);
        )SQL");

        // Room overrides table
        txn.execute(R"SQL(
            CREATE TABLE IF NOT EXISTS ignored_users_overrides (
                id BIGINT NOT NULL PRIMARY KEY AUTOINCREMENT,
                ignorer_user_id TEXT NOT NULL,
                ignored_user_id TEXT NOT NULL,
                room_id TEXT NOT NULL,
                allow_messages INTEGER NOT NULL DEFAULT 0,
                allow_invites INTEGER NOT NULL DEFAULT 0,
                reason TEXT NOT NULL DEFAULT '',
                set_ts BIGINT NOT NULL,
                expires_ts BIGINT NOT NULL DEFAULT 0,
                is_active INTEGER NOT NULL DEFAULT 1
            );
        )SQL");

        txn.execute(R"SQL(
            CREATE UNIQUE INDEX IF NOT EXISTS ignored_users_overrides_triple_idx
                ON ignored_users_overrides (ignorer_user_id, ignored_user_id, room_id);
        )SQL");

        txn.execute(R"SQL(
            CREATE INDEX IF NOT EXISTS ignored_users_overrides_room_idx
                ON ignored_users_overrides (room_id, is_active);
        )SQL");

        // Imports table
        txn.execute(R"SQL(
            CREATE TABLE IF NOT EXISTS ignored_users_imports (
                id BIGINT NOT NULL PRIMARY KEY AUTOINCREMENT,
                import_id TEXT NOT NULL UNIQUE,
                source_type TEXT NOT NULL DEFAULT '',
                source TEXT NOT NULL DEFAULT '',
                imported_by TEXT NOT NULL DEFAULT '',
                imported_ts BIGINT NOT NULL,
                entry_count INTEGER NOT NULL DEFAULT 0,
                error_count INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'completed',
                metadata TEXT NOT NULL DEFAULT '{}'
            );
        )SQL");

        txn.execute(R"SQL(
            CREATE INDEX IF NOT EXISTS ignored_users_imports_source_idx
                ON ignored_users_imports (source_type, imported_ts);
        )SQL");
    }

    // ---------- Ignored Users CRUD ----------

    int64_t add_ignored_user_txn(LoggingTransaction& txn, const IgnoredUserEntry& entry) {
        // Check for duplicates
        auto existing = txn.select_one(
            "SELECT id FROM ignored_users WHERE ignorer_user_id = ? "
            "AND ignored_user_id = ? AND match_type = ?",
            {entry.ignorer_user_id, entry.ignored_user_id,
             static_cast<int64_t>(entry.match_type)});
        if (existing) {
            // Reactivate if it exists but is inactive
            txn.execute(
                "UPDATE ignored_users SET is_active = 1, reason = ?, "
                "invite_policy = ?, message_policy = ?, notes = ?, "
                "ignored_ts = ?, expires_ts = ? WHERE id = ?",
                {entry.reason,
                 static_cast<int64_t>(entry.invite_policy),
                 static_cast<int64_t>(entry.message_policy),
                 entry.notes, entry.ignored_ts, entry.expires_ts,
                 existing->get<int64_t>(0)});
            return existing->get<int64_t>(0);
        }

        txn.execute(
            "INSERT INTO ignored_users (ignorer_user_id, ignored_user_id, "
            "match_type, reason, ignored_ts, expires_ts, is_active, "
            "invite_policy, message_policy, notes, import_source) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            {entry.ignorer_user_id, entry.ignored_user_id,
             static_cast<int64_t>(entry.match_type), entry.reason,
             entry.ignored_ts, entry.expires_ts,
             entry.is_active ? 1 : 0,
             static_cast<int64_t>(entry.invite_policy),
             static_cast<int64_t>(entry.message_policy),
             entry.notes, entry.import_source});
        return txn.last_insert_rowid();
    }

    bool remove_ignored_user_txn(LoggingTransaction& txn, int64_t id) {
        txn.execute(
            "UPDATE ignored_users SET is_active = 0 WHERE id = ?", {id});
        return true;
    }

    bool delete_ignored_user_txn(LoggingTransaction& txn, int64_t id) {
        txn.execute("DELETE FROM ignored_users WHERE id = ?", {id});
        return true;
    }

    bool remove_ignored_user_by_pair_txn(LoggingTransaction& txn,
                                          const std::string& ignorer_user_id,
                                          const std::string& ignored_user_id) {
        txn.execute(
            "UPDATE ignored_users SET is_active = 0 "
            "WHERE ignorer_user_id = ? AND ignored_user_id = ? "
            "AND match_type = 0",
            {ignorer_user_id, ignored_user_id});
        return true;
    }

    bool update_ignored_user_txn(LoggingTransaction& txn, int64_t id,
                                  const json& updates) {
        std::vector<std::string> set_clauses;
        std::vector<storage::SQLParam> params;

        if (updates.contains("reason")) {
            set_clauses.push_back("reason = ?");
            params.push_back(updates["reason"].get<std::string>());
        }
        if (updates.contains("invite_policy")) {
            set_clauses.push_back("invite_policy = ?");
            params.push_back(static_cast<int64_t>(
                ignore_invite_policy_from_str(
                    updates["invite_policy"].get<std::string>())));
        }
        if (updates.contains("message_policy")) {
            set_clauses.push_back("message_policy = ?");
            params.push_back(static_cast<int64_t>(
                ignore_message_policy_from_str(
                    updates["message_policy"].get<std::string>())));
        }
        if (updates.contains("expires_ts")) {
            set_clauses.push_back("expires_ts = ?");
            params.push_back(updates["expires_ts"].get<int64_t>());
        }
        if (updates.contains("is_active")) {
            set_clauses.push_back("is_active = ?");
            params.push_back(updates["is_active"].get<bool>() ? 1 : 0);
        }
        if (updates.contains("notes")) {
            set_clauses.push_back("notes = ?");
            params.push_back(updates["notes"].get<std::string>());
        }
        if (updates.contains("match_type")) {
            set_clauses.push_back("match_type = ?");
            params.push_back(static_cast<int64_t>(
                ignore_match_type_from_str(
                    updates["match_type"].get<std::string>())));
        }

        if (set_clauses.empty()) return false;
        params.push_back(id);

        std::string sql = "UPDATE ignored_users SET " +
                          join(set_clauses, ", ") + " WHERE id = ?";
        txn.execute(sql, params);
        return true;
    }

    std::optional<IgnoredUserEntry> get_ignored_user_txn(
        LoggingTransaction& txn, int64_t id) {
        auto row = txn.select_one(
            "SELECT id, ignorer_user_id, ignored_user_id, match_type, reason, "
            "ignored_ts, expires_ts, is_active, invite_policy, message_policy, "
            "notes, import_source FROM ignored_users WHERE id = ?", {id});
        if (!row) return std::nullopt;
        return row_to_ignored_user(row);
    }

    std::optional<IgnoredUserEntry> get_ignored_user_by_pair_txn(
        LoggingTransaction& txn,
        const std::string& ignorer_user_id,
        const std::string& ignored_user_id) {
        auto row = txn.select_one(
            "SELECT id, ignorer_user_id, ignored_user_id, match_type, reason, "
            "ignored_ts, expires_ts, is_active, invite_policy, message_policy, "
            "notes, import_source FROM ignored_users "
            "WHERE ignorer_user_id = ? AND ignored_user_id = ? AND is_active = 1 "
            "AND (expires_ts = 0 OR expires_ts > ?) "
            "ORDER BY ignored_ts DESC LIMIT 1",
            {ignorer_user_id, ignored_user_id, now_ms()});
        if (!row) return std::nullopt;
        return row_to_ignored_user(row);
    }

    std::vector<IgnoredUserEntry> get_ignored_users_for_txn(
        LoggingTransaction& txn,
        const std::string& ignorer_user_id,
        int limit = 500, int offset = 0) {
        std::vector<IgnoredUserEntry> results;
        auto rows = txn.select(
            "SELECT id, ignorer_user_id, ignored_user_id, match_type, reason, "
            "ignored_ts, expires_ts, is_active, invite_policy, message_policy, "
            "notes, import_source FROM ignored_users "
            "WHERE ignorer_user_id = ? AND is_active = 1 "
            "AND (expires_ts = 0 OR expires_ts > ?) "
            "ORDER BY ignored_ts DESC LIMIT ? OFFSET ?",
            {ignorer_user_id, now_ms(), limit, offset});
        for (auto& row : rows) {
            results.push_back(row_to_ignored_user(row));
        }
        return results;
    }

    std::vector<IgnoredUserEntry> get_all_ignored_users_for_txn(
        LoggingTransaction& txn,
        const std::string& ignorer_user_id,
        int limit = 500, int offset = 0) {
        std::vector<IgnoredUserEntry> results;
        auto rows = txn.select(
            "SELECT id, ignorer_user_id, ignored_user_id, match_type, reason, "
            "ignored_ts, expires_ts, is_active, invite_policy, message_policy, "
            "notes, import_source FROM ignored_users "
            "WHERE ignorer_user_id = ? "
            "ORDER BY ignored_ts DESC LIMIT ? OFFSET ?",
            {ignorer_user_id, limit, offset});
        for (auto& row : rows) {
            results.push_back(row_to_ignored_user(row));
        }
        return results;
    }

    std::vector<IgnoredUserEntry> search_ignored_users_txn(
        LoggingTransaction& txn,
        const std::string& ignorer_user_id,
        const std::string& search_pattern,
        int limit = 500, int offset = 0) {
        std::vector<IgnoredUserEntry> results;
        std::string like_pattern = "%" + search_pattern + "%";
        auto rows = txn.select(
            "SELECT id, ignorer_user_id, ignored_user_id, match_type, reason, "
            "ignored_ts, expires_ts, is_active, invite_policy, message_policy, "
            "notes, import_source FROM ignored_users "
            "WHERE ignorer_user_id = ? AND ignored_user_id LIKE ? "
            "ORDER BY ignored_ts DESC LIMIT ? OFFSET ?",
            {ignorer_user_id, like_pattern, limit, offset});
        for (auto& row : rows) {
            results.push_back(row_to_ignored_user(row));
        }
        return results;
    }

    int64_t count_ignored_users_txn(LoggingTransaction& txn,
                                     const std::string& ignorer_user_id,
                                     bool active_only = true) {
        if (active_only) {
            auto row = txn.select_one(
                "SELECT COUNT(*) FROM ignored_users "
                "WHERE ignorer_user_id = ? AND is_active = 1 "
                "AND (expires_ts = 0 OR expires_ts > ?)",
                {ignorer_user_id, now_ms()});
            return row ? row->get<int64_t>(0) : 0;
        } else {
            auto row = txn.select_one(
                "SELECT COUNT(*) FROM ignored_users "
                "WHERE ignorer_user_id = ?",
                {ignorer_user_id});
            return row ? row->get<int64_t>(0) : 0;
        }
    }

    // Check if a specific user is ignored (by exact match or pattern)
    std::vector<IgnoredUserEntry> check_user_ignored_txn(
        LoggingTransaction& txn,
        const std::string& ignorer_user_id,
        const std::string& target_user_id) {
        std::vector<IgnoredUserEntry> results;
        // First check exact match
        auto exact_rows = txn.select(
            "SELECT id, ignorer_user_id, ignored_user_id, match_type, reason, "
            "ignored_ts, expires_ts, is_active, invite_policy, message_policy, "
            "notes, import_source FROM ignored_users "
            "WHERE ignorer_user_id = ? AND match_type = 0 "
            "AND ignored_user_id = ? AND is_active = 1 "
            "AND (expires_ts = 0 OR expires_ts > ?)",
            {ignorer_user_id, target_user_id, now_ms()});
        for (auto& row : exact_rows) {
            results.push_back(row_to_ignored_user(row));
        }

        // Get all pattern-based ignores and check in-memory
        auto pattern_rows = txn.select(
            "SELECT id, ignorer_user_id, ignored_user_id, match_type, reason, "
            "ignored_ts, expires_ts, is_active, invite_policy, message_policy, "
            "notes, import_source FROM ignored_users "
            "WHERE ignorer_user_id = ? AND match_type > 0 AND is_active = 1 "
            "AND (expires_ts = 0 OR expires_ts > ?)",
            {ignorer_user_id, now_ms()});
        for (auto& row : pattern_rows) {
            auto entry = row_to_ignored_user(row);
            if (user_id_matches(target_user_id, entry.ignored_user_id,
                                entry.match_type)) {
                results.push_back(entry);
            }
        }

        return results;
    }

    // Get users who are ignoring a specific target
    std::vector<IgnoredUserEntry> get_ignorers_for_user_txn(
        LoggingTransaction& txn,
        const std::string& ignored_user_id,
        int limit = 500, int offset = 0) {
        std::vector<IgnoredUserEntry> results;
        auto rows = txn.select(
            "SELECT id, ignorer_user_id, ignored_user_id, match_type, reason, "
            "ignored_ts, expires_ts, is_active, invite_policy, message_policy, "
            "notes, import_source FROM ignored_users "
            "WHERE ignored_user_id = ? AND match_type = 0 AND is_active = 1 "
            "AND (expires_ts = 0 OR expires_ts > ?) "
            "ORDER BY ignored_ts DESC LIMIT ? OFFSET ?",
            {ignored_user_id, now_ms(), limit, offset});
        for (auto& row : rows) {
            results.push_back(row_to_ignored_user(row));
        }
        return results;
    }

    int64_t count_ignorers_for_user_txn(LoggingTransaction& txn,
                                          const std::string& ignored_user_id) {
        auto row = txn.select_one(
            "SELECT COUNT(*) FROM ignored_users "
            "WHERE ignored_user_id = ? AND match_type = 0 AND is_active = 1 "
            "AND (expires_ts = 0 OR expires_ts > ?)",
            {ignored_user_id, now_ms()});
        return row ? row->get<int64_t>(0) : 0;
    }

    void delete_expired_ignores_txn(LoggingTransaction& txn) {
        txn.execute(
            "UPDATE ignored_users SET is_active = 0 "
            "WHERE is_active = 1 AND expires_ts > 0 AND expires_ts <= ?",
            {now_ms()});
    }

    void delete_ignored_users_by_import_source_txn(
        LoggingTransaction& txn, const std::string& import_source) {
        txn.execute("DELETE FROM ignored_users WHERE import_source = ?",
                     {import_source});
    }

    // ---------- Invite Block CRUD ----------

    int64_t log_blocked_invite_txn(LoggingTransaction& txn,
                                    const IgnoreInviteBlockEntry& entry) {
        txn.execute(
            "INSERT INTO ignored_users_invites (ignorer_user_id, ignored_user_id, "
            "room_id, event_id, blocked_ts, rejection_reason, policy_applied, "
            "notified) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            {entry.ignorer_user_id, entry.ignored_user_id, entry.room_id,
             entry.event_id, entry.blocked_ts, entry.rejection_reason,
             entry.policy_applied, entry.notified ? 1 : 0});
        return txn.last_insert_rowid();
    }

    std::vector<IgnoreInviteBlockEntry> get_blocked_invites_txn(
        LoggingTransaction& txn,
        const std::string& ignorer_user_id,
        int limit = 200, int offset = 0) {
        std::vector<IgnoreInviteBlockEntry> results;
        auto rows = txn.select(
            "SELECT id, ignorer_user_id, ignored_user_id, room_id, event_id, "
            "blocked_ts, rejection_reason, policy_applied, notified "
            "FROM ignored_users_invites "
            "WHERE ignorer_user_id = ? "
            "ORDER BY blocked_ts DESC LIMIT ? OFFSET ?",
            {ignorer_user_id, limit, offset});
        for (auto& row : rows) {
            results.push_back(row_to_invite_block(row));
        }
        return results;
    }

    std::vector<IgnoreInviteBlockEntry> get_blocked_invites_by_ignored_txn(
        LoggingTransaction& txn,
        const std::string& ignored_user_id,
        int limit = 200, int offset = 0) {
        std::vector<IgnoreInviteBlockEntry> results;
        auto rows = txn.select(
            "SELECT id, ignorer_user_id, ignored_user_id, room_id, event_id, "
            "blocked_ts, rejection_reason, policy_applied, notified "
            "FROM ignored_users_invites "
            "WHERE ignored_user_id = ? "
            "ORDER BY blocked_ts DESC LIMIT ? OFFSET ?",
            {ignored_user_id, limit, offset});
        for (auto& row : rows) {
            results.push_back(row_to_invite_block(row));
        }
        return results;
    }

    std::vector<IgnoreInviteBlockEntry> get_blocked_invites_for_room_txn(
        LoggingTransaction& txn,
        const std::string& room_id,
        int limit = 200, int offset = 0) {
        std::vector<IgnoreInviteBlockEntry> results;
        auto rows = txn.select(
            "SELECT id, ignorer_user_id, ignored_user_id, room_id, event_id, "
            "blocked_ts, rejection_reason, policy_applied, notified "
            "FROM ignored_users_invites "
            "WHERE room_id = ? "
            "ORDER BY blocked_ts DESC LIMIT ? OFFSET ?",
            {room_id, limit, offset});
        for (auto& row : rows) {
            results.push_back(row_to_invite_block(row));
        }
        return results;
    }

    int64_t count_blocked_invites_txn(LoggingTransaction& txn,
                                       const std::string& ignorer_user_id = "") {
        if (ignorer_user_id.empty()) {
            auto row = txn.select_one(
                "SELECT COUNT(*) FROM ignored_users_invites");
            return row ? row->get<int64_t>(0) : 0;
        }
        auto row = txn.select_one(
            "SELECT COUNT(*) FROM ignored_users_invites "
            "WHERE ignorer_user_id = ?", {ignorer_user_id});
        return row ? row->get<int64_t>(0) : 0;
    }

    int64_t purge_old_invites_txn(LoggingTransaction& txn,
                                    int64_t older_than_ms) {
        txn.execute(
            "DELETE FROM ignored_users_invites WHERE blocked_ts < ?",
            {older_than_ms});
        return 0;
    }

    // ---------- Message Filter CRUD ----------

    int64_t log_filtered_message_txn(LoggingTransaction& txn,
                                      const IgnoreMessageFilterEntry& entry) {
        txn.execute(
            "INSERT INTO ignored_users_messages (ignorer_user_id, ignored_user_id, "
            "room_id, event_id, event_type, filtered_ts, action, is_mention, "
            "delivered, quarantine_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            {entry.ignorer_user_id, entry.ignored_user_id, entry.room_id,
             entry.event_id, entry.event_type, entry.filtered_ts,
             static_cast<int64_t>(entry.action),
             entry.is_mention ? 1 : 0, entry.delivered ? 1 : 0,
             entry.quarantine_id});
        return txn.last_insert_rowid();
    }

    std::vector<IgnoreMessageFilterEntry> get_filtered_messages_txn(
        LoggingTransaction& txn,
        const std::string& ignorer_user_id,
        int limit = 200, int offset = 0) {
        std::vector<IgnoreMessageFilterEntry> results;
        auto rows = txn.select(
            "SELECT id, ignorer_user_id, ignored_user_id, room_id, event_id, "
            "event_type, filtered_ts, action, is_mention, delivered, "
            "quarantine_id FROM ignored_users_messages "
            "WHERE ignorer_user_id = ? "
            "ORDER BY filtered_ts DESC LIMIT ? OFFSET ?",
            {ignorer_user_id, limit, offset});
        for (auto& row : rows) {
            results.push_back(row_to_message_filter(row));
        }
        return results;
    }

    std::vector<IgnoreMessageFilterEntry> get_filtered_messages_by_ignored_txn(
        LoggingTransaction& txn,
        const std::string& ignored_user_id,
        int limit = 200, int offset = 0) {
        std::vector<IgnoreMessageFilterEntry> results;
        auto rows = txn.select(
            "SELECT id, ignorer_user_id, ignored_user_id, room_id, event_id, "
            "event_type, filtered_ts, action, is_mention, delivered, "
            "quarantine_id FROM ignored_users_messages "
            "WHERE ignored_user_id = ? "
            "ORDER BY filtered_ts DESC LIMIT ? OFFSET ?",
            {ignored_user_id, limit, offset});
        for (auto& row : rows) {
            results.push_back(row_to_message_filter(row));
        }
        return results;
    }

    std::vector<IgnoreMessageFilterEntry> get_filtered_messages_for_room_txn(
        LoggingTransaction& txn,
        const std::string& room_id,
        int limit = 200, int offset = 0) {
        std::vector<IgnoreMessageFilterEntry> results;
        auto rows = txn.select(
            "SELECT id, ignorer_user_id, ignored_user_id, room_id, event_id, "
            "event_type, filtered_ts, action, is_mention, delivered, "
            "quarantine_id FROM ignored_users_messages "
            "WHERE room_id = ? "
            "ORDER BY filtered_ts DESC LIMIT ? OFFSET ?",
            {room_id, limit, offset});
        for (auto& row : rows) {
            results.push_back(row_to_message_filter(row));
        }
        return results;
    }

    std::optional<IgnoreMessageFilterEntry> get_quarantined_message_txn(
        LoggingTransaction& txn, const std::string& quarantine_id) {
        auto row = txn.select_one(
            "SELECT id, ignorer_user_id, ignored_user_id, room_id, event_id, "
            "event_type, filtered_ts, action, is_mention, delivered, "
            "quarantine_id FROM ignored_users_messages "
            "WHERE quarantine_id = ?",
            {quarantine_id});
        if (!row) return std::nullopt;
        return row_to_message_filter(row);
    }

    int64_t count_filtered_messages_txn(LoggingTransaction& txn,
                                         const std::string& ignorer_user_id = "") {
        if (ignorer_user_id.empty()) {
            auto row = txn.select_one(
                "SELECT COUNT(*) FROM ignored_users_messages");
            return row ? row->get<int64_t>(0) : 0;
        }
        auto row = txn.select_one(
            "SELECT COUNT(*) FROM ignored_users_messages "
            "WHERE ignorer_user_id = ?", {ignorer_user_id});
        return row ? row->get<int64_t>(0) : 0;
    }

    int64_t purge_old_filtered_messages_txn(LoggingTransaction& txn,
                                              int64_t older_than_ms) {
        txn.execute(
            "DELETE FROM ignored_users_messages WHERE filtered_ts < ?",
            {older_than_ms});
        return 0;
    }

    // ---------- Federation Ignored Users CRUD ----------

    int64_t add_fed_ignored_user_txn(LoggingTransaction& txn,
                                       const FederationIgnoredUserEntry& entry) {
        // Check for existing entry with same sync_id
        if (!entry.sync_id.empty()) {
            auto existing = txn.select_one(
                "SELECT id FROM ignored_users_federation "
                "WHERE sync_id = ?", {entry.sync_id});
            if (existing) {
                txn.execute(
                    "UPDATE ignored_users_federation SET sync_status = ?, "
                    "synced_ts = ?, retry_count = retry_count + 1, "
                    "last_retry_ts = ? WHERE id = ?",
                    {static_cast<int64_t>(entry.sync_status),
                     entry.synced_ts, entry.last_retry_ts,
                     existing->get<int64_t>(0)});
                return existing->get<int64_t>(0);
            }
        }

        txn.execute(
            "INSERT INTO ignored_users_federation (origin_server, target_server, "
            "ignorer_user_id, ignored_user_id, match_type, direction, "
            "sync_status, created_ts, synced_ts, expires_ts, is_active, reason, "
            "sync_id, retry_count, last_retry_ts) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            {entry.origin_server, entry.target_server,
             entry.ignorer_user_id, entry.ignored_user_id,
             static_cast<int64_t>(entry.match_type),
             static_cast<int64_t>(entry.direction),
             static_cast<int64_t>(entry.sync_status),
             entry.created_ts, entry.synced_ts, entry.expires_ts,
             entry.is_active ? 1 : 0, entry.reason,
             entry.sync_id, entry.retry_count, entry.last_retry_ts});
        return txn.last_insert_rowid();
    }

    bool update_fed_ignored_user_txn(LoggingTransaction& txn, int64_t id,
                                       const json& updates) {
        std::vector<std::string> set_clauses;
        std::vector<storage::SQLParam> params;

        if (updates.contains("sync_status")) {
            set_clauses.push_back("sync_status = ?");
            params.push_back(static_cast<int64_t>(
                fed_ignore_sync_status_from_str(
                    updates["sync_status"].get<std::string>())));
        }
        if (updates.contains("synced_ts")) {
            set_clauses.push_back("synced_ts = ?");
            params.push_back(updates["synced_ts"].get<int64_t>());
        }
        if (updates.contains("is_active")) {
            set_clauses.push_back("is_active = ?");
            params.push_back(updates["is_active"].get<bool>() ? 1 : 0);
        }
        if (updates.contains("expires_ts")) {
            set_clauses.push_back("expires_ts = ?");
            params.push_back(updates["expires_ts"].get<int64_t>());
        }
        if (updates.contains("retry_count")) {
            set_clauses.push_back("retry_count = ?");
            params.push_back(updates["retry_count"].get<int64_t>());
        }
        if (updates.contains("last_retry_ts")) {
            set_clauses.push_back("last_retry_ts = ?");
            params.push_back(updates["last_retry_ts"].get<int64_t>());
        }
        if (updates.contains("reason")) {
            set_clauses.push_back("reason = ?");
            params.push_back(updates["reason"].get<std::string>());
        }

        if (set_clauses.empty()) return false;
        params.push_back(id);

        std::string sql = "UPDATE ignored_users_federation SET " +
                          join(set_clauses, ", ") + " WHERE id = ?";
        txn.execute(sql, params);
        return true;
    }

    std::optional<FederationIgnoredUserEntry> get_fed_ignored_user_txn(
        LoggingTransaction& txn, int64_t id) {
        auto row = txn.select_one(
            "SELECT id, origin_server, target_server, ignorer_user_id, "
            "ignored_user_id, match_type, direction, sync_status, created_ts, "
            "synced_ts, expires_ts, is_active, reason, sync_id, retry_count, "
            "last_retry_ts FROM ignored_users_federation WHERE id = ?", {id});
        if (!row) return std::nullopt;
        return row_to_fed_ignored_user(row);
    }

    std::vector<FederationIgnoredUserEntry> get_fed_ignores_by_origin_txn(
        LoggingTransaction& txn, const std::string& origin_server,
        int limit = 500, int offset = 0) {
        std::vector<FederationIgnoredUserEntry> results;
        auto rows = txn.select(
            "SELECT id, origin_server, target_server, ignorer_user_id, "
            "ignored_user_id, match_type, direction, sync_status, created_ts, "
            "synced_ts, expires_ts, is_active, reason, sync_id, retry_count, "
            "last_retry_ts FROM ignored_users_federation "
            "WHERE origin_server = ? AND is_active = 1 "
            "ORDER BY created_ts DESC LIMIT ? OFFSET ?",
            {origin_server, limit, offset});
        for (auto& row : rows) {
            results.push_back(row_to_fed_ignored_user(row));
        }
        return results;
    }

    std::vector<FederationIgnoredUserEntry> get_fed_ignores_by_target_txn(
        LoggingTransaction& txn, const std::string& target_server,
        int limit = 500, int offset = 0) {
        std::vector<FederationIgnoredUserEntry> results;
        auto rows = txn.select(
            "SELECT id, origin_server, target_server, ignorer_user_id, "
            "ignored_user_id, match_type, direction, sync_status, created_ts, "
            "synced_ts, expires_ts, is_active, reason, sync_id, retry_count, "
            "last_retry_ts FROM ignored_users_federation "
            "WHERE target_server = ? AND is_active = 1 "
            "ORDER BY created_ts DESC LIMIT ? OFFSET ?",
            {target_server, limit, offset});
        for (auto& row : rows) {
            results.push_back(row_to_fed_ignored_user(row));
        }
        return results;
    }

    std::vector<FederationIgnoredUserEntry> get_pending_fed_syncs_txn(
        LoggingTransaction& txn, int limit = 100) {
        std::vector<FederationIgnoredUserEntry> results;
        auto rows = txn.select(
            "SELECT id, origin_server, target_server, ignorer_user_id, "
            "ignored_user_id, match_type, direction, sync_status, created_ts, "
            "synced_ts, expires_ts, is_active, reason, sync_id, retry_count, "
            "last_retry_ts FROM ignored_users_federation "
            "WHERE sync_status IN (0, 1) AND is_active = 1 "
            "ORDER BY retry_count ASC, created_ts ASC LIMIT ?", {limit});
        for (auto& row : rows) {
            results.push_back(row_to_fed_ignored_user(row));
        }
        return results;
    }

    std::vector<FederationIgnoredUserEntry> get_failed_fed_syncs_txn(
        LoggingTransaction& txn, int max_retries = 5, int limit = 100) {
        std::vector<FederationIgnoredUserEntry> results;
        auto rows = txn.select(
            "SELECT id, origin_server, target_server, ignorer_user_id, "
            "ignored_user_id, match_type, direction, sync_status, created_ts, "
            "synced_ts, expires_ts, is_active, reason, sync_id, retry_count, "
            "last_retry_ts FROM ignored_users_federation "
            "WHERE sync_status = 3 AND retry_count < ? AND is_active = 1 "
            "ORDER BY retry_count ASC LIMIT ?", {max_retries, limit});
        for (auto& row : rows) {
            results.push_back(row_to_fed_ignored_user(row));
        }
        return results;
    }

    int64_t count_fed_ignores_txn(LoggingTransaction& txn,
                                    const std::string& server = "",
                                    bool active_only = true) {
        if (server.empty()) {
            std::string sql = active_only
                ? "SELECT COUNT(*) FROM ignored_users_federation WHERE is_active = 1"
                : "SELECT COUNT(*) FROM ignored_users_federation";
            auto row = txn.select_one(sql);
            return row ? row->get<int64_t>(0) : 0;
        }
        std::string sql = active_only
            ? "SELECT COUNT(*) FROM ignored_users_federation "
              "WHERE (origin_server = ? OR target_server = ?) AND is_active = 1"
            : "SELECT COUNT(*) FROM ignored_users_federation "
              "WHERE origin_server = ? OR target_server = ?";
        auto row = txn.select_one(sql, {server, server});
        return row ? row->get<int64_t>(0) : 0;
    }

    void delete_expired_fed_ignores_txn(LoggingTransaction& txn) {
        txn.execute(
            "UPDATE ignored_users_federation SET is_active = 0 "
            "WHERE is_active = 1 AND expires_ts > 0 AND expires_ts <= ?",
            {now_ms()});
    }

    // ---------- Audit Log CRUD ----------

    int64_t add_audit_entry_txn(LoggingTransaction& txn,
                                  const IgnoreAuditEntry& entry) {
        txn.execute(
            "INSERT INTO ignored_users_audit (action, actor_user_id, "
            "target_user_id, details, action_ts, ip_address, server_name, "
            "metadata) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            {static_cast<int64_t>(entry.action),
             entry.actor_user_id, entry.target_user_id,
             entry.details, entry.action_ts,
             entry.ip_address, entry.server_name,
             entry.metadata.dump()});
        return txn.last_insert_rowid();
    }

    std::vector<IgnoreAuditEntry> get_audit_log_txn(
        LoggingTransaction& txn,
        int limit = 200, int offset = 0) {
        std::vector<IgnoreAuditEntry> results;
        auto rows = txn.select(
            "SELECT id, action, actor_user_id, target_user_id, details, "
            "action_ts, ip_address, server_name, metadata "
            "FROM ignored_users_audit "
            "ORDER BY action_ts DESC LIMIT ? OFFSET ?",
            {limit, offset});
        for (auto& row : rows) {
            results.push_back(row_to_audit_entry(row));
        }
        return results;
    }

    std::vector<IgnoreAuditEntry> get_audit_log_for_user_txn(
        LoggingTransaction& txn,
        const std::string& user_id,
        int limit = 200, int offset = 0) {
        std::vector<IgnoreAuditEntry> results;
        auto rows = txn.select(
            "SELECT id, action, actor_user_id, target_user_id, details, "
            "action_ts, ip_address, server_name, metadata "
            "FROM ignored_users_audit "
            "WHERE actor_user_id = ? OR target_user_id = ? "
            "ORDER BY action_ts DESC LIMIT ? OFFSET ?",
            {user_id, user_id, limit, offset});
        for (auto& row : rows) {
            results.push_back(row_to_audit_entry(row));
        }
        return results;
    }

    std::vector<IgnoreAuditEntry> get_audit_log_by_action_txn(
        LoggingTransaction& txn,
        IgnoreAuditAction action,
        int limit = 200, int offset = 0) {
        std::vector<IgnoreAuditEntry> results;
        auto rows = txn.select(
            "SELECT id, action, actor_user_id, target_user_id, details, "
            "action_ts, ip_address, server_name, metadata "
            "FROM ignored_users_audit "
            "WHERE action = ? "
            "ORDER BY action_ts DESC LIMIT ? OFFSET ?",
            {static_cast<int64_t>(action), limit, offset});
        for (auto& row : rows) {
            results.push_back(row_to_audit_entry(row));
        }
        return results;
    }

    int64_t count_audit_entries_txn(LoggingTransaction& txn,
                                      const std::string& user_id = "") {
        if (user_id.empty()) {
            auto row = txn.select_one(
                "SELECT COUNT(*) FROM ignored_users_audit");
            return row ? row->get<int64_t>(0) : 0;
        }
        auto row = txn.select_one(
            "SELECT COUNT(*) FROM ignored_users_audit "
            "WHERE actor_user_id = ? OR target_user_id = ?",
            {user_id, user_id});
        return row ? row->get<int64_t>(0) : 0;
    }

    int64_t purge_old_audit_entries_txn(LoggingTransaction& txn,
                                          int64_t older_than_ms) {
        txn.execute(
            "DELETE FROM ignored_users_audit WHERE action_ts < ?",
            {older_than_ms});
        return 0;
    }

    // ---------- Room Overrides CRUD ----------

    int64_t set_room_override_txn(LoggingTransaction& txn,
                                    const IgnoreRoomOverride& override) {
        // Check for existing override
        auto existing = txn.select_one(
            "SELECT id FROM ignored_users_overrides "
            "WHERE ignorer_user_id = ? AND ignored_user_id = ? AND room_id = ?",
            {override.ignorer_user_id, override.ignored_user_id, override.room_id});
        if (existing) {
            txn.execute(
                "UPDATE ignored_users_overrides SET allow_messages = ?, "
                "allow_invites = ?, reason = ?, set_ts = ?, expires_ts = ?, "
                "is_active = 1 WHERE id = ?",
                {override.allow_messages ? 1 : 0,
                 override.allow_invites ? 1 : 0,
                 override.reason, override.set_ts, override.expires_ts,
                 existing->get<int64_t>(0)});
            return existing->get<int64_t>(0);
        }

        txn.execute(
            "INSERT INTO ignored_users_overrides (ignorer_user_id, ignored_user_id, "
            "room_id, allow_messages, allow_invites, reason, set_ts, expires_ts, "
            "is_active) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            {override.ignorer_user_id, override.ignored_user_id,
             override.room_id, override.allow_messages ? 1 : 0,
             override.allow_invites ? 1 : 0,
             override.reason, override.set_ts, override.expires_ts,
             override.is_active ? 1 : 0});
        return txn.last_insert_rowid();
    }

    bool remove_room_override_txn(LoggingTransaction& txn, int64_t id) {
        txn.execute(
            "UPDATE ignored_users_overrides SET is_active = 0 WHERE id = ?",
            {id});
        return true;
    }

    bool delete_room_override_txn(LoggingTransaction& txn, int64_t id) {
        txn.execute("DELETE FROM ignored_users_overrides WHERE id = ?", {id});
        return true;
    }

    std::optional<IgnoreRoomOverride> get_room_override_txn(
        LoggingTransaction& txn,
        const std::string& ignorer_user_id,
        const std::string& ignored_user_id,
        const std::string& room_id) {
        auto row = txn.select_one(
            "SELECT id, ignorer_user_id, ignored_user_id, room_id, "
            "allow_messages, allow_invites, reason, set_ts, expires_ts, "
            "is_active FROM ignored_users_overrides "
            "WHERE ignorer_user_id = ? AND ignored_user_id = ? "
            "AND room_id = ? AND is_active = 1 "
            "AND (expires_ts = 0 OR expires_ts > ?)",
            {ignorer_user_id, ignored_user_id, room_id, now_ms()});
        if (!row) return std::nullopt;
        return row_to_room_override(row);
    }

    std::vector<IgnoreRoomOverride> get_all_overrides_for_user_txn(
        LoggingTransaction& txn,
        const std::string& ignorer_user_id,
        int limit = 200, int offset = 0) {
        std::vector<IgnoreRoomOverride> results;
        auto rows = txn.select(
            "SELECT id, ignorer_user_id, ignored_user_id, room_id, "
            "allow_messages, allow_invites, reason, set_ts, expires_ts, "
            "is_active FROM ignored_users_overrides "
            "WHERE ignorer_user_id = ? AND is_active = 1 "
            "AND (expires_ts = 0 OR expires_ts > ?) "
            "ORDER BY set_ts DESC LIMIT ? OFFSET ?",
            {ignorer_user_id, now_ms(), limit, offset});
        for (auto& row : rows) {
            results.push_back(row_to_room_override(row));
        }
        return results;
    }

    std::vector<IgnoreRoomOverride> get_overrides_for_room_txn(
        LoggingTransaction& txn,
        const std::string& room_id,
        int limit = 200, int offset = 0) {
        std::vector<IgnoreRoomOverride> results;
        auto rows = txn.select(
            "SELECT id, ignorer_user_id, ignored_user_id, room_id, "
            "allow_messages, allow_invites, reason, set_ts, expires_ts, "
            "is_active FROM ignored_users_overrides "
            "WHERE room_id = ? AND is_active = 1 "
            "AND (expires_ts = 0 OR expires_ts > ?) "
            "ORDER BY set_ts DESC LIMIT ? OFFSET ?",
            {room_id, now_ms(), limit, offset});
        for (auto& row : rows) {
            results.push_back(row_to_room_override(row));
        }
        return results;
    }

    void delete_expired_overrides_txn(LoggingTransaction& txn) {
        txn.execute(
            "UPDATE ignored_users_overrides SET is_active = 0 "
            "WHERE is_active = 1 AND expires_ts > 0 AND expires_ts <= ?",
            {now_ms()});
    }

    // ---------- Import CRUD ----------

    int64_t create_import_txn(LoggingTransaction& txn,
                                const IgnoreImportEntry& entry) {
        txn.execute(
            "INSERT INTO ignored_users_imports (import_id, source_type, source, "
            "imported_by, imported_ts, entry_count, error_count, status, "
            "metadata) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            {entry.import_id, entry.source_type, entry.source,
             entry.imported_by, entry.imported_ts,
             entry.entry_count, entry.error_count,
             entry.status, entry.metadata.dump()});
        return txn.last_insert_rowid();
    }

    std::optional<IgnoreImportEntry> get_import_txn(
        LoggingTransaction& txn, const std::string& import_id) {
        auto row = txn.select_one(
            "SELECT id, import_id, source_type, source, imported_by, "
            "imported_ts, entry_count, error_count, status, metadata "
            "FROM ignored_users_imports WHERE import_id = ?", {import_id});
        if (!row) return std::nullopt;
        return row_to_import_entry(row);
    }

    bool update_import_txn(LoggingTransaction& txn, const std::string& import_id,
                             const json& updates) {
        std::vector<std::string> set_clauses;
        std::vector<storage::SQLParam> params;

        if (updates.contains("entry_count")) {
            set_clauses.push_back("entry_count = ?");
            params.push_back(updates["entry_count"].get<int64_t>());
        }
        if (updates.contains("error_count")) {
            set_clauses.push_back("error_count = ?");
            params.push_back(updates["error_count"].get<int64_t>());
        }
        if (updates.contains("status")) {
            set_clauses.push_back("status = ?");
            params.push_back(updates["status"].get<std::string>());
        }
        if (updates.contains("metadata")) {
            set_clauses.push_back("metadata = ?");
            params.push_back(updates["metadata"].dump());
        }

        if (set_clauses.empty()) return false;
        params.push_back(import_id);

        std::string sql = "UPDATE ignored_users_imports SET " +
                          join(set_clauses, ", ") + " WHERE import_id = ?";
        txn.execute(sql, params);
        return true;
    }

    std::vector<IgnoreImportEntry> get_imports_txn(
        LoggingTransaction& txn, int limit = 100, int offset = 0) {
        std::vector<IgnoreImportEntry> results;
        auto rows = txn.select(
            "SELECT id, import_id, source_type, source, imported_by, "
            "imported_ts, entry_count, error_count, status, metadata "
            "FROM ignored_users_imports "
            "ORDER BY imported_ts DESC LIMIT ? OFFSET ?",
            {limit, offset});
        for (auto& row : rows) {
            results.push_back(row_to_import_entry(row));
        }
        return results;
    }

    // ---------- Bulk / Maintenance ----------

    int64_t bulk_add_ignored_users_txn(
        LoggingTransaction& txn,
        const std::vector<IgnoredUserEntry>& entries) {
        int64_t count = 0;
        for (const auto& entry : entries) {
            try {
                add_ignored_user_txn(txn, entry);
                ++count;
            } catch (...) {
                // Skip duplicates
            }
        }
        return count;
    }

    int64_t bulk_remove_ignored_users_txn(
        LoggingTransaction& txn,
        const std::string& ignorer_user_id,
        const std::vector<std::string>& ignored_user_ids) {
        int64_t count = 0;
        for (const auto& uid : ignored_user_ids) {
            txn.execute(
                "UPDATE ignored_users SET is_active = 0 "
                "WHERE ignorer_user_id = ? AND ignored_user_id = ? "
                "AND match_type = 0",
                {ignorer_user_id, uid});
            count++;
        }
        return count;
    }

    void delete_all_expired_txn(LoggingTransaction& txn) {
        delete_expired_ignores_txn(txn);
        delete_expired_fed_ignores_txn(txn);
        delete_expired_overrides_txn(txn);
    }

    // ---------- Statistics ----------

    IgnoredUsersStats get_stats_txn(LoggingTransaction& txn) {
        IgnoredUsersStats stats;

        auto r1 = txn.select_one(
            "SELECT COUNT(*) FROM ignored_users");
        stats.total_ignore_entries = r1 ? r1->get<int64_t>(0) : 0;

        auto r2 = txn.select_one(
            "SELECT COUNT(*) FROM ignored_users WHERE is_active = 1 "
            "AND (expires_ts = 0 OR expires_ts > ?)", {now_ms()});
        stats.active_ignore_entries = r2 ? r2->get<int64_t>(0) : 0;

        auto r3 = txn.select_one(
            "SELECT COUNT(DISTINCT ignored_user_id) FROM ignored_users "
            "WHERE is_active = 1 AND match_type = 0 "
            "AND (expires_ts = 0 OR expires_ts > ?)", {now_ms()});
        stats.total_ignored_unique_users = r3 ? r3->get<int64_t>(0) : 0;

        auto r4 = txn.select_one(
            "SELECT COUNT(*) FROM ignored_users_invites");
        stats.total_invites_blocked = r4 ? r4->get<int64_t>(0) : 0;

        auto r5 = txn.select_one(
            "SELECT COUNT(*) FROM ignored_users_messages");
        stats.total_messages_filtered = r5 ? r5->get<int64_t>(0) : 0;

        auto r6 = txn.select_one(
            "SELECT COUNT(*) FROM ignored_users_federation "
            "WHERE sync_status = 2");
        stats.total_federation_syncs = r6 ? r6->get<int64_t>(0) : 0;

        auto r7 = txn.select_one(
            "SELECT COUNT(*) FROM ignored_users_imports");
        stats.total_imports = r7 ? r7->get<int64_t>(0) : 0;

        auto r8 = txn.select_one(
            "SELECT COUNT(*) FROM ignored_users_audit");
        stats.total_audit_entries = r8 ? r8->get<int64_t>(0) : 0;

        stats.last_maintenance_ts = now_ms();

        return stats;
    }

private:
    DatabasePool& db_;
    IgnoreLogger& logger_;
};

// ============================================================================
// 2. IgnoredUserManager — Per-user ignore list management
// ============================================================================

class IgnoredUserManager {
public:
    explicit IgnoredUserManager(DatabasePool& db, IgnoreLogger& logger)
        : db_(db), store_(db, logger), logger_(logger) {}

    // Add a user to the ignore list
    json add_ignore(const std::string& ignorer_user_id,
                     const std::string& ignored_user_id,
                     const std::string& reason = "",
                     const std::string& match_type_str = "exact",
                     const std::string& invite_policy_str = "block_silently",
                     const std::string& message_policy_str = "drop",
                     int64_t expires_ts = 0,
                     const std::string& notes = "",
                     const std::string& ip_address = "") {
        return db_.with_write_txn([&](LoggingTransaction& txn) -> json {
            IgnoredUserEntry entry;
            entry.ignorer_user_id = ignorer_user_id;
            entry.ignored_user_id = ignored_user_id;
            entry.match_type = ignore_match_type_from_str(match_type_str);
            entry.reason = reason;
            entry.ignored_ts = now_ms();
            entry.expires_ts = expires_ts;
            entry.is_active = true;
            entry.invite_policy = ignore_invite_policy_from_str(invite_policy_str);
            entry.message_policy = ignore_message_policy_from_str(message_policy_str);
            entry.notes = notes;

            int64_t id = store_.add_ignored_user_txn(txn, entry);

            // Audit log
            IgnoreAuditEntry audit;
            audit.action = IgnoreAuditAction::IGNORE_ADDED;
            audit.actor_user_id = ignorer_user_id;
            audit.target_user_id = ignored_user_id;
            audit.details = "Added to ignore list. Reason: " + reason;
            audit.action_ts = now_ms();
            audit.ip_address = ip_address;
            audit.metadata = {
                {"match_type", match_type_str},
                {"invite_policy", invite_policy_str},
                {"message_policy", message_policy_str},
                {"entry_id", id}
            };
            store_.add_audit_entry_txn(txn, audit);

            json result;
            result["success"] = true;
            result["entry_id"] = id;
            result["message"] = "User added to ignore list";
            return result;
        });
    }

    // Remove a user from the ignore list
    json remove_ignore(const std::string& ignorer_user_id,
                        const std::string& ignored_user_id,
                        const std::string& ip_address = "") {
        return db_.with_write_txn([&](LoggingTransaction& txn) -> json {
            store_.remove_ignored_user_by_pair_txn(txn, ignorer_user_id,
                                                    ignored_user_id);

            IgnoreAuditEntry audit;
            audit.action = IgnoreAuditAction::IGNORE_REMOVED;
            audit.actor_user_id = ignorer_user_id;
            audit.target_user_id = ignored_user_id;
            audit.details = "Removed from ignore list";
            audit.action_ts = now_ms();
            audit.ip_address = ip_address;
            store_.add_audit_entry_txn(txn, audit);

            json result;
            result["success"] = true;
            result["message"] = "User removed from ignore list";
            return result;
        });
    }

    // Remove by entry ID
    json remove_ignore_by_id(int64_t entry_id,
                               const std::string& actor_user_id = "") {
        return db_.with_write_txn([&](LoggingTransaction& txn) -> json {
            auto existing = store_.get_ignored_user_txn(txn, entry_id);
            store_.remove_ignored_user_txn(txn, entry_id);

            if (existing) {
                IgnoreAuditEntry audit;
                audit.action = IgnoreAuditAction::IGNORE_REMOVED;
                audit.actor_user_id = actor_user_id.empty() ?
                    existing->ignorer_user_id : actor_user_id;
                audit.target_user_id = existing->ignored_user_id;
                audit.details = "Removed ignore entry by ID";
                audit.action_ts = now_ms();
                audit.metadata = {{"entry_id", entry_id}};
                store_.add_audit_entry_txn(txn, audit);
            }

            json result;
            result["success"] = true;
            result["message"] = "Ignore entry removed";
            return result;
        });
    }

    // Delete permanently
    json delete_ignore(int64_t entry_id) {
        return db_.with_write_txn([&](LoggingTransaction& txn) -> json {
            store_.delete_ignored_user_txn(txn, entry_id);

            json result;
            result["success"] = true;
            result["message"] = "Ignore entry permanently deleted";
            return result;
        });
    }

    // Update an ignore entry
    json update_ignore(int64_t entry_id, const json& updates) {
        return db_.with_write_txn([&](LoggingTransaction& txn) -> json {
            bool updated = store_.update_ignored_user_txn(txn, entry_id, updates);

            auto existing = store_.get_ignored_user_txn(txn, entry_id);
            if (existing) {
                IgnoreAuditEntry audit;
                audit.action = IgnoreAuditAction::IGNORE_UPDATED;
                audit.actor_user_id = existing->ignorer_user_id;
                audit.target_user_id = existing->ignored_user_id;
                audit.details = "Updated ignore entry";
                audit.action_ts = now_ms();
                audit.metadata = updates;
                store_.add_audit_entry_txn(txn, audit);
            }

            json result;
            result["success"] = updated;
            result["message"] = updated ? "Ignore entry updated" :
                                          "No changes to update";
            return result;
        });
    }

    // Check if a user is ignored
    IgnoreCheckResult check_ignored(const std::string& ignorer_user_id,
                                     const std::string& target_user_id,
                                     const std::string& room_id = "") {
        IgnoreCheckResult result;
        result.checked_ts = now_ms();

        db_.with_read_txn([&](LoggingTransaction& txn) {
            auto matches = store_.check_user_ignored_txn(
                txn, ignorer_user_id, target_user_id);

            if (!matches.empty()) {
                result.is_ignored = true;
                // Take the strictest policies
                for (const auto& match : matches) {
                    bool is_exact = match.match_type == IgnoreMatchType::EXACT &&
                                    match.ignored_user_id == target_user_id;
                    if (is_exact) {
                        result.entry_id = match.id;
                        result.matched_pattern = match.ignored_user_id;
                        result.reason = match.reason;
                        result.invite_policy = match.invite_policy;
                        result.message_policy = match.message_policy;
                        break;
                    }
                }
                if (result.entry_id == 0 && !matches.empty()) {
                    const auto& m = matches[0];
                    result.entry_id = m.id;
                    result.matched_pattern = m.ignored_user_id;
                    result.reason = m.reason;
                    result.invite_policy = m.invite_policy;
                    result.message_policy = m.message_policy;
                }

                // Check room overrides
                if (!room_id.empty()) {
                    auto override = store_.get_room_override_txn(
                        txn, ignorer_user_id, target_user_id, room_id);
                    if (override) {
                        result.has_room_override = true;
                        result.room_override = *override;
                    }
                }
            }
        });

        return result;
    }

    // List ignored users for a given user
    json list_ignored_users(const std::string& ignorer_user_id,
                              bool active_only = true,
                              int limit = 500, int offset = 0) {
        return db_.with_read_txn([&](LoggingTransaction& txn) -> json {
            std::vector<IgnoredUserEntry> entries;
            if (active_only) {
                entries = store_.get_ignored_users_for_txn(
                    txn, ignorer_user_id, limit, offset);
            } else {
                entries = store_.get_all_ignored_users_for_txn(
                    txn, ignorer_user_id, limit, offset);
            }

            int64_t total = store_.count_ignored_users_txn(
                txn, ignorer_user_id, active_only);

            json result;
            result["ignored_users"] = json::array();
            for (const auto& entry : entries) {
                result["ignored_users"].push_back(entry.to_json());
            }
            result["total"] = total;
            result["limit"] = limit;
            result["offset"] = offset;
            return result;
        });
    }

    // Search ignored users
    json search_ignored_users(const std::string& ignorer_user_id,
                               const std::string& search_pattern,
                               int limit = 500, int offset = 0) {
        return db_.with_read_txn([&](LoggingTransaction& txn) -> json {
            auto entries = store_.search_ignored_users_txn(
                txn, ignorer_user_id, search_pattern, limit, offset);

            json result;
            result["ignored_users"] = json::array();
            for (const auto& entry : entries) {
                result["ignored_users"].push_back(entry.to_json());
            }
            result["search_pattern"] = search_pattern;
            result["count"] = entries.size();
            return result;
        });
    }

    // Get ignore entry by ID
    json get_ignore_entry(int64_t entry_id) {
        return db_.with_read_txn([&](LoggingTransaction& txn) -> json {
            auto entry = store_.get_ignored_user_txn(txn, entry_id);
            if (!entry) {
                json err;
                err["error"] = "Ignore entry not found";
                return err;
            }
            return entry->to_json();
        });
    }

    // Get all users who ignore a specific target
    json get_ignorers(const std::string& ignored_user_id,
                        int limit = 500, int offset = 0) {
        return db_.with_read_txn([&](LoggingTransaction& txn) -> json {
            auto entries = store_.get_ignorers_for_user_txn(
                txn, ignored_user_id, limit, offset);
            int64_t total = store_.count_ignorers_for_user_txn(
                txn, ignored_user_id);

            json result;
            result["ignorers"] = json::array();
            for (const auto& entry : entries) {
                result["ignorers"].push_back(entry.to_json());
            }
            result["total"] = total;
            result["limit"] = limit;
            result["offset"] = offset;
            return result;
        });
    }

    // Bulk add ignored users
    json bulk_add_ignores(const std::string& ignorer_user_id,
                            const std::vector<std::string>& user_ids,
                            const std::string& reason = "",
                            const std::string& invite_policy_str = "block_silently",
                            const std::string& message_policy_str = "drop") {
        return db_.with_write_txn([&](LoggingTransaction& txn) -> json {
            int64_t added = 0;
            int64_t skipped = 0;
            std::vector<std::string> errors;

            for (const auto& uid : user_ids) {
                try {
                    IgnoredUserEntry entry;
                    entry.ignorer_user_id = ignorer_user_id;
                    entry.ignored_user_id = uid;
                    entry.match_type = IgnoreMatchType::EXACT;
                    entry.reason = reason;
                    entry.ignored_ts = now_ms();
                    entry.expires_ts = 0;
                    entry.is_active = true;
                    entry.invite_policy = ignore_invite_policy_from_str(invite_policy_str);
                    entry.message_policy = ignore_message_policy_from_str(message_policy_str);

                    store_.add_ignored_user_txn(txn, entry);
                    added++;
                } catch (const std::exception& e) {
                    errors.push_back(std::string("Failed for ") + uid + ": " + e.what());
                    skipped++;
                }
            }

            // Audit for bulk operation
            if (added > 0) {
                IgnoreAuditEntry audit;
                audit.action = IgnoreAuditAction::BULK_OPERATION;
                audit.actor_user_id = ignorer_user_id;
                audit.target_user_id = "";
                audit.details = "Bulk added " + std::to_string(added) + " users to ignore list";
                audit.action_ts = now_ms();
                audit.metadata = {
                    {"added", added},
                    {"skipped", skipped},
                    {"total", user_ids.size()}
                };
                store_.add_audit_entry_txn(txn, audit);
            }

            json result;
            result["success"] = true;
            result["added"] = added;
            result["skipped"] = skipped;
            result["errors"] = errors;
            return result;
        });
    }

    // Bulk remove ignored users
    json bulk_remove_ignores(const std::string& ignorer_user_id,
                               const std::vector<std::string>& user_ids) {
        return db_.with_write_txn([&](LoggingTransaction& txn) -> json {
            int64_t removed = store_.bulk_remove_ignored_users_txn(
                txn, ignorer_user_id, user_ids);

            IgnoreAuditEntry audit;
            audit.action = IgnoreAuditAction::BULK_OPERATION;
            audit.actor_user_id = ignorer_user_id;
            audit.target_user_id = "";
            audit.details = "Bulk removed " + std::to_string(removed) + " users from ignore list";
            audit.action_ts = now_ms();
            audit.metadata = {{"removed", removed}, {"total", user_ids.size()}};
            store_.add_audit_entry_txn(txn, audit);

            json result;
            result["success"] = true;
            result["removed"] = removed;
            return result;
        });
    }

    // Count ignored users
    json count_ignored(const std::string& ignorer_user_id,
                         bool active_only = true) {
        return db_.with_read_txn([&](LoggingTransaction& txn) -> json {
            int64_t count = store_.count_ignored_users_txn(
                txn, ignorer_user_id, active_only);
            json result;
            result["count"] = count;
            result["active_only"] = active_only;
            return result;
        });
    }

    // Clean up expired ignores
    json cleanup_expired() {
        return db_.with_write_txn([&](LoggingTransaction& txn) -> json {
            store_.delete_expired_ignores_txn(txn);

            IgnoreAuditEntry audit;
            audit.action = IgnoreAuditAction::IGNORE_EXPIRED;
            audit.actor_user_id = "system";
            audit.target_user_id = "";
            audit.details = "Cleaned up expired ignore entries";
            audit.action_ts = now_ms();
            store_.add_audit_entry_txn(txn, audit);

            json result;
            result["success"] = true;
            result["message"] = "Expired ignore entries cleaned up";
            return result;
        });
    }

    // Set room override
    json set_room_override(const std::string& ignorer_user_id,
                             const std::string& ignored_user_id,
                             const std::string& room_id,
                             bool allow_messages,
                             bool allow_invites,
                             const std::string& reason = "",
                             int64_t expires_ts = 0) {
        return db_.with_write_txn([&](LoggingTransaction& txn) -> json {
            IgnoreRoomOverride override_entry;
            override_entry.ignorer_user_id = ignorer_user_id;
            override_entry.ignored_user_id = ignored_user_id;
            override_entry.room_id = room_id;
            override_entry.allow_messages = allow_messages;
            override_entry.allow_invites = allow_invites;
            override_entry.reason = reason;
            override_entry.set_ts = now_ms();
            override_entry.expires_ts = expires_ts;
            override_entry.is_active = true;

            int64_t id = store_.set_room_override_txn(txn, override_entry);

            json result;
            result["success"] = true;
            result["override_id"] = id;
            result["message"] = "Room override set";
            return result;
        });
    }

    // Remove room override
    json remove_room_override(int64_t override_id) {
        return db_.with_write_txn([&](LoggingTransaction& txn) -> json {
            store_.remove_room_override_txn(txn, override_id);

            json result;
            result["success"] = true;
            result["message"] = "Room override removed";
            return result;
        });
    }

    // Get room overrides for a user
    json get_room_overrides(const std::string& ignorer_user_id,
                              int limit = 200, int offset = 0) {
        return db_.with_read_txn([&](LoggingTransaction& txn) -> json {
            auto overrides = store_.get_all_overrides_for_user_txn(
                txn, ignorer_user_id, limit, offset);

            json result;
            result["overrides"] = json::array();
            for (const auto& ov : overrides) {
                result["overrides"].push_back(ov.to_json());
            }
            result["count"] = overrides.size();
            return result;
        });
    }

    // Toggle ignore status (activate/deactivate)
    json toggle_ignore(int64_t entry_id, bool activate) {
        return db_.with_write_txn([&](LoggingTransaction& txn) -> json {
            json updates;
            updates["is_active"] = activate;
            store_.update_ignored_user_txn(txn, entry_id, updates);

            json result;
            result["success"] = true;
            result["active"] = activate;
            return result;
        });
    }

private:
    DatabasePool& db_;
    IgnoredUsersStore store_;
    IgnoreLogger& logger_;
};

// ============================================================================
// 3. InviteBlocker — Invite blocking for ignored users
// ============================================================================

class InviteBlocker {
public:
    explicit InviteBlocker(DatabasePool& db, IgnoredUserManager& user_mgr,
                            IgnoreLogger& logger)
        : db_(db), store_(db, logger), user_mgr_(user_mgr), logger_(logger) {}

    // Check if an invite should be blocked and handle it
    json check_and_block_invite(const std::string& inviter_user_id,
                                  const std::string& invitee_user_id,
                                  const std::string& room_id,
                                  const std::string& event_id = "",
                                  const std::string& ip_address = "") {
        auto check_result = user_mgr_.check_ignored(invitee_user_id,
                                                      inviter_user_id, room_id);

        json result;
        result["checked_ts"] = now_ms();
        result["inviter"] = inviter_user_id;
        result["invitee"] = invitee_user_id;
        result["room_id"] = room_id;

        if (check_result.is_ignored) {
            // Check room override for invites
            bool override_allows = check_result.has_room_override &&
                                   check_result.room_override.allow_invites;

            if (override_allows) {
                result["blocked"] = false;
                result["reason"] = "Room override allows invites";
                return result;
            }

            auto policy = check_result.invite_policy;
            if (policy == IgnoreInvitePolicy::ALLOW_INVITES) {
                result["blocked"] = false;
                result["reason"] = "Invite policy allows invites";
                return result;
            }

            // Block the invite
            result["blocked"] = true;
            result["rejection_reason"] = "User is ignored. Reason: " +
                                          check_result.reason;
            result["policy_applied"] = ignore_invite_policy_str(policy);

            // Log the blocked invite
            db_.with_write_txn([&](LoggingTransaction& txn) {
                IgnoreInviteBlockEntry block_entry;
                block_entry.ignorer_user_id = invitee_user_id;
                block_entry.ignored_user_id = inviter_user_id;
                block_entry.room_id = room_id;
                block_entry.event_id = event_id;
                block_entry.blocked_ts = now_ms();
                block_entry.rejection_reason = result["rejection_reason"];
                block_entry.policy_applied = result["policy_applied"];
                block_entry.notified =
                    (policy == IgnoreInvitePolicy::BLOCK_AND_NOTIFY);

                store_.log_blocked_invite_txn(txn, block_entry);

                // Audit log
                IgnoreAuditEntry audit;
                audit.action = IgnoreAuditAction::INVITE_BLOCKED;
                audit.actor_user_id = invitee_user_id;
                audit.target_user_id = inviter_user_id;
                audit.details = "Blocked invite from ignored user in room " +
                                room_id;
                audit.action_ts = now_ms();
                audit.ip_address = ip_address;
                audit.metadata = {
                    {"room_id", room_id},
                    {"event_id", event_id},
                    {"policy", result["policy_applied"]},
                    {"ignore_entry_id", check_result.entry_id}
                };
                store_.add_audit_entry_txn(txn, audit);
            });

            result["should_notify"] =
                (policy == IgnoreInvitePolicy::BLOCK_AND_NOTIFY);
        } else {
            result["blocked"] = false;
            result["reason"] = "User is not ignored";
        }

        return result;
    }

    // Get blocked invites for a user
    json get_blocked_invites(const std::string& user_id,
                               int limit = 200, int offset = 0) {
        return db_.with_read_txn([&](LoggingTransaction& txn) -> json {
            auto invites = store_.get_blocked_invites_txn(
                txn, user_id, limit, offset);

            json result;
            result["blocked_invites"] = json::array();
            for (const auto& inv : invites) {
                result["blocked_invites"].push_back(inv.to_json());
            }
            result["count"] = invites.size();
            return result;
        });
    }

    // Get how many times a specific user had their invites blocked
    json get_invites_blocked_for_user(const std::string& user_id,
                                        int limit = 200, int offset = 0) {
        return db_.with_read_txn([&](LoggingTransaction& txn) -> json {
            auto invites = store_.get_blocked_invites_by_ignored_txn(
                txn, user_id, limit, offset);

            json result;
            result["blocked_invites"] = json::array();
            for (const auto& inv : invites) {
                result["blocked_invites"].push_back(inv.to_json());
            }
            result["count"] = invites.size();
            return result;
        });
    }

    // Get blocked invites for a room
    json get_room_blocked_invites(const std::string& room_id,
                                    int limit = 200, int offset = 0) {
        return db_.with_read_txn([&](LoggingTransaction& txn) -> json {
            auto invites = store_.get_blocked_invites_for_room_txn(
                txn, room_id, limit, offset);

            json result;
            result["room_id"] = room_id;
            result["blocked_invites"] = json::array();
            for (const auto& inv : invites) {
                result["blocked_invites"].push_back(inv.to_json());
            }
            result["count"] = invites.size();
            return result;
        });
    }

    // Count blocked invites
    json count_blocked_invites(const std::string& user_id = "") {
        return db_.with_read_txn([&](LoggingTransaction& txn) -> json {
            int64_t count = store_.count_blocked_invites_txn(txn, user_id);
            json result;
            result["count"] = count;
            return result;
        });
    }

    // Purge old invite blocking logs
    json purge_old_invites(int retention_days = 90) {
        return db_.with_write_txn([&](LoggingTransaction& txn) -> json {
            int64_t cutoff = now_ms() - (retention_days * 86400000LL);
            store_.purge_old_invites_txn(txn, cutoff);

            json result;
            result["success"] = true;
            result["message"] = "Old blocked invite logs purged";
            result["cutoff_age_days"] = retention_days;
            return result;
        });
    }

private:
    DatabasePool& db_;
    IgnoredUsersStore store_;
    IgnoredUserManager& user_mgr_;
    IgnoreLogger& logger_;
};

// ============================================================================
// 4. MessageFilter — Message filtering for ignored users
// ============================================================================

class MessageFilter {
public:
    explicit MessageFilter(DatabasePool& db, IgnoredUserManager& user_mgr,
                            IgnoreLogger& logger)
        : db_(db), store_(db, logger), user_mgr_(user_mgr), logger_(logger) {}

    // Filter a message - returns the action that should be taken
    json filter_message(const std::string& sender_user_id,
                          const std::string& recipient_user_id,
                          const std::string& room_id,
                          const std::string& event_id,
                          const std::string& event_type,
                          bool is_mention = false) {
        auto check_result = user_mgr_.check_ignored(recipient_user_id,
                                                      sender_user_id, room_id);

        json result;
        result["filtered_ts"] = now_ms();
        result["sender"] = sender_user_id;
        result["recipient"] = recipient_user_id;
        result["room_id"] = room_id;
        result["event_id"] = event_id;
        result["event_type"] = event_type;

        if (!check_result.is_ignored) {
            result["action"] = "deliver";
            result["deliver"] = true;
            return result;
        }

        // Check room override for messages
        if (check_result.has_room_override &&
            check_result.room_override.allow_messages) {
            result["action"] = "deliver";
            result["reason"] = "Room override allows messages";
            result["deliver"] = true;
            return result;
        }

        // Mentions bypass
        if (is_mention && check_result.message_policy != IgnoreMessagePolicy::DROP) {
            result["action"] = "deliver";
            result["reason"] = "Mention bypass";
            result["deliver"] = true;
            return result;
        }

        // Apply message policy
        auto policy = check_result.message_policy;
        std::string quarantine_id;

        switch (policy) {
            case IgnoreMessagePolicy::DROP:
                result["action"] = "drop";
                result["deliver"] = false;
                break;
            case IgnoreMessagePolicy::QUARANTINE:
                quarantine_id = generate_quarantine_id();
                result["action"] = "quarantine";
                result["quarantine_id"] = quarantine_id;
                result["deliver"] = false;
                break;
            case IgnoreMessagePolicy::FLAG:
                result["action"] = "flag";
                result["deliver"] = true;
                break;
            case IgnoreMessagePolicy::DELIVER_ALL:
                result["action"] = "deliver";
                result["deliver"] = true;
                break;
        }

        // Log the filtered message
        db_.with_write_txn([&](LoggingTransaction& txn) {
            IgnoreMessageFilterEntry filter_entry;
            filter_entry.ignorer_user_id = recipient_user_id;
            filter_entry.ignored_user_id = sender_user_id;
            filter_entry.room_id = room_id;
            filter_entry.event_id = event_id;
            filter_entry.event_type = event_type;
            filter_entry.filtered_ts = now_ms();
            filter_entry.action = policy;
            filter_entry.is_mention = is_mention;
            filter_entry.delivered = result["deliver"];
            filter_entry.quarantine_id = quarantine_id;

            store_.log_filtered_message_txn(txn, filter_entry);

            // Audit log
            IgnoreAuditAction audit_action;
            if (policy == IgnoreMessagePolicy::DROP) {
                audit_action = IgnoreAuditAction::MESSAGE_DROPPED;
            } else if (policy == IgnoreMessagePolicy::FLAG) {
                audit_action = IgnoreAuditAction::MESSAGE_FLAGGED;
            } else {
                audit_action = IgnoreAuditAction::MESSAGE_DROPPED;
            }

            IgnoreAuditEntry audit;
            audit.action = audit_action;
            audit.actor_user_id = recipient_user_id;
            audit.target_user_id = sender_user_id;
            audit.details = "Filtered message from ignored user";
            audit.action_ts = now_ms();
            audit.metadata = {
                {"room_id", room_id},
                {"event_id", event_id},
                {"event_type", event_type},
                {"action", ignore_message_policy_str(policy)},
                {"is_mention", is_mention}
            };
            store_.add_audit_entry_txn(txn, audit);
        });

        return result;
    }

    // Get filtered messages for a user
    json get_filtered_messages(const std::string& user_id,
                                 int limit = 200, int offset = 0) {
        return db_.with_read_txn([&](LoggingTransaction& txn) -> json {
            auto messages = store_.get_filtered_messages_txn(
                txn, user_id, limit, offset);

            json result;
            result["filtered_messages"] = json::array();
            for (const auto& msg : messages) {
                result["filtered_messages"].push_back(msg.to_json());
            }
            result["count"] = messages.size();
            return result;
        });
    }

    // Get messages filtered by a specific ignored user
    json get_filtered_by_user(const std::string& ignored_user_id,
                                int limit = 200, int offset = 0) {
        return db_.with_read_txn([&](LoggingTransaction& txn) -> json {
            auto messages = store_.get_filtered_messages_by_ignored_txn(
                txn, ignored_user_id, limit, offset);

            json result;
            result["filtered_messages"] = json::array();
            for (const auto& msg : messages) {
                result["filtered_messages"].push_back(msg.to_json());
            }
            result["count"] = messages.size();
            return result;
        });
    }

    // Get filtered messages for a room
    json get_filtered_for_room(const std::string& room_id,
                                 int limit = 200, int offset = 0) {
        return db_.with_read_txn([&](LoggingTransaction& txn) -> json {
            auto messages = store_.get_filtered_messages_for_room_txn(
                txn, room_id, limit, offset);

            json result;
            result["room_id"] = room_id;
            result["filtered_messages"] = json::array();
            for (const auto& msg : messages) {
                result["filtered_messages"].push_back(msg.to_json());
            }
            result["count"] = messages.size();
            return result;
        });
    }

    // Retrieve a quarantined message
    json get_quarantined_message(const std::string& quarantine_id) {
        return db_.with_read_txn([&](LoggingTransaction& txn) -> json {
            auto msg = store_.get_quarantined_message_txn(txn, quarantine_id);
            if (!msg) {
                json err;
                err["error"] = "Quarantined message not found";
                return err;
            }
            return msg->to_json();
        });
    }

    // Count filtered messages
    json count_filtered_messages(const std::string& user_id = "") {
        return db_.with_read_txn([&](LoggingTransaction& txn) -> json {
            int64_t count = store_.count_filtered_messages_txn(txn, user_id);
            json result;
            result["count"] = count;
            return result;
        });
    }

    // Purge old filtered messages
    json purge_old_messages(int retention_days = 90) {
        return db_.with_write_txn([&](LoggingTransaction& txn) -> json {
            int64_t cutoff = now_ms() - (retention_days * 86400000LL);
            store_.purge_old_filtered_messages_txn(txn, cutoff);

            json result;
            result["success"] = true;
            result["message"] = "Old filtered messages purged";
            result["cutoff_age_days"] = retention_days;
            return result;
        });
    }

    // Check if a specific event type should be filtered for a user pair
    json should_filter_event(const std::string& sender_user_id,
                               const std::string& recipient_user_id,
                               const std::string& room_id,
                               const std::string& event_type) {
        auto check_result = user_mgr_.check_ignored(recipient_user_id,
                                                      sender_user_id, room_id);

        json result;
        result["should_filter"] = check_result.is_ignored;
        result["policy"] = ignore_message_policy_str(check_result.message_policy);

        // Filter event types that are commonly filtered
        static const std::set<std::string> filterable_types = {
            "m.room.message", "m.room.encrypted", "m.reaction",
            "m.sticker", "m.room.redaction"
        };
        result["is_filterable_type"] =
            filterable_types.count(event_type) > 0;

        if (check_result.has_room_override) {
            result["room_override"] = check_result.room_override.to_json();
            result["override_allows"] =
                check_result.room_override.allow_messages;
        }

        return result;
    }

private:
    DatabasePool& db_;
    IgnoredUsersStore store_;
    IgnoredUserManager& user_mgr_;
    IgnoreLogger& logger_;
};

// ============================================================================
// 5. FederationIgnoredUsers — Federation ignored user handling
// ============================================================================

class FederationIgnoredUsers {
public:
    explicit FederationIgnoredUsers(DatabasePool& db,
                                      IgnoredUserManager& user_mgr,
                                      IgnoreLogger& logger)
        : db_(db), store_(db, logger), user_mgr_(user_mgr), logger_(logger) {}

    // Push local ignores to a remote server
    json push_ignores_to_server(const std::string& origin_server,
                                  const std::string& target_server,
                                  const std::vector<IgnoredUserEntry>& entries,
                                  const std::string& reason = "") {
        return db_.with_write_txn([&](LoggingTransaction& txn) -> json {
            json results;
            results["sync_id"] = generate_sync_id();
            results["pushed"] = json::array();
            int64_t pushed_count = 0;
            int64_t skipped_count = 0;

            for (const auto& entry : entries) {
                FederationIgnoredUserEntry fed_entry;
                fed_entry.origin_server = origin_server;
                fed_entry.target_server = target_server;
                fed_entry.ignorer_user_id = entry.ignorer_user_id;
                fed_entry.ignored_user_id = entry.ignored_user_id;
                fed_entry.match_type = entry.match_type;
                fed_entry.direction = FederationIgnoreDirection::OUTBOUND;
                fed_entry.sync_status = FederationIgnoreSyncStatus::PENDING;
                fed_entry.created_ts = now_ms();
                fed_entry.synced_ts = 0;
                fed_entry.expires_ts = entry.expires_ts;
                fed_entry.is_active = entry.is_active;
                fed_entry.reason = reason.empty() ? entry.reason : reason;
                fed_entry.sync_id = results["sync_id"];

                try {
                    int64_t id = store_.add_fed_ignored_user_txn(txn, fed_entry);
                    json pushed;
                    pushed["fed_entry_id"] = id;
                    pushed["ignorer_user_id"] = entry.ignorer_user_id;
                    pushed["ignored_user_id"] = entry.ignored_user_id;
                    results["pushed"].push_back(pushed);
                    pushed_count++;
                } catch (...) {
                    skipped_count++;
                }
            }

            // Audit
            IgnoreAuditEntry audit;
            audit.action = IgnoreAuditAction::FED_SYNC_PUSH;
            audit.actor_user_id = "federation";
            audit.target_user_id = target_server;
            audit.details = "Pushed " + std::to_string(pushed_count) +
                            " ignores to " + target_server;
            audit.action_ts = now_ms();
            audit.metadata = {
                {"origin_server", origin_server},
                {"target_server", target_server},
                {"pushed_count", pushed_count},
                {"skipped_count", skipped_count},
                {"sync_id", results["sync_id"]}
            };
            store_.add_audit_entry_txn(txn, audit);

            results["pushed_count"] = pushed_count;
            results["skipped_count"] = skipped_count;
            results["success"] = true;
            return results;
        });
    }

    // Pull/receive ignores from a remote server
    json receive_ignores_from_server(const std::string& origin_server,
                                       const std::string& target_server,
                                       const json& incoming_entries,
                                       const std::string& sync_id = "") {
        return db_.with_write_txn([&](LoggingTransaction& txn) -> json {
            json results;
            results["sync_id"] = sync_id.empty() ?
                generate_sync_id() : sync_id;
            results["received"] = json::array();
            int64_t received_count = 0;
            int64_t conflict_count = 0;

            if (!incoming_entries.is_array()) {
                results["error"] = "Invalid format: expected array";
                results["success"] = false;
                return results;
            }

            for (const auto& incoming : incoming_entries) {
                try {
                    FederationIgnoredUserEntry fed_entry;
                    fed_entry.origin_server = origin_server;
                    fed_entry.target_server = target_server;
                    fed_entry.ignorer_user_id = incoming.value("ignorer_user_id", "");
                    fed_entry.ignored_user_id = incoming.value("ignored_user_id", "");
                    fed_entry.match_type = ignore_match_type_from_str(
                        incoming.value("match_type", "exact"));
                    fed_entry.direction = FederationIgnoreDirection::INBOUND;
                    fed_entry.sync_status = FederationIgnoreSyncStatus::SYNCED;
                    fed_entry.created_ts = now_ms();
                    fed_entry.synced_ts = now_ms();
                    fed_entry.expires_ts = incoming.value("expires_ts", 0);
                    fed_entry.is_active = incoming.value("is_active", true);
                    fed_entry.reason = incoming.value("reason", "");
                    fed_entry.sync_id = results["sync_id"];

                    // Check for conflicts — if we already have an ignore in opposite direction
                    auto existing = txn.select_one(
                        "SELECT id, sync_status, direction FROM ignored_users_federation "
                        "WHERE ignorer_user_id = ? AND ignored_user_id = ? "
                        "AND is_active = 1 AND origin_server = ?",
                        {fed_entry.ignorer_user_id, fed_entry.ignored_user_id,
                         origin_server});

                    if (existing &&
                        existing->get<int64_t>(1) == static_cast<int64_t>(FederationIgnoreSyncStatus::SYNCED)) {
                        if (existing->get<int64_t>(2) !=
                            static_cast<int64_t>(FederationIgnoreDirection::INBOUND)) {
                            conflict_count++;
                            // Update to bidirectional
                            txn.execute(
                                "UPDATE ignored_users_federation SET direction = ? WHERE id = ?",
                                {static_cast<int64_t>(FederationIgnoreDirection::BIDIRECTIONAL),
                                 existing->get<int64_t>(0)});
                            continue;
                        }
                    }

                    int64_t id = store_.add_fed_ignored_user_txn(txn, fed_entry);

                    // Also add locally if needed
                    if (fed_entry.is_active) {
                        try {
                            user_mgr_.add_ignore(
                                fed_entry.ignorer_user_id,
                                fed_entry.ignored_user_id,
                                fed_entry.reason + " [via federation from " +
                                origin_server + "]",
                                ignore_match_type_str(fed_entry.match_type),
                                "block_silently", "drop",
                                fed_entry.expires_ts);
                        } catch (...) {
                            // Local add may fail silently
                        }
                    }

                    json received;
                    received["fed_entry_id"] = id;
                    received["ignorer_user_id"] = fed_entry.ignorer_user_id;
                    received["ignored_user_id"] = fed_entry.ignored_user_id;
                    results["received"].push_back(received);
                    received_count++;
                } catch (const std::exception& e) {
                    json err_entry;
                    err_entry["error"] = e.what();
                    results["received"].push_back(err_entry);
                }
            }

            // Audit
            IgnoreAuditEntry audit;
            audit.action = IgnoreAuditAction::FED_SYNC_PULL;
            audit.actor_user_id = "federation";
            audit.target_user_id = origin_server;
            audit.details = "Received " + std::to_string(received_count) +
                            " ignores from " + origin_server;
            audit.action_ts = now_ms();
            audit.metadata = {
                {"origin_server", origin_server},
                {"received_count", received_count},
                {"conflict_count", conflict_count},
                {"sync_id", results["sync_id"]}
            };
            store_.add_audit_entry_txn(txn, audit);

            results["received_count"] = received_count;
            results["conflict_count"] = conflict_count;
            results["success"] = true;
            return results;
        });
    }

    // Verify a remote ignore claim
    json verify_remote_ignore(const std::string& origin_server,
                               const std::string& ignorer_user_id,
                               const std::string& ignored_user_id) {
        return db_.with_read_txn([&](LoggingTransaction& txn) -> json {
            auto row = txn.select_one(
                "SELECT id, origin_server, sync_status, is_active, reason "
                "FROM ignored_users_federation "
                "WHERE origin_server = ? AND ignorer_user_id = ? "
                "AND ignored_user_id = ? AND is_active = 1 "
                "ORDER BY created_ts DESC LIMIT 1",
                {origin_server, ignorer_user_id, ignored_user_id});

            json result;
            result["ignorer_user_id"] = ignorer_user_id;
            result["ignored_user_id"] = ignored_user_id;
            result["origin_server"] = origin_server;

            if (row) {
                result["exists"] = true;
                result["verified"] = true;
                result["entry_id"] = row->get<int64_t>(0);
                result["sync_status"] = fed_ignore_sync_status_str(
                    static_cast<FederationIgnoreSyncStatus>(
                        row->get<int64_t>(1)));
                result["is_active"] = row->get<int64_t>(2) != 0;
                result["reason"] = row->get<std::string>(3);
            } else {
                result["exists"] = false;
                result["verified"] = false;
            }

            return result;
        });
    }

    // Get federation ignores by origin server
    json get_federation_ignores_by_origin(const std::string& origin_server,
                                             int limit = 500, int offset = 0) {
        return db_.with_read_txn([&](LoggingTransaction& txn) -> json {
            auto entries = store_.get_fed_ignores_by_origin_txn(
                txn, origin_server, limit, offset);

            json result;
            result["origin_server"] = origin_server;
            result["entries"] = json::array();
            for (const auto& e : entries) {
                result["entries"].push_back(e.to_json());
            }
            result["count"] = entries.size();
            return result;
        });
    }

    // Get federation ignores by target server
    json get_federation_ignores_by_target(const std::string& target_server,
                                             int limit = 500, int offset = 0) {
        return db_.with_read_txn([&](LoggingTransaction& txn) -> json {
            auto entries = store_.get_fed_ignores_by_target_txn(
                txn, target_server, limit, offset);

            json result;
            result["target_server"] = target_server;
            result["entries"] = json::array();
            for (const auto& e : entries) {
                result["entries"].push_back(e.to_json());
            }
            result["count"] = entries.size();
            return result;
        });
    }

    // Get pending federation syncs
    json get_pending_syncs(int limit = 100) {
        return db_.with_read_txn([&](LoggingTransaction& txn) -> json {
            auto entries = store_.get_pending_fed_syncs_txn(txn, limit);

            json result;
            result["pending_syncs"] = json::array();
            for (const auto& e : entries) {
                result["pending_syncs"].push_back(e.to_json());
            }
            result["count"] = entries.size();
            return result;
        });
    }

    // Retry failed federation syncs
    json retry_failed_syncs(int max_retries = 5, int limit = 100) {
        return db_.with_write_txn([&](LoggingTransaction& txn) -> json {
            auto entries = store_.get_failed_fed_syncs_txn(
                txn, max_retries, limit);

            int64_t retried = 0;
            for (auto& entry : entries) {
                entry.sync_status = FederationIgnoreSyncStatus::PENDING;
                entry.retry_count++;
                entry.last_retry_ts = now_ms();

                json updates;
                updates["sync_status"] = fed_ignore_sync_status_str(
                    entry.sync_status);
                updates["retry_count"] = entry.retry_count;
                updates["last_retry_ts"] = entry.last_retry_ts;
                store_.update_fed_ignored_user_txn(txn, entry.id, updates);
                retried++;
            }

            json result;
            result["success"] = true;
            result["retried"] = retried;
            result["message"] = "Retried " + std::to_string(retried) +
                                 " failed federation syncs";
            return result;
        });
    }

    // Mark sync as completed
    json mark_sync_completed(const std::string& sync_id) {
        return db_.with_write_txn([&](LoggingTransaction& txn) -> json {
            json updates;
            updates["sync_status"] = "synced";
            updates["synced_ts"] = now_ms();

            txn.execute(
                "UPDATE ignored_users_federation SET sync_status = ?, "
                "synced_ts = ? WHERE sync_id = ?",
                {static_cast<int64_t>(FederationIgnoreSyncStatus::SYNCED),
                 now_ms(), sync_id});

            json result;
            result["success"] = true;
            result["sync_id"] = sync_id;
            result["message"] = "Sync marked as completed";
            return result;
        });
    }

    // Mark sync as failed
    json mark_sync_failed(const std::string& sync_id,
                            const std::string& error_msg = "") {
        return db_.with_write_txn([&](LoggingTransaction& txn) -> json {
            json updates;
            updates["sync_status"] = "failed";
            updates["last_retry_ts"] = now_ms();

            txn.execute(
                "UPDATE ignored_users_federation SET sync_status = ?, "
                "last_retry_ts = ? WHERE sync_id = ?",
                {static_cast<int64_t>(FederationIgnoreSyncStatus::FAILED),
                 now_ms(), sync_id});

            json result;
            result["success"] = true;
            result["sync_id"] = sync_id;
            result["error"] = error_msg;
            return result;
        });
    }

    // Count federation ignores
    json count_federation_ignores(const std::string& server = "",
                                     bool active_only = true) {
        return db_.with_read_txn([&](LoggingTransaction& txn) -> json {
            int64_t count = store_.count_fed_ignores_txn(
                txn, server, active_only);

            json result;
            result["count"] = count;
            result["active_only"] = active_only;
            return result;
        });
    }

    // Handle incoming federation invite rejection
    json handle_federation_invite_rejection(const std::string& requester_server,
                                              const std::string& invitee_user_id,
                                              const std::string& inviter_user_id,
                                              const std::string& room_id) {
        json result;
        result["action"] = "check_ignore_status";

        auto check = user_mgr_.check_ignored(invitee_user_id,
                                              inviter_user_id, room_id);
        result["is_ignored"] = check.is_ignored;

        if (check.is_ignored) {
            result["should_reject"] = true;
            result["rejection_reason"] = "User " + invitee_user_id +
                " has ignored " + inviter_user_id;
            result["policy"] = ignore_invite_policy_str(check.invite_policy);
        } else {
            result["should_reject"] = false;
            result["rejection_reason"] = "";
        }

        // Also check federation-level ignores
        db_.with_read_txn([&](LoggingTransaction& txn) {
            auto fed_ignore = txn.select_one(
                "SELECT id FROM ignored_users_federation "
                "WHERE origin_server = ? AND ignorer_user_id = ? "
                "AND ignored_user_id = ? AND is_active = 1",
                {requester_server, invitee_user_id, inviter_user_id});
            if (fed_ignore) {
                result["federation_ignore_found"] = true;
                result["should_reject"] = true;
                result["rejection_reason"] = "Federation-level ignore policy";
            }
        });

        return result;
    }

    // Sync all local ignores to a target server
    json sync_all_to_server(const std::string& origin_server,
                              const std::string& target_server,
                              const std::string& ignorer_user_id = "") {
        return db_.with_read_txn([&](LoggingTransaction& txn) -> json {
            json result;

            std::vector<IgnoredUserEntry> entries;
            if (ignorer_user_id.empty()) {
                // Get all active ignores from all users - for global sync
                auto rows = txn.select(
                    "SELECT DISTINCT ignorer_user_id FROM ignored_users "
                    "WHERE is_active = 1 AND (expires_ts = 0 OR expires_ts > ?) "
                    "LIMIT 100", {now_ms()});
                for (auto& row : rows) {
                    auto user_entries = store_.get_ignored_users_for_txn(
                        txn, row->get<std::string>(0), 200);
                    entries.insert(entries.end(), user_entries.begin(),
                                   user_entries.end());
                }
            } else {
                entries = store_.get_ignored_users_for_txn(
                    txn, ignorer_user_id);
            }

            result["entries_found"] = entries.size();
            result["target_server"] = target_server;

            // Push the entries
            auto push_result = push_ignores_to_server(
                origin_server, target_server, entries);
            result["push_result"] = push_result;

            return result;
        });
    }

private:
    DatabasePool& db_;
    IgnoredUsersStore store_;
    IgnoredUserManager& user_mgr_;
    IgnoreLogger& logger_;
};

// ============================================================================
// 6. IgnoredUsersAuditor — Audit trail management
// ============================================================================

class IgnoredUsersAuditor {
public:
    explicit IgnoredUsersAuditor(DatabasePool& db, IgnoreLogger& logger)
        : db_(db), store_(db, logger), logger_(logger) {}

    // Get full audit log
    json get_audit_log(int limit = 200, int offset = 0) {
        return db_.with_read_txn([&](LoggingTransaction& txn) -> json {
            auto entries = store_.get_audit_log_txn(txn, limit, offset);

            json result;
            result["audit_entries"] = json::array();
            for (const auto& e : entries) {
                result["audit_entries"].push_back(e.to_json());
            }
            result["count"] = entries.size();
            return result;
        });
    }

    // Get audit log for a specific user
    json get_user_audit_log(const std::string& user_id,
                               int limit = 200, int offset = 0) {
        return db_.with_read_txn([&](LoggingTransaction& txn) -> json {
            auto entries = store_.get_audit_log_for_user_txn(
                txn, user_id, limit, offset);

            json result;
            result["user_id"] = user_id;
            result["audit_entries"] = json::array();
            for (const auto& e : entries) {
                result["audit_entries"].push_back(e.to_json());
            }
            result["count"] = entries.size();
            return result;
        });
    }

    // Get audit log filtered by action type
    json get_audit_log_by_action(const std::string& action_str,
                                    int limit = 200, int offset = 0) {
        IgnoreAuditAction action;
        if (action_str == "ignore_added")    action = IgnoreAuditAction::IGNORE_ADDED;
        else if (action_str == "ignore_removed")  action = IgnoreAuditAction::IGNORE_REMOVED;
        else if (action_str == "invite_blocked")  action = IgnoreAuditAction::INVITE_BLOCKED;
        else if (action_str == "message_dropped") action = IgnoreAuditAction::MESSAGE_DROPPED;
        else if (action_str == "fed_sync_push")   action = IgnoreAuditAction::FED_SYNC_PUSH;
        else if (action_str == "fed_sync_pull")   action = IgnoreAuditAction::FED_SYNC_PULL;
        else if (action_str == "list_imported")   action = IgnoreAuditAction::LIST_IMPORTED;
        else if (action_str == "list_exported")   action = IgnoreAuditAction::LIST_EXPORTED;
        else if (action_str == "bulk_operation")  action = IgnoreAuditAction::BULK_OPERATION;
        else {
            json err;
            err["error"] = "Unknown action: " + action_str;
            return err;
        }

        return db_.with_read_txn([&](LoggingTransaction& txn) -> json {
            auto entries = store_.get_audit_log_by_action_txn(
                txn, action, limit, offset);

            json result;
            result["action"] = action_str;
            result["audit_entries"] = json::array();
            for (const auto& e : entries) {
                result["audit_entries"].push_back(e.to_json());
            }
            result["count"] = entries.size();
            return result;
        });
    }

    // Count total audit entries
    json count_audit_entries(const std::string& user_id = "") {
        return db_.with_read_txn([&](LoggingTransaction& txn) -> json {
            int64_t count = store_.count_audit_entries_txn(txn, user_id);
            json result;
            result["count"] = count;
            return result;
        });
    }

    // Purge old audit entries
    json purge_old_entries(int retention_days = 365) {
        return db_.with_write_txn([&](LoggingTransaction& txn) -> json {
            int64_t cutoff = now_ms() - (retention_days * 86400000LL);
            store_.purge_old_audit_entries_txn(txn, cutoff);

            json result;
            result["success"] = true;
            result["message"] = "Old audit entries purged";
            result["cutoff_age_days"] = retention_days;
            return result;
        });
    }

private:
    DatabasePool& db_;
    IgnoredUsersStore store_;
    IgnoreLogger& logger_;
};

// ============================================================================
// 7. IgnoredUsersImportExport — Import/export ignore lists
// ============================================================================

class IgnoredUsersImportExport {
public:
    explicit IgnoredUsersImportExport(DatabasePool& db,
                                        IgnoredUserManager& user_mgr,
                                        IgnoreLogger& logger)
        : db_(db), store_(db, logger), user_mgr_(user_mgr), logger_(logger) {}

    // Import ignore list from JSON
    json import_from_json(const std::string& ignorer_user_id,
                            const json& data,
                            const std::string& imported_by = "",
                            const std::string& source = "api") {
        return db_.with_write_txn([&](LoggingTransaction& txn) -> json {
            IgnoreImportEntry import_entry;
            import_entry.import_id = generate_import_id();
            import_entry.source_type = "json";
            import_entry.source = source;
            import_entry.imported_by = imported_by.empty() ?
                ignorer_user_id : imported_by;
            import_entry.imported_ts = now_ms();

            int64_t entry_count = 0;
            int64_t error_count = 0;
            std::vector<std::string> errors;

            if (data.is_array()) {
                for (const auto& item : data) {
                    try {
                        IgnoredUserEntry entry;
                        entry.ignorer_user_id = ignorer_user_id;
                        entry.ignored_user_id = item.value("ignored_user_id", "");
                        if (item.contains("match_type")) {
                            entry.match_type = ignore_match_type_from_str(
                                item["match_type"].get<std::string>());
                        }
                        entry.reason = item.value("reason", "");
                        entry.ignored_ts = now_ms();
                        entry.expires_ts = item.value("expires_ts", 0);
                        entry.is_active = item.value("is_active", true);
                        if (item.contains("invite_policy")) {
                            entry.invite_policy = ignore_invite_policy_from_str(
                                item["invite_policy"].get<std::string>());
                        }
                        if (item.contains("message_policy")) {
                            entry.message_policy = ignore_message_policy_from_str(
                                item["message_policy"].get<std::string>());
                        }
                        entry.notes = item.value("notes", "");
                        entry.import_source = import_entry.import_id;

                        store_.add_ignored_user_txn(txn, entry);
                        entry_count++;
                    } catch (const std::exception& e) {
                        errors.push_back(std::string("Error: ") + e.what());
                        error_count++;
                    }
                }
            }

            import_entry.entry_count = static_cast<int>(entry_count);
            import_entry.error_count = static_cast<int>(error_count);
            import_entry.status = error_count > 0 ? "partial" : "completed";
            import_entry.metadata = {
                {"format", "json"},
                {"source", source},
                {"errors", errors}
            };
            store_.create_import_txn(txn, import_entry);

            // Audit
            IgnoreAuditEntry audit;
            audit.action = IgnoreAuditAction::LIST_IMPORTED;
            audit.actor_user_id = ignorer_user_id;
            audit.target_user_id = "";
            audit.details = "Imported " + std::to_string(entry_count) +
                            " entries from JSON";
            audit.action_ts = now_ms();
            audit.metadata = {
                {"import_id", import_entry.import_id},
                {"entry_count", entry_count},
                {"error_count", error_count}
            };
            store_.add_audit_entry_txn(txn, audit);

            json result;
            result["success"] = true;
            result["import_id"] = import_entry.import_id;
            result["entry_count"] = entry_count;
            result["error_count"] = error_count;
            result["errors"] = errors;
            return result;
        });
    }

    // Import ignore list from CSV string
    json import_from_csv(const std::string& ignorer_user_id,
                           const std::string& csv_data,
                           const std::string& imported_by = "",
                           const std::string& source = "csv_upload") {
        return db_.with_write_txn([&](LoggingTransaction& txn) -> json {
            IgnoreImportEntry import_entry;
            import_entry.import_id = generate_import_id();
            import_entry.source_type = "csv";
            import_entry.source = source;
            import_entry.imported_by = imported_by.empty() ?
                ignorer_user_id : imported_by;
            import_entry.imported_ts = now_ms();

            int64_t entry_count = 0;
            int64_t error_count = 0;
            std::vector<std::string> errors;

            std::istringstream stream(csv_data);
            std::string line;
            bool header_skipped = false;

            while (std::getline(stream, line)) {
                line = trim(line);
                if (line.empty()) continue;

                // Skip header line
                if (!header_skipped &&
                    (starts_with(to_lower(line), "ignored_user_id") ||
                     starts_with(to_lower(line), "user_id"))) {
                    header_skipped = true;
                    continue;
                }

                header_skipped = true;

                try {
                    auto parts = split(line, ',');
                    if (parts.empty()) {
                        error_count++;
                        errors.push_back("Empty line");
                        continue;
                    }

                    IgnoredUserEntry entry;
                    entry.ignorer_user_id = ignorer_user_id;
                    entry.ignored_user_id = trim(parts[0]);
                    entry.reason = parts.size() > 1 ? trim(parts[1]) : "";
                    entry.ignored_ts = now_ms();
                    entry.is_active = true;
                    if (parts.size() > 2) {
                        entry.invite_policy = ignore_invite_policy_from_str(
                            trim(parts[2]));
                    }
                    if (parts.size() > 3) {
                        entry.message_policy = ignore_message_policy_from_str(
                            trim(parts[3]));
                    }
                    entry.import_source = import_entry.import_id;

                    store_.add_ignored_user_txn(txn, entry);
                    entry_count++;
                } catch (const std::exception& e) {
                    errors.push_back("Line error: " + std::string(e.what()));
                    error_count++;
                }
            }

            import_entry.entry_count = static_cast<int>(entry_count);
            import_entry.error_count = static_cast<int>(error_count);
            import_entry.status = error_count > 0 ? "partial" : "completed";
            import_entry.metadata = {
                {"format", "csv"},
                {"source", source},
                {"errors", errors}
            };
            store_.create_import_txn(txn, import_entry);

            IgnoreAuditEntry audit;
            audit.action = IgnoreAuditAction::LIST_IMPORTED;
            audit.actor_user_id = ignorer_user_id;
            audit.target_user_id = "";
            audit.details = "Imported " + std::to_string(entry_count) +
                            " entries from CSV";
            audit.action_ts = now_ms();
            audit.metadata = {
                {"import_id", import_entry.import_id},
                {"entry_count", entry_count},
                {"error_count", error_count}
            };
            store_.add_audit_entry_txn(txn, audit);

            json result;
            result["success"] = true;
            result["import_id"] = import_entry.import_id;
            result["entry_count"] = entry_count;
            result["error_count"] = error_count;
            result["errors"] = errors;
            return result;
        });
    }

    // Export ignore list to JSON
    json export_to_json(const std::string& ignorer_user_id,
                           bool active_only = true) {
        return db_.with_read_txn([&](LoggingTransaction& txn) -> json {
            std::vector<IgnoredUserEntry> entries;
            if (active_only) {
                entries = store_.get_ignored_users_for_txn(
                    txn, ignorer_user_id);
            } else {
                entries = store_.get_all_ignored_users_for_txn(
                    txn, ignorer_user_id);
            }

            json result;
            result["ignorer_user_id"] = ignorer_user_id;
            result["exported_ts"] = now_ms();
            result["total_count"] = entries.size();
            result["active_only"] = active_only;
            result["ignored_users"] = json::array();
            for (const auto& entry : entries) {
                result["ignored_users"].push_back(entry.to_json());
            }

            // Audit the export
            db_.with_write_txn([&](LoggingTransaction& txn_write) {
                IgnoreAuditEntry audit;
                audit.action = IgnoreAuditAction::LIST_EXPORTED;
                audit.actor_user_id = ignorer_user_id;
                audit.target_user_id = "";
                audit.details = "Exported " + std::to_string(entries.size()) +
                                " entries to JSON";
                audit.action_ts = now_ms();
                audit.metadata = {
                    {"exported_count", entries.size()},
                    {"active_only", active_only}
                };
                // We need a write store for the audit
                IgnoredUsersStore write_store(db_, logger_);
                write_store.add_audit_entry_txn(txn_write, audit);
            });

            return result;
        });
    }

    // Export ignore list to CSV string
    json export_to_csv(const std::string& ignorer_user_id,
                         bool active_only = true) {
        return db_.with_read_txn([&](LoggingTransaction& txn) -> json {
            std::vector<IgnoredUserEntry> entries;
            if (active_only) {
                entries = store_.get_ignored_users_for_txn(
                    txn, ignorer_user_id);
            } else {
                entries = store_.get_all_ignored_users_for_txn(
                    txn, ignorer_user_id);
            }

            std::string csv = "ignored_user_id,reason,invite_policy,message_policy,ignored_ts,expires_ts,notes\n";
            for (const auto& entry : entries) {
                csv += entry.ignored_user_id + ",";
                csv += "\"" + entry.reason + "\",";
                csv + ignore_invite_policy_str(entry.invite_policy);
                csv += "," + ignore_message_policy_str(entry.message_policy);
                csv += "," + std::to_string(entry.ignored_ts);
                csv += "," + std::to_string(entry.expires_ts);
                csv += ",\"" + entry.notes + "\"\n";
            }

            json result;
            result["ignorer_user_id"] = ignorer_user_id;
            result["format"] = "csv";
            result["total_count"] = entries.size();
            result["active_only"] = active_only;
            result["csv_data"] = csv;

            return result;
        });
    }

    // Get import history
    json get_import_history(int limit = 100, int offset = 0) {
        return db_.with_read_txn([&](LoggingTransaction& txn) -> json {
            auto imports = store_.get_imports_txn(txn, limit, offset);

            json result;
            result["imports"] = json::array();
            for (const auto& imp : imports) {
                result["imports"].push_back(imp.to_json());
            }
            result["count"] = imports.size();
            return result;
        });
    }

    // Get a specific import
    json get_import(const std::string& import_id) {
        return db_.with_read_txn([&](LoggingTransaction& txn) -> json {
            auto imp = store_.get_import_txn(txn, import_id);
            if (!imp) {
                json err;
                err["error"] = "Import not found";
                return err;
            }
            return imp->to_json();
        });
    }

private:
    DatabasePool& db_;
    IgnoredUsersStore store_;
    IgnoredUserManager& user_mgr_;
    IgnoreLogger& logger_;
};

// ============================================================================
// 8. IgnoredUsersMetrics — Metrics and statistics
// ============================================================================

class IgnoredUsersMetrics {
public:
    explicit IgnoredUsersMetrics(DatabasePool& db, IgnoreLogger& logger)
        : db_(db), store_(db, logger), logger_(logger) {}

    // Get full statistics
    json get_stats() {
        return db_.with_read_txn([&](LoggingTransaction& txn) -> json {
            auto stats = store_.get_stats_txn(txn);
            return stats.to_json();
        });
    }

    // Get top ignored users (most ignored)
    json get_top_ignored_users(int limit = 20) {
        return db_.with_read_txn([&](LoggingTransaction& txn) -> json {
            auto rows = txn.select(
                "SELECT ignored_user_id, COUNT(*) as ignore_count "
                "FROM ignored_users WHERE is_active = 1 AND match_type = 0 "
                "AND (expires_ts = 0 OR expires_ts > ?) "
                "GROUP BY ignored_user_id ORDER BY ignore_count DESC LIMIT ?",
                {now_ms(), limit});

            json result;
            result["top_ignored"] = json::array();
            for (auto& row : rows) {
                json entry;
                entry["user_id"] = row->get<std::string>(0);
                entry["ignore_count"] = row->get<int64_t>(1);
                result["top_ignored"].push_back(entry);
            }
            result["count"] = rows.size();
            return result;
        });
    }

    // Get top ignorers (users who ignore the most)
    json get_top_ignorers(int limit = 20) {
        return db_.with_read_txn([&](LoggingTransaction& txn) -> json {
            auto rows = txn.select(
                "SELECT ignorer_user_id, COUNT(*) as ignore_count "
                "FROM ignored_users WHERE is_active = 1 "
                "AND (expires_ts = 0 OR expires_ts > ?) "
                "GROUP BY ignorer_user_id ORDER BY ignore_count DESC LIMIT ?",
                {now_ms(), limit});

            json result;
            result["top_ignorers"] = json::array();
            for (auto& row : rows) {
                json entry;
                entry["user_id"] = row->get<std::string>(0);
                entry["ignore_count"] = row->get<int64_t>(1);
                result["top_ignorers"].push_back(entry);
            }
            result["count"] = rows.size();
            return result;
        });
    }

    // Get invite block statistics
    json get_invite_block_stats() {
        return db_.with_read_txn([&](LoggingTransaction& txn) -> json {
            auto row = txn.select_one(
                "SELECT COUNT(*) FROM ignored_users_invites");
            int64_t total = row ? row->get<int64_t>(0) : 0;

            auto row2 = txn.select_one(
                "SELECT COUNT(*) FROM ignored_users_invites "
                "WHERE blocked_ts > ?",
                {now_ms() - 86400000}); // last 24h
            int64_t last_24h = row2 ? row2->get<int64_t>(0) : 0;

            auto row3 = txn.select_one(
                "SELECT COUNT(*) FROM ignored_users_invites "
                "WHERE notified = 1");
            int64_t notified = row3 ? row3->get<int64_t>(0) : 0;

            json result;
            result["total_blocked"] = total;
            result["blocked_last_24h"] = last_24h;
            result["notifications_sent"] = notified;
            return result;
        });
    }

    // Get message filter statistics
    json get_message_filter_stats() {
        return db_.with_read_txn([&](LoggingTransaction& txn) -> json {
            auto row = txn.select_one(
                "SELECT COUNT(*) FROM ignored_users_messages");
            int64_t total = row ? row->get<int64_t>(0) : 0;

            auto row2 = txn.select_one(
                "SELECT COUNT(*) FROM ignored_users_messages "
                "WHERE action = 0");
            int64_t dropped = row2 ? row2->get<int64_t>(0) : 0;

            auto row3 = txn.select_one(
                "SELECT COUNT(*) FROM ignored_users_messages "
                "WHERE action = 1");
            int64_t quarantined = row3 ? row3->get<int64_t>(0) : 0;

            auto row4 = txn.select_one(
                "SELECT COUNT(*) FROM ignored_users_messages "
                "WHERE action = 2");
            int64_t flagged = row4 ? row4->get<int64_t>(0) : 0;

            json result;
            result["total_filtered"] = total;
            result["dropped"] = dropped;
            result["quarantined"] = quarantined;
            result["flagged"] = flagged;
            return result;
        });
    }

    // Get federation sync stats
    json get_federation_stats() {
        return db_.with_read_txn([&](LoggingTransaction& txn) -> json {
            auto row = txn.select_one(
                "SELECT COUNT(*) FROM ignored_users_federation");
            int64_t total = row ? row->get<int64_t>(0) : 0;

            auto row2 = txn.select_one(
                "SELECT COUNT(*) FROM ignored_users_federation "
                "WHERE sync_status = 0");
            int64_t pending = row2 ? row2->get<int64_t>(0) : 0;

            auto row3 = txn.select_one(
                "SELECT COUNT(*) FROM ignored_users_federation "
                "WHERE sync_status = 2");
            int64_t synced = row3 ? row3->get<int64_t>(0) : 0;

            auto row4 = txn.select_one(
                "SELECT COUNT(*) FROM ignored_users_federation "
                "WHERE sync_status = 3");
            int64_t failed = row4 ? row4->get<int64_t>(0) : 0;

            json result;
            result["total_fed_entries"] = total;
            result["pending"] = pending;
            result["synced"] = synced;
            result["failed"] = failed;
            return result;
        });
    }

    // Get match type distribution
    json get_match_type_distribution() {
        return db_.with_read_txn([&](LoggingTransaction& txn) -> json {
            auto rows = txn.select(
                "SELECT match_type, COUNT(*) as cnt FROM ignored_users "
                "WHERE is_active = 1 "
                "GROUP BY match_type ORDER BY cnt DESC");

            json result;
            result["distribution"] = json::object();
            for (auto& row : rows) {
                auto mt = static_cast<IgnoreMatchType>(row->get<int64_t>(0));
                result["distribution"][ignore_match_type_str(mt)] =
                    row->get<int64_t>(1);
            }
            return result;
        });
    }

    // Periodic maintenance
    void periodic_maintenance() {
        db_.with_write_txn([&](LoggingTransaction& txn) {
            store_.delete_all_expired_txn(txn);
        });
        logger_.debug("Periodic ignored users maintenance completed");
    }

private:
    DatabasePool& db_;
    IgnoredUsersStore store_;
    IgnoreLogger& logger_;
};

// ============================================================================
// 9. IgnoredUsersCoordinator — Top-level coordinator
// ============================================================================

class IgnoredUsersCoordinator {
public:
    explicit IgnoredUsersCoordinator(DatabasePool& db)
        : db_(db), logger_("IgnoredUsersCoordinator"),
          store_(db, logger_),
          user_mgr_(db, logger_),
          invite_blocker_(db, user_mgr_, logger_),
          message_filter_(db, user_mgr_, logger_),
          fed_ignores_(db, user_mgr_, logger_),
          auditor_(db, logger_),
          import_export_(db, user_mgr_, logger_),
          metrics_(db, logger_) {}

    // Initialize all tables
    void initialize_tables() {
        db_.with_write_txn([&](LoggingTransaction& txn) {
            IgnoredUsersStore::create_tables(txn);
        });
        logger_.info("Ignored users tables initialized");
    }

    // ---------- User Ignore Management ----------

    json add_ignore(const std::string& ignorer_user_id,
                     const std::string& ignored_user_id,
                     const std::string& reason = "",
                     const std::string& match_type_str = "exact",
                     const std::string& invite_policy_str = "block_silently",
                     const std::string& message_policy_str = "drop",
                     int64_t expires_ts = 0,
                     const std::string& notes = "",
                     const std::string& ip_address = "") {
        return user_mgr_.add_ignore(ignorer_user_id, ignored_user_id,
                                      reason, match_type_str,
                                      invite_policy_str, message_policy_str,
                                      expires_ts, notes, ip_address);
    }

    json remove_ignore(const std::string& ignorer_user_id,
                        const std::string& ignored_user_id,
                        const std::string& ip_address = "") {
        return user_mgr_.remove_ignore(ignorer_user_id, ignored_user_id,
                                        ip_address);
    }

    json remove_ignore_by_id(int64_t entry_id,
                               const std::string& actor_user_id = "") {
        return user_mgr_.remove_ignore_by_id(entry_id, actor_user_id);
    }

    json delete_ignore(int64_t entry_id) {
        return user_mgr_.delete_ignore(entry_id);
    }

    json update_ignore(int64_t entry_id, const json& updates) {
        return user_mgr_.update_ignore(entry_id, updates);
    }

    json check_ignored(const std::string& ignorer_user_id,
                        const std::string& target_user_id,
                        const std::string& room_id = "") {
        auto result = user_mgr_.check_ignored(ignorer_user_id,
                                                target_user_id, room_id);
        return result.to_json();
    }

    json list_ignored_users(const std::string& ignorer_user_id,
                              bool active_only = true,
                              int limit = 500, int offset = 0) {
        return user_mgr_.list_ignored_users(ignorer_user_id, active_only,
                                              limit, offset);
    }

    json search_ignored_users(const std::string& ignorer_user_id,
                               const std::string& search_pattern,
                               int limit = 500, int offset = 0) {
        return user_mgr_.search_ignored_users(ignorer_user_id,
                                                search_pattern, limit, offset);
    }

    json get_ignore_entry(int64_t entry_id) {
        return user_mgr_.get_ignore_entry(entry_id);
    }

    json get_ignorers(const std::string& ignored_user_id,
                        int limit = 500, int offset = 0) {
        return user_mgr_.get_ignorers(ignored_user_id, limit, offset);
    }

    json bulk_add_ignores(const std::string& ignorer_user_id,
                            const std::vector<std::string>& user_ids,
                            const std::string& reason = "",
                            const std::string& invite_policy_str = "block_silently",
                            const std::string& message_policy_str = "drop") {
        return user_mgr_.bulk_add_ignores(ignorer_user_id, user_ids,
                                            reason, invite_policy_str,
                                            message_policy_str);
    }

    json bulk_remove_ignores(const std::string& ignorer_user_id,
                               const std::vector<std::string>& user_ids) {
        return user_mgr_.bulk_remove_ignores(ignorer_user_id, user_ids);
    }

    json count_ignored(const std::string& ignorer_user_id,
                         bool active_only = true) {
        return user_mgr_.count_ignored(ignorer_user_id, active_only);
    }

    json toggle_ignore(int64_t entry_id, bool activate) {
        return user_mgr_.toggle_ignore(entry_id, activate);
    }

    // ---------- Room Overrides ----------

    json set_room_override(const std::string& ignorer_user_id,
                             const std::string& ignored_user_id,
                             const std::string& room_id,
                             bool allow_messages,
                             bool allow_invites,
                             const std::string& reason = "",
                             int64_t expires_ts = 0) {
        return user_mgr_.set_room_override(ignorer_user_id, ignored_user_id,
                                             room_id, allow_messages,
                                             allow_invites, reason, expires_ts);
    }

    json remove_room_override(int64_t override_id) {
        return user_mgr_.remove_room_override(override_id);
    }

    json get_room_overrides(const std::string& ignorer_user_id,
                              int limit = 200, int offset = 0) {
        return user_mgr_.get_room_overrides(ignorer_user_id, limit, offset);
    }

    // ---------- Invite Blocking ----------

    json check_and_block_invite(const std::string& inviter_user_id,
                                  const std::string& invitee_user_id,
                                  const std::string& room_id,
                                  const std::string& event_id = "",
                                  const std::string& ip_address = "") {
        return invite_blocker_.check_and_block_invite(
            inviter_user_id, invitee_user_id, room_id, event_id, ip_address);
    }

    json get_blocked_invites(const std::string& user_id,
                               int limit = 200, int offset = 0) {
        return invite_blocker_.get_blocked_invites(user_id, limit, offset);
    }

    json get_invites_blocked_for_user(const std::string& user_id,
                                        int limit = 200, int offset = 0) {
        return invite_blocker_.get_invites_blocked_for_user(
            user_id, limit, offset);
    }

    json get_room_blocked_invites(const std::string& room_id,
                                    int limit = 200, int offset = 0) {
        return invite_blocker_.get_room_blocked_invites(room_id, limit, offset);
    }

    json count_blocked_invites(const std::string& user_id = "") {
        return invite_blocker_.count_blocked_invites(user_id);
    }

    json purge_old_invites(int retention_days = 90) {
        return invite_blocker_.purge_old_invites(retention_days);
    }

    // ---------- Message Filtering ----------

    json filter_message(const std::string& sender_user_id,
                          const std::string& recipient_user_id,
                          const std::string& room_id,
                          const std::string& event_id,
                          const std::string& event_type,
                          bool is_mention = false) {
        return message_filter_.filter_message(
            sender_user_id, recipient_user_id, room_id,
            event_id, event_type, is_mention);
    }

    json get_filtered_messages(const std::string& user_id,
                                 int limit = 200, int offset = 0) {
        return message_filter_.get_filtered_messages(user_id, limit, offset);
    }

    json get_filtered_by_user(const std::string& ignored_user_id,
                                int limit = 200, int offset = 0) {
        return message_filter_.get_filtered_by_user(
            ignored_user_id, limit, offset);
    }

    json get_filtered_for_room(const std::string& room_id,
                                 int limit = 200, int offset = 0) {
        return message_filter_.get_filtered_for_room(room_id, limit, offset);
    }

    json get_quarantined_message(const std::string& quarantine_id) {
        return message_filter_.get_quarantined_message(quarantine_id);
    }

    json count_filtered_messages(const std::string& user_id = "") {
        return message_filter_.count_filtered_messages(user_id);
    }

    json purge_old_filtered_messages(int retention_days = 90) {
        return message_filter_.purge_old_messages(retention_days);
    }

    json should_filter_event(const std::string& sender_user_id,
                               const std::string& recipient_user_id,
                               const std::string& room_id,
                               const std::string& event_type) {
        return message_filter_.should_filter_event(
            sender_user_id, recipient_user_id, room_id, event_type);
    }

    // ---------- Federation Handling ----------

    json push_ignores_to_server(const std::string& origin_server,
                                  const std::string& target_server,
                                  const std::vector<IgnoredUserEntry>& entries,
                                  const std::string& reason = "") {
        return fed_ignores_.push_ignores_to_server(
            origin_server, target_server, entries, reason);
    }

    json receive_ignores_from_server(const std::string& origin_server,
                                       const std::string& target_server,
                                       const json& incoming_entries,
                                       const std::string& sync_id = "") {
        return fed_ignores_.receive_ignores_from_server(
            origin_server, target_server, incoming_entries, sync_id);
    }

    json verify_remote_ignore(const std::string& origin_server,
                               const std::string& ignorer_user_id,
                               const std::string& ignored_user_id) {
        return fed_ignores_.verify_remote_ignore(
            origin_server, ignorer_user_id, ignored_user_id);
    }

    json get_federation_ignores_by_origin(const std::string& origin_server,
                                             int limit = 500, int offset = 0) {
        return fed_ignores_.get_federation_ignores_by_origin(
            origin_server, limit, offset);
    }

    json get_federation_ignores_by_target(const std::string& target_server,
                                             int limit = 500, int offset = 0) {
        return fed_ignores_.get_federation_ignores_by_target(
            target_server, limit, offset);
    }

    json get_pending_fed_syncs(int limit = 100) {
        return fed_ignores_.get_pending_syncs(limit);
    }

    json retry_failed_fed_syncs(int max_retries = 5, int limit = 100) {
        return fed_ignores_.retry_failed_syncs(max_retries, limit);
    }

    json mark_fed_sync_completed(const std::string& sync_id) {
        return fed_ignores_.mark_sync_completed(sync_id);
    }

    json mark_fed_sync_failed(const std::string& sync_id,
                                const std::string& error_msg = "") {
        return fed_ignores_.mark_sync_failed(sync_id, error_msg);
    }

    json handle_federation_invite_rejection(const std::string& requester_server,
                                              const std::string& invitee_user_id,
                                              const std::string& inviter_user_id,
                                              const std::string& room_id) {
        return fed_ignores_.handle_federation_invite_rejection(
            requester_server, invitee_user_id, inviter_user_id, room_id);
    }

    json sync_all_to_server(const std::string& origin_server,
                              const std::string& target_server,
                              const std::string& ignorer_user_id = "") {
        return fed_ignores_.sync_all_to_server(
            origin_server, target_server, ignorer_user_id);
    }

    json count_federation_ignores(const std::string& server = "",
                                     bool active_only = true) {
        return fed_ignores_.count_federation_ignores(server, active_only);
    }

    // ---------- Audit ----------

    json get_audit_log(int limit = 200, int offset = 0) {
        return auditor_.get_audit_log(limit, offset);
    }

    json get_user_audit_log(const std::string& user_id,
                               int limit = 200, int offset = 0) {
        return auditor_.get_user_audit_log(user_id, limit, offset);
    }

    json get_audit_log_by_action(const std::string& action_str,
                                    int limit = 200, int offset = 0) {
        return auditor_.get_audit_log_by_action(action_str, limit, offset);
    }

    json count_audit_entries(const std::string& user_id = "") {
        return auditor_.count_audit_entries(user_id);
    }

    json purge_old_audit_entries(int retention_days = 365) {
        return auditor_.purge_old_entries(retention_days);
    }

    // ---------- Import/Export ----------

    json import_from_json(const std::string& ignorer_user_id,
                            const json& data,
                            const std::string& imported_by = "",
                            const std::string& source = "api") {
        return import_export_.import_from_json(
            ignorer_user_id, data, imported_by, source);
    }

    json import_from_csv(const std::string& ignorer_user_id,
                           const std::string& csv_data,
                           const std::string& imported_by = "",
                           const std::string& source = "csv_upload") {
        return import_export_.import_from_csv(
            ignorer_user_id, csv_data, imported_by, source);
    }

    json export_to_json(const std::string& ignorer_user_id,
                           bool active_only = true) {
        return import_export_.export_to_json(ignorer_user_id, active_only);
    }

    json export_to_csv(const std::string& ignorer_user_id,
                         bool active_only = true) {
        return import_export_.export_to_csv(ignorer_user_id, active_only);
    }

    json get_import_history(int limit = 100, int offset = 0) {
        return import_export_.get_import_history(limit, offset);
    }

    json get_import(const std::string& import_id) {
        return import_export_.get_import(import_id);
    }

    // ---------- Statistics ----------

    json get_stats() {
        return metrics_.get_stats();
    }

    json get_top_ignored_users(int limit = 20) {
        return metrics_.get_top_ignored_users(limit);
    }

    json get_top_ignorers(int limit = 20) {
        return metrics_.get_top_ignorers(limit);
    }

    json get_invite_block_stats() {
        return metrics_.get_invite_block_stats();
    }

    json get_message_filter_stats() {
        return metrics_.get_message_filter_stats();
    }

    json get_federation_stats() {
        return metrics_.get_federation_stats();
    }

    json get_match_type_distribution() {
        return metrics_.get_match_type_distribution();
    }

    // ---------- Maintenance ----------

    json cleanup_expired() {
        return user_mgr_.cleanup_expired();
    }

    json cleanup_all() {
        db_.with_write_txn([&](LoggingTransaction& txn) {
            store_.delete_all_expired_txn(txn);
        });
        json result;
        result["success"] = true;
        result["message"] = "All expired entries cleaned up";
        return result;
    }

    void periodic_maintenance() {
        metrics_.periodic_maintenance();
    }

    // Full context check — checks all ignore dimensions for a user pair
    json full_context_check(const std::string& ignorer_user_id,
                             const std::string& target_user_id,
                             const std::string& room_id = "",
                             const std::string& event_type = "",
                             bool is_mention = false) {
        json result;
        result["checked_ts"] = now_ms();
        result["ignorer"] = ignorer_user_id;
        result["target"] = target_user_id;

        // Basic ignore check
        auto check = user_mgr_.check_ignored(ignorer_user_id,
                                              target_user_id, room_id);
        result["ignore_check"] = check.to_json();

        // Invite blocking status
        result["invite_policy"] = ignore_invite_policy_str(check.invite_policy);

        // Message filtering status
        if (!event_type.empty()) {
            auto filter_result = message_filter_.should_filter_event(
                target_user_id, ignorer_user_id, room_id, event_type);
            result["message_filter"] = filter_result;
        }

        // Room overrides
        result["has_room_override"] = check.has_room_override;
        if (check.has_room_override) {
            result["room_override"] = check.room_override.to_json();
        }

        return result;
    }

private:
    DatabasePool& db_;
    IgnoreLogger logger_;
    IgnoredUsersStore store_;
    IgnoredUserManager user_mgr_;
    InviteBlocker invite_blocker_;
    MessageFilter message_filter_;
    FederationIgnoredUsers fed_ignores_;
    IgnoredUsersAuditor auditor_;
    IgnoredUsersImportExport import_export_;
    IgnoredUsersMetrics metrics_;
};

} // namespace progressive
