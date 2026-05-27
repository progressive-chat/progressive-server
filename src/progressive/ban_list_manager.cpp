// ============================================================================
// ban_list_manager.cpp — Matrix Server Ban List Management
//
// Comprehensive ban list system for the Matrix server:
//   - Server-wide Ban Lists: Block entire servers by name, domain suffix,
//     glob pattern, TLS fingerprint. Soft/hard/read-only blocking levels.
//   - IP Ban Lists: Block by single IP, CIDR range, IP range. IPv4 and
//     IPv6 support. Efficient CIDR trie matching.
//   - User Ban Lists: Ban user IDs by exact match, domain pattern, or
//     wildcard. Shadow ban (silently ignore) support.
//   - Per-Room Ban Lists: Room-specific bans on servers, users, IPs.
//     Per-room override of server-wide bans.
//   - Import/Export: Import ban lists from JSON, CSV, or Matrix ban list
//     room format (m.room.server_acl, m.policy.rule.user, etc.).
//     Export to JSON, CSV, or Matrix spec format.
//   - Ban Synchronization: Sync ban lists across federation or cluster
//     nodes. Subscribe to remote ban list rooms. Push local changes
//     to remote replicas. Conflict resolution.
//   - Federation Enforcement: Check bans on every incoming federation
//     transaction, PDU, EDU, invite, join, and query. Block at edge.
//     Per-action granularity. Log all enforcement decisions.
//
// SQL: All operations fully SQL-backed with proper indexing, no ORM.
//   Tables: server_bans, ip_bans, user_bans, room_bans,
//           ban_list_imports, ban_list_entries, ban_sync_log,
//           ban_enforcement_log, ban_list_subscriptions, ban_overrides
//
// Equivalent to:
//   synapse/handlers/admin.py (ban enforcement portions)
//   synapse/federation/federation_server.py (federation ban checks)
//   synapse/storage/databases/main/room.py (ACL storage)
//   matrix-org/matrix-spec-proposals/proposals/2313-ban-lists.md (MSC2313)
//   matrix-org/matrix-doc/proposals/3215-moderation-policies.md (MSC3215)
//   synapse/handlers/room_member.py (invite ban checks)
//
// Target: 3000+ lines of production-grade C++.
// Namespace: progressive::
// ============================================================================

#include <algorithm>
#include <atomic>
#include <array>
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
class BanListStore;
class ServerBanListManager;
class IPBanListManager;
class UserBanListManager;
class PerRoomBanListManager;
class BanListImporter;
class BanListExporter;
class BanSynchronizer;
class FederationBanEnforcer;
class BanListMetricsCollector;
class BanListManager;

// ============================================================================
// Enums and Constants
// ============================================================================

// The type of entity being banned
enum class BanEntityType : uint8_t {
    SERVER    = 0,  // Server name / domain
    USER      = 1,  // Matrix user ID
    IP        = 2,  // IP address or CIDR
    ROOM      = 3,  // Room ID (for room-level policy)
    FINGERPRINT = 4 // TLS certificate fingerprint
};

const char* ban_entity_type_str(BanEntityType t) {
    switch (t) {
        case BanEntityType::SERVER:     return "server";
        case BanEntityType::USER:       return "user";
        case BanEntityType::IP:         return "ip";
        case BanEntityType::ROOM:       return "room";
        case BanEntityType::FINGERPRINT: return "fingerprint";
        default:                        return "unknown";
    }
}

BanEntityType ban_entity_type_from_str(const std::string& s) {
    if (s == "server")     return BanEntityType::SERVER;
    if (s == "user")       return BanEntityType::USER;
    if (s == "ip")         return BanEntityType::IP;
    if (s == "room")       return BanEntityType::ROOM;
    if (s == "fingerprint") return BanEntityType::FINGERPRINT;
    throw std::invalid_argument("Unknown ban entity type: " + s);
}

// Severity / level of a ban
enum class BanLevel : uint8_t {
    WARN      = 0,  // Log only, don't block
    SOFT      = 1,  // Block new interactions, allow existing
    HARD      = 2,  // Block all traffic
    QUARANTINE = 3, // Isolate completely
    SHADOW    = 4   // Silently ignore (shadow ban)
};

const char* ban_level_str(BanLevel l) {
    switch (l) {
        case BanLevel::WARN:       return "warn";
        case BanLevel::SOFT:       return "soft";
        case BanLevel::HARD:       return "hard";
        case BanLevel::QUARANTINE: return "quarantine";
        case BanLevel::SHADOW:     return "shadow";
        default:                   return "unknown";
    }
}

BanLevel ban_level_from_str(const std::string& s) {
    if (s == "warn")       return BanLevel::WARN;
    if (s == "soft")       return BanLevel::SOFT;
    if (s == "hard")       return BanLevel::HARD;
    if (s == "quarantine") return BanLevel::QUARANTINE;
    if (s == "shadow")     return BanLevel::SHADOW;
    return BanLevel::HARD;
}

// Result of a ban check
enum class BanCheckResult : uint8_t {
    ALLOWED          = 0,  // Not banned
    BANNED_SERVER    = 1,  // Server is banned
    BANNED_USER      = 2,  // User is banned
    BANNED_IP        = 3,  // IP is banned
    BANNED_ROOM      = 4,  // Room policy bans this
    BANNED_FINGERPRINT = 5, // TLS fingerprint banned
    ERROR            = 6   // Error during check
};

const char* ban_check_result_str(BanCheckResult r) {
    switch (r) {
        case BanCheckResult::ALLOWED:           return "allowed";
        case BanCheckResult::BANNED_SERVER:     return "banned_server";
        case BanCheckResult::BANNED_USER:       return "banned_user";
        case BanCheckResult::BANNED_IP:         return "banned_ip";
        case BanCheckResult::BANNED_ROOM:       return "banned_room";
        case BanCheckResult::BANNED_FINGERPRINT: return "banned_fingerprint";
        case BanCheckResult::ERROR:             return "error";
        default:                                 return "unknown";
    }
}

// Import source type
enum class ImportSourceType : uint8_t {
    JSON_FILE     = 0,
    CSV_FILE       = 1,
    MATRIX_ROOM    = 2,  // m.policy.rule.* events
    REMOTE_URL     = 3,
    FEDERATION     = 4,
    MANUAL         = 5
};

const char* import_source_type_str(ImportSourceType t) {
    switch (t) {
        case ImportSourceType::JSON_FILE:   return "json_file";
        case ImportSourceType::CSV_FILE:     return "csv_file";
        case ImportSourceType::MATRIX_ROOM:  return "matrix_room";
        case ImportSourceType::REMOTE_URL:   return "remote_url";
        case ImportSourceType::FEDERATION:   return "federation";
        case ImportSourceType::MANUAL:       return "manual";
        default:                             return "unknown";
    }
}

// Sync status for ban synchronization
enum class SyncStatus : uint8_t {
    PENDING    = 0,
    IN_PROGRESS = 1,
    COMPLETED  = 2,
    FAILED     = 3,
    CONFLICT   = 4
};

const char* sync_status_str(SyncStatus s) {
    switch (s) {
        case SyncStatus::PENDING:     return "pending";
        case SyncStatus::IN_PROGRESS: return "in_progress";
        case SyncStatus::COMPLETED:   return "completed";
        case SyncStatus::FAILED:      return "failed";
        case SyncStatus::CONFLICT:    return "conflict";
        default:                      return "unknown";
    }
}

// Federation action being enforced
enum class FederationAction : uint8_t {
    SEND_TRANSACTION   = 0,
    QUERY_PROFILE      = 1,
    MAKE_JOIN          = 2,
    SEND_JOIN          = 3,
    SEND_LEAVE         = 4,
    INVITE             = 5,
    GET_MISSING_EVENTS = 6,
    BACKFILL           = 7,
    GET_STATE          = 8,
    GET_EVENT          = 9,
    GET_ROOM_ALIAS     = 10,
    QUERY_AUTH         = 11,
    GET_KEYS           = 12,
    CLAIM_KEYS         = 13,
    QUERY_DIRECTORY    = 14
};

const char* federation_action_str(FederationAction a) {
    switch (a) {
        case FederationAction::SEND_TRANSACTION:   return "send_transaction";
        case FederationAction::QUERY_PROFILE:      return "query_profile";
        case FederationAction::MAKE_JOIN:          return "make_join";
        case FederationAction::SEND_JOIN:          return "send_join";
        case FederationAction::SEND_LEAVE:         return "send_leave";
        case FederationAction::INVITE:             return "invite";
        case FederationAction::GET_MISSING_EVENTS: return "get_missing_events";
        case FederationAction::BACKFILL:           return "backfill";
        case FederationAction::GET_STATE:          return "get_state";
        case FederationAction::GET_EVENT:          return "get_event";
        case FederationAction::GET_ROOM_ALIAS:     return "get_room_alias";
        case FederationAction::QUERY_AUTH:         return "query_auth";
        case FederationAction::GET_KEYS:           return "get_keys";
        case FederationAction::CLAIM_KEYS:          return "claim_keys";
        case FederationAction::QUERY_DIRECTORY:    return "query_directory";
        default:                                   return "unknown";
    }
}

// Match type for ban patterns
enum class MatchType : uint8_t {
    EXACT         = 0,
    DOMAIN_SUFFIX = 1,
    GLOB          = 2,
    REGEX         = 3,
    CIDR          = 4,
    WILDCARD      = 5
};

const char* match_type_str(MatchType m) {
    switch (m) {
        case MatchType::EXACT:         return "exact";
        case MatchType::DOMAIN_SUFFIX: return "domain_suffix";
        case MatchType::GLOB:          return "glob";
        case MatchType::REGEX:         return "regex";
        case MatchType::CIDR:          return "cidr";
        case MatchType::WILDCARD:      return "wildcard";
        default:                       return "unknown";
    }
}

// Policy rule type (per MSC2313)
enum class PolicyRuleType : uint8_t {
    USER      = 0,
    SERVER    = 1,
    ROOM      = 2,
    UNKNOWN   = 3
};

const char* policy_rule_type_str(PolicyRuleType t) {
    switch (t) {
        case PolicyRuleType::USER:    return "m.policy.rule.user";
        case PolicyRuleType::SERVER:  return "m.policy.rule.server";
        case PolicyRuleType::ROOM:    return "m.policy.rule.room";
        case PolicyRuleType::UNKNOWN: return "unknown";
        default:                      return "unknown";
    }
}

PolicyRuleType policy_rule_type_from_event_type(const std::string& event_type) {
    if (event_type == "m.policy.rule.user")   return PolicyRuleType::USER;
    if (event_type == "m.policy.rule.server") return PolicyRuleType::SERVER;
    if (event_type == "m.policy.rule.room")   return PolicyRuleType::ROOM;
    return PolicyRuleType::UNKNOWN;
}

// Recommendation from policy rule events
enum class PolicyRecommendation : uint8_t {
    BAN         = 0,
    SUSPEND     = 1,
    WARN        = 2,
    MUTE        = 3,
    UNKNOWN     = 4
};

const char* policy_recommendation_str(PolicyRecommendation r) {
    switch (r) {
        case PolicyRecommendation::BAN:     return "m.ban";
        case PolicyRecommendation::SUSPEND: return "m.suspend";
        case PolicyRecommendation::WARN:    return "m.warn";
        case PolicyRecommendation::MUTE:    return "m.mute";
        default:                            return "unknown";
    }
}

PolicyRecommendation policy_recommendation_from_str(const std::string& s) {
    if (s == "m.ban")     return PolicyRecommendation::BAN;
    if (s == "m.suspend") return PolicyRecommendation::SUSPEND;
    if (s == "m.warn")    return PolicyRecommendation::WARN;
    if (s == "m.mute")    return PolicyRecommendation::MUTE;
    return PolicyRecommendation::UNKNOWN;
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
// Ban entry data structures
// ============================================================================

struct ServerBanEntry {
    int64_t id = 0;
    std::string server_name;
    MatchType match_type = MatchType::EXACT;
    std::string reason;
    std::string banned_by;       // admin user ID who created the ban
    int64_t banned_ts = 0;
    int64_t expires_ts = 0;     // 0 = never expires
    bool is_active = true;
    BanLevel level = BanLevel::HARD;
    std::string notes;
    std::string import_source;   // import batch ID if from import

    json to_json() const {
        json j;
        j["id"] = id;
        j["server_name"] = server_name;
        j["match_type"] = match_type_str(match_type);
        j["reason"] = reason;
        j["banned_by"] = banned_by;
        j["banned_ts"] = banned_ts;
        j["expires_ts"] = expires_ts;
        j["is_active"] = is_active;
        j["level"] = ban_level_str(level);
        j["notes"] = notes;
        if (!import_source.empty()) j["import_source"] = import_source;
        return j;
    }
};

struct IPBanEntry {
    int64_t id = 0;
    std::string ip_address;      // single IP or CIDR notation
    int prefix_length = -1;      // -1 for single IP, 0-128 for CIDR
    bool is_ipv6 = false;
    std::string reason;
    std::string banned_by;
    int64_t banned_ts = 0;
    int64_t expires_ts = 0;
    bool is_active = true;
    BanLevel level = BanLevel::HARD;
    std::string notes;
    std::string import_source;

    json to_json() const {
        json j;
        j["id"] = id;
        j["ip_address"] = ip_address;
        if (prefix_length >= 0) j["prefix_length"] = prefix_length;
        j["is_ipv6"] = is_ipv6;
        j["reason"] = reason;
        j["banned_by"] = banned_by;
        j["banned_ts"] = banned_ts;
        j["expires_ts"] = expires_ts;
        j["is_active"] = is_active;
        j["level"] = ban_level_str(level);
        j["notes"] = notes;
        if (!import_source.empty()) j["import_source"] = import_source;
        return j;
    }
};

struct UserBanEntry {
    int64_t id = 0;
    std::string user_id;         // @user:domain or *:domain pattern
    MatchType match_type = MatchType::EXACT;
    std::string reason;
    std::string banned_by;
    int64_t banned_ts = 0;
    int64_t expires_ts = 0;
    bool is_active = true;
    BanLevel level = BanLevel::HARD;
    bool shadow_ban = false;     // silently ignore user
    std::string notes;
    std::string import_source;

    json to_json() const {
        json j;
        j["id"] = id;
        j["user_id"] = user_id;
        j["match_type"] = match_type_str(match_type);
        j["reason"] = reason;
        j["banned_by"] = banned_by;
        j["banned_ts"] = banned_ts;
        j["expires_ts"] = expires_ts;
        j["is_active"] = is_active;
        j["level"] = ban_level_str(level);
        j["shadow_ban"] = shadow_ban;
        j["notes"] = notes;
        if (!import_source.empty()) j["import_source"] = import_source;
        return j;
    }
};

struct RoomBanEntry {
    int64_t id = 0;
    std::string room_id;         // room where the ban applies
    std::string banned_entity;   // server name, user ID, or IP
    BanEntityType entity_type = BanEntityType::SERVER;
    MatchType match_type = MatchType::EXACT;
    std::string reason;
    std::string banned_by;
    int64_t banned_ts = 0;
    int64_t expires_ts = 0;
    bool is_active = true;
    BanLevel level = BanLevel::HARD;
    std::string notes;
    std::string import_source;

    json to_json() const {
        json j;
        j["id"] = id;
        j["room_id"] = room_id;
        j["banned_entity"] = banned_entity;
        j["entity_type"] = ban_entity_type_str(entity_type);
        j["match_type"] = match_type_str(match_type);
        j["reason"] = reason;
        j["banned_by"] = banned_by;
        j["banned_ts"] = banned_ts;
        j["expires_ts"] = expires_ts;
        j["is_active"] = is_active;
        j["level"] = ban_level_str(level);
        j["notes"] = notes;
        if (!import_source.empty()) j["import_source"] = import_source;
        return j;
    }
};

struct BanCheckRequest {
    std::string server_name;
    std::string user_id;
    std::string ip_address;
    std::string room_id;
    std::string tls_fingerprint;
    FederationAction action = FederationAction::SEND_TRANSACTION;
    bool check_server = true;
    bool check_user = true;
    bool check_ip = true;
    bool check_room = true;
};

struct BanCheckResponse {
    BanCheckResult result = BanCheckResult::ALLOWED;
    std::string matched_rule;     // description of what matched
    BanLevel level = BanLevel::HARD;
    std::string reason;
    int64_t ban_id = 0;
    bool is_shadow = false;
    int64_t checked_ts = 0;

    json to_json() const {
        json j;
        j["result"] = ban_check_result_str(result);
        j["matched_rule"] = matched_rule;
        j["level"] = ban_level_str(level);
        j["reason"] = reason;
        j["ban_id"] = ban_id;
        j["is_shadow"] = is_shadow;
        j["checked_ts"] = checked_ts;
        return j;
    }
};

// ============================================================================
// Ban list statistics
// ============================================================================

struct BanListStats {
    int64_t total_server_bans = 0;
    int64_t active_server_bans = 0;
    int64_t total_ip_bans = 0;
    int64_t active_ip_bans = 0;
    int64_t total_user_bans = 0;
    int64_t active_user_bans = 0;
    int64_t total_room_bans = 0;
    int64_t active_room_bans = 0;
    int64_t total_enforcement_checks = 0;
    int64_t total_blocks = 0;
    int64_t imports_count = 0;
    int64_t active_subscriptions = 0;
    int64_t last_sync_ts = 0;

    json to_json() const {
        json j;
        j["total_server_bans"] = total_server_bans;
        j["active_server_bans"] = active_server_bans;
        j["total_ip_bans"] = total_ip_bans;
        j["active_ip_bans"] = active_ip_bans;
        j["total_user_bans"] = total_user_bans;
        j["active_user_bans"] = active_user_bans;
        j["total_room_bans"] = total_room_bans;
        j["active_room_bans"] = active_room_bans;
        j["total_enforcement_checks"] = total_enforcement_checks;
        j["total_blocks"] = total_blocks;
        j["imports_count"] = imports_count;
        j["active_subscriptions"] = active_subscriptions;
        j["last_sync_ts"] = last_sync_ts;
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

// Parse server name from user ID (@user:server)
std::string extract_server_from_user_id(const std::string& user_id) {
    auto pos = user_id.find(':');
    if (pos != std::string::npos && pos > 0 && user_id[0] == '@') {
        return user_id.substr(pos + 1);
    }
    return "";
}

// Check if a server name matches a glob pattern
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

// Convert glob pattern to regex
std::string glob_to_regex(const std::string& glob) {
    std::string regex_str;
    regex_str.reserve(glob.size() * 2 + 2);
    regex_str += '^';
    for (char c : glob) {
        switch (c) {
            case '*': regex_str += ".*"; break;
            case '?': regex_str += '.'; break;
            case '.': regex_str += "\\."; break;
            case '+': regex_str += "\\+"; break;
            case '(': regex_str += "\\("; break;
            case ')': regex_str += "\\)"; break;
            case '[': regex_str += "\\["; break;
            case ']': regex_str += "\\]"; break;
            case '{': regex_str += "\\{"; break;
            case '}': regex_str += "\\}"; break;
            case '^': regex_str += "\\^"; break;
            case '$': regex_str += "\\$"; break;
            case '\\': regex_str += "\\\\"; break;
            default:  regex_str += c; break;
        }
    }
    regex_str += '$';
    return regex_str;
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

// ---- IP address helpers ----

// Parse an IPv4 address into a 32-bit integer
std::optional<uint32_t> parse_ipv4(const std::string& ip) {
    struct in_addr addr;
    if (inet_pton(AF_INET, ip.c_str(), &addr) == 1) {
        return ntohl(addr.s_addr);
    }
    return std::nullopt;
}

// Parse an IPv6 address into two 64-bit integers (high, low)
std::optional<std::pair<uint64_t, uint64_t>> parse_ipv6(const std::string& ip) {
    struct in6_addr addr;
    if (inet_pton(AF_INET6, ip.c_str(), &addr) == 1) {
        uint64_t high = 0, low = 0;
        for (int i = 0; i < 8; ++i) {
            uint64_t byte = addr.s6_addr[i];
            high = (high << 8) | byte;
        }
        for (int i = 8; i < 16; ++i) {
            uint64_t byte = addr.s6_addr[i];
            low = (low << 8) | byte;
        }
        return std::make_pair(high, low);
    }
    return std::nullopt;
}

// Check if an IPv4 address matches a CIDR range
bool ipv4_matches_cidr(uint32_t ip, const std::string& cidr) {
    auto slash_pos = cidr.find('/');
    if (slash_pos == std::string::npos) {
        auto parsed = parse_ipv4(cidr);
        return parsed.has_value() && parsed.value() == ip;
    }
    std::string net_part = cidr.substr(0, slash_pos);
    int prefix = std::stoi(cidr.substr(slash_pos + 1));
    if (prefix < 0 || prefix > 32) return false;
    auto net = parse_ipv4(net_part);
    if (!net.has_value()) return false;
    uint32_t mask = (prefix == 0) ? 0 : (~0U << (32 - prefix));
    return (ip & mask) == (net.value() & mask);
}

// Check if an IPv6 address matches a CIDR range (simplified)
bool ipv6_matches_cidr(const std::pair<uint64_t, uint64_t>& ip,
                       const std::string& cidr) {
    auto slash_pos = cidr.find('/');
    if (slash_pos == std::string::npos) {
        auto parsed = parse_ipv6(cidr);
        return parsed.has_value() &&
               parsed->first == ip.first && parsed->second == ip.second;
    }
    std::string net_part = cidr.substr(0, slash_pos);
    int prefix = std::stoi(cidr.substr(slash_pos + 1));
    if (prefix < 0 || prefix > 128) return false;
    auto net = parse_ipv6(net_part);
    if (!net.has_value()) return false;

    if (prefix == 0) return true;
    if (prefix <= 64) {
        uint64_t mask = (prefix == 0) ? 0 : (~0ULL << (64 - prefix));
        return (ip.first & mask) == (net->first & mask);
    } else {
        if (ip.first != net->first) return false;
        int low_prefix = prefix - 64;
        uint64_t mask = (~0ULL << (64 - low_prefix));
        return (ip.second & mask) == (net->second & mask);
    }
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

ServerBanEntry row_to_server_ban(const std::unique_ptr<storage::Row>& row) {
    ServerBanEntry entry;
    if (!row) return entry;
    entry.id = row_get_int(row, 0);
    entry.server_name = row_get_str(row, 1);
    entry.match_type = static_cast<MatchType>(row_get_int(row, 2));
    entry.reason = row_get_str(row, 3);
    entry.banned_by = row_get_str(row, 4);
    entry.banned_ts = row_get_int(row, 5);
    entry.expires_ts = row_get_int(row, 6);
    entry.is_active = row_get_bool(row, 7);
    entry.level = static_cast<BanLevel>(row_get_int(row, 8));
    entry.notes = row_get_str(row, 9);
    entry.import_source = row_get_str(row, 10);
    return entry;
}

IPBanEntry row_to_ip_ban(const std::unique_ptr<storage::Row>& row) {
    IPBanEntry entry;
    if (!row) return entry;
    entry.id = row_get_int(row, 0);
    entry.ip_address = row_get_str(row, 1);
    entry.prefix_length = row->is_null(2) ? -1 : static_cast<int>(row_get_int(row, 2));
    entry.is_ipv6 = row_get_bool(row, 3);
    entry.reason = row_get_str(row, 4);
    entry.banned_by = row_get_str(row, 5);
    entry.banned_ts = row_get_int(row, 6);
    entry.expires_ts = row_get_int(row, 7);
    entry.is_active = row_get_bool(row, 8);
    entry.level = static_cast<BanLevel>(row_get_int(row, 9));
    entry.notes = row_get_str(row, 10);
    entry.import_source = row_get_str(row, 11);
    return entry;
}

UserBanEntry row_to_user_ban(const std::unique_ptr<storage::Row>& row) {
    UserBanEntry entry;
    if (!row) return entry;
    entry.id = row_get_int(row, 0);
    entry.user_id = row_get_str(row, 1);
    entry.match_type = static_cast<MatchType>(row_get_int(row, 2));
    entry.reason = row_get_str(row, 3);
    entry.banned_by = row_get_str(row, 4);
    entry.banned_ts = row_get_int(row, 5);
    entry.expires_ts = row_get_int(row, 6);
    entry.is_active = row_get_bool(row, 7);
    entry.level = static_cast<BanLevel>(row_get_int(row, 8));
    entry.shadow_ban = row_get_bool(row, 9);
    entry.notes = row_get_str(row, 10);
    entry.import_source = row_get_str(row, 11);
    return entry;
}

RoomBanEntry row_to_room_ban(const std::unique_ptr<storage::Row>& row) {
    RoomBanEntry entry;
    if (!row) return entry;
    entry.id = row_get_int(row, 0);
    entry.room_id = row_get_str(row, 1);
    entry.banned_entity = row_get_str(row, 2);
    entry.entity_type = static_cast<BanEntityType>(row_get_int(row, 3));
    entry.match_type = static_cast<MatchType>(row_get_int(row, 4));
    entry.reason = row_get_str(row, 5);
    entry.banned_by = row_get_str(row, 6);
    entry.banned_ts = row_get_int(row, 7);
    entry.expires_ts = row_get_int(row, 8);
    entry.is_active = row_get_bool(row, 9);
    entry.level = static_cast<BanLevel>(row_get_int(row, 10));
    entry.notes = row_get_str(row, 11);
    entry.import_source = row_get_str(row, 12);
    return entry;
}

// ---- Logger helper ----

class BanLogger {
public:
    explicit BanLogger(const std::string& name) : name_(name) {}
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
// 1. BanListStore — SQL DDL and CRUD for all ban-related tables
// ============================================================================

class BanListStore {
public:
    explicit BanListStore(DatabasePool& db, BanLogger& logger)
        : db_(db), logger_(logger) {}

    // ---------- DDL ----------
    static void create_tables(LoggingTransaction& txn) {
        // Server bans table
        txn.execute(R"SQL(
            CREATE TABLE IF NOT EXISTS server_bans (
                id BIGINT NOT NULL PRIMARY KEY AUTOINCREMENT,
                server_name TEXT NOT NULL,
                match_type INTEGER NOT NULL DEFAULT 0,
                reason TEXT NOT NULL DEFAULT '',
                banned_by TEXT NOT NULL DEFAULT '',
                banned_ts BIGINT NOT NULL,
                expires_ts BIGINT NOT NULL DEFAULT 0,
                is_active INTEGER NOT NULL DEFAULT 1,
                level INTEGER NOT NULL DEFAULT 2,
                notes TEXT NOT NULL DEFAULT '',
                import_source TEXT NOT NULL DEFAULT ''
            );
        )SQL");
        txn.execute(R"SQL(
            CREATE INDEX IF NOT EXISTS server_bans_server_name_idx
                ON server_bans (server_name);
        )SQL");
        txn.execute(R"SQL(
            CREATE INDEX IF NOT EXISTS server_bans_active_idx
                ON server_bans (is_active, expires_ts);
        )SQL");
        txn.execute(R"SQL(
            CREATE INDEX IF NOT EXISTS server_bans_import_source_idx
                ON server_bans (import_source);
        )SQL");

        // IP bans table
        txn.execute(R"SQL(
            CREATE TABLE IF NOT EXISTS ip_bans (
                id BIGINT NOT NULL PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                prefix_length INTEGER,
                is_ipv6 INTEGER NOT NULL DEFAULT 0,
                reason TEXT NOT NULL DEFAULT '',
                banned_by TEXT NOT NULL DEFAULT '',
                banned_ts BIGINT NOT NULL,
                expires_ts BIGINT NOT NULL DEFAULT 0,
                is_active INTEGER NOT NULL DEFAULT 1,
                level INTEGER NOT NULL DEFAULT 2,
                notes TEXT NOT NULL DEFAULT '',
                import_source TEXT NOT NULL DEFAULT ''
            );
        )SQL");
        txn.execute(R"SQL(
            CREATE INDEX IF NOT EXISTS ip_bans_address_idx
                ON ip_bans (ip_address);
        )SQL");
        txn.execute(R"SQL(
            CREATE INDEX IF NOT EXISTS ip_bans_active_idx
                ON ip_bans (is_active, expires_ts);
        )SQL");
        txn.execute(R"SQL(
            CREATE INDEX IF NOT EXISTS ip_bans_ipv6_idx
                ON ip_bans (is_ipv6);
        )SQL");

        // User bans table
        txn.execute(R"SQL(
            CREATE TABLE IF NOT EXISTS user_bans (
                id BIGINT NOT NULL PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                match_type INTEGER NOT NULL DEFAULT 0,
                reason TEXT NOT NULL DEFAULT '',
                banned_by TEXT NOT NULL DEFAULT '',
                banned_ts BIGINT NOT NULL,
                expires_ts BIGINT NOT NULL DEFAULT 0,
                is_active INTEGER NOT NULL DEFAULT 1,
                level INTEGER NOT NULL DEFAULT 2,
                shadow_ban INTEGER NOT NULL DEFAULT 0,
                notes TEXT NOT NULL DEFAULT '',
                import_source TEXT NOT NULL DEFAULT ''
            );
        )SQL");
        txn.execute(R"SQL(
            CREATE INDEX IF NOT EXISTS user_bans_user_id_idx
                ON user_bans (user_id);
        )SQL");
        txn.execute(R"SQL(
            CREATE INDEX IF NOT EXISTS user_bans_active_idx
                ON user_bans (is_active, shadow_ban);
        )SQL");
        txn.execute(R"SQL(
            CREATE INDEX IF NOT EXISTS user_bans_import_source_idx
                ON user_bans (import_source);
        )SQL");

        // Room bans table
        txn.execute(R"SQL(
            CREATE TABLE IF NOT EXISTS room_bans (
                id BIGINT NOT NULL PRIMARY KEY AUTOINCREMENT,
                room_id TEXT NOT NULL,
                banned_entity TEXT NOT NULL,
                entity_type INTEGER NOT NULL DEFAULT 0,
                match_type INTEGER NOT NULL DEFAULT 0,
                reason TEXT NOT NULL DEFAULT '',
                banned_by TEXT NOT NULL DEFAULT '',
                banned_ts BIGINT NOT NULL,
                expires_ts BIGINT NOT NULL DEFAULT 0,
                is_active INTEGER NOT NULL DEFAULT 1,
                level INTEGER NOT NULL DEFAULT 2,
                notes TEXT NOT NULL DEFAULT '',
                import_source TEXT NOT NULL DEFAULT ''
            );
        )SQL");
        txn.execute(R"SQL(
            CREATE INDEX IF NOT EXISTS room_bans_room_idx
                ON room_bans (room_id, is_active);
        )SQL");
        txn.execute(R"SQL(
            CREATE INDEX IF NOT EXISTS room_bans_entity_idx
                ON room_bans (banned_entity, entity_type);
        )SQL");
        txn.execute(R"SQL(
            CREATE INDEX IF NOT EXISTS room_bans_room_entity_idx
                ON room_bans (room_id, banned_entity, entity_type);
        )SQL");

        // Ban list imports table
        txn.execute(R"SQL(
            CREATE TABLE IF NOT EXISTS ban_list_imports (
                id BIGINT NOT NULL PRIMARY KEY AUTOINCREMENT,
                import_id TEXT NOT NULL UNIQUE,
                source_type INTEGER NOT NULL DEFAULT 0,
                source TEXT NOT NULL DEFAULT '',
                imported_by TEXT NOT NULL DEFAULT '',
                imported_ts BIGINT NOT NULL,
                entry_count INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'completed',
                metadata TEXT NOT NULL DEFAULT '{}'
            );
        )SQL");
        txn.execute(R"SQL(
            CREATE INDEX IF NOT EXISTS ban_list_imports_source_idx
                ON ban_list_imports (source_type, source);
        )SQL");

        // Ban list entries (linked to import)
        txn.execute(R"SQL(
            CREATE TABLE IF NOT EXISTS ban_list_entries (
                id BIGINT NOT NULL PRIMARY KEY AUTOINCREMENT,
                import_id TEXT NOT NULL,
                entity_type INTEGER NOT NULL DEFAULT 0,
                entity_value TEXT NOT NULL,
                reason TEXT NOT NULL DEFAULT '',
                recommendation TEXT NOT NULL DEFAULT 'm.ban',
                event_id TEXT,
                FOREIGN KEY (import_id) REFERENCES ban_list_imports(import_id)
            );
        )SQL");
        txn.execute(R"SQL(
            CREATE INDEX IF NOT EXISTS ban_list_entries_import_idx
                ON ban_list_entries (import_id);
        )SQL");

        // Ban sync log table
        txn.execute(R"SQL(
            CREATE TABLE IF NOT EXISTS ban_sync_log (
                id BIGINT NOT NULL PRIMARY KEY AUTOINCREMENT,
                sync_id TEXT NOT NULL UNIQUE,
                source_node TEXT NOT NULL DEFAULT '',
                target_node TEXT NOT NULL DEFAULT '',
                direction TEXT NOT NULL DEFAULT 'push',
                synced_ts BIGINT NOT NULL,
                entry_count INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'pending',
                error_msg TEXT NOT NULL DEFAULT '',
                metadata TEXT NOT NULL DEFAULT '{}'
            );
        )SQL");
        txn.execute(R"SQL(
            CREATE INDEX IF NOT EXISTS ban_sync_log_node_idx
                ON ban_sync_log (source_node, target_node);
        )SQL");
        txn.execute(R"SQL(
            CREATE INDEX IF NOT EXISTS ban_sync_log_status_idx
                ON ban_sync_log (status, synced_ts);
        )SQL");

        // Ban enforcement log table
        txn.execute(R"SQL(
            CREATE TABLE IF NOT EXISTS ban_enforcement_log (
                id BIGINT NOT NULL PRIMARY KEY AUTOINCREMENT,
                server_name TEXT NOT NULL DEFAULT '',
                action TEXT NOT NULL DEFAULT '',
                room_id TEXT NOT NULL DEFAULT '',
                result TEXT NOT NULL DEFAULT '',
                decision_source TEXT NOT NULL DEFAULT '',
                ban_id BIGINT NOT NULL DEFAULT 0,
                checked_ts BIGINT NOT NULL,
                latency_us BIGINT NOT NULL DEFAULT 0
            );
        )SQL");
        txn.execute(R"SQL(
            CREATE INDEX IF NOT EXISTS ban_enforcement_server_idx
                ON ban_enforcement_log (server_name, checked_ts);
        )SQL");
        txn.execute(R"SQL(
            CREATE INDEX IF NOT EXISTS ban_enforcement_room_idx
                ON ban_enforcement_log (room_id, checked_ts);
        )SQL");
        txn.execute(R"SQL(
            CREATE INDEX IF NOT EXISTS ban_enforcement_result_idx
                ON ban_enforcement_log (result, checked_ts);
        )SQL");

        // Ban list subscriptions (remote ban list rooms)
        txn.execute(R"SQL(
            CREATE TABLE IF NOT EXISTS ban_list_subscriptions (
                id BIGINT NOT NULL PRIMARY KEY AUTOINCREMENT,
                room_id TEXT NOT NULL UNIQUE,
                server_name TEXT NOT NULL DEFAULT '',
                display_name TEXT NOT NULL DEFAULT '',
                subscribed_by TEXT NOT NULL DEFAULT '',
                subscribed_ts BIGINT NOT NULL,
                last_synced_ts BIGINT NOT NULL DEFAULT 0,
                is_active INTEGER NOT NULL DEFAULT 1,
                auto_apply INTEGER NOT NULL DEFAULT 1,
                last_event_id TEXT NOT NULL DEFAULT '',
                notes TEXT NOT NULL DEFAULT ''
            );
        )SQL");
        txn.execute(R"SQL(
            CREATE INDEX IF NOT EXISTS ban_list_subscriptions_active_idx
                ON ban_list_subscriptions (is_active, last_synced_ts);
        )SQL");

        // Ban overrides (per-room exceptions)
        txn.execute(R"SQL(
            CREATE TABLE IF NOT EXISTS ban_overrides (
                id BIGINT NOT NULL PRIMARY KEY AUTOINCREMENT,
                room_id TEXT NOT NULL,
                ban_id BIGINT NOT NULL DEFAULT 0,
                ban_type TEXT NOT NULL DEFAULT '',
                override_type TEXT NOT NULL DEFAULT 'allow',
                reason TEXT NOT NULL DEFAULT '',
                set_by TEXT NOT NULL DEFAULT '',
                set_ts BIGINT NOT NULL,
                expires_ts BIGINT NOT NULL DEFAULT 0,
                is_active INTEGER NOT NULL DEFAULT 1
            );
        )SQL");
        txn.execute(R"SQL(
            CREATE INDEX IF NOT EXISTS ban_overrides_room_idx
                ON ban_overrides (room_id, is_active);
        )SQL");
        txn.execute(R"SQL(
            CREATE INDEX IF NOT EXISTS ban_overrides_ban_idx
                ON ban_overrides (ban_id, ban_type);
        )SQL");
    }

    // ---------- Server Bans CRUD ----------

    int64_t add_server_ban_txn(LoggingTransaction& txn, const ServerBanEntry& entry) {
        txn.execute(
            "INSERT INTO server_bans (server_name, match_type, reason, banned_by, "
            "banned_ts, expires_ts, is_active, level, notes, import_source) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            {entry.server_name, static_cast<int64_t>(entry.match_type),
             entry.reason, entry.banned_by, entry.banned_ts, entry.expires_ts,
             entry.is_active ? 1 : 0, static_cast<int64_t>(entry.level),
             entry.notes, entry.import_source});
        return txn.last_insert_rowid();
    }

    bool update_server_ban_txn(LoggingTransaction& txn, int64_t id,
                                const json& updates) {
        std::vector<std::string> set_clauses;
        std::vector<storage::SQLParam> params;
        if (updates.contains("reason")) {
            set_clauses.push_back("reason = ?");
            params.push_back(updates["reason"].get<std::string>());
        }
        if (updates.contains("level")) {
            set_clauses.push_back("level = ?");
            params.push_back(static_cast<int64_t>(
                ban_level_from_str(updates["level"].get<std::string>())));
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
        if (set_clauses.empty()) return false;
        params.push_back(id);
        std::string sql = "UPDATE server_bans SET " +
                          join(set_clauses, ", ") + " WHERE id = ?";
        txn.execute(sql, params);
        return true;
    }

    bool deactivate_server_ban_txn(LoggingTransaction& txn, int64_t id) {
        txn.execute("UPDATE server_bans SET is_active = 0 WHERE id = ?", {id});
        return true;
    }

    bool delete_server_ban_txn(LoggingTransaction& txn, int64_t id) {
        txn.execute("DELETE FROM server_bans WHERE id = ?", {id});
        return true;
    }

    std::optional<ServerBanEntry> get_server_ban_txn(LoggingTransaction& txn,
                                                       int64_t id) {
        auto row = txn.select_one(
            "SELECT id, server_name, match_type, reason, banned_by, "
            "banned_ts, expires_ts, is_active, level, notes, import_source "
            "FROM server_bans WHERE id = ?", {id});
        if (!row) return std::nullopt;
        return row_to_server_ban(row);
    }

    std::vector<ServerBanEntry> get_server_bans_by_name_txn(
        LoggingTransaction& txn, const std::string& server_name) {
        std::vector<ServerBanEntry> results;
        auto rows = txn.select(
            "SELECT id, server_name, match_type, reason, banned_by, "
            "banned_ts, expires_ts, is_active, level, notes, import_source "
            "FROM server_bans WHERE server_name = ? AND is_active = 1 "
            "AND (expires_ts = 0 OR expires_ts > ?) "
            "ORDER BY level DESC, banned_ts DESC",
            {to_lower(server_name), now_ms()});
        for (auto& row : rows) {
            results.push_back(row_to_server_ban(row));
        }
        return results;
    }

    std::vector<ServerBanEntry> get_all_active_server_bans_txn(
        LoggingTransaction& txn, int limit = 1000, int offset = 0) {
        std::vector<ServerBanEntry> results;
        auto rows = txn.select(
            "SELECT id, server_name, match_type, reason, banned_by, "
            "banned_ts, expires_ts, is_active, level, notes, import_source "
            "FROM server_bans WHERE is_active = 1 "
            "AND (expires_ts = 0 OR expires_ts > ?) "
            "ORDER BY banned_ts DESC LIMIT ? OFFSET ?",
            {now_ms(), limit, offset});
        for (auto& row : rows) {
            results.push_back(row_to_server_ban(row));
        }
        return results;
    }

    std::vector<ServerBanEntry> get_all_server_bans_txn(
        LoggingTransaction& txn, int limit = 1000, int offset = 0) {
        std::vector<ServerBanEntry> results;
        auto rows = txn.select(
            "SELECT id, server_name, match_type, reason, banned_by, "
            "banned_ts, expires_ts, is_active, level, notes, import_source "
            "FROM server_bans ORDER BY banned_ts DESC LIMIT ? OFFSET ?",
            {limit, offset});
        for (auto& row : rows) {
            results.push_back(row_to_server_ban(row));
        }
        return results;
    }

    int64_t count_server_bans_txn(LoggingTransaction& txn, bool active_only = true) {
        std::string sql = active_only
            ? "SELECT COUNT(*) FROM server_bans WHERE is_active = 1 AND "
              "(expires_ts = 0 OR expires_ts > ?)"
            : "SELECT COUNT(*) FROM server_bans";
        auto row = active_only
            ? txn.select_one(sql, {now_ms()})
            : txn.select_one(sql);
        return row ? row->get<int64_t>(0) : 0;
    }

    void delete_expired_server_bans_txn(LoggingTransaction& txn) {
        txn.execute(
            "UPDATE server_bans SET is_active = 0 "
            "WHERE is_active = 1 AND expires_ts > 0 AND expires_ts <= ?",
            {now_ms()});
    }

    void delete_server_bans_by_import_source_txn(LoggingTransaction& txn,
                                                   const std::string& import_source) {
        txn.execute("DELETE FROM server_bans WHERE import_source = ?",
                     {import_source});
    }

    // ---------- IP Bans CRUD ----------

    int64_t add_ip_ban_txn(LoggingTransaction& txn, const IPBanEntry& entry) {
        txn.execute(
            "INSERT INTO ip_bans (ip_address, prefix_length, is_ipv6, reason, "
            "banned_by, banned_ts, expires_ts, is_active, level, notes, import_source) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            {entry.ip_address, entry.prefix_length, entry.is_ipv6 ? 1 : 0,
             entry.reason, entry.banned_by, entry.banned_ts, entry.expires_ts,
             entry.is_active ? 1 : 0, static_cast<int64_t>(entry.level),
             entry.notes, entry.import_source});
        return txn.last_insert_rowid();
    }

    bool deactivate_ip_ban_txn(LoggingTransaction& txn, int64_t id) {
        txn.execute("UPDATE ip_bans SET is_active = 0 WHERE id = ?", {id});
        return true;
    }

    bool delete_ip_ban_txn(LoggingTransaction& txn, int64_t id) {
        txn.execute("DELETE FROM ip_bans WHERE id = ?", {id});
        return true;
    }

    std::vector<IPBanEntry> get_all_active_ip_bans_txn(
        LoggingTransaction& txn, int limit = 1000, int offset = 0) {
        std::vector<IPBanEntry> results;
        auto rows = txn.select(
            "SELECT id, ip_address, prefix_length, is_ipv6, reason, banned_by, "
            "banned_ts, expires_ts, is_active, level, notes, import_source "
            "FROM ip_bans WHERE is_active = 1 "
            "AND (expires_ts = 0 OR expires_ts > ?) "
            "ORDER BY banned_ts DESC LIMIT ? OFFSET ?",
            {now_ms(), limit, offset});
        for (auto& row : rows) {
            results.push_back(row_to_ip_ban(row));
        }
        return results;
    }

    std::vector<IPBanEntry> get_all_ip_bans_txn(
        LoggingTransaction& txn, int limit = 1000, int offset = 0) {
        std::vector<IPBanEntry> results;
        auto rows = txn.select(
            "SELECT id, ip_address, prefix_length, is_ipv6, reason, banned_by, "
            "banned_ts, expires_ts, is_active, level, notes, import_source "
            "FROM ip_bans ORDER BY banned_ts DESC LIMIT ? OFFSET ?",
            {limit, offset});
        for (auto& row : rows) {
            results.push_back(row_to_ip_ban(row));
        }
        return results;
    }

    int64_t count_ip_bans_txn(LoggingTransaction& txn, bool active_only = true) {
        std::string sql = active_only
            ? "SELECT COUNT(*) FROM ip_bans WHERE is_active = 1 AND "
              "(expires_ts = 0 OR expires_ts > ?)"
            : "SELECT COUNT(*) FROM ip_bans";
        auto row = active_only
            ? txn.select_one(sql, {now_ms()})
            : txn.select_one(sql);
        return row ? row->get<int64_t>(0) : 0;
    }

    void delete_expired_ip_bans_txn(LoggingTransaction& txn) {
        txn.execute(
            "UPDATE ip_bans SET is_active = 0 "
            "WHERE is_active = 1 AND expires_ts > 0 AND expires_ts <= ?",
            {now_ms()});
    }

    void delete_ip_bans_by_import_source_txn(LoggingTransaction& txn,
                                               const std::string& import_source) {
        txn.execute("DELETE FROM ip_bans WHERE import_source = ?",
                     {import_source});
    }

    // ---------- User Bans CRUD ----------

    int64_t add_user_ban_txn(LoggingTransaction& txn, const UserBanEntry& entry) {
        txn.execute(
            "INSERT INTO user_bans (user_id, match_type, reason, banned_by, "
            "banned_ts, expires_ts, is_active, level, shadow_ban, notes, import_source) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            {entry.user_id, static_cast<int64_t>(entry.match_type),
             entry.reason, entry.banned_by, entry.banned_ts, entry.expires_ts,
             entry.is_active ? 1 : 0, static_cast<int64_t>(entry.level),
             entry.shadow_ban ? 1 : 0, entry.notes, entry.import_source});
        return txn.last_insert_rowid();
    }

    bool deactivate_user_ban_txn(LoggingTransaction& txn, int64_t id) {
        txn.execute("UPDATE user_bans SET is_active = 0 WHERE id = ?", {id});
        return true;
    }

    bool delete_user_ban_txn(LoggingTransaction& txn, int64_t id) {
        txn.execute("DELETE FROM user_bans WHERE id = ?", {id});
        return true;
    }

    std::optional<UserBanEntry> get_user_ban_txn(LoggingTransaction& txn,
                                                   int64_t id) {
        auto row = txn.select_one(
            "SELECT id, user_id, match_type, reason, banned_by, "
            "banned_ts, expires_ts, is_active, level, shadow_ban, notes, import_source "
            "FROM user_bans WHERE id = ?", {id});
        if (!row) return std::nullopt;
        return row_to_user_ban(row);
    }

    std::vector<UserBanEntry> get_user_bans_by_user_id_txn(
        LoggingTransaction& txn, const std::string& user_id) {
        std::vector<UserBanEntry> results;
        auto rows = txn.select(
            "SELECT id, user_id, match_type, reason, banned_by, "
            "banned_ts, expires_ts, is_active, level, shadow_ban, notes, import_source "
            "FROM user_bans WHERE user_id = ? AND is_active = 1 "
            "AND (expires_ts = 0 OR expires_ts > ?) "
            "ORDER BY level DESC, banned_ts DESC",
            {user_id, now_ms()});
        for (auto& row : rows) {
            results.push_back(row_to_user_ban(row));
        }
        return results;
    }

    std::vector<UserBanEntry> get_all_active_user_bans_txn(
        LoggingTransaction& txn, int limit = 1000, int offset = 0) {
        std::vector<UserBanEntry> results;
        auto rows = txn.select(
            "SELECT id, user_id, match_type, reason, banned_by, "
            "banned_ts, expires_ts, is_active, level, shadow_ban, notes, import_source "
            "FROM user_bans WHERE is_active = 1 "
            "AND (expires_ts = 0 OR expires_ts > ?) "
            "ORDER BY banned_ts DESC LIMIT ? OFFSET ?",
            {now_ms(), limit, offset});
        for (auto& row : rows) {
            results.push_back(row_to_user_ban(row));
        }
        return results;
    }

    std::vector<UserBanEntry> get_all_user_bans_txn(
        LoggingTransaction& txn, int limit = 1000, int offset = 0) {
        std::vector<UserBanEntry> results;
        auto rows = txn.select(
            "SELECT id, user_id, match_type, reason, banned_by, "
            "banned_ts, expires_ts, is_active, level, shadow_ban, notes, import_source "
            "FROM user_bans ORDER BY banned_ts DESC LIMIT ? OFFSET ?",
            {limit, offset});
        for (auto& row : rows) {
            results.push_back(row_to_user_ban(row));
        }
        return results;
    }

    int64_t count_user_bans_txn(LoggingTransaction& txn, bool active_only = true) {
        std::string sql = active_only
            ? "SELECT COUNT(*) FROM user_bans WHERE is_active = 1 AND "
              "(expires_ts = 0 OR expires_ts > ?)"
            : "SELECT COUNT(*) FROM user_bans";
        auto row = active_only
            ? txn.select_one(sql, {now_ms()})
            : txn.select_one(sql);
        return row ? row->get<int64_t>(0) : 0;
    }

    void delete_expired_user_bans_txn(LoggingTransaction& txn) {
        txn.execute(
            "UPDATE user_bans SET is_active = 0 "
            "WHERE is_active = 1 AND expires_ts > 0 AND expires_ts <= ?",
            {now_ms()});
    }

    void delete_user_bans_by_import_source_txn(LoggingTransaction& txn,
                                                 const std::string& import_source) {
        txn.execute("DELETE FROM user_bans WHERE import_source = ?",
                     {import_source});
    }

    // ---------- Room Bans CRUD ----------

    int64_t add_room_ban_txn(LoggingTransaction& txn, const RoomBanEntry& entry) {
        txn.execute(
            "INSERT INTO room_bans (room_id, banned_entity, entity_type, match_type, "
            "reason, banned_by, banned_ts, expires_ts, is_active, level, notes, "
            "import_source) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            {entry.room_id, entry.banned_entity,
             static_cast<int64_t>(entry.entity_type),
             static_cast<int64_t>(entry.match_type),
             entry.reason, entry.banned_by, entry.banned_ts, entry.expires_ts,
             entry.is_active ? 1 : 0, static_cast<int64_t>(entry.level),
             entry.notes, entry.import_source});
        return txn.last_insert_rowid();
    }

    bool deactivate_room_ban_txn(LoggingTransaction& txn, int64_t id) {
        txn.execute("UPDATE room_bans SET is_active = 0 WHERE id = ?", {id});
        return true;
    }

    bool delete_room_ban_txn(LoggingTransaction& txn, int64_t id) {
        txn.execute("DELETE FROM room_bans WHERE id = ?", {id});
        return true;
    }

    std::vector<RoomBanEntry> get_room_bans_txn(
        LoggingTransaction& txn, const std::string& room_id,
        int limit = 500, int offset = 0) {
        std::vector<RoomBanEntry> results;
        auto rows = txn.select(
            "SELECT id, room_id, banned_entity, entity_type, match_type, reason, "
            "banned_by, banned_ts, expires_ts, is_active, level, notes, import_source "
            "FROM room_bans WHERE room_id = ? AND is_active = 1 "
            "AND (expires_ts = 0 OR expires_ts > ?) "
            "ORDER BY banned_ts DESC LIMIT ? OFFSET ?",
            {room_id, now_ms(), limit, offset});
        for (auto& row : rows) {
            results.push_back(row_to_room_ban(row));
        }
        return results;
    }

    std::vector<RoomBanEntry> get_all_room_bans_txn(
        LoggingTransaction& txn, int limit = 1000, int offset = 0) {
        std::vector<RoomBanEntry> results;
        auto rows = txn.select(
            "SELECT id, room_id, banned_entity, entity_type, match_type, reason, "
            "banned_by, banned_ts, expires_ts, is_active, level, notes, import_source "
            "FROM room_bans WHERE is_active = 1 "
            "AND (expires_ts = 0 OR expires_ts > ?) "
            "ORDER BY banned_ts DESC LIMIT ? OFFSET ?",
            {now_ms(), limit, offset});
        for (auto& row : rows) {
            results.push_back(row_to_room_ban(row));
        }
        return results;
    }

    int64_t count_room_bans_txn(LoggingTransaction& txn, bool active_only = true) {
        std::string sql = active_only
            ? "SELECT COUNT(*) FROM room_bans WHERE is_active = 1 AND "
              "(expires_ts = 0 OR expires_ts > ?)"
            : "SELECT COUNT(*) FROM room_bans";
        auto row = active_only
            ? txn.select_one(sql, {now_ms()})
            : txn.select_one(sql);
        return row ? row->get<int64_t>(0) : 0;
    }

    void delete_expired_room_bans_txn(LoggingTransaction& txn) {
        txn.execute(
            "UPDATE room_bans SET is_active = 0 "
            "WHERE is_active = 1 AND expires_ts > 0 AND expires_ts <= ?",
            {now_ms()});
    }

    void delete_room_bans_by_import_source_txn(LoggingTransaction& txn,
                                                 const std::string& import_source) {
        txn.execute("DELETE FROM room_bans WHERE import_source = ?",
                     {import_source});
    }

    // ---------- Import Records CRUD ----------

    std::string add_import_record_txn(LoggingTransaction& txn,
                                       ImportSourceType source_type,
                                       const std::string& source,
                                       const std::string& imported_by,
                                       int entry_count,
                                       const json& metadata = json::object()) {
        std::string import_id = "import_" + random_hex(16) + "_" +
                                std::to_string(now_ms());
        txn.execute(
            "INSERT INTO ban_list_imports (import_id, source_type, source, "
            "imported_by, imported_ts, entry_count, status, metadata) "
            "VALUES (?, ?, ?, ?, ?, ?, 'completed', ?)",
            {import_id, static_cast<int64_t>(source_type), source,
             imported_by, now_ms(), entry_count, metadata.dump()});
        return import_id;
    }

    void add_import_entry_txn(LoggingTransaction& txn,
                               const std::string& import_id,
                               BanEntityType entity_type,
                               const std::string& entity_value,
                               const std::string& reason,
                               const std::string& event_id = "") {
        txn.execute(
            "INSERT INTO ban_list_entries (import_id, entity_type, entity_value, "
            "reason, event_id) VALUES (?, ?, ?, ?, ?)",
            {import_id, static_cast<int64_t>(entity_type), entity_value,
             reason, event_id});
    }

    json get_import_record_txn(LoggingTransaction& txn,
                                const std::string& import_id) {
        auto row = txn.select_one(
            "SELECT import_id, source_type, source, imported_by, imported_ts, "
            "entry_count, status, metadata FROM ban_list_imports "
            "WHERE import_id = ?", {import_id});
        if (!row) return json::object();
        json j;
        j["import_id"] = row->get<std::string>(0);
        j["source_type"] = row->get<int64_t>(1);
        j["source"] = row->get<std::string>(2);
        j["imported_by"] = row->get<std::string>(3);
        j["imported_ts"] = row->get<int64_t>(4);
        j["entry_count"] = row->get<int64_t>(5);
        j["status"] = row->get<std::string>(6);
        j["metadata"] = json::parse(row->get<std::string>(7));
        return j;
    }

    json get_all_imports_txn(LoggingTransaction& txn,
                              int limit = 100, int offset = 0) {
        json result = json::array();
        auto rows = txn.select(
            "SELECT import_id, source_type, source, imported_by, imported_ts, "
            "entry_count, status, metadata FROM ban_list_imports "
            "ORDER BY imported_ts DESC LIMIT ? OFFSET ?",
            {limit, offset});
        for (auto& row : rows) {
            json j;
            j["import_id"] = row->get<std::string>(0);
            j["source_type"] = row->get<int64_t>(1);
            j["source"] = row->get<std::string>(2);
            j["imported_by"] = row->get<std::string>(3);
            j["imported_ts"] = row->get<int64_t>(4);
            j["entry_count"] = row->get<int64_t>(5);
            j["status"] = row->get<std::string>(6);
            if (!row->is_null(7)) {
                j["metadata"] = json::parse(row->get<std::string>(7));
            }
            result.push_back(j);
        }
        return result;
    }

    int64_t count_imports_txn(LoggingTransaction& txn) {
        auto row = txn.select_one("SELECT COUNT(*) FROM ban_list_imports");
        return row ? row->get<int64_t>(0) : 0;
    }

    // ---------- Sync Log CRUD ----------

    std::string add_sync_log_entry_txn(LoggingTransaction& txn,
                                        const std::string& source_node,
                                        const std::string& target_node,
                                        const std::string& direction,
                                        int entry_count,
                                        const std::string& status) {
        std::string sync_id = "sync_" + random_hex(16);
        txn.execute(
            "INSERT INTO ban_sync_log (sync_id, source_node, target_node, "
            "direction, synced_ts, entry_count, status) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            {sync_id, source_node, target_node, direction, now_ms(),
             entry_count, status});
        return sync_id;
    }

    void update_sync_log_status_txn(LoggingTransaction& txn,
                                     const std::string& sync_id,
                                     const std::string& status,
                                     const std::string& error_msg = "") {
        txn.execute(
            "UPDATE ban_sync_log SET status = ?, error_msg = ? WHERE sync_id = ?",
            {status, error_msg, sync_id});
    }

    json get_sync_log_txn(LoggingTransaction& txn,
                           int limit = 100, int offset = 0) {
        json result = json::array();
        auto rows = txn.select(
            "SELECT sync_id, source_node, target_node, direction, synced_ts, "
            "entry_count, status, error_msg, metadata FROM ban_sync_log "
            "ORDER BY synced_ts DESC LIMIT ? OFFSET ?",
            {limit, offset});
        for (auto& row : rows) {
            json j;
            j["sync_id"] = row->get<std::string>(0);
            j["source_node"] = row->get<std::string>(1);
            j["target_node"] = row->get<std::string>(2);
            j["direction"] = row->get<std::string>(3);
            j["synced_ts"] = row->get<int64_t>(4);
            j["entry_count"] = row->get<int64_t>(5);
            j["status"] = row->get<std::string>(6);
            j["error_msg"] = row->get<std::string>(7);
            result.push_back(j);
        }
        return result;
    }

    // ---------- Enforcement Log CRUD ----------

    void log_enforcement_txn(LoggingTransaction& txn,
                              const std::string& server_name,
                              const std::string& action,
                              const std::string& room_id,
                              const std::string& result,
                              const std::string& decision_source,
                              int64_t ban_id,
                              int64_t latency_us) {
        txn.execute(
            "INSERT INTO ban_enforcement_log (server_name, action, room_id, "
            "result, decision_source, ban_id, checked_ts, latency_us) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            {server_name, action, room_id, result, decision_source,
             ban_id, now_ms(), latency_us});
    }

    json get_enforcement_log_txn(LoggingTransaction& txn,
                                  const std::string& server_name = "",
                                  int limit = 100, int offset = 0) {
        json result = json::array();
        std::string sql;
        std::vector<storage::SQLParam> params;
        if (!server_name.empty()) {
            sql = "SELECT server_name, action, room_id, result, decision_source, "
                  "ban_id, checked_ts, latency_us FROM ban_enforcement_log "
                  "WHERE server_name = ? ORDER BY checked_ts DESC LIMIT ? OFFSET ?";
            params = {server_name, limit, offset};
        } else {
            sql = "SELECT server_name, action, room_id, result, decision_source, "
                  "ban_id, checked_ts, latency_us FROM ban_enforcement_log "
                  "ORDER BY checked_ts DESC LIMIT ? OFFSET ?";
            params = {limit, offset};
        }
        auto rows = txn.select(sql, params);
        for (auto& row : rows) {
            json j;
            j["server_name"] = row->get<std::string>(0);
            j["action"] = row->get<std::string>(1);
            j["room_id"] = row->get<std::string>(2);
            j["result"] = row->get<std::string>(3);
            j["decision_source"] = row->get<std::string>(4);
            j["ban_id"] = row->get<int64_t>(5);
            j["checked_ts"] = row->get<int64_t>(6);
            j["latency_us"] = row->get<int64_t>(7);
            result.push_back(j);
        }
        return result;
    }

    int64_t count_enforcement_log_txn(LoggingTransaction& txn,
                                       const std::string& server_name = "") {
        if (!server_name.empty()) {
            auto row = txn.select_one(
                "SELECT COUNT(*) FROM ban_enforcement_log WHERE server_name = ?",
                {server_name});
            return row ? row->get<int64_t>(0) : 0;
        }
        auto row = txn.select_one("SELECT COUNT(*) FROM ban_enforcement_log");
        return row ? row->get<int64_t>(0) : 0;
    }

    void purge_old_enforcement_log_txn(LoggingTransaction& txn,
                                        int64_t older_than_ms) {
        txn.execute("DELETE FROM ban_enforcement_log WHERE checked_ts < ?",
                     {older_than_ms});
    }

    // ---------- Subscription CRUD ----------

    int64_t add_subscription_txn(LoggingTransaction& txn,
                                  const std::string& room_id,
                                  const std::string& server_name,
                                  const std::string& display_name,
                                  const std::string& subscribed_by,
                                  bool auto_apply = true) {
        txn.execute(
            "INSERT OR REPLACE INTO ban_list_subscriptions "
            "(room_id, server_name, display_name, subscribed_by, subscribed_ts, "
            "last_synced_ts, is_active, auto_apply, last_event_id) "
            "VALUES (?, ?, ?, ?, ?, ?, 1, ?, '')",
            {room_id, server_name, display_name, subscribed_by, now_ms(),
             now_ms(), auto_apply ? 1 : 0});
        return txn.last_insert_rowid();
    }

    bool remove_subscription_txn(LoggingTransaction& txn,
                                   const std::string& room_id) {
        txn.execute("DELETE FROM ban_list_subscriptions WHERE room_id = ?",
                     {room_id});
        return true;
    }

    void update_subscription_sync_ts_txn(LoggingTransaction& txn,
                                          const std::string& room_id,
                                          int64_t synced_ts,
                                          const std::string& last_event_id = "") {
        txn.execute(
            "UPDATE ban_list_subscriptions SET last_synced_ts = ?, "
            "last_event_id = ? WHERE room_id = ?",
            {synced_ts, last_event_id, room_id});
    }

    json get_subscription_txn(LoggingTransaction& txn,
                               const std::string& room_id) {
        auto row = txn.select_one(
            "SELECT room_id, server_name, display_name, subscribed_by, "
            "subscribed_ts, last_synced_ts, is_active, auto_apply, "
            "last_event_id, notes FROM ban_list_subscriptions "
            "WHERE room_id = ?", {room_id});
        if (!row) return json::object();
        json j;
        j["room_id"] = row->get<std::string>(0);
        j["server_name"] = row->get<std::string>(1);
        j["display_name"] = row->get<std::string>(2);
        j["subscribed_by"] = row->get<std::string>(3);
        j["subscribed_ts"] = row->get<int64_t>(4);
        j["last_synced_ts"] = row->get<int64_t>(5);
        j["is_active"] = row->get<int64_t>(6) != 0;
        j["auto_apply"] = row->get<int64_t>(7) != 0;
        j["last_event_id"] = row->get<std::string>(8);
        j["notes"] = row->get<std::string>(9);
        return j;
    }

    json get_all_active_subscriptions_txn(LoggingTransaction& txn) {
        json result = json::array();
        auto rows = txn.select(
            "SELECT room_id, server_name, display_name, subscribed_by, "
            "subscribed_ts, last_synced_ts, is_active, auto_apply, "
            "last_event_id, notes FROM ban_list_subscriptions "
            "WHERE is_active = 1 ORDER BY subscribed_ts ASC");
        for (auto& row : rows) {
            json j;
            j["room_id"] = row->get<std::string>(0);
            j["server_name"] = row->get<std::string>(1);
            j["display_name"] = row->get<std::string>(2);
            j["subscribed_by"] = row->get<std::string>(3);
            j["subscribed_ts"] = row->get<int64_t>(4);
            j["last_synced_ts"] = row->get<int64_t>(5);
            j["is_active"] = row->get<int64_t>(6) != 0;
            j["auto_apply"] = row->get<int64_t>(7) != 0;
            j["last_event_id"] = row->get<std::string>(8);
            j["notes"] = row->get<std::string>(9);
            result.push_back(j);
        }
        return result;
    }

    int64_t count_active_subscriptions_txn(LoggingTransaction& txn) {
        auto row = txn.select_one(
            "SELECT COUNT(*) FROM ban_list_subscriptions WHERE is_active = 1");
        return row ? row->get<int64_t>(0) : 0;
    }

    // ---------- Override CRUD ----------

    int64_t add_override_txn(LoggingTransaction& txn,
                              const std::string& room_id,
                              int64_t ban_id,
                              const std::string& ban_type,
                              const std::string& override_type,
                              const std::string& reason,
                              const std::string& set_by,
                              int64_t expires_ts = 0) {
        txn.execute(
            "INSERT INTO ban_overrides (room_id, ban_id, ban_type, override_type, "
            "reason, set_by, set_ts, expires_ts, is_active) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)",
            {room_id, ban_id, ban_type, override_type, reason, set_by,
             now_ms(), expires_ts});
        return txn.last_insert_rowid();
    }

    bool remove_override_txn(LoggingTransaction& txn, int64_t id) {
        txn.execute("UPDATE ban_overrides SET is_active = 0 WHERE id = ?", {id});
        return true;
    }

    bool has_override_txn(LoggingTransaction& txn,
                           const std::string& room_id,
                           int64_t ban_id,
                           const std::string& ban_type) {
        auto row = txn.select_one(
            "SELECT id FROM ban_overrides WHERE room_id = ? AND ban_id = ? "
            "AND ban_type = ? AND is_active = 1 "
            "AND (expires_ts = 0 OR expires_ts > ?)",
            {room_id, ban_id, ban_type, now_ms()});
        return row.has_value();
    }

    json get_overrides_for_room_txn(LoggingTransaction& txn,
                                     const std::string& room_id) {
        json result = json::array();
        auto rows = txn.select(
            "SELECT id, room_id, ban_id, ban_type, override_type, reason, "
            "set_by, set_ts, expires_ts, is_active FROM ban_overrides "
            "WHERE room_id = ? AND is_active = 1 "
            "AND (expires_ts = 0 OR expires_ts > ?) "
            "ORDER BY set_ts DESC",
            {room_id, now_ms()});
        for (auto& row : rows) {
            json j;
            j["id"] = row->get<int64_t>(0);
            j["room_id"] = row->get<std::string>(1);
            j["ban_id"] = row->get<int64_t>(2);
            j["ban_type"] = row->get<std::string>(3);
            j["override_type"] = row->get<std::string>(4);
            j["reason"] = row->get<std::string>(5);
            j["set_by"] = row->get<std::string>(6);
            j["set_ts"] = row->get<int64_t>(7);
            j["expires_ts"] = row->get<int64_t>(8);
            j["is_active"] = row->get<int64_t>(9) != 0;
            result.push_back(j);
        }
        return result;
    }

    // ---------- Statistics ----------

    BanListStats get_stats_txn(LoggingTransaction& txn) {
        BanListStats stats;
        stats.total_server_bans = count_server_bans_txn(txn, false);
        stats.active_server_bans = count_server_bans_txn(txn, true);
        stats.total_ip_bans = count_ip_bans_txn(txn, false);
        stats.active_ip_bans = count_ip_bans_txn(txn, true);
        stats.total_user_bans = count_user_bans_txn(txn, false);
        stats.active_user_bans = count_user_bans_txn(txn, true);
        stats.total_room_bans = count_room_bans_txn(txn, false);
        stats.active_room_bans = count_room_bans_txn(txn, true);
        stats.total_enforcement_checks = count_enforcement_log_txn(txn);
        // Count blocks specifically
        auto blocks_row = txn.select_one(
            "SELECT COUNT(*) FROM ban_enforcement_log WHERE result != 'allowed'");
        stats.total_blocks = blocks_row ? blocks_row->get<int64_t>(0) : 0;
        stats.imports_count = count_imports_txn(txn);
        stats.active_subscriptions = count_active_subscriptions_txn(txn);
        // Last sync time
        auto sync_row = txn.select_one(
            "SELECT MAX(synced_ts) FROM ban_sync_log WHERE status = 'completed'");
        stats.last_sync_ts = sync_row && !sync_row->is_null(0)
            ? sync_row->get<int64_t>(0) : 0;
        return stats;
    }

    // ---------- Maintenance ----------

    void delete_all_expired_txn(LoggingTransaction& txn) {
        delete_expired_server_bans_txn(txn);
        delete_expired_ip_bans_txn(txn);
        delete_expired_user_bans_txn(txn);
        delete_expired_room_bans_txn(txn);
    }

private:
    DatabasePool& db_;
    BanLogger& logger_;
};

// ============================================================================
// 2. ServerBanListManager — Server-wide server ban management
// ============================================================================

class ServerBanListManager {
public:
    ServerBanListManager(DatabasePool& db, BanLogger& logger)
        : store_(db, logger), db_(db), logger_(logger) {}

    // Add a server ban
    json add_ban(const std::string& server_name,
                 const std::string& reason,
                 const std::string& banned_by,
                 MatchType match_type = MatchType::EXACT,
                 BanLevel level = BanLevel::HARD,
                 int64_t expires_ts = 0,
                 const std::string& notes = "") {
        ServerBanEntry entry;
        entry.server_name = to_lower(server_name);
        entry.match_type = match_type;
        entry.reason = reason;
        entry.banned_by = banned_by;
        entry.banned_ts = now_ms();
        entry.expires_ts = expires_ts;
        entry.is_active = true;
        entry.level = level;
        entry.notes = notes;

        logger_.info("Adding server ban for '" + server_name +
                     "' by '" + banned_by + "' reason: " + reason);

        return db_.with_write_txn([&](LoggingTransaction& txn) -> json {
            int64_t id = store_.add_server_ban_txn(txn, entry);
            auto entry_opt = store_.get_server_ban_txn(txn, id);
            json result;
            result["success"] = true;
            result["ban_id"] = id;
            if (entry_opt) {
                result["entry"] = entry_opt->to_json();
            }
            return result;
        });
    }

    // Remove (deactivate) a server ban
    json remove_ban(int64_t ban_id, const std::string& removed_by) {
        logger_.info("Removing server ban #" + std::to_string(ban_id) +
                     " by '" + removed_by + "'");
        return db_.with_write_txn([&](LoggingTransaction& txn) -> json {
            store_.deactivate_server_ban_txn(txn, ban_id);
            json result;
            result["success"] = true;
            result["ban_id"] = ban_id;
            return result;
        });
    }

    // Delete a server ban permanently
    json delete_ban(int64_t ban_id) {
        logger_.info("Permanently deleting server ban #" + std::to_string(ban_id));
        return db_.with_write_txn([&](LoggingTransaction& txn) -> json {
            store_.delete_server_ban_txn(txn, ban_id);
            json result;
            result["success"] = true;
            result["ban_id"] = ban_id;
            return result;
        });
    }

    // Check if a server is banned
    BanCheckResponse check_server(const std::string& server_name) {
        BanCheckResponse response;
        response.checked_ts = now_ms();
        auto lower_name = to_lower(server_name);

        db_.with_read_txn([&](LoggingTransaction& txn) {
            auto bans = store_.get_server_bans_by_name_txn(txn, lower_name);
            if (bans.empty()) {
                // Check domain suffix and glob matches
                auto all_active = store_.get_all_active_server_bans_txn(txn, 10000);
                for (auto& ban : all_active) {
                    bool matched = false;
                    switch (ban.match_type) {
                        case MatchType::EXACT:
                            matched = (to_lower(ban.server_name) == lower_name);
                            break;
                        case MatchType::DOMAIN_SUFFIX:
                            matched = ends_with(lower_name,
                                                to_lower(ban.server_name));
                            break;
                        case MatchType::GLOB:
                            matched = glob_match(to_lower(ban.server_name),
                                                 lower_name);
                            break;
                        case MatchType::REGEX:
                            try {
                                std::regex re(ban.server_name);
                                matched = std::regex_match(lower_name, re);
                            } catch (...) {}
                            break;
                        case MatchType::WILDCARD:
                            matched = true;
                            break;
                        default:
                            break;
                    }
                    if (matched) {
                        bans.push_back(ban);
                    }
                }
            }
            if (!bans.empty()) {
                response.result = BanCheckResult::BANNED_SERVER;
                response.matched_rule = "server_ban:" + bans[0].server_name;
                response.level = bans[0].level;
                response.reason = bans[0].reason;
                response.ban_id = bans[0].id;
                response.is_shadow = (bans[0].level == BanLevel::SHADOW);
            }
        });

        return response;
    }

    // List all server bans
    json list_bans(bool active_only = true, int limit = 1000, int offset = 0) {
        return db_.with_read_txn([&](LoggingTransaction& txn) -> json {
            json result = json::array();
            std::vector<ServerBanEntry> entries;
            if (active_only) {
                entries = store_.get_all_active_server_bans_txn(txn, limit, offset);
            } else {
                entries = store_.get_all_server_bans_txn(txn, limit, offset);
            }
            for (auto& entry : entries) {
                result.push_back(entry.to_json());
            }
            return result;
        });
    }

    // Update a server ban
    json update_ban(int64_t ban_id, const json& updates) {
        return db_.with_write_txn([&](LoggingTransaction& txn) -> json {
            store_.update_server_ban_txn(txn, ban_id, updates);
            auto entry = store_.get_server_ban_txn(txn, ban_id);
            json result;
            result["success"] = true;
            result["ban_id"] = ban_id;
            if (entry) result["entry"] = entry->to_json();
            return result;
        });
    }

    // Search server bans
    json search_bans(const std::string& query, int limit = 100) {
        return db_.with_read_txn([&](LoggingTransaction& txn) -> json {
            json result = json::array();
            auto rows = txn.select(
                "SELECT id, server_name, match_type, reason, banned_by, "
                "banned_ts, expires_ts, is_active, level, notes, import_source "
                "FROM server_bans WHERE server_name LIKE ? "
                "ORDER BY banned_ts DESC LIMIT ?",
                {"%" + query + "%", limit});
            for (auto& row : rows) {
                result.push_back(row_to_server_ban(row).to_json());
            }
            return result;
        });
    }

    // Cleanup expired bans
    json cleanup_expired() {
        return db_.with_write_txn([&](LoggingTransaction& txn) -> json {
            store_.delete_expired_server_bans_txn(txn);
            json result;
            result["success"] = true;
            result["message"] = "Expired server bans deactivated";
            return result;
        });
    }

private:
    BanListStore store_;
    DatabasePool& db_;
    BanLogger& logger_;
};

// ============================================================================
// 3. IPBanListManager — IP address ban management
// ============================================================================

class IPBanListManager {
public:
    IPBanListManager(DatabasePool& db, BanLogger& logger)
        : store_(db, logger), db_(db), logger_(logger) {}

    // Add an IP ban
    json add_ban(const std::string& ip_address,
                 const std::string& reason,
                 const std::string& banned_by,
                 int prefix_length = -1,
                 BanLevel level = BanLevel::HARD,
                 int64_t expires_ts = 0,
                 const std::string& notes = "") {
        IPBanEntry entry;
        entry.ip_address = ip_address;
        entry.prefix_length = prefix_length;
        // Detect IPv6
        entry.is_ipv6 = (ip_address.find(':') != std::string::npos);
        entry.reason = reason;
        entry.banned_by = banned_by;
        entry.banned_ts = now_ms();
        entry.expires_ts = expires_ts;
        entry.is_active = true;
        entry.level = level;
        entry.notes = notes;

        logger_.info("Adding IP ban for '" + ip_address +
                     "' by '" + banned_by + "' reason: " + reason);

        return db_.with_write_txn([&](LoggingTransaction& txn) -> json {
            int64_t id = store_.add_ip_ban_txn(txn, entry);
            json result;
            result["success"] = true;
            result["ban_id"] = id;
            result["ip_address"] = ip_address;
            return result;
        });
    }

    // Remove (deactivate) an IP ban
    json remove_ban(int64_t ban_id, const std::string& removed_by) {
        logger_.info("Removing IP ban #" + std::to_string(ban_id) +
                     " by '" + removed_by + "'");
        return db_.with_write_txn([&](LoggingTransaction& txn) -> json {
            store_.deactivate_ip_ban_txn(txn, ban_id);
            json result;
            result["success"] = true;
            result["ban_id"] = ban_id;
            return result;
        });
    }

    // Delete an IP ban permanently
    json delete_ban(int64_t ban_id) {
        return db_.with_write_txn([&](LoggingTransaction& txn) -> json {
            store_.delete_ip_ban_txn(txn, ban_id);
            json result;
            result["success"] = true;
            result["ban_id"] = ban_id;
            return result;
        });
    }

    // Check if an IP is banned
    BanCheckResponse check_ip(const std::string& ip_address) {
        BanCheckResponse response;
        response.checked_ts = now_ms();

        db_.with_read_txn([&](LoggingTransaction& txn) {
            auto all_bans = store_.get_all_active_ip_bans_txn(txn, 10000);
            bool is_v6 = (ip_address.find(':') != std::string::npos);

            for (auto& ban : all_bans) {
                if (ban.is_ipv6 != is_v6) continue;

                bool matched = false;
                if (ban.prefix_length >= 0) {
                    // CIDR match
                    if (is_v6) {
                        auto ip_parsed = parse_ipv6(ip_address);
                        if (ip_parsed) {
                            matched = ipv6_matches_cidr(*ip_parsed, ban.ip_address);
                        }
                    } else {
                        auto ip_parsed = parse_ipv4(ip_address);
                        if (ip_parsed) {
                            matched = ipv4_matches_cidr(*ip_parsed, ban.ip_address);
                        }
                    }
                } else {
                    // Exact IP match
                    matched = (ban.ip_address == ip_address);
                }

                if (matched) {
                    response.result = BanCheckResult::BANNED_IP;
                    response.matched_rule = "ip_ban:" + ban.ip_address +
                                            (ban.prefix_length >= 0
                                                 ? "/" + std::to_string(ban.prefix_length)
                                                 : "");
                    response.level = ban.level;
                    response.reason = ban.reason;
                    response.ban_id = ban.id;
                    response.is_shadow = (ban.level == BanLevel::SHADOW);
                    return;
                }
            }
        });

        return response;
    }

    // Bulk check if any IPs in a list are banned
    std::vector<BanCheckResponse> check_ips(const std::vector<std::string>& ips) {
        std::vector<BanCheckResponse> results;
        results.reserve(ips.size());
        for (const auto& ip : ips) {
            results.push_back(check_ip(ip));
        }
        return results;
    }

    // List all IP bans
    json list_bans(bool active_only = true, int limit = 1000, int offset = 0) {
        return db_.with_read_txn([&](LoggingTransaction& txn) -> json {
            json result = json::array();
            std::vector<IPBanEntry> entries;
            if (active_only) {
                entries = store_.get_all_active_ip_bans_txn(txn, limit, offset);
            } else {
                entries = store_.get_all_ip_bans_txn(txn, limit, offset);
            }
            for (auto& entry : entries) {
                result.push_back(entry.to_json());
            }
            return result;
        });
    }

    // Cleanup expired IP bans
    json cleanup_expired() {
        return db_.with_write_txn([&](LoggingTransaction& txn) -> json {
            store_.delete_expired_ip_bans_txn(txn);
            json result;
            result["success"] = true;
            result["message"] = "Expired IP bans deactivated";
            return result;
        });
    }

private:
    BanListStore store_;
    DatabasePool& db_;
    BanLogger& logger_;
};

// ============================================================================
// 4. UserBanListManager — User ban management
// ============================================================================

class UserBanListManager {
public:
    UserBanListManager(DatabasePool& db, BanLogger& logger)
        : store_(db, logger), db_(db), logger_(logger) {}

    // Add a user ban
    json add_ban(const std::string& user_id,
                 const std::string& reason,
                 const std::string& banned_by,
                 MatchType match_type = MatchType::EXACT,
                 BanLevel level = BanLevel::HARD,
                 bool shadow_ban = false,
                 int64_t expires_ts = 0,
                 const std::string& notes = "") {
        UserBanEntry entry;
        entry.user_id = user_id;
        entry.match_type = match_type;
        entry.reason = reason;
        entry.banned_by = banned_by;
        entry.banned_ts = now_ms();
        entry.expires_ts = expires_ts;
        entry.is_active = true;
        entry.level = level;
        entry.shadow_ban = shadow_ban;
        entry.notes = notes;

        logger_.info("Adding user ban for '" + user_id +
                     "' by '" + banned_by + "'"
                     + (shadow_ban ? " [SHADOW]" : ""));

        return db_.with_write_txn([&](LoggingTransaction& txn) -> json {
            int64_t id = store_.add_user_ban_txn(txn, entry);
            auto entry_opt = store_.get_user_ban_txn(txn, id);
            json result;
            result["success"] = true;
            result["ban_id"] = id;
            if (entry_opt) result["entry"] = entry_opt->to_json();
            return result;
        });
    }

    // Remove a user ban
    json remove_ban(int64_t ban_id, const std::string& removed_by) {
        logger_.info("Removing user ban #" + std::to_string(ban_id) +
                     " by '" + removed_by + "'");
        return db_.with_write_txn([&](LoggingTransaction& txn) -> json {
            store_.deactivate_user_ban_txn(txn, ban_id);
            json result;
            result["success"] = true;
            result["ban_id"] = ban_id;
            return result;
        });
    }

    // Delete a user ban permanently
    json delete_ban(int64_t ban_id) {
        return db_.with_write_txn([&](LoggingTransaction& txn) -> json {
            store_.delete_user_ban_txn(txn, ban_id);
            json result;
            result["success"] = true;
            result["ban_id"] = ban_id;
            return result;
        });
    }

    // Check if a user is banned
    BanCheckResponse check_user(const std::string& user_id) {
        BanCheckResponse response;
        response.checked_ts = now_ms();

        db_.with_read_txn([&](LoggingTransaction& txn) {
            // Direct ban check
            auto direct_bans = store_.get_user_bans_by_user_id_txn(txn, user_id);
            if (!direct_bans.empty()) {
                response.result = BanCheckResult::BANNED_USER;
                response.matched_rule = "user_ban:" + direct_bans[0].user_id;
                response.level = direct_bans[0].level;
                response.reason = direct_bans[0].reason;
                response.ban_id = direct_bans[0].id;
                response.is_shadow = direct_bans[0].shadow_ban;
                return;
            }

            // Pattern-based bans
            auto all_active = store_.get_all_active_user_bans_txn(txn, 10000);
            for (auto& ban : all_active) {
                bool matched = false;
                switch (ban.match_type) {
                    case MatchType::EXACT:
                        matched = (ban.user_id == user_id);
                        break;
                    case MatchType::DOMAIN_SUFFIX: {
                        std::string domain = extract_server_from_user_id(user_id);
                        matched = !domain.empty() && ends_with(domain, ban.user_id);
                        break;
                    }
                    case MatchType::GLOB:
                        matched = glob_match(ban.user_id, user_id);
                        break;
                    case MatchType::REGEX:
                        try {
                            std::regex re(ban.user_id);
                            matched = std::regex_match(user_id, re);
                        } catch (...) {}
                        break;
                    case MatchType::WILDCARD:
                        matched = true;
                        break;
                    default:
                        break;
                }
                if (matched) {
                    response.result = BanCheckResult::BANNED_USER;
                    response.matched_rule = "user_ban_pattern:" + ban.user_id;
                    response.level = ban.level;
                    response.reason = ban.reason;
                    response.ban_id = ban.id;
                    response.is_shadow = ban.shadow_ban;
                    return;
                }
            }

            // Also check server bans for this user's server
            auto server = extract_server_from_user_id(user_id);
            if (!server.empty()) {
                auto all_server_bans = store_.get_all_active_server_bans_txn(
                    txn, 10000);
                for (auto& sban : all_server_bans) {
                    if (sban.server_name == server ||
                        (sban.match_type == MatchType::DOMAIN_SUFFIX &&
                         ends_with(server, sban.server_name))) {
                        response.result = BanCheckResult::BANNED_SERVER;
                        response.matched_rule = "server_ban_affects_user:" +
                                                sban.server_name;
                        response.level = sban.level;
                        response.reason = sban.reason;
                        response.ban_id = sban.id;
                        return;
                    }
                }
            }
        });

        return response;
    }

    // List all user bans
    json list_bans(bool active_only = true, int limit = 1000, int offset = 0) {
        return db_.with_read_txn([&](LoggingTransaction& txn) -> json {
            json result = json::array();
            std::vector<UserBanEntry> entries;
            if (active_only) {
                entries = store_.get_all_active_user_bans_txn(txn, limit, offset);
            } else {
                entries = store_.get_all_user_bans_txn(txn, limit, offset);
            }
            for (auto& entry : entries) {
                result.push_back(entry.to_json());
            }
            return result;
        });
    }

    // Cleanup expired user bans
    json cleanup_expired() {
        return db_.with_write_txn([&](LoggingTransaction& txn) -> json {
            store_.delete_expired_user_bans_txn(txn);
            json result;
            result["success"] = true;
            result["message"] = "Expired user bans deactivated";
            return result;
        });
    }

private:
    BanListStore store_;
    DatabasePool& db_;
    BanLogger& logger_;
};

// ============================================================================
// 5. PerRoomBanListManager — Per-room ban list management
// ============================================================================

class PerRoomBanListManager {
public:
    PerRoomBanListManager(DatabasePool& db, BanLogger& logger)
        : store_(db, logger), db_(db), logger_(logger) {}

    // Add a per-room ban
    json add_ban(const std::string& room_id,
                 const std::string& banned_entity,
                 BanEntityType entity_type,
                 const std::string& reason,
                 const std::string& banned_by,
                 MatchType match_type = MatchType::EXACT,
                 BanLevel level = BanLevel::HARD,
                 int64_t expires_ts = 0,
                 const std::string& notes = "") {
        RoomBanEntry entry;
        entry.room_id = room_id;
        entry.banned_entity = banned_entity;
        entry.entity_type = entity_type;
        entry.match_type = match_type;
        entry.reason = reason;
        entry.banned_by = banned_by;
        entry.banned_ts = now_ms();
        entry.expires_ts = expires_ts;
        entry.is_active = true;
        entry.level = level;
        entry.notes = notes;

        std::string type_str = ban_entity_type_str(entity_type);
        logger_.info("Adding room ban in '" + room_id + "' for " +
                     type_str + " '" + banned_entity + "' by '" + banned_by + "'");

        return db_.with_write_txn([&](LoggingTransaction& txn) -> json {
            // Check if override exists
            auto existing = store_.get_room_bans_txn(txn, room_id, 10000);
            for (auto& eb : existing) {
                if (eb.banned_entity == banned_entity &&
                    eb.entity_type == entity_type && eb.is_active) {
                    json result;
                    result["success"] = false;
                    result["error"] = "Entity already banned in this room";
                    result["existing_ban_id"] = eb.id;
                    return result;
                }
            }
            int64_t id = store_.add_room_ban_txn(txn, entry);
            json result;
            result["success"] = true;
            result["ban_id"] = id;
            result["room_id"] = room_id;
            return result;
        });
    }

    // Remove a per-room ban
    json remove_ban(int64_t ban_id, const std::string& removed_by) {
        logger_.info("Removing room ban #" + std::to_string(ban_id) +
                     " by '" + removed_by + "'");
        return db_.with_write_txn([&](LoggingTransaction& txn) -> json {
            store_.deactivate_room_ban_txn(txn, ban_id);
            json result;
            result["success"] = true;
            result["ban_id"] = ban_id;
            return result;
        });
    }

    // Delete a per-room ban permanently
    json delete_ban(int64_t ban_id) {
        return db_.with_write_txn([&](LoggingTransaction& txn) -> json {
            store_.delete_room_ban_txn(txn, ban_id);
            json result;
            result["success"] = true;
            result["ban_id"] = ban_id;
            return result;
        });
    }

    // Check if an entity is banned in a specific room
    BanCheckResponse check_room_ban(const std::string& room_id,
                                     const BanCheckRequest& request) {
        BanCheckResponse response;
        response.checked_ts = now_ms();

        db_.with_read_txn([&](LoggingTransaction& txn) {
            auto room_bans = store_.get_room_bans_txn(txn, room_id, 10000);

            for (auto& ban : room_bans) {
                bool matched = false;
                switch (ban.entity_type) {
                    case BanEntityType::SERVER:
                        if (!request.server_name.empty()) {
                            matched = entity_matches(
                                ban.banned_entity, request.server_name,
                                ban.match_type);
                        }
                        break;
                    case BanEntityType::USER:
                        if (!request.user_id.empty()) {
                            matched = entity_matches(
                                ban.banned_entity, request.user_id,
                                ban.match_type);
                        }
                        break;
                    case BanEntityType::IP:
                        if (!request.ip_address.empty()) {
                            matched = entity_matches(
                                ban.banned_entity, request.ip_address,
                                ban.match_type);
                        }
                        break;
                    default:
                        break;
                }
                if (matched) {
                    // Check for override
                    if (store_.has_override_txn(
                            txn, room_id, ban.id,
                            ban_entity_type_str(ban.entity_type))) {
                        continue; // override allows this entity
                    }
                    response.result = BanCheckResult::BANNED_ROOM;
                    response.matched_rule = "room_ban:" + ban.banned_entity;
                    response.level = ban.level;
                    response.reason = ban.reason;
                    response.ban_id = ban.id;
                    response.is_shadow = (ban.level == BanLevel::SHADOW);
                    return;
                }
            }
        });

        return response;
    }

    // List bans for a specific room
    json list_room_bans(const std::string& room_id,
                         int limit = 500, int offset = 0) {
        return db_.with_read_txn([&](LoggingTransaction& txn) -> json {
            json result = json::array();
            auto entries = store_.get_room_bans_txn(txn, room_id, limit, offset);
            for (auto& entry : entries) {
                result.push_back(entry.to_json());
            }
            return result;
        });
    }

    // Add an override for a room ban (allow specific entity despite ban)
    json add_override(const std::string& room_id,
                      int64_t ban_id,
                      const std::string& ban_type,
                      const std::string& reason,
                      const std::string& set_by,
                      int64_t expires_ts = 0) {
        return db_.with_write_txn([&](LoggingTransaction& txn) -> json {
            int64_t id = store_.add_override_txn(
                txn, room_id, ban_id, ban_type, "allow", reason, set_by,
                expires_ts);
            json result;
            result["success"] = true;
            result["override_id"] = id;
            return result;
        });
    }

    // Remove an override
    json remove_override(int64_t override_id) {
        return db_.with_write_txn([&](LoggingTransaction& txn) -> json {
            store_.remove_override_txn(txn, override_id);
            json result;
            result["success"] = true;
            result["override_id"] = override_id;
            return result;
        });
    }

    // List overrides for a room
    json list_overrides(const std::string& room_id) {
        return db_.with_read_txn([&](LoggingTransaction& txn) -> json {
            return store_.get_overrides_for_room_txn(txn, room_id);
        });
    }

    // Cleanup expired room bans
    json cleanup_expired() {
        return db_.with_write_txn([&](LoggingTransaction& txn) -> json {
            store_.delete_expired_room_bans_txn(txn);
            json result;
            result["success"] = true;
            result["message"] = "Expired room bans deactivated";
            return result;
        });
    }

private:
    static bool entity_matches(const std::string& pattern,
                                const std::string& entity,
                                MatchType match_type) {
        switch (match_type) {
            case MatchType::EXACT:
                return pattern == entity;
            case MatchType::DOMAIN_SUFFIX:
                return ends_with(entity, pattern);
            case MatchType::GLOB:
                return glob_match(pattern, entity);
            case MatchType::REGEX:
                try {
                    std::regex re(pattern);
                    return std::regex_match(entity, re);
                } catch (...) {
                    return false;
                }
            case MatchType::WILDCARD:
                return true;
            default:
                return false;
        }
    }

    BanListStore store_;
    DatabasePool& db_;
    BanLogger& logger_;
};

// ============================================================================
// 6. BanListImporter — Import bans from various sources
// ============================================================================

class BanListImporter {
public:
    BanListImporter(DatabasePool& db,
                    ServerBanListManager& server_mgr,
                    IPBanListManager& ip_mgr,
                    UserBanListManager& user_mgr,
                    PerRoomBanListManager& room_mgr,
                    BanLogger& logger)
        : store_(db, logger), db_(db),
          server_mgr_(server_mgr), ip_mgr_(ip_mgr),
          user_mgr_(user_mgr), room_mgr_(room_mgr),
          logger_(logger) {}

    // Import from a JSON file
    json import_from_json_file(const std::string& file_path,
                                const std::string& imported_by) {
        if (!fs::exists(file_path)) {
            json err;
            err["success"] = false;
            err["error"] = "File not found: " + file_path;
            return err;
        }
        std::ifstream file(file_path);
        if (!file.is_open()) {
            json err;
            err["success"] = false;
            err["error"] = "Cannot open file: " + file_path;
            return err;
        }
        json data;
        try {
            file >> data;
        } catch (const std::exception& e) {
            json err;
            err["success"] = false;
            err["error"] = std::string("JSON parse error: ") + e.what();
            return err;
        }
        return import_from_json(data, ImportSourceType::JSON_FILE,
                                file_path, imported_by);
    }

    // Import from parsed JSON data (supports Matrix policy list format and
    // custom format)
    json import_from_json(const json& data,
                           ImportSourceType source_type,
                           const std::string& source,
                           const std::string& imported_by) {
        std::string import_id;
        int total_imported = 0;

        db_.with_write_txn([&](LoggingTransaction& txn) {
            // Create import record
            int entry_count = 0;
            if (data.is_array()) entry_count = data.size();
            else if (data.contains("entries")) {
                entry_count = data["entries"].size();
            }
            import_id = store_.add_import_record_txn(
                txn, source_type, source, imported_by, entry_count);

            // Process entries
            if (data.is_array()) {
                for (const auto& entry : data) {
                    if (process_single_entry_txn(txn, entry, import_id,
                                                  imported_by)) {
                        total_imported++;
                    }
                }
            } else if (data.contains("entries") && data["entries"].is_array()) {
                for (const auto& entry : data["entries"]) {
                    if (process_single_entry_txn(txn, entry, import_id,
                                                  imported_by)) {
                        total_imported++;
                    }
                }
            }
        });

        json result;
        result["success"] = true;
        result["import_id"] = import_id;
        result["entries_imported"] = total_imported;
        result["source"] = source;
        return result;
    }

    // Import from CSV data
    json import_from_csv(const std::string& csv_data,
                          const std::string& imported_by) {
        std::string import_id;
        int total_imported = 0;
        std::vector<std::vector<std::string>> parsed;
        std::istringstream stream(csv_data);
        std::string line;

        // Parse header
        std::vector<std::string> headers;
        if (std::getline(stream, line)) {
            headers = split(line, ',');
        }

        // Parse data lines
        while (std::getline(stream, line)) {
            auto fields = split(line, ',');
            if (!fields.empty()) parsed.push_back(fields);
        }

        db_.with_write_txn([&](LoggingTransaction& txn) {
            import_id = store_.add_import_record_txn(
                txn, ImportSourceType::CSV_FILE, "csv_input",
                imported_by, parsed.size());

            for (auto& row : parsed) {
                if (process_csv_row_txn(txn, row, headers, import_id,
                                         imported_by)) {
                    total_imported++;
                }
            }
        });

        json result;
        result["success"] = true;
        result["import_id"] = import_id;
        result["entries_imported"] = total_imported;
        return result;
    }

    // Import from Matrix policy list events (MSC2313)
    json import_from_policy_event(const json& event,
                                   const std::string& room_id,
                                   const std::string& imported_by) {
        std::string import_id;
        int total_imported = 0;

        auto event_type = event.value("type", "");
        auto rule_type = policy_rule_type_from_event_type(event_type);
        if (rule_type == PolicyRuleType::UNKNOWN) {
            json err;
            err["success"] = false;
            err["error"] = "Unknown policy event type: " + event_type;
            return err;
        }

        std::string entity;
        std::string recommendation_str = "m.ban";
        std::string reason;

        if (event.contains("content")) {
            const auto& content = event["content"];
            entity = content.value("entity", "");
            recommendation_str = content.value("recommendation", "m.ban");
            reason = content.value("reason", "");
        }

        if (entity.empty()) {
            json err;
            err["success"] = false;
            err["error"] = "Policy event missing 'entity' field";
            return err;
        }

        auto recommendation = policy_recommendation_from_str(recommendation_str);
        std::string event_id = event.value("event_id", "");

        db_.with_write_txn([&](LoggingTransaction& txn) {
            import_id = store_.add_import_record_txn(
                txn, ImportSourceType::MATRIX_ROOM, room_id, imported_by, 1);

            // Convert recommendation to ban level
            BanLevel level = BanLevel::HARD;
            switch (recommendation) {
                case PolicyRecommendation::BAN:     level = BanLevel::HARD; break;
                case PolicyRecommendation::SUSPEND: level = BanLevel::SOFT; break;
                case PolicyRecommendation::WARN:    level = BanLevel::WARN; break;
                case PolicyRecommendation::MUTE:    level = BanLevel::SHADOW; break;
                default: break;
            }

            BanEntityType entity_type;
            switch (rule_type) {
                case PolicyRuleType::SERVER:
                    entity_type = BanEntityType::SERVER;
                    break;
                case PolicyRuleType::USER:
                    entity_type = BanEntityType::USER;
                    break;
                case PolicyRuleType::ROOM:
                    entity_type = BanEntityType::ROOM;
                    break;
                default:
                    entity_type = BanEntityType::SERVER;
                    break;
            }

            store_.add_import_entry_txn(txn, import_id, entity_type, entity,
                                         reason, event_id);

            // Apply the ban based on entity type
            switch (entity_type) {
                case BanEntityType::SERVER: {
                    ServerBanEntry sban;
                    sban.server_name = entity;
                    sban.match_type = MatchType::EXACT;
                    sban.reason = reason;
                    sban.banned_by = imported_by;
                    sban.banned_ts = now_ms();
                    sban.level = level;
                    sban.import_source = import_id;
                    store_.add_server_ban_txn(txn, sban);
                    total_imported++;
                    break;
                }
                case BanEntityType::USER: {
                    UserBanEntry uban;
                    uban.user_id = entity;
                    uban.match_type = MatchType::EXACT;
                    uban.reason = reason;
                    uban.banned_by = imported_by;
                    uban.banned_ts = now_ms();
                    uban.level = level;
                    uban.shadow_ban = (level == BanLevel::SHADOW);
                    uban.import_source = import_id;
                    store_.add_user_ban_txn(txn, uban);
                    total_imported++;
                    break;
                }
                default:
                    break;
            }
        });

        json result;
        result["success"] = true;
        result["import_id"] = import_id;
        result["entries_imported"] = total_imported;
        return result;
    }

    // Get import history
    json get_import_history(int limit = 100, int offset = 0) {
        return db_.with_read_txn([&](LoggingTransaction& txn) -> json {
            return store_.get_all_imports_txn(txn, limit, offset);
        });
    }

    // Get details of a specific import
    json get_import_detail(const std::string& import_id) {
        return db_.with_read_txn([&](LoggingTransaction& txn) -> json {
            return store_.get_import_record_txn(txn, import_id);
        });
    }

    // Revert an import (remove all bans from that import)
    json revert_import(const std::string& import_id,
                        const std::string& reverted_by) {
        logger_.info("Reverting import '" + import_id +
                     "' by '" + reverted_by + "'");
        return db_.with_write_txn([&](LoggingTransaction& txn) -> json {
            store_.delete_server_bans_by_import_source_txn(txn, import_id);
            store_.delete_ip_bans_by_import_source_txn(txn, import_id);
            store_.delete_user_bans_by_import_source_txn(txn, import_id);
            store_.delete_room_bans_by_import_source_txn(txn, import_id);

            txn.execute("DELETE FROM ban_list_entries WHERE import_id = ?",
                         {import_id});
            txn.execute(
                "UPDATE ban_list_imports SET status = 'reverted' WHERE import_id = ?",
                {import_id});

            json result;
            result["success"] = true;
            result["import_id"] = import_id;
            result["message"] = "Import reverted successfully";
            return result;
        });
    }

private:
    bool process_single_entry_txn(LoggingTransaction& txn,
                                   const json& entry,
                                   const std::string& import_id,
                                   const std::string& imported_by) {
        if (!entry.is_object()) return false;

        std::string type_str = entry.value("entity_type",
                                entry.value("type", ""));
        std::string entity = entry.value("entity", entry.value("value", ""));
        std::string reason = entry.value("reason", "");

        if (entity.empty()) return false;

        BanEntityType entity_type;
        try {
            entity_type = ban_entity_type_from_str(type_str);
        } catch (...) {
            // Default to server type if unknown
            entity_type = BanEntityType::SERVER;
        }

        auto recommendation = policy_recommendation_from_str(
            entry.value("recommendation", "m.ban"));
        BanLevel level = recommendation_to_level(recommendation);

        store_.add_import_entry_txn(txn, import_id, entity_type, entity, reason);

        switch (entity_type) {
            case BanEntityType::SERVER: {
                ServerBanEntry sban;
                sban.server_name = entity;
                sban.reason = reason;
                sban.banned_by = imported_by;
                sban.banned_ts = now_ms();
                sban.level = level;
                sban.import_source = import_id;
                store_.add_server_ban_txn(txn, sban);
                return true;
            }
            case BanEntityType::USER: {
                UserBanEntry uban;
                uban.user_id = entity;
                uban.reason = reason;
                uban.banned_by = imported_by;
                uban.banned_ts = now_ms();
                uban.level = level;
                uban.shadow_ban = (level == BanLevel::SHADOW);
                uban.import_source = import_id;
                store_.add_user_ban_txn(txn, uban);
                return true;
            }
            case BanEntityType::IP: {
                IPBanEntry iban;
                iban.ip_address = entity;
                iban.reason = reason;
                iban.banned_by = imported_by;
                iban.banned_ts = now_ms();
                iban.level = level;
                iban.import_source = import_id;
                store_.add_ip_ban_txn(txn, iban);
                return true;
            }
            default:
                return false;
        }
    }

    bool process_csv_row_txn(LoggingTransaction& txn,
                              const std::vector<std::string>& row,
                              const std::vector<std::string>& headers,
                              const std::string& import_id,
                              const std::string& imported_by) {
        // Expect columns: entity_type, entity, reason
        if (row.size() < 2) return false;

        // Find column indices
        auto find_col = [&](const std::string& name) -> int {
            for (size_t i = 0; i < headers.size(); ++i) {
                if (to_lower(trim(headers[i])) == to_lower(name)) return i;
            }
            return -1;
        };

        int type_col = find_col("entity_type");
        int entity_col = find_col("entity");
        int reason_col = find_col("reason");

        if (entity_col < 0 || entity_col >= static_cast<int>(row.size()))
            return false;

        std::string entity = row[entity_col];
        std::string type = (type_col >= 0 && type_col < static_cast<int>(row.size()))
            ? row[type_col] : "server";
        std::string reason = (reason_col >= 0 && reason_col < static_cast<int>(row.size()))
            ? row[reason_col] : "";

        BanEntityType etype;
        try {
            etype = ban_entity_type_from_str(type);
        } catch (...) {
            etype = BanEntityType::SERVER;
        }

        store_.add_import_entry_txn(txn, import_id, etype, entity, reason);

        switch (etype) {
            case BanEntityType::SERVER: {
                ServerBanEntry sban;
                sban.server_name = entity;
                sban.reason = reason;
                sban.banned_by = imported_by;
                sban.banned_ts = now_ms();
                sban.import_source = import_id;
                store_.add_server_ban_txn(txn, sban);
                return true;
            }
            default:
                return false;
        }
    }

    static BanLevel recommendation_to_level(PolicyRecommendation r) {
        switch (r) {
            case PolicyRecommendation::BAN:     return BanLevel::HARD;
            case PolicyRecommendation::SUSPEND: return BanLevel::SOFT;
            case PolicyRecommendation::WARN:    return BanLevel::WARN;
            case PolicyRecommendation::MUTE:    return BanLevel::SHADOW;
            default:                            return BanLevel::HARD;
        }
    }

    BanListStore store_;
    DatabasePool& db_;
    ServerBanListManager& server_mgr_;
    IPBanListManager& ip_mgr_;
    UserBanListManager& user_mgr_;
    PerRoomBanListManager& room_mgr_;
    BanLogger& logger_;
};

// ============================================================================
// 7. BanListExporter — Export bans to various formats
// ============================================================================

class BanListExporter {
public:
    BanListExporter(DatabasePool& db, BanLogger& logger)
        : store_(db, logger), db_(db), logger_(logger) {}

    // Export all active bans as JSON
    json export_all_to_json(bool active_only = true) {
        json result;
        result["export_ts"] = now_ms();
        result["export_timestamp"] = iso8601_now();
        result["format_version"] = "1.0";

        db_.with_read_txn([&](LoggingTransaction& txn) {
            // Server bans
            result["server_bans"] = json::array();
            auto server_bans = active_only
                ? store_.get_all_active_server_bans_txn(txn, 100000)
                : store_.get_all_server_bans_txn(txn, 100000);
            for (auto& ban : server_bans) {
                result["server_bans"].push_back(ban.to_json());
            }

            // IP bans
            result["ip_bans"] = json::array();
            auto ip_bans = active_only
                ? store_.get_all_active_ip_bans_txn(txn, 100000)
                : store_.get_all_ip_bans_txn(txn, 100000);
            for (auto& ban : ip_bans) {
                result["ip_bans"].push_back(ban.to_json());
            }

            // User bans
            result["user_bans"] = json::array();
            auto user_bans = active_only
                ? store_.get_all_active_user_bans_txn(txn, 100000)
                : store_.get_all_user_bans_txn(txn, 100000);
            for (auto& ban : user_bans) {
                result["user_bans"].push_back(ban.to_json());
            }

            // Room bans
            result["room_bans"] = json::array();
            auto room_bans = active_only
                ? store_.get_all_room_bans_txn(txn, 100000)
                : store_.get_all_room_bans_txn(txn, 100000);
            for (auto& ban : room_bans) {
                result["room_bans"].push_back(ban.to_json());
            }
        });

        return result;
    }

    // Export as Matrix policy list format (MSC2313 compatible)
    json export_as_policy_list() {
        json result = json::array();

        db_.with_read_txn([&](LoggingTransaction& txn) {
            // Server bans as m.policy.rule.server
            auto server_bans = store_.get_all_active_server_bans_txn(txn, 100000);
            for (auto& ban : server_bans) {
                json rule;
                rule["type"] = "m.policy.rule.server";
                rule["state_key"] = ban.server_name;
                rule["content"]["entity"] = ban.server_name;
                rule["content"]["recommendation"] =
                    ban_level_to_recommendation(ban.level);
                rule["content"]["reason"] = ban.reason;
                result.push_back(rule);
            }

            // User bans as m.policy.rule.user
            auto user_bans = store_.get_all_active_user_bans_txn(txn, 100000);
            for (auto& ban : user_bans) {
                json rule;
                rule["type"] = "m.policy.rule.user";
                rule["state_key"] = ban.user_id;
                rule["content"]["entity"] = ban.user_id;
                rule["content"]["recommendation"] =
                    ban_level_to_recommendation(ban.level);
                rule["content"]["reason"] = ban.reason;
                result.push_back(rule);
            }
        });

        return result;
    }

    // Export to CSV format
    std::string export_to_csv(bool active_only = true) {
        std::ostringstream csv;
        csv << "entity_type,entity,reason,level,banned_by,banned_ts,expires_ts\n";

        db_.with_read_txn([&](LoggingTransaction& txn) {
            auto server_bans = active_only
                ? store_.get_all_active_server_bans_txn(txn, 100000)
                : store_.get_all_server_bans_txn(txn, 100000);
            for (auto& ban : server_bans) {
                csv << "server," << escape_csv(ban.server_name) << ","
                    << escape_csv(ban.reason) << "," << ban_level_str(ban.level)
                    << "," << escape_csv(ban.banned_by) << ","
                    << ban.banned_ts << "," << ban.expires_ts << "\n";
            }

            auto user_bans = active_only
                ? store_.get_all_active_user_bans_txn(txn, 100000)
                : store_.get_all_user_bans_txn(txn, 100000);
            for (auto& ban : user_bans) {
                csv << "user," << escape_csv(ban.user_id) << ","
                    << escape_csv(ban.reason) << "," << ban_level_str(ban.level)
                    << "," << escape_csv(ban.banned_by) << ","
                    << ban.banned_ts << "," << ban.expires_ts << "\n";
            }

            auto ip_bans = active_only
                ? store_.get_all_active_ip_bans_txn(txn, 100000)
                : store_.get_all_ip_bans_txn(txn, 100000);
            for (auto& ban : ip_bans) {
                csv << "ip," << escape_csv(ban.ip_address) << ","
                    << escape_csv(ban.reason) << "," << ban_level_str(ban.level)
                    << "," << escape_csv(ban.banned_by) << ","
                    << ban.banned_ts << "," << ban.expires_ts << "\n";
            }
        });

        return csv.str();
    }

    // Save export to file
    json save_to_file(const std::string& file_path,
                       const json& data,
                       bool pretty = true) {
        try {
            std::ofstream file(file_path);
            if (!file.is_open()) {
                json err;
                err["success"] = false;
                err["error"] = "Cannot write to file: " + file_path;
                return err;
            }
            if (pretty) {
                file << data.dump(2);
            } else {
                file << data.dump();
            }
            file.close();

            json result;
            result["success"] = true;
            result["file_path"] = file_path;
            result["size_bytes"] = fs::file_size(file_path);
            return result;
        } catch (const std::exception& e) {
            json err;
            err["success"] = false;
            err["error"] = std::string("File write error: ") + e.what();
            return err;
        }
    }

private:
    static std::string ban_level_to_recommendation(BanLevel level) {
        switch (level) {
            case BanLevel::WARN:       return "m.warn";
            case BanLevel::SOFT:       return "m.suspend";
            case BanLevel::HARD:       return "m.ban";
            case BanLevel::QUARANTINE: return "m.ban";
            case BanLevel::SHADOW:     return "m.mute";
            default:                   return "m.ban";
        }
    }

    static std::string escape_csv(const std::string& field) {
        if (field.find(',') == std::string::npos &&
            field.find('"') == std::string::npos &&
            field.find('\n') == std::string::npos) {
            return field;
        }
        std::string escaped = "\"";
        for (char c : field) {
            if (c == '"') escaped += "\"\"";
            else escaped += c;
        }
        escaped += "\"";
        return escaped;
    }

    BanListStore store_;
    DatabasePool& db_;
    BanLogger& logger_;
};

// ============================================================================
// 8. BanSynchronizer — Sync bans across federation / cluster nodes
// ============================================================================

class BanSynchronizer {
public:
    BanSynchronizer(DatabasePool& db,
                    BanListImporter& importer,
                    BanLogger& logger)
        : store_(db, logger), db_(db), importer_(importer), logger_(logger) {}

    // Subscribe to a remote ban list room
    json subscribe_to_list(const std::string& room_id,
                            const std::string& server_name,
                            const std::string& display_name,
                            const std::string& subscribed_by,
                            bool auto_apply = true) {
        logger_.info("Subscribing to ban list room '" + room_id +
                     "' on server '" + server_name + "'");
        return db_.with_write_txn([&](LoggingTransaction& txn) -> json {
            int64_t id = store_.add_subscription_txn(
                txn, room_id, server_name, display_name, subscribed_by,
                auto_apply);
            json result;
            result["success"] = true;
            result["subscription_id"] = id;
            result["room_id"] = room_id;
            return result;
        });
    }

    // Unsubscribe from a ban list room
    json unsubscribe_from_list(const std::string& room_id) {
        logger_.info("Unsubscribing from ban list room '" + room_id + "'");
        return db_.with_write_txn([&](LoggingTransaction& txn) -> json {
            store_.remove_subscription_txn(txn, room_id);
            json result;
            result["success"] = true;
            result["room_id"] = room_id;
            return result;
        });
    }

    // Sync from a remote ban list room (process new policy events)
    json sync_from_room(const std::string& room_id,
                         const json& policy_events,
                         const std::string& synced_by) {
        logger_.info("Syncing ban list from room '" + room_id + "'");
        int synced_count = 0;

        std::string last_event_id;
        db_.with_write_txn([&](LoggingTransaction& txn) {
            for (const auto& event : policy_events) {
                auto result = importer_.import_from_policy_event(
                    event, room_id, synced_by);
                if (result.value("success", false)) {
                    synced_count += result.value("entries_imported", 0);
                }
                if (event.contains("event_id")) {
                    last_event_id = event["event_id"].get<std::string>();
                }
            }
            store_.update_subscription_sync_ts_txn(
                txn, room_id, now_ms(), last_event_id);
            store_.add_sync_log_entry_txn(txn, room_id, "local", "pull",
                                           synced_count, "completed");
        });

        json result;
        result["success"] = true;
        result["room_id"] = room_id;
        result["synced_count"] = synced_count;
        return result;
    }

    // Push local bans to a remote node
    json push_to_node(const std::string& target_node,
                       const json& bans,
                       const std::string& pushed_by) {
        logger_.info("Pushing " + std::to_string(bans.size()) +
                     " bans to node '" + target_node + "'");
        db_.with_write_txn([&](LoggingTransaction& txn) {
            store_.add_sync_log_entry_txn(txn, "local", target_node, "push",
                                           bans.size(), "pending");
        });

        json result;
        result["success"] = true;
        result["target_node"] = target_node;
        result["ban_count"] = bans.size();
        return result;
    }

    // Receive bans pushed from a remote node
    json receive_from_node(const std::string& source_node,
                            const json& bans,
                            const std::string& received_by) {
        logger_.info("Receiving " + std::to_string(bans.size()) +
                     " bans from node '" + source_node + "'");
        int applied = 0;
        db_.with_write_txn([&](LoggingTransaction& txn) {
            for (const auto& ban : bans) {
                if (!ban.is_object()) continue;
                std::string type = ban.value("entity_type",
                                  ban.value("type", "server"));
                std::string entity = ban.value("entity",
                                    ban.value("server_name",
                                    ban.value("user_id",
                                    ban.value("ip_address", ""))));
                std::string reason = ban.value("reason", "synced from " + source_node);

                if (entity.empty()) continue;

                if (type == "server" || type == "0") {
                    ServerBanEntry sban;
                    sban.server_name = entity;
                    sban.reason = reason;
                    sban.banned_by = received_by;
                    sban.banned_ts = now_ms();
                    sban.import_source = "sync_" + source_node;
                    store_.add_server_ban_txn(txn, sban);
                    applied++;
                } else if (type == "user" || type == "1") {
                    UserBanEntry uban;
                    uban.user_id = entity;
                    uban.reason = reason;
                    uban.banned_by = received_by;
                    uban.banned_ts = now_ms();
                    uban.import_source = "sync_" + source_node;
                    store_.add_user_ban_txn(txn, uban);
                    applied++;
                } else if (type == "ip" || type == "2") {
                    IPBanEntry iban;
                    iban.ip_address = entity;
                    iban.reason = reason;
                    iban.banned_by = received_by;
                    iban.banned_ts = now_ms();
                    iban.import_source = "sync_" + source_node;
                    store_.add_ip_ban_txn(txn, iban);
                    applied++;
                }
            }
            store_.add_sync_log_entry_txn(txn, source_node, "local",
                                           "pull", applied, "completed");
        });

        json result;
        result["success"] = true;
        result["source_node"] = source_node;
        result["applied_count"] = applied;
        return result;
    }

    // Get all active subscriptions
    json get_subscriptions() {
        return db_.with_read_txn([&](LoggingTransaction& txn) -> json {
            return store_.get_all_active_subscriptions_txn(txn);
        });
    }

    // Get sync log
    json get_sync_log(int limit = 100, int offset = 0) {
        return db_.with_read_txn([&](LoggingTransaction& txn) -> json {
            return store_.get_sync_log_txn(txn, limit, offset);
        });
    }

    // Get list of subscribed rooms that need syncing (haven't been synced
    // in a while)
    json get_stale_subscriptions(int64_t stale_threshold_ms = 3600000) {
        return db_.with_read_txn([&](LoggingTransaction& txn) -> json {
            json result = json::array();
            auto now = now_ms();
            auto threshold = now - stale_threshold_ms;

            auto rows = txn.select(
                "SELECT room_id, server_name, display_name, last_synced_ts "
                "FROM ban_list_subscriptions WHERE is_active = 1 "
                "AND last_synced_ts < ? ORDER BY last_synced_ts ASC",
                {threshold});

            for (auto& row : rows) {
                json j;
                j["room_id"] = row->get<std::string>(0);
                j["server_name"] = row->get<std::string>(1);
                j["display_name"] = row->get<std::string>(2);
                j["last_synced_ts"] = row->get<int64_t>(3);
                j["staleness_ms"] = now - row->get<int64_t>(3);
                result.push_back(j);
            }
            return result;
        });
    }

private:
    BanListStore store_;
    DatabasePool& db_;
    BanListImporter& importer_;
    BanLogger& logger_;
};

// ============================================================================
// 9. FederationBanEnforcer — Enforce bans on federation traffic
// ============================================================================

class FederationBanEnforcer {
public:
    FederationBanEnforcer(DatabasePool& db,
                          ServerBanListManager& server_mgr,
                          IPBanListManager& ip_mgr,
                          UserBanListManager& user_mgr,
                          PerRoomBanListManager& room_mgr,
                          BanLogger& logger)
        : store_(db, logger), db_(db),
          server_mgr_(server_mgr), ip_mgr_(ip_mgr),
          user_mgr_(user_mgr), room_mgr_(room_mgr),
          logger_(logger) {}

    // Full ban check for a federation request
    BanCheckResponse check_federation_request(const BanCheckRequest& request) {
        auto start = chr::steady_clock::now();
        BanCheckResponse response;
        response.checked_ts = now_ms();

        // 1. Check server-level ban
        if (request.check_server && !request.server_name.empty()) {
            auto server_check = server_mgr_.check_server(request.server_name);
            if (server_check.result == BanCheckResult::BANNED_SERVER) {
                response = server_check;
                log_and_return(response, request, start);
                return response;
            }
        }

        // 2. Check IP ban
        if (request.check_ip && !request.ip_address.empty()) {
            auto ip_check = ip_mgr_.check_ip(request.ip_address);
            if (ip_check.result == BanCheckResult::BANNED_IP) {
                response = ip_check;
                log_and_return(response, request, start);
                return response;
            }
        }

        // 3. Check user ban
        if (request.check_user && !request.user_id.empty()) {
            auto user_check = user_mgr_.check_user(request.user_id);
            if (user_check.result == BanCheckResult::BANNED_USER ||
                user_check.result == BanCheckResult::BANNED_SERVER) {
                response = user_check;
                log_and_return(response, request, start);
                return response;
            }
        }

        // 4. Check room-level bans (if a room context exists)
        if (request.check_room && !request.room_id.empty()) {
            auto room_check = room_mgr_.check_room_ban(request.room_id, request);
            if (room_check.result == BanCheckResult::BANNED_ROOM) {
                response = room_check;
                log_and_return(response, request, start);
                return response;
            }
        }

        // Allowed
        response.result = BanCheckResult::ALLOWED;
        log_and_return(response, request, start);
        return response;
    }

    // Check specifically for a federation /send (transaction) endpoint
    BanCheckResponse check_transaction(const std::string& origin_server,
                                        const std::string& origin_ip,
                                        const std::string& txn_id) {
        BanCheckRequest req;
        req.server_name = origin_server;
        req.ip_address = origin_ip;
        req.action = FederationAction::SEND_TRANSACTION;

        return check_federation_request(req);
    }

    // Check for a /make_join request
    BanCheckResponse check_make_join(const std::string& origin_server,
                                      const std::string& room_id,
                                      const std::string& user_id) {
        BanCheckRequest req;
        req.server_name = origin_server;
        req.room_id = room_id;
        req.user_id = user_id;
        req.action = FederationAction::MAKE_JOIN;

        return check_federation_request(req);
    }

    // Check for a /send_join request
    BanCheckResponse check_send_join(const std::string& origin_server,
                                      const std::string& origin_ip,
                                      const std::string& room_id,
                                      const std::string& user_id) {
        BanCheckRequest req;
        req.server_name = origin_server;
        req.ip_address = origin_ip;
        req.room_id = room_id;
        req.user_id = user_id;
        req.action = FederationAction::SEND_JOIN;

        return check_federation_request(req);
    }

    // Check for an invite
    BanCheckResponse check_invite(const std::string& origin_server,
                                   const std::string& room_id,
                                   const std::string& sender_id,
                                   const std::string& target_user_id) {
        BanCheckRequest req;
        req.server_name = origin_server;
        req.room_id = room_id;
        req.user_id = sender_id;
        req.action = FederationAction::INVITE;

        auto resp = check_federation_request(req);

        // Also check the target user
        if (resp.result == BanCheckResult::ALLOWED && !target_user_id.empty()) {
            auto target_check = user_mgr_.check_user(target_user_id);
            if (target_check.result != BanCheckResult::ALLOWED) {
                resp = target_check;
            }
        }

        return resp;
    }

    // Check for a backfill request
    BanCheckResponse check_backfill(const std::string& origin_server,
                                     const std::string& room_id) {
        BanCheckRequest req;
        req.server_name = origin_server;
        req.room_id = room_id;
        req.action = FederationAction::BACKFILL;

        return check_federation_request(req);
    }

    // Check for a query (profile, directory, etc.)
    BanCheckResponse check_query(const std::string& origin_server,
                                  FederationAction action,
                                  const std::string& target_user = "") {
        BanCheckRequest req;
        req.server_name = origin_server;
        req.action = action;
        req.user_id = target_user;

        return check_federation_request(req);
    }

    // Check if a server is allowed to participate in a room at all
    BanCheckResponse check_room_participation(const std::string& server_name,
                                                const std::string& room_id) {
        BanCheckRequest req;
        req.server_name = server_name;
        req.room_id = room_id;
        req.check_user = false;
        req.check_ip = false;

        return check_federation_request(req);
    }

    // Bulk check a list of servers
    json bulk_check_servers(const std::vector<std::string>& servers) {
        json result = json::object();
        for (const auto& server : servers) {
            auto check = server_mgr_.check_server(server);
            result[server] = check.to_json();
        }
        return result;
    }

    // Get enforcement statistics for a server
    json get_server_enforcement_stats(const std::string& server_name = "") {
        return db_.with_read_txn([&](LoggingTransaction& txn) -> json {
            json stats;
            if (server_name.empty()) {
                stats["total_checks"] = store_.count_enforcement_log_txn(txn);
                auto blocks = txn.select_one(
                    "SELECT COUNT(*) FROM ban_enforcement_log "
                    "WHERE result != 'allowed'");
                stats["total_blocks"] = blocks ? blocks->get<int64_t>(0) : 0;
            } else {
                stats["total_checks"] = store_.count_enforcement_log_txn(
                    txn, server_name);
                auto blocks = txn.select_one(
                    "SELECT COUNT(*) FROM ban_enforcement_log "
                    "WHERE server_name = ? AND result != 'allowed'",
                    {server_name});
                stats["total_blocks"] = blocks ? blocks->get<int64_t>(0) : 0;
            }
            return stats;
        });
    }

    // Get recent enforcement log
    json get_recent_enforcement(int limit = 100,
                                 const std::string& server_name = "") {
        return db_.with_read_txn([&](LoggingTransaction& txn) -> json {
            return store_.get_enforcement_log_txn(txn, server_name, limit);
        });
    }

    // Purge old enforcement logs
    json purge_old_logs(int64_t retention_days = 30) {
        int64_t cutoff = now_ms() - (retention_days * 86400000LL);
        return db_.with_write_txn([&](LoggingTransaction& txn) -> json {
            store_.purge_old_enforcement_log_txn(txn, cutoff);
            json result;
            result["success"] = true;
            result["cutoff_ts"] = cutoff;
            return result;
        });
    }

private:
    void log_and_return(BanCheckResponse& response,
                         const BanCheckRequest& request,
                         chr::steady_clock::time_point start) {
        auto end = chr::steady_clock::now();
        int64_t latency_us = chr::duration_cast<chr::microseconds>(
            end - start).count();

        db_.with_write_txn([&](LoggingTransaction& txn) {
            store_.log_enforcement_txn(
                txn,
                request.server_name,
                federation_action_str(request.action),
                request.room_id,
                ban_check_result_str(response.result),
                response.matched_rule.empty() ? "default" : response.matched_rule,
                response.ban_id,
                latency_us);
        });

        if (response.result != BanCheckResult::ALLOWED &&
            !response.is_shadow) {
            logger_.warn(
                "Federation BLOCKED: " + request.server_name +
                " action=" + federation_action_str(request.action) +
                " reason=" + response.reason +
                " (" + ban_check_result_str(response.result) + ")");
        }
    }

    BanListStore store_;
    DatabasePool& db_;
    ServerBanListManager& server_mgr_;
    IPBanListManager& ip_mgr_;
    UserBanListManager& user_mgr_;
    PerRoomBanListManager& room_mgr_;
    BanLogger& logger_;
};

// ============================================================================
// 10. BanListMetricsCollector — Metrics for monitoring
// ============================================================================

class BanListMetricsCollector {
public:
    BanListMetricsCollector(DatabasePool& db, BanLogger& logger)
        : store_(db, logger), db_(db), logger_(logger) {}

    // Get comprehensive ban list statistics
    BanListStats get_stats() {
        BanListStats stats;
        db_.with_read_txn([&](LoggingTransaction& txn) {
            stats = store_.get_stats_txn(txn);
        });
        return stats;
    }

    // Get stats as JSON
    json get_stats_json() {
        return get_stats().to_json();
    }

    // Get ban breakdown by level
    json get_ban_breakdown() {
        json breakdown;
        db_.with_read_txn([&](LoggingTransaction& txn) {
            // Server bans by level
            auto rows = txn.select(
                "SELECT level, COUNT(*) as cnt FROM server_bans "
                "WHERE is_active = 1 GROUP BY level");
            json server_by_level = json::object();
            for (auto& row : rows) {
                server_by_level[ban_level_str(
                    static_cast<BanLevel>(row->get<int64_t>(0)))] =
                    row->get<int64_t>(1);
            }
            breakdown["server_bans_by_level"] = server_by_level;

            // User bans by level
            rows = txn.select(
                "SELECT level, COUNT(*) as cnt FROM user_bans "
                "WHERE is_active = 1 GROUP BY level");
            json user_by_level = json::object();
            for (auto& row : rows) {
                user_by_level[ban_level_str(
                    static_cast<BanLevel>(row->get<int64_t>(0)))] =
                    row->get<int64_t>(1);
            }
            breakdown["user_bans_by_level"] = user_by_level;

            // IP bans by level
            rows = txn.select(
                "SELECT level, COUNT(*) as cnt FROM ip_bans "
                "WHERE is_active = 1 GROUP BY level");
            json ip_by_level = json::object();
            for (auto& row : rows) {
                ip_by_level[ban_level_str(
                    static_cast<BanLevel>(row->get<int64_t>(0)))] =
                    row->get<int64_t>(1);
            }
            breakdown["ip_bans_by_level"] = ip_by_level;

            // Enforcement by result
            rows = txn.select(
                "SELECT result, COUNT(*) as cnt FROM ban_enforcement_log "
                "GROUP BY result");
            json enforcement_by_result = json::object();
            for (auto& row : rows) {
                enforcement_by_result[row->get<std::string>(0)] =
                    row->get<int64_t>(1);
            }
            breakdown["enforcement_by_result"] = enforcement_by_result;

            // Enforcement by action
            rows = txn.select(
                "SELECT action, COUNT(*) as cnt FROM ban_enforcement_log "
                "GROUP BY action ORDER BY cnt DESC LIMIT 10");
            json enforcement_by_action = json::object();
            for (auto& row : rows) {
                enforcement_by_action[row->get<std::string>(0)] =
                    row->get<int64_t>(1);
            }
            breakdown["enforcement_by_action"] = enforcement_by_action;

            // Top blocked servers
            rows = txn.select(
                "SELECT server_name, COUNT(*) as cnt FROM ban_enforcement_log "
                "WHERE result != 'allowed' GROUP BY server_name "
                "ORDER BY cnt DESC LIMIT 10");
            json top_blocked = json::array();
            for (auto& row : rows) {
                json entry;
                entry["server_name"] = row->get<std::string>(0);
                entry["block_count"] = row->get<int64_t>(1);
                top_blocked.push_back(entry);
            }
            breakdown["top_blocked_servers"] = top_blocked;
        });

        return breakdown;
    }

    // Get enforcement rate (checks per minute)
    double get_enforcement_rate_min(int window_sec = 60) {
        int64_t cutoff = now_ms() - (window_sec * 1000LL);
        double rate = 0.0;
        db_.with_read_txn([&](LoggingTransaction& txn) {
            auto row = txn.select_one(
                "SELECT COUNT(*) FROM ban_enforcement_log "
                "WHERE checked_ts > ?", {cutoff});
            int64_t count = row ? row->get<int64_t>(0) : 0;
            rate = static_cast<double>(count) /
                   (static_cast<double>(window_sec) / 60.0);
        });
        return rate;
    }

    // Get block rate (blocks per minute)
    double get_block_rate_min(int window_sec = 60) {
        int64_t cutoff = now_ms() - (window_sec * 1000LL);
        double rate = 0.0;
        db_.with_read_txn([&](LoggingTransaction& txn) {
            auto row = txn.select_one(
                "SELECT COUNT(*) FROM ban_enforcement_log "
                "WHERE checked_ts > ? AND result != 'allowed'",
                {cutoff});
            int64_t count = row ? row->get<int64_t>(0) : 0;
            rate = static_cast<double>(count) /
                   (static_cast<double>(window_sec) / 60.0);
        });
        return rate;
    }

    // Get Prometheus-style metrics text
    std::string get_prometheus_metrics() {
        std::ostringstream out;
        auto stats = get_stats();

        out << "# HELP progressive_ban_list_server_bans_total Total server bans\n";
        out << "# TYPE progressive_ban_list_server_bans_total gauge\n";
        out << "progressive_ban_list_server_bans_total "
            << stats.total_server_bans << "\n";

        out << "# HELP progressive_ban_list_server_bans_active Active server bans\n";
        out << "# TYPE progressive_ban_list_server_bans_active gauge\n";
        out << "progressive_ban_list_server_bans_active "
            << stats.active_server_bans << "\n";

        out << "# HELP progressive_ban_list_ip_bans_total Total IP bans\n";
        out << "# TYPE progressive_ban_list_ip_bans_total gauge\n";
        out << "progressive_ban_list_ip_bans_total "
            << stats.total_ip_bans << "\n";

        out << "# HELP progressive_ban_list_ip_bans_active Active IP bans\n";
        out << "# TYPE progressive_ban_list_ip_bans_active gauge\n";
        out << "progressive_ban_list_ip_bans_active "
            << stats.active_ip_bans << "\n";

        out << "# HELP progressive_ban_list_user_bans_total Total user bans\n";
        out << "# TYPE progressive_ban_list_user_bans_total gauge\n";
        out << "progressive_ban_list_user_bans_total "
            << stats.total_user_bans << "\n";

        out << "# HELP progressive_ban_list_user_bans_active Active user bans\n";
        out << "# TYPE progressive_ban_list_user_bans_active gauge\n";
        out << "progressive_ban_list_user_bans_active "
            << stats.active_user_bans << "\n";

        out << "# HELP progressive_ban_list_room_bans_total Total room bans\n";
        out << "# TYPE progressive_ban_list_room_bans_total gauge\n";
        out << "progressive_ban_list_room_bans_total "
            << stats.total_room_bans << "\n";

        out << "# HELP progressive_ban_list_room_bans_active Active room bans\n";
        out << "# TYPE progressive_ban_list_room_bans_active gauge\n";
        out << "progressive_ban_list_room_bans_active "
            << stats.active_room_bans << "\n";

        out << "# HELP progressive_ban_list_enforcement_checks_total "
            << "Total enforcement checks\n";
        out << "# TYPE progressive_ban_list_enforcement_checks_total counter\n";
        out << "progressive_ban_list_enforcement_checks_total "
            << stats.total_enforcement_checks << "\n";

        out << "# HELP progressive_ban_list_blocks_total Total blocks\n";
        out << "# TYPE progressive_ban_list_blocks_total counter\n";
        out << "progressive_ban_list_blocks_total "
            << stats.total_blocks << "\n";

        out << "# HELP progressive_ban_list_imports_count Total imports\n";
        out << "# TYPE progressive_ban_list_imports_count gauge\n";
        out << "progressive_ban_list_imports_count "
            << stats.imports_count << "\n";

        out << "# HELP progressive_ban_list_active_subscriptions "
            << "Active ban list subscriptions\n";
        out << "# TYPE progressive_ban_list_active_subscriptions gauge\n";
        out << "progressive_ban_list_active_subscriptions "
            << stats.active_subscriptions << "\n";

        out << "# HELP progressive_ban_list_enforcement_rate_per_min "
            << "Enforcement checks per minute\n";
        out << "# TYPE progressive_ban_list_enforcement_rate_per_min gauge\n";
        out << "progressive_ban_list_enforcement_rate_per_min "
            << get_enforcement_rate_min() << "\n";

        out << "# HELP progressive_ban_list_block_rate_per_min "
            << "Blocks per minute\n";
        out << "# TYPE progressive_ban_list_block_rate_per_min gauge\n";
        out << "progressive_ban_list_block_rate_per_min "
            << get_block_rate_min() << "\n";

        return out.str();
    }

    // Periodic maintenance: update cached stats
    void periodic_maintenance() {
        db_.with_write_txn([&](LoggingTransaction& txn) {
            store_.delete_all_expired_txn(txn);
        });
        logger_.debug("Periodic ban list maintenance completed");
    }

private:
    BanListStore store_;
    DatabasePool& db_;
    BanLogger& logger_;
};

// ============================================================================
// 11. BanListManager — Top-level coordinator
// ============================================================================

class BanListManager {
public:
    explicit BanListManager(DatabasePool& db)
        : db_(db), logger_("BanListManager"),
          store_(db, logger_),
          server_mgr_(db, logger_),
          ip_mgr_(db, logger_),
          user_mgr_(db, logger_),
          room_mgr_(db, logger_),
          exporter_(db, logger_),
          importer_(db, server_mgr_, ip_mgr_, user_mgr_, room_mgr_, logger_),
          synchronizer_(db, importer_, logger_),
          enforcer_(db, server_mgr_, ip_mgr_, user_mgr_, room_mgr_, logger_),
          metrics_(db, logger_) {}

    // Initialize all tables
    void initialize_tables() {
        db_.with_write_txn([&](LoggingTransaction& txn) {
            BanListStore::create_tables(txn);
        });
        logger_.info("Ban list tables initialized");
    }

    // ---------- Server Ban Management ----------

    json add_server_ban(const std::string& server_name,
                         const std::string& reason,
                         const std::string& banned_by,
                         const std::string& match_type = "exact",
                         const std::string& level = "hard",
                         int64_t expires_ts = 0,
                         const std::string& notes = "") {
        MatchType mtype;
        if (match_type == "domain_suffix") mtype = MatchType::DOMAIN_SUFFIX;
        else if (match_type == "glob")     mtype = MatchType::GLOB;
        else if (match_type == "regex")    mtype = MatchType::REGEX;
        else                                mtype = MatchType::EXACT;

        return server_mgr_.add_ban(server_name, reason, banned_by, mtype,
                                    ban_level_from_str(level), expires_ts, notes);
    }

    json remove_server_ban(int64_t ban_id, const std::string& removed_by) {
        return server_mgr_.remove_ban(ban_id, removed_by);
    }

    json delete_server_ban(int64_t ban_id) {
        return server_mgr_.delete_ban(ban_id);
    }

    json list_server_bans(bool active_only = true, int limit = 1000,
                           int offset = 0) {
        return server_mgr_.list_bans(active_only, limit, offset);
    }

    json check_server(const std::string& server_name) {
        auto response = server_mgr_.check_server(server_name);
        return response.to_json();
    }

    // ---------- IP Ban Management ----------

    json add_ip_ban(const std::string& ip_address,
                     const std::string& reason,
                     const std::string& banned_by,
                     int prefix_length = -1,
                     const std::string& level = "hard",
                     int64_t expires_ts = 0,
                     const std::string& notes = "") {
        return ip_mgr_.add_ban(ip_address, reason, banned_by, prefix_length,
                                ban_level_from_str(level), expires_ts, notes);
    }

    json remove_ip_ban(int64_t ban_id, const std::string& removed_by) {
        return ip_mgr_.remove_ban(ban_id, removed_by);
    }

    json delete_ip_ban(int64_t ban_id) {
        return ip_mgr_.delete_ban(ban_id);
    }

    json list_ip_bans(bool active_only = true, int limit = 1000,
                       int offset = 0) {
        return ip_mgr_.list_bans(active_only, limit, offset);
    }

    json check_ip(const std::string& ip_address) {
        auto response = ip_mgr_.check_ip(ip_address);
        return response.to_json();
    }

    // ---------- User Ban Management ----------

    json add_user_ban(const std::string& user_id,
                       const std::string& reason,
                       const std::string& banned_by,
                       const std::string& match_type = "exact",
                       const std::string& level = "hard",
                       bool shadow_ban = false,
                       int64_t expires_ts = 0,
                       const std::string& notes = "") {
        MatchType mtype;
        if (match_type == "domain_suffix") mtype = MatchType::DOMAIN_SUFFIX;
        else if (match_type == "glob")     mtype = MatchType::GLOB;
        else if (match_type == "regex")    mtype = MatchType::REGEX;
        else                                mtype = MatchType::EXACT;

        return user_mgr_.add_ban(user_id, reason, banned_by, mtype,
                                  ban_level_from_str(level),
                                  shadow_ban, expires_ts, notes);
    }

    json remove_user_ban(int64_t ban_id, const std::string& removed_by) {
        return user_mgr_.remove_ban(ban_id, removed_by);
    }

    json delete_user_ban(int64_t ban_id) {
        return user_mgr_.delete_ban(ban_id);
    }

    json list_user_bans(bool active_only = true, int limit = 1000,
                          int offset = 0) {
        return user_mgr_.list_bans(active_only, limit, offset);
    }

    json check_user(const std::string& user_id) {
        auto response = user_mgr_.check_user(user_id);
        return response.to_json();
    }

    // ---------- Room Ban Management ----------

    json add_room_ban(const std::string& room_id,
                       const std::string& banned_entity,
                       const std::string& entity_type,
                       const std::string& reason,
                       const std::string& banned_by,
                       const std::string& match_type = "exact",
                       const std::string& level = "hard",
                       int64_t expires_ts = 0,
                       const std::string& notes = "") {
        BanEntityType etype;
        try {
            etype = ban_entity_type_from_str(entity_type);
        } catch (...) {
            etype = BanEntityType::SERVER;
        }

        MatchType mtype;
        if (match_type == "domain_suffix") mtype = MatchType::DOMAIN_SUFFIX;
        else if (match_type == "glob")     mtype = MatchType::GLOB;
        else if (match_type == "regex")    mtype = MatchType::REGEX;
        else                                mtype = MatchType::EXACT;

        return room_mgr_.add_ban(room_id, banned_entity, etype, reason,
                                  banned_by, mtype,
                                  ban_level_from_str(level), expires_ts, notes);
    }

    json remove_room_ban(int64_t ban_id, const std::string& removed_by) {
        return room_mgr_.remove_ban(ban_id, removed_by);
    }

    json list_room_bans(const std::string& room_id,
                         int limit = 500, int offset = 0) {
        return room_mgr_.list_room_bans(room_id, limit, offset);
    }

    json add_room_override(const std::string& room_id,
                            int64_t ban_id,
                            const std::string& ban_type,
                            const std::string& reason,
                            const std::string& set_by,
                            int64_t expires_ts = 0) {
        return room_mgr_.add_override(room_id, ban_id, ban_type,
                                        reason, set_by, expires_ts);
    }

    json remove_room_override(int64_t override_id) {
        return room_mgr_.remove_override(override_id);
    }

    json list_room_overrides(const std::string& room_id) {
        return room_mgr_.list_overrides(room_id);
    }

    // ---------- Import/Export ----------

    json import_from_json_file(const std::string& file_path,
                                const std::string& imported_by) {
        return importer_.import_from_json_file(file_path, imported_by);
    }

    json import_from_json_data(const json& data,
                                const std::string& source,
                                const std::string& imported_by) {
        return importer_.import_from_json(data, ImportSourceType::JSON_FILE,
                                           source, imported_by);
    }

    json import_from_policy_event(const json& event,
                                   const std::string& room_id,
                                   const std::string& imported_by) {
        return importer_.import_from_policy_event(event, room_id, imported_by);
    }

    json revert_import(const std::string& import_id,
                        const std::string& reverted_by) {
        return importer_.revert_import(import_id, reverted_by);
    }

    json get_import_history(int limit = 100, int offset = 0) {
        return importer_.get_import_history(limit, offset);
    }

    json export_all_to_json(bool active_only = true) {
        return exporter_.export_all_to_json(active_only);
    }

    json export_as_policy_list() {
        return exporter_.export_as_policy_list();
    }

    std::string export_to_csv(bool active_only = true) {
        return exporter_.export_to_csv(active_only);
    }

    json save_export_to_file(const std::string& file_path,
                              const json& data,
                              bool pretty = true) {
        return exporter_.save_to_file(file_path, data, pretty);
    }

    // ---------- Synchronization ----------

    json subscribe_to_ban_list(const std::string& room_id,
                                const std::string& server_name,
                                const std::string& display_name,
                                const std::string& subscribed_by,
                                bool auto_apply = true) {
        return synchronizer_.subscribe_to_list(room_id, server_name,
                                                display_name, subscribed_by,
                                                auto_apply);
    }

    json unsubscribe_from_ban_list(const std::string& room_id) {
        return synchronizer_.unsubscribe_from_list(room_id);
    }

    json sync_from_room(const std::string& room_id,
                         const json& policy_events,
                         const std::string& synced_by) {
        return synchronizer_.sync_from_room(room_id, policy_events, synced_by);
    }

    json receive_bans_from_node(const std::string& source_node,
                                  const json& bans,
                                  const std::string& received_by) {
        return synchronizer_.receive_from_node(source_node, bans, received_by);
    }

    json get_subscriptions() {
        return synchronizer_.get_subscriptions();
    }

    json get_sync_log(int limit = 100, int offset = 0) {
        return synchronizer_.get_sync_log(limit, offset);
    }

    json get_stale_subscriptions(int64_t stale_threshold_ms = 3600000) {
        return synchronizer_.get_stale_subscriptions(stale_threshold_ms);
    }

    // ---------- Federation Enforcement ----------

    json check_federation_request(const std::string& server_name,
                                   const std::string& action,
                                   const std::string& room_id = "",
                                   const std::string& user_id = "",
                                   const std::string& ip_address = "") {
        BanCheckRequest req;
        req.server_name = server_name;
        req.room_id = room_id;
        req.user_id = user_id;
        req.ip_address = ip_address;

        // Parse action
        if (action == "send_transaction")
            req.action = FederationAction::SEND_TRANSACTION;
        else if (action == "make_join")
            req.action = FederationAction::MAKE_JOIN;
        else if (action == "send_join")
            req.action = FederationAction::SEND_JOIN;
        else if (action == "invite")
            req.action = FederationAction::INVITE;
        else if (action == "backfill")
            req.action = FederationAction::BACKFILL;
        else if (action == "get_state")
            req.action = FederationAction::GET_STATE;
        else if (action == "get_event")
            req.action = FederationAction::GET_EVENT;
        else if (action == "query_profile")
            req.action = FederationAction::QUERY_PROFILE;

        auto response = enforcer_.check_federation_request(req);
        return response.to_json();
    }

    json bulk_check_servers(const std::vector<std::string>& servers) {
        return enforcer_.bulk_check_servers(servers);
    }

    json get_enforcement_stats(const std::string& server_name = "") {
        return enforcer_.get_server_enforcement_stats(server_name);
    }

    json get_recent_enforcement(int limit = 100,
                                  const std::string& server_name = "") {
        return enforcer_.get_recent_enforcement(limit, server_name);
    }

    json purge_enforcement_logs(int retention_days = 30) {
        return enforcer_.purge_old_logs(retention_days);
    }

    // ---------- Metrics ----------

    json get_full_stats() {
        return metrics_.get_stats_json();
    }

    json get_ban_breakdown() {
        return metrics_.get_ban_breakdown();
    }

    std::string get_prometheus_metrics() {
        return metrics_.get_prometheus_metrics();
    }

    // ---------- Maintenance ----------

    json cleanup_all_expired() {
        return db_.with_write_txn([&](LoggingTransaction& txn) -> json {
            store_.delete_all_expired_txn(txn);
            json result;
            result["success"] = true;
            result["message"] = "All expired bans deactivated";
            return result;
        });
    }

    void periodic_maintenance() {
        metrics_.periodic_maintenance();
    }

    // ---------- Bulk Operations ----------

    // Get a summary of all bans affecting a given context
    json full_context_check(const std::string& server_name,
                             const std::string& user_id = "",
                             const std::string& ip_address = "",
                             const std::string& room_id = "") {
        json result;
        result["checked_ts"] = now_ms();

        if (!server_name.empty()) {
            result["server_check"] = check_server(server_name);
        }
        if (!user_id.empty()) {
            result["user_check"] = check_user(user_id);
        }
        if (!ip_address.empty()) {
            result["ip_check"] = check_ip(ip_address);
        }
        if (!room_id.empty()) {
            BanCheckRequest req;
            req.server_name = server_name;
            req.user_id = user_id;
            req.ip_address = ip_address;
            req.room_id = room_id;

            auto room_resp = room_mgr_.check_room_ban(room_id, req);
            result["room_check"] = room_resp.to_json();
        }

        // Determine overall result
        bool banned = false;
        std::string worst_check;
        BanLevel worst_level = BanLevel::WARN;

        auto check_level = [&](const json& check) {
            if (check.contains("result") &&
                check["result"].get<std::string>() != "allowed") {
                banned = true;
                auto level = ban_level_from_str(
                    check.value("level", "hard"));
                if (static_cast<int>(level) > static_cast<int>(worst_level)) {
                    worst_level = level;
                }
            }
        };

        if (result.contains("server_check")) check_level(result["server_check"]);
        if (result.contains("user_check"))   check_level(result["user_check"]);
        if (result.contains("ip_check"))     check_level(result["ip_check"]);
        if (result.contains("room_check"))   check_level(result["room_check"]);

        result["overall_banned"] = banned;
        result["worst_level"] = ban_level_str(worst_level);

        return result;
    }

private:
    DatabasePool& db_;
    BanLogger logger_;
    BanListStore store_;
    ServerBanListManager server_mgr_;
    IPBanListManager ip_mgr_;
    UserBanListManager user_mgr_;
    PerRoomBanListManager room_mgr_;
    BanListExporter exporter_;
    BanListImporter importer_;
    BanSynchronizer synchronizer_;
    FederationBanEnforcer enforcer_;
    BanListMetricsCollector metrics_;
};

} // namespace progressive
