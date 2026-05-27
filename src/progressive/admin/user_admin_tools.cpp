// ============================================================================
// user_admin_tools.cpp - Matrix Admin User Management Tools (3500+ lines)
// Comprehensive user administration, device management, room membership
// control, pushers, rate-limit overrides, shadow-banning, and user data
// export for the progressive-server Matrix homeserver.
//
// Namespace: progressive::admin
// Include:   ../json.hpp
//
// Endpoint coverage:
//   1.  GET    /_synapse/admin/v1/users                          - List users
//          Filters: name, guests, deactivated, user_id,
//                    order_by, dir, from, limit, admins, locked
//   2.  GET    /_synapse/admin/v1/users/{userId}/details         - User details
//          Returns: profile, devices, threepids, connections,
//                    joined rooms, pushers, consent, external_ids
//   3.  POST   /_synapse/admin/v1/users                          - Create user
//          Body: username, password, admin, displayname, threepids,
//                avatar_url, user_type, email, locked
//   4.  POST   /_synapse/admin/v1/users/{userId}/deactivate      - Deactivate
//          Body: erase (bool) — GDPR erase if true
//   5.  POST   /_synapse/admin/v1/users/{userId}/reactivate      - Reactivate
//   6.  POST   /_synapse/admin/v1/users/{userId}/shadow_ban      - Shadow-ban
//   7.  POST   /_synapse/admin/v1/users/{userId}/override_ratelimit - Rate limit
//   8.  POST   /_synapse/admin/v1/users/{userId}/reset_password   - Reset password
//          Body: new_password, logout_devices
//   9.  POST   /_synapse/admin/v1/users/{userId}/registration_token - Gen token
//  10.  GET    /_synapse/admin/v1/users/{userId}/devices          - List devices
//  11.  DELETE /_synapse/admin/v1/users/{userId}/devices/{devId}  - Delete device
//  12.  GET    /_synapse/admin/v1/users/{userId}/pushers          - List pushers
//  13.  GET    /_synapse/admin/v1/users/{userId}/rooms            - List rooms
//  14.  POST   /_synapse/admin/v1/users/{userId}/force_join       - Force join room
//  15.  POST   /_synapse/admin/v1/users/{userId}/force_leave      - Force leave room
//  16.  GET    /_synapse/admin/v1/users/{userId}/export           - Export user data
// ============================================================================

#include "../json.hpp"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <functional>
#include <iomanip>
#include <map>
#include <mutex>
#include <optional>
#include <random>
#include <regex>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace progressive {
namespace admin {

// ============================================================================
// Forward type alias
// ============================================================================

using json = nlohmann::json;

// ============================================================================
// Internal database structures and in-memory stores
// ============================================================================

namespace db {

// --- User record ---
struct UserRecord {
    std::string id;                     // Full MXID: @localpart:domain
    std::string displayname;
    std::string avatar_url;
    std::string password_hash;
    std::string email;
    bool admin = false;
    bool deactivated = false;
    bool locked = false;
    bool shadow_banned = false;
    std::string creation_ts;            // epoch ms
    std::string consent_version;
    std::string consent_ts;
    bool consent_given = false;
    std::string user_type;              // "", "support", "bot"
    bool is_guest = false;
    bool approved = true;
    bool erased = false;
    std::string external_ids;           // JSON array string
    std::string threepids;              // JSON array string
    int password_hash_iterations = 0;
    std::string password_salt;
    // Rate-limit overrides
    bool rate_limit_overridden = false;
    int64_t rate_limit_messages_per_second = 0;
    int64_t rate_limit_burst_count = 0;
    std::string rate_limit_overridden_ts;
    std::string rate_limit_overridden_by;
    // Export metadata
    std::string last_export_ts;
    int export_count = 0;
};

// --- Device / session record ---
struct DeviceRecord {
    std::string device_id;
    std::string user_id;
    std::string display_name;
    std::string last_seen_ip;
    std::string last_seen_user_agent;
    std::string last_seen_ts;           // epoch ms
    std::string creation_ts;
    bool is_active = true;
    bool hidden = false;                // soft-deleted
    std::string device_type;            // "mobile", "web", "desktop", "unknown"
    std::string access_token_hash;
    std::string push_key;               // push notification key
};

// --- Pusher record ---
struct PusherRecord {
    std::string pusher_id;
    std::string user_id;
    std::string app_id;
    std::string app_display_name;
    std::string device_display_name;
    std::string pushkey;
    std::string kind;                   // "http", "email"
    std::string lang;
    std::string profile_tag;
    bool enabled = true;
    std::string created_ts;
    std::string updated_ts;
    bool has_device = true;
    std::string device_id;
    std::string data;                   // JSON for extra pusher data
};

// --- Room record ---
struct RoomRecord {
    std::string room_id;
    std::string name;
    std::string canonical_alias;
    std::string creator;
    std::string creation_ts;
    std::string topic;
    std::string avatar_url;
    int joined_members = 0;
    int invited_members = 0;
    int banned_members = 0;
    int total_members = 0;
    bool blocked = false;
    bool is_encrypted = false;
    bool federatable = true;
    bool public_room = false;
    std::string join_rules;
    std::string guest_access;
    std::string history_visibility;
    std::string room_version;
    std::string room_type;
};

// --- Registration token ---
struct RegistrationToken {
    std::string token;
    std::string uses_allowed;           // "0" = unlimited
    int pending = 0;
    int completed = 0;
    std::string expiry_time;            // epoch ms, "0" = never
    std::string created_ts;
    std::string created_by;
    std::string for_user_id;            // optional: tied to a specific user
};

// --- Room membership ---
struct RoomMembership {
    std::string room_id;
    std::string user_id;
    std::string membership;             // "join", "invite", "ban", "leave", "knock"
    std::string sender;                 // who initiated the state change
    std::string event_id;
    std::string origin_server_ts;
    bool is_direct = false;
};

// --- User connection / session info ---
struct UserConnection {
    std::string connection_id;
    std::string user_id;
    std::string ip_address;
    std::string user_agent;
    std::string last_seen_ts;
    std::string connected_since;
    std::string device_id;
    bool is_active = true;
    int request_count = 0;
};

// --- Rate-limit override record ---
struct RateLimitOverride {
    std::string user_id;
    std::string overridden_by;          // admin who set it
    std::string overridden_ts;
    int64_t messages_per_second = 0;    // 0 = effectively unlimited
    int64_t burst_count = 0;
    std::string reason;
    bool active = true;
};

// In-memory stores
extern std::mutex users_mutex;
extern std::mutex devices_mutex;
extern std::mutex pushers_mutex;
extern std::mutex rooms_mutex;
extern std::mutex tokens_mutex;
extern std::mutex connections_mutex;
extern std::mutex membership_mutex;

extern std::unordered_map<std::string, UserRecord> users;
extern std::unordered_map<std::string, DeviceRecord> devices;           // device_id -> record
extern std::unordered_map<std::string, std::vector<std::string>> user_devices; // user_id -> device_ids
extern std::unordered_map<std::string, PusherRecord> pushers;           // pusher_id -> record
extern std::unordered_map<std::string, std::vector<std::string>> user_pushers; // user_id -> pusher_ids
extern std::unordered_map<std::string, RoomRecord> rooms;
extern std::unordered_map<std::string, RegistrationToken> reg_tokens;
extern std::unordered_map<std::string, std::vector<std::string>> room_members; // room_id -> user_ids
extern std::unordered_map<std::string, std::vector<std::string>> user_rooms;   // user_id -> room_ids
extern std::unordered_map<std::string, RoomMembership> memberships; // "room_id:user_id" -> membership
extern std::unordered_map<std::string, UserConnection> connections;  // connection_id -> record
extern std::unordered_map<std::string, std::vector<std::string>> user_connections; // user_id -> connection_ids
extern std::unordered_map<std::string, RateLimitOverride> rate_limit_overrides;

} // namespace db

// ============================================================================
// Mutex definitions
// ============================================================================

std::mutex db::users_mutex;
std::mutex db::devices_mutex;
std::mutex db::pushers_mutex;
std::mutex db::rooms_mutex;
std::mutex db::tokens_mutex;
std::mutex db::connections_mutex;
std::mutex db::membership_mutex;

std::unordered_map<std::string, db::UserRecord> db::users;
std::unordered_map<std::string, db::DeviceRecord> db::devices;
std::unordered_map<std::string, std::vector<std::string>> db::user_devices;
std::unordered_map<std::string, db::PusherRecord> db::pushers;
std::unordered_map<std::string, std::vector<std::string>> db::user_pushers;
std::unordered_map<std::string, db::RoomRecord> db::rooms;
std::unordered_map<std::string, db::RegistrationToken> db::reg_tokens;
std::unordered_map<std::string, std::vector<std::string>> db::room_members;
std::unordered_map<std::string, std::vector<std::string>> db::user_rooms;
std::unordered_map<std::string, db::RoomMembership> db::memberships;
std::unordered_map<std::string, db::UserConnection> db::connections;
std::unordered_map<std::string, std::vector<std::string>> db::user_connections;
std::unordered_map<std::string, db::RateLimitOverride> db::rate_limit_overrides;

// ============================================================================
// Utility helpers
// ============================================================================

namespace {

// Current timestamp in milliseconds since epoch
std::string now_ms() {
    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()).count();
    return std::to_string(ms);
}

// Generate a random hex string of given length
std::string random_hex(int length) {
    static const char hex_chars[] = "0123456789abcdef";
    std::string result;
    result.reserve(length);
    for (int i = 0; i < length; ++i) {
        result += hex_chars[rand() % 16];
    }
    return result;
}

// Generate a random alphanumeric token
std::string random_token(int length) {
    static const char chars[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    std::string result;
    result.reserve(length);
    for (int i = 0; i < length; ++i) {
        result += chars[rand() % (sizeof(chars) - 1)];
    }
    return result;
}

// SHA-256 hash (simplified placeholder)
std::string sha256(const std::string& input) {
    std::hash<std::string> hasher;
    size_t h = hasher(input);
    std::stringstream ss;
    ss << std::hex << std::setfill('0') << std::setw(16) << h;
    std::string hex = ss.str();
    while (hex.size() < 64) hex = "0" + hex;
    return hex.substr(0, 64);
}

// Simple bcrypt-like password hash simulation
std::string hash_password(const std::string& password) {
    std::string salt = random_hex(16);
    return "$2b$12$" + salt + "$" + sha256(salt + password);
}

// Validate user ID format: @localpart:domain
bool is_valid_user_id(const std::string& uid) {
    static std::regex re(R"(^@[a-zA-Z0-9._=\\-/]+:.+$)");
    return std::regex_match(uid, re);
}

// Validate room ID format: !opaque:domain
bool is_valid_room_id(const std::string& rid) {
    static std::regex re(R"(^![a-zA-Z0-9._=\\-/]+:.+$)");
    return std::regex_match(rid, re);
}

// Validate device ID format
bool is_valid_device_id(const std::string& did) {
    if (did.empty()) return false;
    if (did.size() > 256) return false;
    return true;
}

// Extract localpart from user ID
std::string localpart(const std::string& uid) {
    auto pos = uid.find(':');
    if (pos != std::string::npos) {
        return uid.substr(1, pos - 1);
    }
    return uid;
}

// URL-decode a string
std::string url_decode(const std::string& src) {
    std::string result;
    result.reserve(src.size());
    for (size_t i = 0; i < src.size(); ++i) {
        if (src[i] == '%' && i + 2 < src.size()) {
            int c = 0;
            std::stringstream ss;
            ss << std::hex << src.substr(i + 1, 2);
            ss >> c;
            result += static_cast<char>(c);
            i += 2;
        } else if (src[i] == '+') {
            result += ' ';
        } else {
            result += src[i];
        }
    }
    return result;
}

// Build JSON error response
json error_response(const std::string& errcode,
                     const std::string& error,
                     int http_status = 400) {
    return {
        {"errcode", errcode},
        {"error", error},
        {"http_status", http_status}
    };
}

// Build JSON success response
json success_response(const std::string& message = "OK",
                       const json& extra = json::object()) {
    json resp;
    resp["success"] = true;
    if (!message.empty()) resp["message"] = message;
    for (const auto& [k, v] : extra.items()) {
        resp[k] = v;
    }
    return resp;
}

// Helper: case-insensitive string contains
bool matches_filter(const std::string& target, const std::string& filter) {
    if (filter.empty()) return true;
    auto it = std::search(
        target.begin(), target.end(),
        filter.begin(), filter.end(),
        [](char a, char b) { return std::tolower(a) == std::tolower(b); });
    return it != target.end();
}

// Helper: parse boolean from string or bool json value
bool parse_bool_param(const json& params, const std::string& key, bool default_val = false) {
    if (!params.contains(key)) return default_val;
    if (params[key].is_boolean()) return params[key].get<bool>();
    if (params[key].is_string()) {
        std::string v = params[key].get<std::string>();
        return (v == "true" || v == "1" || v == "yes");
    }
    if (params[key].is_number()) return params[key].get<int>() != 0;
    return default_val;
}

// Helper: parse int param
int parse_int_param(const json& params, const std::string& key, int default_val = 0) {
    if (!params.contains(key)) return default_val;
    if (params[key].is_number()) return params[key].get<int>();
    if (params[key].is_string()) {
        try { return std::stoi(params[key].get<std::string>()); }
        catch (...) { return default_val; }
    }
    return default_val;
}

// Helper: parse string param
std::string parse_string_param(const json& params, const std::string& key,
                                const std::string& default_val = "") {
    if (!params.contains(key)) return default_val;
    if (params[key].is_string()) return params[key].get<std::string>();
    if (params[key].is_number()) return std::to_string(params[key].get<int>());
    return default_val;
}

// Helper: escape JSON for safe embedding
std::string json_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 16);
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b";  break;
            case '\f': out += "\\f";  break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:   out += c;      break;
        }
    }
    return out;
}

// Generate a unique pusher ID
std::string generate_pusher_id(const std::string& user_id, const std::string& app_id,
                                const std::string& pushkey) {
    std::string composite = user_id + ":" + app_id + ":" + pushkey;
    return "pusher_" + sha256(composite).substr(0, 16);
}

// Extract the user_id from a request path for prefix routes like
// /_synapse/admin/v1/users/{userId}/...
bool extract_user_id_from_path(const std::string& path,
                                const std::string& prefix,
                                std::string& user_id) {
    auto pos = path.find(prefix);
    if (pos == std::string::npos) return false;
    std::string remainder = path.substr(pos + prefix.size());
    // Find the end of the user_id (next '/' or end)
    auto slash = remainder.find('/');
    if (slash != std::string::npos) {
        user_id = remainder.substr(0, slash);
    } else {
        user_id = remainder;
    }
    user_id = url_decode(user_id);
    return !user_id.empty();
}

// Serialize a user record to JSON (common across multiple endpoints)
json user_record_to_json(const db::UserRecord& rec, bool include_sensitive = false) {
    json u;
    u["name"] = rec.id;
    u["displayname"] = rec.displayname;
    u["avatar_url"] = rec.avatar_url;
    u["is_guest"] = rec.is_guest ? 1 : 0;
    u["admin"] = rec.admin ? 1 : 0;
    u["deactivated"] = rec.deactivated;
    u["locked"] = rec.locked;
    u["shadow_banned"] = rec.shadow_banned;
    u["creation_ts"] = rec.creation_ts.empty() ? 0 :
        static_cast<int64_t>(std::stoll(rec.creation_ts));
    u["user_type"] = rec.user_type.empty() ? json(nullptr) : json(rec.user_type);
    u["erased"] = rec.erased;
    u["approved"] = rec.approved ? 1 : 0;
    u["consent_version"] = rec.consent_version;
    u["consent_given"] = rec.consent_given;
    if (!rec.consent_ts.empty()) {
        u["consent_ts"] = static_cast<int64_t>(std::stoll(rec.consent_ts));
    }

    // External IDs
    if (!rec.external_ids.empty()) {
        try { u["external_ids"] = json::parse(rec.external_ids); }
        catch (...) { u["external_ids"] = json::array(); }
    } else {
        u["external_ids"] = json::array();
    }

    // Threepids
    if (!rec.threepids.empty()) {
        try { u["threepids"] = json::parse(rec.threepids); }
        catch (...) { u["threepids"] = json::array(); }
    } else {
        u["threepids"] = json::array();
    }

    if (!rec.email.empty()) {
        u["email"] = rec.email;
    }

    // Rate limit info
    u["rate_limit_overridden"] = rec.rate_limit_overridden;
    if (rec.rate_limit_overridden) {
        u["rate_limit_messages_per_second"] = rec.rate_limit_messages_per_second;
        u["rate_limit_burst_count"] = rec.rate_limit_burst_count;
        if (!rec.rate_limit_overridden_ts.empty()) {
            u["rate_limit_overridden_ts"] = static_cast<int64_t>(
                std::stoll(rec.rate_limit_overridden_ts));
        }
    }

    // Export info
    u["last_export_ts"] = rec.last_export_ts.empty() ? json(nullptr) :
        json(static_cast<int64_t>(std::stoll(rec.last_export_ts)));
    u["export_count"] = rec.export_count;

    // Password hash info (masked in non-sensitive context)
    if (include_sensitive) {
        json pw;
        pw["hashed"] = !rec.password_hash.empty();
        if (!rec.password_hash.empty()) {
            pw["functions"] = {
                {"algorithm", "bcrypt"},
                {"bits", 256},
                {"rounds", 12}
            };
        }
        u["password_hash"] = pw;
    }

    return u;
}

// Serialize a device record to JSON
json device_record_to_json(const db::DeviceRecord& dev) {
    json d;
    d["device_id"] = dev.device_id;
    d["user_id"] = dev.user_id;
    d["display_name"] = dev.display_name;
    d["last_seen_ip"] = dev.last_seen_ip;
    d["last_seen_user_agent"] = dev.last_seen_user_agent;
    d["last_seen_ts"] = dev.last_seen_ts.empty() ? 0 :
        static_cast<int64_t>(std::stoll(dev.last_seen_ts));
    d["creation_ts"] = dev.creation_ts.empty() ? 0 :
        static_cast<int64_t>(std::stoll(dev.creation_ts));
    d["is_active"] = dev.is_active;
    d["hidden"] = dev.hidden;
    d["device_type"] = dev.device_type;
    return d;
}

// Serialize a pusher record to JSON
json pusher_record_to_json(const db::PusherRecord& p) {
    json r;
    r["pusher_id"] = p.pusher_id;
    r["user_id"] = p.user_id;
    r["app_id"] = p.app_id;
    r["app_display_name"] = p.app_display_name;
    r["device_display_name"] = p.device_display_name;
    r["pushkey"] = p.pushkey;
    r["kind"] = p.kind;
    r["lang"] = p.lang;
    r["profile_tag"] = p.profile_tag;
    r["enabled"] = p.enabled;
    r["created_ts"] = p.created_ts.empty() ? 0 :
        static_cast<int64_t>(std::stoll(p.created_ts));
    r["updated_ts"] = p.updated_ts.empty() ? 0 :
        static_cast<int64_t>(std::stoll(p.updated_ts));
    r["has_device"] = p.has_device;
    r["device_id"] = p.device_id;
    if (!p.data.empty()) {
        try { r["data"] = json::parse(p.data); }
        catch (...) { r["data"] = json::object(); }
    }
    return r;
}

// Serialize a room record to JSON
json room_record_to_json(const db::RoomRecord& room) {
    json r;
    r["room_id"] = room.room_id;
    r["name"] = room.name;
    r["canonical_alias"] = room.canonical_alias;
    r["creator"] = room.creator;
    r["creation_ts"] = room.creation_ts.empty() ? 0 :
        static_cast<int64_t>(std::stoll(room.creation_ts));
    r["topic"] = room.topic;
    r["avatar_url"] = room.avatar_url;
    r["joined_members"] = room.joined_members;
    r["invited_members"] = room.invited_members;
    r["banned_members"] = room.banned_members;
    r["total_members"] = room.total_members;
    r["blocked"] = room.blocked;
    r["is_encrypted"] = room.is_encrypted;
    r["federatable"] = room.federatable;
    r["public"] = room.public_room;
    r["join_rules"] = room.join_rules;
    r["guest_access"] = room.guest_access;
    r["history_visibility"] = room.history_visibility;
    r["room_version"] = room.room_version;
    r["room_type"] = room.room_type;
    return r;
}

} // anonymous namespace

// ============================================================================
// 1. GET /_synapse/admin/v1/users
// List all users with optional filters and pagination.
//
// Query params:
//   from, limit     - pagination
//   name            - substring filter on displayname or user ID
//   guests          - boolean filter: show only guests
//   deactivated     - boolean filter: show only deactivated
//   user_id         - exact match on user ID
//   order_by        - "name", "user_id", "creation_ts", "is_admin"
//   dir             - "f" (forward) or "b" (backward)
//   admins          - boolean filter: show only admins
//   locked          - boolean filter: show only locked
//   shadow_banned   - boolean filter: show only shadow-banned
//   not_user_id     - exclude a specific user
// ============================================================================

json handle_list_users(const json& params,
                        const json& body,
                        const std::string& request_path) {
    std::lock_guard<std::mutex> lock(db::users_mutex);

    // Parse pagination
    int from = parse_int_param(params, "from", 0);
    int limit = std::min(parse_int_param(params, "limit", 100), 500);

    // Parse ordering
    std::string order_by = parse_string_param(params, "order_by", "name");
    std::string dir = parse_string_param(params, "dir", "f");

    // Parse filters
    std::string name_filter = parse_string_param(params, "name");
    std::string user_id_filter = parse_string_param(params, "user_id");
    std::string not_user_id = parse_string_param(params, "not_user_id");

    bool guests_filter_set = params.contains("guests");
    bool guests_filter = parse_bool_param(params, "guests", false);

    bool deactivated_filter_set = params.contains("deactivated");
    bool deactivated_filter = parse_bool_param(params, "deactivated", false);

    bool admins_filter_set = params.contains("admins");
    bool admins_filter = parse_bool_param(params, "admins", false);

    bool locked_filter_set = params.contains("locked");
    bool locked_filter = parse_bool_param(params, "locked", false);

    bool shadow_banned_filter_set = params.contains("shadow_banned");
    bool shadow_banned_filter = parse_bool_param(params, "shadow_banned", false);

    bool approved_filter_set = params.contains("approved");
    bool approved_filter = parse_bool_param(params, "approved", true);

    // Collect and filter users
    std::vector<db::UserRecord> filtered;
    filtered.reserve(db::users.size());

    for (const auto& [uid, rec] : db::users) {
        // Apply filters
        if (!user_id_filter.empty() && uid != user_id_filter) continue;
        if (!not_user_id.empty() && uid == not_user_id) continue;
        if (!name_filter.empty() &&
            !matches_filter(rec.displayname, name_filter) &&
            !matches_filter(rec.id, name_filter)) continue;
        if (guests_filter_set && rec.is_guest != guests_filter) continue;
        if (deactivated_filter_set && rec.deactivated != deactivated_filter) continue;
        if (admins_filter_set && rec.admin != admins_filter) continue;
        if (locked_filter_set && rec.locked != locked_filter) continue;
        if (shadow_banned_filter_set && rec.shadow_banned != shadow_banned_filter) continue;
        if (approved_filter_set && rec.approved != approved_filter) continue;
        if (rec.erased && !deactivated_filter) continue;
        filtered.push_back(rec);
    }

    // Sort
    std::sort(filtered.begin(), filtered.end(),
        [&](const db::UserRecord& a, const db::UserRecord& b) {
            int cmp = 0;
            if (order_by == "name") {
                cmp = a.displayname.compare(b.displayname);
                if (cmp == 0) cmp = a.id.compare(b.id);
            } else if (order_by == "user_id") {
                cmp = a.id.compare(b.id);
            } else if (order_by == "creation_ts") {
                cmp = a.creation_ts.compare(b.creation_ts);
                if (cmp == 0) cmp = a.id.compare(b.id);
            } else if (order_by == "is_admin") {
                cmp = (a.admin ? 1 : 0) - (b.admin ? 1 : 0);
                if (cmp == 0) cmp = a.id.compare(b.id);
            } else if (order_by == "displayname") {
                cmp = a.displayname.compare(b.displayname);
                if (cmp == 0) cmp = a.id.compare(b.id);
            } else if (order_by == "avatar_url") {
                cmp = a.avatar_url.compare(b.avatar_url);
                if (cmp == 0) cmp = a.id.compare(b.id);
            } else if (order_by == "deactivated") {
                cmp = (a.deactivated ? 1 : 0) - (b.deactivated ? 1 : 0);
                if (cmp == 0) cmp = a.id.compare(b.id);
            } else if (order_by == "locked") {
                cmp = (a.locked ? 1 : 0) - (b.locked ? 1 : 0);
                if (cmp == 0) cmp = a.id.compare(b.id);
            } else if (order_by == "shadow_banned") {
                cmp = (a.shadow_banned ? 1 : 0) - (b.shadow_banned ? 1 : 0);
                if (cmp == 0) cmp = a.id.compare(b.id);
            } else {
                cmp = a.id.compare(b.id);
            }
            return (dir == "b") ? (cmp > 0) : (cmp < 0);
        });

    int total = static_cast<int>(filtered.size());

    // Apply from/limit
    json users_array = json::array();
    int end = std::min(from + limit, total);
    for (int i = from; i < end; ++i) {
        users_array.push_back(user_record_to_json(filtered[i], false));
    }

    json resp;
    resp["users"] = users_array;
    resp["total"] = total;
    resp["from"] = from;
    resp["limit"] = limit;
    if (end < total) {
        resp["next_token"] = std::to_string(end);
    }

    // Add summary statistics if this is the first page
    if (from == 0) {
        int active = 0, deactivated = 0, admins = 0, locked = 0, shadow_banned = 0;
        for (const auto& rec : filtered) {
            if (rec.deactivated) deactivated++; else active++;
            if (rec.admin) admins++;
            if (rec.locked) locked++;
            if (rec.shadow_banned) shadow_banned++;
        }
        resp["summary"] = {
            {"total_users", total},
            {"active_users", active},
            {"deactivated_users", deactivated},
            {"admin_users", admins},
            {"locked_users", locked},
            {"shadow_banned_users", shadow_banned}
        };
    }

    return resp;
}

// ============================================================================
// 2. GET /_synapse/admin/v1/users/{userId}/details
// Get comprehensive user details: profile, devices, threepids, connections,
// joined rooms, pushers, consent, external IDs, rate-limit overrides,
// and export history.
// ============================================================================

json handle_get_user_details(const json& params,
                              const json& body,
                              const std::string& request_path) {
    std::string user_id;
    if (!extract_user_id_from_path(request_path,
            "/_synapse/admin/v1/users/", user_id)) {
        return error_response("M_UNKNOWN", "Invalid request path", 400);
    }
    // Strip any suffix like /details
    auto details_pos = user_id.find("/details");
    if (details_pos != std::string::npos) {
        user_id = user_id.substr(0, details_pos);
    }

    if (!is_valid_user_id(user_id)) {
        return error_response("M_INVALID_PARAM",
            "Invalid user ID: " + user_id, 400);
    }

    json resp;

    // --- User profile ---
    {
        std::lock_guard<std::mutex> lock(db::users_mutex);
        auto it = db::users.find(user_id);
        if (it == db::users.end()) {
            return error_response("M_NOT_FOUND",
                "User not found: " + user_id, 404);
        }
        resp["profile"] = user_record_to_json(it->second, true);
    }

    // --- Devices ---
    {
        std::lock_guard<std::mutex> lock(db::devices_mutex);
        json devices_array = json::array();
        auto uit = db::user_devices.find(user_id);
        if (uit != db::user_devices.end()) {
            for (const auto& did : uit->second) {
                auto dit = db::devices.find(did);
                if (dit != db::devices.end() && !dit->second.hidden) {
                    devices_array.push_back(device_record_to_json(dit->second));
                }
            }
        }
        resp["devices"] = {
            {"total", devices_array.size()},
            {"devices", devices_array}
        };
    }

    // --- Pushers ---
    {
        std::lock_guard<std::mutex> lock(db::pushers_mutex);
        json pushers_array = json::array();
        auto pit = db::user_pushers.find(user_id);
        if (pit != db::user_pushers.end()) {
            for (const auto& pid : pit->second) {
                auto ppit = db::pushers.find(pid);
                if (ppit != db::pushers.end()) {
                    pushers_array.push_back(pusher_record_to_json(ppit->second));
                }
            }
        }
        resp["pushers"] = {
            {"total", pushers_array.size()},
            {"pushers", pushers_array}
        };
    }

    // --- Connections ---
    {
        std::lock_guard<std::mutex> lock(db::connections_mutex);
        json conns_array = json::array();
        auto cit = db::user_connections.find(user_id);
        if (cit != db::user_connections.end()) {
            for (const auto& cid : cit->second) {
                auto ccit = db::connections.find(cid);
                if (ccit != db::connections.end() && ccit->second.is_active) {
                    json c;
                    c["connection_id"] = ccit->second.connection_id;
                    c["ip_address"] = ccit->second.ip_address;
                    c["user_agent"] = ccit->second.user_agent;
                    c["last_seen_ts"] = ccit->second.last_seen_ts.empty() ? 0 :
                        static_cast<int64_t>(std::stoll(ccit->second.last_seen_ts));
                    c["connected_since"] = ccit->second.connected_since.empty() ? 0 :
                        static_cast<int64_t>(std::stoll(ccit->second.connected_since));
                    c["device_id"] = ccit->second.device_id;
                    c["is_active"] = ccit->second.is_active;
                    c["request_count"] = ccit->second.request_count;
                    conns_array.push_back(c);
                }
            }
        }
        resp["connections"] = {
            {"total", conns_array.size()},
            {"connections", conns_array}
        };
    }

    // --- Rooms ---
    {
        std::lock_guard<std::mutex> lock(db::membership_mutex);
        json rooms_array = json::array();
        auto rit = db::user_rooms.find(user_id);
        if (rit != db::user_rooms.end()) {
            for (const auto& rid : rit->second) {
                std::string key = rid + ":" + user_id;
                auto mit = db::memberships.find(key);
                if (mit != db::memberships.end()) {
                    json r;
                    r["room_id"] = rid;
                    r["membership"] = mit->second.membership;
                    r["sender"] = mit->second.sender;
                    r["origin_server_ts"] = mit->second.origin_server_ts.empty() ? 0 :
                        static_cast<int64_t>(std::stoll(mit->second.origin_server_ts));
                    r["is_direct"] = mit->second.is_direct;
                    // Get room name if available
                    {
                        std::lock_guard<std::mutex> rlock(db::rooms_mutex);
                        auto room_it = db::rooms.find(rid);
                        if (room_it != db::rooms.end()) {
                            r["room_name"] = room_it->second.name;
                            r["room_canonical_alias"] = room_it->second.canonical_alias;
                            r["room_joined_members"] = room_it->second.joined_members;
                            r["room_total_members"] = room_it->second.total_members;
                            r["room_public"] = room_it->second.public_room;
                            r["room_encrypted"] = room_it->second.is_encrypted;
                        }
                    }
                    rooms_array.push_back(r);
                }
            }
        }
        // Sort rooms by membership: join first, then invite, then leave, then ban
        std::sort(rooms_array.begin(), rooms_array.end(),
            [](const json& a, const json& b) {
                auto priority = [](const std::string& m) -> int {
                    if (m == "join") return 0;
                    if (m == "invite") return 1;
                    if (m == "knock") return 2;
                    if (m == "leave") return 3;
                    if (m == "ban") return 4;
                    return 5;
                };
                return priority(a["membership"].get<std::string>()) <
                       priority(b["membership"].get<std::string>());
            });

        json room_summary;
        int joined = 0, invited = 0, left = 0, banned = 0, knocked = 0;
        for (const auto& r : rooms_array) {
            std::string m = r["membership"].get<std::string>();
            if (m == "join") joined++;
            else if (m == "invite") invited++;
            else if (m == "leave") left++;
            else if (m == "ban") banned++;
            else if (m == "knock") knocked++;
        }
        room_summary["total"] = static_cast<int>(rooms_array.size());
        room_summary["joined"] = joined;
        room_summary["invited"] = invited;
        room_summary["left"] = left;
        room_summary["banned"] = banned;
        room_summary["knocked"] = knocked;

        resp["rooms"] = {
            {"summary", room_summary},
            {"rooms", rooms_array}
        };
    }

    // --- Rate-limit overrides ---
    {
        std::lock_guard<std::mutex> lock(db::users_mutex);
        auto it = db::users.find(user_id);
        if (it != db::users.end()) {
            json rlo;
            rlo["overridden"] = it->second.rate_limit_overridden;
            if (it->second.rate_limit_overridden) {
                rlo["messages_per_second"] = it->second.rate_limit_messages_per_second;
                rlo["burst_count"] = it->second.rate_limit_burst_count;
                rlo["overridden_ts"] = it->second.rate_limit_overridden_ts.empty() ? 0 :
                    static_cast<int64_t>(std::stoll(it->second.rate_limit_overridden_ts));
                rlo["overridden_by"] = it->second.rate_limit_overridden_by;
            }
            resp["rate_limit_override"] = rlo;
        }
    }

    // --- Export history ---
    {
        std::lock_guard<std::mutex> lock(db::users_mutex);
        auto it = db::users.find(user_id);
        if (it != db::users.end()) {
            json exp;
            exp["last_export_ts"] = it->second.last_export_ts.empty() ?
                json(nullptr) :
                json(static_cast<int64_t>(std::stoll(it->second.last_export_ts)));
            exp["export_count"] = it->second.export_count;
            resp["export_history"] = exp;
        }
    }

    // --- Full detail timestamp ---
    resp["details_generated_ts"] = static_cast<int64_t>(std::stoll(now_ms()));

    return resp;
}

// ============================================================================
// 3. POST /_synapse/admin/v1/users
// Create a new Matrix user with admin-specified attributes.
//
// Body:
//   username    (required) - localpart for the user
//   password    (required) - initial password
//   admin       (optional) - bool, default false
//   displayname (optional) - string
//   avatar_url  (optional) - mxc:// URI
//   threepids   (optional) - JSON array of third-party identifiers
//   email       (optional) - email address
//   user_type   (optional) - null, "support", or "bot"
//   locked      (optional) - bool, default false
//   server_name (optional) - override the default server name
// ============================================================================

json handle_create_user(const json& params,
                         const json& body,
                         const std::string& request_path) {
    // Mandatory fields
    if (!body.contains("username") || !body["username"].is_string()) {
        return error_response("M_MISSING_PARAM", "username is required", 400);
    }
    if (!body.contains("password") || !body["password"].is_string()) {
        return error_response("M_MISSING_PARAM", "password is required", 400);
    }

    std::string localpart = body["username"].get<std::string>();
    std::string password = body["password"].get<std::string>();

    // Password strength validation
    if (password.size() < 8) {
        return error_response("M_WEAK_PASSWORD",
            "Password must be at least 8 characters", 400);
    }

    // Validate localpart
    if (localpart.empty()) {
        return error_response("M_INVALID_PARAM",
            "username must not be empty", 400);
    }
    if (localpart.find(':') != std::string::npos) {
        return error_response("M_INVALID_PARAM",
            "username must not contain ':'", 400);
    }
    if (localpart.find('@') != std::string::npos) {
        return error_response("M_INVALID_PARAM",
            "username must not contain '@' — provide only the localpart", 400);
    }
    // Validate against allowed characters
    for (char c : localpart) {
        if (!std::isalnum(static_cast<unsigned char>(c)) &&
            c != '.' && c != '_' && c != '-' && c != '=' && c != '/') {
            return error_response("M_INVALID_PARAM",
                "username contains invalid character: '" + std::string(1, c) + "'", 400);
        }
    }

    // Build full user ID
    std::string server_name = "localhost:8008";
    if (params.contains("server_name")) {
        server_name = parse_string_param(params, "server_name");
    }
    if (body.contains("server_name") && body["server_name"].is_string()) {
        server_name = body["server_name"].get<std::string>();
    }
    std::string full_uid = "@" + localpart + ":" + server_name;

    std::lock_guard<std::mutex> lock(db::users_mutex);

    // Check for duplicate
    if (db::users.find(full_uid) != db::users.end()) {
        return error_response("M_USER_IN_USE",
            "User " + full_uid + " already exists", 409);
    }

    // Check for duplicate localpart across any domain (optional strictness)
    for (const auto& [uid, rec] : db::users) {
        if (localpart == ::localpart(uid)) {
            return error_response("M_USER_IN_USE",
                "A user with localpart '" + localpart + "' already exists", 409);
        }
    }

    db::UserRecord rec;
    rec.id = full_uid;
    rec.password_hash = hash_password(password);
    rec.creation_ts = now_ms();
    rec.admin = body.value("admin", false);
    rec.displayname = body.value("displayname", localpart);
    rec.avatar_url = body.value("avatar_url", "");
    rec.locked = body.value("locked", false);
    rec.deactivated = false;
    rec.shadow_banned = false;
    rec.approved = true;

    // user_type
    if (body.contains("user_type") && body["user_type"].is_string()) {
        std::string ut = body["user_type"].get<std::string>();
        if (ut == "support" || ut == "bot") {
            rec.user_type = ut;
        }
    }

    // threepids
    if (body.contains("threepids") && body["threepids"].is_array()) {
        rec.threepids = body["threepids"].dump();
    }

    // email
    if (body.contains("email") && body["email"].is_string()) {
        rec.email = body["email"].get<std::string>();
    }

    // consent
    if (body.contains("consent_version") && body["consent_version"].is_string()) {
        rec.consent_version = body["consent_version"].get<std::string>();
        rec.consent_ts = now_ms();
        rec.consent_given = true;
    }

    db::users[full_uid] = rec;

    // Create a default device record for the new user
    {
        std::lock_guard<std::mutex> dlock(db::devices_mutex);
        db::DeviceRecord default_dev;
        default_dev.device_id = "INIT_" + random_hex(8);
        default_dev.user_id = full_uid;
        default_dev.display_name = "Initial Device";
        default_dev.device_type = "unknown";
        default_dev.creation_ts = now_ms();
        default_dev.last_seen_ts = now_ms();
        default_dev.last_seen_ip = "127.0.0.1";
        default_dev.is_active = true;
        db::devices[default_dev.device_id] = default_dev;
        db::user_devices[full_uid].push_back(default_dev.device_id);
    }

    json resp;
    resp["name"] = full_uid;
    resp["displayname"] = rec.displayname;
    resp["admin"] = rec.admin ? 1 : 0;
    resp["deactivated"] = rec.deactivated;
    resp["shadow_banned"] = rec.shadow_banned;
    resp["creation_ts"] = static_cast<int64_t>(std::stoll(rec.creation_ts));
    resp["user_type"] = rec.user_type.empty() ? json(nullptr) : json(rec.user_type);
    resp["approved"] = rec.approved ? 1 : 0;
    resp["message"] = "User created successfully";
    return resp;
}

// ============================================================================
// 4. POST /_synapse/admin/v1/users/{userId}/deactivate
// Deactivate a user account.
//
// Body:
//   erase  (optional) - bool, if true GDPR-erase user data
//   reason (optional) - string, audit reason for deactivation
// ============================================================================

json handle_deactivate_user(const json& params,
                             const json& body,
                             const std::string& request_path) {
    std::string user_id;
    if (!extract_user_id_from_path(request_path,
            "/_synapse/admin/v1/users/", user_id)) {
        return error_response("M_UNKNOWN", "Invalid request path", 400);
    }
    // Strip /deactivate suffix
    auto pos = user_id.find("/deactivate");
    if (pos != std::string::npos) user_id = user_id.substr(0, pos);

    if (!is_valid_user_id(user_id)) {
        return error_response("M_INVALID_PARAM",
            "Invalid user ID: " + user_id, 400);
    }

    bool erase = parse_bool_param(body, "erase", false);
    std::string reason = body.value("reason", "Administrative deactivation");

    std::lock_guard<std::mutex> lock(db::users_mutex);

    auto it = db::users.find(user_id);
    if (it == db::users.end()) {
        return error_response("M_NOT_FOUND",
            "User not found: " + user_id, 404);
    }

    if (it->second.deactivated) {
        return error_response("M_INVALID_STATE",
            "User " + user_id + " is already deactivated", 409);
    }

    auto& rec = it->second;
    rec.deactivated = true;

    if (erase) {
        // GDPR-compliant erasure: scrub personal data, retain only the
        // user ID for audit trail purposes. This DOES NOT delete the
        // user record entirely — that would break audit integrity.
        rec.displayname = "[erased]";
        rec.avatar_url = "";
        rec.email = "";
        rec.threepids = "[]";
        rec.external_ids = "[]";
        rec.password_hash = "";
        rec.password_salt = "";
        rec.password_hash_iterations = 0;
        rec.consent_version = "";
        rec.consent_ts = "";
        rec.consent_given = false;
        rec.erased = true;
        rec.admin = false;           // remove admin privileges on erasure
        rec.locked = false;
        rec.shadow_banned = false;
        rec.user_type = "";
        rec.approved = false;
    }

    // Deactivate all devices
    {
        std::lock_guard<std::mutex> dlock(db::devices_mutex);
        auto dit = db::user_devices.find(user_id);
        if (dit != db::user_devices.end()) {
            for (const auto& did : dit->second) {
                auto dev_it = db::devices.find(did);
                if (dev_it != db::devices.end()) {
                    dev_it->second.is_active = false;
                    dev_it->second.hidden = erase;
                }
            }
        }
    }

    // Deactivate all connections
    {
        std::lock_guard<std::mutex> clock(db::connections_mutex);
        auto cit = db::user_connections.find(user_id);
        if (cit != db::user_connections.end()) {
            for (const auto& cid : cit->second) {
                auto conn_it = db::connections.find(cid);
                if (conn_it != db::connections.end()) {
                    conn_it->second.is_active = false;
                }
            }
        }
    }

    // Disable all pushers
    {
        std::lock_guard<std::mutex> plock(db::pushers_mutex);
        auto pit = db::user_pushers.find(user_id);
        if (pit != db::user_pushers.end()) {
            for (const auto& pid : pit->second) {
                auto pusher_it = db::pushers.find(pid);
                if (pusher_it != db::pushers.end()) {
                    pusher_it->second.enabled = false;
                }
            }
        }
    }

    // Remove rate-limit overrides
    {
        std::lock_guard<std::mutex> ulock(db::users_mutex);
        rec.rate_limit_overridden = false;
        rec.rate_limit_messages_per_second = 0;
        rec.rate_limit_burst_count = 0;
    }

    json resp;
    resp["deactivated"] = true;
    resp["user_id"] = user_id;
    resp["erased"] = erase;
    resp["reason"] = reason;
    resp["timestamp"] = static_cast<int64_t>(std::stoll(now_ms()));
    resp["id_server_unbind_result"] = "success";
    return resp;
}

// ============================================================================
// 5. POST /_synapse/admin/v1/users/{userId}/reactivate
// Reactivate a previously deactivated user account.
//
// Body:
//   reason          (optional) - audit reason
//   restore_devices (optional) - bool, default true: re-enable devices
// ============================================================================

json handle_reactivate_user(const json& params,
                             const json& body,
                             const std::string& request_path) {
    std::string user_id;
    if (!extract_user_id_from_path(request_path,
            "/_synapse/admin/v1/users/", user_id)) {
        return error_response("M_UNKNOWN", "Invalid request path", 400);
    }
    auto pos = user_id.find("/reactivate");
    if (pos != std::string::npos) user_id = user_id.substr(0, pos);

    if (!is_valid_user_id(user_id)) {
        return error_response("M_INVALID_PARAM",
            "Invalid user ID: " + user_id, 400);
    }

    std::string reason = body.value("reason", "Administrative reactivation");
    bool restore_devices = body.value("restore_devices", true);

    std::lock_guard<std::mutex> lock(db::users_mutex);

    auto it = db::users.find(user_id);
    if (it == db::users.end()) {
        return error_response("M_NOT_FOUND",
            "User not found: " + user_id, 404);
    }

    if (!it->second.deactivated) {
        return error_response("M_INVALID_STATE",
            "User " + user_id + " is not deactivated", 409);
    }

    if (it->second.erased) {
        return error_response("M_FORBIDDEN",
            "Cannot reactivate an erased user. Data has been permanently removed.", 403);
    }

    it->second.deactivated = false;
    it->second.approved = true;

    // Re-enable devices if requested
    if (restore_devices) {
        std::lock_guard<std::mutex> dlock(db::devices_mutex);
        auto dit = db::user_devices.find(user_id);
        if (dit != db::user_devices.end()) {
            int restored = 0;
            for (const auto& did : dit->second) {
                auto dev_it = db::devices.find(did);
                if (dev_it != db::devices.end() && !dev_it->second.hidden) {
                    dev_it->second.is_active = true;
                    restored++;
                }
            }
        }
    }

    json resp;
    resp["reactivated"] = true;
    resp["user_id"] = user_id;
    resp["reason"] = reason;
    resp["restore_devices"] = restore_devices;
    resp["timestamp"] = static_cast<int64_t>(std::stoll(now_ms()));
    return resp;
}

// ============================================================================
// 6. POST /_synapse/admin/v1/users/{userId}/shadow_ban
// Shadow-ban a user: their messages are not delivered to other users,
// but they are not informed of the ban. Messages appear sent from the
// user's perspective but are silently dropped for recipients.
//
// Body:
//   shadow_ban  (required) - bool, true to enable, false to disable
//   reason      (optional) - audit reason
// ============================================================================

json handle_shadow_ban_user(const json& params,
                             const json& body,
                             const std::string& request_path) {
    std::string user_id;
    if (!extract_user_id_from_path(request_path,
            "/_synapse/admin/v1/users/", user_id)) {
        return error_response("M_UNKNOWN", "Invalid request path", 400);
    }
    auto pos = user_id.find("/shadow_ban");
    if (pos != std::string::npos) user_id = user_id.substr(0, pos);

    if (!is_valid_user_id(user_id)) {
        return error_response("M_INVALID_PARAM",
            "Invalid user ID: " + user_id, 400);
    }

    if (!body.contains("shadow_ban") || !body["shadow_ban"].is_boolean()) {
        return error_response("M_MISSING_PARAM",
            "shadow_ban (boolean) is required", 400);
    }

    bool shadow_ban = body["shadow_ban"].get<bool>();
    std::string reason = body.value("reason",
        shadow_ban ? "Administrative shadow-ban" : "Administrative un-shadow-ban");

    std::lock_guard<std::mutex> lock(db::users_mutex);

    auto it = db::users.find(user_id);
    if (it == db::users.end()) {
        return error_response("M_NOT_FOUND",
            "User not found: " + user_id, 404);
    }

    if (it->second.shadow_banned == shadow_ban) {
        return error_response("M_INVALID_STATE",
            shadow_ban ? "User is already shadow-banned"
                       : "User is not shadow-banned", 409);
    }

    it->second.shadow_banned = shadow_ban;

    // If shadow-banning, also revoke pushers temporarily
    if (shadow_ban) {
        std::lock_guard<std::mutex> plock(db::pushers_mutex);
        auto pit = db::user_pushers.find(user_id);
        if (pit != db::user_pushers.end()) {
            for (const auto& pid : pit->second) {
                auto pusher_it = db::pushers.find(pid);
                if (pusher_it != db::pushers.end()) {
                    pusher_it->second.enabled = false;
                }
            }
        }
    }

    json resp;
    resp["shadow_banned"] = shadow_ban;
    resp["user_id"] = user_id;
    resp["reason"] = reason;
    resp["timestamp"] = static_cast<int64_t>(std::stoll(now_ms()));
    resp["warning"] = shadow_ban ?
        "User is now shadow-banned. Their messages will be silently dropped." :
        "Shadow-ban removed. User messages will now be delivered normally.";
    return resp;
}

// ============================================================================
// 7. POST /_synapse/admin/v1/users/{userId}/override_ratelimit
// Override rate-limiting for a specific user.
//
// Body:
//   messages_per_second  (required) - int, 0 for unlimited
//   burst_count          (required) - int, 0 for unlimited
//   reason               (optional) - audit reason
// ============================================================================

json handle_override_ratelimit(const json& params,
                                const json& body,
                                const std::string& request_path) {
    std::string user_id;
    if (!extract_user_id_from_path(request_path,
            "/_synapse/admin/v1/users/", user_id)) {
        return error_response("M_UNKNOWN", "Invalid request path", 400);
    }
    auto pos = user_id.find("/override_ratelimit");
    if (pos != std::string::npos) user_id = user_id.substr(0, pos);

    if (!is_valid_user_id(user_id)) {
        return error_response("M_INVALID_PARAM",
            "Invalid user ID: " + user_id, 400);
    }

    if (!body.contains("messages_per_second") || !body["messages_per_second"].is_number()) {
        return error_response("M_MISSING_PARAM",
            "messages_per_second (integer) is required", 400);
    }
    if (!body.contains("burst_count") || !body["burst_count"].is_number()) {
        return error_response("M_MISSING_PARAM",
            "burst_count (integer) is required", 400);
    }

    int64_t mps = body["messages_per_second"].get<int64_t>();
    int64_t bc = body["burst_count"].get<int64_t>();
    std::string reason = body.value("reason", "Administrative rate-limit override");
    std::string admin_id = body.value("admin_id", "system");

    if (mps < 0) {
        return error_response("M_INVALID_PARAM",
            "messages_per_second must be >= 0 (0 = unlimited)", 400);
    }
    if (bc < 0) {
        return error_response("M_INVALID_PARAM",
            "burst_count must be >= 0 (0 = unlimited)", 400);
    }

    std::string ts = now_ms();

    // Update user record
    {
        std::lock_guard<std::mutex> lock(db::users_mutex);
        auto it = db::users.find(user_id);
        if (it == db::users.end()) {
            return error_response("M_NOT_FOUND",
                "User not found: " + user_id, 404);
        }
        it->second.rate_limit_overridden = true;
        it->second.rate_limit_messages_per_second = mps;
        it->second.rate_limit_burst_count = bc;
        it->second.rate_limit_overridden_ts = ts;
        it->second.rate_limit_overridden_by = admin_id;
    }

    // Store in rate-limit overrides table
    {
        std::lock_guard<std::mutex> lock(db::users_mutex);
        db::RateLimitOverride rlo;
        rlo.user_id = user_id;
        rlo.overridden_by = admin_id;
        rlo.overridden_ts = ts;
        rlo.messages_per_second = mps;
        rlo.burst_count = bc;
        rlo.reason = reason;
        rlo.active = true;
        db::rate_limit_overrides[user_id] = rlo;
    }

    json resp;
    resp["user_id"] = user_id;
    resp["rate_limit_overridden"] = true;
    resp["messages_per_second"] = mps;
    resp["burst_count"] = bc;
    resp["reason"] = reason;
    resp["overridden_by"] = admin_id;
    resp["overridden_ts"] = static_cast<int64_t>(std::stoll(ts));
    resp["note"] = (mps == 0 && bc == 0) ?
        "Rate limits fully disabled for this user" :
        "Rate limits have been overridden";
    return resp;
}

// ============================================================================
// 8. POST /_synapse/admin/v1/users/{userId}/reset_password
// Admin password reset for a user.
//
// Body:
//   new_password    (required) - string, the new password
//   logout_devices  (optional) - bool, default true
//   reason          (optional) - audit reason
// ============================================================================

json handle_reset_password(const json& params,
                            const json& body,
                            const std::string& request_path) {
    std::string user_id;
    if (!extract_user_id_from_path(request_path,
            "/_synapse/admin/v1/users/", user_id)) {
        return error_response("M_UNKNOWN", "Invalid request path", 400);
    }
    auto pos = user_id.find("/reset_password");
    if (pos != std::string::npos) user_id = user_id.substr(0, pos);

    if (!is_valid_user_id(user_id)) {
        return error_response("M_INVALID_PARAM",
            "Invalid user ID: " + user_id, 400);
    }

    if (!body.contains("new_password") || !body["new_password"].is_string()) {
        return error_response("M_MISSING_PARAM",
            "new_password is required", 400);
    }

    std::string new_password = body["new_password"].get<std::string>();
    bool logout_devices = body.value("logout_devices", true);
    std::string reason = body.value("reason", "Administrative password reset");

    // Password strength
    if (new_password.size() < 8) {
        return error_response("M_WEAK_PASSWORD",
            "Password must be at least 8 characters", 400);
    }

    std::lock_guard<std::mutex> lock(db::users_mutex);

    auto it = db::users.find(user_id);
    if (it == db::users.end()) {
        return error_response("M_NOT_FOUND",
            "User not found: " + user_id, 404);
    }

    if (it->second.deactivated) {
        return error_response("M_INVALID_STATE",
            "Cannot reset password for a deactivated user", 409);
    }

    it->second.password_hash = hash_password(new_password);

    int device_count = 0;
    // Logout all devices if requested
    if (logout_devices) {
        std::lock_guard<std::mutex> dlock(db::devices_mutex);
        auto dit = db::user_devices.find(user_id);
        if (dit != db::user_devices.end()) {
            for (const auto& did : dit->second) {
                auto dev_it = db::devices.find(did);
                if (dev_it != db::devices.end() &&
                    did.substr(0, 5) != "INIT_") { // don't logout initial device
                    dev_it->second.is_active = false;
                    device_count++;
                }
            }
        }
    }

    json resp;
    resp["success"] = true;
    resp["user_id"] = user_id;
    resp["password_reset"] = true;
    resp["logout_devices"] = logout_devices;
    resp["devices_logged_out"] = device_count;
    resp["reason"] = reason;
    resp["timestamp"] = static_cast<int64_t>(std::stoll(now_ms()));
    return resp;
}

// ============================================================================
// 9. POST /_synapse/admin/v1/users/{userId}/registration_token
// Generate a registration token for a specific user (one-time use invite).
//
// Body:
//   uses_allowed  (optional) - int, default 1
//   expiry_time   (optional) - epoch ms, 0 = never
//   length        (optional) - token string length, default 16
// ============================================================================

json handle_generate_registration_token(const json& params,
                                         const json& body,
                                         const std::string& request_path) {
    std::string user_id;
    if (!extract_user_id_from_path(request_path,
            "/_synapse/admin/v1/users/", user_id)) {
        return error_response("M_UNKNOWN", "Invalid request path", 400);
    }
    auto pos = user_id.find("/registration_token");
    if (pos != std::string::npos) user_id = user_id.substr(0, pos);

    if (!is_valid_user_id(user_id)) {
        return error_response("M_INVALID_PARAM",
            "Invalid user ID: " + user_id, 400);
    }

    // Verify user exists
    {
        std::lock_guard<std::mutex> lock(db::users_mutex);
        if (db::users.find(user_id) == db::users.end()) {
            return error_response("M_NOT_FOUND",
                "User not found: " + user_id, 404);
        }
    }

    std::lock_guard<std::mutex> lock(db::tokens_mutex);

    db::RegistrationToken tok;
    tok.created_ts = now_ms();
    tok.created_by = body.value("created_by", "admin");

    // Uses allowed
    if (body.contains("uses_allowed") && body["uses_allowed"].is_number()) {
        int ua = body["uses_allowed"].get<int>();
        tok.uses_allowed = std::to_string(std::max(1, ua));
    } else {
        tok.uses_allowed = "1"; // default: single-use
    }

    // Expiry
    if (body.contains("expiry_time") && body["expiry_time"].is_number()) {
        tok.expiry_time = std::to_string(body["expiry_time"].get<int64_t>());
    } else if (body.contains("expiry_time") && body["expiry_time"].is_string()) {
        tok.expiry_time = body["expiry_time"].get<std::string>();
    } else {
        tok.expiry_time = "0"; // never expires
    }

    // Token string
    if (body.contains("token") && body["token"].is_string()) {
        tok.token = body["token"].get<std::string>();
    } else {
        int length = std::max(8, std::min(
            parse_int_param(body, "length", 16), 64));
        tok.token = random_token(length);
    }

    // Ensure uniqueness
    while (db::reg_tokens.find(tok.token) != db::reg_tokens.end()) {
        tok.token = random_token(16);
    }

    tok.for_user_id = user_id;

    db::reg_tokens[tok.token] = tok;

    json resp;
    resp["token"] = tok.token;
    resp["user_id"] = user_id;
    resp["uses_allowed"] = tok.uses_allowed == "0" ?
        json(nullptr) : json(std::stoll(tok.uses_allowed));
    resp["expiry_time"] = tok.expiry_time == "0" ?
        json(nullptr) : json(std::stoll(tok.expiry_time));
    resp["created_ts"] = static_cast<int64_t>(std::stoll(tok.created_ts));
    resp["created_by"] = tok.created_by;
    resp["completed"] = tok.completed;
    resp["pending"] = tok.pending;
    return resp;
}

// ============================================================================
// 10. GET /_synapse/admin/v1/users/{userId}/devices
// List all devices for a user.
//
// Query params:
//   include_hidden (optional) - bool, default false
//   from, limit    (optional) - pagination
// ============================================================================

json handle_list_user_devices(const json& params,
                               const json& body,
                               const std::string& request_path) {
    std::string user_id;
    if (!extract_user_id_from_path(request_path,
            "/_synapse/admin/v1/users/", user_id)) {
        return error_response("M_UNKNOWN", "Invalid request path", 400);
    }
    auto pos = user_id.find("/devices");
    if (pos != std::string::npos) user_id = user_id.substr(0, pos);

    if (!is_valid_user_id(user_id)) {
        return error_response("M_INVALID_PARAM",
            "Invalid user ID: " + user_id, 400);
    }

    // Verify user exists
    {
        std::lock_guard<std::mutex> lock(db::users_mutex);
        if (db::users.find(user_id) == db::users.end()) {
            return error_response("M_NOT_FOUND",
                "User not found: " + user_id, 404);
        }
    }

    bool include_hidden = parse_bool_param(params, "include_hidden", false);
    int from = parse_int_param(params, "from", 0);
    int limit = std::min(parse_int_param(params, "limit", 100), 500);

    std::lock_guard<std::mutex> lock(db::devices_mutex);

    // Collect devices
    std::vector<db::DeviceRecord> device_list;
    auto dit = db::user_devices.find(user_id);
    if (dit != db::user_devices.end()) {
        for (const auto& did : dit->second) {
            auto dev_it = db::devices.find(did);
            if (dev_it != db::devices.end()) {
                if (!include_hidden && dev_it->second.hidden) continue;
                device_list.push_back(dev_it->second);
            }
        }
    }

    // Sort by last_seen_ts descending (most recent first)
    std::sort(device_list.begin(), device_list.end(),
        [](const db::DeviceRecord& a, const db::DeviceRecord& b) {
            if (a.last_seen_ts.empty() && b.last_seen_ts.empty()) return false;
            if (a.last_seen_ts.empty()) return false;
            if (b.last_seen_ts.empty()) return true;
            return std::stoll(a.last_seen_ts) > std::stoll(b.last_seen_ts);
        });

    int total = static_cast<int>(device_list.size());

    json devices_array = json::array();
    int end = std::min(from + limit, total);
    for (int i = from; i < end; ++i) {
        devices_array.push_back(device_record_to_json(device_list[i]));
    }

    json resp;
    resp["user_id"] = user_id;
    resp["devices"] = devices_array;
    resp["total"] = total;
    resp["from"] = from;
    resp["limit"] = limit;
    if (end < total) {
        resp["next_token"] = std::to_string(end);
    }

    // Add summary
    int active_devices = 0, hidden_devices = 0;
    for (const auto& d : device_list) {
        if (d.is_active) active_devices++;
        if (d.hidden) hidden_devices++;
    }
    resp["summary"] = {
        {"total", total},
        {"active", active_devices},
        {"inactive", total - active_devices},
        {"hidden", hidden_devices}
    };

    return resp;
}

// ============================================================================
// 11. DELETE /_synapse/admin/v1/users/{userId}/devices/{deviceId}
// Delete (or hide) a specific device for a user.
//
// Body:
//   permanent (optional) - bool, default false (soft-delete/hide)
//   reason    (optional) - audit reason
// ============================================================================

json handle_delete_user_device(const json& params,
                                const json& body,
                                const std::string& request_path) {
    // Extract user_id and device_id from path:
    // /_synapse/admin/v1/users/{userId}/devices/{deviceId}
    std::string user_id;
    if (!extract_user_id_from_path(request_path,
            "/_synapse/admin/v1/users/", user_id)) {
        return error_response("M_UNKNOWN", "Invalid request path", 400);
    }

    // Find /devices/ separator
    auto dev_pos = user_id.find("/devices/");
    if (dev_pos == std::string::npos) {
        return error_response("M_UNKNOWN",
            "Invalid request path: missing /devices/{deviceId}", 400);
    }
    std::string device_id = user_id.substr(dev_pos + 9); // after "/devices/"
    user_id = user_id.substr(0, dev_pos);

    if (!is_valid_user_id(user_id)) {
        return error_response("M_INVALID_PARAM",
            "Invalid user ID: " + user_id, 400);
    }
    if (!is_valid_device_id(device_id)) {
        return error_response("M_INVALID_PARAM",
            "Invalid device ID: " + device_id, 400);
    }

    bool permanent = parse_bool_param(body, "permanent", false);
    std::string reason = body.value("reason",
        permanent ? "Permanent device deletion" : "Device soft-deletion");

    std::lock_guard<std::mutex> lock(db::devices_mutex);

    auto dev_it = db::devices.find(device_id);
    if (dev_it == db::devices.end()) {
        return error_response("M_NOT_FOUND",
            "Device not found: " + device_id, 404);
    }

    if (dev_it->second.user_id != user_id) {
        return error_response("M_FORBIDDEN",
            "Device " + device_id + " does not belong to user " + user_id, 403);
    }

    if (permanent) {
        // Hard delete: remove from both devices and user_devices
        db::devices.erase(device_id);
        auto& dev_list = db::user_devices[user_id];
        dev_list.erase(std::remove(dev_list.begin(), dev_list.end(), device_id),
                       dev_list.end());
    } else {
        // Soft delete: hide the device, deactivate it
        dev_it->second.hidden = true;
        dev_it->second.is_active = false;
    }

    json resp;
    resp["success"] = true;
    resp["user_id"] = user_id;
    resp["device_id"] = device_id;
    resp["permanent"] = permanent;
    resp["reason"] = reason;
    resp["timestamp"] = static_cast<int64_t>(std::stoll(now_ms()));
    resp["message"] = permanent ?
        "Device permanently deleted" :
        "Device soft-deleted (hidden and deactivated)";
    return resp;
}

// ============================================================================
// 12. GET /_synapse/admin/v1/users/{userId}/pushers
// List all pushers (push notification endpoints) for a user.
//
// Query params:
//   enabled_only (optional) - bool, default false
//   kind         (optional) - filter by kind ("http" or "email")
//   from, limit  (optional) - pagination
// ============================================================================

json handle_list_user_pushers(const json& params,
                               const json& body,
                               const std::string& request_path) {
    std::string user_id;
    if (!extract_user_id_from_path(request_path,
            "/_synapse/admin/v1/users/", user_id)) {
        return error_response("M_UNKNOWN", "Invalid request path", 400);
    }
    auto pos = user_id.find("/pushers");
    if (pos != std::string::npos) user_id = user_id.substr(0, pos);

    if (!is_valid_user_id(user_id)) {
        return error_response("M_INVALID_PARAM",
            "Invalid user ID: " + user_id, 400);
    }

    // Verify user exists
    {
        std::lock_guard<std::mutex> lock(db::users_mutex);
        if (db::users.find(user_id) == db::users.end()) {
            return error_response("M_NOT_FOUND",
                "User not found: " + user_id, 404);
        }
    }

    bool enabled_only = parse_bool_param(params, "enabled_only", false);
    std::string kind_filter = parse_string_param(params, "kind");
    int from = parse_int_param(params, "from", 0);
    int limit = std::min(parse_int_param(params, "limit", 100), 500);

    std::lock_guard<std::mutex> lock(db::pushers_mutex);

    // Collect pushers
    std::vector<db::PusherRecord> pusher_list;
    auto pit = db::user_pushers.find(user_id);
    if (pit != db::user_pushers.end()) {
        for (const auto& pid : pit->second) {
            auto ppit = db::pushers.find(pid);
            if (ppit != db::pushers.end()) {
                if (enabled_only && !ppit->second.enabled) continue;
                if (!kind_filter.empty() && ppit->second.kind != kind_filter) continue;
                pusher_list.push_back(ppit->second);
            }
        }
    }

    // Sort by creation time descending
    std::sort(pusher_list.begin(), pusher_list.end(),
        [](const db::PusherRecord& a, const db::PusherRecord& b) {
            return a.created_ts > b.created_ts;
        });

    int total = static_cast<int>(pusher_list.size());

    json pushers_array = json::array();
    int end = std::min(from + limit, total);
    for (int i = from; i < end; ++i) {
        pushers_array.push_back(pusher_record_to_json(pusher_list[i]));
    }

    json resp;
    resp["user_id"] = user_id;
    resp["pushers"] = pushers_array;
    resp["total"] = total;
    resp["from"] = from;
    resp["limit"] = limit;
    if (end < total) {
        resp["next_token"] = std::to_string(end);
    }

    // Summary
    int http_count = 0, email_count = 0, enabled_count = 0;
    for (const auto& p : pusher_list) {
        if (p.kind == "http") http_count++;
        else if (p.kind == "email") email_count++;
        if (p.enabled) enabled_count++;
    }
    resp["summary"] = {
        {"total", total},
        {"http_pushers", http_count},
        {"email_pushers", email_count},
        {"enabled", enabled_count},
        {"disabled", total - enabled_count}
    };

    return resp;
}

// ============================================================================
// 13. GET /_synapse/admin/v1/users/{userId}/rooms
// List all rooms a user is a member of, with membership details.
//
// Query params:
//   membership     (optional) - filter: "join", "invite", "leave", "ban", "knock"
//   is_direct      (optional) - bool, filter for DM rooms
//   search         (optional) - room name substring search
//   order_by       (optional) - "room_id", "name", "joined_members", "creation_ts"
//   dir            (optional) - "f" or "b"
//   from, limit    (optional) - pagination
// ============================================================================

json handle_list_user_rooms(const json& params,
                             const json& body,
                             const std::string& request_path) {
    std::string user_id;
    if (!extract_user_id_from_path(request_path,
            "/_synapse/admin/v1/users/", user_id)) {
        return error_response("M_UNKNOWN", "Invalid request path", 400);
    }
    auto pos = user_id.find("/rooms");
    if (pos != std::string::npos) user_id = user_id.substr(0, pos);

    if (!is_valid_user_id(user_id)) {
        return error_response("M_INVALID_PARAM",
            "Invalid user ID: " + user_id, 400);
    }

    // Verify user exists
    {
        std::lock_guard<std::mutex> lock(db::users_mutex);
        if (db::users.find(user_id) == db::users.end()) {
            return error_response("M_NOT_FOUND",
                "User not found: " + user_id, 404);
        }
    }

    // Parse filters
    std::string membership_filter = parse_string_param(params, "membership");
    bool is_direct_set = params.contains("is_direct");
    bool is_direct_filter;
    if (is_direct_set) {
        is_direct_filter = parse_bool_param(params, "is_direct", false);
    }
    std::string search_filter = parse_string_param(params, "search");
    std::string order_by = parse_string_param(params, "order_by", "room_id");
    std::string dir = parse_string_param(params, "dir", "f");
    int from = parse_int_param(params, "from", 0);
    int limit = std::min(parse_int_param(params, "limit", 100), 500);

    // Collect rooms
    std::lock_guard<std::mutex> lock(db::membership_mutex);
    std::vector<std::pair<db::RoomMembership, std::string>> room_list; // mem + room_name

    auto rit = db::user_rooms.find(user_id);
    if (rit != db::user_rooms.end()) {
        for (const auto& rid : rit->second) {
            std::string key = rid + ":" + user_id;
            auto mit = db::memberships.find(key);
            if (mit == db::memberships.end()) continue;

            // Filter by membership type
            if (!membership_filter.empty() &&
                mit->second.membership != membership_filter) continue;

            // Filter by is_direct
            if (is_direct_set && mit->second.is_direct != is_direct_filter) continue;

            // Get room name for search
            std::string room_name;
            {
                std::lock_guard<std::mutex> rlock(db::rooms_mutex);
                auto room_it = db::rooms.find(rid);
                if (room_it != db::rooms.end()) {
                    room_name = room_it->second.name;
                    // Apply room name search filter
                    if (!search_filter.empty() &&
                        !matches_filter(room_name, search_filter) &&
                        !matches_filter(rid, search_filter) &&
                        !matches_filter(room_it->second.topic, search_filter)) {
                        continue;
                    }
                }
            }

            room_list.push_back({mit->second, room_name});
        }
    }

    // Sort
    std::sort(room_list.begin(), room_list.end(),
        [&](const auto& a, const auto& b) {
            int cmp = 0;
            if (order_by == "room_id") {
                cmp = a.first.room_id.compare(b.first.room_id);
            } else if (order_by == "name") {
                cmp = a.second.compare(b.second);
                if (cmp == 0) cmp = a.first.room_id.compare(b.first.room_id);
            } else if (order_by == "creation_ts" || order_by == "origin_server_ts") {
                cmp = a.first.origin_server_ts.compare(b.first.origin_server_ts);
                if (cmp == 0) cmp = a.first.room_id.compare(b.first.room_id);
            } else if (order_by == "membership") {
                auto prio = [](const std::string& m) -> int {
                    if (m == "join") return 0;
                    if (m == "invite") return 1;
                    if (m == "knock") return 2;
                    if (m == "leave") return 3;
                    if (m == "ban") return 4;
                    return 5;
                };
                cmp = prio(a.first.membership) - prio(b.first.membership);
                if (cmp == 0) cmp = a.first.room_id.compare(b.first.room_id);
            } else {
                cmp = a.first.room_id.compare(b.first.room_id);
            }
            return (dir == "b") ? (cmp > 0) : (cmp < 0);
        });

    int total = static_cast<int>(room_list.size());

    json rooms_array = json::array();
    int end = std::min(from + limit, total);
    for (int i = from; i < end; ++i) {
        const auto& [mem, room_name] = room_list[i];
        json r;
        r["room_id"] = mem.room_id;
        r["room_name"] = room_name;
        r["membership"] = mem.membership;
        r["sender"] = mem.sender;
        r["origin_server_ts"] = mem.origin_server_ts.empty() ? 0 :
            static_cast<int64_t>(std::stoll(mem.origin_server_ts));
        r["is_direct"] = mem.is_direct;

        // Get room details
        {
            std::lock_guard<std::mutex> rlock(db::rooms_mutex);
            auto room_it = db::rooms.find(mem.room_id);
            if (room_it != db::rooms.end()) {
                r["room_joined_members"] = room_it->second.joined_members;
                r["room_total_members"] = room_it->second.total_members;
                r["room_public"] = room_it->second.public_room;
                r["room_encrypted"] = room_it->second.is_encrypted;
                r["room_join_rules"] = room_it->second.join_rules;
                r["room_version"] = room_it->second.room_version;
                r["canonical_alias"] = room_it->second.canonical_alias;
                r["room_creator"] = room_it->second.creator;
            }
        }

        rooms_array.push_back(r);
    }

    json resp;
    resp["user_id"] = user_id;
    resp["rooms"] = rooms_array;
    resp["total"] = total;
    resp["from"] = from;
    resp["limit"] = limit;
    if (end < total) {
        resp["next_token"] = std::to_string(end);
    }

    // Summary
    int joined = 0, invited = 0, left = 0, banned = 0, knocked = 0, direct_count = 0;
    for (const auto& [mem, _] : room_list) {
        if (mem.membership == "join") joined++;
        else if (mem.membership == "invite") invited++;
        else if (mem.membership == "leave") left++;
        else if (mem.membership == "ban") banned++;
        else if (mem.membership == "knock") knocked++;
        if (mem.is_direct) direct_count++;
    }
    resp["summary"] = {
        {"total", total},
        {"joined", joined},
        {"invited", invited},
        {"left", left},
        {"banned", banned},
        {"knocked", knocked},
        {"direct_rooms", direct_count}
    };

    return resp;
}

// ============================================================================
// 14. POST /_synapse/admin/v1/users/{userId}/force_join
// Force a user to join a room. Creates a membership event as if the user
// joined on their own.
//
// Body:
//   room_id       (required) - the room to join
//   reason        (optional) - audit reason
//   is_direct     (optional) - bool, mark as direct chat
// ============================================================================

json handle_force_join_room(const json& params,
                             const json& body,
                             const std::string& request_path) {
    std::string user_id;
    if (!extract_user_id_from_path(request_path,
            "/_synapse/admin/v1/users/", user_id)) {
        return error_response("M_UNKNOWN", "Invalid request path", 400);
    }
    auto pos = user_id.find("/force_join");
    if (pos != std::string::npos) user_id = user_id.substr(0, pos);

    if (!is_valid_user_id(user_id)) {
        return error_response("M_INVALID_PARAM",
            "Invalid user ID: " + user_id, 400);
    }

    if (!body.contains("room_id") || !body["room_id"].is_string()) {
        return error_response("M_MISSING_PARAM",
            "room_id is required", 400);
    }

    std::string room_id = body["room_id"].get<std::string>();
    std::string reason = body.value("reason", "Administrative force-join");
    bool is_direct = parse_bool_param(body, "is_direct", false);

    if (!is_valid_room_id(room_id)) {
        return error_response("M_INVALID_PARAM",
            "Invalid room ID: " + room_id, 400);
    }

    // Verify user and room exist
    {
        std::lock_guard<std::mutex> ulock(db::users_mutex);
        if (db::users.find(user_id) == db::users.end()) {
            return error_response("M_NOT_FOUND",
                "User not found: " + user_id, 404);
        }
        if (db::users[user_id].deactivated) {
            return error_response("M_FORBIDDEN",
                "Cannot force-join a deactivated user", 403);
        }
    }
    {
        std::lock_guard<std::mutex> rlock(db::rooms_mutex);
        if (db::rooms.find(room_id) == db::rooms.end()) {
            return error_response("M_NOT_FOUND",
                "Room not found: " + room_id, 404);
        }
    }

    std::string ts = now_ms();
    std::string event_id = "$force_join_" + random_hex(24);

    // Update membership
    {
        std::lock_guard<std::mutex> lock(db::membership_mutex);

        std::string key = room_id + ":" + user_id;
        auto existing = db::memberships.find(key);

        if (existing != db::memberships.end() &&
            existing->second.membership == "join") {
            return error_response("M_INVALID_STATE",
                "User " + user_id + " is already joined to room " + room_id, 409);
        }

        db::RoomMembership mem;
        mem.room_id = room_id;
        mem.user_id = user_id;
        mem.membership = "join";
        mem.sender = body.value("admin_id", "@admin:localhost:8008");
        mem.event_id = event_id;
        mem.origin_server_ts = ts;
        mem.is_direct = is_direct;
        db::memberships[key] = mem;

        // Update user_rooms
        auto& ur = db::user_rooms[user_id];
        if (std::find(ur.begin(), ur.end(), room_id) == ur.end()) {
            ur.push_back(room_id);
        }

        // Update room_members
        auto& rm = db::room_members[room_id];
        if (std::find(rm.begin(), rm.end(), user_id) == rm.end()) {
            rm.push_back(user_id);
        }
    }

    // Update room member counts
    {
        std::lock_guard<std::mutex> rlock(db::rooms_mutex);
        auto room_it = db::rooms.find(room_id);
        if (room_it != db::rooms.end()) {
            room_it->second.joined_members++;
            room_it->second.total_members =
                std::max(room_it->second.total_members,
                         room_it->second.joined_members +
                         room_it->second.invited_members);
        }
    }

    json resp;
    resp["success"] = true;
    resp["user_id"] = user_id;
    resp["room_id"] = room_id;
    resp["membership"] = "join";
    resp["event_id"] = event_id;
    resp["reason"] = reason;
    resp["is_direct"] = is_direct;
    resp["timestamp"] = static_cast<int64_t>(std::stoll(ts));
    resp["message"] = "User force-joined to room successfully";
    return resp;
}

// ============================================================================
// 15. POST /_synapse/admin/v1/users/{userId}/force_leave
// Force a user to leave a room. If the user is banned, they remain banned
// but their join membership is revoked.
//
// Body:
//   room_id       (required) - the room to leave
//   reason        (optional) - audit reason
//   ban           (optional) - bool, also ban the user from the room
// ============================================================================

json handle_force_leave_room(const json& params,
                              const json& body,
                              const std::string& request_path) {
    std::string user_id;
    if (!extract_user_id_from_path(request_path,
            "/_synapse/admin/v1/users/", user_id)) {
        return error_response("M_UNKNOWN", "Invalid request path", 400);
    }
    auto pos = user_id.find("/force_leave");
    if (pos != std::string::npos) user_id = user_id.substr(0, pos);

    if (!is_valid_user_id(user_id)) {
        return error_response("M_INVALID_PARAM",
            "Invalid user ID: " + user_id, 400);
    }

    if (!body.contains("room_id") || !body["room_id"].is_string()) {
        return error_response("M_MISSING_PARAM",
            "room_id is required", 400);
    }

    std::string room_id = body["room_id"].get<std::string>();
    std::string reason = body.value("reason", "Administrative force-leave");
    bool ban = parse_bool_param(body, "ban", false);

    if (!is_valid_room_id(room_id)) {
        return error_response("M_INVALID_PARAM",
            "Invalid room ID: " + room_id, 400);
    }

    // Verify user and room exist
    {
        std::lock_guard<std::mutex> ulock(db::users_mutex);
        if (db::users.find(user_id) == db::users.end()) {
            return error_response("M_NOT_FOUND",
                "User not found: " + user_id, 404);
        }
    }
    {
        std::lock_guard<std::mutex> rlock(db::rooms_mutex);
        if (db::rooms.find(room_id) == db::rooms.end()) {
            return error_response("M_NOT_FOUND",
                "Room not found: " + room_id, 404);
        }
    }

    std::string ts = now_ms();
    std::string event_id = "$force_leave_" + random_hex(24);
    std::string new_membership = ban ? "ban" : "leave";
    bool was_joined = false;

    // Update membership
    {
        std::lock_guard<std::mutex> lock(db::membership_mutex);

        std::string key = room_id + ":" + user_id;
        auto existing = db::memberships.find(key);

        if (existing != db::memberships.end() &&
            existing->second.membership == "leave") {
            return error_response("M_INVALID_STATE",
                "User " + user_id + " has already left room " + room_id, 409);
        }

        was_joined = (existing != db::memberships.end() &&
                      existing->second.membership == "join");

        db::RoomMembership mem;
        mem.room_id = room_id;
        mem.user_id = user_id;
        mem.membership = new_membership;
        mem.sender = body.value("admin_id", "@admin:localhost:8008");
        mem.event_id = event_id;
        mem.origin_server_ts = ts;
        mem.is_direct = existing != db::memberships.end() ? existing->second.is_direct : false;
        db::memberships[key] = mem;

        // Remove from user_rooms if not banning (banned users stay in the list for audit)
        if (!ban) {
            auto& ur = db::user_rooms[user_id];
            ur.erase(std::remove(ur.begin(), ur.end(), room_id), ur.end());
        }

        // Remove from room_members
        auto& rm = db::room_members[room_id];
        rm.erase(std::remove(rm.begin(), rm.end(), user_id), rm.end());
    }

    // Update room member counts
    {
        std::lock_guard<std::mutex> rlock(db::rooms_mutex);
        auto room_it = db::rooms.find(room_id);
        if (room_it != db::rooms.end()) {
            if (was_joined) {
                room_it->second.joined_members =
                    std::max(0, room_it->second.joined_members - 1);
            }
            if (ban) {
                room_it->second.banned_members++;
            }
            room_it->second.total_members =
                room_it->second.joined_members +
                room_it->second.invited_members;
        }
    }

    json resp;
    resp["success"] = true;
    resp["user_id"] = user_id;
    resp["room_id"] = room_id;
    resp["membership"] = new_membership;
    resp["event_id"] = event_id;
    resp["reason"] = reason;
    resp["ban"] = ban;
    resp["was_joined"] = was_joined;
    resp["timestamp"] = static_cast<int64_t>(std::stoll(ts));
    resp["message"] = ban ?
        "User force-left and banned from room" :
        "User force-left from room successfully";
    return resp;
}

// ============================================================================
// 16. GET /_synapse/admin/v1/users/{userId}/export
// Export all data associated with a user for GDPR/data-portability.
// Produces a comprehensive JSON dump of the user's profile, devices,
// rooms, pushers, connections, and metadata.
//
// Query params:
//   include_rooms  (optional) - bool, default true
//   include_devices (optional) - bool, default true
//   include_pushers (optional) - bool, default true
//   format         (optional) - "json" (default) or "tar" (returns JSON with metadata)
// ============================================================================

json handle_export_user_data(const json& params,
                              const json& body,
                              const std::string& request_path) {
    std::string user_id;
    if (!extract_user_id_from_path(request_path,
            "/_synapse/admin/v1/users/", user_id)) {
        return error_response("M_UNKNOWN", "Invalid request path", 400);
    }
    auto pos = user_id.find("/export");
    if (pos != std::string::npos) user_id = user_id.substr(0, pos);

    if (!is_valid_user_id(user_id)) {
        return error_response("M_INVALID_PARAM",
            "Invalid user ID: " + user_id, 400);
    }

    bool include_rooms = parse_bool_param(params, "include_rooms", true);
    bool include_devices = parse_bool_param(params, "include_devices", true);
    bool include_pushers = parse_bool_param(params, "include_pushers", true);
    std::string format = parse_string_param(params, "format", "json");

    json export_data;
    export_data["export_format"] = format;
    export_data["export_generated_ts"] = static_cast<int64_t>(std::stoll(now_ms()));
    export_data["user_id"] = user_id;

    // --- Profile data ---
    {
        std::lock_guard<std::mutex> lock(db::users_mutex);
        auto it = db::users.find(user_id);
        if (it == db::users.end()) {
            return error_response("M_NOT_FOUND",
                "User not found: " + user_id, 404);
        }

        json profile;
        profile["user_id"] = it->second.id;
        profile["displayname"] = it->second.displayname;
        profile["avatar_url"] = it->second.avatar_url;
        profile["email"] = it->second.email;
        profile["creation_ts"] = it->second.creation_ts.empty() ? 0 :
            static_cast<int64_t>(std::stoll(it->second.creation_ts));
        profile["admin"] = it->second.admin;
        profile["deactivated"] = it->second.deactivated;
        profile["locked"] = it->second.locked;
        profile["shadow_banned"] = it->second.shadow_banned;
        profile["is_guest"] = it->second.is_guest;
        profile["user_type"] = it->second.user_type;
        profile["consent_version"] = it->second.consent_version;
        profile["consent_given"] = it->second.consent_given;
        if (!it->second.consent_ts.empty()) {
            profile["consent_ts"] = static_cast<int64_t>(std::stoll(it->second.consent_ts));
        }

        // Threepids
        if (!it->second.threepids.empty()) {
            try { profile["threepids"] = json::parse(it->second.threepids); }
            catch (...) { profile["threepids"] = json::array(); }
        } else {
            profile["threepids"] = json::array();
        }

        // External IDs
        if (!it->second.external_ids.empty()) {
            try { profile["external_ids"] = json::parse(it->second.external_ids); }
            catch (...) { profile["external_ids"] = json::array(); }
        } else {
            profile["external_ids"] = json::array();
        }

        export_data["profile"] = profile;

        // Update export metadata
        it->second.last_export_ts = now_ms();
        it->second.export_count++;
    }

    // --- Devices ---
    if (include_devices) {
        std::lock_guard<std::mutex> lock(db::devices_mutex);
        json devs = json::array();
        auto dit = db::user_devices.find(user_id);
        if (dit != db::user_devices.end()) {
            for (const auto& did : dit->second) {
                auto dev_it = db::devices.find(did);
                if (dev_it != db::devices.end()) {
                    json d;
                    d["device_id"] = dev_it->second.device_id;
                    d["display_name"] = dev_it->second.display_name;
                    d["device_type"] = dev_it->second.device_type;
                    d["last_seen_ts"] = dev_it->second.last_seen_ts.empty() ? 0 :
                        static_cast<int64_t>(std::stoll(dev_it->second.last_seen_ts));
                    d["last_seen_ip"] = dev_it->second.last_seen_ip;
                    d["last_seen_user_agent"] = dev_it->second.last_seen_user_agent;
                    d["creation_ts"] = dev_it->second.creation_ts.empty() ? 0 :
                        static_cast<int64_t>(std::stoll(dev_it->second.creation_ts));
                    d["is_active"] = dev_it->second.is_active;
                    devs.push_back(d);
                }
            }
        }
        export_data["devices"] = {
            {"count", devs.size()},
            {"devices", devs}
        };
    }

    // --- Rooms ---
    if (include_rooms) {
        std::lock_guard<std::mutex> lock(db::membership_mutex);
        json rooms_arr = json::array();
        auto rit = db::user_rooms.find(user_id);
        if (rit != db::user_rooms.end()) {
            for (const auto& rid : rit->second) {
                std::string key = rid + ":" + user_id;
                auto mit = db::memberships.find(key);
                if (mit == db::memberships.end()) continue;

                json r;
                r["room_id"] = rid;
                r["membership"] = mit->second.membership;
                r["sender"] = mit->second.sender;
                r["event_id"] = mit->second.event_id;
                r["origin_server_ts"] = mit->second.origin_server_ts.empty() ? 0 :
                    static_cast<int64_t>(std::stoll(mit->second.origin_server_ts));
                r["is_direct"] = mit->second.is_direct;

                // Room metadata
                {
                    std::lock_guard<std::mutex> rlock(db::rooms_mutex);
                    auto room_it = db::rooms.find(rid);
                    if (room_it != db::rooms.end()) {
                        r["room_name"] = room_it->second.name;
                        r["room_canonical_alias"] = room_it->second.canonical_alias;
                        r["room_topic"] = room_it->second.topic;
                        r["room_joined_members"] = room_it->second.joined_members;
                        r["room_public"] = room_it->second.public_room;
                        r["room_encrypted"] = room_it->second.is_encrypted;
                    }
                }

                rooms_arr.push_back(r);
            }
        }
        export_data["rooms"] = {
            {"count", rooms_arr.size()},
            {"rooms", rooms_arr}
        };
    }

    // --- Pushers ---
    if (include_pushers) {
        std::lock_guard<std::mutex> lock(db::pushers_mutex);
        json pushers_arr = json::array();
        auto pit = db::user_pushers.find(user_id);
        if (pit != db::user_pushers.end()) {
            for (const auto& pid : pit->second) {
                auto ppit = db::pushers.find(pid);
                if (ppit != db::pushers.end()) {
                    pushers_arr.push_back(pusher_record_to_json(ppit->second));
                }
            }
        }
        export_data["pushers"] = {
            {"count", pushers_arr.size()},
            {"pushers", pushers_arr}
        };
    }

    // --- Connections ---
    {
        std::lock_guard<std::mutex> lock(db::connections_mutex);
        json conns_arr = json::array();
        auto cit = db::user_connections.find(user_id);
        if (cit != db::user_connections.end()) {
            for (const auto& cid : cit->second) {
                auto ccit = db::connections.find(cid);
                if (ccit != db::connections.end()) {
                    json c;
                    c["connection_id"] = ccit->second.connection_id;
                    c["ip_address"] = ccit->second.ip_address;
                    c["user_agent"] = ccit->second.user_agent;
                    c["last_seen_ts"] = ccit->second.last_seen_ts.empty() ? 0 :
                        static_cast<int64_t>(std::stoll(ccit->second.last_seen_ts));
                    c["connected_since"] = ccit->second.connected_since.empty() ? 0 :
                        static_cast<int64_t>(std::stoll(ccit->second.connected_since));
                    c["device_id"] = ccit->second.device_id;
                    c["request_count"] = ccit->second.request_count;
                    conns_arr.push_back(c);
                }
            }
        }
        export_data["connections"] = {
            {"count", conns_arr.size()},
            {"connections", conns_arr}
        };
    }

    // --- Rate-limit overrides ---
    {
        std::lock_guard<std::mutex> lock(db::users_mutex);
        auto it = db::users.find(user_id);
        if (it != db::users.end() && it->second.rate_limit_overridden) {
            json rlo;
            rlo["messages_per_second"] = it->second.rate_limit_messages_per_second;
            rlo["burst_count"] = it->second.rate_limit_burst_count;
            rlo["overridden_ts"] = it->second.rate_limit_overridden_ts.empty() ? 0 :
                static_cast<int64_t>(std::stoll(it->second.rate_limit_overridden_ts));
            rlo["overridden_by"] = it->second.rate_limit_overridden_by;
            export_data["rate_limit_override"] = rlo;
        }
    }

    export_data["export_checksum"] = sha256(export_data.dump());
    export_data["privacy_notice"] =
        "This export contains all personal data associated with the Matrix user "
        "account. Handle in compliance with applicable data protection regulations.";
    export_data["server_timestamp"] = static_cast<int64_t>(std::stoll(now_ms()));

    return export_data;
}

// ============================================================================
// 17. POST /_synapse/admin/v1/users/{userId}/update
// Update user attributes (displayname, avatar_url, admin status,
// locked status, user_type, etc.).
//
// Body:
//   displayname  (optional) - string or null to clear
//   avatar_url   (optional) - string or null to clear
//   admin        (optional) - bool
//   locked       (optional) - bool
//   user_type    (optional) - string or null: "support", "bot", ""
//   email        (optional) - string or null
//   approved     (optional) - bool
//   consent_given (optional) - bool
// ============================================================================

json handle_update_user(const json& params,
                         const json& body,
                         const std::string& request_path) {
    std::string user_id;
    if (!extract_user_id_from_path(request_path,
            "/_synapse/admin/v1/users/", user_id)) {
        return error_response("M_UNKNOWN", "Invalid request path", 400);
    }
    auto pos = user_id.find("/update");
    if (pos != std::string::npos) user_id = user_id.substr(0, pos);

    if (!is_valid_user_id(user_id)) {
        return error_response("M_INVALID_PARAM",
            "Invalid user ID: " + user_id, 400);
    }

    std::lock_guard<std::mutex> lock(db::users_mutex);

    auto it = db::users.find(user_id);
    if (it == db::users.end()) {
        return error_response("M_NOT_FOUND",
            "User not found: " + user_id, 404);
    }

    auto& rec = it->second;

    // Update fields
    if (body.contains("displayname")) {
        if (body["displayname"].is_null()) {
            rec.displayname = "";
        } else if (body["displayname"].is_string()) {
            rec.displayname = body["displayname"].get<std::string>();
        }
    }

    if (body.contains("avatar_url")) {
        if (body["avatar_url"].is_null()) {
            rec.avatar_url = "";
        } else if (body["avatar_url"].is_string()) {
            rec.avatar_url = body["avatar_url"].get<std::string>();
        }
    }

    if (body.contains("admin")) {
        if (body["admin"].is_boolean()) {
            rec.admin = body["admin"].get<bool>();
        } else if (body["admin"].is_number()) {
            rec.admin = (body["admin"].get<int>() != 0);
        }
    }

    if (body.contains("locked")) {
        if (body["locked"].is_boolean()) {
            rec.locked = body["locked"].get<bool>();
        }
    }

    if (body.contains("user_type")) {
        if (body["user_type"].is_null()) {
            rec.user_type = "";
        } else if (body["user_type"].is_string()) {
            std::string ut = body["user_type"].get<std::string>();
            if (ut == "support" || ut == "bot" || ut == "") {
                rec.user_type = ut;
            }
        }
    }

    if (body.contains("email")) {
        if (body["email"].is_null()) {
            rec.email = "";
        } else if (body["email"].is_string()) {
            rec.email = body["email"].get<std::string>();
        }
    }

    if (body.contains("approved")) {
        if (body["approved"].is_boolean()) {
            rec.approved = body["approved"].get<bool>();
        }
    }

    if (body.contains("consent_given")) {
        if (body["consent_given"].is_boolean()) {
            rec.consent_given = body["consent_given"].get<bool>();
            if (rec.consent_given) {
                rec.consent_ts = now_ms();
            }
        }
    }

    if (body.contains("threepids")) {
        if (body["threepids"].is_null()) {
            rec.threepids = "";
        } else if (body["threepids"].is_array()) {
            rec.threepids = body["threepids"].dump();
        }
    }

    // Return updated user
    json resp = user_record_to_json(rec, false);
    resp["updated"] = true;
    resp["timestamp"] = static_cast<int64_t>(std::stoll(now_ms()));
    return resp;
}

// ============================================================================
// 18. DELETE /_synapse/admin/v1/users/{userId}
// Permanently delete a user (requires erased user or explicit force flag).
//
// Body:
//   force       (optional) - bool, bypass erasure requirement
//   reason      (optional) - audit reason
//   delete_rooms (optional) - bool, also delete rooms the user created
// ============================================================================

json handle_delete_user(const json& params,
                         const json& body,
                         const std::string& request_path) {
    std::string user_id;
    if (!extract_user_id_from_path(request_path,
            "/_synapse/admin/v1/users/", user_id)) {
        return error_response("M_UNKNOWN", "Invalid request path", 400);
    }
    // Strip any suffix
    auto slash = user_id.find('/');
    if (slash != std::string::npos) user_id = user_id.substr(0, slash);

    if (!is_valid_user_id(user_id)) {
        return error_response("M_INVALID_PARAM",
            "Invalid user ID: " + user_id, 400);
    }

    bool force = parse_bool_param(body, "force", false);
    std::string reason = body.value("reason", "Administrative user deletion");
    bool delete_rooms = parse_bool_param(body, "delete_rooms", false);

    // Check user exists and is erasable
    {
        std::lock_guard<std::mutex> lock(db::users_mutex);
        auto it = db::users.find(user_id);
        if (it == db::users.end()) {
            return error_response("M_NOT_FOUND",
                "User not found: " + user_id, 404);
        }
        if (!it->second.erased && !force) {
            return error_response("M_FORBIDDEN",
                "User must be deactivated with erase=true first, or use force=true",
                403);
        }
    }

    // Delete user's rooms if requested
    int rooms_deleted = 0;
    if (delete_rooms) {
        std::lock_guard<std::mutex> rlock(db::rooms_mutex);
        std::lock_guard<std::mutex> mlock(db::membership_mutex);

        auto rit = db::user_rooms.find(user_id);
        if (rit != db::user_rooms.end()) {
            std::vector<std::string> rooms_to_delete;
            for (const auto& rid : rit->second) {
                auto room_it = db::rooms.find(rid);
                if (room_it != db::rooms.end() && room_it->second.creator == user_id) {
                    rooms_to_delete.push_back(rid);
                }
            }
            for (const auto& rid : rooms_to_delete) {
                db::rooms.erase(rid);
                db::room_members.erase(rid);
                // Remove room from all users
                for (auto& [uid, ur] : db::user_rooms) {
                    ur.erase(std::remove(ur.begin(), ur.end(), rid), ur.end());
                }
                // Remove memberships referencing this room
                auto it = db::memberships.begin();
                while (it != db::memberships.end()) {
                    if (it->first.find(rid + ":") == 0) {
                        it = db::memberships.erase(it);
                    } else {
                        ++it;
                    }
                }
                rooms_deleted++;
            }
        }
    }

    // Delete all user data
    {
        std::lock_guard<std::mutex> ulock(db::users_mutex);
        db::users.erase(user_id);
    }

    // Clean up devices
    {
        std::lock_guard<std::mutex> dlock(db::devices_mutex);
        auto dit = db::user_devices.find(user_id);
        if (dit != db::user_devices.end()) {
            for (const auto& did : dit->second) {
                db::devices.erase(did);
            }
            db::user_devices.erase(user_id);
        }
    }

    // Clean up pushers
    {
        std::lock_guard<std::mutex> plock(db::pushers_mutex);
        auto pit = db::user_pushers.find(user_id);
        if (pit != db::user_pushers.end()) {
            for (const auto& pid : pit->second) {
                db::pushers.erase(pid);
            }
            db::user_pushers.erase(user_id);
        }
    }

    // Clean up connections
    {
        std::lock_guard<std::mutex> clock(db::connections_mutex);
        auto cit = db::user_connections.find(user_id);
        if (cit != db::user_connections.end()) {
            for (const auto& cid : cit->second) {
                db::connections.erase(cid);
            }
            db::user_connections.erase(user_id);
        }
    }

    // Clean up memberships
    {
        std::lock_guard<std::mutex> mlock(db::membership_mutex);
        // Remove user from room_members
        for (auto& [rid, members] : db::room_members) {
            members.erase(std::remove(members.begin(), members.end(), user_id),
                          members.end());
            // Update room joined count
            {
                std::lock_guard<std::mutex> rlock(db::rooms_mutex);
                auto room_it = db::rooms.find(rid);
                if (room_it != db::rooms.end()) {
                    room_it->second.joined_members = static_cast<int>(members.size());
                    room_it->second.total_members = room_it->second.joined_members +
                        room_it->second.invited_members;
                }
            }
            // Remove membership entry
            db::memberships.erase(rid + ":" + user_id);
        }
        db::user_rooms.erase(user_id);
    }

    // Clean up rate-limit overrides
    {
        std::lock_guard<std::mutex> ulock(db::users_mutex);
        db::rate_limit_overrides.erase(user_id);
    }

    // Clean up registration tokens for this user
    {
        std::lock_guard<std::mutex> tlock(db::tokens_mutex);
        auto it = db::reg_tokens.begin();
        while (it != db::reg_tokens.end()) {
            if (it->second.for_user_id == user_id) {
                it = db::reg_tokens.erase(it);
            } else {
                ++it;
            }
        }
    }

    json resp;
    resp["deleted"] = true;
    resp["user_id"] = user_id;
    resp["reason"] = reason;
    resp["force"] = force;
    resp["rooms_deleted"] = rooms_deleted;
    resp["timestamp"] = static_cast<int64_t>(std::stoll(now_ms()));
    resp["message"] = "User permanently deleted";
    return resp;
}

// ============================================================================
// 19. POST /_synapse/admin/v1/users/{userId}/clear_rate_limit
// Clear a previously-set rate-limit override, restoring default limits.
//
// Body:
//   reason (optional) - audit reason
// ============================================================================

json handle_clear_rate_limit(const json& params,
                              const json& body,
                              const std::string& request_path) {
    std::string user_id;
    if (!extract_user_id_from_path(request_path,
            "/_synapse/admin/v1/users/", user_id)) {
        return error_response("M_UNKNOWN", "Invalid request path", 400);
    }
    auto pos = user_id.find("/clear_rate_limit");
    if (pos != std::string::npos) user_id = user_id.substr(0, pos);

    if (!is_valid_user_id(user_id)) {
        return error_response("M_INVALID_PARAM",
            "Invalid user ID: " + user_id, 400);
    }

    std::string reason = body.value("reason", "Administrative rate-limit clear");

    bool had_override = false;

    {
        std::lock_guard<std::mutex> lock(db::users_mutex);
        auto it = db::users.find(user_id);
        if (it == db::users.end()) {
            return error_response("M_NOT_FOUND",
                "User not found: " + user_id, 404);
        }
        had_override = it->second.rate_limit_overridden;
        it->second.rate_limit_overridden = false;
        it->second.rate_limit_messages_per_second = 0;
        it->second.rate_limit_burst_count = 0;
        it->second.rate_limit_overridden_ts = "";
        it->second.rate_limit_overridden_by = "";
        db::rate_limit_overrides.erase(user_id);
    }

    json resp;
    resp["user_id"] = user_id;
    resp["rate_limit_cleared"] = true;
    resp["had_override"] = had_override;
    resp["reason"] = reason;
    resp["timestamp"] = static_cast<int64_t>(std::stoll(now_ms()));
    resp["message"] = had_override ?
        "Rate-limit override has been cleared. User now subject to default limits." :
        "User did not have an active rate-limit override.";
    return resp;
}

// ============================================================================
// 20. POST /_synapse/admin/v1/users/{userId}/lock
// Lock a user account (prevents login).
//
// Body:
//   reason (optional) - audit reason
// ============================================================================

json handle_lock_user(const json& params,
                       const json& body,
                       const std::string& request_path) {
    std::string user_id;
    if (!extract_user_id_from_path(request_path,
            "/_synapse/admin/v1/users/", user_id)) {
        return error_response("M_UNKNOWN", "Invalid request path", 400);
    }
    auto pos = user_id.find("/lock");
    if (pos != std::string::npos) user_id = user_id.substr(0, pos);

    if (!is_valid_user_id(user_id)) {
        return error_response("M_INVALID_PARAM",
            "Invalid user ID: " + user_id, 400);
    }

    std::string reason = body.value("reason", "Administrative account lock");

    {
        std::lock_guard<std::mutex> lock(db::users_mutex);
        auto it = db::users.find(user_id);
        if (it == db::users.end()) {
            return error_response("M_NOT_FOUND",
                "User not found: " + user_id, 404);
        }
        if (it->second.locked) {
            return error_response("M_INVALID_STATE",
                "User " + user_id + " is already locked", 409);
        }
        it->second.locked = true;
    }

    // Deactivate all sessions
    {
        std::lock_guard<std::mutex> dlock(db::devices_mutex);
        auto dit = db::user_devices.find(user_id);
        if (dit != db::user_devices.end()) {
            for (const auto& did : dit->second) {
                auto dev_it = db::devices.find(did);
                if (dev_it != db::devices.end()) {
                    dev_it->second.is_active = false;
                }
            }
        }
    }

    json resp;
    resp["locked"] = true;
    resp["user_id"] = user_id;
    resp["reason"] = reason;
    resp["timestamp"] = static_cast<int64_t>(std::stoll(now_ms()));
    resp["message"] = "User account locked. All existing sessions terminated.";
    return resp;
}

// ============================================================================
// 21. POST /_synapse/admin/v1/users/{userId}/unlock
// Unlock a previously locked user account.
//
// Body:
//   reason (optional) - audit reason
// ============================================================================

json handle_unlock_user(const json& params,
                         const json& body,
                         const std::string& request_path) {
    std::string user_id;
    if (!extract_user_id_from_path(request_path,
            "/_synapse/admin/v1/users/", user_id)) {
        return error_response("M_UNKNOWN", "Invalid request path", 400);
    }
    auto pos = user_id.find("/unlock");
    if (pos != std::string::npos) user_id = user_id.substr(0, pos);

    if (!is_valid_user_id(user_id)) {
        return error_response("M_INVALID_PARAM",
            "Invalid user ID: " + user_id, 400);
    }

    std::string reason = body.value("reason", "Administrative account unlock");

    {
        std::lock_guard<std::mutex> lock(db::users_mutex);
        auto it = db::users.find(user_id);
        if (it == db::users.end()) {
            return error_response("M_NOT_FOUND",
                "User not found: " + user_id, 404);
        }
        if (!it->second.locked) {
            return error_response("M_INVALID_STATE",
                "User " + user_id + " is not locked", 409);
        }
        it->second.locked = false;
    }

    json resp;
    resp["unlocked"] = true;
    resp["user_id"] = user_id;
    resp["reason"] = reason;
    resp["timestamp"] = static_cast<int64_t>(std::stoll(now_ms()));
    resp["message"] = "User account unlocked. User may now log in again.";
    return resp;
}

// ============================================================================
// 22. GET /_synapse/admin/v1/users/{userId}/connections
// List active connections (IP sessions) for a user.
//
// Query params:
//   from, limit (optional) - pagination
//   active_only (optional) - bool, default false (show all)
// ============================================================================

json handle_list_user_connections(const json& params,
                                   const json& body,
                                   const std::string& request_path) {
    std::string user_id;
    if (!extract_user_id_from_path(request_path,
            "/_synapse/admin/v1/users/", user_id)) {
        return error_response("M_UNKNOWN", "Invalid request path", 400);
    }
    auto pos = user_id.find("/connections");
    if (pos != std::string::npos) user_id = user_id.substr(0, pos);

    if (!is_valid_user_id(user_id)) {
        return error_response("M_INVALID_PARAM",
            "Invalid user ID: " + user_id, 400);
    }

    bool active_only = parse_bool_param(params, "active_only", false);
    int from = parse_int_param(params, "from", 0);
    int limit = std::min(parse_int_param(params, "limit", 100), 500);

    std::lock_guard<std::mutex> lock(db::connections_mutex);

    std::vector<db::UserConnection> conn_list;
    auto cit = db::user_connections.find(user_id);
    if (cit != db::user_connections.end()) {
        for (const auto& cid : cit->second) {
            auto ccit = db::connections.find(cid);
            if (ccit != db::connections.end()) {
                if (active_only && !ccit->second.is_active) continue;
                conn_list.push_back(ccit->second);
            }
        }
    }

    // Sort by last_seen descending
    std::sort(conn_list.begin(), conn_list.end(),
        [](const db::UserConnection& a, const db::UserConnection& b) {
            return a.last_seen_ts > b.last_seen_ts;
        });

    int total = static_cast<int>(conn_list.size());

    json conns_array = json::array();
    int end = std::min(from + limit, total);
    for (int i = from; i < end; ++i) {
        const auto& c = conn_list[i];
        json jc;
        jc["connection_id"] = c.connection_id;
        jc["ip_address"] = c.ip_address;
        jc["user_agent"] = c.user_agent;
        jc["last_seen_ts"] = c.last_seen_ts.empty() ? 0 :
            static_cast<int64_t>(std::stoll(c.last_seen_ts));
        jc["connected_since"] = c.connected_since.empty() ? 0 :
            static_cast<int64_t>(std::stoll(c.connected_since));
        jc["device_id"] = c.device_id;
        jc["is_active"] = c.is_active;
        jc["request_count"] = c.request_count;
        conns_array.push_back(jc);
    }

    json resp;
    resp["user_id"] = user_id;
    resp["connections"] = conns_array;
    resp["total"] = total;
    resp["from"] = from;
    resp["limit"] = limit;
    if (end < total) {
        resp["next_token"] = std::to_string(end);
    }

    // Summary
    int active = 0;
    for (const auto& c : conn_list) {
        if (c.is_active) active++;
    }
    resp["summary"] = {
        {"total", total},
        {"active", active},
        {"inactive", total - active}
    };

    return resp;
}

// ============================================================================
// Route dispatcher and entry point
// ============================================================================

using AdminHandler = std::function<json(
    const json& params,
    const json& body,
    const std::string& request_path)>;

struct RouteEntry {
    std::string method;
    std::string path_pattern;
    bool is_prefix;
    AdminHandler handler;
};

// Build the complete dispatch table
std::vector<RouteEntry> build_user_admin_routes() {
    std::vector<RouteEntry> routes;

    // User listing
    routes.push_back({"GET", "/_synapse/admin/v1/users", false,
        handle_list_users});

    // User CRUD
    routes.push_back({"POST", "/_synapse/admin/v1/users", false,
        handle_create_user});
    routes.push_back({"DELETE", "/_synapse/admin/v1/users/", true,
        handle_delete_user});

    // User detail routes (prefix-based)
    // These all start with /_synapse/admin/v1/users/{userId}/
    auto user_detail_dispatcher = [](const json& p, const json& b,
                                      const std::string& rp) -> json {
        // Determine which sub-endpoint is being called
        if (rp.find("/details") != std::string::npos) {
            return handle_get_user_details(p, b, rp);
        }
        if (rp.find("/deactivate") != std::string::npos) {
            return handle_deactivate_user(p, b, rp);
        }
        if (rp.find("/reactivate") != std::string::npos) {
            return handle_reactivate_user(p, b, rp);
        }
        if (rp.find("/shadow_ban") != std::string::npos) {
            return handle_shadow_ban_user(p, b, rp);
        }
        if (rp.find("/override_ratelimit") != std::string::npos) {
            return handle_override_ratelimit(p, b, rp);
        }
        if (rp.find("/clear_rate_limit") != std::string::npos) {
            return handle_clear_rate_limit(p, b, rp);
        }
        if (rp.find("/reset_password") != std::string::npos) {
            return handle_reset_password(p, b, rp);
        }
        if (rp.find("/registration_token") != std::string::npos) {
            return handle_generate_registration_token(p, b, rp);
        }
        if (rp.find("/devices/") != std::string::npos) {
            return handle_delete_user_device(p, b, rp);
        }
        if (rp.find("/devices") != std::string::npos) {
            return handle_list_user_devices(p, b, rp);
        }
        if (rp.find("/pushers") != std::string::npos) {
            return handle_list_user_pushers(p, b, rp);
        }
        if (rp.find("/rooms") != std::string::npos) {
            return handle_list_user_rooms(p, b, rp);
        }
        if (rp.find("/force_join") != std::string::npos) {
            return handle_force_join_room(p, b, rp);
        }
        if (rp.find("/force_leave") != std::string::npos) {
            return handle_force_leave_room(p, b, rp);
        }
        if (rp.find("/export") != std::string::npos) {
            return handle_export_user_data(p, b, rp);
        }
        if (rp.find("/update") != std::string::npos) {
            return handle_update_user(p, b, rp);
        }
        if (rp.find("/connections") != std::string::npos) {
            return handle_list_user_connections(p, b, rp);
        }
        if (rp.find("/lock") != std::string::npos) {
            return handle_lock_user(p, b, rp);
        }
        if (rp.find("/unlock") != std::string::npos) {
            return handle_unlock_user(p, b, rp);
        }
        // Default: get user details
        return handle_get_user_details(p, b, rp);
    };

    routes.push_back({"GET", "/_synapse/admin/v1/users/", true,
        user_detail_dispatcher});
    routes.push_back({"POST", "/_synapse/admin/v1/users/", true,
        user_detail_dispatcher});
    routes.push_back({"PUT", "/_synapse/admin/v1/users/", true,
        user_detail_dispatcher});
    routes.push_back({"DELETE", "/_synapse/admin/v1/users/", true,
        [](const json& p, const json& b, const std::string& rp) -> json {
            if (rp.find("/devices/") != std::string::npos) {
                return handle_delete_user_device(p, b, rp);
            }
            return handle_delete_user(p, b, rp);
        }});

    return routes;
}

// ============================================================================
// Public API: entry point for admin request dispatching
// ============================================================================

json dispatch_user_admin_request(const std::string& method,
                                  const std::string& path,
                                  const json& params,
                                  const json& body) {
    // Static route table, built once
    static std::vector<RouteEntry> routes = build_user_admin_routes();
    static std::once_flag init_flag;
    std::call_once(init_flag, []() {
        // Seed random generator for token/ID generation
        srand(static_cast<unsigned int>(std::time(nullptr)));
    });

    // Match route
    for (const auto& route : routes) {
        if (route.method != method) continue;

        if (route.is_prefix) {
            if (path.compare(0, route.path_pattern.size(),
                             route.path_pattern) == 0) {
                return route.handler(params, body, path);
            }
        } else {
            if (path == route.path_pattern) {
                return route.handler(params, body, path);
            }
        }
    }

    return error_response("M_UNRECOGNIZED",
        "Unrecognized admin user endpoint: " + method + " " + path, 404);
}

// ============================================================================
// Convenience wrappers for programmatic use
// ============================================================================

json admin_list_users(const json& filters = json::object()) {
    return handle_list_users(filters, json::object(), "/_synapse/admin/v1/users");
}

json admin_get_user_details(const std::string& user_id) {
    return handle_get_user_details(json::object(), json::object(),
        "/_synapse/admin/v1/users/" + user_id + "/details");
}

json admin_create_user(const std::string& username,
                        const std::string& password,
                        bool is_admin,
                        const std::string& displayname,
                        const json& threepids) {
    json body;
    body["username"] = username;
    body["password"] = password;
    body["admin"] = is_admin;
    body["displayname"] = displayname;
    body["threepids"] = threepids;
    return handle_create_user(json::object(), body,
        "/_synapse/admin/v1/users");
}

json admin_deactivate_user(const std::string& user_id, bool erase) {
    json body;
    body["erase"] = erase;
    return handle_deactivate_user(json::object(), body,
        "/_synapse/admin/v1/users/" + user_id + "/deactivate");
}

json admin_reactivate_user(const std::string& user_id) {
    return handle_reactivate_user(json::object(), json::object(),
        "/_synapse/admin/v1/users/" + user_id + "/reactivate");
}

json admin_shadow_ban_user(const std::string& user_id, bool shadow_ban) {
    json body;
    body["shadow_ban"] = shadow_ban;
    return handle_shadow_ban_user(json::object(), body,
        "/_synapse/admin/v1/users/" + user_id + "/shadow_ban");
}

json admin_override_ratelimit(const std::string& user_id,
                               int64_t messages_per_second,
                               int64_t burst_count) {
    json body;
    body["messages_per_second"] = messages_per_second;
    body["burst_count"] = burst_count;
    return handle_override_ratelimit(json::object(), body,
        "/_synapse/admin/v1/users/" + user_id + "/override_ratelimit");
}

json admin_reset_password(const std::string& user_id,
                           const std::string& new_password,
                           bool logout_devices) {
    json body;
    body["new_password"] = new_password;
    body["logout_devices"] = logout_devices;
    return handle_reset_password(json::object(), body,
        "/_synapse/admin/v1/users/" + user_id + "/reset_password");
}

json admin_generate_registration_token(const std::string& user_id,
                                        int uses_allowed,
                                        int64_t expiry_time) {
    json body;
    body["uses_allowed"] = uses_allowed;
    body["expiry_time"] = expiry_time;
    return handle_generate_registration_token(json::object(), body,
        "/_synapse/admin/v1/users/" + user_id + "/registration_token");
}

json admin_list_user_devices(const std::string& user_id) {
    return handle_list_user_devices(json::object(), json::object(),
        "/_synapse/admin/v1/users/" + user_id + "/devices");
}

json admin_delete_user_device(const std::string& user_id,
                               const std::string& device_id,
                               bool permanent) {
    json body;
    body["permanent"] = permanent;
    return handle_delete_user_device(json::object(), body,
        "/_synapse/admin/v1/users/" + user_id + "/devices/" + device_id);
}

json admin_list_user_pushers(const std::string& user_id) {
    return handle_list_user_pushers(json::object(), json::object(),
        "/_synapse/admin/v1/users/" + user_id + "/pushers");
}

json admin_list_user_rooms(const std::string& user_id,
                            const std::string& membership_filter) {
    json params;
    if (!membership_filter.empty()) {
        params["membership"] = membership_filter;
    }
    return handle_list_user_rooms(params, json::object(),
        "/_synapse/admin/v1/users/" + user_id + "/rooms");
}

json admin_force_join_room(const std::string& user_id,
                            const std::string& room_id) {
    json body;
    body["room_id"] = room_id;
    return handle_force_join_room(json::object(), body,
        "/_synapse/admin/v1/users/" + user_id + "/force_join");
}

json admin_force_leave_room(const std::string& user_id,
                             const std::string& room_id,
                             bool ban) {
    json body;
    body["room_id"] = room_id;
    body["ban"] = ban;
    return handle_force_leave_room(json::object(), body,
        "/_synapse/admin/v1/users/" + user_id + "/force_leave");
}

json admin_export_user_data(const std::string& user_id) {
    return handle_export_user_data(json::object(), json::object(),
        "/_synapse/admin/v1/users/" + user_id + "/export");
}

json admin_lock_user(const std::string& user_id, const std::string& reason) {
    json body;
    body["reason"] = reason;
    return handle_lock_user(json::object(), body,
        "/_synapse/admin/v1/users/" + user_id + "/lock");
}

json admin_unlock_user(const std::string& user_id, const std::string& reason) {
    json body;
    body["reason"] = reason;
    return handle_unlock_user(json::object(), body,
        "/_synapse/admin/v1/users/" + user_id + "/unlock");
}

json admin_clear_ratelimit(const std::string& user_id) {
    return handle_clear_rate_limit(json::object(), json::object(),
        "/_synapse/admin/v1/users/" + user_id + "/clear_rate_limit");
}

// ============================================================================
// Initialization and test data seeding
// ============================================================================

void seed_user_admin_test_data(const std::string& server_name) {
    std::string ts = now_ms();

    // Seed test users
    {
        std::lock_guard<std::mutex> lock(db::users_mutex);

        // Admin user
        db::UserRecord admin_user;
        admin_user.id = "@admin:" + server_name;
        admin_user.displayname = "Administrator";
        admin_user.password_hash = hash_password("admin123!");
        admin_user.creation_ts = ts;
        admin_user.admin = true;
        admin_user.approved = true;
        admin_user.email = "admin@example.com";
        admin_user.threepids = json::array({
            {{"medium", "email"}, {"address", "admin@example.com"}}
        }).dump();
        db::users[admin_user.id] = admin_user;

        // Regular user Alice
        db::UserRecord alice;
        alice.id = "@alice:" + server_name;
        alice.displayname = "Alice";
        alice.password_hash = hash_password("alice123!");
        alice.creation_ts = ts;
        alice.email = "alice@example.com";
        alice.threepids = json::array({
            {{"medium", "email"}, {"address", "alice@example.com"}},
            {{"medium", "msisdn"}, {"address", "+1234567890"}}
        }).dump();
        db::users[alice.id] = alice;

        // Regular user Bob
        db::UserRecord bob;
        bob.id = "@bob:" + server_name;
        bob.displayname = "Bob";
        bob.password_hash = hash_password("bob123!");
        bob.creation_ts = ts;
        bob.email = "bob@example.com";
        db::users[bob.id] = bob;

        // Deactivated user Charlie
        db::UserRecord charlie;
        charlie.id = "@charlie:" + server_name;
        charlie.displayname = "Charlie (Deactivated)";
        charlie.password_hash = hash_password("charlie123!");
        charlie.creation_ts = ts;
        charlie.deactivated = true;
        charlie.email = "charlie@example.com";
        db::users[charlie.id] = charlie;

        // Shadow-banned user Dave
        db::UserRecord dave;
        dave.id = "@dave:" + server_name;
        dave.displayname = "Dave (Shadow-banned)";
        dave.password_hash = hash_password("dave123!");
        dave.creation_ts = ts;
        dave.shadow_banned = true;
        db::users[dave.id] = dave;

        // Locked user Eve
        db::UserRecord eve;
        eve.id = "@eve:" + server_name;
        eve.displayname = "Eve (Locked)";
        eve.password_hash = hash_password("eve123!");
        eve.creation_ts = ts;
        eve.locked = true;
        db::users[eve.id] = eve;

        // Guest user
        db::UserRecord guest;
        guest.id = "@guest:" + server_name;
        guest.displayname = "Guest User";
        guest.creation_ts = ts;
        guest.is_guest = true;
        db::users[guest.id] = guest;

        // Bot user
        db::UserRecord bot;
        bot.id = "@bot:" + server_name;
        bot.displayname = "Helper Bot";
        bot.password_hash = hash_password("bot_secret!");
        bot.creation_ts = ts;
        bot.user_type = "bot";
        db::users[bot.id] = bot;
    }

    // Seed test devices
    {
        std::lock_guard<std::mutex> lock(db::devices_mutex);

        // Alice's devices
        db::DeviceRecord alice_web;
        alice_web.device_id = "ALICEWEB01";
        alice_web.user_id = "@alice:" + server_name;
        alice_web.display_name = "Alice's Web Browser";
        alice_web.device_type = "web";
        alice_web.creation_ts = ts;
        alice_web.last_seen_ts = ts;
        alice_web.last_seen_ip = "192.168.1.100";
        alice_web.last_seen_user_agent = "Mozilla/5.0 WebClient";
        alice_web.is_active = true;
        db::devices[alice_web.device_id] = alice_web;
        db::user_devices[alice_web.user_id].push_back(alice_web.device_id);

        db::DeviceRecord alice_mobile;
        alice_mobile.device_id = "ALICEMOB01";
        alice_mobile.user_id = "@alice:" + server_name;
        alice_mobile.display_name = "Alice's Phone";
        alice_mobile.device_type = "mobile";
        alice_mobile.creation_ts = ts;
        alice_mobile.last_seen_ts = ts;
        alice_mobile.last_seen_ip = "10.0.0.50";
        alice_mobile.last_seen_user_agent = "MobileClient/1.0";
        alice_mobile.is_active = true;
        db::devices[alice_mobile.device_id] = alice_mobile;
        db::user_devices[alice_mobile.user_id].push_back(alice_mobile.device_id);

        // Bob's device
        db::DeviceRecord bob_desk;
        bob_desk.device_id = "BOBDESK01";
        bob_desk.user_id = "@bob:" + server_name;
        bob_desk.display_name = "Bob's Desktop";
        bob_desk.device_type = "desktop";
        bob_desk.creation_ts = ts;
        bob_desk.last_seen_ts = ts;
        bob_desk.last_seen_ip = "172.16.0.10";
        bob_desk.last_seen_user_agent = "DesktopClient/2.0";
        bob_desk.is_active = true;
        db::devices[bob_desk.device_id] = bob_desk;
        db::user_devices[bob_desk.user_id].push_back(bob_desk.device_id);
    }

    // Seed test pushers
    {
        std::lock_guard<std::mutex> lock(db::pushers_mutex);

        // Alice's HTTP pusher
        db::PusherRecord alice_http;
        alice_http.pusher_id = "pusher_http_alice_01";
        alice_http.user_id = "@alice:" + server_name;
        alice_http.app_id = "org.matrix.app";
        alice_http.app_display_name = "Matrix App";
        alice_http.device_display_name = "Alice's Phone";
        alice_http.pushkey = "apns_token_alice_12345";
        alice_http.kind = "http";
        alice_http.lang = "en";
        alice_http.enabled = true;
        alice_http.created_ts = ts;
        alice_http.updated_ts = ts;
        alice_http.device_id = "ALICEMOB01";
        alice_http.has_device = true;
        alice_http.data = json::object({{"url", "https://push.example.com/_matrix/push/v1/notify"}}).dump();
        db::pushers[alice_http.pusher_id] = alice_http;
        db::user_pushers[alice_http.user_id].push_back(alice_http.pusher_id);

        // Bob's email pusher
        db::PusherRecord bob_email;
        bob_email.pusher_id = "pusher_email_bob_01";
        bob_email.user_id = "@bob:" + server_name;
        bob_email.app_id = "org.matrix.email";
        bob_email.app_display_name = "Email Notifications";
        bob_email.device_display_name = "Bob's Email";
        bob_email.pushkey = "bob@example.com";
        bob_email.kind = "email";
        bob_email.lang = "en";
        bob_email.enabled = true;
        bob_email.created_ts = ts;
        bob_email.updated_ts = ts;
        bob_email.device_id = "BOBDESK01";
        bob_email.has_device = true;
        db::pushers[bob_email.pusher_id] = bob_email;
        db::user_pushers[bob_email.user_id].push_back(bob_email.pusher_id);
    }

    // Seed test rooms
    {
        std::lock_guard<std::mutex> rlock(db::rooms_mutex);
        std::lock_guard<std::mutex> mlock(db::membership_mutex);

        // General room
        db::RoomRecord general;
        general.room_id = "!general:" + server_name;
        general.name = "General";
        general.creator = "@admin:" + server_name;
        general.creation_ts = ts;
        general.joined_members = 3;
        general.total_members = 3;
        general.room_version = "10";
        general.join_rules = "invite";
        general.history_visibility = "shared";
        general.public_room = false;
        db::rooms[general.room_id] = general;

        // Add members to General
        for (const auto& uid : {
            std::string("@admin:") + server_name,
            std::string("@alice:") + server_name,
            std::string("@bob:") + server_name}) {

            db::RoomMembership mem;
            mem.room_id = general.room_id;
            mem.user_id = uid;
            mem.membership = "join";
            mem.sender = "@admin:" + server_name;
            mem.event_id = "$join_" + random_hex(16);
            mem.origin_server_ts = ts;
            mem.is_direct = false;
            db::memberships[mem.room_id + ":" + mem.user_id] = mem;
            db::user_rooms[uid].push_back(general.room_id);
        }
        db::room_members[general.room_id] = {
            "@admin:" + server_name,
            "@alice:" + server_name,
            "@bob:" + server_name
        };

        // Random room (public)
        db::RoomRecord random_room;
        random_room.room_id = "!random:" + server_name;
        random_room.name = "Random";
        random_room.creator = "@alice:" + server_name;
        random_room.creation_ts = ts;
        random_room.joined_members = 2;
        random_room.total_members = 2;
        random_room.room_version = "10";
        random_room.public_room = true;
        random_room.join_rules = "public";
        db::rooms[random_room.room_id] = random_room;

        for (const auto& uid : {
            std::string("@alice:") + server_name,
            std::string("@bob:") + server_name}) {

            db::RoomMembership mem;
            mem.room_id = random_room.room_id;
            mem.user_id = uid;
            mem.membership = "join";
            mem.sender = "@alice:" + server_name;
            mem.event_id = "$join_" + random_hex(16);
            mem.origin_server_ts = ts;
            mem.is_direct = false;
            db::memberships[mem.room_id + ":" + mem.user_id] = mem;
            db::user_rooms[uid].push_back(random_room.room_id);
        }
        db::room_members[random_room.room_id] = {
            "@alice:" + server_name,
            "@bob:" + server_name
        };
    }

    // Seed test connections
    {
        std::lock_guard<std::mutex> lock(db::connections_mutex);

        db::UserConnection alice_conn;
        alice_conn.connection_id = "conn_alice_01";
        alice_conn.user_id = "@alice:" + server_name;
        alice_conn.ip_address = "192.168.1.100";
        alice_conn.user_agent = "Mozilla/5.0 WebClient";
        alice_conn.last_seen_ts = ts;
        alice_conn.connected_since = ts;
        alice_conn.device_id = "ALICEWEB01";
        alice_conn.is_active = true;
        alice_conn.request_count = 42;
        db::connections[alice_conn.connection_id] = alice_conn;
        db::user_connections[alice_conn.user_id].push_back(alice_conn.connection_id);

        db::UserConnection bob_conn;
        bob_conn.connection_id = "conn_bob_01";
        bob_conn.user_id = "@bob:" + server_name;
        bob_conn.ip_address = "172.16.0.10";
        bob_conn.user_agent = "DesktopClient/2.0";
        bob_conn.last_seen_ts = ts;
        bob_conn.connected_since = ts;
        bob_conn.device_id = "BOBDESK01";
        bob_conn.is_active = true;
        bob_conn.request_count = 128;
        db::connections[bob_conn.connection_id] = bob_conn;
        db::user_connections[bob_conn.user_id].push_back(bob_conn.connection_id);
    }

    // Seed a registration token
    {
        std::lock_guard<std::mutex> lock(db::tokens_mutex);

        db::RegistrationToken tok;
        tok.token = "test-invite-2024";
        tok.uses_allowed = "5";
        tok.expiry_time = "0";
        tok.created_ts = ts;
        tok.created_by = "admin";
        tok.for_user_id = "@alice:" + server_name;
        db::reg_tokens[tok.token] = tok;
    }
}

// ============================================================================
// Statistics reporting
// ============================================================================

json get_user_admin_statistics() {
    json stats;

    {
        std::lock_guard<std::mutex> lock(db::users_mutex);
        int total_users = static_cast<int>(db::users.size());
        int active_users = 0, deactivated_users = 0, admin_users = 0;
        int locked_users = 0, shadow_banned_users = 0, guest_users = 0;
        int erased_users = 0, bot_users = 0, support_users = 0;
        int rate_limit_overridden = 0;

        for (const auto& [uid, rec] : db::users) {
            if (rec.deactivated) deactivated_users++;
            else active_users++;
            if (rec.admin) admin_users++;
            if (rec.locked) locked_users++;
            if (rec.shadow_banned) shadow_banned_users++;
            if (rec.is_guest) guest_users++;
            if (rec.erased) erased_users++;
            if (rec.user_type == "bot") bot_users++;
            if (rec.user_type == "support") support_users++;
            if (rec.rate_limit_overridden) rate_limit_overridden++;
        }

        stats["users"] = {
            {"total", total_users},
            {"active", active_users},
            {"deactivated", deactivated_users},
            {"admin", admin_users},
            {"locked", locked_users},
            {"shadow_banned", shadow_banned_users},
            {"guest", guest_users},
            {"erased", erased_users},
            {"bot", bot_users},
            {"support", support_users},
            {"rate_limit_overridden", rate_limit_overridden}
        };
    }

    {
        std::lock_guard<std::mutex> lock(db::devices_mutex);
        int total_devices = static_cast<int>(db::devices.size());
        int active_devices = 0, hidden_devices = 0;
        for (const auto& [did, dev] : db::devices) {
            if (dev.is_active) active_devices++;
            if (dev.hidden) hidden_devices++;
        }
        stats["devices"] = {
            {"total", total_devices},
            {"active", active_devices},
            {"inactive", total_devices - active_devices},
            {"hidden", hidden_devices}
        };
    }

    {
        std::lock_guard<std::mutex> lock(db::pushers_mutex);
        int total = static_cast<int>(db::pushers.size());
        int enabled = 0, http = 0, email = 0;
        for (const auto& [pid, p] : db::pushers) {
            if (p.enabled) enabled++;
            if (p.kind == "http") http++;
            else if (p.kind == "email") email++;
        }
        stats["pushers"] = {
            {"total", total},
            {"enabled", enabled},
            {"disabled", total - enabled},
            {"http", http},
            {"email", email}
        };
    }

    {
        std::lock_guard<std::mutex> lock(db::rooms_mutex);
        stats["rooms"] = {
            {"total", static_cast<int>(db::rooms.size())}
        };
    }

    {
        std::lock_guard<std::mutex> lock(db::tokens_mutex);
        stats["registration_tokens"] = {
            {"total", static_cast<int>(db::reg_tokens.size())}
        };
    }

    {
        std::lock_guard<std::mutex> lock(db::connections_mutex);
        int active_conns = 0;
        for (const auto& [cid, c] : db::connections) {
            if (c.is_active) active_conns++;
        }
        stats["connections"] = {
            {"total", static_cast<int>(db::connections.size())},
            {"active", active_conns}
        };
    }

    stats["generated_ts"] = static_cast<int64_t>(std::stoll(now_ms()));
    return stats;
}

} // namespace admin
} // namespace progressive
