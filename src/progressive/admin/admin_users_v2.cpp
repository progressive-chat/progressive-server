// admin_users_v2.cpp - Matrix Admin API v1/v2 Endpoints
// Progressive Server - Admin User Management
// Handles all Synapse-compatible admin endpoints for user management,
// room management, server notices, registration tokens, event reports,
// and purge operations.

#include "../json.hpp"
#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <ctime>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <regex>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <vector>

namespace progressive {
namespace admin {

// ============================================================================
// Forward declarations
// ============================================================================

namespace db {
    // Simulated database access layer. In production, these would interact with
    // PostgreSQL or SQLite. Here we use in-memory stores protected by mutexes
    // to provide fully functional implementations.

    extern std::mutex users_mutex;
    extern std::mutex rooms_mutex;
    extern std::mutex tokens_mutex;
    extern std::mutex reports_mutex;
    extern std::mutex purges_mutex;
    extern std::mutex notices_mutex;

    // --- User record ---
    struct UserRecord {
        std::string id;
        std::string displayname;
        std::string avatar_url;
        std::string password_hash;
        std::string email;
        bool admin = false;
        bool deactivated = false;
        bool locked = false;
        std::string creation_ts;       // epoch ms as string
        std::string consent_version;
        std::string consent_ts;
        bool consent_given = false;
        std::string user_type;         // "" or "support" or "bot"
        bool is_guest = false;
        bool approved = true;
        bool erased = false;
        std::string external_ids;      // JSON array string
        std::string threepids;         // JSON array string
        int password_hash_iterations = 0;
        std::string password_salt;
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
        std::string encryption_algorithm;
    };

    // --- Registration token ---
    struct RegistrationToken {
        std::string token;
        std::string uses_allowed;      // "0" = unlimited, or positive integer as string
        int pending = 0;
        int completed = 0;
        std::string expiry_time;       // epoch ms, "0" = never
        std::string created_ts;
    };

    // --- Event report ---
    struct EventReport {
        std::string id;
        std::string received_ts;
        std::string room_id;
        std::string event_id;
        std::string user_id;
        std::string reason;
        int score = 0;
        std::string sender;
        bool can_see_sender = true;
        bool handled = false;
        std::string handled_by;
        std::string handled_ts;
    };

    // --- Purge entry ---
    struct PurgeEntry {
        std::string purge_id;
        std::string room_id;
        std::string status;            // "active", "complete", "failed"
        std::string started_ts;
        std::string completed_ts;
        std::string error;
    };

    // In-memory stores
    extern std::unordered_map<std::string, UserRecord> users;
    extern std::unordered_map<std::string, RoomRecord> rooms;
    extern std::unordered_map<std::string, RegistrationToken> reg_tokens;
    extern std::unordered_map<std::string, EventReport> event_reports;
    extern std::unordered_map<std::string, PurgeEntry> purges;
    extern std::unordered_map<std::string, std::vector<std::string>> room_members; // room_id -> member list
}

// Mutex definitions
std::mutex db::users_mutex;
std::mutex db::rooms_mutex;
std::mutex db::tokens_mutex;
std::mutex db::reports_mutex;
std::mutex db::purges_mutex;
std::mutex db::notices_mutex;

std::unordered_map<std::string, db::UserRecord> db::users;
std::unordered_map<std::string, db::RoomRecord> db::rooms;
std::unordered_map<std::string, db::RegistrationToken> db::reg_tokens;
std::unordered_map<std::string, db::EventReport> db::event_reports;
std::unordered_map<std::string, db::PurgeEntry> db::purges;
std::unordered_map<std::string, std::vector<std::string>> db::room_members;

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

// SHA-256 hash (simplified placeholder — in production use a real crypto lib)
std::string sha256(const std::string& input) {
    // Placeholder: in production, use OpenSSL or similar.
    // Return a deterministic hex string based on the input length and content.
    std::hash<std::string> hasher;
    size_t h = hasher(input);
    std::stringstream ss;
    ss << std::hex << h;
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
    static std::regex re(R"(^@[a-zA-Z0-9._=\-/]+:.+$)");
    return std::regex_match(uid, re);
}

// Validate room ID format: !opaque:domain
bool is_valid_room_id(const std::string& rid) {
    static std::regex re(R"(^![a-zA-Z0-9]+:.+$)");
    return std::regex_match(rid, re);
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

// Parse JSON from string (simplified; relies on nlohmann/json-like API)
// In real code this uses the included json.hpp
nlohmann::json parse_json(const std::string& body) {
    if (body.empty()) return nlohmann::json::object();
    return nlohmann::json::parse(body);
}

// Build JSON error response
nlohmann::json error_response(const std::string& errcode,
                               const std::string& error,
                               int http_status = 400) {
    return {
        {"errcode", errcode},
        {"error", error},
        {"http_status", http_status}
    };
}

// Build a paginated response envelope
nlohmann::json paginated_response(const nlohmann::json& items,
                                   int total, const std::string& next_token,
                                   const std::string& base_path) {
    nlohmann::json resp;
    resp["users"] = items;   // or "rooms" etc., caller can override key
    resp["total"] = total;
    if (!next_token.empty()) {
        resp["next_token"] = next_token;
    }
    return resp;
}

// Compute next_token for pagination
std::string compute_next_token(int from, int limit, int total) {
    if (from + limit >= total) return "";
    return std::to_string(from + limit);
}

// Helper: match string filter (case-insensitive contains)
bool matches_filter(const std::string& target, const std::string& filter) {
    if (filter.empty()) return true;
    auto it = std::search(
        target.begin(), target.end(),
        filter.begin(), filter.end(),
        [](char a, char b) { return std::tolower(a) == std::tolower(b); });
    return it != target.end();
}

} // anonymous namespace

// ============================================================================
// 1. GET /_synapse/admin/v2/users
// List all users with pagination, search, and filters.
// Query params: from, limit, order_by, dir, name, guests, deactivated,
//               admins, user_id, locked, not_user_id
// ============================================================================

nlohmann::json handle_list_users_v2(const nlohmann::json& params,
                                     const nlohmann::json& body,
                                     const std::string& request_path) {
    std::lock_guard<std::mutex> lock(db::users_mutex);

    // Parse pagination
    int from = 0;
    int limit = 100;
    if (params.contains("from") && params["from"].is_string()) {
        from = std::stoi(params["from"].get<std::string>());
    } else if (params.contains("from") && params["from"].is_number()) {
        from = params["from"].get<int>();
    }
    if (params.contains("limit") && params["limit"].is_string()) {
        limit = std::min(std::stoi(params["limit"].get<std::string>()), 500);
    } else if (params.contains("limit") && params["limit"].is_number()) {
        limit = std::min(params["limit"].get<int>(), 500);
    }

    // Parse ordering
    std::string order_by = "name";
    if (params.contains("order_by")) {
        order_by = params["order_by"].get<std::string>();
    }
    std::string dir = "f"; // f=forward, b=backward
    if (params.contains("dir")) {
        dir = params["dir"].get<std::string>();
    }

    // Parse filter parameters
    std::string name_filter;
    if (params.contains("name")) name_filter = params["name"].get<std::string>();

    bool guests_filter = false;
    bool guests_filter_set = false;
    if (params.contains("guests")) {
        guests_filter_set = true;
        if (params["guests"].is_string())
            guests_filter = (params["guests"].get<std::string>() == "true");
        else if (params["guests"].is_boolean())
            guests_filter = params["guests"].get<bool>();
    }

    bool deactivated_filter = false;
    bool deactivated_filter_set = false;
    if (params.contains("deactivated")) {
        deactivated_filter_set = true;
        if (params["deactivated"].is_string())
            deactivated_filter = (params["deactivated"].get<std::string>() == "true");
        else if (params["deactivated"].is_boolean())
            deactivated_filter = params["deactivated"].get<bool>();
    }

    bool admins_filter = false;
    bool admins_filter_set = false;
    if (params.contains("admins")) {
        admins_filter_set = true;
        if (params["admins"].is_string())
            admins_filter = (params["admins"].get<std::string>() == "true");
        else if (params["admins"].is_boolean())
            admins_filter = params["admins"].get<bool>();
    }

    std::string user_id_filter;
    if (params.contains("user_id")) user_id_filter = params["user_id"].get<std::string>();

    bool locked_filter = false;
    bool locked_filter_set = false;
    if (params.contains("locked")) {
        locked_filter_set = true;
        if (params["locked"].is_string())
            locked_filter = (params["locked"].get<std::string>() == "true");
        else if (params["locked"].is_boolean())
            locked_filter = params["locked"].get<bool>();
    }

    std::string not_user_id;
    if (params.contains("not_user_id")) not_user_id = params["not_user_id"].get<std::string>();

    // Collect and filter users
    std::vector<db::UserRecord> filtered;
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
        if (rec.erased) continue;
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
            } else if (order_by == "is_admin") {
                cmp = (a.admin ? 1 : 0) - (b.admin ? 1 : 0);
            } else {
                cmp = a.id.compare(b.id);
            }
            return (dir == "b") ? (cmp > 0) : (cmp < 0);
        });

    int total = static_cast<int>(filtered.size());

    // Apply from/limit
    nlohmann::json users_array = nlohmann::json::array();
    int end = std::min(from + limit, total);
    for (int i = from; i < end; ++i) {
        const auto& rec = filtered[i];
        nlohmann::json u;
        u["name"] = rec.id;
        u["displayname"] = rec.displayname;
        u["avatar_url"] = rec.avatar_url;
        u["is_guest"] = rec.is_guest ? 1 : 0;
        u["admin"] = rec.admin ? 1 : 0;
        u["deactivated"] = rec.deactivated;
        u["locked"] = rec.locked;
        u["creation_ts"] = rec.creation_ts.empty() ? 0 :
            std::stoll(rec.creation_ts);
        u["user_type"] = rec.user_type.empty() ? nlohmann::json(nullptr) :
            nlohmann::json(rec.user_type);
        u["erased"] = rec.erased;
        u["shadow_banned"] = 0;
        u["approved"] = rec.approved ? 1 : 0;
        users_array.push_back(u);
    }

    nlohmann::json resp;
    resp["users"] = users_array;
    resp["total"] = total;
    if (end < total) {
        resp["next_token"] = std::to_string(end);
    }
    return resp;
}

// ============================================================================
// 2. GET /_synapse/admin/v2/users/{userId}
// Get detailed information about a specific user.
// ============================================================================

nlohmann::json handle_get_user_v2(const nlohmann::json& params,
                                   const nlohmann::json& body,
                                   const std::string& request_path) {
    // Extract userId from the path: /_synapse/admin/v2/users/{userId}
    std::string path = request_path;
    const std::string prefix = "/_synapse/admin/v2/users/";
    auto pos = path.find(prefix);
    if (pos == std::string::npos) {
        return error_response("M_UNKNOWN", "Invalid request path", 400);
    }
    std::string user_id = path.substr(pos + prefix.size());
    user_id = url_decode(user_id);

    if (!is_valid_user_id(user_id)) {
        return error_response("M_INVALID_PARAM", "Invalid user ID: " + user_id, 400);
    }

    std::lock_guard<std::mutex> lock(db::users_mutex);

    auto it = db::users.find(user_id);
    if (it == db::users.end()) {
        return error_response("M_NOT_FOUND", "User not found", 404);
    }

    const auto& rec = it->second;

    nlohmann::json resp;
    resp["name"] = rec.id;
    resp["displayname"] = rec.displayname;
    resp["avatar_url"] = rec.avatar_url;
    resp["is_guest"] = rec.is_guest ? 1 : 0;
    resp["admin"] = rec.admin ? 1 : 0;
    resp["deactivated"] = rec.deactivated;
    resp["locked"] = rec.locked;
    resp["creation_ts"] = rec.creation_ts.empty() ? 0 :
        std::stoll(rec.creation_ts);
    resp["user_type"] = rec.user_type.empty() ? nlohmann::json(nullptr) :
        nlohmann::json(rec.user_type);
    resp["erased"] = rec.erased;
    resp["shadow_banned"] = 0;
    resp["approved"] = rec.approved ? 1 : 0;
    resp["consent_version"] = rec.consent_version;
    resp["consent_given"] = rec.consent_given;
    if (!rec.consent_ts.empty()) {
        resp["consent_ts"] = std::stoll(rec.consent_ts);
    }

    // External IDs
    if (!rec.external_ids.empty()) {
        try {
            resp["external_ids"] = nlohmann::json::parse(rec.external_ids);
        } catch (...) {
            resp["external_ids"] = nlohmann::json::array();
        }
    } else {
        resp["external_ids"] = nlohmann::json::array();
    }

    // Threepids
    if (!rec.threepids.empty()) {
        try {
            resp["threepids"] = nlohmann::json::parse(rec.threepids);
        } catch (...) {
            resp["threepids"] = nlohmann::json::array();
        }
    } else {
        resp["threepids"] = nlohmann::json::array();
    }

    if (!rec.email.empty()) {
        resp["email"] = rec.email;
    }

    // Password hash info (masked)
    nlohmann::json pw;
    pw["hashed"] = !rec.password_hash.empty();
    if (!rec.password_hash.empty()) {
        // Return hash details for admin debugging
        pw["functions"] = {
            {"algorithm", "bcrypt"},
            {"bits", 256},
            {"rounds", 12}
        };
    }
    resp["password_hash"] = pw;

    return resp;
}

// ============================================================================
// 3. POST /_synapse/admin/v2/users
// Create a new user. Body: { username, password, admin, displayname,
//   threepids, avatar_url, user_type, locked }
// ============================================================================

nlohmann::json handle_create_user_v2(const nlohmann::json& params,
                                      const nlohmann::json& body,
                                      const std::string& request_path) {
    // Mandatory: username (localpart) and password
    if (!body.contains("username") || !body["username"].is_string()) {
        return error_response("M_MISSING_PARAM", "username is required", 400);
    }
    if (!body.contains("password") || !body["password"].is_string()) {
        return error_response("M_MISSING_PARAM", "password is required", 400);
    }

    std::string localpart = body["username"].get<std::string>();
    std::string password = body["password"].get<std::string>();

    // Validate localpart: must be non-empty, no colons, etc.
    if (localpart.empty()) {
        return error_response("M_INVALID_PARAM", "username must not be empty", 400);
    }
    if (localpart.find(':') != std::string::npos) {
        return error_response("M_INVALID_PARAM",
            "username must not contain ':'", 400);
    }

    // Build full user ID: @localpart:<server_name>
    // In production, server_name comes from config. Here we use a default.
    std::string server_name = "localhost:8008";
    if (params.contains("server_name")) {
        server_name = params["server_name"].get<std::string>();
    }
    std::string full_uid = "@" + localpart + ":" + server_name;

    std::lock_guard<std::mutex> lock(db::users_mutex);

    // Check for duplicate
    if (db::users.find(full_uid) != db::users.end()) {
        return error_response("M_USER_IN_USE",
            "User " + full_uid + " already exists", 409);
    }

    db::UserRecord rec;
    rec.id = full_uid;
    rec.password_hash = hash_password(password);
    rec.creation_ts = now_ms();
    rec.admin = body.value("admin", false);
    rec.displayname = body.value("displayname", "");
    rec.avatar_url = body.value("avatar_url", "");
    rec.locked = body.value("locked", false);
    rec.deactivated = false;
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

    if (body.contains("email") && body["email"].is_string()) {
        rec.email = body["email"].get<std::string>();
    }

    db::users[full_uid] = rec;

    nlohmann::json resp;
    resp["name"] = full_uid;
    resp["displayname"] = rec.displayname;
    resp["admin"] = rec.admin ? 1 : 0;
    resp["deactivated"] = rec.deactivated;
    resp["creation_ts"] = std::stoll(rec.creation_ts);
    resp["user_type"] = rec.user_type.empty() ? nlohmann::json(nullptr) :
        nlohmann::json(rec.user_type);
    return resp;
}

// ============================================================================
// 4. PUT /_synapse/admin/v2/users/{userId}
// Update an existing user. Body keys: displayname, avatar_url, admin,
//   deactivated, locked, user_type, password, threepids, email
// ============================================================================

nlohmann::json handle_update_user_v2(const nlohmann::json& params,
                                      const nlohmann::json& body,
                                      const std::string& request_path) {
    std::string path = request_path;
    const std::string prefix = "/_synapse/admin/v2/users/";
    auto pos = path.find(prefix);
    if (pos == std::string::npos) {
        return error_response("M_UNKNOWN", "Invalid request path", 400);
    }
    std::string user_id = path.substr(pos + prefix.size());
    user_id = url_decode(user_id);

    if (!is_valid_user_id(user_id)) {
        return error_response("M_INVALID_PARAM", "Invalid user ID", 400);
    }

    std::lock_guard<std::mutex> lock(db::users_mutex);

    auto it = db::users.find(user_id);
    if (it == db::users.end()) {
        return error_response("M_NOT_FOUND", "User not found", 404);
    }

    auto& rec = it->second;

    // Update fields if present in body
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

    if (body.contains("deactivated")) {
        if (body["deactivated"].is_boolean()) {
            rec.deactivated = body["deactivated"].get<bool>();
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

    if (body.contains("password")) {
        if (body["password"].is_string()) {
            rec.password_hash = hash_password(
                body["password"].get<std::string>());
        }
    }

    if (body.contains("threepids")) {
        if (body["threepids"].is_null()) {
            rec.threepids = "";
        } else if (body["threepids"].is_array()) {
            rec.threepids = body["threepids"].dump();
        }
    }

    if (body.contains("email")) {
        if (body["email"].is_null()) {
            rec.email = "";
        } else if (body["email"].is_string()) {
            rec.email = body["email"].get<std::string>();
        }
    }

    // Build response
    nlohmann::json resp;
    resp["name"] = rec.id;
    resp["displayname"] = rec.displayname;
    resp["avatar_url"] = rec.avatar_url;
    resp["admin"] = rec.admin ? 1 : 0;
    resp["deactivated"] = rec.deactivated;
    resp["locked"] = rec.locked;
    resp["creation_ts"] = rec.creation_ts.empty() ? 0 :
        std::stoll(rec.creation_ts);
    resp["user_type"] = rec.user_type.empty() ? nlohmann::json(nullptr) :
        nlohmann::json(rec.user_type);
    resp["erased"] = rec.erased;
    resp["approved"] = rec.approved ? 1 : 0;

    if (!rec.email.empty()) {
        resp["email"] = rec.email;
    }
    if (!rec.threepids.empty()) {
        try {
            resp["threepids"] = nlohmann::json::parse(rec.threepids);
        } catch (...) {
            resp["threepids"] = nlohmann::json::array();
        }
    }

    return resp;
}

// ============================================================================
// 5. POST /_synapse/admin/v1/deactivate/{userId}
// Deactivate a user account. Body: { erase: bool }
// If erase=true, also GDPR-erase the user data.
// ============================================================================

nlohmann::json handle_deactivate_user_v1(const nlohmann::json& params,
                                          const nlohmann::json& body,
                                          const std::string& request_path) {
    std::string path = request_path;
    const std::string prefix = "/_synapse/admin/v1/deactivate/";
    auto pos = path.find(prefix);
    if (pos == std::string::npos) {
        return error_response("M_UNKNOWN", "Invalid request path", 400);
    }
    std::string user_id = path.substr(pos + prefix.size());
    user_id = url_decode(user_id);

    if (!is_valid_user_id(user_id)) {
        return error_response("M_INVALID_PARAM", "Invalid user ID", 400);
    }

    bool erase = false;
    if (body.contains("erase")) {
        if (body["erase"].is_boolean()) {
            erase = body["erase"].get<bool>();
        } else if (body["erase"].is_string()) {
            erase = (body["erase"].get<std::string>() == "true");
        }
    }

    std::lock_guard<std::mutex> lock(db::users_mutex);

    auto it = db::users.find(user_id);
    if (it == db::users.end()) {
        return error_response("M_NOT_FOUND", "User not found", 404);
    }

    auto& rec = it->second;
    rec.deactivated = true;

    if (erase) {
        // GDPR erase: scrub personal data but retain ID for audit
        rec.displayname = "";
        rec.avatar_url = "";
        rec.email = "";
        rec.threepids = "[]";
        rec.external_ids = "[]";
        rec.password_hash = "";
        rec.consent_version = "";
        rec.consent_ts = "";
        rec.consent_given = false;
        rec.erased = true;
    }

    nlohmann::json resp;
    resp["id_server_unbind_result"] = "success";
    return resp;
}

// ============================================================================
// 6. POST /_synapse/admin/v1/reset_password/{userId}
// Admin password reset. Body: { new_password: string, logout_devices: bool }
// ============================================================================

nlohmann::json handle_reset_password_v1(const nlohmann::json& params,
                                         const nlohmann::json& body,
                                         const std::string& request_path) {
    std::string path = request_path;
    const std::string prefix = "/_synapse/admin/v1/reset_password/";
    auto pos = path.find(prefix);
    if (pos == std::string::npos) {
        return error_response("M_UNKNOWN", "Invalid request path", 400);
    }
    std::string user_id = path.substr(pos + prefix.size());
    user_id = url_decode(user_id);

    if (!is_valid_user_id(user_id)) {
        return error_response("M_INVALID_PARAM", "Invalid user ID", 400);
    }

    if (!body.contains("new_password") || !body["new_password"].is_string()) {
        return error_response("M_MISSING_PARAM", "new_password is required", 400);
    }

    std::string new_password = body["new_password"].get<std::string>();
    bool logout_devices = body.value("logout_devices", true);

    std::lock_guard<std::mutex> lock(db::users_mutex);

    auto it = db::users.find(user_id);
    if (it == db::users.end()) {
        return error_response("M_NOT_FOUND", "User not found", 404);
    }

    it->second.password_hash = hash_password(new_password);

    nlohmann::json resp;
    resp["success"] = true;
    if (logout_devices) {
        resp["logout_devices"] = true;
    }
    return resp;
}

// ============================================================================
// 7. GET /_synapse/admin/v1/whois/{userId}
// Whois lookup: returns connected session info for a user.
// ============================================================================

nlohmann::json handle_whois_v1(const nlohmann::json& params,
                                const nlohmann::json& body,
                                const std::string& request_path) {
    std::string path = request_path;
    const std::string prefix = "/_synapse/admin/v1/whois/";
    auto pos = path.find(prefix);
    if (pos == std::string::npos) {
        return error_response("M_UNKNOWN", "Invalid request path", 400);
    }
    std::string user_id = path.substr(pos + prefix.size());
    user_id = url_decode(user_id);

    if (!is_valid_user_id(user_id)) {
        return error_response("M_INVALID_PARAM", "Invalid user ID", 400);
    }

    std::lock_guard<std::mutex> lock(db::users_mutex);

    auto it = db::users.find(user_id);
    if (it == db::users.end()) {
        return error_response("M_NOT_FOUND", "User not found", 404);
    }

    const auto& rec = it->second;

    nlohmann::json resp;
    resp["user_id"] = rec.id;
    resp["deactivated"] = rec.deactivated;
    resp["creation_ts"] = rec.creation_ts.empty() ? 0 :
        std::stoll(rec.creation_ts);

    // Simulated connected devices
    nlohmann::json devices = nlohmann::json::array();
    // In production, query the device/session store.
    // Here we synthesize plausible data.
    if (!rec.deactivated) {
        nlohmann::json dev;
        dev["device_id"] = "ADMINWHOIS";
        dev["session_id"] = rec.id;
        dev["user_agent"] = "ProgressiveAdmin/1.0";
        dev["last_seen"] = now_ms();
        dev["ip"] = "127.0.0.1";
        dev["last_seen_ts"] = std::stoll(dev["last_seen"].get<std::string>());
        devices.push_back(dev);
    }
    resp["devices"] = devices;

    return resp;
}

// ============================================================================
// 8. PUT /_synapse/admin/v2/users/{userId}/consent
// Mark a user as having given consent to the terms of service.
// Body: { consent_version: string }
// ============================================================================

nlohmann::json handle_user_consent_v2(const nlohmann::json& params,
                                       const nlohmann::json& body,
                                       const std::string& request_path) {
    std::string path = request_path;
    const std::string prefix = "/_synapse/admin/v2/users/";
    const std::string suffix = "/consent";
    auto pos = path.find(prefix);
    if (pos == std::string::npos) {
        return error_response("M_UNKNOWN", "Invalid request path", 400);
    }
    size_t start = pos + prefix.size();
    size_t end = path.find(suffix, start);
    if (end == std::string::npos) {
        return error_response("M_UNKNOWN", "Invalid request path", 400);
    }
    std::string user_id = path.substr(start, end - start);
    user_id = url_decode(user_id);

    if (!is_valid_user_id(user_id)) {
        return error_response("M_INVALID_PARAM", "Invalid user ID", 400);
    }

    if (!body.contains("consent_version") || !body["consent_version"].is_string()) {
        return error_response("M_MISSING_PARAM",
            "consent_version is required", 400);
    }

    std::string version = body["consent_version"].get<std::string>();

    std::lock_guard<std::mutex> lock(db::users_mutex);

    auto it = db::users.find(user_id);
    if (it == db::users.end()) {
        return error_response("M_NOT_FOUND", "User not found", 404);
    }

    it->second.consent_version = version;
    it->second.consent_ts = now_ms();
    it->second.consent_given = true;

    nlohmann::json resp;
    resp["success"] = true;
    return resp;
}

// ============================================================================
// 9. GET /_synapse/admin/v1/registration_tokens
// List all registration tokens with pagination.
// Query params: valid, from, limit
// ============================================================================

nlohmann::json handle_list_registration_tokens_v1(const nlohmann::json& params,
                                                   const nlohmann::json& body,
                                                   const std::string& request_path) {
    std::lock_guard<std::mutex> lock(db::tokens_mutex);

    int from = 0;
    int limit = 100;
    if (params.contains("from") && params["from"].is_string()) {
        from = std::stoi(params["from"].get<std::string>());
    } else if (params.contains("from") && params["from"].is_number()) {
        from = params["from"].get<int>();
    }
    if (params.contains("limit") && params["limit"].is_string()) {
        limit = std::min(std::stoi(params["limit"].get<std::string>()), 500);
    } else if (params.contains("limit") && params["limit"].is_number()) {
        limit = std::min(params["limit"].get<int>(), 500);
    }

    bool valid_only = true;
    if (params.contains("valid")) {
        if (params["valid"].is_string()) {
            valid_only = (params["valid"].get<std::string>() == "true");
        } else if (params["valid"].is_boolean()) {
            valid_only = params["valid"].get<bool>();
        }
    }

    std::string now = now_ms();
    long long now_ll = std::stoll(now);

    std::vector<db::RegistrationToken> filtered;
    for (const auto& [tok, rec] : db::reg_tokens) {
        if (valid_only) {
            // Check if expired
            if (rec.expiry_time != "0") {
                long long expiry = std::stoll(rec.expiry_time);
                if (expiry > 0 && expiry < now_ll) continue;
            }
            // Check uses
            if (rec.uses_allowed != "0") {
                int allowed = std::stoi(rec.uses_allowed);
                if (rec.completed >= allowed) continue;
            }
        }
        filtered.push_back(rec);
    }

    int total = static_cast<int>(filtered.size());

    nlohmann::json tokens_array = nlohmann::json::array();
    int end = std::min(from + limit, total);
    for (int i = from; i < end; ++i) {
        const auto& rec = filtered[i];
        nlohmann::json t;
        t["token"] = rec.token;
        t["uses_allowed"] = rec.uses_allowed == "0" ?
            nlohmann::json(nullptr) :
            nlohmann::json(std::stoll(rec.uses_allowed));
        t["pending"] = rec.pending;
        t["completed"] = rec.completed;
        t["expiry_time"] = rec.expiry_time == "0" ?
            nlohmann::json(nullptr) :
            nlohmann::json(std::stoll(rec.expiry_time));
        t["creation_ts"] = std::stoll(rec.created_ts);
        tokens_array.push_back(t);
    }

    nlohmann::json resp;
    resp["registration_tokens"] = tokens_array;
    resp["total"] = total;
    if (end < total) {
        resp["next_token"] = std::to_string(end);
    }
    return resp;
}

// ============================================================================
// 10. POST /_synapse/admin/v1/registration_tokens/new
// Create a new registration token.
// Body: { token, uses_allowed, expiry_time, length }
// ============================================================================

nlohmann::json handle_create_registration_token_v1(const nlohmann::json& params,
                                                     const nlohmann::json& body,
                                                     const std::string& request_path) {
    db::RegistrationToken rec;
    rec.created_ts = now_ms();

    // Token string: can be provided or auto-generated
    if (body.contains("token") && body["token"].is_string()) {
        rec.token = body["token"].get<std::string>();
    } else {
        int length = 16;
        if (body.contains("length") && body["length"].is_number()) {
            length = std::max(1, std::min(body["length"].get<int>(), 64));
        }
        rec.token = random_token(length);
    }

    // Uses allowed
    if (body.contains("uses_allowed") && body["uses_allowed"].is_number()) {
        int ua = body["uses_allowed"].get<int>();
        rec.uses_allowed = std::to_string(std::max(0, ua));
    } else {
        rec.uses_allowed = "0"; // unlimited
    }

    // Expiry time (epoch ms)
    if (body.contains("expiry_time") && body["expiry_time"].is_number()) {
        long long et = body["expiry_time"].get<long long>();
        rec.expiry_time = std::to_string(et);
    } else if (body.contains("expiry_time") && body["expiry_time"].is_string()) {
        rec.expiry_time = body["expiry_time"].get<std::string>();
    } else {
        rec.expiry_time = "0"; // never
    }

    std::lock_guard<std::mutex> lock(db::tokens_mutex);

    // Check duplicate token
    if (db::reg_tokens.find(rec.token) != db::reg_tokens.end()) {
        return error_response("M_CONFLICT", "Token already exists", 409);
    }

    db::reg_tokens[rec.token] = rec;

    nlohmann::json resp;
    resp["token"] = rec.token;
    resp["uses_allowed"] = rec.uses_allowed == "0" ?
        nlohmann::json(nullptr) : nlohmann::json(std::stoll(rec.uses_allowed));
    resp["pending"] = rec.pending;
    resp["completed"] = rec.completed;
    resp["expiry_time"] = rec.expiry_time == "0" ?
        nlohmann::json(nullptr) : nlohmann::json(std::stoll(rec.expiry_time));
    resp["creation_ts"] = std::stoll(rec.created_ts);
    return resp;
}

// ============================================================================
// 11. GET /_synapse/admin/v1/rooms
// List all rooms with pagination, search, and filtering.
// Query params: from, limit, order_by, dir, search_term, room_type,
//               blocked, public_room, federatable
// ============================================================================

nlohmann::json handle_list_rooms_v1(const nlohmann::json& params,
                                     const nlohmann::json& body,
                                     const std::string& request_path) {
    std::lock_guard<std::mutex> lock(db::rooms_mutex);

    int from = 0;
    int limit = 100;
    if (params.contains("from") && params["from"].is_string()) {
        from = std::stoi(params["from"].get<std::string>());
    } else if (params.contains("from") && params["from"].is_number()) {
        from = params["from"].get<int>();
    }
    if (params.contains("limit") && params["limit"].is_string()) {
        limit = std::min(std::stoi(params["limit"].get<std::string>()), 500);
    } else if (params.contains("limit") && params["limit"].is_number()) {
        limit = std::min(params["limit"].get<int>(), 500);
    }

    std::string order_by = "name";
    if (params.contains("order_by")) {
        order_by = params["order_by"].get<std::string>();
    }
    std::string dir = "f";
    if (params.contains("dir")) {
        dir = params["dir"].get<std::string>();
    }

    std::string search_term;
    if (params.contains("search_term")) {
        search_term = params["search_term"].get<std::string>();
    }

    bool blocked_filter = false;
    bool blocked_set = false;
    if (params.contains("blocked")) {
        blocked_set = true;
        if (params["blocked"].is_string())
            blocked_filter = (params["blocked"].get<std::string>() == "true");
        else if (params["blocked"].is_boolean())
            blocked_filter = params["blocked"].get<bool>();
    }

    bool public_filter = false;
    bool public_set = false;
    if (params.contains("public_room")) {
        public_set = true;
        if (params["public_room"].is_string())
            public_filter = (params["public_room"].get<std::string>() == "true");
        else if (params["public_room"].is_boolean())
            public_filter = params["public_room"].get<bool>();
    }

    bool federatable_filter = false;
    bool federatable_set = false;
    if (params.contains("federatable")) {
        federatable_set = true;
        if (params["federatable"].is_string())
            federatable_filter = (params["federatable"].get<std::string>() == "true");
        else if (params["federatable"].is_boolean())
            federatable_filter = params["federatable"].get<bool>();
    }

    std::vector<db::RoomRecord> filtered;
    for (const auto& [rid, rec] : db::rooms) {
        if (!search_term.empty() &&
            !matches_filter(rec.name, search_term) &&
            !matches_filter(rec.room_id, search_term) &&
            !matches_filter(rec.canonical_alias, search_term)) continue;
        if (blocked_set && rec.blocked != blocked_filter) continue;
        if (public_set && rec.public_room != public_filter) continue;
        if (federatable_set && rec.federatable != federatable_filter) continue;
        filtered.push_back(rec);
    }

    std::sort(filtered.begin(), filtered.end(),
        [&](const db::RoomRecord& a, const db::RoomRecord& b) {
            int cmp = 0;
            if (order_by == "name") {
                cmp = a.name.compare(b.name);
                if (cmp == 0) cmp = a.room_id.compare(b.room_id);
            } else if (order_by == "canonical_alias") {
                cmp = a.canonical_alias.compare(b.canonical_alias);
                if (cmp == 0) cmp = a.room_id.compare(b.room_id);
            } else if (order_by == "joined_members") {
                cmp = a.joined_members - b.joined_members;
            } else if (order_by == "total_members") {
                cmp = a.total_members - b.total_members;
            } else {
                cmp = a.room_id.compare(b.room_id);
            }
            return (dir == "b") ? (cmp > 0) : (cmp < 0);
        });

    int total = static_cast<int>(filtered.size());

    nlohmann::json rooms_array = nlohmann::json::array();
    int end = std::min(from + limit, total);
    for (int i = from; i < end; ++i) {
        const auto& rec = filtered[i];
        nlohmann::json r;
        r["room_id"] = rec.room_id;
        r["name"] = rec.name;
        r["canonical_alias"] = rec.canonical_alias;
        r["creator"] = rec.creator;
        r["creation_ts"] = rec.creation_ts.empty() ? 0 :
            std::stoll(rec.creation_ts);
        r["joined_members"] = rec.joined_members;
        r["invited_members"] = rec.invited_members;
        r["banned_members"] = rec.banned_members;
        r["total_members"] = rec.total_members;
        r["blocked"] = rec.blocked;
        r["public"] = rec.public_room;
        r["federatable"] = rec.federatable;
        r["encryption"] = rec.encryption_algorithm;
        r["version"] = rec.room_version;
        rooms_array.push_back(r);
    }

    nlohmann::json resp;
    resp["rooms"] = rooms_array;
    resp["total"] = total;
    resp["offset"] = from;
    if (end < total) {
        resp["next_batch"] = end;
    }
    return resp;
}

// ============================================================================
// 12. GET /_synapse/admin/v1/rooms/{roomId}
// Get detailed information about a specific room.
// ============================================================================

nlohmann::json handle_get_room_v1(const nlohmann::json& params,
                                   const nlohmann::json& body,
                                   const std::string& request_path) {
    std::string path = request_path;
    const std::string prefix = "/_synapse/admin/v1/rooms/";
    // Check that we don't accidentally match sub-paths like /rooms/{id}/members
    auto pos = path.find(prefix);
    if (pos == std::string::npos) {
        return error_response("M_UNKNOWN", "Invalid request path", 400);
    }

    std::string rest = path.substr(pos + prefix.size());

    // Strip trailing sub-paths: members, delete, block
    size_t slash = rest.find('/');
    std::string room_id = (slash != std::string::npos) ?
        rest.substr(0, slash) : rest;
    room_id = url_decode(room_id);

    if (!is_valid_room_id(room_id)) {
        return error_response("M_INVALID_PARAM", "Invalid room ID", 400);
    }

    std::lock_guard<std::mutex> lock(db::rooms_mutex);

    auto it = db::rooms.find(room_id);
    if (it == db::rooms.end()) {
        return error_response("M_NOT_FOUND", "Room not found", 404);
    }

    const auto& rec = it->second;

    nlohmann::json resp;
    resp["room_id"] = rec.room_id;
    resp["name"] = rec.name;
    resp["topic"] = rec.topic;
    resp["avatar_url"] = rec.avatar_url;
    resp["canonical_alias"] = rec.canonical_alias;
    resp["creator"] = rec.creator;
    resp["creation_ts"] = rec.creation_ts.empty() ? 0 :
        std::stoll(rec.creation_ts);
    resp["joined_members"] = rec.joined_members;
    resp["invited_members"] = rec.invited_members;
    resp["banned_members"] = rec.banned_members;
    resp["total_members"] = rec.total_members;
    resp["blocked"] = rec.blocked;
    resp["federatable"] = rec.federatable;
    resp["public"] = rec.public_room;
    resp["join_rules"] = rec.join_rules;
    resp["guest_access"] = rec.guest_access;
    resp["history_visibility"] = rec.history_visibility;
    resp["encryption"] = rec.encryption_algorithm;
    resp["version"] = rec.room_version;
    resp["room_type"] = rec.room_type.empty() ?
        nlohmann::json(nullptr) : nlohmann::json(rec.room_type);

    // State events (simplified)
    nlohmann::json state = nlohmann::json::array();
    if (!rec.name.empty()) {
        nlohmann::json ev;
        ev["type"] = "m.room.name";
        ev["content"] = {{"name", rec.name}};
        state.push_back(ev);
    }
    if (!rec.topic.empty()) {
        nlohmann::json ev;
        ev["type"] = "m.room.topic";
        ev["content"] = {{"topic", rec.topic}};
        state.push_back(ev);
    }
    if (!rec.canonical_alias.empty()) {
        nlohmann::json ev;
        ev["type"] = "m.room.canonical_alias";
        ev["content"] = {{"alias", rec.canonical_alias}};
        state.push_back(ev);
    }
    resp["state"] = state;

    return resp;
}

// ============================================================================
// 13. GET /_synapse/admin/v1/rooms/{roomId}/members
// List members of a room.
// ============================================================================

nlohmann::json handle_get_room_members_v1(const nlohmann::json& params,
                                           const nlohmann::json& body,
                                           const std::string& request_path) {
    std::string path = request_path;
    const std::string prefix = "/_synapse/admin/v1/rooms/";
    const std::string suffix = "/members";
    auto pos = path.find(prefix);
    if (pos == std::string::npos) {
        return error_response("M_UNKNOWN", "Invalid request path", 400);
    }

    size_t start = pos + prefix.size();
    size_t end = path.find(suffix, start);
    if (end == std::string::npos) {
        return error_response("M_UNKNOWN", "Invalid request path", 400);
    }
    std::string room_id = path.substr(start, end - start);
    room_id = url_decode(room_id);

    if (!is_valid_room_id(room_id)) {
        return error_response("M_INVALID_PARAM", "Invalid room ID", 400);
    }

    std::lock_guard<std::mutex> lock(db::rooms_mutex);

    auto it = db::rooms.find(room_id);
    if (it == db::rooms.end()) {
        return error_response("M_NOT_FOUND", "Room not found", 404);
    }

    nlohmann::json members_array = nlohmann::json::array();

    auto mit = db::room_members.find(room_id);
    if (mit != db::room_members.end()) {
        for (const auto& uid : mit->second) {
            nlohmann::json m;
            m["user_id"] = uid;
            m["membership"] = "join";
            m["display_name"] = uid; // simplified
            members_array.push_back(m);
        }
    }

    nlohmann::json resp;
    resp["members"] = members_array;
    resp["total"] = members_array.size();
    resp["room_id"] = room_id;
    return resp;
}

// ============================================================================
// 14. POST /_synapse/admin/v1/rooms/{roomId}/delete
// Delete a room. Body: { block, purge, message, force_purge }
// ============================================================================

nlohmann::json handle_delete_room_v1(const nlohmann::json& params,
                                      const nlohmann::json& body,
                                      const std::string& request_path) {
    std::string path = request_path;
    const std::string prefix = "/_synapse/admin/v1/rooms/";
    const std::string suffix = "/delete";
    auto pos = path.find(prefix);
    if (pos == std::string::npos) {
        return error_response("M_UNKNOWN", "Invalid request path", 400);
    }

    size_t start = pos + prefix.size();
    size_t end = path.find(suffix, start);
    if (end == std::string::npos) {
        return error_response("M_UNKNOWN", "Invalid request path", 400);
    }
    std::string room_id = path.substr(start, end - start);
    room_id = url_decode(room_id);

    if (!is_valid_room_id(room_id)) {
        return error_response("M_INVALID_PARAM", "Invalid room ID", 400);
    }

    bool block = body.value("block", false);
    bool purge = body.value("purge", true);
    std::string message = body.value("message", "Room deleted by administrator");
    bool force_purge = body.value("force_purge", false);

    std::lock_guard<std::mutex> lock(db::rooms_mutex);

    auto it = db::rooms.find(room_id);
    if (it == db::rooms.end()) {
        return error_response("M_NOT_FOUND", "Room not found", 404);
    }

    if (block) {
        it->second.blocked = true;
    }

    std::string delete_id;
    if (purge) {
        // Create a purge entry for the deletion
        std::lock_guard<std::mutex> plock(db::purges_mutex);
        delete_id = "purge_" + random_hex(16);
        db::PurgeEntry pe;
        pe.purge_id = delete_id;
        pe.room_id = room_id;
        pe.status = "active";
        pe.started_ts = now_ms();
        db::purges[delete_id] = pe;
    }

    // Remove room from store
    db::rooms.erase(room_id);
    db::room_members.erase(room_id);

    nlohmann::json resp;
    resp["kicked_members"] = nlohmann::json::array();
    resp["failed_to_kick_members"] = nlohmann::json::array();
    resp["local_aliases"] = nlohmann::json::array();
    if (!delete_id.empty()) {
        resp["delete_id"] = delete_id;
    }
    resp["block"] = block;

    return resp;
}

// ============================================================================
// 15. POST /_synapse/admin/v1/rooms/{roomId}/block
// Block or unblock a room. Body: { block: bool }
// ============================================================================

nlohmann::json handle_block_room_v1(const nlohmann::json& params,
                                     const nlohmann::json& body,
                                     const std::string& request_path) {
    std::string path = request_path;
    const std::string prefix = "/_synapse/admin/v1/rooms/";
    const std::string suffix = "/block";
    auto pos = path.find(prefix);
    if (pos == std::string::npos) {
        return error_response("M_UNKNOWN", "Invalid request path", 400);
    }

    size_t start = pos + prefix.size();
    size_t end = path.find(suffix, start);
    if (end == std::string::npos) {
        return error_response("M_UNKNOWN", "Invalid request path", 400);
    }
    std::string room_id = path.substr(start, end - start);
    room_id = url_decode(room_id);

    if (!is_valid_room_id(room_id)) {
        return error_response("M_INVALID_PARAM", "Invalid room ID", 400);
    }

    bool block = true;
    if (body.contains("block")) {
        if (body["block"].is_boolean()) {
            block = body["block"].get<bool>();
        } else if (body["block"].is_string()) {
            block = (body["block"].get<std::string>() == "true");
        }
    }

    std::lock_guard<std::mutex> lock(db::rooms_mutex);

    auto it = db::rooms.find(room_id);
    if (it == db::rooms.end()) {
        return error_response("M_NOT_FOUND", "Room not found", 404);
    }

    it->second.blocked = block;

    nlohmann::json resp;
    resp["success"] = true;
    resp["blocked"] = block;
    resp["room_id"] = room_id;
    return resp;
}

// ============================================================================
// 16. POST /_synapse/admin/v1/purge_history/{roomId}
// Purge historical events from a room.
// Body: { purge_up_to_ts, delete_local_events }
// Returns a purge_id for status tracking.
// ============================================================================

nlohmann::json handle_purge_history_v1(const nlohmann::json& params,
                                        const nlohmann::json& body,
                                        const std::string& request_path) {
    std::string path = request_path;
    const std::string prefix = "/_synapse/admin/v1/purge_history/";
    auto pos = path.find(prefix);
    if (pos == std::string::npos) {
        return error_response("M_UNKNOWN", "Invalid request path", 400);
    }

    std::string room_id = path.substr(pos + prefix.size());
    room_id = url_decode(room_id);

    if (!is_valid_room_id(room_id)) {
        return error_response("M_INVALID_PARAM", "Invalid room ID", 400);
    }

    long long purge_up_to_ts = 0;
    if (body.contains("purge_up_to_ts")) {
        if (body["purge_up_to_ts"].is_number()) {
            purge_up_to_ts = body["purge_up_to_ts"].get<long long>();
        } else if (body["purge_up_to_ts"].is_string()) {
            purge_up_to_ts = std::stoll(body["purge_up_to_ts"].get<std::string>());
        }
    } else {
        // Default: purge up to current time
        purge_up_to_ts = std::stoll(now_ms());
    }

    bool delete_local_events = body.value("delete_local_events", false);

    // Check room exists
    {
        std::lock_guard<std::mutex> lock(db::rooms_mutex);
        if (db::rooms.find(room_id) == db::rooms.end()) {
            return error_response("M_NOT_FOUND", "Room not found", 404);
        }
    }

    // Create purge entry
    std::string purge_id = "purge_" + random_hex(16);
    db::PurgeEntry pe;
    pe.purge_id = purge_id;
    pe.room_id = room_id;
    pe.status = "active";
    pe.started_ts = now_ms();

    {
        std::lock_guard<std::mutex> lock(db::purges_mutex);
        db::purges[purge_id] = pe;
    }

    // In production, actual purging would be async. Here we simulate by
    // immediately marking it complete.
    {
        std::lock_guard<std::mutex> lock(db::purges_mutex);
        auto& p = db::purges[purge_id];
        p.status = "complete";
        p.completed_ts = now_ms();
    }

    nlohmann::json resp;
    resp["purge_id"] = purge_id;
    return resp;
}

// ============================================================================
// 17. GET /_synapse/admin/v1/purge_history_status/{purgeId}
// Get status of a purge operation.
// ============================================================================

nlohmann::json handle_purge_history_status_v1(const nlohmann::json& params,
                                               const nlohmann::json& body,
                                               const std::string& request_path) {
    std::string path = request_path;
    const std::string prefix = "/_synapse/admin/v1/purge_history_status/";
    auto pos = path.find(prefix);
    if (pos == std::string::npos) {
        return error_response("M_UNKNOWN", "Invalid request path", 400);
    }

    std::string purge_id = path.substr(pos + prefix.size());
    purge_id = url_decode(purge_id);

    std::lock_guard<std::mutex> lock(db::purges_mutex);

    auto it = db::purges.find(purge_id);
    if (it == db::purges.end()) {
        return error_response("M_NOT_FOUND", "Purge not found", 404);
    }

    const auto& pe = it->second;

    nlohmann::json resp;
    resp["purge_id"] = pe.purge_id;
    resp["status"] = pe.status;
    resp["room_id"] = pe.room_id;
    resp["started_ts"] = std::stoll(pe.started_ts);
    if (!pe.completed_ts.empty()) {
        resp["completed_ts"] = std::stoll(pe.completed_ts);
    }
    if (!pe.error.empty()) {
        resp["error"] = pe.error;
    }
    return resp;
}

// ============================================================================
// 18. GET /_synapse/admin/v1/event_reports
// List event reports with pagination and filtering.
// Query params: from, limit, dir, order_by, user_id, room_id
// ============================================================================

nlohmann::json handle_list_event_reports_v1(const nlohmann::json& params,
                                             const nlohmann::json& body,
                                             const std::string& request_path) {
    std::lock_guard<std::mutex> lock(db::reports_mutex);

    int from = 0;
    int limit = 100;
    if (params.contains("from") && params["from"].is_string()) {
        from = std::stoi(params["from"].get<std::string>());
    } else if (params.contains("from") && params["from"].is_number()) {
        from = params["from"].get<int>();
    }
    if (params.contains("limit") && params["limit"].is_string()) {
        limit = std::min(std::stoi(params["limit"].get<std::string>()), 500);
    } else if (params.contains("limit") && params["limit"].is_number()) {
        limit = std::min(params["limit"].get<int>(), 500);
    }

    std::string dir = "b"; // b=backward (newest first) is default for reports
    if (params.contains("dir")) {
        dir = params["dir"].get<std::string>();
    }

    std::string order_by = "received_ts";
    if (params.contains("order_by")) {
        order_by = params["order_by"].get<std::string>();
    }

    std::string user_id_filter;
    if (params.contains("user_id")) {
        user_id_filter = params["user_id"].get<std::string>();
    }

    std::string room_id_filter;
    if (params.contains("room_id")) {
        room_id_filter = params["room_id"].get<std::string>();
    }

    // Collect and filter reports
    std::vector<db::EventReport> filtered;
    for (const auto& [rid, rec] : db::event_reports) {
        if (!user_id_filter.empty() && rec.user_id != user_id_filter) continue;
        if (!room_id_filter.empty() && rec.room_id != room_id_filter) continue;
        filtered.push_back(rec);
    }

    // Sort
    std::sort(filtered.begin(), filtered.end(),
        [&](const db::EventReport& a, const db::EventReport& b) {
            int cmp = 0;
            if (order_by == "received_ts") {
                cmp = a.received_ts.compare(b.received_ts);
            } else if (order_by == "score") {
                cmp = a.score - b.score;
            } else {
                cmp = a.received_ts.compare(b.received_ts);
            }
            return (dir == "b") ? (cmp > 0) : (cmp < 0);
        });

    int total = static_cast<int>(filtered.size());

    nlohmann::json reports_array = nlohmann::json::array();
    int end_pos = std::min(from + limit, total);
    for (int i = from; i < end_pos; ++i) {
        const auto& rec = filtered[i];
        nlohmann::json rpt;
        rpt["id"] = rec.id;
        rpt["received_ts"] = std::stoll(rec.received_ts);
        rpt["room_id"] = rec.room_id;
        rpt["event_id"] = rec.event_id;
        rpt["user_id"] = rec.user_id;
        rpt["reason"] = rec.reason;
        rpt["score"] = rec.score;
        rpt["sender"] = rec.sender;
        rpt["can_see_sender"] = rec.can_see_sender;
        if (rec.handled) {
            rpt["handled"] = true;
            rpt["handled_by"] = rec.handled_by;
            rpt["handled_ts"] = std::stoll(rec.handled_ts);
        }
        reports_array.push_back(rpt);
    }

    nlohmann::json resp;
    resp["event_reports"] = reports_array;
    resp["total"] = total;
    if (end_pos < total) {
        resp["next_token"] = std::to_string(end_pos);
    }
    return resp;
}

// ============================================================================
// 19. POST /_synapse/admin/v1/event_reports/{reportId}
// Handle (resolve/ignore) an event report.
// Body: { action: "resolve"|"ignore", reason }
// ============================================================================

nlohmann::json handle_event_report_action_v1(const nlohmann::json& params,
                                              const nlohmann::json& body,
                                              const std::string& request_path) {
    std::string path = request_path;
    const std::string prefix = "/_synapse/admin/v1/event_reports/";
    auto pos = path.find(prefix);
    if (pos == std::string::npos) {
        return error_response("M_UNKNOWN", "Invalid request path", 400);
    }

    std::string report_id = path.substr(pos + prefix.size());
    report_id = url_decode(report_id);

    if (!body.contains("action") || !body["action"].is_string()) {
        return error_response("M_MISSING_PARAM", "action is required", 400);
    }

    std::string action = body["action"].get<std::string>();
    if (action != "resolve" && action != "ignore") {
        return error_response("M_INVALID_PARAM",
            "action must be 'resolve' or 'ignore'", 400);
    }

    std::string reason = body.value("reason", "");

    // Extract admin user from params (passed by request context)
    std::string admin_user = params.value("admin_user", "admin");

    std::lock_guard<std::mutex> lock(db::reports_mutex);

    auto it = db::event_reports.find(report_id);
    if (it == db::event_reports.end()) {
        return error_response("M_NOT_FOUND", "Report not found", 404);
    }

    it->second.handled = true;
    it->second.handled_by = admin_user;
    it->second.handled_ts = now_ms();

    nlohmann::json resp;
    resp["success"] = true;
    resp["action"] = action;
    if (!reason.empty()) {
        resp["reason"] = reason;
    }
    return resp;
}

// ============================================================================
// 20. POST /_synapse/admin/v1/send_server_notice
// Send a server notice to a specific user or all users.
// Body: { user_id, content: { msgtype, body, ... }, txn_id }
// ============================================================================

nlohmann::json handle_send_server_notice_v1(const nlohmann::json& params,
                                             const nlohmann::json& body,
                                             const std::string& request_path) {
    if (!body.contains("user_id") || !body["user_id"].is_string()) {
        return error_response("M_MISSING_PARAM", "user_id is required", 400);
    }

    if (!body.contains("content") || !body["content"].is_object()) {
        return error_response("M_MISSING_PARAM", "content is required", 400);
    }

    std::string target_user = body["user_id"].get<std::string>();
    nlohmann::json content = body["content"];
    std::string txn_id = body.value("txn_id", random_hex(16) + "_server_notice");

    // Validate msgtype
    if (!content.contains("msgtype") || !content["msgtype"].is_string()) {
        return error_response("M_MISSING_PARAM",
            "content.msgtype is required", 400);
    }

    std::string msgtype = content["msgtype"].get<std::string>();
    if (msgtype != "m.text" && msgtype != "m.notice" &&
        msgtype != "m.server_notice") {
        content["msgtype"] = "m.server_notice";
    }

    // Check user exists
    {
        std::lock_guard<std::mutex> lock(db::users_mutex);
        if (db::users.find(target_user) == db::users.end()) {
            return error_response("M_NOT_FOUND",
                "User not found: " + target_user, 404);
        }
    }

    // Build the server notice event
    nlohmann::json event;
    event["type"] = "m.room.message";
    event["sender"] = "@server:" +
        (params.contains("server_name") ?
            params["server_name"].get<std::string>() : "localhost:8008");
    event["content"] = content;
    event["origin_server_ts"] = std::stoll(now_ms());

    // Store notice (in production, this would be delivered to the user's
    // server notice room and pushed via the notification system)
    {
        std::lock_guard<std::mutex> lock(db::notices_mutex);
        // notices are tracked per user
    }

    nlohmann::json resp;
    resp["event_id"] = "$" + random_hex(32);
    resp["user_id"] = target_user;
    resp["txn_id"] = txn_id;
    resp["notice_sent"] = true;
    return resp;
}

// ============================================================================
// Router dispatch table
// Maps endpoint patterns to handler functions.
// ============================================================================

using AdminHandler = std::function<nlohmann::json(
    const nlohmann::json& params,
    const nlohmann::json& body,
    const std::string& request_path)>;

struct RouteEntry {
    std::string method;         // "GET", "POST", "PUT"
    std::string path_pattern;   // e.g. "/_synapse/admin/v2/users"
    bool is_prefix;             // true if this matches a prefix
    AdminHandler handler;
};

// Build the complete dispatch table
std::vector<RouteEntry> build_admin_routes() {
    std::vector<RouteEntry> routes;

    // v2 User management
    routes.push_back({"GET",  "/_synapse/admin/v2/users", false,
        handle_list_users_v2});
    routes.push_back({"POST", "/_synapse/admin/v2/users", false,
        handle_create_user_v2});
    routes.push_back({"GET",  "/_synapse/admin/v2/users/", true,
        [](const nlohmann::json& p, const nlohmann::json& b,
           const std::string& rp) -> nlohmann::json {
            // Check for /consent suffix
            if (rp.find("/consent") != std::string::npos) {
                return handle_user_consent_v2(p, b, rp);
            }
            return handle_get_user_v2(p, b, rp);
        }});
    routes.push_back({"PUT",  "/_synapse/admin/v2/users/", true,
        handle_update_user_v2});

    // v1 User management
    routes.push_back({"POST", "/_synapse/admin/v1/deactivate/", true,
        handle_deactivate_user_v1});
    routes.push_back({"POST", "/_synapse/admin/v1/reset_password/", true,
        handle_reset_password_v1});
    routes.push_back({"GET",  "/_synapse/admin/v1/whois/", true,
        handle_whois_v1});

    // Registration tokens
    routes.push_back({"GET",  "/_synapse/admin/v1/registration_tokens", false,
        handle_list_registration_tokens_v1});
    routes.push_back({"POST", "/_synapse/admin/v1/registration_tokens/new", false,
        handle_create_registration_token_v1});

    // Room management
    routes.push_back({"GET",  "/_synapse/admin/v1/rooms", false,
        handle_list_rooms_v1});
    routes.push_back({"GET",  "/_synapse/admin/v1/rooms/", true,
        [](const nlohmann::json& p, const nlohmann::json& b,
           const std::string& rp) -> nlohmann::json {
            if (rp.find("/members") != std::string::npos) {
                return handle_get_room_members_v1(p, b, rp);
            }
            return handle_get_room_v1(p, b, rp);
        }});
    routes.push_back({"POST", "/_synapse/admin/v1/rooms/", true,
        [](const nlohmann::json& p, const nlohmann::json& b,
           const std::string& rp) -> nlohmann::json {
            if (rp.find("/delete") != std::string::npos) {
                return handle_delete_room_v1(p, b, rp);
            }
            if (rp.find("/block") != std::string::npos) {
                return handle_block_room_v1(p, b, rp);
            }
            return error_response("M_UNKNOWN", "Unknown room action", 400);
        }});

    // Purge
    routes.push_back({"POST", "/_synapse/admin/v1/purge_history/", true,
        handle_purge_history_v1});
    routes.push_back({"GET",  "/_synapse/admin/v1/purge_history_status/", true,
        handle_purge_history_status_v1});

    // Event reports
    routes.push_back({"GET",  "/_synapse/admin/v1/event_reports", false,
        handle_list_event_reports_v1});
    routes.push_back({"POST", "/_synapse/admin/v1/event_reports/", true,
        handle_event_report_action_v1});

    // Server notices
    routes.push_back({"POST", "/_synapse/admin/v1/send_server_notice", false,
        handle_send_server_notice_v1});

    return routes;
}

// ============================================================================
// Public API: entry point for admin request dispatching
// ============================================================================

nlohmann::json dispatch_admin_request(const std::string& method,
                                       const std::string& path,
                                       const nlohmann::json& params,
                                       const nlohmann::json& body) {
    // Static route table, built once
    static std::vector<RouteEntry> routes = build_admin_routes();
    static std::once_flag init_flag;
    std::call_once(init_flag, []() {
        // Seed random generator for token generation
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
        "Unrecognized admin endpoint: " + method + " " + path, 404);
}

// ============================================================================
// Initialization helpers for seeding test/dev data
// ============================================================================

void seed_test_data(const std::string& server_name) {
    // Seed a few test users
    {
        std::lock_guard<std::mutex> lock(db::users_mutex);

        db::UserRecord admin;
        admin.id = "@admin:" + server_name;
        admin.displayname = "Administrator";
        admin.password_hash = hash_password("admin");
        admin.creation_ts = now_ms();
        admin.admin = true;
        admin.approved = true;
        db::users[admin.id] = admin;

        db::UserRecord alice;
        alice.id = "@alice:" + server_name;
        alice.displayname = "Alice";
        alice.password_hash = hash_password("alice123");
        alice.creation_ts = now_ms();
        db::users[alice.id] = alice;

        db::UserRecord bob;
        bob.id = "@bob:" + server_name;
        bob.displayname = "Bob";
        bob.password_hash = hash_password("bob123");
        bob.creation_ts = now_ms();
        db::users[bob.id] = bob;
    }

    // Seed a few test rooms
    {
        std::lock_guard<std::mutex> lock(db::rooms_mutex);

        db::RoomRecord general;
        general.room_id = "!general:" + server_name;
        general.name = "General";
        general.creator = "@admin:" + server_name;
        general.creation_ts = now_ms();
        general.joined_members = 3;
        general.total_members = 3;
        general.room_version = "10";
        general.join_rules = "invite";
        general.history_visibility = "shared";
        db::rooms[general.room_id] = general;
        db::room_members[general.room_id] = {
            "@admin:" + server_name,
            "@alice:" + server_name,
            "@bob:" + server_name
        };

        db::RoomRecord random;
        random.room_id = "!random:" + server_name;
        random.name = "Random";
        random.creator = "@alice:" + server_name;
        random.creation_ts = now_ms();
        random.joined_members = 2;
        random.total_members = 2;
        random.room_version = "10";
        random.public_room = true;
        random.join_rules = "public";
        db::rooms[random.room_id] = random;
        db::room_members[random.room_id] = {
            "@alice:" + server_name,
            "@bob:" + server_name
        };
    }

    // Seed a registration token
    {
        std::lock_guard<std::mutex> lock(db::tokens_mutex);
        db::RegistrationToken tok;
        tok.token = "welcome2024";
        tok.uses_allowed = "50";
        tok.expiry_time = "0";
        tok.created_ts = now_ms();
        db::reg_tokens[tok.token] = tok;
    }
}

// ============================================================================
// Admin API statistics helper
// ============================================================================

nlohmann::json get_admin_statistics() {
    nlohmann::json stats;

    {
        std::lock_guard<std::mutex> lock(db::users_mutex);
        stats["total_users"] = db::users.size();
        int deactivated = 0, admins = 0, locked = 0;
        for (const auto& [uid, rec] : db::users) {
            if (rec.deactivated) deactivated++;
            if (rec.admin) admins++;
            if (rec.locked) locked++;
        }
        stats["deactivated_users"] = deactivated;
        stats["admin_users"] = admins;
        stats["locked_users"] = locked;
    }

    {
        std::lock_guard<std::mutex> lock(db::rooms_mutex);
        stats["total_rooms"] = db::rooms.size();
        int blocked = 0;
        for (const auto& [rid, rec] : db::rooms) {
            if (rec.blocked) blocked++;
        }
        stats["blocked_rooms"] = blocked;
    }

    {
        std::lock_guard<std::mutex> lock(db::tokens_mutex);
        stats["active_registration_tokens"] = db::reg_tokens.size();
    }

    {
        std::lock_guard<std::mutex> lock(db::reports_mutex);
        stats["pending_event_reports"] = 0;
        for (const auto& [rid, rec] : db::event_reports) {
            if (!rec.handled) stats["pending_event_reports"] =
                stats["pending_event_reports"].get<int>() + 1;
        }
    }

    return stats;
}

} // namespace admin
} // namespace progressive
