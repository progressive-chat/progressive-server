// admin_room_directory.cpp - Matrix Admin Room Directory & Visibility Management
// Progressive Server - Admin Room Operations
// Handles all Synapse-compatible admin endpoints for room directory,
// room aliases, room visibility, public room listing, room state/member
// dumps, timeline exports, force join/leave, and room statistics.
//
// Namespace: progressive::admin

#include "../json.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <fstream>
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
// Forward declarations — database structures from admin_users_v2.cpp
// ============================================================================

namespace db {

    // --- Mutex declarations (extern — defined in admin_users_v2.cpp) ---
    extern std::mutex users_mutex;
    extern std::mutex rooms_mutex;
    extern std::mutex tokens_mutex;
    extern std::mutex reports_mutex;
    extern std::mutex purges_mutex;
    extern std::mutex notices_mutex;

    // --- User record (mirror of admin_users_v2.cpp) ---
    struct UserRecord {
        std::string id;
        std::string displayname;
        std::string avatar_url;
        std::string password_hash;
        std::string email;
        bool admin = false;
        bool deactivated = false;
        bool locked = false;
        std::string creation_ts;
        std::string consent_version;
        std::string consent_ts;
        bool consent_given = false;
        std::string user_type;
        bool is_guest = false;
        bool approved = true;
        bool erased = false;
        std::string external_ids;
        std::string threepids;
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

    // --- Alias record ---
    struct AliasRecord {
        std::string alias;           // e.g. #general:localhost
        std::string room_id;
        std::string creator;
        std::string creation_ts;
        bool is_published = false;   // visible in public room directory
    };

    // --- Room state event ---
    struct StateEvent {
        std::string event_type;
        std::string state_key;
        std::string sender;
        std::string origin_server_ts;
        nlohmann::json content;
        nlohmann::json unsigned_data;
        std::string event_id;
        std::string prev_content_json;
    };

    // --- Room timeline event ---
    struct TimelineEvent {
        std::string event_id;
        std::string room_id;
        std::string sender;
        std::string event_type;
        std::string origin_server_ts;
        nlohmann::json content;
        std::string state_key;       // non-empty if state event
        int depth = 0;
        std::string prev_event_id;
    };

    // --- Room visibility settings ---
    struct RoomVisibilitySettings {
        std::string room_id;
        std::string visibility;      // "public", "private"
        bool is_published = false;
        std::string published_alias;
        std::string avatar_url;
        std::string topic;
        int joined_members = 0;
    };

    // --- Room join/leave log entry ---
    struct MembershipLogEntry {
        std::string room_id;
        std::string user_id;
        std::string membership;      // "join", "leave", "invite", "ban"
        std::string timestamp;
        std::string reason;
        std::string performed_by;     // admin user_id (for force operations)
    };

    // --- In-memory stores (extern — defined in admin_users_v2.cpp) ---
    extern std::unordered_map<std::string, UserRecord> users;
    extern std::unordered_map<std::string, RoomRecord> rooms;
    extern std::unordered_map<std::string, RegistrationToken> reg_tokens;
    extern std::unordered_map<std::string, EventReport> event_reports;
    extern std::unordered_map<std::string, PurgeEntry> purges;
    extern std::unordered_map<std::string, std::vector<std::string>> room_members;
}

// ============================================================================
// Local in-memory stores for room directory / alias / visibility data
// ============================================================================

namespace {

    // Protect local stores
    std::mutex g_aliases_mutex;
    std::mutex g_state_mutex;
    std::mutex g_timeline_mutex;
    std::mutex g_visibility_mutex;
    std::mutex g_membership_log_mutex;
    std::mutex g_room_stats_cache_mutex;

    // Room aliases: alias string -> AliasRecord
    std::unordered_map<std::string, db::AliasRecord> g_aliases;

    // Room state events: room_id -> vector of state events
    std::unordered_map<std::string, std::vector<db::StateEvent>> g_room_state;

    // Room timeline events: room_id -> vector of timeline events (sorted by depth)
    std::unordered_map<std::string, std::vector<db::TimelineEvent>> g_room_timeline;

    // Visibility settings per room
    std::unordered_map<std::string, db::RoomVisibilitySettings> g_visibility;

    // Membership change log
    std::vector<db::MembershipLogEntry> g_membership_log;

    // Room statistics cache
    std::unordered_map<std::string, nlohmann::json> g_room_stats_cache;
    std::atomic<int64_t> g_stats_cache_age_ms{0};

} // anonymous namespace

// ============================================================================
// Utility helpers (local to this module)
// ============================================================================

namespace {

    // -----------------------------------------------------------------------
    // Timestamp helpers
    // -----------------------------------------------------------------------

    std::string now_ms() {
        auto now = std::chrono::system_clock::now();
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()).count();
        return std::to_string(ms);
    }

    std::string iso8601_now() {
        auto now = std::chrono::system_clock::now();
        auto tt = std::chrono::system_clock::to_time_t(now);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()).count() % 1000;
        std::stringstream ss;
        ss << std::put_time(std::gmtime(&tt), "%Y-%m-%dT%H:%M:%S");
        ss << "." << std::setfill('0') << std::setw(3) << ms << "Z";
        return ss.str();
    }

    std::string iso8601_from_epoch(long long epoch_ms) {
        time_t sec = static_cast<time_t>(epoch_ms / 1000);
        int ms = static_cast<int>(epoch_ms % 1000);
        std::stringstream ss;
        ss << std::put_time(std::gmtime(&sec), "%Y-%m-%dT%H:%M:%S");
        ss << "." << std::setfill('0') << std::setw(3) << ms << "Z";
        return ss.str();
    }

    // -----------------------------------------------------------------------
    // Random generation
    // -----------------------------------------------------------------------

    std::string random_hex(int length) {
        static thread_local std::mt19937 rng(std::random_device{}());
        static const char hex[] = "0123456789abcdef";
        std::uniform_int_distribution<int> dist(0, 15);
        std::string out(length, '\0');
        for (int i = 0; i < length; ++i) out[i] = hex[dist(rng)];
        return out;
    }

    std::string random_alphanumeric(int length) {
        static thread_local std::mt19937 rng(std::random_device{}());
        static const char chars[] =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        std::uniform_int_distribution<int> dist(0, 61);
        std::string out(length, '\0');
        for (int i = 0; i < length; ++i) out[i] = chars[dist(rng)];
        return out;
    }

    std::string generate_event_id() {
        return "$" + random_hex(32);
    }

    // -----------------------------------------------------------------------
    // Validation helpers
    // -----------------------------------------------------------------------

    bool is_valid_room_id(const std::string& rid) {
        static std::regex re(R"(^![a-zA-Z0-9]+:.+$)");
        return std::regex_match(rid, re);
    }

    bool is_valid_user_id(const std::string& uid) {
        static std::regex re(R"(^@[a-zA-Z0-9._=\\-/]+:.+$)");
        return std::regex_match(uid, re);
    }

    bool is_valid_alias(const std::string& alias) {
        static std::regex re(R"(^#[a-zA-Z0-9._=\\-/]+:.+$)");
        return std::regex_match(alias, re);
    }

    bool is_valid_alias_localpart(const std::string& localpart) {
        static std::regex re(R"(^[a-zA-Z0-9._=\\-/]+$)");
        return std::regex_match(localpart, re);
    }

    // -----------------------------------------------------------------------
    // URL decode
    // -----------------------------------------------------------------------

    std::string url_decode(const std::string& src) {
        std::string result;
        result.reserve(src.size());
        for (size_t i = 0; i < src.size(); ++i) {
            if (src[i] == '%' && i + 2 < src.size() &&
                std::isxdigit(static_cast<unsigned char>(src[i + 1])) &&
                std::isxdigit(static_cast<unsigned char>(src[i + 2]))) {
                int val;
                std::stringstream ss;
                ss << std::hex << src.substr(i + 1, 2);
                ss >> val;
                result.push_back(static_cast<char>(val));
                i += 2;
            } else if (src[i] == '+') {
                result.push_back(' ');
            } else {
                result.push_back(src[i]);
            }
        }
        return result;
    }

    // -----------------------------------------------------------------------
    // String helpers
    // -----------------------------------------------------------------------

    std::string to_lower(const std::string& s) {
        std::string out = s;
        std::transform(out.begin(), out.end(), out.begin(),
            [](unsigned char c) { return std::tolower(c); });
        return out;
    }

    bool matches_filter(const std::string& target, const std::string& filter) {
        if (filter.empty()) return true;
        return to_lower(target).find(to_lower(filter)) != std::string::npos;
    }

    bool starts_with(const std::string& s, const std::string& prefix) {
        return s.size() >= prefix.size() &&
               s.compare(0, prefix.size(), prefix) == 0;
    }

    bool ends_with(const std::string& s, const std::string& suffix) {
        return s.size() >= suffix.size() &&
               s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
    }

    std::string extract_server_name(const std::string& room_or_user_id) {
        auto pos = room_or_user_id.find(':');
        if (pos != std::string::npos) return room_or_user_id.substr(pos + 1);
        return "localhost";
    }

    // -----------------------------------------------------------------------
    // JSON helpers
    // -----------------------------------------------------------------------

    nlohmann::json error_response(const std::string& errcode,
                                   const std::string& error,
                                   int http_status = 400) {
        return {
            {"errcode", errcode},
            {"error", error},
            {"http_status", http_status}
        };
    }

    nlohmann::json success_response(const std::string& msg = "Success") {
        return {{"success", true}, {"message", msg}};
    }

    // -----------------------------------------------------------------------
    // Extract room_id from URL path of the form /_synapse/admin/v1/rooms/{id}
    // or /_synapse/admin/v1/rooms/{id}/{action}
    // -----------------------------------------------------------------------

    std::string extract_room_id_from_path(const std::string& path,
                                           const std::string& prefix) {
        auto pos = path.find(prefix);
        if (pos == std::string::npos) return "";
        std::string suffix = path.substr(pos + prefix.size());
        // Strip query string
        auto qpos = suffix.find('?');
        if (qpos != std::string::npos) suffix = suffix.substr(0, qpos);
        // Strip trailing slash
        if (!suffix.empty() && suffix.back() == '/')
            suffix.pop_back();
        // If there's another slash, extract just the room_id portion
        auto slash = suffix.find('/');
        if (slash != std::string::npos)
            suffix = suffix.substr(0, slash);
        return url_decode(suffix);
    }

    // -----------------------------------------------------------------------
    // Query parameter parsing from nlohmann::json params object
    // -----------------------------------------------------------------------

    int query_int(const nlohmann::json& params, const std::string& key,
                  int default_val = 0) {
        if (!params.contains(key)) return default_val;
        if (params[key].is_number()) return params[key].get<int>();
        if (params[key].is_string()) {
            try { return std::stoi(params[key].get<std::string>()); }
            catch (...) { return default_val; }
        }
        return default_val;
    }

    std::string query_str(const nlohmann::json& params, const std::string& key,
                           const std::string& default_val = "") {
        if (!params.contains(key)) return default_val;
        if (params[key].is_string()) return params[key].get<std::string>();
        return default_val;
    }

    bool query_bool(const nlohmann::json& params, const std::string& key,
                    bool default_val = false) {
        if (!params.contains(key)) return default_val;
        if (params[key].is_boolean()) return params[key].get<bool>();
        if (params[key].is_string()) {
            auto s = params[key].get<std::string>();
            return s == "true" || s == "1" || s == "yes";
        }
        return default_val;
    }

} // anonymous namespace

// ============================================================================
// Initialization helpers — seed demo data for testing
// ============================================================================

namespace {

    std::once_flag g_init_flag;

    void init_demo_data(const std::string& server_name) {
        std::call_once(g_init_flag, [&server_name]() {
            // Seed room aliases
            {
                std::lock_guard<std::mutex> lock(g_aliases_mutex);

                db::AliasRecord a1;
                a1.alias = "#general:" + server_name;
                a1.room_id = "!general:" + server_name;
                a1.creator = "@admin:" + server_name;
                a1.creation_ts = now_ms();
                a1.is_published = true;
                g_aliases[a1.alias] = a1;

                db::AliasRecord a2;
                a2.alias = "#random:" + server_name;
                a2.room_id = "!random:" + server_name;
                a2.creator = "@alice:" + server_name;
                a2.creation_ts = now_ms();
                a2.is_published = true;
                g_aliases[a2.alias] = a2;

                db::AliasRecord a3;
                a3.alias = "#private-staff:" + server_name;
                a3.room_id = "!staff:" + server_name;
                a3.creator = "@admin:" + server_name;
                a3.creation_ts = now_ms();
                a3.is_published = false;
                g_aliases[a3.alias] = a3;

                db::AliasRecord a4;
                a4.alias = "#announcements:" + server_name;
                a4.room_id = "!announcements:" + server_name;
                a4.creator = "@admin:" + server_name;
                a4.creation_ts = now_ms();
                a4.is_published = true;
                g_aliases[a4.alias] = a4;

                db::AliasRecord a5;
                a5.alias = "#dev:" + server_name;
                a5.room_id = "!devchat:" + server_name;
                a5.creator = "@alice:" + server_name;
                a5.creation_ts = now_ms();
                a5.is_published = false;
                g_aliases[a5.alias] = a5;
            }

            // Seed visibility settings
            {
                std::lock_guard<std::mutex> lock(g_visibility_mutex);

                db::RoomVisibilitySettings vs;
                vs.room_id = "!general:" + server_name;
                vs.visibility = "public";
                vs.is_published = true;
                vs.published_alias = "#general:" + server_name;
                vs.topic = "General discussion room";
                vs.joined_members = 3;
                g_visibility[vs.room_id] = vs;

                vs.room_id = "!random:" + server_name;
                vs.visibility = "public";
                vs.is_published = true;
                vs.published_alias = "#random:" + server_name;
                vs.topic = "Random off-topic chat";
                vs.joined_members = 2;
                g_visibility[vs.room_id] = vs;

                vs.room_id = "!staff:" + server_name;
                vs.visibility = "private";
                vs.is_published = false;
                vs.published_alias = "";
                vs.topic = "Staff internal discussions";
                vs.joined_members = 1;
                g_visibility[vs.room_id] = vs;

                vs.room_id = "!announcements:" + server_name;
                vs.visibility = "public";
                vs.is_published = true;
                vs.published_alias = "#announcements:" + server_name;
                vs.topic = "Official server announcements";
                vs.joined_members = 1;
                g_visibility[vs.room_id] = vs;

                vs.room_id = "!devchat:" + server_name;
                vs.visibility = "private";
                vs.is_published = false;
                vs.published_alias = "";
                vs.topic = "Developer chat";
                vs.joined_members = 2;
                g_visibility[vs.room_id] = vs;
            }

            // Seed room state for demo rooms
            {
                std::lock_guard<std::mutex> lock(g_state_mutex);

                auto add_state = [&](const std::string& room_id,
                                      const std::string& type,
                                      const std::string& state_key,
                                      const std::string& sender,
                                      nlohmann::json content) {
                    db::StateEvent se;
                    se.event_type = type;
                    se.state_key = state_key;
                    se.sender = sender;
                    se.origin_server_ts = now_ms();
                    se.content = content;
                    se.event_id = generate_event_id();
                    g_room_state[room_id].push_back(se);
                };

                // General room state
                add_state("!general:" + server_name, "m.room.create", "",
                    "@admin:" + server_name, {{"creator", "@admin:" + server_name}});
                add_state("!general:" + server_name, "m.room.name", "",
                    "@admin:" + server_name, {{"name", "General"}});
                add_state("!general:" + server_name, "m.room.topic", "",
                    "@admin:" + server_name, {{"topic", "General discussion room"}});
                add_state("!general:" + server_name, "m.room.join_rules", "",
                    "@admin:" + server_name, {{"join_rule", "invite"}});
                add_state("!general:" + server_name, "m.room.history_visibility", "",
                    "@admin:" + server_name, {{"history_visibility", "shared"}});
                add_state("!general:" + server_name, "m.room.power_levels", "",
                    "@admin:" + server_name, {
                        {"users", {{"@admin:" + server_name, 100}}},
                        {"users_default", 0},
                        {"events_default", 0},
                        {"state_default", 50}
                    });

                // Random room state
                add_state("!random:" + server_name, "m.room.create", "",
                    "@alice:" + server_name, {{"creator", "@alice:" + server_name}});
                add_state("!random:" + server_name, "m.room.name", "",
                    "@alice:" + server_name, {{"name", "Random"}});
                add_state("!random:" + server_name, "m.room.join_rules", "",
                    "@alice:" + server_name, {{"join_rule", "public"}});

                // Staff room state
                add_state("!staff:" + server_name, "m.room.create", "",
                    "@admin:" + server_name, {{"creator", "@admin:" + server_name}});
                add_state("!staff:" + server_name, "m.room.name", "",
                    "@admin:" + server_name, {{"name", "Staff Room"}});
                add_state("!staff:" + server_name, "m.room.join_rules", "",
                    "@admin:" + server_name, {{"join_rule", "invite"}});

                // Announcements room state
                add_state("!announcements:" + server_name, "m.room.create", "",
                    "@admin:" + server_name, {{"creator", "@admin:" + server_name}});
                add_state("!announcements:" + server_name, "m.room.name", "",
                    "@admin:" + server_name, {{"name", "Announcements"}});
                add_state("!announcements:" + server_name, "m.room.join_rules", "",
                    "@admin:" + server_name, {{"join_rule", "public"}});

                // Devchat room state
                add_state("!devchat:" + server_name, "m.room.create", "",
                    "@alice:" + server_name, {{"creator", "@alice:" + server_name}});
                add_state("!devchat:" + server_name, "m.room.name", "",
                    "@alice:" + server_name, {{"name", "Dev Chat"}});
                add_state("!devchat:" + server_name, "m.room.topic", "",
                    "@alice:" + server_name, {{"topic", "Developer chat"}});
                add_state("!devchat:" + server_name, "m.room.join_rules", "",
                    "@alice:" + server_name, {{"join_rule", "invite"}});
            }

            // Seed timeline events
            {
                std::lock_guard<std::mutex> lock(g_timeline_mutex);

                auto add_event = [&](const std::string& room_id,
                                      const std::string& sender,
                                      const std::string& type,
                                      nlohmann::json content,
                                      int depth) {
                    db::TimelineEvent te;
                    te.event_id = generate_event_id();
                    te.room_id = room_id;
                    te.sender = sender;
                    te.event_type = type;
                    te.origin_server_ts = now_ms();
                    te.content = content;
                    te.depth = depth;
                    g_room_timeline[room_id].push_back(te);
                };

                // General room timeline
                add_event("!general:" + server_name, "@admin:" + server_name,
                    "m.room.message",
                    {{"msgtype", "m.text"}, {"body", "Welcome to the General room!"}},
                    1);
                add_event("!general:" + server_name, "@alice:" + server_name,
                    "m.room.message",
                    {{"msgtype", "m.text"}, {"body", "Hi everyone!"}},
                    2);
                add_event("!general:" + server_name, "@bob:" + server_name,
                    "m.room.message",
                    {{"msgtype", "m.text"}, {"body", "Hello Alice!"}},
                    3);
                add_event("!general:" + server_name, "@admin:" + server_name,
                    "m.room.message",
                    {{"msgtype", "m.notice"}, {"body", "Room rules: be respectful."}},
                    4);

                // Random room timeline
                add_event("!random:" + server_name, "@alice:" + server_name,
                    "m.room.message",
                    {{"msgtype", "m.text"}, {"body", "Random stuff goes here"}},
                    1);
                add_event("!random:" + server_name, "@bob:" + server_name,
                    "m.room.message",
                    {{"msgtype", "m.image"}, {"body", "cat.jpg"},
                     {"url", "mxc://localhost/cat123"}},
                    2);

                // Staff room timeline
                add_event("!staff:" + server_name, "@admin:" + server_name,
                    "m.room.message",
                    {{"msgtype", "m.text"}, {"body", "Staff meeting @ 3pm"}},
                    1);

                // Announcements timeline
                add_event("!announcements:" + server_name, "@admin:" + server_name,
                    "m.room.message",
                    {{"msgtype", "m.text"},
                     {"body", "Server will be upgraded on Saturday."}},
                    1);

                // Devchat timeline
                add_event("!devchat:" + server_name, "@alice:" + server_name,
                    "m.room.message",
                    {{"msgtype", "m.text"}, {"body", "Pushing new build today"}},
                    1);
                add_event("!devchat:" + server_name, "@bob:" + server_name,
                    "m.room.message",
                    {{"msgtype", "m.text"}, {"body", "Tests are all green!"}},
                    2);
            }

            // Seed membership log
            {
                std::lock_guard<std::mutex> lock(g_membership_log_mutex);
                auto add_log = [&](const std::string& room, const std::string& user,
                                    const std::string& ms, const std::string& by) {
                    db::MembershipLogEntry e;
                    e.room_id = room;
                    e.user_id = user;
                    e.membership = ms;
                    e.timestamp = iso8601_now();
                    e.performed_by = by;
                    g_membership_log.push_back(e);
                };
                add_log("!general:" + server_name, "@admin:" + server_name, "join", "@admin:" + server_name);
                add_log("!general:" + server_name, "@alice:" + server_name, "join", "@admin:" + server_name);
                add_log("!general:" + server_name, "@bob:" + server_name, "join", "@admin:" + server_name);
                add_log("!random:" + server_name, "@alice:" + server_name, "join", "@alice:" + server_name);
                add_log("!random:" + server_name, "@bob:" + server_name, "join", "@alice:" + server_name);
            }
        });
    }

} // anonymous namespace

// ============================================================================
// 1. GET /_synapse/admin/v1/rooms
//    List all rooms with comprehensive filtering and pagination.
//    Query params: from, limit, order_by, dir, search_term, room_type,
//                  blocked, public_room, federatable, join_rules,
//                  min_joined_members, max_joined_members, creator
// ============================================================================

nlohmann::json admin_list_all_rooms(const nlohmann::json& params,
                                     const nlohmann::json& body,
                                     const std::string& request_path) {
    init_demo_data(query_str(params, "server_name", "localhost:8008"));
    std::lock_guard<std::mutex> lock(db::rooms_mutex);

    // Parse pagination
    int from = query_int(params, "from", 0);
    int limit = query_int(params, "limit", 100);
    limit = std::max(1, std::min(limit, 500));

    // Parse sorting
    std::string order_by = query_str(params, "order_by", "name");
    std::string dir = query_str(params, "dir", "f");

    // Parse filters
    std::string search_term = query_str(params, "search_term", "");
    std::string room_type_filter = query_str(params, "room_type", "");
    bool blocked_filter = false;
    bool blocked_set = params.contains("blocked");
    if (blocked_set) blocked_filter = query_bool(params, "blocked", false);

    bool public_filter = false;
    bool public_set = params.contains("public_room");
    if (public_set) public_filter = query_bool(params, "public_room", false);

    bool federatable_filter = false;
    bool federatable_set = params.contains("federatable");
    if (federatable_set) federatable_filter = query_bool(params, "federatable", false);

    std::string join_rules_filter = query_str(params, "join_rules", "");
    std::string creator_filter = query_str(params, "creator", "");

    int min_joined = -1;
    if (params.contains("min_joined_members"))
        min_joined = query_int(params, "min_joined_members", -1);
    int max_joined = -1;
    if (params.contains("max_joined_members"))
        max_joined = query_int(params, "max_joined_members", -1);

    // Collect and filter rooms
    std::vector<db::RoomRecord> filtered;
    for (const auto& [rid, rec] : db::rooms) {
        if (!search_term.empty() &&
            !matches_filter(rec.name, search_term) &&
            !matches_filter(rec.room_id, search_term) &&
            !matches_filter(rec.canonical_alias, search_term) &&
            !matches_filter(rec.topic, search_term))
            continue;
        if (!room_type_filter.empty() && rec.room_type != room_type_filter)
            continue;
        if (blocked_set && rec.blocked != blocked_filter) continue;
        if (public_set && rec.public_room != public_filter) continue;
        if (federatable_set && rec.federatable != federatable_filter) continue;
        if (!join_rules_filter.empty() && rec.join_rules != join_rules_filter)
            continue;
        if (!creator_filter.empty() && rec.creator != creator_filter)
            continue;
        if (min_joined >= 0 && rec.joined_members < min_joined) continue;
        if (max_joined >= 0 && rec.joined_members > max_joined) continue;
        filtered.push_back(rec);
    }

    // Sort
    std::sort(filtered.begin(), filtered.end(),
        [&](const db::RoomRecord& a, const db::RoomRecord& b) {
            int cmp = 0;
            if (order_by == "name")
                cmp = a.name.compare(b.name);
            else if (order_by == "canonical_alias")
                cmp = a.canonical_alias.compare(b.canonical_alias);
            else if (order_by == "joined_members")
                cmp = a.joined_members - b.joined_members;
            else if (order_by == "total_members")
                cmp = a.total_members - b.total_members;
            else if (order_by == "creation_ts")
                cmp = a.creation_ts.compare(b.creation_ts);
            else if (order_by == "room_id")
                cmp = a.room_id.compare(b.room_id);
            else if (order_by == "blocked")
                cmp = static_cast<int>(a.blocked) - static_cast<int>(b.blocked);
            else
                cmp = a.name.compare(b.name);
            if (cmp == 0) cmp = a.room_id.compare(b.room_id);
            return (dir == "b") ? (cmp > 0) : (cmp < 0);
        });

    int total = static_cast<int>(filtered.size());

    // Slice for pagination
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
        r["join_rules"] = rec.join_rules;
        r["encryption"] = rec.encryption_algorithm;
        r["version"] = rec.room_version;
        r["room_type"] = rec.room_type.empty() ?
            nlohmann::json(nullptr) : nlohmann::json(rec.room_type);
        rooms_array.push_back(r);
    }

    nlohmann::json resp;
    resp["rooms"] = rooms_array;
    resp["total"] = total;
    resp["offset"] = from;
    resp["limit"] = limit;
    if (end < total) {
        resp["next_batch"] = end;
    }
    resp["server_time_ms"] = now_ms();
    return resp;
}

// ============================================================================
// 2. GET /_synapse/admin/v1/rooms/{roomId}
//    Get detailed information about a specific room.
//    Includes: room metadata, state events, member summary, aliases,
//              visibility settings, and moderation status.
// ============================================================================

nlohmann::json admin_room_details(const nlohmann::json& params,
                                   const nlohmann::json& body,
                                   const std::string& request_path) {
    init_demo_data(query_str(params, "server_name", "localhost:8008"));

    std::string room_id = extract_room_id_from_path(
        request_path, "/_synapse/admin/v1/rooms/");

    if (room_id.empty()) {
        // Might be called without room_id in path
        if (params.contains("room_id"))
            room_id = params["room_id"].get<std::string>();
    }

    if (!is_valid_room_id(room_id))
        return error_response("M_INVALID_PARAM", "Invalid room ID", 400);

    // Fetch room record
    db::RoomRecord rec;
    bool found = false;
    {
        std::lock_guard<std::mutex> lock(db::rooms_mutex);
        auto it = db::rooms.find(room_id);
        if (it != db::rooms.end()) {
            rec = it->second;
            found = true;
        }
    }

    if (!found)
        return error_response("M_NOT_FOUND", "Room not found: " + room_id, 404);

    nlohmann::json resp;

    // --- Basic room info ---
    resp["room_id"] = rec.room_id;
    resp["name"] = rec.name;
    resp["topic"] = rec.topic;
    resp["avatar_url"] = rec.avatar_url;
    resp["canonical_alias"] = rec.canonical_alias;
    resp["creator"] = rec.creator;
    resp["creation_ts"] = rec.creation_ts.empty() ? 0 :
        std::stoll(rec.creation_ts);
    if (!rec.creation_ts.empty())
        resp["creation_iso8601"] = iso8601_from_epoch(std::stoll(rec.creation_ts));

    // --- Membership counts ---
    resp["joined_members"] = rec.joined_members;
    resp["invited_members"] = rec.invited_members;
    resp["banned_members"] = rec.banned_members;
    resp["total_members"] = rec.total_members;

    // --- Settings ---
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

    // --- Visibility settings ---
    {
        std::lock_guard<std::mutex> lock(g_visibility_mutex);
        auto vit = g_visibility.find(room_id);
        if (vit != g_visibility.end()) {
            resp["visibility"] = vit->second.visibility;
            resp["is_published"] = vit->second.is_published;
            if (!vit->second.published_alias.empty())
                resp["published_alias"] = vit->second.published_alias;
        } else {
            resp["visibility"] = "private";
            resp["is_published"] = false;
        }
    }

    // --- Room aliases ---
    nlohmann::json aliases_arr = nlohmann::json::array();
    {
        std::lock_guard<std::mutex> lock(g_aliases_mutex);
        for (const auto& [alias, arec] : g_aliases) {
            if (arec.room_id == room_id) {
                nlohmann::json a;
                a["alias"] = arec.alias;
                a["creator"] = arec.creator;
                a["creation_ts"] = std::stoll(arec.creation_ts);
                a["published"] = arec.is_published;
                aliases_arr.push_back(a);
            }
        }
    }
    resp["aliases"] = aliases_arr;

    // --- State events ---
    nlohmann::json state_arr = nlohmann::json::array();
    {
        std::lock_guard<std::mutex> lock(g_state_mutex);
        auto sit = g_room_state.find(room_id);
        if (sit != g_room_state.end()) {
            for (const auto& se : sit->second) {
                nlohmann::json ev;
                ev["type"] = se.event_type;
                ev["state_key"] = se.state_key;
                ev["sender"] = se.sender;
                ev["origin_server_ts"] = std::stoll(se.origin_server_ts);
                ev["event_id"] = se.event_id;
                ev["content"] = se.content;
                state_arr.push_back(ev);
            }
        }
    }
    resp["state_events"] = state_arr;
    resp["state_event_count"] = state_arr.size();

    // --- Member list ---
    nlohmann::json members_arr = nlohmann::json::array();
    {
        std::lock_guard<std::mutex> lock(db::rooms_mutex);
        auto mit = db::room_members.find(room_id);
        if (mit != db::room_members.end()) {
            for (const auto& uid : mit->second) {
                nlohmann::json m;
                m["user_id"] = uid;
                m["membership"] = "join";
                members_arr.push_back(m);
            }
        }
    }
    resp["members"] = members_arr;
    resp["member_count"] = members_arr.size();

    // --- Moderation summary ---
    nlohmann::json mod;
    mod["blocked"] = rec.blocked;
    mod["federatable"] = rec.federatable;
    mod["join_rules"] = rec.join_rules;
    mod["guest_access"] = rec.guest_access;
    mod["history_visibility"] = rec.history_visibility;
    resp["moderation"] = mod;

    return resp;
}

// ============================================================================
// 3. POST /_synapse/admin/v1/rooms/{roomId}/delete
//    Delete a room. Supports block-before-delete and purge modes.
//    Body: { block, purge, message, force_purge, notify_members }
// ============================================================================

nlohmann::json admin_delete_room(const nlohmann::json& params,
                                  const nlohmann::json& body,
                                  const std::string& request_path) {
    init_demo_data(query_str(params, "server_name", "localhost:8008"));

    std::string room_id = extract_room_id_from_path(
        request_path, "/_synapse/admin/v1/rooms/");
    if (room_id.empty() && params.contains("room_id"))
        room_id = params["room_id"].get<std::string>();

    if (!is_valid_room_id(room_id))
        return error_response("M_INVALID_PARAM", "Invalid room ID", 400);

    // Parse options
    bool block = false;
    if (body.contains("block")) {
        if (body["block"].is_boolean()) block = body["block"].get<bool>();
        else if (body["block"].is_string())
            block = (body["block"].get<std::string>() == "true");
    }

    bool purge = true;
    if (body.contains("purge")) {
        if (body["purge"].is_boolean()) purge = body["purge"].get<bool>();
        else if (body["purge"].is_string())
            purge = (body["purge"].get<std::string>() == "true");
    }

    std::string message = body.value("message", "Room deleted by administrator");
    bool force_purge = body.value("force_purge", false);
    bool notify_members = body.value("notify_members", false);

    nlohmann::json resp;
    nlohmann::json kicked_members = nlohmann::json::array();
    nlohmann::json failed_kicks = nlohmann::json::array();
    nlohmann::json local_aliases = nlohmann::json::array();

    // Collect members to kick
    std::vector<std::string> members_to_kick;
    {
        std::lock_guard<std::mutex> lock(db::rooms_mutex);
        auto mit = db::room_members.find(room_id);
        if (mit != db::room_members.end())
            members_to_kick = mit->second;
    }

    // Block the room first if requested
    if (block) {
        std::lock_guard<std::mutex> lock(db::rooms_mutex);
        auto it = db::rooms.find(room_id);
        if (it != db::rooms.end())
            it->second.blocked = true;
        resp["blocked"] = true;
    }

    // Notify members (simulated)
    if (notify_members && !members_to_kick.empty()) {
        for (const auto& uid : members_to_kick)
            kicked_members.push_back(uid);
        resp["notifications_sent"] = members_to_kick.size();
    }

    // Collect local aliases
    {
        std::lock_guard<std::mutex> lock(g_aliases_mutex);
        for (auto it = g_aliases.begin(); it != g_aliases.end();) {
            if (it->second.room_id == room_id) {
                local_aliases.push_back(it->first);
                it = g_aliases.erase(it);
            } else {
                ++it;
            }
        }
    }

    // Purge room data
    std::string delete_id;
    std::string purge_id;
    if (purge) {
        purge_id = "purge_" + random_hex(16);
        db::PurgeEntry pe;
        pe.purge_id = purge_id;
        pe.room_id = room_id;
        pe.status = "active";
        pe.started_ts = now_ms();
        {
            std::lock_guard<std::mutex> lock(db::purges_mutex);
            db::purges[purge_id] = pe;
        }

        // Remove room state
        {
            std::lock_guard<std::mutex> lock(g_state_mutex);
            g_room_state.erase(room_id);
        }

        // Remove timeline
        {
            std::lock_guard<std::mutex> lock(g_timeline_mutex);
            g_room_timeline.erase(room_id);
        }

        // Remove visibility
        {
            std::lock_guard<std::mutex> lock(g_visibility_mutex);
            g_visibility.erase(room_id);
        }

        // Mark purge complete
        {
            std::lock_guard<std::mutex> lock(db::purges_mutex);
            auto& p = db::purges[purge_id];
            p.status = "complete";
            p.completed_ts = now_ms();
        }

        delete_id = purge_id;
    }

    // Remove room and members from store
    {
        std::lock_guard<std::mutex> lock(db::rooms_mutex);
        db::rooms.erase(room_id);
        db::room_members.erase(room_id);
    }

    // Log membership changes
    {
        std::lock_guard<std::mutex> lock(g_membership_log_mutex);
        std::string admin_user = params.value("admin_user", "admin");
        for (const auto& uid : members_to_kick) {
            db::MembershipLogEntry e;
            e.room_id = room_id;
            e.user_id = uid;
            e.membership = "leave";
            e.timestamp = iso8601_now();
            e.reason = message;
            e.performed_by = admin_user;
            g_membership_log.push_back(e);
        }
    }

    // Build response
    resp["kicked_members"] = kicked_members;
    resp["failed_to_kick_members"] = failed_kicks;
    resp["local_aliases"] = local_aliases;
    if (!delete_id.empty())
        resp["delete_id"] = delete_id;
    if (!purge_id.empty())
        resp["purge_id"] = purge_id;
    resp["room_id"] = room_id;
    resp["message"] = message;

    return resp;
}

// ============================================================================
// 4. POST /_synapse/admin/v1/rooms/{roomId}/block
//    Block or unblock a room. Body: { block: bool, reason: string }
// ============================================================================

nlohmann::json admin_block_room(const nlohmann::json& params,
                                 const nlohmann::json& body,
                                 const std::string& request_path) {
    init_demo_data(query_str(params, "server_name", "localhost:8008"));

    std::string room_id = extract_room_id_from_path(
        request_path, "/_synapse/admin/v1/rooms/");
    if (room_id.empty() && params.contains("room_id"))
        room_id = params["room_id"].get<std::string>();

    if (!is_valid_room_id(room_id))
        return error_response("M_INVALID_PARAM", "Invalid room ID", 400);

    bool block = true;
    if (body.contains("block")) {
        if (body["block"].is_boolean()) block = body["block"].get<bool>();
        else if (body["block"].is_string())
            block = (body["block"].get<std::string>() == "true");
    }

    std::string reason = body.value("reason", block ?
        "Room blocked by administrator" : "Room unblocked by administrator");

    {
        std::lock_guard<std::mutex> lock(db::rooms_mutex);
        auto it = db::rooms.find(room_id);
        if (it == db::rooms.end())
            return error_response("M_NOT_FOUND", "Room not found: " + room_id, 404);
        it->second.blocked = block;
    }

    // If blocking, also unpublish from directory
    if (block) {
        std::lock_guard<std::mutex> lock(g_visibility_mutex);
        auto vit = g_visibility.find(room_id);
        if (vit != g_visibility.end()) {
            vit->second.is_published = false;
        }
    }

    nlohmann::json resp;
    resp["success"] = true;
    resp["blocked"] = block;
    resp["room_id"] = room_id;
    resp["reason"] = reason;
    resp["timestamp"] = iso8601_now();
    return resp;
}

// ============================================================================
// 5. POST /_synapse/admin/v1/rooms/{roomId}/force_join
//    Force a specified user to join a room.
//    Body: { user_id: string, reason: string }
// ============================================================================

nlohmann::json admin_force_join_room(const nlohmann::json& params,
                                      const nlohmann::json& body,
                                      const std::string& request_path) {
    init_demo_data(query_str(params, "server_name", "localhost:8008"));

    std::string room_id = extract_room_id_from_path(
        request_path, "/_synapse/admin/v1/rooms/");
    if (room_id.empty() && params.contains("room_id"))
        room_id = params["room_id"].get<std::string>();

    if (!is_valid_room_id(room_id))
        return error_response("M_INVALID_PARAM", "Invalid room ID", 400);

    if (!body.contains("user_id") || !body["user_id"].is_string())
        return error_response("M_MISSING_PARAM", "user_id is required", 400);

    std::string user_id = body["user_id"].get<std::string>();
    if (!is_valid_user_id(user_id))
        return error_response("M_INVALID_PARAM", "Invalid user ID", 400);

    std::string reason = body.value("reason", "Force joined by administrator");
    std::string admin_user = params.value("admin_user", "admin");

    // Verify room exists
    {
        std::lock_guard<std::mutex> lock(db::rooms_mutex);
        if (db::rooms.find(room_id) == db::rooms.end())
            return error_response("M_NOT_FOUND", "Room not found: " + room_id, 404);
    }

    // Verify user exists
    {
        std::lock_guard<std::mutex> lock(db::users_mutex);
        if (db::users.find(user_id) == db::users.end())
            return error_response("M_NOT_FOUND", "User not found: " + user_id, 404);
    }

    // Check room is not blocked
    {
        std::lock_guard<std::mutex> lock(db::rooms_mutex);
        auto it = db::rooms.find(room_id);
        if (it != db::rooms.end() && it->second.blocked)
            return error_response("M_FORBIDDEN",
                "Cannot force join a blocked room", 403);
    }

    // Add user to room members
    bool already_member = false;
    {
        std::lock_guard<std::mutex> lock(db::rooms_mutex);
        auto& members = db::room_members[room_id];
        for (const auto& m : members) {
            if (m == user_id) { already_member = true; break; }
        }
        if (!already_member) {
            members.push_back(user_id);
            // Update member count
            auto rit = db::rooms.find(room_id);
            if (rit != db::rooms.end()) {
                rit->second.joined_members++;
                rit->second.total_members++;
            }
        }
    }

    // Add membership log entry
    {
        std::lock_guard<std::mutex> lock(g_membership_log_mutex);
        db::MembershipLogEntry e;
        e.room_id = room_id;
        e.user_id = user_id;
        e.membership = "join";
        e.timestamp = iso8601_now();
        e.reason = reason;
        e.performed_by = admin_user;
        g_membership_log.push_back(e);
    }

    // Generate a synthetic join state event in timeline
    {
        std::lock_guard<std::mutex> lock(g_timeline_mutex);
        db::TimelineEvent te;
        te.event_id = generate_event_id();
        te.room_id = room_id;
        te.sender = admin_user;
        te.event_type = "m.room.member";
        te.origin_server_ts = now_ms();
        te.content = {
            {"membership", "join"},
            {"displayname", user_id},
            {"reason", reason}
        };
        te.state_key = user_id;
        int max_depth = 0;
        auto& tl = g_room_timeline[room_id];
        for (const auto& ev : tl) max_depth = std::max(max_depth, ev.depth);
        te.depth = max_depth + 1;
        tl.push_back(te);
    }

    nlohmann::json resp;
    resp["success"] = true;
    resp["room_id"] = room_id;
    resp["user_id"] = user_id;
    resp["already_member"] = already_member;
    resp["reason"] = reason;
    resp["timestamp"] = iso8601_now();
    return resp;
}

// ============================================================================
// 6. POST /_synapse/admin/v1/rooms/{roomId}/force_leave
//    Force a specified user to leave a room (or kick them).
//    Body: { user_id: string, reason: string, ban: bool }
// ============================================================================

nlohmann::json admin_force_leave_room(const nlohmann::json& params,
                                       const nlohmann::json& body,
                                       const std::string& request_path) {
    init_demo_data(query_str(params, "server_name", "localhost:8008"));

    std::string room_id = extract_room_id_from_path(
        request_path, "/_synapse/admin/v1/rooms/");
    if (room_id.empty() && params.contains("room_id"))
        room_id = params["room_id"].get<std::string>();

    if (!is_valid_room_id(room_id))
        return error_response("M_INVALID_PARAM", "Invalid room ID", 400);

    if (!body.contains("user_id") || !body["user_id"].is_string())
        return error_response("M_MISSING_PARAM", "user_id is required", 400);

    std::string user_id = body["user_id"].get<std::string>();
    if (!is_valid_user_id(user_id))
        return error_response("M_INVALID_PARAM", "Invalid user ID", 400);

    std::string reason = body.value("reason", "Force removed by administrator");
    bool should_ban = body.value("ban", false);
    std::string admin_user = params.value("admin_user", "admin");
    std::string membership_type = should_ban ? "ban" : "leave";

    // Verify room exists
    {
        std::lock_guard<std::mutex> lock(db::rooms_mutex);
        if (db::rooms.find(room_id) == db::rooms.end())
            return error_response("M_NOT_FOUND", "Room not found: " + room_id, 404);
    }

    // Remove user from room members
    bool was_member = false;
    {
        std::lock_guard<std::mutex> lock(db::rooms_mutex);
        auto mit = db::room_members.find(room_id);
        if (mit != db::room_members.end()) {
            auto& members = mit->second;
            auto it = std::find(members.begin(), members.end(), user_id);
            if (it != members.end()) {
                members.erase(it);
                was_member = true;
                // Update member count
                auto rit = db::rooms.find(room_id);
                if (rit != db::rooms.end()) {
                    rit->second.joined_members =
                        std::max(0, rit->second.joined_members - 1);
                    rit->second.total_members =
                        std::max(0, rit->second.total_members - 1);
                    if (should_ban)
                        rit->second.banned_members++;
                }
            }
        }
    }

    if (!was_member)
        return error_response("M_NOT_FOUND",
            "User " + user_id + " is not a member of room " + room_id, 404);

    // Log membership change
    {
        std::lock_guard<std::mutex> lock(g_membership_log_mutex);
        db::MembershipLogEntry e;
        e.room_id = room_id;
        e.user_id = user_id;
        e.membership = membership_type;
        e.timestamp = iso8601_now();
        e.reason = reason;
        e.performed_by = admin_user;
        g_membership_log.push_back(e);
    }

    // Generate a synthetic leave/ban state event in timeline
    {
        std::lock_guard<std::mutex> lock(g_timeline_mutex);
        db::TimelineEvent te;
        te.event_id = generate_event_id();
        te.room_id = room_id;
        te.sender = admin_user;
        te.event_type = "m.room.member";
        te.origin_server_ts = now_ms();
        te.content = {
            {"membership", membership_type},
            {"displayname", user_id},
            {"reason", reason}
        };
        te.state_key = user_id;
        int max_depth = 0;
        auto& tl = g_room_timeline[room_id];
        for (const auto& ev : tl) max_depth = std::max(max_depth, ev.depth);
        te.depth = max_depth + 1;
        tl.push_back(te);
    }

    nlohmann::json resp;
    resp["success"] = true;
    resp["room_id"] = room_id;
    resp["user_id"] = user_id;
    resp["membership"] = membership_type;
    resp["banned"] = should_ban;
    resp["reason"] = reason;
    resp["timestamp"] = iso8601_now();
    return resp;
}

// ============================================================================
// 7. GET /_synapse/admin/v1/room_aliases
//    List all room aliases with filtering and pagination.
//    Query params: from, limit, search_term, room_id, published, creator
// ============================================================================

nlohmann::json admin_list_room_aliases(const nlohmann::json& params,
                                        const nlohmann::json& body,
                                        const std::string& request_path) {
    init_demo_data(query_str(params, "server_name", "localhost:8008"));

    int from = query_int(params, "from", 0);
    int limit = query_int(params, "limit", 100);
    limit = std::max(1, std::min(limit, 500));

    std::string search_term = query_str(params, "search_term", "");
    std::string room_id_filter = query_str(params, "room_id", "");
    std::string creator_filter = query_str(params, "creator", "");

    bool published_set = params.contains("published");
    bool published_filter = false;
    if (published_set) published_filter = query_bool(params, "published", false);

    std::lock_guard<std::mutex> lock(g_aliases_mutex);

    // Collect and filter aliases
    std::vector<db::AliasRecord> filtered;
    for (const auto& [alias, arec] : g_aliases) {
        if (!search_term.empty() &&
            !matches_filter(arec.alias, search_term) &&
            !matches_filter(arec.room_id, search_term))
            continue;
        if (!room_id_filter.empty() && arec.room_id != room_id_filter)
            continue;
        if (!creator_filter.empty() && arec.creator != creator_filter)
            continue;
        if (published_set && arec.is_published != published_filter)
            continue;
        filtered.push_back(arec);
    }

    int total = static_cast<int>(filtered.size());

    // Sort by alias
    std::sort(filtered.begin(), filtered.end(),
        [](const db::AliasRecord& a, const db::AliasRecord& b) {
            return a.alias < b.alias;
        });

    nlohmann::json aliases_arr = nlohmann::json::array();
    int end = std::min(from + limit, total);
    for (int i = from; i < end; ++i) {
        const auto& arec = filtered[i];
        nlohmann::json a;
        a["alias"] = arec.alias;
        a["room_id"] = arec.room_id;
        a["creator"] = arec.creator;
        a["creation_ts"] = arec.creation_ts.empty() ? 0 : std::stoll(arec.creation_ts);
        a["published"] = arec.is_published;
        aliases_arr.push_back(a);
    }

    nlohmann::json resp;
    resp["aliases"] = aliases_arr;
    resp["total"] = total;
    resp["offset"] = from;
    resp["limit"] = limit;
    if (end < total)
        resp["next_batch"] = end;
    return resp;
}

// ============================================================================
// 8. POST /_synapse/admin/v1/room_aliases/create
//    Create a new room alias. Body: { alias, room_id, published }
// ============================================================================

nlohmann::json admin_create_alias(const nlohmann::json& params,
                                   const nlohmann::json& body,
                                   const std::string& request_path) {
    init_demo_data(query_str(params, "server_name", "localhost:8008"));

    if (!body.contains("alias") || !body["alias"].is_string())
        return error_response("M_MISSING_PARAM", "alias is required", 400);

    if (!body.contains("room_id") || !body["room_id"].is_string())
        return error_response("M_MISSING_PARAM", "room_id is required", 400);

    std::string alias = body["alias"].get<std::string>();
    std::string room_id = body["room_id"].get<std::string>();
    std::string creator = params.value("admin_user",
        body.value("creator", "admin"));
    bool published = body.value("published", false);

    // Validate alias format
    if (!starts_with(alias, "#"))
        return error_response("M_INVALID_PARAM",
            "Alias must start with #", 400);

    // If no domain, append server name
    if (alias.find(':') == std::string::npos) {
        std::string server_name = query_str(params, "server_name", "localhost:8008");
        alias = alias + ":" + server_name;
    }

    if (!is_valid_alias(alias))
        return error_response("M_INVALID_PARAM",
            "Invalid alias format. Expected: #localpart:domain", 400);

    if (!is_valid_room_id(room_id))
        return error_response("M_INVALID_PARAM", "Invalid room ID", 400);

    // Verify room exists
    {
        std::lock_guard<std::mutex> lock(db::rooms_mutex);
        if (db::rooms.find(room_id) == db::rooms.end())
            return error_response("M_NOT_FOUND", "Room not found: " + room_id, 404);
    }

    // Create alias
    {
        std::lock_guard<std::mutex> lock(g_aliases_mutex);
        if (g_aliases.find(alias) != g_aliases.end())
            return error_response("M_CONFLICT",
                "Alias already exists: " + alias, 409);

        db::AliasRecord arec;
        arec.alias = alias;
        arec.room_id = room_id;
        arec.creator = creator;
        arec.creation_ts = now_ms();
        arec.is_published = published;
        g_aliases[alias] = arec;
    }

    // Update room canonical alias if not set
    {
        std::lock_guard<std::mutex> lock(db::rooms_mutex);
        auto it = db::rooms.find(room_id);
        if (it != db::rooms.end() && it->second.canonical_alias.empty())
            it->second.canonical_alias = alias;
    }

    // Update visibility if published
    if (published) {
        std::lock_guard<std::mutex> lock(g_visibility_mutex);
        auto vit = g_visibility.find(room_id);
        if (vit != g_visibility.end()) {
            vit->second.published_alias = alias;
            vit->second.is_published = true;
            vit->second.visibility = "public";
        } else {
            db::RoomVisibilitySettings vs;
            vs.room_id = room_id;
            vs.visibility = "public";
            vs.is_published = true;
            vs.published_alias = alias;
            g_visibility[room_id] = vs;
        }
    }

    // Add state event to room
    {
        std::lock_guard<std::mutex> lock(g_state_mutex);
        db::StateEvent se;
        se.event_type = "m.room.aliases";
        se.state_key = "";
        se.sender = creator;
        se.origin_server_ts = now_ms();
        se.event_id = generate_event_id();
        se.content["aliases"] = nlohmann::json::array({alias});
        g_room_state[room_id].push_back(se);
    }

    nlohmann::json resp;
    resp["success"] = true;
    resp["alias"] = alias;
    resp["room_id"] = room_id;
    resp["created_ts"] = std::stoll(now_ms());
    resp["published"] = published;
    return resp;
}

// ============================================================================
// 9. POST /_synapse/admin/v1/room_aliases/delete
//    Delete a room alias. Body: { alias }
// ============================================================================

nlohmann::json admin_delete_alias(const nlohmann::json& params,
                                   const nlohmann::json& body,
                                   const std::string& request_path) {
    init_demo_data(query_str(params, "server_name", "localhost:8008"));

    if (!body.contains("alias") || !body["alias"].is_string())
        return error_response("M_MISSING_PARAM", "alias is required", 400);

    std::string alias = body["alias"].get<std::string>();

    // If no domain, append server name
    if (alias.find(':') == std::string::npos) {
        std::string server_name = query_str(params, "server_name", "localhost:8008");
        alias = alias + ":" + server_name;
    }

    if (!is_valid_alias(alias))
        return error_response("M_INVALID_PARAM",
            "Invalid alias format. Expected: #localpart:domain", 400);

    db::AliasRecord removed;
    bool found = false;
    {
        std::lock_guard<std::mutex> lock(g_aliases_mutex);
        auto it = g_aliases.find(alias);
        if (it == g_aliases.end())
            return error_response("M_NOT_FOUND",
                "Alias not found: " + alias, 404);
        removed = it->second;
        g_aliases.erase(it);
        found = true;
    }

    // Clear canonical alias if this was it
    {
        std::lock_guard<std::mutex> lock(db::rooms_mutex);
        auto it = db::rooms.find(removed.room_id);
        if (it != db::rooms.end() && it->second.canonical_alias == alias) {
            it->second.canonical_alias = "";
        }
    }

    // Unpublish if this was the published alias
    {
        std::lock_guard<std::mutex> lock(g_visibility_mutex);
        auto vit = g_visibility.find(removed.room_id);
        if (vit != g_visibility.end() &&
            vit->second.published_alias == alias) {
            vit->second.published_alias = "";
            vit->second.is_published = false;
        }
    }

    nlohmann::json resp;
    resp["success"] = true;
    resp["deleted"] = true;
    resp["alias"] = alias;
    resp["room_id"] = removed.room_id;
    resp["was_published"] = removed.is_published;
    resp["timestamp"] = iso8601_now();
    return resp;
}

// ============================================================================
// 10. POST /_synapse/admin/v1/rooms/{roomId}/visibility
//     Set room visibility (public/private) and directory publishing.
//     Body: { visibility: "public"|"private", publish: bool, alias: string }
// ============================================================================

nlohmann::json admin_set_room_visibility(const nlohmann::json& params,
                                          const nlohmann::json& body,
                                          const std::string& request_path) {
    init_demo_data(query_str(params, "server_name", "localhost:8008"));

    std::string room_id = extract_room_id_from_path(
        request_path, "/_synapse/admin/v1/rooms/");
    if (room_id.empty() && params.contains("room_id"))
        room_id = params["room_id"].get<std::string>();

    if (!is_valid_room_id(room_id))
        return error_response("M_INVALID_PARAM", "Invalid room ID", 400);

    // Verify room exists
    {
        std::lock_guard<std::mutex> lock(db::rooms_mutex);
        if (db::rooms.find(room_id) == db::rooms.end())
            return error_response("M_NOT_FOUND", "Room not found: " + room_id, 404);
    }

    // Parse visibility settings
    std::string visibility = "private";
    if (body.contains("visibility") && body["visibility"].is_string()) {
        visibility = body["visibility"].get<std::string>();
        if (visibility != "public" && visibility != "private")
            return error_response("M_INVALID_PARAM",
                "visibility must be 'public' or 'private'", 400);
    }

    bool publish = false;
    if (body.contains("publish")) {
        if (body["publish"].is_boolean()) publish = body["publish"].get<bool>();
        else if (body["publish"].is_string())
            publish = (body["publish"].get<std::string>() == "true");
    } else if (visibility == "public") {
        publish = true; // default: publish when setting public
    }

    std::string published_alias;
    if (body.contains("alias") && body["alias"].is_string())
        published_alias = body["alias"].get<std::string>();

    // Validate alias ownership
    if (!published_alias.empty()) {
        std::lock_guard<std::mutex> lock(g_aliases_mutex);
        auto it = g_aliases.find(published_alias);
        if (it != g_aliases.end() && it->second.room_id != room_id)
            return error_response("M_INVALID_PARAM",
                "Alias " + published_alias + " belongs to a different room", 400);
    }

    // Update visibility
    {
        std::lock_guard<std::mutex> lock(g_visibility_mutex);
        auto vit = g_visibility.find(room_id);
        if (vit != g_visibility.end()) {
            vit->second.visibility = visibility;
            vit->second.is_published = publish;
            if (!published_alias.empty())
                vit->second.published_alias = published_alias;
            else if (publish && vit->second.published_alias.empty()) {
                // Try to find a published alias
                std::lock_guard<std::mutex> alock(g_aliases_mutex);
                for (const auto& [a, arec] : g_aliases) {
                    if (arec.room_id == room_id && arec.is_published) {
                        vit->second.published_alias = a;
                        break;
                    }
                }
            }
        } else {
            db::RoomVisibilitySettings vs;
            vs.room_id = room_id;
            vs.visibility = visibility;
            vs.is_published = publish;
            vs.published_alias = published_alias;
            g_visibility[room_id] = vs;
        }
    }

    // Update room public flag
    {
        std::lock_guard<std::mutex> lock(db::rooms_mutex);
        auto it = db::rooms.find(room_id);
        if (it != db::rooms.end())
            it->second.public_room = publish;
    }

    // Generate state event
    {
        std::lock_guard<std::mutex> lock(g_state_mutex);
        std::string admin_user = params.value("admin_user", "admin");
        db::StateEvent se;
        se.event_type = "m.room.join_rules";
        se.state_key = "";
        se.sender = admin_user;
        se.origin_server_ts = now_ms();
        se.event_id = generate_event_id();
        se.content["join_rule"] = (visibility == "public") ? "public" : "invite";
        g_room_state[room_id].push_back(se);
    }

    nlohmann::json resp;
    resp["success"] = true;
    resp["room_id"] = room_id;
    resp["visibility"] = visibility;
    resp["published"] = publish;
    if (!published_alias.empty())
        resp["published_alias"] = published_alias;
    resp["timestamp"] = iso8601_now();
    return resp;
}

// ============================================================================
// 11. GET /_synapse/admin/v1/public_rooms
//     List all public rooms in the directory.
//     Query params: from, limit, search_term, server, order_by, dir,
//                   include_all_networks, third_party_instance_id
// ============================================================================

nlohmann::json admin_list_public_rooms(const nlohmann::json& params,
                                        const nlohmann::json& body,
                                        const std::string& request_path) {
    init_demo_data(query_str(params, "server_name", "localhost:8008"));

    int from = query_int(params, "from", 0);
    int limit = query_int(params, "limit", 100);
    limit = std::max(1, std::min(limit, 500));

    std::string search_term = query_str(params, "search_term", "");
    std::string server_filter = query_str(params, "server", "");
    std::string order_by = query_str(params, "order_by", "num_joined_members");
    std::string dir = query_str(params, "dir", "f");

    // Collect public rooms (published)
    std::vector<std::pair<std::string, db::RoomVisibilitySettings>> public_rooms;
    {
        std::lock_guard<std::mutex> lock(g_visibility_mutex);
        for (const auto& [rid, vs] : g_visibility) {
            if (!vs.is_published) continue;
            if (!search_term.empty()) {
                // Check room name from room record
                std::lock_guard<std::mutex> rlock(db::rooms_mutex);
                auto rit = db::rooms.find(rid);
                bool matches = false;
                if (rit != db::rooms.end()) {
                    if (matches_filter(rit->second.name, search_term)) matches = true;
                    if (matches_filter(rit->second.topic, search_term)) matches = true;
                    if (matches_filter(rit->second.canonical_alias, search_term)) matches = true;
                }
                if (matches_filter(rid, search_term)) matches = true;
                if (matches_filter(vs.published_alias, search_term)) matches = true;
                if (!matches) continue;
            }
            if (!server_filter.empty()) {
                std::string alias_server = extract_server_name(vs.published_alias.empty() ?
                    rid : vs.published_alias);
                if (alias_server != server_filter) continue;
            }
            public_rooms.push_back({rid, vs});
        }
    }

    int total = static_cast<int>(public_rooms.size());

    // Sort
    std::sort(public_rooms.begin(), public_rooms.end(),
        [&](const auto& a, const auto& b) {
            int cmp = 0;
            if (order_by == "num_joined_members") {
                cmp = a.second.joined_members - b.second.joined_members;
            } else if (order_by == "name") {
                // Get names from room store
                std::lock_guard<std::mutex> rlock(db::rooms_mutex);
                std::string na, nb;
                auto ita = db::rooms.find(a.first);
                auto itb = db::rooms.find(b.first);
                if (ita != db::rooms.end()) na = ita->second.name;
                if (itb != db::rooms.end()) nb = itb->second.name;
                cmp = na.compare(nb);
            } else if (order_by == "canonical_alias") {
                cmp = a.second.published_alias.compare(b.second.published_alias);
            }
            if (cmp == 0) cmp = a.first.compare(b.first);
            return (dir == "b") ? (cmp > 0) : (cmp < 0);
        });

    nlohmann::json rooms_arr = nlohmann::json::array();
    int end = std::min(from + limit, total);
    for (int i = from; i < end; ++i) {
        const auto& [rid, vs] = public_rooms[i];
        nlohmann::json r;

        // Get room details
        {
            std::lock_guard<std::mutex> rlock(db::rooms_mutex);
            auto rit = db::rooms.find(rid);
            if (rit != db::rooms.end()) {
                r["room_id"] = rit->second.room_id;
                r["name"] = rit->second.name;
                r["topic"] = rit->second.topic;
                r["avatar_url"] = rit->second.avatar_url;
                r["num_joined_members"] = rit->second.joined_members;
                r["world_readable"] = (rit->second.history_visibility == "world_readable");
                r["guest_can_join"] = (rit->second.guest_access == "can_join");
                r["room_type"] = rit->second.room_type.empty() ?
                    nlohmann::json(nullptr) : nlohmann::json(rit->second.room_type);
            } else {
                r["room_id"] = rid;
                r["name"] = rid;
                r["num_joined_members"] = vs.joined_members;
            }
        }

        // Add alias
        if (!vs.published_alias.empty())
            r["canonical_alias"] = vs.published_alias;

        // Add join rule
        r["join_rule"] = "public";

        // Federated server list
        nlohmann::json servers = nlohmann::json::array();
        servers.push_back(extract_server_name(rid));
        r["servers"] = servers;

        rooms_arr.push_back(r);
    }

    nlohmann::json resp;
    resp["chunk"] = rooms_arr;
    resp["total_room_count_estimate"] = total;
    resp["offset"] = from;
    resp["limit"] = limit;
    if (end < total)
        resp["next_batch"] = std::to_string(end);
    return resp;
}

// ============================================================================
// 12. POST /_synapse/admin/v1/rooms/{roomId}/publish
//     Publish a room to the public directory.
//     Body: { publish: bool, alias: string }
// ============================================================================

nlohmann::json admin_publish_room(const nlohmann::json& params,
                                   const nlohmann::json& body,
                                   const std::string& request_path) {
    init_demo_data(query_str(params, "server_name", "localhost:8008"));

    std::string room_id = extract_room_id_from_path(
        request_path, "/_synapse/admin/v1/rooms/");
    if (room_id.empty() && params.contains("room_id"))
        room_id = params["room_id"].get<std::string>();

    if (!is_valid_room_id(room_id))
        return error_response("M_INVALID_PARAM", "Invalid room ID", 400);

    bool publish = true;
    if (body.contains("publish")) {
        if (body["publish"].is_boolean()) publish = body["publish"].get<bool>();
        else if (body["publish"].is_string())
            publish = (body["publish"].get<std::string>() == "true");
    }

    // Verify room exists
    {
        std::lock_guard<std::mutex> lock(db::rooms_mutex);
        if (db::rooms.find(room_id) == db::rooms.end())
            return error_response("M_NOT_FOUND", "Room not found: " + room_id, 404);
    }

    std::string alias;
    if (body.contains("alias") && body["alias"].is_string())
        alias = body["alias"].get<std::string>();

    // If publishing, validate alias or find one
    if (publish) {
        if (alias.empty()) {
            // Try to find an existing alias for this room
            std::lock_guard<std::mutex> lock(g_aliases_mutex);
            for (const auto& [a, arec] : g_aliases) {
                if (arec.room_id == room_id) {
                    alias = a;
                    break;
                }
            }
        }
        if (alias.empty())
            return error_response("M_MISSING_PARAM",
                "No alias available for publishing. Create an alias first.", 400);
    }

    // Update visibility and publish status
    {
        std::lock_guard<std::mutex> lock(g_visibility_mutex);
        auto vit = g_visibility.find(room_id);
        if (vit != g_visibility.end()) {
            vit->second.is_published = publish;
            if (publish) {
                vit->second.visibility = "public";
                if (!alias.empty())
                    vit->second.published_alias = alias;
            } else {
                vit->second.published_alias = "";
            }
        } else {
            db::RoomVisibilitySettings vs;
            vs.room_id = room_id;
            vs.is_published = publish;
            vs.visibility = publish ? "public" : "private";
            vs.published_alias = publish ? alias : "";
            g_visibility[room_id] = vs;
        }
    }

    // Update room record
    {
        std::lock_guard<std::mutex> lock(db::rooms_mutex);
        auto it = db::rooms.find(room_id);
        if (it != db::rooms.end()) {
            it->second.public_room = publish;
            if (publish)
                it->second.join_rules = "public";
        }
    }

    // Update alias published status
    if (!alias.empty()) {
        std::lock_guard<std::mutex> lock(g_aliases_mutex);
        auto ait = g_aliases.find(alias);
        if (ait != g_aliases.end())
            ait->second.is_published = publish;
    }

    nlohmann::json resp;
    resp["success"] = true;
    resp["room_id"] = room_id;
    resp["published"] = publish;
    resp["visibility"] = publish ? "public" : "private";
    if (!alias.empty())
        resp["alias"] = alias;
    resp["timestamp"] = iso8601_now();
    return resp;
}

// ============================================================================
// 13. POST /_synapse/admin/v1/rooms/{roomId}/unpublish
//     Unpublish a room from the public directory.
//     Body: {} (no required fields)
// ============================================================================

nlohmann::json admin_unpublish_room(const nlohmann::json& params,
                                     const nlohmann::json& body,
                                     const std::string& request_path) {
    init_demo_data(query_str(params, "server_name", "localhost:8008"));

    std::string room_id = extract_room_id_from_path(
        request_path, "/_synapse/admin/v1/rooms/");
    if (room_id.empty() && params.contains("room_id"))
        room_id = params["room_id"].get<std::string>();

    if (!is_valid_room_id(room_id))
        return error_response("M_INVALID_PARAM", "Invalid room ID", 400);

    // Verify room exists
    {
        std::lock_guard<std::mutex> lock(db::rooms_mutex);
        if (db::rooms.find(room_id) == db::rooms.end())
            return error_response("M_NOT_FOUND", "Room not found: " + room_id, 404);
    }

    // Unpublish
    {
        std::lock_guard<std::mutex> lock(g_visibility_mutex);
        auto vit = g_visibility.find(room_id);
        if (vit != g_visibility.end()) {
            vit->second.is_published = false;
            vit->second.visibility = "private";
            vit->second.published_alias = "";
        }
    }

    // Update room record
    {
        std::lock_guard<std::mutex> lock(db::rooms_mutex);
        auto it = db::rooms.find(room_id);
        if (it != db::rooms.end())
            it->second.public_room = false;
    }

    // Update alias published status
    {
        std::lock_guard<std::mutex> lock(g_aliases_mutex);
        for (auto& [a, arec] : g_aliases) {
            if (arec.room_id == room_id)
                arec.is_published = false;
        }
    }

    nlohmann::json resp;
    resp["success"] = true;
    resp["room_id"] = room_id;
    resp["published"] = false;
    resp["visibility"] = "private";
    resp["timestamp"] = iso8601_now();
    return resp;
}

// ============================================================================
// 14. GET /_synapse/admin/v1/rooms/{roomId}/statistics
//     Get detailed statistics for a specific room (or all rooms if no ID).
//     Includes message counts, active users, event types breakdown,
//     storage estimates, and activity timeline.
// ============================================================================

nlohmann::json admin_room_statistics(const nlohmann::json& params,
                                      const nlohmann::json& body,
                                      const std::string& request_path) {
    init_demo_data(query_str(params, "server_name", "localhost:8008"));

    // Check if this is for a specific room
    std::string room_id = extract_room_id_from_path(
        request_path, "/_synapse/admin/v1/rooms/");
    if (room_id.empty() && params.contains("room_id"))
        room_id = params["room_id"].get<std::string>();

    bool all_rooms = room_id.empty();
    bool refresh = query_bool(params, "refresh", false);

    // Check cache
    if (!refresh && !all_rooms) {
        std::lock_guard<std::mutex> lock(g_room_stats_cache_mutex);
        auto cit = g_room_stats_cache.find(room_id);
        if (cit != g_room_stats_cache.end()) {
            auto age = std::stoll(now_ms()) - g_stats_cache_age_ms.load();
            if (age < 60000) // 1 minute cache
                return cit->second;
        }
    }

    if (all_rooms) {
        // Aggregate statistics across all rooms
        nlohmann::json resp;
        nlohmann::json rooms_stats = nlohmann::json::array();

        int total_rooms = 0;
        int total_members = 0;
        int total_messages = 0;
        int total_state_events = 0;
        int total_public_rooms = 0;
        int total_blocked_rooms = 0;
        int total_encrypted_rooms = 0;

        std::map<std::string, int> event_type_counts;
        std::map<std::string, int> join_rule_counts;
        std::map<std::string, int> room_version_counts;

        // Collect per-room stats
        {
            std::lock_guard<std::mutex> rlock(db::rooms_mutex);
            for (const auto& [rid, rec] : db::rooms) {
                total_rooms++;
                total_members += rec.joined_members;
                if (rec.public_room) total_public_rooms++;
                if (rec.blocked) total_blocked_rooms++;
                if (rec.is_encrypted) total_encrypted_rooms++;

                join_rule_counts[rec.join_rules.empty() ? "unknown" : rec.join_rules]++;
                room_version_counts[rec.room_version.empty() ? "unknown" : rec.room_version]++;

                nlohmann::json rs;
                rs["room_id"] = rid;
                rs["name"] = rec.name;
                rs["joined_members"] = rec.joined_members;
                rs["total_members"] = rec.total_members;

                // Timeline events count
                int msg_count = 0;
                int state_count = 0;
                {
                    std::lock_guard<std::mutex> tlock(g_timeline_mutex);
                    auto tit = g_room_timeline.find(rid);
                    if (tit != g_room_timeline.end()) {
                        msg_count = static_cast<int>(tit->second.size());
                        for (const auto& ev : tit->second) {
                            event_type_counts[ev.event_type]++;
                        }
                    }
                }
                {
                    std::lock_guard<std::mutex> slock(g_state_mutex);
                    auto sit = g_room_state.find(rid);
                    if (sit != g_room_state.end())
                        state_count = static_cast<int>(sit->second.size());
                }

                total_messages += msg_count;
                total_state_events += state_count;

                rs["message_count"] = msg_count;
                rs["state_event_count"] = state_count;
                rs["blocked"] = rec.blocked;
                rs["public"] = rec.public_room;
                rs["encrypted"] = rec.is_encrypted;
                rs["join_rules"] = rec.join_rules;

                // Last activity (latest event timestamp)
                std::string last_activity = rec.creation_ts;
                {
                    std::lock_guard<std::mutex> tlock(g_timeline_mutex);
                    auto tit = g_room_timeline.find(rid);
                    if (tit != g_room_timeline.end() && !tit->second.empty()) {
                        last_activity = tit->second.back().origin_server_ts;
                    }
                }
                if (!last_activity.empty())
                    rs["last_activity_ts"] = std::stoll(last_activity);

                rooms_stats.push_back(rs);
            }
        }

        // Sort rooms by message count descending
        std::sort(rooms_stats.begin(), rooms_stats.end(),
            [](const nlohmann::json& a, const nlohmann::json& b) {
                return a["message_count"].get<int>() > b["message_count"].get<int>();
            });

        resp["rooms"] = rooms_stats;
        resp["totals"]["rooms"] = total_rooms;
        resp["totals"]["total_members"] = total_members;
        resp["totals"]["total_messages"] = total_messages;
        resp["totals"]["total_state_events"] = total_state_events;
        resp["totals"]["public_rooms"] = total_public_rooms;
        resp["totals"]["blocked_rooms"] = total_blocked_rooms;
        resp["totals"]["encrypted_rooms"] = total_encrypted_rooms;

        // Event type breakdown
        nlohmann::json et_breakdown = nlohmann::json::object();
        for (const auto& [etype, count] : event_type_counts)
            et_breakdown[etype] = count;
        resp["event_type_breakdown"] = et_breakdown;

        // Join rule distribution
        nlohmann::json jr_dist = nlohmann::json::object();
        for (const auto& [jr, count] : join_rule_counts)
            jr_dist[jr] = count;
        resp["join_rule_distribution"] = jr_dist;

        // Room version distribution
        nlohmann::json ver_dist = nlohmann::json::object();
        for (const auto& [ver, count] : room_version_counts)
            ver_dist[ver] = count;
        resp["room_version_distribution"] = ver_dist;

        // Average members per room
        if (total_rooms > 0)
            resp["averages"]["members_per_room"] =
                static_cast<double>(total_members) / total_rooms;
        if (total_rooms > 0)
            resp["averages"]["messages_per_room"] =
                static_cast<double>(total_messages) / total_rooms;

        resp["generated_ts"] = std::stoll(now_ms());

        return resp;
    }

    // --- Per-room detailed statistics ---

    if (!is_valid_room_id(room_id))
        return error_response("M_INVALID_PARAM", "Invalid room ID", 400);

    // Verify room exists
    {
        std::lock_guard<std::mutex> lock(db::rooms_mutex);
        if (db::rooms.find(room_id) == db::rooms.end())
            return error_response("M_NOT_FOUND", "Room not found: " + room_id, 404);
    }

    nlohmann::json stats;
    stats["room_id"] = room_id;

    // Basic info
    {
        std::lock_guard<std::mutex> lock(db::rooms_mutex);
        auto it = db::rooms.find(room_id);
        if (it != db::rooms.end()) {
            stats["name"] = it->second.name;
            stats["creator"] = it->second.creator;
            stats["creation_ts"] = it->second.creation_ts.empty() ? 0 :
                std::stoll(it->second.creation_ts);
            stats["joined_members"] = it->second.joined_members;
            stats["invited_members"] = it->second.invited_members;
            stats["banned_members"] = it->second.banned_members;
            stats["total_members"] = it->second.total_members;
            stats["blocked"] = it->second.blocked;
            stats["encrypted"] = it->second.is_encrypted;
            stats["version"] = it->second.room_version;
            stats["join_rules"] = it->second.join_rules;
            stats["public"] = it->second.public_room;
        }
    }

    // Timeline statistics
    int total_events = 0;
    int oldest_depth = std::numeric_limits<int>::max();
    int newest_depth = 0;
    std::map<std::string, int> event_types;
    std::map<std::string, int> sender_counts;
    std::set<std::string> unique_senders;
    int64_t first_event_ts = 0;
    int64_t last_event_ts = 0;
    int encrypted_msgs = 0;
    int media_msgs = 0;
    int reaction_msgs = 0;
    int edit_msgs = 0;

    {
        std::lock_guard<std::mutex> lock(g_timeline_mutex);
        auto tit = g_room_timeline.find(room_id);
        if (tit != g_room_timeline.end()) {
            for (const auto& ev : tit->second) {
                total_events++;
                event_types[ev.event_type]++;
                sender_counts[ev.sender]++;
                unique_senders.insert(ev.sender);

                oldest_depth = std::min(oldest_depth, ev.depth);
                newest_depth = std::max(newest_depth, ev.depth);

                long long ts = 0;
                try { ts = std::stoll(ev.origin_server_ts); }
                catch (...) {}
                if (first_event_ts == 0 || ts < first_event_ts)
                    first_event_ts = ts;
                if (ts > last_event_ts) last_event_ts = ts;

                // Content analysis
                if (ev.content.contains("msgtype")) {
                    std::string mt = ev.content["msgtype"].get<std::string>();
                    if (mt == "m.image" || mt == "m.video" ||
                        mt == "m.audio" || mt == "m.file")
                        media_msgs++;
                }
                if (ev.content.contains("m.relates_to")) {
                    auto& rt = ev.content["m.relates_to"];
                    if (rt.contains("rel_type")) {
                        std::string rel = rt["rel_type"].get<std::string>();
                        if (rel == "m.annotation") reaction_msgs++;
                        if (rel == "m.replace") edit_msgs++;
                    }
                }
            }
        }
    }

    // State event statistics
    int state_event_count = 0;
    std::map<std::string, int> state_types;
    {
        std::lock_guard<std::mutex> lock(g_state_mutex);
        auto sit = g_room_state.find(room_id);
        if (sit != g_room_state.end()) {
            state_event_count = static_cast<int>(sit->second.size());
            for (const auto& se : sit->second)
                state_types[se.event_type]++;
        }
    }

    // Member statistics
    int member_count = 0;
    {
        std::lock_guard<std::mutex> lock(db::rooms_mutex);
        auto mit = db::room_members.find(room_id);
        if (mit != db::room_members.end())
            member_count = static_cast<int>(mit->second.size());
    }

    // Alias count
    int alias_count = 0;
    {
        std::lock_guard<std::mutex> lock(g_aliases_mutex);
        for (const auto& [a, arec] : g_aliases)
            if (arec.room_id == room_id) alias_count++;
    }

    // Build statistics response
    stats["total_events"] = total_events;
    stats["total_state_events"] = state_event_count;
    stats["total_aliases"] = alias_count;
    stats["current_members"] = member_count;
    stats["unique_senders"] = unique_senders.size();

    if (total_events > 0) {
        stats["oldest_depth"] = oldest_depth;
        stats["newest_depth"] = newest_depth;
        stats["depth_range"] = newest_depth - oldest_depth;
    }

    if (first_event_ts > 0) {
        stats["first_event_ts"] = first_event_ts;
        stats["first_event_iso8601"] = iso8601_from_epoch(first_event_ts);
    }
    if (last_event_ts > 0) {
        stats["last_event_ts"] = last_event_ts;
        stats["last_event_iso8601"] = iso8601_from_epoch(last_event_ts);
        if (first_event_ts > 0) {
            long long duration_ms = last_event_ts - first_event_ts;
            stats["activity_duration_ms"] = duration_ms;
            stats["activity_duration_days"] =
                std::round(duration_ms / 86400000.0 * 100.0) / 100.0;
        }
    }

    // Content breakdown
    nlohmann::json content_breakdown;
    content_breakdown["encrypted_messages"] = encrypted_msgs;
    content_breakdown["media_messages"] = media_msgs;
    content_breakdown["reactions"] = reaction_msgs;
    content_breakdown["edits"] = edit_msgs;
    content_breakdown["text_messages"] = total_events - encrypted_msgs - media_msgs;
    stats["content_breakdown"] = content_breakdown;

    // Event type distribution
    nlohmann::json et_dist = nlohmann::json::object();
    for (const auto& [et, cnt] : event_types)
        et_dist[et] = cnt;
    stats["event_type_distribution"] = et_dist;

    // State type distribution
    nlohmann::json st_dist = nlohmann::json::object();
    for (const auto& [st, cnt] : state_types)
        st_dist[st] = cnt;
    stats["state_type_distribution"] = st_dist;

    // Top senders
    std::vector<std::pair<std::string, int>> senders_vec(sender_counts.begin(), sender_counts.end());
    std::sort(senders_vec.begin(), senders_vec.end(),
        [](const auto& a, const auto& b) { return a.second > b.second; });
    nlohmann::json top_senders = nlohmann::json::array();
    int sender_limit = std::min(20, static_cast<int>(senders_vec.size()));
    for (int i = 0; i < sender_limit; ++i) {
        nlohmann::json s;
        s["user_id"] = senders_vec[i].first;
        s["count"] = senders_vec[i].second;
        s["percentage"] = (total_events > 0) ?
            std::round(100.0 * senders_vec[i].second / total_events * 100.0) / 100.0 : 0.0;
        top_senders.push_back(s);
    }
    stats["top_senders"] = top_senders;

    // Storage estimate
    long long estimated_bytes = total_events * 512LL + state_event_count * 1024LL;
    stats["estimated_storage_bytes"] = estimated_bytes;
    stats["estimated_storage_kb"] = estimated_bytes / 1024;
    stats["estimated_storage_mb"] = std::round(estimated_bytes / 1048576.0 * 100.0) / 100.0;

    stats["generated_ts"] = std::stoll(now_ms());

    // Cache
    {
        std::lock_guard<std::mutex> lock(g_room_stats_cache_mutex);
        g_room_stats_cache[room_id] = stats;
        g_stats_cache_age_ms.store(static_cast<int64_t>(std::stoll(now_ms())));
    }

    return stats;
}

// ============================================================================
// 15. POST /_synapse/admin/v1/purge_room/{roomId}
//     Full room purge: delete all state, timeline, aliases, members.
//     More aggressive than room deletion — wipes everything.
//     Body: { force: bool, purge_up_to_ts: number }
// ============================================================================

nlohmann::json admin_purge_room(const nlohmann::json& params,
                                 const nlohmann::json& body,
                                 const std::string& request_path) {
    init_demo_data(query_str(params, "server_name", "localhost:8008"));

    std::string room_id = extract_room_id_from_path(
        request_path, "/_synapse/admin/v1/purge_room/");
    if (room_id.empty() && params.contains("room_id"))
        room_id = params["room_id"].get<std::string>();

    if (!is_valid_room_id(room_id))
        return error_response("M_INVALID_PARAM", "Invalid room ID", 400);

    bool force = body.value("force", false);

    long long purge_up_to_ts = 0;
    if (body.contains("purge_up_to_ts")) {
        if (body["purge_up_to_ts"].is_number())
            purge_up_to_ts = body["purge_up_to_ts"].get<long long>();
        else if (body["purge_up_to_ts"].is_string())
            try { purge_up_to_ts = std::stoll(body["purge_up_to_ts"].get<std::string>()); }
            catch (...) {}
    }

    // Verify room exists
    {
        std::lock_guard<std::mutex> lock(db::rooms_mutex);
        if (db::rooms.find(room_id) == db::rooms.end())
            return error_response("M_NOT_FOUND", "Room not found: " + room_id, 404);
    }

    // Create purge entry
    std::string purge_id = "purge_full_" + random_hex(16);
    {
        std::lock_guard<std::mutex> lock(db::purges_mutex);
        db::PurgeEntry pe;
        pe.purge_id = purge_id;
        pe.room_id = room_id;
        pe.status = "active";
        pe.started_ts = now_ms();
        db::purges[purge_id] = pe;
    }

    nlohmann::json purge_report;
    int purged_state_events = 0;
    int purged_timeline_events = 0;
    int purged_aliases = 0;

    // Purge state events
    {
        std::lock_guard<std::mutex> lock(g_state_mutex);
        auto it = g_room_state.find(room_id);
        if (it != g_room_state.end()) {
            purged_state_events = static_cast<int>(it->second.size());
            g_room_state.erase(it);
        }
    }

    // Purge timeline events
    {
        std::lock_guard<std::mutex> lock(g_timeline_mutex);
        auto it = g_room_timeline.find(room_id);
        if (it != g_room_timeline.end()) {
            if (purge_up_to_ts > 0) {
                // Selective purge: remove events up to timestamp
                auto& events = it->second;
                auto new_end = std::remove_if(events.begin(), events.end(),
                    [purge_up_to_ts](const db::TimelineEvent& ev) {
                        long long ts = 0;
                        try { ts = std::stoll(ev.origin_server_ts); }
                        catch (...) { return false; }
                        return ts <= purge_up_to_ts;
                    });
                purged_timeline_events =
                    static_cast<int>(std::distance(new_end, events.end()));
                events.erase(new_end, events.end());
            } else {
                purged_timeline_events = static_cast<int>(it->second.size());
                g_room_timeline.erase(it);
            }
        }
    }

    // Purge aliases
    {
        std::lock_guard<std::mutex> lock(g_aliases_mutex);
        for (auto it = g_aliases.begin(); it != g_aliases.end();) {
            if (it->second.room_id == room_id) {
                purged_aliases++;
                it = g_aliases.erase(it);
            } else {
                ++it;
            }
        }
    }

    // Purge visibility
    {
        std::lock_guard<std::mutex> lock(g_visibility_mutex);
        g_visibility.erase(room_id);
    }

    // Purge members
    int purged_members = 0;
    {
        std::lock_guard<std::mutex> lock(db::rooms_mutex);
        auto mit = db::room_members.find(room_id);
        if (mit != db::room_members.end()) {
            purged_members = static_cast<int>(mit->second.size());
            db::room_members.erase(mit);
        }
    }

    // Purge stats cache
    {
        std::lock_guard<std::mutex> lock(g_room_stats_cache_mutex);
        g_room_stats_cache.erase(room_id);
    }

    // Mark purge complete
    {
        std::lock_guard<std::mutex> lock(db::purges_mutex);
        auto& p = db::purges[purge_id];
        p.status = "complete";
        p.completed_ts = now_ms();
    }

    purge_report["purge_id"] = purge_id;
    purge_report["room_id"] = room_id;
    purge_report["purged_state_events"] = purged_state_events;
    purge_report["purged_timeline_events"] = purged_timeline_events;
    purge_report["purged_aliases"] = purged_aliases;
    purge_report["purged_members"] = purged_members;
    purge_report["total_purged"] = purged_state_events + purged_timeline_events +
        purged_aliases + purged_members;
    purge_report["status"] = "complete";
    purge_report["force"] = force;
    if (purge_up_to_ts > 0)
        purge_report["purge_up_to_ts"] = purge_up_to_ts;

    return purge_report;
}

// ============================================================================
// 16. GET /_synapse/admin/v1/rooms/{roomId}/state
//     Dump all state events for a room. Optionally filtered by event type.
//     Query params: event_type, state_key
// ============================================================================

nlohmann::json admin_room_state_dump(const nlohmann::json& params,
                                      const nlohmann::json& body,
                                      const std::string& request_path) {
    init_demo_data(query_str(params, "server_name", "localhost:8008"));

    std::string room_id = extract_room_id_from_path(
        request_path, "/_synapse/admin/v1/rooms/");
    if (room_id.empty() && params.contains("room_id"))
        room_id = params["room_id"].get<std::string>();

    if (!is_valid_room_id(room_id))
        return error_response("M_INVALID_PARAM", "Invalid room ID", 400);

    std::string event_type_filter = query_str(params, "event_type", "");
    std::string state_key_filter = query_str(params, "state_key", "");

    // Verify room exists
    {
        std::lock_guard<std::mutex> lock(db::rooms_mutex);
        if (db::rooms.find(room_id) == db::rooms.end())
            return error_response("M_NOT_FOUND", "Room not found: " + room_id, 404);
    }

    nlohmann::json resp;
    resp["room_id"] = room_id;

    nlohmann::json state_arr = nlohmann::json::array();
    {
        std::lock_guard<std::mutex> lock(g_state_mutex);
        auto sit = g_room_state.find(room_id);
        if (sit != g_room_state.end()) {
            for (const auto& se : sit->second) {
                if (!event_type_filter.empty() && se.event_type != event_type_filter)
                    continue;
                if (!state_key_filter.empty() && se.state_key != state_key_filter)
                    continue;

                nlohmann::json ev;
                ev["type"] = se.event_type;
                ev["state_key"] = se.state_key;
                ev["sender"] = se.sender;
                ev["origin_server_ts"] = std::stoll(se.origin_server_ts);
                if (!se.origin_server_ts.empty())
                    ev["origin_server_iso8601"] =
                        iso8601_from_epoch(std::stoll(se.origin_server_ts));
                ev["event_id"] = se.event_id;
                ev["content"] = se.content;
                if (!se.unsigned_data.is_null())
                    ev["unsigned"] = se.unsigned_data;
                if (!se.prev_content_json.is_null())
                    ev["prev_content"] = se.prev_content_json;
                state_arr.push_back(ev);
            }
        }
    }

    resp["state"] = state_arr;
    resp["total_state_events"] = state_arr.size();

    // State summary by type
    nlohmann::json type_summary = nlohmann::json::object();
    {
        std::lock_guard<std::mutex> lock(g_state_mutex);
        auto sit = g_room_state.find(room_id);
        if (sit != g_room_state.end()) {
            for (const auto& se : sit->second) {
                if (!type_summary.contains(se.event_type))
                    type_summary[se.event_type] = 0;
                type_summary[se.event_type] = type_summary[se.event_type].get<int>() + 1;
            }
        }
    }
    resp["state_summary_by_type"] = type_summary;

    return resp;
}

// ============================================================================
// 17. GET /_synapse/admin/v1/rooms/{roomId}/members
//     Dump all members of a room with detailed membership information.
//     Query params: membership (join|invite|ban|leave), user_id_search
// ============================================================================

nlohmann::json admin_room_members_dump(const nlohmann::json& params,
                                        const nlohmann::json& body,
                                        const std::string& request_path) {
    init_demo_data(query_str(params, "server_name", "localhost:8008"));

    std::string room_id = extract_room_id_from_path(
        request_path, "/_synapse/admin/v1/rooms/");
    if (room_id.empty() && params.contains("room_id"))
        room_id = params["room_id"].get<std::string>();

    if (!is_valid_room_id(room_id))
        return error_response("M_INVALID_PARAM", "Invalid room ID", 400);

    std::string membership_filter = query_str(params, "membership", "");
    std::string user_search = query_str(params, "user_id_search", "");

    // Verify room exists
    {
        std::lock_guard<std::mutex> lock(db::rooms_mutex);
        if (db::rooms.find(room_id) == db::rooms.end())
            return error_response("M_NOT_FOUND", "Room not found: " + room_id, 404);
    }

    nlohmann::json resp;
    resp["room_id"] = room_id;

    // Collect members with details
    nlohmann::json members_arr = nlohmann::json::array();
    std::vector<std::string> member_ids;
    {
        std::lock_guard<std::mutex> lock(db::rooms_mutex);
        auto mit = db::room_members.find(room_id);
        if (mit != db::room_members.end())
            member_ids = mit->second;
    }

    int joined_count = 0;
    int invited_count = 0;
    int banned_count = 0;

    for (const auto& uid : member_ids) {
        if (!user_search.empty() && !matches_filter(uid, user_search))
            continue;

        nlohmann::json m;
        m["user_id"] = uid;

        // Get user details from users store
        {
            std::lock_guard<std::mutex> lock(db::users_mutex);
            auto uit = db::users.find(uid);
            if (uit != db::users.end()) {
                m["displayname"] = uit->second.displayname;
                m["avatar_url"] = uit->second.avatar_url;
                m["deactivated"] = uit->second.deactivated;
                m["is_admin"] = uit->second.admin;
                m["user_type"] = uit->second.user_type;
                m["creation_ts"] = uit->second.creation_ts.empty() ? 0 :
                    std::stoll(uit->second.creation_ts);
            } else {
                m["displayname"] = uid;
                m["deactivated"] = false;
                m["is_admin"] = false;
            }
        }

        // Determine membership from state
        m["membership"] = "join";
        joined_count++;

        // Check membership log for join time
        {
            std::lock_guard<std::mutex> lock(g_membership_log_mutex);
            for (auto it = g_membership_log.rbegin();
                 it != g_membership_log.rend(); ++it) {
                if (it->room_id == room_id && it->user_id == uid &&
                    it->membership == "join") {
                    m["joined_at"] = it->timestamp;
                    m["joined_by"] = it->performed_by;
                    m["join_reason"] = it->reason;
                    break;
                }
            }
        }

        // Check power levels from room state
        {
            std::lock_guard<std::mutex> lock(g_state_mutex);
            auto sit = g_room_state.find(room_id);
            if (sit != g_room_state.end()) {
                for (const auto& se : sit->second) {
                    if (se.event_type == "m.room.power_levels" &&
                        se.content.contains("users") &&
                        se.content["users"].contains(uid)) {
                        m["power_level"] = se.content["users"][uid].get<int>();
                        break;
                    }
                }
            }
        }

        if (!membership_filter.empty() &&
            m.value("membership", "join") != membership_filter)
            continue;

        members_arr.push_back(m);
    }

    // Also include banned members from room state
    {
        std::lock_guard<std::mutex> lock(g_state_mutex);
        auto sit = g_room_state.find(room_id);
        if (sit != g_room_state.end()) {
            for (const auto& se : sit->second) {
                if (se.event_type == "m.room.member" &&
                    se.content.contains("membership") &&
                    (se.content["membership"] == "ban" || se.content["membership"] == "leave")) {
                    if (!user_search.empty() &&
                        !matches_filter(se.state_key, user_search))
                        continue;

                    if (!membership_filter.empty() &&
                        se.content["membership"].get<std::string>() != membership_filter)
                        continue;

                    nlohmann::json m;
                    m["user_id"] = se.state_key;
                    m["membership"] = se.content["membership"];
                    if (se.content.contains("displayname"))
                        m["displayname"] = se.content["displayname"];
                    if (se.content.contains("reason"))
                        m["reason"] = se.content["reason"];
                    m["sender"] = se.sender;
                    if (se.content["membership"] == "ban") banned_count++;
                    if (!m.contains("displayname"))
                        m["displayname"] = se.state_key;
                    members_arr.push_back(m);
                }
            }
        }
    }

    // Membership log entries for full history
    nlohmann::json membership_log = nlohmann::json::array();
    {
        std::lock_guard<std::mutex> lock(g_membership_log_mutex);
        for (const auto& log_entry : g_membership_log) {
            if (log_entry.room_id != room_id) continue;
            if (!user_search.empty() &&
                !matches_filter(log_entry.user_id, user_search))
                continue;
            nlohmann::json le;
            le["user_id"] = log_entry.user_id;
            le["membership"] = log_entry.membership;
            le["timestamp"] = log_entry.timestamp;
            le["reason"] = log_entry.reason;
            le["performed_by"] = log_entry.performed_by;
            membership_log.push_back(le);
        }
    }

    resp["members"] = members_arr;
    resp["total_members"] = members_arr.size();
    resp["joined_count"] = joined_count;
    resp["invited_count"] = invited_count;
    resp["banned_count"] = banned_count;
    resp["membership_log"] = membership_log;
    resp["membership_log_count"] = membership_log.size();

    return resp;
}

// ============================================================================
// 18. GET /_synapse/admin/v1/rooms/{roomId}/timeline
//     Export room timeline events with filtering and pagination.
//     Query params: from, limit, event_type, sender, since, until,
//                   order (asc|desc), include_state, filter_content
// ============================================================================

nlohmann::json admin_room_timeline_export(const nlohmann::json& params,
                                           const nlohmann::json& body,
                                           const std::string& request_path) {
    init_demo_data(query_str(params, "server_name", "localhost:8008"));

    std::string room_id = extract_room_id_from_path(
        request_path, "/_synapse/admin/v1/rooms/");
    if (room_id.empty() && params.contains("room_id"))
        room_id = params["room_id"].get<std::string>();

    if (!is_valid_room_id(room_id))
        return error_response("M_INVALID_PARAM", "Invalid room ID", 400);

    // Parse query params
    int from = query_int(params, "from", 0);
    int limit = query_int(params, "limit", 100);
    limit = std::max(1, std::min(limit, 1000));

    std::string event_type_filter = query_str(params, "event_type", "");
    std::string sender_filter = query_str(params, "sender", "");
    std::string order = query_str(params, "order", "asc");
    bool include_state = query_bool(params, "include_state", true);
    std::string filter_content = query_str(params, "filter_content", "");

    long long since_ts = 0;
    if (params.contains("since") && params["since"].is_string())
        try { since_ts = std::stoll(params["since"].get<std::string>()); }
        catch (...) {}
    else if (params.contains("since") && params["since"].is_number())
        since_ts = params["since"].get<long long>();

    long long until_ts = 0;
    if (params.contains("until") && params["until"].is_string())
        try { until_ts = std::stoll(params["until"].get<std::string>()); }
        catch (...) {}
    else if (params.contains("until") && params["until"].is_number())
        until_ts = params["until"].get<long long>();

    // Verify room exists
    {
        std::lock_guard<std::mutex> lock(db::rooms_mutex);
        if (db::rooms.find(room_id) == db::rooms.end())
            return error_response("M_NOT_FOUND", "Room not found: " + room_id, 404);
    }

    // Collect timeline events
    std::vector<db::TimelineEvent> timeline;
    {
        std::lock_guard<std::mutex> lock(g_timeline_mutex);
        auto tit = g_room_timeline.find(room_id);
        if (tit != g_room_timeline.end())
            timeline = tit->second;
    }

    // Also collect state events as timeline entries if requested
    if (include_state) {
        std::lock_guard<std::mutex> lock(g_state_mutex);
        auto sit = g_room_state.find(room_id);
        if (sit != g_room_state.end()) {
            for (const auto& se : sit->second) {
                db::TimelineEvent te;
                te.event_id = se.event_id;
                te.room_id = room_id;
                te.sender = se.sender;
                te.event_type = se.event_type;
                te.origin_server_ts = se.origin_server_ts;
                te.content = se.content;
                te.state_key = se.state_key;
                timeline.push_back(te);
            }
        }
    }

    // Filter
    std::vector<db::TimelineEvent> filtered;
    for (const auto& ev : timeline) {
        if (!event_type_filter.empty() && ev.event_type != event_type_filter)
            continue;
        if (!sender_filter.empty() && ev.sender != sender_filter)
            continue;

        // Time range filter
        long long ev_ts = 0;
        try { ev_ts = std::stoll(ev.origin_server_ts); } catch (...) {}
        if (since_ts > 0 && ev_ts < since_ts) continue;
        if (until_ts > 0 && ev_ts > until_ts) continue;

        // Content filter (search in body/content)
        if (!filter_content.empty()) {
            bool match = false;
            if (ev.content.contains("body") &&
                matches_filter(ev.content["body"].get<std::string>(), filter_content))
                match = true;
            if (ev.content.contains("formatted_body") &&
                matches_filter(ev.content["formatted_body"].get<std::string>(), filter_content))
                match = true;
            if (!match) continue;
        }

        filtered.push_back(ev);
    }

    // Sort
    std::sort(filtered.begin(), filtered.end(),
        [&order](const db::TimelineEvent& a, const db::TimelineEvent& b) {
            long long ta = 0, tb = 0;
            try { ta = std::stoll(a.origin_server_ts); } catch (...) {}
            try { tb = std::stoll(b.origin_server_ts); } catch (...) {}
            if (ta != tb)
                return (order == "desc") ? (ta > tb) : (ta < tb);
            return (order == "desc") ? (a.depth > b.depth) : (a.depth < b.depth);
        });

    int total = static_cast<int>(filtered.size());

    // Paginate
    nlohmann::json events_arr = nlohmann::json::array();
    int end = std::min(from + limit, total);
    for (int i = from; i < end; ++i) {
        const auto& ev = filtered[i];
        nlohmann::json jev;
        jev["event_id"] = ev.event_id;
        jev["sender"] = ev.sender;
        jev["type"] = ev.event_type;
        jev["origin_server_ts"] = ev.origin_server_ts.empty() ? 0 :
            std::stoll(ev.origin_server_ts);
        if (!ev.origin_server_ts.empty())
            jev["origin_server_iso8601"] =
                iso8601_from_epoch(std::stoll(ev.origin_server_ts));
        jev["content"] = ev.content;
        if (!ev.state_key.empty()) {
            jev["state_key"] = ev.state_key;
            jev["is_state_event"] = true;
        }
        jev["depth"] = ev.depth;
        jev["room_id"] = ev.room_id;
        events_arr.push_back(jev);
    }

    // Build response
    nlohmann::json resp;
    resp["room_id"] = room_id;
    resp["events"] = events_arr;
    resp["total_events"] = total;
    resp["offset"] = from;
    resp["limit"] = limit;
    resp["order"] = order;
    if (end < total)
        resp["next_batch"] = end;
    resp["include_state"] = include_state;

    // Summary statistics
    nlohmann::json summary;
    std::map<std::string, int> type_counts;
    std::set<std::string> senders;
    for (const auto& ev : filtered) {
        type_counts[ev.event_type]++;
        senders.insert(ev.sender);
    }
    summary["total_filtered"] = total;
    summary["unique_senders"] = senders.size();
    summary["event_types"] = type_counts;
    resp["summary"] = summary;

    resp["export_ts"] = std::stoll(now_ms());
    return resp;
}

// ============================================================================
// 19. GET /_synapse/admin/v1/rooms/{roomId}/aliases
//     Get all aliases for a specific room.
// ============================================================================

nlohmann::json admin_get_room_aliases(const nlohmann::json& params,
                                       const nlohmann::json& body,
                                       const std::string& request_path) {
    init_demo_data(query_str(params, "server_name", "localhost:8008"));

    std::string room_id = extract_room_id_from_path(
        request_path, "/_synapse/admin/v1/rooms/");
    if (room_id.empty() && params.contains("room_id"))
        room_id = params["room_id"].get<std::string>();

    if (!is_valid_room_id(room_id))
        return error_response("M_INVALID_PARAM", "Invalid room ID", 400);

    // Verify room exists
    {
        std::lock_guard<std::mutex> lock(db::rooms_mutex);
        if (db::rooms.find(room_id) == db::rooms.end())
            return error_response("M_NOT_FOUND", "Room not found: " + room_id, 404);
    }

    nlohmann::json aliases_arr = nlohmann::json::array();
    std::string canonical;
    {
        std::lock_guard<std::mutex> lock(g_aliases_mutex);
        for (const auto& [alias, arec] : g_aliases) {
            if (arec.room_id == room_id) {
                nlohmann::json a;
                a["alias"] = arec.alias;
                a["creator"] = arec.creator;
                a["creation_ts"] = arec.creation_ts.empty() ? 0 :
                    std::stoll(arec.creation_ts);
                a["published"] = arec.is_published;
                aliases_arr.push_back(a);
            }
        }
    }
    {
        std::lock_guard<std::mutex> lock(db::rooms_mutex);
        auto it = db::rooms.find(room_id);
        if (it != db::rooms.end())
            canonical = it->second.canonical_alias;
    }

    nlohmann::json resp;
    resp["room_id"] = room_id;
    resp["aliases"] = aliases_arr;
    resp["alias_count"] = aliases_arr.size();
    if (!canonical.empty())
        resp["canonical_alias"] = canonical;
    return resp;
}

// ============================================================================
// 20. GET /_synapse/admin/v1/rooms/{roomId}/visibility
//     Get the visibility settings for a specific room.
// ============================================================================

nlohmann::json admin_get_room_visibility(const nlohmann::json& params,
                                          const nlohmann::json& body,
                                          const std::string& request_path) {
    init_demo_data(query_str(params, "server_name", "localhost:8008"));

    std::string room_id = extract_room_id_from_path(
        request_path, "/_synapse/admin/v1/rooms/");
    if (room_id.empty() && params.contains("room_id"))
        room_id = params["room_id"].get<std::string>();

    if (!is_valid_room_id(room_id))
        return error_response("M_INVALID_PARAM", "Invalid room ID", 400);

    // Verify room exists
    {
        std::lock_guard<std::mutex> lock(db::rooms_mutex);
        if (db::rooms.find(room_id) == db::rooms.end())
            return error_response("M_NOT_FOUND", "Room not found: " + room_id, 404);
    }

    nlohmann::json resp;
    resp["room_id"] = room_id;

    {
        std::lock_guard<std::mutex> lock(g_visibility_mutex);
        auto vit = g_visibility.find(room_id);
        if (vit != g_visibility.end()) {
            resp["visibility"] = vit->second.visibility;
            resp["is_published"] = vit->second.is_published;
            if (!vit->second.published_alias.empty())
                resp["published_alias"] = vit->second.published_alias;
            resp["topic"] = vit->second.topic;
            resp["avatar_url"] = vit->second.avatar_url;
            resp["joined_members"] = vit->second.joined_members;
        } else {
            resp["visibility"] = "private";
            resp["is_published"] = false;
        }
    }

    // Also include room-level public flag
    {
        std::lock_guard<std::mutex> lock(db::rooms_mutex);
        auto it = db::rooms.find(room_id);
        if (it != db::rooms.end()) {
            resp["public_room_flag"] = it->second.public_room;
            resp["join_rules"] = it->second.join_rules;
            resp["guest_access"] = it->second.guest_access;
            resp["history_visibility"] = it->second.history_visibility;
        }
    }

    return resp;
}

// ============================================================================
// 21. GET /_synapse/admin/v1/room_directory/search
//     Search the room directory with advanced filtering.
//     Query params: q, order_by, dir, from, limit, include_private,
//                   room_type, min_members, max_members
// ============================================================================

nlohmann::json admin_search_room_directory(const nlohmann::json& params,
                                            const nlohmann::json& body,
                                            const std::string& request_path) {
    init_demo_data(query_str(params, "server_name", "localhost:8008"));

    std::string query = query_str(params, "q", "");
    int from = query_int(params, "from", 0);
    int limit = query_int(params, "limit", 50);
    limit = std::max(1, std::min(limit, 200));

    std::string order_by = query_str(params, "order_by", "num_joined_members");
    std::string dir = query_str(params, "dir", "f");
    bool include_private = query_bool(params, "include_private", false);

    std::string room_type_filter = query_str(params, "room_type", "");
    int min_members = query_int(params, "min_members", -1);
    int max_members = query_int(params, "max_members", -1);

    // Collect eligible rooms
    struct SearchEntry {
        std::string room_id;
        std::string name;
        std::string alias;
        std::string topic;
        int joined_members = 0;
        bool is_public = false;
    };
    std::vector<SearchEntry> results;

    {
        std::lock_guard<std::mutex> lock(db::rooms_mutex);
        for (const auto& [rid, rec] : db::rooms) {
            if (!include_private && !rec.public_room) continue;
            if (rec.blocked) continue;

            SearchEntry entry;
            entry.room_id = rid;
            entry.name = rec.name;
            entry.topic = rec.topic;
            entry.joined_members = rec.joined_members;
            entry.is_public = rec.public_room;

            // Get alias
            {
                std::lock_guard<std::mutex> alock(g_aliases_mutex);
                for (const auto& [a, arec] : g_aliases) {
                    if (arec.room_id == rid) {
                        if (entry.alias.empty() || arec.is_published)
                            entry.alias = a;
                        if (arec.is_published) break;
                    }
                }
                if (entry.alias.empty())
                    entry.alias = rec.canonical_alias;
            }

            // Member count filter
            if (min_members >= 0 && entry.joined_members < min_members) continue;
            if (max_members >= 0 && entry.joined_members > max_members) continue;

            // Room type filter
            if (!room_type_filter.empty() && rec.room_type != room_type_filter)
                continue;

            // Search query
            if (!query.empty()) {
                bool match = matches_filter(entry.name, query) ||
                             matches_filter(entry.alias, query) ||
                             matches_filter(entry.topic, query) ||
                             matches_filter(entry.room_id, query);
                if (!match) continue;
            }

            results.push_back(entry);
        }
    }

    // Sort
    std::sort(results.begin(), results.end(),
        [&](const SearchEntry& a, const SearchEntry& b) {
            int cmp = 0;
            if (order_by == "name")
                cmp = a.name.compare(b.name);
            else if (order_by == "num_joined_members")
                cmp = a.joined_members - b.joined_members;
            else if (order_by == "alias")
                cmp = a.alias.compare(b.alias);
            else
                cmp = a.joined_members - b.joined_members;
            if (cmp == 0) cmp = a.room_id.compare(b.room_id);
            return (dir == "b") ? (cmp > 0) : (cmp < 0);
        });

    int total = static_cast<int>(results.size());

    nlohmann::json results_arr = nlohmann::json::array();
    int end = std::min(from + limit, total);
    for (int i = from; i < end; ++i) {
        const auto& entry = results[i];
        nlohmann::json r;
        r["room_id"] = entry.room_id;
        r["name"] = entry.name;
        r["topic"] = entry.topic;
        r["canonical_alias"] = entry.alias;
        r["num_joined_members"] = entry.joined_members;
        r["public"] = entry.is_public;
        results_arr.push_back(r);
    }

    nlohmann::json resp;
    resp["results"] = results_arr;
    resp["total"] = total;
    resp["offset"] = from;
    resp["limit"] = limit;
    resp["query"] = query;
    if (end < total)
        resp["next_batch"] = std::to_string(end);
    return resp;
}

// ============================================================================
// 22. GET /_synapse/admin/v1/rooms/{roomId}/moderation
//     Get full moderation status and history for a room.
// ============================================================================

nlohmann::json admin_room_moderation_info(const nlohmann::json& params,
                                           const nlohmann::json& body,
                                           const std::string& request_path) {
    init_demo_data(query_str(params, "server_name", "localhost:8008"));

    std::string room_id = extract_room_id_from_path(
        request_path, "/_synapse/admin/v1/rooms/");
    if (room_id.empty() && params.contains("room_id"))
        room_id = params["room_id"].get<std::string>();

    if (!is_valid_room_id(room_id))
        return error_response("M_INVALID_PARAM", "Invalid room ID", 400);

    nlohmann::json resp;
    resp["room_id"] = room_id;

    // Room status
    {
        std::lock_guard<std::mutex> lock(db::rooms_mutex);
        auto it = db::rooms.find(room_id);
        if (it == db::rooms.end())
            return error_response("M_NOT_FOUND", "Room not found: " + room_id, 404);

        resp["name"] = it->second.name;
        resp["blocked"] = it->second.blocked;
        resp["federatable"] = it->second.federatable;
        resp["join_rules"] = it->second.join_rules;
        resp["guest_access"] = it->second.guest_access;
        resp["history_visibility"] = it->second.history_visibility;
        resp["encrypted"] = it->second.is_encrypted;
        resp["encryption_algorithm"] = it->second.encryption_algorithm;
        resp["version"] = it->second.room_version;
        resp["creator"] = it->second.creator;
        resp["creation_ts"] = it->second.creation_ts.empty() ? 0 :
            std::stoll(it->second.creation_ts);
    }

    // Visibility
    {
        std::lock_guard<std::mutex> lock(g_visibility_mutex);
        auto vit = g_visibility.find(room_id);
        resp["published"] = (vit != g_visibility.end()) ?
            vit->second.is_published : false;
        resp["visibility"] = (vit != g_visibility.end()) ?
            vit->second.visibility : "private";
    }

    // Ban list from room state
    nlohmann::json ban_list = nlohmann::json::array();
    {
        std::lock_guard<std::mutex> lock(g_state_mutex);
        auto sit = g_room_state.find(room_id);
        if (sit != g_room_state.end()) {
            for (const auto& se : sit->second) {
                if (se.event_type == "m.room.member" &&
                    se.content.contains("membership") &&
                    se.content["membership"] == "ban") {
                    nlohmann::json ban;
                    ban["user_id"] = se.state_key;
                    if (se.content.contains("reason"))
                        ban["reason"] = se.content["reason"];
                    if (se.content.contains("displayname"))
                        ban["displayname"] = se.content["displayname"];
                    ban["banned_by"] = se.sender;
                    ban_list.push_back(ban);
                }
            }
        }
    }
    resp["bans"] = ban_list;
    resp["ban_count"] = ban_list.size();

    // Membership log (recent)
    nlohmann::json recent_log = nlohmann::json::array();
    {
        std::lock_guard<std::mutex> lock(g_membership_log_mutex);
        int count = 0;
        for (auto it = g_membership_log.rbegin();
             it != g_membership_log.rend() && count < 50; ++it) {
            if (it->room_id == room_id) {
                nlohmann::json le;
                le["user_id"] = it->user_id;
                le["membership"] = it->membership;
                le["timestamp"] = it->timestamp;
                le["reason"] = it->reason;
                le["performed_by"] = it->performed_by;
                recent_log.push_back(le);
                count++;
            }
        }
    }
    resp["recent_membership_log"] = recent_log;

    // Event reports for this room
    nlohmann::json room_reports = nlohmann::json::array();
    {
        std::lock_guard<std::mutex> lock(db::reports_mutex);
        for (const auto& [rid, report] : db::event_reports) {
            if (report.room_id == room_id) {
                nlohmann::json rpt;
                rpt["id"] = report.id;
                rpt["event_id"] = report.event_id;
                rpt["user_id"] = report.user_id;
                rpt["reason"] = report.reason;
                rpt["score"] = report.score;
                rpt["handled"] = report.handled;
                if (report.handled) {
                    rpt["handled_by"] = report.handled_by;
                    rpt["handled_ts"] = std::stoll(report.handled_ts);
                }
                room_reports.push_back(rpt);
            }
        }
    }
    resp["event_reports"] = room_reports;
    resp["event_report_count"] = room_reports.size();

    return resp;
}

// ============================================================================
// 23. POST /_synapse/admin/v1/room_directory/sync
//     Manually trigger a room directory synchronization.
//     Body: { full_sync: bool }
// ============================================================================

nlohmann::json admin_sync_room_directory(const nlohmann::json& params,
                                          const nlohmann::json& body,
                                          const std::string& request_path) {
    init_demo_data(query_str(params, "server_name", "localhost:8008"));

    bool full_sync = body.value("full_sync", false);

    nlohmann::json sync_report;
    sync_report["sync_id"] = "sync_" + random_hex(16);
    sync_report["full_sync"] = full_sync;

    int synced_rooms = 0;
    int updated_rooms = 0;
    int removed_from_directory = 0;
    int new_published = 0;

    // Sync visibility with room records
    {
        std::lock_guard<std::mutex> vlock(g_visibility_mutex);
        std::lock_guard<std::mutex> rlock(db::rooms_mutex);

        for (const auto& [rid, rec] : db::rooms) {
            synced_rooms++;
            auto vit = g_visibility.find(rid);
            if (vit != g_visibility.end()) {
                // Update member counts
                if (vit->second.joined_members != rec.joined_members) {
                    vit->second.joined_members = rec.joined_members;
                    updated_rooms++;
                }
                // Sync published status with public flag
                if (rec.public_room != vit->second.is_published) {
                    vit->second.is_published = rec.public_room;
                    vit->second.visibility = rec.public_room ? "public" : "private";
                    updated_rooms++;
                }
            } else if (full_sync) {
                db::RoomVisibilitySettings vs;
                vs.room_id = rid;
                vs.visibility = rec.public_room ? "public" : "private";
                vs.is_published = rec.public_room;
                vs.joined_members = rec.joined_members;
                g_visibility[rid] = vs;
                if (rec.public_room) new_published++;
            }
        }
    }

    // Remove visibility entries for rooms that no longer exist
    {
        std::lock_guard<std::mutex> vlock(g_visibility_mutex);
        std::lock_guard<std::mutex> rlock(db::rooms_mutex);
        for (auto it = g_visibility.begin(); it != g_visibility.end();) {
            if (db::rooms.find(it->first) == db::rooms.end()) {
                if (it->second.is_published) removed_from_directory++;
                it = g_visibility.erase(it);
            } else {
                ++it;
            }
        }
    }

    // Push state events for published rooms
    if (full_sync) {
        std::lock_guard<std::mutex> vlock(g_visibility_mutex);
        std::lock_guard<std::mutex> slock(g_state_mutex);

        for (const auto& [rid, vs] : g_visibility) {
            if (vs.is_published) {
                db::StateEvent se;
                se.event_type = "m.room.join_rules";
                se.state_key = "";
                se.sender = "@server:localhost";
                se.origin_server_ts = now_ms();
                se.event_id = generate_event_id();
                se.content["join_rule"] = "public";
                g_room_state[rid].push_back(se);
            }
        }
    }

    sync_report["synced_rooms"] = synced_rooms;
    sync_report["updated_rooms"] = updated_rooms;
    sync_report["removed_from_directory"] = removed_from_directory;
    sync_report["new_published"] = new_published;
    sync_report["completed_ts"] = std::stoll(now_ms());
    sync_report["success"] = true;

    return sync_report;
}

// ============================================================================
// 24. GET /_synapse/admin/v1/room_directory/stats
//     Get overall room directory statistics.
// ============================================================================

nlohmann::json admin_room_directory_stats(const nlohmann::json& params,
                                           const nlohmann::json& body,
                                           const std::string& request_path) {
    init_demo_data(query_str(params, "server_name", "localhost:8008"));

    nlohmann::json stats;

    // Alias statistics
    {
        std::lock_guard<std::mutex> lock(g_aliases_mutex);
        stats["total_aliases"] = g_aliases.size();
        int published_aliases = 0;
        std::set<std::string> unique_rooms_with_aliases;
        for (const auto& [a, arec] : g_aliases) {
            if (arec.is_published) published_aliases++;
            unique_rooms_with_aliases.insert(arec.room_id);
        }
        stats["published_aliases"] = published_aliases;
        stats["unpublished_aliases"] = static_cast<int>(g_aliases.size()) - published_aliases;
        stats["rooms_with_aliases"] = unique_rooms_with_aliases.size();
    }

    // Visibility statistics
    {
        std::lock_guard<std::mutex> lock(g_visibility_mutex);
        int total_visible = static_cast<int>(g_visibility.size());
        int public_count = 0;
        int private_count = 0;
        int published_count = 0;
        for (const auto& [rid, vs] : g_visibility) {
            if (vs.visibility == "public") public_count++;
            else private_count++;
            if (vs.is_published) published_count++;
        }
        stats["rooms_with_visibility"] = total_visible;
        stats["public_rooms"] = public_count;
        stats["private_rooms"] = private_count;
        stats["published_rooms"] = published_count;
    }

    // Room statistics (all)
    {
        std::lock_guard<std::mutex> lock(db::rooms_mutex);
        stats["total_rooms"] = db::rooms.size();
        int blocked = 0, public_rooms = 0, encrypted = 0;
        int total_joined = 0;
        for (const auto& [rid, rec] : db::rooms) {
            if (rec.blocked) blocked++;
            if (rec.public_room) public_rooms++;
            if (rec.is_encrypted) encrypted++;
            total_joined += rec.joined_members;
        }
        stats["blocked_rooms"] = blocked;
        stats["public_rooms_flag"] = public_rooms;
        stats["encrypted_rooms"] = encrypted;
        stats["total_joined_members"] = total_joined;
        stats["avg_members_per_room"] = db::rooms.empty() ? 0.0 :
            static_cast<double>(total_joined) / db::rooms.size();
    }

    // State and timeline stats
    {
        std::lock_guard<std::mutex> slock(g_state_mutex);
        std::lock_guard<std::mutex> tlock(g_timeline_mutex);
        int total_state = 0, total_timeline = 0;
        for (const auto& [rid, state] : g_room_state)
            total_state += static_cast<int>(state.size());
        for (const auto& [rid, timeline] : g_room_timeline)
            total_timeline += static_cast<int>(timeline.size());
        stats["total_state_events"] = total_state;
        stats["total_timeline_events"] = total_timeline;
    }

    // Membership log stats
    {
        std::lock_guard<std::mutex> lock(g_membership_log_mutex);
        stats["total_membership_changes"] = g_membership_log.size();
        int joins = 0, leaves = 0, bans = 0;
        for (const auto& entry : g_membership_log) {
            if (entry.membership == "join") joins++;
            else if (entry.membership == "leave") leaves++;
            else if (entry.membership == "ban") bans++;
        }
        stats["membership_joins"] = joins;
        stats["membership_leaves"] = leaves;
        stats["membership_bans"] = bans;
    }

    stats["generated_ts"] = std::stoll(now_ms());
    return stats;
}

// ============================================================================
// 25. POST /_synapse/admin/v1/rooms/{roomId}/set_canonical_alias
//     Set the canonical alias for a room.
//     Body: { alias: string }
// ============================================================================

nlohmann::json admin_set_canonical_alias(const nlohmann::json& params,
                                          const nlohmann::json& body,
                                          const std::string& request_path) {
    init_demo_data(query_str(params, "server_name", "localhost:8008"));

    std::string room_id = extract_room_id_from_path(
        request_path, "/_synapse/admin/v1/rooms/");
    if (room_id.empty() && params.contains("room_id"))
        room_id = params["room_id"].get<std::string>();

    if (!is_valid_room_id(room_id))
        return error_response("M_INVALID_PARAM", "Invalid room ID", 400);

    if (!body.contains("alias") || !body["alias"].is_string())
        return error_response("M_MISSING_PARAM", "alias is required", 400);

    std::string alias = body["alias"].get<std::string>();

    // Verify alias exists and belongs to this room
    {
        std::lock_guard<std::mutex> lock(g_aliases_mutex);
        auto it = g_aliases.find(alias);
        if (it == g_aliases.end())
            return error_response("M_NOT_FOUND", "Alias not found: " + alias, 404);
        if (it->second.room_id != room_id)
            return error_response("M_INVALID_PARAM",
                "Alias does not belong to this room", 400);
    }

    // Set canonical alias
    {
        std::lock_guard<std::mutex> lock(db::rooms_mutex);
        auto it = db::rooms.find(room_id);
        if (it == db::rooms.end())
            return error_response("M_NOT_FOUND", "Room not found", 404);
        it->second.canonical_alias = alias;
    }

    // Add canonical alias state event
    {
        std::lock_guard<std::mutex> lock(g_state_mutex);
        std::string admin_user = params.value("admin_user", "admin");
        db::StateEvent se;
        se.event_type = "m.room.canonical_alias";
        se.state_key = "";
        se.sender = admin_user;
        se.origin_server_ts = now_ms();
        se.event_id = generate_event_id();
        se.content["alias"] = alias;
        g_room_state[room_id].push_back(se);
    }

    nlohmann::json resp;
    resp["success"] = true;
    resp["room_id"] = room_id;
    resp["canonical_alias"] = alias;
    resp["timestamp"] = iso8601_now();
    return resp;
}

// ============================================================================
// 26. POST /_synapse/admin/v1/rooms/{roomId}/clear_canonical_alias
//     Clear the canonical alias for a room. Body: {}
// ============================================================================

nlohmann::json admin_clear_canonical_alias(const nlohmann::json& params,
                                            const nlohmann::json& body,
                                            const std::string& request_path) {
    init_demo_data(query_str(params, "server_name", "localhost:8008"));

    std::string room_id = extract_room_id_from_path(
        request_path, "/_synapse/admin/v1/rooms/");
    if (room_id.empty() && params.contains("room_id"))
        room_id = params["room_id"].get<std::string>();

    if (!is_valid_room_id(room_id))
        return error_response("M_INVALID_PARAM", "Invalid room ID", 400);

    {
        std::lock_guard<std::mutex> lock(db::rooms_mutex);
        auto it = db::rooms.find(room_id);
        if (it == db::rooms.end())
            return error_response("M_NOT_FOUND", "Room not found", 404);
        it->second.canonical_alias = "";
    }

    nlohmann::json resp;
    resp["success"] = true;
    resp["room_id"] = room_id;
    resp["canonical_alias"] = nullptr;
    resp["timestamp"] = iso8601_now();
    return resp;
}

// ============================================================================
// 27. POST /_synapse/admin/v1/room_directory/rebuild
//     Full rebuild of the room directory from room data.
//     This is an expensive operation that re-indexes all rooms.
//     Body: { confirm: bool }
// ============================================================================

nlohmann::json admin_rebuild_room_directory(const nlohmann::json& params,
                                             const nlohmann::json& body,
                                             const std::string& request_path) {
    init_demo_data(query_str(params, "server_name", "localhost:8008"));

    if (!body.value("confirm", false))
        return error_response("M_MISSING_PARAM",
            "Set confirm=true to proceed with full rebuild", 400);

    nlohmann::json report;
    std::string rebuild_id = "rebuild_" + random_hex(16);
    report["rebuild_id"] = rebuild_id;
    report["started_ts"] = std::stoll(now_ms());

    int processed = 0;
    int published = 0;
    int created_visibility = 0;
    int linked_aliases = 0;

    // Rebuild visibility entries
    {
        std::lock_guard<std::mutex> vlock(g_visibility_mutex);
        std::lock_guard<std::mutex> rlock(db::rooms_mutex);

        for (const auto& [rid, rec] : db::rooms) {
            processed++;
            auto it = g_visibility.find(rid);
            if (it == g_visibility.end()) {
                db::RoomVisibilitySettings vs;
                vs.room_id = rid;
                vs.visibility = rec.public_room ? "public" : "private";
                vs.is_published = rec.public_room;
                vs.joined_members = rec.joined_members;
                vs.topic = rec.topic;
                g_visibility[rid] = vs;
                created_visibility++;
                if (rec.public_room) published++;
            } else {
                it->second.joined_members = rec.joined_members;
                it->second.is_published = rec.public_room;
                it->second.visibility = rec.public_room ? "public" : "private";
                if (rec.public_room) published++;
            }

            // Link alias
            std::lock_guard<std::mutex> alock(g_aliases_mutex);
            for (const auto& [a, arec] : g_aliases) {
                if (arec.room_id == rid) {
                    if (it == g_visibility.end()) {
                        g_visibility[rid].published_alias = a;
                    } else if (it->second.published_alias.empty()) {
                        it->second.published_alias = a;
                    }
                    linked_aliases++;
                    break;
                }
            }
        }
    }

    // Invalidate stats cache
    {
        std::lock_guard<std::mutex> lock(g_room_stats_cache_mutex);
        g_room_stats_cache.clear();
        g_stats_cache_age_ms.store(0);
    }

    report["processed_rooms"] = processed;
    report["published_rooms"] = published;
    report["created_visibility_entries"] = created_visibility;
    report["linked_aliases"] = linked_aliases;
    report["completed_ts"] = std::stoll(now_ms());
    report["success"] = true;

    return report;
}

// ============================================================================
// 28. GET /_synapse/admin/v1/room_aliases/{alias}
//     Get detailed information about a specific alias.
// ============================================================================

nlohmann::json admin_get_alias_details(const nlohmann::json& params,
                                        const nlohmann::json& body,
                                        const std::string& request_path) {
    init_demo_data(query_str(params, "server_name", "localhost:8008"));

    // Extract alias from path
    std::string alias;
    const std::string prefix = "/_synapse/admin/v1/room_aliases/";
    auto pos = request_path.find(prefix);
    if (pos != std::string::npos)
        alias = url_decode(request_path.substr(pos + prefix.size()));
    if (alias.empty() && params.contains("alias"))
        alias = params["alias"].get<std::string>();

    if (!is_valid_alias(alias))
        return error_response("M_INVALID_PARAM",
            "Invalid alias format. Expected: #localpart:domain", 400);

    std::lock_guard<std::mutex> lock(g_aliases_mutex);
    auto it = g_aliases.find(alias);
    if (it == g_aliases.end())
        return error_response("M_NOT_FOUND", "Alias not found: " + alias, 404);

    const auto& arec = it->second;
    nlohmann::json resp;
    resp["alias"] = arec.alias;
    resp["room_id"] = arec.room_id;
    resp["creator"] = arec.creator;
    resp["creation_ts"] = arec.creation_ts.empty() ? 0 : std::stoll(arec.creation_ts);
    if (!arec.creation_ts.empty())
        resp["creation_iso8601"] = iso8601_from_epoch(std::stoll(arec.creation_ts));
    resp["published"] = arec.is_published;

    // Room info
    {
        std::lock_guard<std::mutex> rlock(db::rooms_mutex);
        auto rit = db::rooms.find(arec.room_id);
        if (rit != db::rooms.end()) {
            resp["room_name"] = rit->second.name;
            resp["room_topic"] = rit->second.topic;
            resp["room_joined_members"] = rit->second.joined_members;
            resp["room_blocked"] = rit->second.blocked;
            resp["room_federatable"] = rit->second.federatable;
            resp["room_public"] = rit->second.public_room;
            resp["room_canonical_alias"] = rit->second.canonical_alias;
        } else {
            resp["room_name"] = arec.room_id;
        }
    }

    return resp;
}

// ============================================================================
// 29. POST /_synapse/admin/v1/room_aliases/bulk_create
//     Create multiple room aliases in one request.
//     Body: { aliases: [{ alias, room_id, published }] }
// ============================================================================

nlohmann::json admin_bulk_create_aliases(const nlohmann::json& params,
                                          const nlohmann::json& body,
                                          const std::string& request_path) {
    init_demo_data(query_str(params, "server_name", "localhost:8008"));

    if (!body.contains("aliases") || !body["aliases"].is_array())
        return error_response("M_MISSING_PARAM",
            "aliases array is required", 400);

    std::string server_name = query_str(params, "server_name", "localhost:8008");

    nlohmann::json report;
    nlohmann::json created_arr = nlohmann::json::array();
    nlohmann::json errors_arr = nlohmann::json::array();
    int success_count = 0;
    int error_count = 0;

    for (const auto& entry : body["aliases"]) {
        if (!entry.is_object() || !entry.contains("alias") || !entry.contains("room_id")) {
            errors_arr.push_back({
                {"entry", entry},
                {"error", "Each entry must have 'alias' and 'room_id'"}
            });
            error_count++;
            continue;
        }

        std::string alias = entry["alias"].get<std::string>();
        std::string room_id = entry["room_id"].get<std::string>();
        std::string creator = entry.value("creator",
            params.value("admin_user", "admin"));
        bool published = entry.value("published", false);

        if (!starts_with(alias, "#")) {
            errors_arr.push_back({
                {"alias", alias},
                {"error", "Alias must start with #"}
            });
            error_count++;
            continue;
        }

        if (alias.find(':') == std::string::npos)
            alias = alias + ":" + server_name;

        if (!is_valid_alias(alias)) {
            errors_arr.push_back({
                {"alias", alias},
                {"error", "Invalid alias format"}
            });
            error_count++;
            continue;
        }

        if (!is_valid_room_id(room_id)) {
            errors_arr.push_back({
                {"alias", alias},
                {"room_id", room_id},
                {"error", "Invalid room ID"}
            });
            error_count++;
            continue;
        }

        // Check room exists
        {
            std::lock_guard<std::mutex> lock(db::rooms_mutex);
            if (db::rooms.find(room_id) == db::rooms.end()) {
                errors_arr.push_back({
                    {"alias", alias},
                    {"room_id", room_id},
                    {"error", "Room not found"}
                });
                error_count++;
                continue;
            }
        }

        // Create alias
        {
            std::lock_guard<std::mutex> lock(g_aliases_mutex);
            if (g_aliases.find(alias) != g_aliases.end()) {
                errors_arr.push_back({
                    {"alias", alias},
                    {"error", "Alias already exists"}
                });
                error_count++;
                continue;
            }

            db::AliasRecord arec;
            arec.alias = alias;
            arec.room_id = room_id;
            arec.creator = creator;
            arec.creation_ts = now_ms();
            arec.is_published = published;
            g_aliases[alias] = arec;
        }

        created_arr.push_back({
            {"alias", alias},
            {"room_id", room_id},
            {"created", true}
        });
        success_count++;
    }

    report["created"] = created_arr;
    report["errors"] = errors_arr;
    report["success_count"] = success_count;
    report["error_count"] = error_count;
    report["total"] = static_cast<int>(body["aliases"].size());
    report["timestamp"] = iso8601_now();

    return report;
}

// ============================================================================
// 30. POST /_synapse/admin/v1/room_aliases/bulk_delete
//     Delete multiple room aliases in one request.
//     Body: { aliases: [string] }
// ============================================================================

nlohmann::json admin_bulk_delete_aliases(const nlohmann::json& params,
                                          const nlohmann::json& body,
                                          const std::string& request_path) {
    init_demo_data(query_str(params, "server_name", "localhost:8008"));

    if (!body.contains("aliases") || !body["aliases"].is_array())
        return error_response("M_MISSING_PARAM",
            "aliases array is required", 400);

    nlohmann::json report;
    nlohmann::json deleted_arr = nlohmann::json::array();
    nlohmann::json errors_arr = nlohmann::json::array();
    int success_count = 0;
    int error_count = 0;

    for (const auto& entry : body["aliases"]) {
        if (!entry.is_string()) {
            errors_arr.push_back({
                {"entry", entry},
                {"error", "Each entry must be an alias string"}
            });
            error_count++;
            continue;
        }

        std::string alias = entry.get<std::string>();

        {
            std::lock_guard<std::mutex> lock(g_aliases_mutex);
            auto it = g_aliases.find(alias);
            if (it == g_aliases.end()) {
                errors_arr.push_back({
                    {"alias", alias},
                    {"error", "Alias not found"}
                });
                error_count++;
                continue;
            }
            g_aliases.erase(it);
        }

        deleted_arr.push_back(alias);
        success_count++;
    }

    report["deleted"] = deleted_arr;
    report["errors"] = errors_arr;
    report["success_count"] = success_count;
    report["error_count"] = error_count;
    report["total"] = static_cast<int>(body["aliases"].size());
    report["timestamp"] = iso8601_now();

    return report;
}

// ============================================================================
// Router dispatch table for room directory endpoints
// ============================================================================

using AdminHandler = std::function<nlohmann::json(
    const nlohmann::json& params,
    const nlohmann::json& body,
    const std::string& request_path)>;

struct RouteEntry {
    std::string method;
    std::string path_pattern;
    bool is_prefix;
    AdminHandler handler;
};

std::vector<RouteEntry> build_room_directory_routes() {
    std::vector<RouteEntry> routes;

    // Room listing and details
    routes.push_back({"GET",  "/_synapse/admin/v1/rooms", false,
        admin_list_all_rooms});
    routes.push_back({"GET",  "/_synapse/admin/v1/rooms/", true,
        [](const nlohmann::json& p, const nlohmann::json& b,
           const std::string& rp) -> nlohmann::json {
            // Check for sub-paths
            if (rp.find("/force_join") != std::string::npos) {
                return error_response("M_UNKNOWN",
                    "force_join uses POST method", 405);
            }
            if (rp.find("/force_leave") != std::string::npos) {
                return error_response("M_UNKNOWN",
                    "force_leave uses POST method", 405);
            }
            if (rp.find("/delete") != std::string::npos) {
                return error_response("M_UNKNOWN",
                    "delete uses POST method", 405);
            }
            if (rp.find("/statistics") != std::string::npos) {
                return admin_room_statistics(p, b, rp);
            }
            if (rp.find("/state") != std::string::npos) {
                return admin_room_state_dump(p, b, rp);
            }
            if (rp.find("/members") != std::string::npos) {
                return admin_room_members_dump(p, b, rp);
            }
            if (rp.find("/timeline") != std::string::npos) {
                return admin_room_timeline_export(p, b, rp);
            }
            if (rp.find("/aliases") != std::string::npos) {
                return admin_get_room_aliases(p, b, rp);
            }
            if (rp.find("/visibility") != std::string::npos) {
                return admin_get_room_visibility(p, b, rp);
            }
            if (rp.find("/moderation") != std::string::npos) {
                return admin_room_moderation_info(p, b, rp);
            }
            if (rp.find("/publish") != std::string::npos) {
                return error_response("M_UNKNOWN",
                    "publish uses POST method", 405);
            }
            if (rp.find("/unpublish") != std::string::npos) {
                return error_response("M_UNKNOWN",
                    "unpublish uses POST method", 405);
            }
            if (rp.find("/block") != std::string::npos) {
                return error_response("M_UNKNOWN",
                    "block uses POST method", 405);
            }
            if (rp.find("/set_canonical_alias") != std::string::npos) {
                return error_response("M_UNKNOWN",
                    "set_canonical_alias uses POST method", 405);
            }
            if (rp.find("/clear_canonical_alias") != std::string::npos) {
                return error_response("M_UNKNOWN",
                    "clear_canonical_alias uses POST method", 405);
            }
            return admin_room_details(p, b, rp);
        }});

    // Room actions (POST)
    routes.push_back({"POST", "/_synapse/admin/v1/rooms/", true,
        [](const nlohmann::json& p, const nlohmann::json& b,
           const std::string& rp) -> nlohmann::json {
            if (rp.find("/force_join") != std::string::npos)
                return admin_force_join_room(p, b, rp);
            if (rp.find("/force_leave") != std::string::npos)
                return admin_force_leave_room(p, b, rp);
            if (rp.find("/delete") != std::string::npos)
                return admin_delete_room(p, b, rp);
            if (rp.find("/block") != std::string::npos)
                return admin_block_room(p, b, rp);
            if (rp.find("/visibility") != std::string::npos)
                return admin_set_room_visibility(p, b, rp);
            if (rp.find("/publish") != std::string::npos)
                return admin_publish_room(p, b, rp);
            if (rp.find("/unpublish") != std::string::npos)
                return admin_unpublish_room(p, b, rp);
            if (rp.find("/set_canonical_alias") != std::string::npos)
                return admin_set_canonical_alias(p, b, rp);
            if (rp.find("/clear_canonical_alias") != std::string::npos)
                return admin_clear_canonical_alias(p, b, rp);
            return error_response("M_UNKNOWN",
                "Unknown room POST action", 400);
        }});

    // Room aliases
    routes.push_back({"GET",  "/_synapse/admin/v1/room_aliases", false,
        admin_list_room_aliases});
    routes.push_back({"GET",  "/_synapse/admin/v1/room_aliases/", true,
        admin_get_alias_details});
    routes.push_back({"POST", "/_synapse/admin/v1/room_aliases/create", false,
        admin_create_alias});
    routes.push_back({"POST", "/_synapse/admin/v1/room_aliases/delete", false,
        admin_delete_alias});
    routes.push_back({"POST", "/_synapse/admin/v1/room_aliases/bulk_create", false,
        admin_bulk_create_aliases});
    routes.push_back({"POST", "/_synapse/admin/v1/room_aliases/bulk_delete", false,
        admin_bulk_delete_aliases});

    // Public rooms
    routes.push_back({"GET",  "/_synapse/admin/v1/public_rooms", false,
        admin_list_public_rooms});

    // Room directory search
    routes.push_back({"GET",  "/_synapse/admin/v1/room_directory/search", false,
        admin_search_room_directory});
    routes.push_back({"GET",  "/_synapse/admin/v1/room_directory/stats", false,
        admin_room_directory_stats});
    routes.push_back({"POST", "/_synapse/admin/v1/room_directory/sync", false,
        admin_sync_room_directory});
    routes.push_back({"POST", "/_synapse/admin/v1/room_directory/rebuild", false,
        admin_rebuild_room_directory});

    // Purge room
    routes.push_back({"POST", "/_synapse/admin/v1/purge_room/", true,
        admin_purge_room});

    return routes;
}

// ============================================================================
// Public API: entry point for room directory admin request dispatching
// ============================================================================

nlohmann::json dispatch_room_directory_request(const std::string& method,
                                                const std::string& path,
                                                const nlohmann::json& params,
                                                const nlohmann::json& body) {
    // Static route table, built once
    static std::vector<RouteEntry> routes = build_room_directory_routes();

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
        "Unrecognized room directory endpoint: " + method + " " + path, 404);
}

// ============================================================================
// Initialization helper — called by server startup to seed room directory data
// ============================================================================

void init_room_directory(const std::string& server_name) {
    init_demo_data(server_name);
}

// ============================================================================
// Diagnostics / health check for room directory subsystem
// ============================================================================

nlohmann::json room_directory_health_check() {
    nlohmann::json health;
    health["subsystem"] = "room_directory";
    health["status"] = "healthy";

    {
        std::lock_guard<std::mutex> lock(g_aliases_mutex);
        health["total_aliases"] = g_aliases.size();
    }
    {
        std::lock_guard<std::mutex> lock(g_visibility_mutex);
        health["visibility_entries"] = g_visibility.size();
    }
    {
        std::lock_guard<std::mutex> lock(g_state_mutex);
        health["rooms_with_state"] = g_room_state.size();
    }
    {
        std::lock_guard<std::mutex> lock(g_timeline_mutex);
        health["rooms_with_timeline"] = g_room_timeline.size();
    }
    {
        std::lock_guard<std::mutex> lock(g_membership_log_mutex);
        health["membership_log_entries"] = g_membership_log.size();
    }

    health["timestamp_ms"] = std::stoll(now_ms());
    return health;
}

} // namespace admin
} // namespace progressive
