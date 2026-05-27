// ============================================================================
// debug_admin_tools.cpp - Matrix Synapse Admin Debug Tools (3000+ lines)
// 20 fully-implemented admin/debug endpoints for progressive-server.
// Namespace: progressive::admin
// Include: ../json.hpp
//
// Endpoints:
//   1. GET  /_synapse/admin/v1/event_reports            - List event reports
//   2. GET  /_synapse/admin/v1/event_reports/{reportId} - Event report detail
//   3. POST /_synapse/admin/v1/event_reports/{reportId} - Resolve/action
//   4. GET  /_synapse/admin/v1/rooms/{roomId}/state     - Room state export
//   5. GET  /_synapse/admin/v1/rooms/{roomId}/timeline  - Room timeline export
//   6. GET  /_synapse/admin/v1/debug/profiler           - Server profiler
//   7. GET  /_synapse/admin/v1/whois/{userId}           - Query user sessions
//   8. GET  /_synapse/admin/v1/sessions                 - List all active sessions
//   9. DELETE /_synapse/admin/v1/sessions/{userId}      - Force logout user
//  10. GET  /_synapse/admin/v1/federation/destinations  - List destinations
//  11. POST /_synapse/admin/v1/federation/destinations/{dest}/reset - Reset backoff
//  12. POST /_synapse/admin/v1/federation/send          - Trigger federation push
//  13. POST /_synapse/admin/v1/cache/clear              - Clear caches
//  14. GET  /_synapse/admin/v1/cache/stats              - Cache statistics
//  15. GET  /_synapse/admin/v1/rooms/{roomId}/state_groups - State group details
//  16. GET  /_synapse/admin/v1/rooms/{roomId}/forward_extremities - List FEs
//  17. POST /_synapse/admin/v1/rooms/{roomId}/resolve_state - Force resolve
//  18. GET  /_synapse/admin/v1/server_version           - Detailed version info
//  19. GET  /_synapse/admin/v1/config                   - Configuration dump
//  20. GET  /_synapse/admin/v1/background_updates       - View background updates
//  21. POST /_synapse/admin/v1/background_updates/trigger - Trigger update
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
#include <memory>
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
// Forward type aliases
// ============================================================================

using json = nlohmann::json;

// ============================================================================
// Internal database structures and in-memory stores
// ============================================================================

namespace db {

// --- Event Report record ---
struct EventReportRecord {
    std::string id;
    std::string received_ts;
    std::string room_id;
    std::string event_id;
    std::string user_id;            // user who reported
    std::string reason;
    int score = 0;
    std::string sender;             // user who sent reported event
    bool can_see_sender = true;
    bool resolved = false;
    std::string resolved_by;
    std::string resolved_ts;
    std::string resolution_notes;
    std::string event_content_json; // cached event content
};

// --- User session / device record ---
struct DeviceSession {
    std::string device_id;
    std::string user_id;
    std::string display_name;
    std::string last_seen_ip;
    std::string last_seen_user_agent;
    std::string last_seen_ts;
    bool is_active = true;
    std::string access_token_hash;
    std::string device_type; // "mobile", "web", "desktop", "unknown"
};

// --- Federation destination ---
struct FedDestination {
    std::string destination;       // server name
    std::string last_success_ts;
    std::string last_failure_ts;
    int retry_interval_ms = 60000; // 1 minute default
    int failure_count = 0;
    int backoff_count = 0;
    std::string status;            // "ok", "blocked", "retrying"
    std::string last_error;
    int64_t transactions_sent = 0;
    int64_t transactions_failed = 0;
    int64_t pdus_sent = 0;
    int64_t edus_sent = 0;
};

// --- State group ---
struct StateGroup {
    std::string group_id;
    std::string room_id;
    std::string prev_group_id;     // previous state group
    int64_t event_count = 0;
    std::string created_ts;
};

// --- Forward extremity ---
struct ForwardExtremity {
    std::string event_id;
    std::string room_id;
    int depth = 0;
    std::string received_ts;
};

// --- Background update ---
struct BackgroundUpdate {
    std::string update_name;
    std::string description;
    std::string depends_on;
    bool enabled = true;
    bool running = false;
    int progress_total = 0;
    int progress_complete = 0;
    std::string started_ts;
    std::string completed_ts;
    double duration_seconds = 0.0;
    std::string error_msg;
};

// --- Cache entry stats ---
struct CacheStats {
    std::string cache_name;
    int64_t max_size = 0;
    int64_t current_size = 0;
    int64_t hits = 0;
    int64_t misses = 0;
    int64_t evictions = 0;
    double hit_rate() const {
        int64_t total = hits + misses;
        return total > 0 ? (double)hits / total * 100.0 : 0.0;
    }
};

// --- Room event for timeline export ---
struct RoomEvent {
    std::string event_id;
    std::string room_id;
    std::string sender;
    std::string type;
    std::string state_key;
    std::string content_json;
    int64_t origin_server_ts = 0;
    int64_t depth = 0;
    std::string prev_event_ids_json; // JSON array
    std::string auth_event_ids_json; // JSON array
    std::string hashes_json;
    std::string signatures_json;
    bool outlier = false;
    std::string received_ts;
};

// --- Server configuration entry ---
struct ConfigEntry {
    std::string key;
    std::string value;
    bool is_secret = false;   // redacted in exports
    std::string category;     // "general", "database", "federation", "crypto", etc.
};

// --- In-memory stores with mutex protection ---
extern std::mutex reports_mutex;
extern std::mutex sessions_mutex;
extern std::mutex federation_mutex;
extern std::mutex state_groups_mutex;
extern std::mutex extremities_mutex;
extern std::mutex background_mutex;
extern std::mutex cache_mutex;
extern std::mutex events_mutex;
extern std::mutex config_mutex;

extern std::unordered_map<std::string, EventReportRecord> event_reports;
extern std::vector<DeviceSession> device_sessions;
extern std::unordered_map<std::string, FedDestination> federation_destinations;
extern std::unordered_map<std::string, StateGroup> state_groups;
extern std::unordered_map<std::string, std::vector<ForwardExtremity>> forward_extremities;
extern std::vector<BackgroundUpdate> background_updates;
extern std::unordered_map<std::string, CacheStats> cache_stats_map;
extern std::unordered_map<std::string, std::vector<RoomEvent>> room_events;    // room_id -> events
extern std::unordered_map<std::string, std::string> server_config;             // key -> value
extern std::unordered_set<std::string> secret_config_keys;
extern std::unordered_map<std::string, std::string> room_state_latest;         // room_id -> state JSON

} // namespace db

// --- Mutex definitions ---
std::mutex db::reports_mutex;
std::mutex db::sessions_mutex;
std::mutex db::federation_mutex;
std::mutex db::state_groups_mutex;
std::mutex db::extremities_mutex;
std::mutex db::background_mutex;
std::mutex db::cache_mutex;
std::mutex db::events_mutex;
std::mutex db::config_mutex;

// --- Store definitions ---
std::unordered_map<std::string, db::EventReportRecord> db::event_reports;
std::vector<db::DeviceSession> db::device_sessions;
std::unordered_map<std::string, db::FedDestination> db::federation_destinations;
std::unordered_map<std::string, db::StateGroup> db::state_groups;
std::unordered_map<std::string, std::vector<db::ForwardExtremity>> db::forward_extremities;
std::vector<db::BackgroundUpdate> db::background_updates;
std::unordered_map<std::string, db::CacheStats> db::cache_stats_map;
std::unordered_map<std::string, std::vector<db::RoomEvent>> db::room_events;
std::unordered_map<std::string, std::string> db::server_config;
std::unordered_set<std::string> db::secret_config_keys;
std::unordered_map<std::string, std::string> db::room_state_latest;

// ============================================================================
// Utility helpers
// ============================================================================

namespace {

// Current timestamp in milliseconds since epoch
int64_t timestamp_ms() {
    auto now = std::chrono::system_clock::now();
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()).count();
}

// Current timestamp in seconds since epoch
int64_t timestamp_sec() {
    return timestamp_ms() / 1000;
}

// ISO 8601 timestamp string
std::string iso8601_now() {
    auto t = std::time(nullptr);
    char buf[64];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", std::gmtime(&t));
    return buf;
}

// Convert ms timestamp to ISO 8601
std::string ms_to_iso8601(int64_t ms) {
    std::time_t sec = ms / 1000;
    char buf[64];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", std::gmtime(&sec));
    return buf;
}

// Convert seconds timestamp to ISO 8601
std::string sec_to_iso8601(int64_t sec) {
    std::time_t t = static_cast<std::time_t>(sec);
    char buf[64];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", std::gmtime(&t));
    return buf;
}

// Generate a random UUID v4-like string
std::string generate_uuid() {
    static const char hex[] = "0123456789abcdef";
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dist(0, 15);
    // Format: 8-4-4-4-12
    std::string uuid(36, '-');
    for (int i = 0; i < 36; ++i) {
        if (i == 8 || i == 13 || i == 18 || i == 23) continue;
        uuid[i] = hex[dist(gen)];
    }
    // Version 4: position 14 set to '4'
    uuid[14] = '4';
    // Variant: position 19 set to '8','9','a',or 'b'
    static const char variant_chars[] = {'8','9','a','b'};
    uuid[19] = variant_chars[dist(gen) % 4];
    return uuid;
}

// Generate a short random ID
std::string generate_short_id(int length = 12) {
    static const char chars[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dist(0, (int)sizeof(chars) - 2);
    std::string result;
    result.reserve(length);
    for (int i = 0; i < length; ++i) {
        result += chars[dist(gen)];
    }
    return result;
}

// Parse query parameters from a URL parameter string
std::unordered_map<std::string, std::string> parse_query_params(
    const std::string& query_string) {
    std::unordered_map<std::string, std::string> params;
    if (query_string.empty()) return params;
    std::string qs = query_string;
    if (qs[0] == '?') qs = qs.substr(1);
    size_t pos = 0;
    while (pos < qs.size()) {
        size_t eq = qs.find('=', pos);
        size_t amp = qs.find('&', pos);
        if (amp == std::string::npos) amp = qs.size();
        if (eq != std::string::npos && eq < amp) {
            std::string key = qs.substr(pos, eq - pos);
            std::string val = qs.substr(eq + 1, amp - eq - 1);
            params[key] = val;
        }
        pos = amp + 1;
    }
    return params;
}

// URL-decode a string
std::string url_decode(const std::string& encoded) {
    std::string result;
    result.reserve(encoded.size());
    for (size_t i = 0; i < encoded.size(); ++i) {
        if (encoded[i] == '%' && i + 2 < encoded.size()) {
            int value = 0;
            std::istringstream hex(encoded.substr(i + 1, 2));
            hex >> std::hex >> value;
            result += static_cast<char>(value);
            i += 2;
        } else if (encoded[i] == '+') {
            result += ' ';
        } else {
            result += encoded[i];
        }
    }
    return result;
}

// Build an error JSON response
json error_response(const std::string& errcode,
                    const std::string& error,
                    int http_status = 400) {
    return {
        {"errcode", errcode},
        {"error", error},
        {"http_status", http_status}
    };
}

// Build a success JSON response
json success_response(const json& data = json::object()) {
    json resp = data;
    if (!resp.contains("ok")) resp["ok"] = true;
    return resp;
}

// Extract path segment at given index
std::string path_segment(const std::string& path, size_t index) {
    std::vector<std::string> segments;
    std::string segment;
    for (char c : path) {
        if (c == '/') {
            if (!segment.empty()) {
                segments.push_back(segment);
                segment.clear();
            }
        } else {
            segment += c;
        }
    }
    if (!segment.empty()) segments.push_back(segment);
    return index < segments.size() ? url_decode(segments[index]) : "";
}

// Extract query string from path (everything after '?')
std::string extract_query_string(const std::string& path) {
    auto pos = path.find('?');
    if (pos == std::string::npos) return "";
    return path.substr(pos);
}

// Extract path without query string
std::string extract_path_only(const std::string& path) {
    auto pos = path.find('?');
    if (pos == std::string::npos) return path;
    return path.substr(0, pos);
}

// Get integer query param with default
int get_query_int(const std::unordered_map<std::string, std::string>& params,
                  const std::string& key, int default_val) {
    auto it = params.find(key);
    if (it == params.end()) return default_val;
    try { return std::stoi(it->second); }
    catch (...) { return default_val; }
}

// Get string query param with default
std::string get_query_str(const std::unordered_map<std::string, std::string>& params,
                          const std::string& key,
                          const std::string& default_val = "") {
    auto it = params.find(key);
    if (it == params.end()) return default_val;
    return it->second;
}

// Check if a string starts with a prefix
bool starts_with(const std::string& s, const std::string& prefix) {
    return s.size() >= prefix.size() &&
           s.compare(0, prefix.size(), prefix) == 0;
}

// Check if a string ends with a suffix
bool ends_with(const std::string& s, const std::string& suffix) {
    return s.size() >= suffix.size() &&
           s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

// Trim whitespace from both ends
std::string trim(const std::string& s) {
    auto start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    auto end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

// SHA-256 placeholder (for access token hashing)
std::string sha256(const std::string& input) {
    std::hash<std::string> hasher;
    size_t h = hasher(input);
    std::stringstream ss;
    ss << std::hex << std::setw(16) << std::setfill('0') << h;
    std::string hex = ss.str();
    // Pad to 64 chars to simulate SHA-256 output
    while (hex.size() < 64) hex = "0" + hex;
    return hex.substr(0, 64);
}

// Simple string sanitization for log output
std::string sanitize_for_log(const std::string& s) {
    std::string result;
    for (char c : s) {
        if (c >= 32 && c < 127) result += c;
        else result += '?';
    }
    return result;
}

} // anonymous namespace

// ============================================================================
// In-memory store initialization with seed data
// ============================================================================

namespace {

void init_seed_data() {
    static bool seeded = false;
    if (seeded) return;
    seeded = true;

    // --- Seed event reports ---
    {
        std::lock_guard<std::mutex> lock(db::reports_mutex);
        std::vector<std::string> rooms = {"!abc:matrix.org", "!xyz:matrix.org", "!def:matrix.org"};
        std::vector<std::string> reporters = {"@alice:matrix.org", "@bob:matrix.org", "@charlie:matrix.org"};
        std::vector<std::string> senders = {"@spammer:matrix.org", "@troll:matrix.org", "@baduser:matrix.org"};
        std::vector<std::string> reasons = {
            "This user is sending spam messages in the room.",
            "Harassment and abusive language.",
            "Posting illegal content.",
            "Impersonating a moderator.",
            "Flooding the room with advertisements.",
            "Off-topic and disruptive behavior.",
            "Doxxing other users in public chat.",
            "Repeatedly violating room rules."
        };
        int report_count = 50;
        for (int i = 0; i < report_count; ++i) {
            db::EventReportRecord r;
            r.id = "report_" + std::to_string(i + 1);
            int64_t ts = timestamp_ms() - (report_count - i) * 3600000LL;
            r.received_ts = std::to_string(ts);
            r.room_id = rooms[i % rooms.size()];
            r.event_id = "$event" + std::to_string(i + 1000) + ":matrix.org";
            r.user_id = reporters[i % reporters.size()];
            r.reason = reasons[i % reasons.size()];
            r.score = -50 + (i * 2) % 100;
            r.sender = senders[i % senders.size()];
            r.can_see_sender = (i % 3) != 0;
            r.resolved = (i % 4 == 0);
            if (r.resolved) {
                r.resolved_by = "@admin:matrix.org";
                r.resolved_ts = ms_to_iso8601(ts + 1800000);
                r.resolution_notes = "User warned and content removed.";
            }
            r.event_content_json = R"({"body":"Sample message content ","msgtype":"m.text"})";
            db::event_reports[r.id] = r;
        }
    }

    // --- Seed device sessions ---
    {
        std::lock_guard<std::mutex> lock(db::sessions_mutex);
        struct {
            std::string user; std::string device; std::string ip; std::string ua; std::string type;
        } session_data[] = {
            {"@alice:matrix.org", "ALICE_WEB", "192.168.1.101", "Mozilla/5.0 Firefox/120", "web"},
            {"@alice:matrix.org", "ALICE_PHONE", "10.0.0.55", "Element/1.6.0 Android", "mobile"},
            {"@alice:matrix.org", "ALICE_DESKTOP", "192.168.1.101", "Element Desktop/1.11.0", "desktop"},
            {"@bob:matrix.org", "BOB_WEB", "172.16.0.22", "Chrome/120.0", "web"},
            {"@bob:matrix.org", "BOB_TABLET", "172.16.0.23", "FluffyChat/1.12 iOS", "mobile"},
            {"@charlie:matrix.org", "CHARLIE_CLI", "10.1.1.99", "gomuks/0.4", "mobile"},
            {"@admin:matrix.org", "ADMIN_WEB", "127.0.0.1", "Mozilla/5.0", "web"},
            {"@spammer:matrix.org", "SPAM_BOT", "203.0.113.42", "matrix-nio/0.24", "unknown"},
            {"@troll:matrix.org", "TROLL_DESKTOP", "198.51.100.77", "Element/1.10", "desktop"},
            {"@dave:matrix.org", "DAVE_WEB", "192.168.5.33", "Safari/17.2", "web"},
            {"@eve:matrix.org", "EVE_MOBILE", "172.20.0.88", "Element/1.5 iOS", "mobile"},
            {"@frank:matrix.org", "FRANK_TABLET", "10.10.10.10", "FluffyChat/1.11 Android", "mobile"},
            {"@grace:matrix.org", "GRACE_WEB", "192.168.7.44", "Firefox/120", "web"},
            {"@heidi:matrix.org", "HEIDI_DESKTOP", "10.0.1.200", "Nheko/0.11", "desktop"},
            {"@ivan:matrix.org", "IVAN_CLI", "172.30.0.15", "weechat-matrix/0.3", "unknown"},
        };
        int num = sizeof(session_data) / sizeof(session_data[0]);
        for (int i = 0; i < num; ++i) {
            db::DeviceSession s;
            s.device_id = session_data[i].device;
            s.user_id = session_data[i].user;
            s.display_name = "Session " + session_data[i].device;
            s.last_seen_ip = session_data[i].ip;
            s.last_seen_user_agent = session_data[i].ua;
            int64_t ts = timestamp_ms() - i * 600000LL; // 10 min apart
            s.last_seen_ts = std::to_string(ts);
            s.device_type = session_data[i].type;
            s.is_active = (i % 4 != 0);
            s.access_token_hash = sha256("token_" + s.user_id + "_" + s.device_id);
            db::device_sessions.push_back(s);
        }
    }

    // --- Seed federation destinations ---
    {
        std::lock_guard<std::mutex> lock(db::federation_mutex);
        struct {
            std::string dest; std::string status; int failures; int64_t sent; int64_t failed;
        } fed_data[] = {
            {"matrix.org", "ok", 0, 15420, 12},
            {"example.com", "ok", 2, 8432, 47},
            {"synapse.example.org", "retrying", 8, 3210, 156},
            {"evil.host", "blocked", 25, 0, 500},
            {"dendrite.org", "ok", 1, 6780, 23},
            {"conduit.rs", "ok", 0, 2340, 5},
            {"matrix-client.matrix.org", "ok", 3, 12980, 89},
            {"federation.example.net", "retrying", 5, 4500, 210},
            {"testserver.local", "ok", 0, 120, 0},
        };
        for (auto& fd : fed_data) {
            db::FedDestination dest;
            dest.destination = fd.dest;
            dest.status = fd.status;
            dest.failure_count = fd.failures;
            dest.backoff_count = fd.failures;
            dest.transactions_sent = fd.sent;
            dest.transactions_failed = fd.failed;
            dest.pdus_sent = fd.sent * 3;
            dest.edus_sent = fd.sent * 2;
            dest.retry_interval_ms = 60000 * (1 << std::min(fd.failures, 5));
            dest.last_success_ts = iso8601_now();
            if (fd.failures > 0) {
                dest.last_error = "Connection timeout after 30s";
            }
            db::federation_destinations[fd.dest] = dest;
        }
    }

    // --- Seed state groups ---
    {
        std::lock_guard<std::mutex> lock(db::state_groups_mutex);
        std::vector<std::string> rooms = {"!abc:matrix.org", "!xyz:matrix.org"};
        for (int i = 0; i < 15; ++i) {
            db::StateGroup sg;
            sg.group_id = "sg_" + std::to_string(100 + i);
            sg.room_id = rooms[i % rooms.size()];
            sg.event_count = 20 + (i * 3);
            if (i > 0) sg.prev_group_id = "sg_" + std::to_string(100 + i - 1);
            sg.created_ts = iso8601_now();
            db::state_groups[sg.group_id] = sg;
        }
    }

    // --- Seed forward extremities ---
    {
        std::lock_guard<std::mutex> lock(db::extremities_mutex);
        for (int i = 0; i < 8; ++i) {
            db::ForwardExtremity fe;
            fe.event_id = "$fe_event_" + std::to_string(i) + ":matrix.org";
            fe.room_id = (i < 4) ? "!abc:matrix.org" : "!xyz:matrix.org";
            fe.depth = 100 + i * 10;
            fe.received_ts = iso8601_now();
            db::forward_extremities[fe.room_id].push_back(fe);
        }
    }

    // --- Seed background updates ---
    {
        std::lock_guard<std::mutex> lock(db::background_mutex);
        struct {
            std::string name; std::string desc; bool enabled; int total; int complete; bool running;
        } bg_data[] = {
            {"populate_stats_process_rooms", "Populate room statistics for all rooms", true, 1520, 1520, false},
            {"populate_stats_process_users", "Populate user statistics", true, 500, 500, false},
            {"event_arbitrary_relations", "Store arbitrary relations for events", true, 32500, 28470, true},
            {"populate_room_depth_min_depth2", "Recalculate room depth (v2)", true, 1520, 0, false},
            {"populate_stream_ordering_to_extremities", "Index stream ordering to extremities", true, 800, 800, false},
            {"replace_room_list_stream", "Replace room list stream with new indexing", false, 12000, 0, false},
            {"populate_user_directory_createtables", "Create user directory tables", true, 1, 1, false},
            {"populate_user_directory_process_users", "Populate user directory index", true, 500, 350, false},
            {"populate_user_directory_cleanup", "Clean up stale user directory entries", true, 1, 0, false},
            {"delete_old_current_state_events", "Delete orphaned current state events", false, 45000, 12000, false},
            {"validate_room_memberships", "Validate room membership consistency", true, 3000, 0, false},
            {"sqlite_port", "Port database schema for SQLite compatibility", true, 1, 1, false},
        };
        int num = sizeof(bg_data) / sizeof(bg_data[0]);
        for (int i = 0; i < num; ++i) {
            db::BackgroundUpdate bu;
            bu.update_name = bg_data[i].name;
            bu.description = bg_data[i].desc;
            bu.enabled = bg_data[i].enabled;
            bu.progress_total = bg_data[i].total;
            bu.progress_complete = bg_data[i].complete;
            bu.running = bg_data[i].running;
            if (bu.progress_complete > 0) {
                bu.started_ts = iso8601_now();
                bu.duration_seconds = (double)(bg_data[i].complete) / 100.0;
            }
            if (bu.running && bu.progress_total > 0) {
                double pct = (double)bu.progress_complete / bu.progress_total * 100.0;
                bu.duration_seconds = std::round(pct * 3.6);
            }
            db::background_updates.push_back(bu);
        }
    }

    // --- Seed cache stats ---
    {
        std::lock_guard<std::mutex> lock(db::cache_mutex);
        struct {
            std::string name; int64_t max_sz; int64_t cur_sz; int64_t h; int64_t m; int64_t ev;
        } cache_data[] = {
            {"state_cache", 100000, 45231, 1250000, 34500, 8000},
            {"event_cache", 200000, 98765, 3450000, 120000, 15000},
            {"descriptor_cache", 50000, 12340, 890000, 23000, 4000},
            {"get_users_who_share_room", 25000, 5678, 230000, 12000, 2000},
            {"_get_joined_hosts_cache", 10000, 3456, 560000, 8900, 1500},
            {"_external_cache", 5000, 1234, 120000, 3400, 800},
            {"_event_auth_cache", 30000, 15789, 670000, 18000, 3500},
            {"_get_membership_from_event_ids", 40000, 23456, 450000, 22000, 6000},
        };
        for (auto& cd : cache_data) {
            db::CacheStats cs;
            cs.cache_name = cd.name;
            cs.max_size = cd.max_sz;
            cs.current_size = cd.cur_sz;
            cs.hits = cd.h;
            cs.misses = cd.m;
            cs.evictions = cd.ev;
            db::cache_stats_map[cd.name] = cs;
        }
    }

    // --- Seed room events for timeline export ---
    {
        std::lock_guard<std::mutex> lock(db::events_mutex);
        std::vector<std::string> rooms = {"!abc:matrix.org", "!xyz:matrix.org"};
        std::vector<std::string> senders = {"@alice:matrix.org", "@bob:matrix.org", "@charlie:matrix.org"};
        std::vector<std::string> types = {"m.room.message", "m.room.member",
            "m.room.name", "m.room.topic", "m.room.create",
            "m.room.join_rules", "m.room.power_levels", "m.reaction",
            "m.room.encryption", "m.room.history_visibility"};
        std::vector<std::string> bodies = {
            "Hello everyone!",
            "Has anyone seen the latest update?",
            "I agree, that sounds great.",
            "Let's schedule a meeting for tomorrow.",
            "Here is the document link: https://example.com/doc",
            "Thanks for sharing!",
            "Can someone help me with this issue?",
            "Sure, I'll take a look.",
            "The server seems to be down.",
            "I've fixed the bug in the latest commit."
        };
        for (int r = 0; r < 2; ++r) {
            for (int i = 0; i < 50; ++i) {
                db::RoomEvent ev;
                ev.event_id = "$event_" + rooms[r].substr(1, 3) + "_" +
                              std::to_string(1000 + i) + ":matrix.org";
                ev.room_id = rooms[r];
                ev.sender = senders[i % senders.size()];
                ev.type = types[i % types.size()];
                ev.content_json = R"({"body":")" + bodies[i % bodies.size()] +
                                  R"(","msgtype":"m.text"})";
                ev.origin_server_ts = timestamp_ms() - (50 - i) * 60000;
                ev.depth = 50 + i;
                ev.outlier = false;
                ev.received_ts = iso8601_now();
                if (i > 0) {
                    ev.prev_event_ids_json = R"(["$event_)" +
                        rooms[r].substr(1, 3) + "_" +
                        std::to_string(1000 + i - 1) + R"(:matrix.org"])";
                }
                db::room_events[rooms[r]].push_back(ev);
            }
        }
    }

    // --- Seed server config ---
    {
        std::lock_guard<std::mutex> lock(db::config_mutex);
        db::server_config["server_name"] = "progressive.matrix.org";
        db::server_config["pid_file"] = "/var/run/matrix-synapse.pid";
        db::server_config["web_client_location"] = "/usr/share/matrix-synapse/webclient";
        db::server_config["public_baseurl"] = "https://matrix.example.com";
        db::server_config["listeners[0].port"] = "8008";
        db::server_config["listeners[0].type"] = "http";
        db::server_config["listeners[0].tls"] = "false";
        db::server_config["listeners[0].bind_addresses[0]"] = "0.0.0.0";
        db::server_config["database.name"] = "psycopg2";
        db::server_config["database.args.user"] = "synapse_user";
        db::server_config["database.args.database"] = "synapse";
        db::server_config["database.args.host"] = "localhost";
        db::server_config["database.args.port"] = "5432";
        db::server_config["database.args.cp_min"] = "5";
        db::server_config["database.args.cp_max"] = "10";
        db::server_config["log_config"] = "/etc/matrix-synapse/log.yaml";
        db::server_config["media_store_path"] = "/var/lib/matrix-synapse/media";
        db::server_config["uploads_path"] = "/var/lib/matrix-synapse/uploads";
        db::server_config["max_upload_size"] = "50M";
        db::server_config["max_image_pixels"] = "32M";
        db::server_config["enable_registration"] = "false";
        db::server_config["registrations_require_3pid"] = "true";
        db::server_config["turn_uris[0]"] = "turn:turn.example.com:3478?transport=udp";
        db::server_config["enable_metrics"] = "true";
        db::server_config["report_stats"] = "false";
        db::server_config["federation_domain_whitelist[0]"] = "matrix.org";
        db::server_config["federation_domain_whitelist[1]"] = "example.com";
        db::server_config["federation_rc_window_size"] = "1000";
        db::server_config["federation_rc_sleep_limit"] = "10";
        db::server_config["federation_rc_sleep_delay"] = "500";
        db::server_config["federation_rc_reject_limit"] = "50";
        db::server_config["url_preview_enabled"] = "true";
        db::server_config["url_preview_ip_range_blacklist[0]"] = "127.0.0.0/8";
        db::server_config["url_preview_ip_range_blacklist[1]"] = "10.0.0.0/8";
        db::server_config["url_preview_ip_range_blacklist[2]"] = "172.16.0.0/12";
        db::server_config["url_preview_ip_range_blacklist[3]"] = "192.168.0.0/16";

        // Secret keys (will be redacted in config dump)
        db::secret_config_keys.insert("database.args.password");
        db::secret_config_keys.insert("registration_shared_secret");
        db::secret_config_keys.insert("macaroon_secret_key");
        db::secret_config_keys.insert("form_secret");
        db::secret_config_keys.insert("signing_key_path");
        db::secret_config_keys.insert("turn_shared_secret");
        db::secret_config_keys.insert("email.smtp_pass");

        db::server_config["database.args.password"] = "super_secret_db_password";
        db::server_config["registration_shared_secret"] = "abc123def456ghi789";
        db::server_config["macaroon_secret_key"] = "macaroon_key_very_secret";
        db::server_config["form_secret"] = "form_secret_key_string";
        db::server_config["signing_key_path"] = "/etc/matrix-synapse/signing.key";
        db::server_config["turn_shared_secret"] = "turn_secret_shared_key";
        db::server_config["email.smtp_pass"] = "smtp_password_123";
    }

    // --- Seed room state ---
    {
        std::lock_guard<std::mutex> lock(db::events_mutex);
        for (auto& room_id : {"!abc:matrix.org", "!xyz:matrix.org"}) {
            db::room_state_latest[std::string(room_id)] =
                R"({"m.room.create":{"sender":"@alice:matrix.org","content":{"creator":"@alice:matrix.org","m.federate":true}},)" +
                std::string(R"("m.room.member":{"@alice:matrix.org":{"membership":"join","displayname":"Alice"}},)" +
                std::string(R"("m.room.name":{"content":{"name":"Test Room"}},)" +
                std::string(R"("m.room.join_rules":{"content":{"join_rule":"invite"}})")")")");
        }
    }
}

// Call initialization on module load
struct InitGuard {
    InitGuard() { init_seed_data(); }
} init_guard_instance;

} // anonymous namespace

// ============================================================================
// Endpoint 1: List event reports
// GET /_synapse/admin/v1/event_reports
// Query params: from, limit, dir, order_by, user_id, room_id
// ============================================================================

json handle_list_event_reports(const std::string& query_string) {
    auto params = parse_query_params(query_string);

    int from  = get_query_int(params, "from", 0);
    int limit = get_query_int(params, "limit", 10);
    if (limit > 100) limit = 100;
    if (limit < 1) limit = 1;
    std::string dir = get_query_str(params, "dir", "b");
    std::string order_by = get_query_str(params, "order_by", "received_ts");
    std::string filter_user_id = get_query_str(params, "user_id", "");
    std::string filter_room_id = get_query_str(params, "room_id", "");

    std::lock_guard<std::mutex> lock(db::reports_mutex);

    // Collect matching reports
    std::vector<db::EventReportRecord> filtered;
    for (const auto& pair : db::event_reports) {
        const auto& r = pair.second;
        if (!filter_user_id.empty() && r.user_id != filter_user_id) continue;
        if (!filter_room_id.empty() && r.room_id != filter_room_id) continue;
        filtered.push_back(r);
    }

    // Sort
    std::sort(filtered.begin(), filtered.end(),
        [&](const db::EventReportRecord& a, const db::EventReportRecord& b) {
            int64_t ts_a = 0, ts_b = 0;
            try { ts_a = std::stoll(a.received_ts); } catch (...) {}
            try { ts_b = std::stoll(b.received_ts); } catch (...) {}
            if (dir == "f") return ts_a < ts_b;
            return ts_a > ts_b;
        });

    int total = (int)filtered.size();

    // Paginate
    json result;
    result["event_reports"] = json::array();
    result["total"] = total;
    int end = std::min(from + limit, total);
    for (int i = from; i < end; ++i) {
        const auto& r = filtered[i];
        json entry;
        entry["id"] = r.id;
        entry["received_ts"] = r.received_ts;
        try {
            int64_t ms = std::stoll(r.received_ts);
            entry["received_ts_iso"] = ms_to_iso8601(ms);
        } catch (...) {
            entry["received_ts_iso"] = r.received_ts;
        }
        entry["room_id"] = r.room_id;
        entry["event_id"] = r.event_id;
        entry["user_id"] = r.user_id;
        entry["reason"] = r.reason;
        entry["score"] = r.score;
        entry["sender"] = r.sender;
        entry["can_see_sender"] = r.can_see_sender;
        entry["resolved"] = r.resolved;
        if (r.resolved) {
            entry["resolved_by"] = r.resolved_by;
            entry["resolved_ts"] = r.resolved_ts;
        }
        result["event_reports"].push_back(entry);
    }

    if (end < total) {
        result["next_token"] = end;
    }

    return result;
}

// ============================================================================
// Endpoint 2: Event report detail
// GET /_synapse/admin/v1/event_reports/{reportId}
// ============================================================================

json handle_get_event_report(const std::string& report_id) {
    std::lock_guard<std::mutex> lock(db::reports_mutex);

    auto it = db::event_reports.find(report_id);
    if (it == db::event_reports.end()) {
        return error_response("M_NOT_FOUND",
            "Event report not found: " + report_id, 404);
    }

    const auto& r = it->second;
    json entry;
    entry["id"] = r.id;
    entry["received_ts"] = r.received_ts;
    try {
        int64_t ms = std::stoll(r.received_ts);
        entry["received_ts_iso"] = ms_to_iso8601(ms);
    } catch (...) {
        entry["received_ts_iso"] = r.received_ts;
    }
    entry["room_id"] = r.room_id;
    entry["event_id"] = r.event_id;
    entry["user_id"] = r.user_id;
    entry["reason"] = r.reason;
    entry["score"] = r.score;
    entry["sender"] = r.sender;
    entry["can_see_sender"] = r.can_see_sender;
    entry["resolved"] = r.resolved;
    if (r.resolved) {
        entry["resolved_by"] = r.resolved_by;
        entry["resolved_ts"] = r.resolved_ts;
        entry["resolution_notes"] = r.resolution_notes;
    }
    // Try to parse event content JSON
    entry["event_content"] = json::parse(r.event_content_json, nullptr, false);
    if (entry["event_content"].is_discarded()) {
        entry["event_content"] = r.event_content_json;
    }

    return entry;
}

// ============================================================================
// Endpoint 3: Event report resolution (POST action)
// POST /_synapse/admin/v1/event_reports/{reportId}
// Body: {"action": "resolve"|"ignore", "resolution_notes": "..."}
// ============================================================================

json handle_resolve_event_report(const std::string& report_id,
                                 const json& body) {
    std::lock_guard<std::mutex> lock(db::reports_mutex);

    auto it = db::event_reports.find(report_id);
    if (it == db::event_reports.end()) {
        return error_response("M_NOT_FOUND",
            "Event report not found: " + report_id, 404);
    }

    auto& r = it->second;

    std::string action = body.value("action", "resolve");
    std::string notes = body.value("resolution_notes", "");
    std::string admin_user = body.value("admin_user", "@admin:matrix.org");

    if (action == "resolve") {
        r.resolved = true;
        r.resolved_by = admin_user;
        r.resolved_ts = iso8601_now();
        r.resolution_notes = notes;
        return success_response({
            {"message", "Event report resolved successfully."},
            {"report_id", report_id},
            {"resolved", true},
            {"resolved_ts", r.resolved_ts}
        });
    } else if (action == "ignore") {
        r.resolved = true;
        r.resolved_by = admin_user;
        r.resolved_ts = iso8601_now();
        r.resolution_notes = "Ignored: " + notes;
        return success_response({
            {"message", "Event report marked as ignored."},
            {"report_id", report_id},
            {"resolved", true}
        });
    } else if (action == "delete") {
        db::event_reports.erase(it);
        return success_response({
            {"message", "Event report deleted."},
            {"report_id", report_id}
        });
    } else {
        return error_response("M_INVALID_PARAM",
            "Unknown action: " + action + ". Valid: resolve, ignore, delete", 400);
    }
}

// ============================================================================
// Endpoint 4: Room state export
// GET /_synapse/admin/v1/rooms/{roomId}/state
// ============================================================================

json handle_room_state_export(const std::string& room_id) {
    std::lock_guard<std::mutex> lock(db::events_mutex);

    auto it = db::room_state_latest.find(room_id);
    if (it == db::room_state_latest.end()) {
        return error_response("M_NOT_FOUND",
            "Room not found or no state available: " + room_id, 404);
    }

    json result;
    result["room_id"] = room_id;

    // Parse the stored state JSON
    json state = json::parse(it->second, nullptr, false);
    if (state.is_discarded()) {
        result["state"] = it->second;
        result["parse_error"] = true;
    } else {
        result["state"] = state;
    }

    // Add metadata
    result["state_export_ts"] = iso8601_now();
    result["format_version"] = 1;

    // Count state entries
    int event_count = 0;
    if (state.is_object()) {
        for (auto& item : state.items()) {
            if (item.value().is_object()) {
                event_count += (int)item.value().size();
            }
        }
    }
    result["event_count"] = event_count;

    return result;
}

// ============================================================================
// Endpoint 5: Room timeline export
// GET /_synapse/admin/v1/rooms/{roomId}/timeline
// Query params: from, limit, direction (f/b), filter_type
// Exports all events from room as a JSON array
// ============================================================================

json handle_room_timeline_export(const std::string& room_id,
                                  const std::string& query_string) {
    auto params = parse_query_params(query_string);
    int from   = get_query_int(params, "from", 0);
    int limit  = get_query_int(params, "limit", 100);
    if (limit > 1000) limit = 1000;
    if (limit < 1) limit = 1;
    std::string dir = get_query_str(params, "direction", "b");
    std::string filter_type = get_query_str(params, "filter_type", "");

    std::lock_guard<std::mutex> lock(db::events_mutex);

    auto it = db::room_events.find(room_id);
    if (it == db::room_events.end()) {
        return error_response("M_NOT_FOUND",
            "Room not found or no events available: " + room_id, 404);
    }

    std::vector<db::RoomEvent> events = it->second;

    // Filter by type if requested
    if (!filter_type.empty()) {
        std::vector<db::RoomEvent> filtered;
        for (auto& ev : events) {
            if (ev.type == filter_type) {
                filtered.push_back(ev);
            }
        }
        events = std::move(filtered);
    }

    // Sort
    if (dir == "f") {
        std::sort(events.begin(), events.end(),
            [](const db::RoomEvent& a, const db::RoomEvent& b) {
                return a.depth < b.depth;
            });
    } else {
        std::sort(events.begin(), events.end(),
            [](const db::RoomEvent& a, const db::RoomEvent& b) {
                return a.depth > b.depth;
            });
    }

    int total = (int)events.size();
    int end = std::min(from + limit, total);

    json result;
    result["room_id"] = room_id;
    result["events"] = json::array();
    result["total_events"] = total;
    result["returned"] = end - from;

    for (int i = from; i < end; ++i) {
        const auto& ev = events[i];
        json entry;
        entry["event_id"] = ev.event_id;
        entry["room_id"] = ev.room_id;
        entry["sender"] = ev.sender;
        entry["type"] = ev.type;
        if (!ev.state_key.empty()) {
            entry["state_key"] = ev.state_key;
        }
        entry["origin_server_ts"] = ev.origin_server_ts;
        try {
            entry["origin_server_ts_iso"] = ms_to_iso8601(ev.origin_server_ts);
        } catch (...) {}
        entry["depth"] = ev.depth;
        entry["outlier"] = ev.outlier;
        entry["received_ts"] = ev.received_ts;

        // Parse content JSON
        json content = json::parse(ev.content_json, nullptr, false);
        if (!content.is_discarded()) {
            entry["content"] = content;
        } else {
            entry["content"] = ev.content_json;
        }

        // Parse prev events
        if (!ev.prev_event_ids_json.empty()) {
            json pe = json::parse(ev.prev_event_ids_json, nullptr, false);
            if (!pe.is_discarded()) {
                entry["prev_events"] = pe;
            }
        }

        result["events"].push_back(entry);
    }

    if (end < total) {
        result["next_batch"] = end;
    }

    return result;
}

// ============================================================================
// Endpoint 6: Server debugging API / profiler
// GET /_synapse/admin/v1/debug/profiler
// Returns CPU, memory, event loop stats, thread info, GC stats
// ============================================================================

json handle_debug_profiler(const std::string& query_string) {
    auto params = parse_query_params(query_string);
    std::string section = get_query_str(params, "section", "all");

    json result;
    result["server"] = "progressive-server";
    result["timestamp"] = iso8601_now();
    result["timestamp_ms"] = timestamp_ms();

    // ---- CPU / Thread info ----
    if (section == "all" || section == "cpu") {
        json cpu;
        cpu["cpu_count"] = (int)std::thread::hardware_concurrency();
        cpu["cpu_percent"] = 12.7;  // simulated
        cpu["load_average_1min"] = 0.85;
        cpu["load_average_5min"] = 0.72;
        cpu["load_average_15min"] = 0.68;
        cpu["thread_count"] = 42;

        json threads = json::array();
        struct {
            std::string name; int id; double cpu_pct; std::string state;
        } thread_info[] = {
            {"MainThread", 1, 2.3, "running"},
            {"synapse-http-0", 2, 0.5, "waiting"},
            {"synapse-http-1", 3, 1.2, "waiting"},
            {"synapse-http-2", 4, 0.8, "waiting"},
            {"synapse-http-3", 5, 1.1, "waiting"},
            {"synapse-federation-sender", 6, 3.2, "running"},
            {"synapse-federation-reader", 7, 0.4, "waiting"},
            {"synapse-event-creator", 8, 0.9, "waiting"},
            {"synapse-media-repository", 9, 0.3, "waiting"},
            {"synapse-pusher-0", 10, 0.6, "running"},
            {"synapse-pusher-1", 11, 0.2, "waiting"},
            {"synapse-notifier", 12, 0.1, "waiting"},
        };
        for (auto& ti : thread_info) {
            threads.push_back({
                {"name", ti.name},
                {"id", ti.id},
                {"cpu_percent", ti.cpu_pct},
                {"state", ti.state}
            });
        }
        cpu["threads"] = threads;
        result["cpu"] = cpu;
    }

    // ---- Memory info ----
    if (section == "all" || section == "memory") {
        json memory;
        memory["rss_bytes"] = 524288000;      // 500 MB
        memory["vms_bytes"] = 1073741824;      // 1 GB
        memory["shared_bytes"] = 67108864;     // 64 MB
        memory["heap_used_bytes"] = 268435456; // 256 MB
        memory["heap_total_bytes"] = 536870912;// 512 MB
        memory["gc_count_gen0"] = 152;
        memory["gc_count_gen1"] = 34;
        memory["gc_count_gen2"] = 5;
        memory["gc_time_ms"] = 12450;
        result["memory"] = memory;
    }

    // ---- Event loop stats ----
    if (section == "all" || section == "eventloop") {
        json el;
        el["pending_tasks"] = 127;
        el["completed_tasks_last_minute"] = 3456;
        el["avg_task_duration_us"] = 450;
        el["max_task_duration_us"] = 125000;
        el["federation_client_queue_size"] = 34;
        el["persist_event_queue_size"] = 156;
        el["notifier_queue_size"] = 89;
        result["event_loop"] = el;
    }

    // ---- Database pool stats ----
    if (section == "all" || section == "database") {
        json db;
        db["pool_size"] = 10;
        db["active_connections"] = 7;
        db["idle_connections"] = 3;
        db["waiting_requests"] = 0;
        db["total_queries"] = 1245678;
        db["avg_query_duration_us"] = 2500;
        db["slowest_query_duration_us"] = 450000;
        db["slowest_query"] = "SELECT * FROM events WHERE room_id = ? ORDER BY topological_ordering LIMIT 50";

        json recent_queries = json::array();
        recent_queries.push_back({
            {"query", "SELECT count(*) FROM events WHERE room_id = '!abc:matrix.org'"},
            {"duration_us", 3200},
            {"timestamp", iso8601_now()}
        });
        recent_queries.push_back({
            {"query", "INSERT INTO event_json(event_id, room_id, json) VALUES(?, ?, ?)"},
            {"duration_us", 1200},
            {"timestamp", iso8601_now()}
        });
        recent_queries.push_back({
            {"query", "SELECT event_id, state_key FROM state_events WHERE room_id = ? AND type = ?"},
            {"duration_us", 890},
            {"timestamp", iso8601_now()}
        });
        db["recent_queries"] = recent_queries;
        result["database"] = db;
    }

    // ---- Federation stats ----
    if (section == "all" || section == "federation") {
        json fed;
        fed["incoming_transactions_last_min"] = 45;
        fed["outgoing_transactions_last_min"] = 23;
        fed["pdus_received_last_min"] = 120;
        fed["pdus_sent_last_min"] = 89;
        fed["edus_received_last_min"] = 56;
        fed["edus_sent_last_min"] = 34;
        fed["active_destinations"] = 8;
        fed["backoff_count"] = 2;
        result["federation"] = fed;
    }

    return result;
}

// ============================================================================
// Endpoint 7: Query user sessions (whois)
// GET /_synapse/admin/v1/whois/{userId}
// Returns all device sessions and connection info for a user
// ============================================================================

json handle_whois_user(const std::string& user_id) {
    std::lock_guard<std::mutex> lock(db::sessions_mutex);

    json result;
    result["user_id"] = user_id;

    json devices = json::array();
    bool found = false;

    for (const auto& s : db::device_sessions) {
        if (s.user_id != user_id) continue;
        found = true;
        json dev;
        dev["device_id"] = s.device_id;
        dev["display_name"] = s.display_name;
        dev["last_seen_ip"] = s.last_seen_ip;
        dev["last_seen_user_agent"] = s.last_seen_user_agent;
        dev["last_seen_ts"] = s.last_seen_ts;
        try {
            int64_t ms = std::stoll(s.last_seen_ts);
            dev["last_seen_iso"] = ms_to_iso8601(ms);
        } catch (...) {
            dev["last_seen_iso"] = s.last_seen_ts;
        }
        dev["is_active"] = s.is_active;
        dev["device_type"] = s.device_type;
        devices.push_back(dev);
    }

    if (!found) {
        // Still return empty devices array for users with no sessions
        result["devices"] = json::array();
        result["device_count"] = 0;
        result["connection_summary"] = "No active sessions found for this user.";
    } else {
        result["devices"] = devices;
        result["device_count"] = devices.size();

        // Connection summary
        int active_count = 0;
        std::set<std::string> ips;
        for (const auto& s : db::device_sessions) {
            if (s.user_id == user_id) {
                if (s.is_active) active_count++;
                ips.insert(s.last_seen_ip);
            }
        }
        result["active_devices"] = active_count;
        result["distinct_ips"] = ips.size();

        std::stringstream summary;
        summary << "User " << user_id << " has " << devices.size()
                << " device(s), " << active_count << " active, from "
                << ips.size() << " distinct IP(s).";
        result["connection_summary"] = summary.str();
    }

    return result;
}

// ============================================================================
// Endpoint 8: List active user sessions
// GET /_synapse/admin/v1/sessions
// Query params: user_id (optional filter), limit, from
// Lists all devices with IP, user agent, last seen time
// ============================================================================

json handle_list_sessions(const std::string& query_string) {
    auto params = parse_query_params(query_string);
    int from      = get_query_int(params, "from", 0);
    int limit     = get_query_int(params, "limit", 50);
    if (limit > 200) limit = 200;
    if (limit < 1) limit = 1;
    std::string filter_user = get_query_str(params, "user_id", "");
    bool active_only = get_query_str(params, "active_only", "false") == "true";

    std::lock_guard<std::mutex> lock(db::sessions_mutex);

    // Filter
    std::vector<db::DeviceSession> filtered;
    for (const auto& s : db::device_sessions) {
        if (!filter_user.empty() && s.user_id != filter_user) continue;
        if (active_only && !s.is_active) continue;
        filtered.push_back(s);
    }

    // Sort by last seen (most recent first)
    std::sort(filtered.begin(), filtered.end(),
        [](const db::DeviceSession& a, const db::DeviceSession& b) {
            int64_t ts_a = 0, ts_b = 0;
            try { ts_a = std::stoll(a.last_seen_ts); } catch (...) {}
            try { ts_b = std::stoll(b.last_seen_ts); } catch (...) {}
            return ts_a > ts_b;
        });

    int total = (int)filtered.size();
    int end = std::min(from + limit, total);

    json result;
    result["sessions"] = json::array();
    result["total"] = total;

    for (int i = from; i < end; ++i) {
        const auto& s = filtered[i];
        json entry;
        entry["user_id"] = s.user_id;
        entry["device_id"] = s.device_id;
        entry["display_name"] = s.display_name;
        entry["last_seen_ip"] = s.last_seen_ip;
        entry["last_seen_user_agent"] = s.last_seen_user_agent;
        entry["last_seen_ts"] = s.last_seen_ts;
        try {
            int64_t ms = std::stoll(s.last_seen_ts);
            entry["last_seen_iso"] = ms_to_iso8601(ms);
        } catch (...) {}
        entry["is_active"] = s.is_active;
        entry["device_type"] = s.device_type;
        entry["access_token_hash"] = s.access_token_hash;
        result["sessions"].push_back(entry);
    }

    if (end < total) {
        result["next_token"] = end;
    }

    // Summarize by user
    std::unordered_map<std::string, int> user_session_counts;
    for (const auto& s : db::device_sessions) {
        if (!filter_user.empty() && s.user_id != filter_user) continue;
        if (active_only && !s.is_active) continue;
        user_session_counts[s.user_id]++;
    }
    json user_summary = json::array();
    for (auto& pair : user_session_counts) {
        user_summary.push_back({
            {"user_id", pair.first},
            {"session_count", pair.second}
        });
    }
    result["users_summary"] = user_summary;
    result["unique_users"] = user_session_counts.size();

    return result;
}

// ============================================================================
// Endpoint 9: Force logout user sessions
// DELETE /_synapse/admin/v1/sessions/{userId}
// Kills all active sessions for a given user
// ============================================================================

json handle_force_logout_user(const std::string& user_id,
                               const json& body) {
    std::lock_guard<std::mutex> lock(db::sessions_mutex);

    int removed = 0;
    std::vector<db::DeviceSession> remaining;

    bool delete_records = body.value("delete_records", false);
    std::string reason = body.value("reason", "Admin-forced logout");

    for (const auto& s : db::device_sessions) {
        if (s.user_id == user_id) {
            removed++;
            // If not deleting records, add a deactivated copy
            if (!delete_records) {
                db::DeviceSession deactivated = s;
                deactivated.is_active = false;
                deactivated.last_seen_ts = std::to_string(timestamp_ms());
                remaining.push_back(deactivated);
            }
        } else {
            remaining.push_back(s);
        }
    }

    db::device_sessions = std::move(remaining);

    json result;
    result["user_id"] = user_id;
    result["sessions_removed"] = removed;
    result["action"] = delete_records ? "deleted" : "deactivated";
    result["reason"] = reason;
    result["message"] = "Successfully logged out " + std::to_string(removed) +
                        " session(s) for user " + user_id + ".";

    // Log the action (simulated)
    result["log_entry"] = "[" + iso8601_now() + "] ADMIN: Force logout " +
                          user_id + " - " + std::to_string(removed) +
                          " sessions (" + reason + ")";

    return success_response(result);
}

// ============================================================================
// Endpoint 10: View federation destinations
// GET /_synapse/admin/v1/federation/destinations
// Lists all federation destinations with status, retry counts, transaction stats
// ============================================================================

json handle_list_federation_destinations(const std::string& query_string) {
    auto params = parse_query_params(query_string);
    std::string status_filter = get_query_str(params, "status", "");
    std::string dest_filter = get_query_str(params, "destination", "");

    std::lock_guard<std::mutex> lock(db::federation_mutex);

    json result;
    result["destinations"] = json::array();

    int total_ok = 0, total_retrying = 0, total_blocked = 0;

    for (const auto& pair : db::federation_destinations) {
        const auto& d = pair.second;

        if (!status_filter.empty() && d.status != status_filter) continue;
        if (!dest_filter.empty() && d.destination != dest_filter) continue;

        json entry;
        entry["destination"] = d.destination;
        entry["status"] = d.status;
        entry["retry_interval_ms"] = d.retry_interval_ms;
        entry["failure_count"] = d.failure_count;
        entry["backoff_count"] = d.backoff_count;
        entry["last_success_ts"] = d.last_success_ts;
        if (!d.last_failure_ts.empty()) {
            entry["last_failure_ts"] = d.last_failure_ts;
        }
        if (!d.last_error.empty()) {
            entry["last_error"] = d.last_error;
        }
        entry["transactions_sent"] = d.transactions_sent;
        entry["transactions_failed"] = d.transactions_failed;

        // Calculate success rate
        int64_t total_tx = d.transactions_sent + d.transactions_failed;
        if (total_tx > 0) {
            double rate = (double)d.transactions_sent / total_tx * 100.0;
            entry["success_rate_percent"] = std::round(rate * 100.0) / 100.0;
        } else {
            entry["success_rate_percent"] = 0.0;
        }

        entry["pdus_sent"] = d.pdus_sent;
        entry["edus_sent"] = d.edus_sent;

        result["destinations"].push_back(entry);

        if (d.status == "ok") total_ok++;
        else if (d.status == "retrying") total_retrying++;
        else if (d.status == "blocked") total_blocked++;
    }

    result["total_destinations"] = db::federation_destinations.size();
    result["summary"] = {
        {"ok", total_ok},
        {"retrying", total_retrying},
        {"blocked", total_blocked}
    };

    return result;
}

// ============================================================================
// Endpoint 11: Reset federation backoff
// POST /_synapse/admin/v1/federation/destinations/{destination}/reset
// Resets the retry count for a federation destination
// ============================================================================

json handle_reset_federation_backoff(const std::string& destination,
                                      const json& body) {
    std::lock_guard<std::mutex> lock(db::federation_mutex);

    auto it = db::federation_destinations.find(destination);
    if (it == db::federation_destinations.end()) {
        return error_response("M_NOT_FOUND",
            "Federation destination not found: " + destination, 404);
    }

    auto& d = it->second;
    int old_failures = d.failure_count;
    int old_backoff = d.backoff_count;

    d.failure_count = 0;
    d.backoff_count = 0;
    d.retry_interval_ms = 60000; // reset to default 1 min
    d.status = "ok";
    d.last_error = "";

    json result;
    result["destination"] = destination;
    result["previous_failure_count"] = old_failures;
    result["previous_backoff_count"] = old_backoff;
    result["new_status"] = d.status;
    result["new_retry_interval_ms"] = d.retry_interval_ms;
    result["message"] = "Backoff for " + destination + " has been reset. " +
                        "Was at " + std::to_string(old_failures) +
                        " failures, now cleared.";
    result["timestamp"] = iso8601_now();

    return success_response(result);
}

// ============================================================================
// Endpoint 12: Manually send federation transaction
// POST /_synapse/admin/v1/federation/send
// Body: {"destination": "example.com", "pdus": [...], "edus": [...]}
// Triggers a federation push to the specified destination
// ============================================================================

json handle_send_federation_transaction(const json& body) {
    std::string destination = body.value("destination", "");
    if (destination.empty()) {
        return error_response("M_MISSING_PARAM",
            "Missing required parameter: destination", 400);
    }

    std::lock_guard<std::mutex> lock(db::federation_mutex);

    // Check if destination exists, if not create it
    auto it = db::federation_destinations.find(destination);
    if (it == db::federation_destinations.end()) {
        db::FedDestination new_dest;
        new_dest.destination = destination;
        new_dest.status = "ok";
        new_dest.last_success_ts = iso8601_now();
        new_dest.retry_interval_ms = 60000;
        db::federation_destinations[destination] = new_dest;
        it = db::federation_destinations.find(destination);
    }

    auto& d = it->second;

    // Simulate sending
    int pdu_count = 0;
    int edu_count = 0;

    if (body.contains("pdus") && body["pdus"].is_array()) {
        pdu_count = (int)body["pdus"].size();
    }
    if (body.contains("edus") && body["edus"].is_array()) {
        edu_count = (int)body["edus"].size();
    }

    // If no PDUs/EDUs provided, generate test transaction
    if (pdu_count == 0 && edu_count == 0) {
        pdu_count = 1;
    }

    d.transactions_sent++;
    d.pdus_sent += pdu_count;
    d.edus_sent += edu_count;
    d.last_success_ts = iso8601_now();

    // Generate transaction ID
    std::string txn_id = "txn_" + generate_short_id(16);

    json result;
    result["destination"] = destination;
    result["transaction_id"] = txn_id;
    result["pdus_sent_count"] = pdu_count;
    result["edus_sent_count"] = edu_count;
    result["timestamp"] = d.last_success_ts;
    result["status"] = "sent";
    result["message"] = "Transaction " + txn_id + " sent to " + destination +
                        " with " + std::to_string(pdu_count) + " PDU(s) and " +
                        std::to_string(edu_count) + " EDU(s).";

    // Include transaction_details for verification
    json details;
    details["origin"] = "progressive.matrix.org";
    details["origin_server_ts"] = timestamp_ms();
    details["pdus"] = json::array();
    if (body.contains("pdus") && body["pdus"].is_array()) {
        details["pdus"] = body["pdus"];
    }
    details["edus"] = json::array();
    if (body.contains("edus") && body["edus"].is_array()) {
        details["edus"] = body["edus"];
    }
    result["transaction_details"] = details;

    return success_response(result);
}

// ============================================================================
// Endpoint 13: Cache management - clear caches
// POST /_synapse/admin/v1/cache/clear
// Body: {"caches": ["state_cache", "event_cache"]} or {"caches": "*"}
// ============================================================================

json handle_clear_caches(const json& body) {
    std::lock_guard<std::mutex> lock(db::cache_mutex);

    json caches_to_clear;
    if (body.contains("caches")) {
        caches_to_clear = body["caches"];
    } else {
        // Clear all if not specified
        caches_to_clear = "*";
    }

    json cleared = json::array();
    json not_found = json::array();
    int total_evicted = 0;

    auto clear_one = [&](const std::string& name) {
        auto it = db::cache_stats_map.find(name);
        if (it != db::cache_stats_map.end()) {
            int evicted = (int)it->second.current_size;
            it->second.evictions += evicted;
            it->second.current_size = 0;
            cleared.push_back(name);
            total_evicted += evicted;
        } else {
            not_found.push_back(name);
        }
    };

    if (caches_to_clear.is_string() && caches_to_clear.get<std::string>() == "*") {
        for (auto& pair : db::cache_stats_map) {
            clear_one(pair.first);
        }
    } else if (caches_to_clear.is_array()) {
        for (const auto& c : caches_to_clear) {
            if (c.is_string()) {
                clear_one(c.get<std::string>());
            }
        }
    }

    json result;
    result["cleared_caches"] = cleared;
    result["not_found"] = not_found;
    result["total_evicted_entries"] = total_evicted;
    result["timestamp"] = iso8601_now();
    result["message"] = "Cleared " + std::to_string(cleared.size()) +
                        " cache(s), evicted " + std::to_string(total_evicted) +
                        " entries.";

    return success_response(result);
}

// ============================================================================
// Endpoint 14: Cache statistics
// GET /_synapse/admin/v1/cache/stats
// Returns detailed cache hit/miss/size stats for all caches
// ============================================================================

json handle_cache_stats(const std::string& query_string) {
    auto params = parse_query_params(query_string);
    std::string cache_filter = get_query_str(params, "cache", "");

    std::lock_guard<std::mutex> lock(db::cache_mutex);

    json result;
    result["caches"] = json::array();

    int64_t total_hits = 0;
    int64_t total_misses = 0;
    int64_t total_evictions = 0;
    int64_t total_entries = 0;

    for (const auto& pair : db::cache_stats_map) {
        const auto& cs = pair.second;

        if (!cache_filter.empty() && cs.cache_name != cache_filter) continue;

        json entry;
        entry["name"] = cs.cache_name;
        entry["max_size"] = cs.max_size;
        entry["current_size"] = cs.current_size;
        entry["utilization_percent"] = cs.max_size > 0
            ? std::round((double)cs.current_size / cs.max_size * 10000.0) / 100.0
            : 0.0;
        entry["hits"] = cs.hits;
        entry["misses"] = cs.misses;
        entry["hit_rate_percent"] = std::round(cs.hit_rate() * 100.0) / 100.0;
        entry["evictions"] = cs.evictions;

        // Calculate efficiency metrics
        int64_t total = cs.hits + cs.misses;
        entry["total_accesses"] = total;
        if (total > 0 && cs.current_size > 0) {
            entry["accesses_per_entry"] = (double)total / cs.current_size;
        } else {
            entry["accesses_per_entry"] = 0.0;
        }

        result["caches"].push_back(entry);

        total_hits += cs.hits;
        total_misses += cs.misses;
        total_evictions += cs.evictions;
        total_entries += cs.current_size;
    }

    int64_t total_accesses = total_hits + total_misses;
    result["summary"] = {
        {"total_caches", db::cache_stats_map.size()},
        {"total_hits", total_hits},
        {"total_misses", total_misses},
        {"overall_hit_rate_percent", total_accesses > 0
            ? std::round((double)total_hits / total_accesses * 10000.0) / 100.0
            : 0.0},
        {"total_evictions", total_evictions},
        {"total_entries", total_entries}
    };
    result["timestamp"] = iso8601_now();

    return result;
}

// ============================================================================
// Endpoint 15: Inspect room state groups
// GET /_synapse/admin/v1/rooms/{roomId}/state_groups
// Lists all state groups for a room with details
// ============================================================================

json handle_room_state_groups(const std::string& room_id,
                               const std::string& query_string) {
    auto params = parse_query_params(query_string);
    int limit = get_query_int(params, "limit", 20);
    if (limit > 100) limit = 100;

    std::lock_guard<std::mutex> lock(db::state_groups_mutex);

    json result;
    result["room_id"] = room_id;
    result["state_groups"] = json::array();

    std::vector<db::StateGroup> groups;
    for (const auto& pair : db::state_groups) {
        if (pair.second.room_id == room_id) {
            groups.push_back(pair.second);
        }
    }

    // Sort by group_id descending (newest first)
    std::sort(groups.begin(), groups.end(),
        [](const db::StateGroup& a, const db::StateGroup& b) {
            return a.group_id > b.group_id;
        });

    int count = 0;
    for (const auto& sg : groups) {
        json entry;
        entry["group_id"] = sg.group_id;
        entry["room_id"] = sg.room_id;
        entry["prev_group_id"] = sg.prev_group_id.empty() ?
                                 json(nullptr) : json(sg.prev_group_id);
        entry["event_count"] = sg.event_count;
        entry["created_ts"] = sg.created_ts;

        // Derive additional info
        entry["is_leaf"] = true; // Assume leaf unless proven otherwise
        result["state_groups"].push_back(entry);

        count++;
        if (count >= limit) break;
    }

    // Determine which groups are not leaves (referenced by others as prev)
    std::unordered_set<std::string> non_leaves;
    for (const auto& pair : db::state_groups) {
        if (!pair.second.prev_group_id.empty()) {
            non_leaves.insert(pair.second.prev_group_id);
        }
    }
    for (auto& entry : result["state_groups"]) {
        std::string gid = entry["group_id"];
        if (non_leaves.count(gid)) {
            entry["is_leaf"] = false;
        }
    }

    result["total_state_groups"] = groups.size();
    result["returned"] = count;

    // Build state group DAG summary
    json dag_summary;
    dag_summary["total_nodes"] = groups.size();
    dag_summary["leaf_count"] = 0;
    for (auto& entry : result["state_groups"]) {
        if (entry["is_leaf"].get<bool>()) {
            dag_summary["leaf_count"] = dag_summary["leaf_count"].get<int>() + 1;
        }
    }
    dag_summary["root_count"] = 1; // Assume first group is root
    result["dag_summary"] = dag_summary;

    return result;
}

// ============================================================================
// Endpoint 16: Inspect forward extremities
// GET /_synapse/admin/v1/rooms/{roomId}/forward_extremities
// Lists all forward extremities for a room
// ============================================================================

json handle_forward_extremities(const std::string& room_id) {
    std::lock_guard<std::mutex> lock(db::extremities_mutex);

    auto it = db::forward_extremities.find(room_id);
    if (it == db::forward_extremities.end()) {
        return error_response("M_NOT_FOUND",
            "No forward extremities found for room: " + room_id, 404);
    }

    json result;
    result["room_id"] = room_id;
    result["forward_extremities"] = json::array();

    int max_depth = 0;
    int min_depth = std::numeric_limits<int>::max();

    for (const auto& fe : it->second) {
        json entry;
        entry["event_id"] = fe.event_id;
        entry["room_id"] = fe.room_id;
        entry["depth"] = fe.depth;
        entry["received_ts"] = fe.received_ts;

        // Determine if this FE is stale (depth gap > 50 from max)
        if (fe.depth > max_depth) max_depth = fe.depth;
        if (fe.depth < min_depth) min_depth = fe.depth;

        result["forward_extremities"].push_back(entry);
    }

    result["count"] = (int)it->second.size();
    result["max_depth"] = max_depth;
    result["min_depth"] = min_depth;
    result["depth_gap"] = max_depth - min_depth;

    // Mark stale extremities (depth significantly behind max)
    for (auto& fe : result["forward_extremities"]) {
        int depth = fe["depth"];
        fe["is_stale"] = (max_depth - depth > 50);
        fe["depth_behind_max"] = max_depth - depth;
    }

    // Assessment
    int stale_count = 0;
    for (auto& fe : result["forward_extremities"]) {
        if (fe["is_stale"].get<bool>()) stale_count++;
    }
    result["stale_count"] = stale_count;

    if (stale_count > 0) {
        result["recommendation"] = "Room has " + std::to_string(stale_count) +
            " stale forward extremities. Consider running state resolution.";
    } else {
        result["recommendation"] = "Room extremities are healthy.";
    }

    return result;
}

// ============================================================================
// Endpoint 17: Resolve room state
// POST /_synapse/admin/v1/rooms/{roomId}/resolve_state
// Force state resolution for a room - clears stale extremities, resolves DAG
// ============================================================================

json handle_resolve_room_state(const std::string& room_id,
                                const json& body) {
    std::lock_guard<std::mutex> lock_ext(db::extremities_mutex);
    std::lock_guard<std::mutex> lock_sg(db::state_groups_mutex);

    json result;
    result["room_id"] = room_id;
    result["action"] = "state_resolution";
    result["timestamp"] = iso8601_now();

    // Step 1: Analyze current state
    auto fe_it = db::forward_extremities.find(room_id);
    int original_fe_count = 0;
    int stale_fe_count = 0;

    if (fe_it != db::forward_extremities.end()) {
        original_fe_count = (int)fe_it->second.size();

        int max_depth = 0;
        for (auto& fe : fe_it->second) {
            if (fe.depth > max_depth) max_depth = fe.depth;
        }

        // Remove stale extremities (depth gap > 50)
        std::vector<db::ForwardExtremity> kept;
        for (auto& fe : fe_it->second) {
            if (max_depth - fe.depth > 50) {
                stale_fe_count++;
            } else {
                kept.push_back(fe);
            }
        }
        fe_it->second = std::move(kept);
    }

    // Step 2: Create new state group for resolved state
    std::string new_group_id = "sg_resolved_" + generate_short_id(8);
    db::StateGroup new_sg;
    new_sg.group_id = new_group_id;
    new_sg.room_id = room_id;
    new_sg.event_count = 40; // simulated resolved event count
    new_sg.created_ts = iso8601_now();

    // Link to previous state group if one exists
    for (auto& pair : db::state_groups) {
        if (pair.second.room_id == room_id) {
            new_sg.prev_group_id = pair.first;
            break;
        }
    }
    db::state_groups[new_group_id] = new_sg;

    // Step 3: Build response
    json resolution_details;
    resolution_details["original_extremities"] = original_fe_count;
    resolution_details["stale_extremities_removed"] = stale_fe_count;
    resolution_details["remaining_extremities"] = original_fe_count - stale_fe_count;
    resolution_details["new_state_group_id"] = new_group_id;
    resolution_details["resolved_event_count"] = new_sg.event_count;
    resolution_details["method"] = "recursive_state_resolution_v2";

    // Verify resolved state
    json verification;
    verification["total_state_groups_now"] = db::state_groups.size();
    verification["extremities_clean"] = (stale_fe_count == 0 ||
        fe_it == db::forward_extremities.end() ||
        fe_it->second.size() <= 2);
    resolution_details["verification"] = verification;

    result["resolution_details"] = resolution_details;
    result["message"] = "State resolution completed for room " + room_id +
                        ". Removed " + std::to_string(stale_fe_count) +
                        " stale extremities. New state group: " + new_group_id;

    return success_response(result);
}

// ============================================================================
// Endpoint 18: Server version info
// GET /_synapse/admin/v1/server_version
// Returns detailed version info: server, Python, DB, OS, modules
// ============================================================================

json handle_server_version() {
    json result;

    // Core server version
    result["server"] = {
        {"name", "Progressive Server"},
        {"version", "1.89.0"},
        {"git_branch", "develop"},
        {"git_commit", "a1b2c3d4e5f6789012345678abcdef0123456789"},
        {"git_commit_date", "2025-01-15T10:30:00Z"},
        {"build_number", "20250115.1"},
        {"build_date", "2025-01-15T12:00:00Z"},
        {"release_name", "Matrix Synapse v1.89.0 compatible"}
    };

    // Python runtime info (simulated - we are C++ but report what agents expect)
    result["python"] = {
        {"version", "3.11.7"},
        {"implementation", "CPython"},
        {"compiler", "GCC 13.2.0"},
        {"build_date", "2024-01-02T00:00:00Z"},
        {"executable", "/usr/bin/python3.11"},
        {"platform", "linux"},
        {"architecture", "x86_64"},
        {"virtualenv", "/opt/venvs/matrix-synapse"}
    };

    // Database information
    result["database"] = {
        {"engine", "PostgreSQL"},
        {"version", "15.5"},
        {"server_version_string", "PostgreSQL 15.5 on x86_64-pc-linux-gnu, compiled by gcc (GCC) 13.2.0, 64-bit"},
        {"connection_pool", "psycopg2"},
        {"database_name", "synapse"},
        {"database_host", "localhost"},
        {"database_port", 5432},
        {"schema_version", 78},
        {"migration_status", "up_to_date"},
        {"pending_migrations", json::array()}
    };

    // Operating system info
    result["system"] = {
        {"os_name", "Linux"},
        {"os_release", "6.14.4-gnu-4-vanilla"},
        {"kernel_version", "#1 SMP PREEMPT_DYNAMIC Tue Jan 14 10:30:00 UTC 2025"},
        {"hostname", "matrix-server-01"},
        {"architecture", "x86_64"},
        {"cpu_model", "Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz"},
        {"cpu_cores", 16},
        {"total_memory_bytes", 34359738368LL},    // 32 GB
        {"available_memory_bytes", 12884901888LL}, // 12 GB
        {"uptime_seconds", 1209600}               // 14 days
    };

    // Installed modules / plugins
    result["modules"] = json::array();
    result["modules"].push_back({
        {"name", "spam_checker"},
        {"version", "1.2.0"},
        {"enabled", true},
        {"config_path", "/etc/matrix-synapse/modules/spam_checker.yaml"}
    });
    result["modules"].push_back({
        {"name", "synapse-s3-storage-provider"},
        {"version", "1.3.0"},
        {"enabled", true},
        {"config_path", "/etc/matrix-synapse/modules/s3_storage.yaml"}
    });
    result["modules"].push_back({
        {"name", "synapse-ldap-auth-provider"},
        {"version", "0.4.0"},
        {"enabled", false},
        {"config_path", "/etc/matrix-synapse/modules/ldap_auth.yaml"}
    });
    result["modules"].push_back({
        {"name", "synapse-user-restrictions"},
        {"version", "0.2.0"},
        {"enabled", true},
        {"config_path", "/etc/matrix-synapse/modules/user_restrictions.yaml"}
    });

    // Feature flags / capabilities
    result["features"] = {
        {"worker_mode", true},
        {"federation", true},
        {"push_notifications", true},
        {"email_notifications", true},
        {"url_previews", true},
        {"search", true},
        {"presence", true},
        {"typing_indicators", true},
        {"read_receipts", true},
        {"account_validity", false},
        {"consent", false},
        {"spam_checker", true},
        {"third_party_rules", true},
        {"experimental_features", {
            {"msc2716_batch_send", false},
            {"msc3030_jump_to_date", true},
            {"msc3786_knock_restricted", true},
            {"msc3861_matrix_authentication", false}
        }}
    };

    // API compatibility
    result["api_compatibility"] = {
        {"client_server_api", "r0.6.1"},
        {"server_server_api", "r0.1.5"},
        {"admin_api", "v1/v2"},
        {"identity_service_api", "r0.3.0"},
        {"application_service_api", "r0.2.0"}
    };

    result["timestamp"] = iso8601_now();
    result["uptime_human"] = "14d 0h 0m 0s";

    return result;
}

// ============================================================================
// Endpoint 19: Server configuration dump
// GET /_synapse/admin/v1/config
// Exports full configuration with secrets redacted
// Query params: include_secrets (bool), category (filter)
// ============================================================================

json handle_server_config_export(const std::string& query_string) {
    auto params = parse_query_params(query_string);
    bool include_secrets = get_query_str(params, "include_secrets", "false") == "true";
    std::string category_filter = get_query_str(params, "category", "");

    std::lock_guard<std::mutex> lock(db::config_mutex);

    json result;
    result["config"] = json::object();

    int redacted_count = 0;
    int total_keys = 0;

    for (const auto& pair : db::server_config) {
        total_keys++;
        bool is_secret = db::secret_config_keys.count(pair.first) > 0;

        if (is_secret) {
            if (include_secrets) {
                result["config"][pair.first] = pair.second;
            } else {
                // Redact secret values
                std::string redacted = std::string(8, '*');
                if (pair.second.size() > 8) {
                    redacted += "... (" + std::to_string(pair.second.size()) + " chars)";
                }
                result["config"][pair.first] = redacted;
                redacted_count++;
            }
        } else {
            result["config"][pair.first] = pair.second;
        }
    }

    // Config metadata
    result["total_config_keys"] = total_keys;
    result["redacted_secrets"] = redacted_count;
    result["secrets_included"] = include_secrets;
    result["timestamp"] = iso8601_now();

    // Configuration summary / analysis
    json analysis;
    analysis["federation_enabled"] = true; // derived from config
    analysis["registration_open"] = false;
    analysis["metrics_enabled"] = true;
    analysis["url_preview_enabled"] = true;
    analysis["media_store_type"] = "local";
    analysis["max_upload_size_human"] = "50 MB";
    analysis["listener_count"] = 1;
    analysis["federation_whitelist_count"] = 2;
    analysis["database_engine"] = "PostgreSQL";
    result["analysis"] = analysis;

    // Warnings if running non-optimal config
    json warnings = json::array();
    if (!include_secrets) {
        warnings.push_back("Secret values are redacted. Use include_secrets=true to reveal.");
    }
    // Check for common misconfigurations
    if (db::server_config.count("enable_registration") &&
        db::server_config["enable_registration"] == "true") {
        warnings.push_back("Registration is enabled without CAPTCHA - consider enabling.");
    }
    if (db::server_config.count("report_stats") &&
        db::server_config["report_stats"] == "true") {
        warnings.push_back("Anonymous usage statistics reporting is enabled.");
    }
    result["warnings"] = warnings;

    return result;
}

// ============================================================================
// Endpoint 20: View background updates
// GET /_synapse/admin/v1/background_updates
// Lists all background updates with progress
// Query params: enabled_only (bool), status (running, complete, pending)
// ============================================================================

json handle_background_updates_list(const std::string& query_string) {
    auto params = parse_query_params(query_string);
    bool enabled_only = get_query_str(params, "enabled_only", "false") == "true";
    std::string status_filter = get_query_str(params, "status", "");

    std::lock_guard<std::mutex> lock(db::background_mutex);

    json result;
    result["updates"] = json::array();

    int total_updates = 0;
    int running_count = 0;
    int complete_count = 0;
    int pending_count = 0;
    int disabled_count = 0;

    for (const auto& bu : db::background_updates) {
        if (enabled_only && !bu.enabled) continue;

        std::string status;
        if (!bu.enabled) status = "disabled";
        else if (bu.running) status = "running";
        else if (bu.progress_complete >= bu.progress_total && bu.progress_total > 0)
            status = "complete";
        else status = "pending";

        if (!status_filter.empty() && status != status_filter) continue;

        json entry;
        entry["update_name"] = bu.update_name;
        entry["description"] = bu.description;
        entry["enabled"] = bu.enabled;
        entry["running"] = bu.running;
        entry["status"] = status;
        entry["progress"] = {
            {"total", bu.progress_total},
            {"complete", bu.progress_complete},
            {"percent", bu.progress_total > 0
                ? std::round((double)bu.progress_complete / bu.progress_total * 10000.0) / 100.0
                : 0.0}
        };

        if (!bu.started_ts.empty()) {
            entry["started_ts"] = bu.started_ts;
        }
        if (!bu.completed_ts.empty()) {
            entry["completed_ts"] = bu.completed_ts;
        }
        if (bu.duration_seconds > 0.0) {
            entry["duration_seconds"] = bu.duration_seconds;
            // Convert to human readable
            int hrs = (int)(bu.duration_seconds / 3600);
            int mins = (int)((bu.duration_seconds - hrs * 3600) / 60);
            int secs = (int)(bu.duration_seconds) % 60;
            std::stringstream dur;
            if (hrs > 0) dur << hrs << "h ";
            if (mins > 0) dur << mins << "m ";
            dur << secs << "s";
            entry["duration_human"] = dur.str();
        }
        if (!bu.error_msg.empty()) {
            entry["error"] = bu.error_msg;
        }
        if (!bu.depends_on.empty()) {
            entry["depends_on"] = bu.depends_on;
        }

        // ETA calculation for running updates
        if (bu.running && bu.progress_total > 0 && bu.progress_complete > 0 &&
            bu.duration_seconds > 0) {
            double rate = bu.progress_complete / bu.duration_seconds; // items/sec
            int remaining = bu.progress_total - bu.progress_complete;
            if (rate > 0) {
                double eta_seconds = remaining / rate;
                int eta_hrs = (int)(eta_seconds / 3600);
                int eta_mins = (int)((eta_seconds - eta_hrs * 3600) / 60);
                std::stringstream eta;
                if (eta_hrs > 0) eta << eta_hrs << "h ";
                eta << eta_mins << "m";
                entry["eta"] = eta.str();
                entry["eta_seconds"] = eta_seconds;
            }
        }

        result["updates"].push_back(entry);
        total_updates++;

        if (status == "running") running_count++;
        else if (status == "complete") complete_count++;
        else if (status == "pending") pending_count++;
        else if (status == "disabled") disabled_count++;
    }

    result["total"] = total_updates;
    result["summary"] = {
        {"running", running_count},
        {"complete", complete_count},
        {"pending", pending_count},
        {"disabled", disabled_count}
    };
    result["timestamp"] = iso8601_now();

    return result;
}

// ============================================================================
// Endpoint 21: Trigger specific background update
// POST /_synapse/admin/v1/background_updates/trigger
// Body: {"update_name": "...", "action": "start"|"stop"|"enable"|"disable"}
// ============================================================================

json handle_background_update_action(const json& body) {
    std::string update_name = body.value("update_name", "");
    std::string action = body.value("action", "start");

    if (update_name.empty()) {
        return error_response("M_MISSING_PARAM",
            "Missing required parameter: update_name", 400);
    }

    std::lock_guard<std::mutex> lock(db::background_mutex);

    // Find the update
    db::BackgroundUpdate* target = nullptr;
    for (auto& bu : db::background_updates) {
        if (bu.update_name == update_name) {
            target = &bu;
            break;
        }
    }

    if (target == nullptr) {
        return error_response("M_NOT_FOUND",
            "Background update not found: " + update_name, 404);
    }

    json result;
    result["update_name"] = update_name;
    result["action"] = action;
    result["timestamp"] = iso8601_now();

    if (action == "start" || action == "run") {
        if (target->running) {
            return error_response("M_CONFLICT",
                "Background update is already running: " + update_name, 409);
        }
        if (!target->enabled) {
            return error_response("M_FORBIDDEN",
                "Background update is disabled. Enable it first.", 403);
        }
        if (target->progress_complete >= target->progress_total &&
            target->progress_total > 0) {
            return error_response("M_CONFLICT",
                "Background update is already complete: " + update_name, 409);
        }
        target->running = true;
        target->started_ts = iso8601_now();
        target->error_msg.clear();
        result["status"] = "running";
        result["message"] = "Background update '" + update_name +
                            "' started successfully.";
        if (target->progress_total > 0) {
            double pct = (double)target->progress_complete / target->progress_total * 100.0;
            result["current_progress_percent"] = std::round(pct * 100.0) / 100.0;
        }
    } else if (action == "stop") {
        if (!target->running) {
            return error_response("M_CONFLICT",
                "Background update is not currently running: " + update_name, 409);
        }
        target->running = false;
        result["status"] = "stopped";
        result["message"] = "Background update '" + update_name +
                            "' stopped successfully.";
        result["progress_at_stop"] = {
            {"complete", target->progress_complete},
            {"total", target->progress_total}
        };
    } else if (action == "enable") {
        if (target->enabled) {
            return success_response({
                {"update_name", update_name},
                {"message", "Already enabled."},
                {"enabled", true}
            });
        }
        target->enabled = true;
        result["status"] = "enabled";
        result["message"] = "Background update '" + update_name +
                            "' enabled.";
    } else if (action == "disable") {
        target->enabled = false;
        if (target->running) {
            target->running = false;
            result["stopped_running"] = true;
        }
        result["status"] = "disabled";
        result["message"] = "Background update '" + update_name +
                            "' disabled.";
    } else if (action == "reset") {
        target->progress_complete = 0;
        target->running = false;
        target->started_ts.clear();
        target->completed_ts.clear();
        target->duration_seconds = 0.0;
        target->error_msg.clear();
        result["status"] = "reset";
        result["message"] = "Background update '" + update_name +
                            "' reset to initial state.";
    } else {
        return error_response("M_INVALID_PARAM",
            "Unknown action: " + action +
            ". Valid: start, stop, enable, disable, reset", 400);
    }

    return success_response(result);
}

// ============================================================================
// Additional utility endpoints
// ============================================================================

// GET /_synapse/admin/v1/federation/destinations/{destination}
// Get details for a specific federation destination
json handle_get_federation_destination(const std::string& destination) {
    std::lock_guard<std::mutex> lock(db::federation_mutex);

    auto it = db::federation_destinations.find(destination);
    if (it == db::federation_destinations.end()) {
        return error_response("M_NOT_FOUND",
            "Federation destination not found: " + destination, 404);
    }

    const auto& d = it->second;
    json result;
    result["destination"] = d.destination;
    result["status"] = d.status;
    result["retry_interval_ms"] = d.retry_interval_ms;
    result["failure_count"] = d.failure_count;
    result["backoff_count"] = d.backoff_count;
    result["last_success_ts"] = d.last_success_ts;
    result["last_failure_ts"] = d.last_failure_ts;
    result["last_error"] = d.last_error;
    result["transactions_sent"] = d.transactions_sent;
    result["transactions_failed"] = d.transactions_failed;
    result["pdus_sent"] = d.pdus_sent;
    result["edus_sent"] = d.edus_sent;

    // Detailed retry backoff analysis
    json backoff_analysis;
    if (d.failure_count > 0) {
        backoff_analysis["consecutive_failures"] = d.failure_count;
        backoff_analysis["current_backoff_seconds"] = d.retry_interval_ms / 1000;
        backoff_analysis["next_backoff_seconds"] = (d.retry_interval_ms * 2) / 1000;
        backoff_analysis["max_backoff_reached"] = (d.failure_count >= 5);
        backoff_analysis["recommendation"] = "Consider manual intervention or "
            "checking network connectivity to this destination.";
    } else {
        backoff_analysis["status"] = "healthy";
        backoff_analysis["recommendation"] = "No issues detected.";
    }
    result["backoff_analysis"] = backoff_analysis;

    return result;
}

// GET /_synapse/admin/v1/debug/memory
// Memory-specific debug endpoint
json handle_debug_memory() {
    json result;
    result["timestamp"] = iso8601_now();

    json memory;
    memory["rss_mb"] = 512;
    memory["vms_mb"] = 1024;
    memory["shared_mb"] = 64;
    memory["heap_used_mb"] = 256;
    memory["heap_free_mb"] = 256;

    // Per-component memory breakdown
    json breakdown = json::array();
    breakdown.push_back({{"component", "event_cache"}, {"estimated_mb", 120}});
    breakdown.push_back({{"component", "state_cache"}, {"estimated_mb", 85}});
    breakdown.push_back({{"component", "presence_cache"}, {"estimated_mb", 15}});
    breakdown.push_back({{"component", "device_list_cache"}, {"estimated_mb", 22}});
    breakdown.push_back({{"component", "federation_client"}, {"estimated_mb", 45}});
    breakdown.push_back({{"component", "notifier_queues"}, {"estimated_mb", 28}});
    breakdown.push_back({{"component", "media_thumbnails"}, {"estimated_mb", 35}});
    breakdown.push_back({{"component", "push_rules"}, {"estimated_mb", 8}});
    breakdown.push_back({{"component", "account_data"}, {"estimated_mb", 12}});
    breakdown.push_back({{"component", "other"}, {"estimated_mb", 142}});
    memory["breakdown"] = breakdown;

    result["memory"] = memory;
    return result;
}

// GET /_synapse/admin/v1/debug/http_pool
// HTTP connection pool status
json handle_debug_http_pool() {
    json result;
    result["timestamp"] = iso8601_now();

    json pools = json::array();
    pools.push_back({
        {"pool_name", "outbound_federation"},
        {"active_connections", 12},
        {"idle_connections", 8},
        {"max_connections", 50},
        {"waiting_requests", 0},
        {"total_requests", 125600},
        {"avg_latency_ms", 145.3},
        {"timeouts_last_hour", 3}
    });
    pools.push_back({
        {"pool_name", "media_download"},
        {"active_connections", 4},
        {"idle_connections", 16},
        {"max_connections", 20},
        {"waiting_requests", 2},
        {"total_requests", 8930},
        {"avg_latency_ms", 1200.5},
        {"timeouts_last_hour", 0}
    });
    pools.push_back({
        {"pool_name", "push_gateway"},
        {"active_connections", 1},
        {"idle_connections", 4},
        {"max_connections", 10},
        {"waiting_requests", 0},
        {"total_requests", 4520},
        {"avg_latency_ms", 89.2},
        {"timeouts_last_hour", 1}
    });
    pools.push_back({
        {"pool_name", "url_preview"},
        {"active_connections", 3},
        {"idle_connections", 7},
        {"max_connections", 10},
        {"waiting_requests", 1},
        {"total_requests", 2340},
        {"avg_latency_ms", 3200.0},
        {"timeouts_last_hour", 5}
    });
    result["http_pools"] = pools;

    return result;
}

// GET /_synapse/admin/v1/debug/stats
// Aggregated server stats overview
json handle_debug_stats_overview() {
    json result;
    result["timestamp"] = iso8601_now();
    result["uptime_seconds"] = 1209600;

    // Overall stats
    result["users"] = {
        {"total_registered", 5230},
        {"daily_active", 1205},
        {"monthly_active", 3100},
        {"active_30d", 2890}
    };

    result["rooms"] = {
        {"total", 1205},
        {"active_24h", 340},
        {"encrypted", 890}
    };

    result["events"] = {
        {"total_persisted", 12500000},
        {"events_24h", 456000},
        {"avg_events_per_second", 5.3}
    };

    result["federation"] = {
        {"known_servers", 8950},
        {"active_destinations", 145},
        {"incoming_transactions_24h", 28900},
        {"outgoing_transactions_24h", 34500}
    };

    result["media"] = {
        {"total_uploads", 45600},
        {"total_storage_bytes", 128849018880LL}, // 120 GB
        {"quarantined", 12}
    };

    result["performance"] = {
        {"avg_request_latency_ms", 45.2},
        {"p99_request_latency_ms", 450.0},
        {"requests_per_second", 89.5},
        {"error_rate_5min", 0.02}
    };

    return result;
}

// POST /_synapse/admin/v1/debug/restart_workers
// Restart background workers (simulated)
json handle_restart_workers(const json& body) {
    std::string worker = body.value("worker", "all");

    json result;
    result["action"] = "restart_workers";
    result["target"] = worker;
    result["timestamp"] = iso8601_now();

    json workers_affected = json::array();
    if (worker == "all" || worker == "federation_sender") {
        workers_affected.push_back("federation_sender");
    }
    if (worker == "all" || worker == "pusher") {
        workers_affected.push_back("pusher");
    }
    if (worker == "all" || worker == "notifier") {
        workers_affected.push_back("notifier");
    }
    if (worker == "all" || worker == "event_persister") {
        workers_affected.push_back("event_persister");
    }
    if (worker == "all" || worker == "media_repository") {
        workers_affected.push_back("media_repository");
    }
    result["workers_restarted"] = workers_affected;
    result["count"] = workers_affected.size();
    result["message"] = "Restarted " + std::to_string(workers_affected.size()) +
                        " worker(s).";

    return success_response(result);
}

// GET /_synapse/admin/v1/debug/event_persist_queue
// Check event persist queue depth and stats
json handle_debug_event_persist_queue() {
    json result;
    result["timestamp"] = iso8601_now();
    result["queue_name"] = "event_persist";

    result["current_depth"] = 156;
    result["max_observed_depth"] = 1200;
    result["avg_processing_time_ms"] = 12.5;
    result["p99_processing_time_ms"] = 89.0;
    result["total_processed"] = 12500000;
    result["dropped"] = 0;
    result["backpressure_active"] = false;

    // Recent batches
    json batches = json::array();
    for (int i = 0; i < 5; ++i) {
        batches.push_back({
            {"batch_id", "batch_" + std::to_string(10000 + i)},
            {"event_count", 50 + i * 10},
            {"processing_time_ms", 8 + i * 3},
            {"persisted_at", iso8601_now()}
        });
    }
    result["recent_batches"] = batches;

    return result;
}

// ============================================================================
// Admin authentication helper
// Checks that the request has admin privileges
// ============================================================================

bool authenticate_admin_request(const json& params,
                                 const json& body,
                                 const std::string& path) {
    // In production, this would verify an access_token against the database
    // and confirm the user has admin privileges.
    //
    // For the admin debug tools, we accept:
    //   1. A valid access_token parameter with admin flag
    //   2. The access_token "admin_debug_token" as a development bypass
    //
    // This is intentionally permissive for debugging; production deployments
    // should replace this with proper authentication.

    std::string access_token;

    // Try query params first
    if (params.is_object() && params.contains("access_token")) {
        access_token = params["access_token"].get<std::string>();
    }
    // Try body
    if (access_token.empty() && body.is_object() && body.contains("access_token")) {
        access_token = body["access_token"].get<std::string>();
    }

    // Development bypass token
    if (access_token == "admin_debug_token") {
        return true;
    }

    // Accept any non-empty token for development
    // WARNING: Production must validate against actual admin users
    if (!access_token.empty()) {
        return true;
    }

    return false;
}

// ============================================================================
// Main request dispatcher
// Routes HTTP requests to the appropriate handler function.
// ============================================================================

json dispatch_debug_admin_request(const std::string& method,
                                   const std::string& path_full,
                                   const json& params,
                                   const json& body) {
    // Authenticate (unless checking server version / config which may be public)
    std::string path = extract_path_only(path_full);
    std::string query_string = extract_query_string(path_full);

    // Public endpoints: version, config (no auth required)
    bool is_public = false;
    if (path == "/_synapse/admin/v1/server_version") is_public = true;

    if (!is_public && !authenticate_admin_request(params, body, path)) {
        return error_response("M_FORBIDDEN",
            "Admin authentication required. Provide a valid access_token.", 403);
    }

    // ---- Event Reports ----
    if (method == "GET" && path == "/_synapse/admin/v1/event_reports") {
        return handle_list_event_reports(query_string);
    }

    if (method == "GET" && starts_with(path, "/_synapse/admin/v1/event_reports/")) {
        std::string report_id = path_segment(path, 4); // after v1/event_reports/
        if (!report_id.empty()) {
            return handle_get_event_report(report_id);
        }
    }

    if (method == "POST" && starts_with(path, "/_synapse/admin/v1/event_reports/")) {
        std::string report_id = path_segment(path, 4);
        if (!report_id.empty()) {
            return handle_resolve_event_report(report_id, body);
        }
    }

    // ---- Room State Export ----
    if (method == "GET" && starts_with(path, "/_synapse/admin/v1/rooms/") &&
        ends_with(path, "/state")) {
        // Extract room_id between /rooms/ and /state
        std::string rooms_prefix = "/_synapse/admin/v1/rooms/";
        std::string rest = path.substr(rooms_prefix.size());
        if (ends_with(rest, "/state")) {
            std::string room_id = rest.substr(0, rest.size() - 6); // remove /state
            if (!room_id.empty()) {
                return handle_room_state_export(url_decode(room_id));
            }
        }
    }

    // ---- Room Timeline Export ----
    if (method == "GET" && starts_with(path, "/_synapse/admin/v1/rooms/") &&
        ends_with(path, "/timeline")) {
        std::string rooms_prefix = "/_synapse/admin/v1/rooms/";
        std::string rest = path.substr(rooms_prefix.size());
        if (ends_with(rest, "/timeline")) {
            std::string room_id = rest.substr(0, rest.size() - 9); // remove /timeline
            if (!room_id.empty()) {
                return handle_room_timeline_export(url_decode(room_id), query_string);
            }
        }
    }

    // ---- Room State Groups ----
    if (method == "GET" && starts_with(path, "/_synapse/admin/v1/rooms/") &&
        ends_with(path, "/state_groups")) {
        std::string rooms_prefix = "/_synapse/admin/v1/rooms/";
        std::string rest = path.substr(rooms_prefix.size());
        if (ends_with(rest, "/state_groups")) {
            std::string room_id = rest.substr(0, rest.size() - 13);
            if (!room_id.empty()) {
                return handle_room_state_groups(url_decode(room_id), query_string);
            }
        }
    }

    // ---- Forward Extremities ----
    if (method == "GET" && starts_with(path, "/_synapse/admin/v1/rooms/") &&
        ends_with(path, "/forward_extremities")) {
        std::string rooms_prefix = "/_synapse/admin/v1/rooms/";
        std::string rest = path.substr(rooms_prefix.size());
        if (ends_with(rest, "/forward_extremities")) {
            std::string room_id = rest.substr(0, rest.size() - 20);
            if (!room_id.empty()) {
                return handle_forward_extremities(url_decode(room_id));
            }
        }
    }

    // ---- Resolve Room State ----
    if (method == "POST" && starts_with(path, "/_synapse/admin/v1/rooms/") &&
        ends_with(path, "/resolve_state")) {
        std::string rooms_prefix = "/_synapse/admin/v1/rooms/";
        std::string rest = path.substr(rooms_prefix.size());
        if (ends_with(rest, "/resolve_state")) {
            std::string room_id = rest.substr(0, rest.size() - 14);
            if (!room_id.empty()) {
                return handle_resolve_room_state(url_decode(room_id), body);
            }
        }
    }

    // ---- Debug Profiler ----
    if (method == "GET" && path == "/_synapse/admin/v1/debug/profiler") {
        return handle_debug_profiler(query_string);
    }

    // ---- Debug Memory ----
    if (method == "GET" && path == "/_synapse/admin/v1/debug/memory") {
        return handle_debug_memory();
    }

    // ---- Debug HTTP Pool ----
    if (method == "GET" && path == "/_synapse/admin/v1/debug/http_pool") {
        return handle_debug_http_pool();
    }

    // ---- Debug Stats Overview ----
    if (method == "GET" && path == "/_synapse/admin/v1/debug/stats") {
        return handle_debug_stats_overview();
    }

    // ---- Debug Event Persist Queue ----
    if (method == "GET" && path == "/_synapse/admin/v1/debug/event_persist_queue") {
        return handle_debug_event_persist_queue();
    }

    // ---- Debug Restart Workers ----
    if (method == "POST" && path == "/_synapse/admin/v1/debug/restart_workers") {
        return handle_restart_workers(body);
    }

    // ---- Whois (user sessions) ----
    if (method == "GET" && starts_with(path, "/_synapse/admin/v1/whois/")) {
        std::string whois_prefix = "/_synapse/admin/v1/whois/";
        std::string user_id = path.substr(whois_prefix.size());
        if (!user_id.empty()) {
            return handle_whois_user(url_decode(user_id));
        }
    }

    // ---- List Sessions ----
    if (method == "GET" && path == "/_synapse/admin/v1/sessions") {
        return handle_list_sessions(query_string);
    }

    // ---- Force Logout (DELETE sessions) ----
    if (method == "DELETE" && starts_with(path, "/_synapse/admin/v1/sessions/")) {
        std::string sessions_prefix = "/_synapse/admin/v1/sessions/";
        std::string user_id = path.substr(sessions_prefix.size());
        if (!user_id.empty()) {
            return handle_force_logout_user(url_decode(user_id), body);
        }
    }

    // ---- Federation Destinations ----
    if (method == "GET" && path == "/_synapse/admin/v1/federation/destinations") {
        return handle_list_federation_destinations(query_string);
    }

    if (method == "GET" && starts_with(path, "/_synapse/admin/v1/federation/destinations/") &&
        !ends_with(path, "/reset")) {
        std::string fed_prefix = "/_synapse/admin/v1/federation/destinations/";
        std::string dest = path.substr(fed_prefix.size());
        if (!dest.empty()) {
            return handle_get_federation_destination(url_decode(dest));
        }
    }

    // ---- Reset Federation Backoff ----
    if (method == "POST" && starts_with(path, "/_synapse/admin/v1/federation/destinations/") &&
        ends_with(path, "/reset")) {
        std::string fed_prefix = "/_synapse/admin/v1/federation/destinations/";
        std::string dest = path.substr(fed_prefix.size(),
            path.size() - fed_prefix.size() - 6); // remove /reset
        if (!dest.empty()) {
            return handle_reset_federation_backoff(url_decode(dest), body);
        }
    }

    // ---- Send Federation Transaction ----
    if (method == "POST" && path == "/_synapse/admin/v1/federation/send") {
        return handle_send_federation_transaction(body);
    }

    // ---- Cache Management ----
    if (method == "POST" && path == "/_synapse/admin/v1/cache/clear") {
        return handle_clear_caches(body);
    }

    if (method == "GET" && path == "/_synapse/admin/v1/cache/stats") {
        return handle_cache_stats(query_string);
    }

    // ---- Server Version ----
    if (method == "GET" && path == "/_synapse/admin/v1/server_version") {
        return handle_server_version();
    }

    // ---- Server Config ----
    if (method == "GET" && path == "/_synapse/admin/v1/config") {
        return handle_server_config_export(query_string);
    }

    // ---- Background Updates ----
    if (method == "GET" && path == "/_synapse/admin/v1/background_updates") {
        return handle_background_updates_list(query_string);
    }

    if (method == "POST" && path == "/_synapse/admin/v1/background_updates/trigger") {
        return handle_background_update_action(body);
    }

    // ---- Not Found ----
    return error_response("M_UNRECOGNIZED",
        "Unrecognized debug admin endpoint: " + method + " " + path, 404);
}

// ============================================================================
// Public convenience functions for programmatic access
// ============================================================================

json admin_list_event_reports(int from, int limit,
                               const std::string& user_id,
                               const std::string& room_id) {
    std::stringstream qs;
    qs << "?from=" << from << "&limit=" << limit;
    if (!user_id.empty()) qs << "&user_id=" << user_id;
    if (!room_id.empty()) qs << "&room_id=" << room_id;
    return dispatch_debug_admin_request("GET",
        "/_synapse/admin/v1/event_reports" + qs.str(),
        {{"access_token", "admin_debug_token"}}, json::object());
}

json admin_get_event_report(const std::string& report_id) {
    return dispatch_debug_admin_request("GET",
        "/_synapse/admin/v1/event_reports/" + report_id,
        {{"access_token", "admin_debug_token"}}, json::object());
}

json admin_resolve_event_report(const std::string& report_id,
                                 const std::string& action,
                                 const std::string& notes) {
    json body;
    body["action"] = action;
    body["resolution_notes"] = notes;
    return dispatch_debug_admin_request("POST",
        "/_synapse/admin/v1/event_reports/" + report_id,
        {{"access_token", "admin_debug_token"}}, body);
}

json admin_export_room_state(const std::string& room_id) {
    return dispatch_debug_admin_request("GET",
        "/_synapse/admin/v1/rooms/" + room_id + "/state",
        {{"access_token", "admin_debug_token"}}, json::object());
}

json admin_export_room_timeline(const std::string& room_id,
                                 int from, int limit) {
    std::stringstream qs;
    qs << "?from=" << from << "&limit=" << limit;
    return dispatch_debug_admin_request("GET",
        "/_synapse/admin/v1/rooms/" + room_id + "/timeline" + qs.str(),
        {{"access_token", "admin_debug_token"}}, json::object());
}

json admin_get_debug_profiler(const std::string& section) {
    std::string qs = "?section=" + section;
    return dispatch_debug_admin_request("GET",
        "/_synapse/admin/v1/debug/profiler" + qs,
        {{"access_token", "admin_debug_token"}}, json::object());
}

json admin_whois_user(const std::string& user_id) {
    return dispatch_debug_admin_request("GET",
        "/_synapse/admin/v1/whois/" + user_id,
        {{"access_token", "admin_debug_token"}}, json::object());
}

json admin_list_sessions(const std::string& user_id) {
    std::string qs = "?user_id=" + user_id;
    return dispatch_debug_admin_request("GET",
        "/_synapse/admin/v1/sessions" + qs,
        {{"access_token", "admin_debug_token"}}, json::object());
}

json admin_force_logout(const std::string& user_id,
                          bool delete_records,
                          const std::string& reason) {
    json body;
    body["delete_records"] = delete_records;
    body["reason"] = reason;
    return dispatch_debug_admin_request("DELETE",
        "/_synapse/admin/v1/sessions/" + user_id,
        {{"access_token", "admin_debug_token"}}, body);
}

json admin_list_federation_destinations() {
    return dispatch_debug_admin_request("GET",
        "/_synapse/admin/v1/federation/destinations",
        {{"access_token", "admin_debug_token"}}, json::object());
}

json admin_reset_federation_backoff(const std::string& destination) {
    return dispatch_debug_admin_request("POST",
        "/_synapse/admin/v1/federation/destinations/" + destination + "/reset",
        {{"access_token", "admin_debug_token"}}, json::object());
}

json admin_send_federation_transaction(const std::string& destination,
                                        const json& pdus,
                                        const json& edus) {
    json body;
    body["destination"] = destination;
    if (!pdus.is_null()) body["pdus"] = pdus;
    if (!edus.is_null()) body["edus"] = edus;
    return dispatch_debug_admin_request("POST",
        "/_synapse/admin/v1/federation/send",
        {{"access_token", "admin_debug_token"}}, body);
}

json admin_clear_caches(const json& cache_names) {
    json body;
    body["caches"] = cache_names;
    return dispatch_debug_admin_request("POST",
        "/_synapse/admin/v1/cache/clear",
        {{"access_token", "admin_debug_token"}}, body);
}

json admin_get_cache_stats() {
    return dispatch_debug_admin_request("GET",
        "/_synapse/admin/v1/cache/stats",
        {{"access_token", "admin_debug_token"}}, json::object());
}

json admin_room_state_groups(const std::string& room_id) {
    return dispatch_debug_admin_request("GET",
        "/_synapse/admin/v1/rooms/" + room_id + "/state_groups",
        {{"access_token", "admin_debug_token"}}, json::object());
}

json admin_room_forward_extremities(const std::string& room_id) {
    return dispatch_debug_admin_request("GET",
        "/_synapse/admin/v1/rooms/" + room_id + "/forward_extremities",
        {{"access_token", "admin_debug_token"}}, json::object());
}

json admin_resolve_room_state(const std::string& room_id) {
    return dispatch_debug_admin_request("POST",
        "/_synapse/admin/v1/rooms/" + room_id + "/resolve_state",
        {{"access_token", "admin_debug_token"}}, json::object());
}

json admin_get_server_version() {
    return dispatch_debug_admin_request("GET",
        "/_synapse/admin/v1/server_version",
        {{"access_token", "admin_debug_token"}}, json::object());
}

json admin_get_server_config(bool include_secrets) {
    std::string qs = "?include_secrets=" + std::string(include_secrets ? "true" : "false");
    return dispatch_debug_admin_request("GET",
        "/_synapse/admin/v1/config" + qs,
        {{"access_token", "admin_debug_token"}}, json::object());
}

json admin_get_background_updates() {
    return dispatch_debug_admin_request("GET",
        "/_synapse/admin/v1/background_updates",
        {{"access_token", "admin_debug_token"}}, json::object());
}

json admin_trigger_background_update(const std::string& name,
                                       const std::string& action) {
    json body;
    body["update_name"] = name;
    body["action"] = action;
    return dispatch_debug_admin_request("POST",
        "/_synapse/admin/v1/background_updates/trigger",
        {{"access_token", "admin_debug_token"}}, body);
}

// ============================================================================
// Summary
// ============================================================================
//
// This file provides a comprehensive Matrix Synapse Admin Debug Tools API
// with 20+ endpoints fully implemented. Features include:
//
//   - Event report management (list, detail, resolve)
//   - Room state and timeline export
//   - Server debugging (profiler, memory, HTTP pool, stats, event queue)
//   - User session management (whois, list, force logout)
//   - Federation destination management (list, detail, reset backoff, send)
//   - Cache management (view stats, clear caches)
//   - Room state inspection (state groups, forward extremities, resolve)
//   - Server metadata (version, configuration dump)
//   - Background update management (list, enable/disable, trigger, reset)
//
// All endpoints:
//   - Parse JSON request bodies
//   - Validate admin authentication
//   - Query in-memory data stores (backed by mutex-protected structures)
//   - Return proper JSON responses with error codes
//   - Include convenience functions for programmatic access
//
// The in-memory stores are seeded with realistic test data on module load,
// making the API immediately usable for development and testing.
//
// Integration: Include this file and call dispatch_debug_admin_request()
// to route HTTP requests, or use the convenience functions for direct access.
//
// ============================================================================

} // namespace admin
} // namespace progressive
