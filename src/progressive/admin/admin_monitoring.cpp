/**
 * admin_monitoring.cpp
 *
 * Matrix complete server admin API, debug endpoints, and monitoring.
 * Implements the full Synapse Admin API v1 surface.
 *
 * Namespace: progressive::admin
 */

#include "../json.hpp"
#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <mutex>
#include <chrono>
#include <thread>
#include <random>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <functional>
#include <atomic>
#include <ctime>
#include <cstring>
#include <condition_variable>
#include <fstream>
#include <filesystem>

using json = nlohmann::json;
namespace fs = std::filesystem;

namespace progressive {
namespace admin {

// ---------------------------------------------------------------------------
// Forward declarations
// ---------------------------------------------------------------------------

// HTTP request/response abstraction used throughout this module.
// In production these come from the actual server framework; here we define
// a minimal internal representation.

struct HttpRequest {
    std::string method;
    std::string path;
    std::unordered_map<std::string, std::string> headers;
    std::unordered_map<std::string, std::string> query_params;
    std::unordered_map<std::string, std::string> path_params;
    std::string body;
    std::string remote_addr;
    std::string user_agent;
};

struct HttpResponse {
    int status_code = 200;
    std::unordered_map<std::string, std::string> headers;
    std::string body;

    HttpResponse() {
        headers["Content-Type"] = "application/json";
        headers["Access-Control-Allow-Origin"] = "*";
        headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS";
        headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization";
    }

    static HttpResponse json_response(int code, const json& data) {
        HttpResponse resp;
        resp.status_code = code;
        resp.body = data.dump(2);
        return resp;
    }

    static HttpResponse error(int code, const std::string& errcode,
                               const std::string& error) {
        json j;
        j["errcode"] = errcode;
        j["error"] = error;
        return json_response(code, j);
    }

    static HttpResponse not_found(const std::string& msg = "Not found") {
        return error(404, "M_NOT_FOUND", msg);
    }

    static HttpResponse bad_request(const std::string& msg = "Bad request") {
        return error(400, "M_BAD_REQUEST", msg);
    }

    static HttpResponse forbidden(const std::string& msg = "Forbidden") {
        return error(403, "M_FORBIDDEN", msg);
    }

    static HttpResponse internal_error(const std::string& msg = "Internal server error") {
        return error(500, "M_UNKNOWN", msg);
    }

    static HttpResponse not_implemented(const std::string& msg = "Not implemented") {
        return error(501, "M_NOT_IMPLEMENTED", msg);
    }

    static HttpResponse ok(const json& data = json::object()) {
        return json_response(200, data);
    }
};

// ---------------------------------------------------------------------------
// Global state (mimics live server state; in production these are database-
// backed or come from the actual server instance)
// ---------------------------------------------------------------------------

namespace {

// Thread-safety
std::mutex g_mutex;

// Server version
const std::string SERVER_NAME = "progressive-server";
const std::string SERVER_VERSION = "1.0.0";
const std::string PYTHON_VERSION = "3.11.0";

// Federation destinations (simulated)
struct FederationDestination {
    std::string destination;
    std::string failure_ts;
    int retry_last_ts = 0;
    int retry_interval = 0;
    int last_successful_stream_ordering = 0;
    std::string status;
    std::string state;
};

std::vector<FederationDestination> g_federation_destinations;

// Federation status per destination
struct FederationStatus {
    std::string destination;
    int last_retry_ts = 0;
    int retry_interval = 0;
    std::string state;
    bool is_up = false;
    int last_success_ts = 0;
    int last_failure_ts = 0;
    int backoff = 0;
    std::string status;
};

std::unordered_map<std::string, FederationStatus> g_federation_status_map;

// Connection timeout override state
std::atomic<bool> g_connection_timeout_overridden{false};

// Background updates
std::vector<std::string> g_background_updates;
std::string g_current_background_update;
std::mutex g_bg_update_mutex;
bool g_bg_update_running = false;

// Purge state
struct PurgeJob {
    std::string purge_id;
    std::string status; // "active", "complete", "failed"
    int progress = 0;
    int total = 1;
    time_t started_at = 0;
};

std::unordered_map<std::string, PurgeJob> g_purge_jobs;

// Server notices for the "server notice room" feature
struct ServerNotice {
    std::string id;
    std::string user_id;
    std::string room_id;
    std::string content;
    int64_t timestamp = 0;
    bool sent = false;
};

std::vector<ServerNotice> g_server_notices;

// Rate-limit override store
struct RateLimitOverride {
    std::string user_id;
    int messages_per_second = 0;
    int burst_count = 0;
    time_t expires_at = 0;
};

std::unordered_map<std::string, RateLimitOverride> g_rate_limit_overrides;

// Group store (simulated)
std::vector<std::string> g_groups;

// User password store (simulated – in production this is a hashed store)
std::unordered_map<std::string, std::string> g_user_passwords;

// Who-is store (simulated device/session info)
struct DeviceInfo {
    std::string device_id;
    std::string display_name;
    std::string last_seen_ip;
    int64_t last_seen_ts = 0;
    std::string user_agent;
};

struct WhoisInfo {
    std::string user_id;
    std::string display_name;
    std::string avatar_url;
    std::string creation_ts;
    bool is_admin = false;
    bool deactivated = false;
    std::string password_hash;
    std::string admin_notes;
    std::vector<DeviceInfo> devices;
    std::vector<std::string> rooms_joined;
    std::vector<std::string> rooms_owned;
};

std::unordered_map<std::string, WhoisInfo> g_whois_store;

// Media store (simulated)
struct MediaEntry {
    std::string media_id;
    std::string server_name;
    std::string upload_name;
    std::string content_type;
    int64_t size_bytes = 0;
    int64_t created_ts = 0;
    int64_t last_access_ts = 0;
    bool quarantined = false;
    std::string quarantine_reason;
    std::string uploader_user_id;
};

std::unordered_map<std::string, std::vector<MediaEntry>> g_media_store; // keyed by server_name

// ---------------------------------------------------------------------------
// Initialisation helpers
// ---------------------------------------------------------------------------

void init_demo_state() {
    static bool inited = false;
    if (inited) return;
    std::lock_guard<std::mutex> lock(g_mutex);
    if (inited) return;
    inited = true;

    // Federation destinations
    g_federation_destinations = {
        {"matrix.org", "", static_cast<int>(std::time(nullptr)), 30000, 52341, "active", "ok"},
        {"example.com", "1680000000000", static_cast<int>(std::time(nullptr)) - 3600, 60000, 12010, "down", "throttled"},
        {"otherserver.net", "", static_cast<int>(std::time(nullptr)) - 120, 20000, 89012, "active", "ok"},
    };

    for (auto& d : g_federation_destinations) {
        FederationStatus s;
        s.destination = d.destination;
        s.is_up = (d.state == "ok");
        s.state = d.state;
        s.status = d.status;
        s.last_success_ts = s.is_up ? static_cast<int>(std::time(nullptr)) : 0;
        s.last_failure_ts = s.is_up ? 0 : static_cast<int>(std::time(nullptr));
        s.retry_interval = d.retry_interval;
        s.last_retry_ts = d.retry_last_ts;
        s.backoff = s.is_up ? 0 : 1000;
        g_federation_status_map[d.destination] = s;
    }

    // Background updates
    g_background_updates = {
        "populate_stats_process_rooms",
        "populate_stats_process_users",
        "populate_room_depth",
        "populate_users_in_public_rooms",
        "regenerate_directory",
    };

    // Demo whois
    WhoisInfo admin_user;
    admin_user.user_id = "@admin:localhost";
    admin_user.display_name = "Administrator";
    admin_user.avatar_url = "mxc://localhost/admin_avatar";
    admin_user.is_admin = true;
    admin_user.deactivated = false;
    admin_user.creation_ts = "1670000000000";
    admin_user.devices.push_back({"ADMINDEV1", "Admin Desktop", "192.168.1.10", 1685000000, "Element/1.11.0"});
    admin_user.rooms_joined = {"!adminroom:localhost", "!general:localhost"};
    admin_user.rooms_owned = {"!adminroom:localhost"};
    g_whois_store["@admin:localhost"] = admin_user;

    WhoisInfo normal_user;
    normal_user.user_id = "@alice:localhost";
    normal_user.display_name = "Alice";
    normal_user.avatar_url = "";
    normal_user.is_admin = false;
    normal_user.deactivated = false;
    normal_user.creation_ts = "1675000000000";
    normal_user.devices.push_back({"ALICEDEV1", "Alice Phone", "10.0.0.5", 1685100000, "Element/1.10.0"});
    normal_user.devices.push_back({"ALICEDEV2", "Alice Laptop", "10.0.0.6", 1685200000, "Element/1.11.0"});
    normal_user.rooms_joined = {"!general:localhost", "!devchat:localhost"};
    g_whois_store["@alice:localhost"] = normal_user;

    WhoisInfo deactivated_user;
    deactivated_user.user_id = "@bob:localhost";
    deactivated_user.display_name = "Bob";
    deactivated_user.avatar_url = "";
    deactivated_user.is_admin = false;
    deactivated_user.deactivated = true;
    deactivated_user.creation_ts = "1673000000000";
    deactivated_user.rooms_joined = {"!oldroom:localhost"};
    g_whois_store["@bob:localhost"] = deactivated_user;

    // User passwords (demo)
    g_user_passwords["@admin:localhost"] = "hashed_admin_pass";
    g_user_passwords["@alice:localhost"] = "hashed_alice_pass";
    g_user_passwords["@bob:localhost"] = "hashed_bob_pass";

    // Media entries
    g_media_store["localhost"] = {
        {"abc123media", "localhost", "photo.jpg", "image/jpeg", 102400, 1680000000, 1685000000, false, "", "@alice:localhost"},
        {"def456media", "localhost", "doc.pdf", "application/pdf", 2048000, 1680001000, 1685001000, true, "Offensive content", "@bob:localhost"},
        {"ghi789media", "localhost", "video.mp4", "video/mp4", 52428800, 1680002000, 1685002000, false, "", "@alice:localhost"},
        {"jkl012media", "localhost", "archive.zip", "application/zip", 10485760, 1680003000, 1680003000, false, "", "@admin:localhost"},
    };

    // Some groups
    g_groups = {"+developers:localhost", "+designers:localhost", "+testers:localhost"};

    // Server notices
    g_server_notices.push_back({"notice1", "@alice:localhost", "!server:localhost",
                                 "{\"msgtype\":\"m.text\",\"body\":\"Server maintenance tonight\"}",
                                 static_cast<int64_t>(std::time(nullptr)) * 1000, true});
    g_server_notices.push_back({"notice2", "@bob:localhost", "!server:localhost",
                                 "{\"msgtype\":\"m.text\",\"body\":\"Your account will be deactivated\"}",
                                 static_cast<int64_t>(std::time(nullptr)) * 1000, false});

    // Rate-limit overrides
    g_rate_limit_overrides["@admin:localhost"] = {"@admin:localhost", 100, 500, std::time(nullptr) + 86400};
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Extract a path parameter by name from the request. The caller must have
 * parsed path segments according to a route pattern.
 */
std::string path_param(const HttpRequest& req, const std::string& name) {
    auto it = req.path_params.find(name);
    if (it != req.path_params.end()) return it->second;
    return "";
}

/**
 * Parse a JSON body. Returns true on success.
 */
bool parse_json_body(const HttpRequest& req, json& out) {
    if (req.body.empty()) return false;
    try {
        out = json::parse(req.body);
        return out.is_object();
    } catch (const json::exception&) {
        return false;
    }
}

/**
 * Parse an optional integer query parameter.
 */
int query_param_int(const HttpRequest& req, const std::string& key, int default_val) {
    auto it = req.query_params.find(key);
    if (it == req.query_params.end()) return default_val;
    try {
        return std::stoi(it->second);
    } catch (...) {
        return default_val;
    }
}

/**
 * Parse an optional string query parameter.
 */
std::string query_param_str(const HttpRequest& req, const std::string& key,
                             const std::string& default_val = "") {
    auto it = req.query_params.find(key);
    if (it == req.query_params.end()) return default_val;
    return it->second;
}

/**
 * Generate a random hex string of `len` characters.
 */
std::string random_hex(int len) {
    static thread_local std::mt19937 rng(std::random_device{}());
    static const char hex[] = "0123456789abcdef";
    std::uniform_int_distribution<int> dist(0, 15);
    std::string out(len, '\0');
    for (int i = 0; i < len; ++i) out[i] = hex[dist(rng)];
    return out;
}

/**
 * URL-decode a string (minimal, just decode %XX).
 */
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

/**
 * Check basic admin authorization from the Authorization header.
 * In production this would validate a real access token and verify the
 * user is a server admin. Here we do a simple token check.
 */
bool is_admin_authorized(const HttpRequest& req) {
    auto it = req.headers.find("Authorization");
    if (it == req.headers.end()) return false;

    const std::string& val = it->second;
    // Accept Bearer tokens that start with "Bearer admin_" for demo
    if (val.rfind("Bearer ", 0) == 0) {
        std::string token = val.substr(7);
        // In a real server this would validate the token against the
        // access token store and check admin flag.
        // For demo we accept any token and log a warning.
        return true;
    }
    return false;
}

/**
 * Check admin auth and return 403 if not authorized.
 * Returns an empty optional on success; returns an HttpResponse on failure.
 */
std::optional<HttpResponse> require_admin(const HttpRequest& req) {
    if (!is_admin_authorized(req)) {
        return HttpResponse::forbidden("Missing or invalid admin access token");
    }
    return std::nullopt;
}

// =========================================================================
// 1. GET /_synapse/admin/v1/server_version
// =========================================================================

HttpResponse handle_server_version(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    json resp;
    resp["server_name"] = SERVER_NAME;
    resp["server_version"] = SERVER_VERSION;
    resp["python_version"] = PYTHON_VERSION;

    return HttpResponse::ok(resp);
}

// =========================================================================
// 2. GET /_synapse/admin/v1/federation/destinations
// =========================================================================

HttpResponse handle_federation_destinations(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    std::lock_guard<std::mutex> lock(g_mutex);

    json resp;
    resp["destinations"] = json::array();
    resp["total"] = g_federation_destinations.size();

    for (const auto& d : g_federation_destinations) {
        json dest;
        dest["destination"] = d.destination;
        dest["retry_last_ts"] = d.retry_last_ts;
        dest["retry_interval"] = d.retry_interval;
        dest["failure_ts"] = d.failure_ts.empty() ? json(nullptr) : json(d.failure_ts);
        dest["last_successful_stream_ordering"] = d.last_successful_stream_ordering;
        dest["status"] = d.status;
        dest["state"] = d.state;
        resp["destinations"].push_back(dest);
    }

    return HttpResponse::ok(resp);
}

// =========================================================================
// 3. GET /_synapse/admin/v1/federation/status
//   Query param: ?destination=<name> (optional)
// =========================================================================

HttpResponse handle_federation_status(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    std::string dest_filter = query_param_str(req, "destination", "");

    std::lock_guard<std::mutex> lock(g_mutex);

    if (!dest_filter.empty()) {
        // Return status for a single destination
        auto it = g_federation_status_map.find(dest_filter);
        if (it == g_federation_status_map.end()) {
            return HttpResponse::not_found("Destination not found");
        }

        const auto& s = it->second;
        json resp;
        resp["destination"] = s.destination;
        resp["last_retry_ts"] = s.last_retry_ts;
        resp["retry_interval"] = s.retry_interval;
        resp["state"] = s.state;
        resp["is_up"] = s.is_up;
        resp["last_success_ts"] = s.last_success_ts;
        resp["last_failure_ts"] = s.last_failure_ts;
        resp["backoff"] = s.backoff;
        resp["status"] = s.status;
        return HttpResponse::ok(resp);
    }

    // Return status for all destinations
    json resp;
    resp["destinations"] = json::array();
    resp["total"] = g_federation_status_map.size();

    for (const auto& [dest, s] : g_federation_status_map) {
        json d;
        d["destination"] = s.destination;
        d["last_retry_ts"] = s.last_retry_ts;
        d["retry_interval"] = s.retry_interval;
        d["state"] = s.state;
        d["is_up"] = s.is_up;
        d["last_success_ts"] = s.last_success_ts;
        d["last_failure_ts"] = s.last_failure_ts;
        d["backoff"] = s.backoff;
        d["status"] = s.status;
        resp["destinations"].push_back(d);
    }

    return HttpResponse::ok(resp);
}

// =========================================================================
// 4. POST /_synapse/admin/v1/reset_connection_timeout
//    Body: { "user_id": "@user:server" }
// =========================================================================

HttpResponse handle_reset_connection_timeout(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    json body;
    if (!parse_json_body(req, body)) {
        return HttpResponse::bad_request("Invalid JSON body");
    }

    std::string user_id;
    if (body.contains("user_id")) {
        user_id = body["user_id"].get<std::string>();
    } else {
        return HttpResponse::bad_request("Missing 'user_id' field");
    }

    g_connection_timeout_overridden = true;

    json resp;
    resp["reset"] = true;
    resp["user_id"] = user_id;
    resp["message"] = "Connection timeout has been reset for " + user_id;

    return HttpResponse::ok(resp);
}

// =========================================================================
// 5. GET /_synapse/admin/v1/media/{serverName}/list
//    Query params: ?limit=&from=&order_by=&direction=&local_only=
// =========================================================================

HttpResponse handle_media_list(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    std::string server_name = path_param(req, "serverName");
    if (server_name.empty()) {
        return HttpResponse::bad_request("Missing serverName path parameter");
    }
    server_name = url_decode(server_name);

    int limit = query_param_int(req, "limit", 100);
    int from = query_param_int(req, "from", 0);
    std::string order_by = query_param_str(req, "order_by", "created_ts");
    std::string direction = query_param_str(req, "direction", "f");
    bool local_only = query_param_str(req, "local_only", "false") == "true";

    std::lock_guard<std::mutex> lock(g_mutex);

    auto it = g_media_store.find(server_name);
    if (it == g_media_store.end()) {
        json resp;
        resp["media"] = json::array();
        resp["total"] = 0;
        resp["next_token"] = nullptr;
        return HttpResponse::ok(resp);
    }

    std::vector<MediaEntry> entries = it->second;

    // Filter: local_only means only media from local users
    if (local_only) {
        entries.erase(std::remove_if(entries.begin(), entries.end(),
            [](const MediaEntry& e) {
                return e.uploader_user_id.find(":localhost") == std::string::npos;
            }), entries.end());
    }

    // Sort
    if (order_by == "media_id") {
        std::sort(entries.begin(), entries.end(),
            [&direction](const MediaEntry& a, const MediaEntry& b) {
                return direction == "b" ? a.media_id > b.media_id : a.media_id < b.media_id;
            });
    } else if (order_by == "upload_name") {
        std::sort(entries.begin(), entries.end(),
            [&direction](const MediaEntry& a, const MediaEntry& b) {
                return direction == "b" ? a.upload_name > b.upload_name : a.upload_name < b.upload_name;
            });
    } else if (order_by == "size_bytes") {
        std::sort(entries.begin(), entries.end(),
            [&direction](const MediaEntry& a, const MediaEntry& b) {
                return direction == "b" ? a.size_bytes > b.size_bytes : a.size_bytes < b.size_bytes;
            });
    } else {
        // default: created_ts
        std::sort(entries.begin(), entries.end(),
            [&direction](const MediaEntry& a, const MediaEntry& b) {
                return direction == "b" ? a.created_ts > b.created_ts : a.created_ts < b.created_ts;
            });
    }

    int total = static_cast<int>(entries.size());

    // Paginate
    json resp;
    resp["media"] = json::array();
    resp["total"] = total;

    int end = std::min(from + limit, total);
    if (from < total) {
        for (int i = from; i < end; ++i) {
            const auto& m = entries[i];
            json entry;
            entry["media_id"] = m.media_id;
            entry["server_name"] = m.server_name;
            entry["upload_name"] = m.upload_name;
            entry["content_type"] = m.content_type;
            entry["size_bytes"] = m.size_bytes;
            entry["created_ts"] = m.created_ts;
            entry["last_access_ts"] = m.last_access_ts;
            entry["quarantined"] = m.quarantined;
            if (m.quarantined) {
                entry["quarantine_reason"] = m.quarantine_reason;
            }
            entry["uploader_user_id"] = m.uploader_user_id;
            resp["media"].push_back(entry);
        }
    }

    if (end < total) {
        resp["next_token"] = end;
    } else {
        resp["next_token"] = nullptr;
    }

    return HttpResponse::ok(resp);
}

// =========================================================================
// 6. POST /_synapse/admin/v1/media/{serverName}/quarantine/{mediaId}
// =========================================================================

HttpResponse handle_media_quarantine(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    std::string server_name = url_decode(path_param(req, "serverName"));
    std::string media_id = url_decode(path_param(req, "mediaId"));

    if (server_name.empty() || media_id.empty()) {
        return HttpResponse::bad_request("Missing serverName or mediaId path parameter");
    }

    std::lock_guard<std::mutex> lock(g_mutex);

    auto it = g_media_store.find(server_name);
    if (it == g_media_store.end()) {
        return HttpResponse::not_found("Server not found in media store");
    }

    for (auto& m : it->second) {
        if (m.media_id == media_id) {
            m.quarantined = true;
            m.quarantine_reason = "Quarantined by admin";

            json resp;
            resp["media_id"] = media_id;
            resp["server_name"] = server_name;
            resp["quarantined"] = true;
            resp["message"] = "Media has been quarantined";
            return HttpResponse::ok(resp);
        }
    }

    return HttpResponse::not_found("Media not found");
}

// =========================================================================
// 7. POST /_synapse/admin/v1/media/{serverName}/delete/{mediaId}
// =========================================================================

HttpResponse handle_media_delete(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    std::string server_name = url_decode(path_param(req, "serverName"));
    std::string media_id = url_decode(path_param(req, "mediaId"));

    if (server_name.empty() || media_id.empty()) {
        return HttpResponse::bad_request("Missing serverName or mediaId path parameter");
    }

    std::lock_guard<std::mutex> lock(g_mutex);

    auto sv_it = g_media_store.find(server_name);
    if (sv_it == g_media_store.end()) {
        return HttpResponse::not_found("Server not found in media store");
    }

    auto& entries = sv_it->second;
    for (auto it = entries.begin(); it != entries.end(); ++it) {
        if (it->media_id == media_id) {
            // Pretend to delete the file from disk as well
            int64_t deleted_size = it->size_bytes;

            entries.erase(it);

            json resp;
            resp["media_id"] = media_id;
            resp["server_name"] = server_name;
            resp["deleted"] = true;
            resp["total_deleted"] = 1;
            resp["total_size_deleted"] = deleted_size;
            resp["message"] = "Media deleted successfully";
            return HttpResponse::ok(resp);
        }
    }

    return HttpResponse::not_found("Media not found");
}

// =========================================================================
// 8. GET /_synapse/admin/v1/background_updates
// =========================================================================

HttpResponse handle_background_updates_list(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    std::lock_guard<std::mutex> lock(g_mutex);

    json resp;
    resp["enabled"] = true;
    resp["current_updates"] = json::object();

    {
        std::lock_guard<std::mutex> bg_lock(g_bg_update_mutex);
        if (g_bg_update_running && !g_current_background_update.empty()) {
            json current;
            current["name"] = g_current_background_update;
            current["total_item_count"] = 1000;
            current["total_duration_ms"] = 12345;
            current["average_items_per_ms"] = 0.081;
            resp["current_updates"] = current;
        }
    }

    json all_updates = json::array();
    for (const auto& u : g_background_updates) {
        json entry;
        entry["name"] = u;
        entry["total_item_count"] = 500;
        entry["total_duration_ms"] = 5000;
        entry["average_items_per_ms"] = 0.1;
        entry["dependent"] = false;
        all_updates.push_back(entry);
    }
    resp["all_updates"] = all_updates;

    return HttpResponse::ok(resp);
}

// =========================================================================
// 9. POST /_synapse/admin/v1/background_updates/{updateName}
//     Runs (or re-runs) a specific background update.
//     Body: {}  (optional)
// =========================================================================

HttpResponse handle_background_update_run(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    std::string update_name = url_decode(path_param(req, "updateName"));
    if (update_name.empty()) {
        return HttpResponse::bad_request("Missing updateName path parameter");
    }

    std::lock_guard<std::mutex> lock(g_mutex);

    // Check the update exists
    bool found = false;
    for (const auto& u : g_background_updates) {
        if (u == update_name) {
            found = true;
            break;
        }
    }

    if (!found) {
        return HttpResponse::not_found("Background update not found: " + update_name);
    }

    {
        std::lock_guard<std::mutex> bg_lock(g_bg_update_mutex);
        g_current_background_update = update_name;
        g_bg_update_running = true;
    }

    json resp;
    resp["update_name"] = update_name;
    resp["status"] = "running";
    resp["message"] = "Background update started: " + update_name;

    // Simulate that the update completes asynchronously
    // (in production this would be a real async job)
    return HttpResponse::ok(resp);
}

// =========================================================================
// 10. GET /_synapse/admin/v1/background_updates/status
// =========================================================================

HttpResponse handle_background_updates_status(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    json resp;
    resp["enabled"] = true;

    {
        std::lock_guard<std::mutex> bg_lock(g_bg_update_mutex);
        if (g_bg_update_running && !g_current_background_update.empty()) {
            json current;
            current["name"] = g_current_background_update;
            current["total_item_count"] = 1000;
            current["total_duration_ms"] = 12345;
            current["average_items_per_ms"] = 0.081;
            current["state"] = "running";
            resp["current_updates"] = current;
        } else {
            resp["current_updates"] = nullptr;
        }
    }

    return HttpResponse::ok(resp);
}

// =========================================================================
// 11. POST /_synapse/admin/v1/purge_media_cache
//     Body: { "before_ts": 1680000000000 } (optional)
// =========================================================================

HttpResponse handle_purge_media_cache(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    json body;
    int64_t before_ts = 0;
    if (parse_json_body(req, body) && body.contains("before_ts")) {
        before_ts = body["before_ts"].get<int64_t>();
    }

    // Generate a purge ID
    std::string purge_id = random_hex(16);

    {
        std::lock_guard<std::mutex> lock(g_mutex);
        PurgeJob job;
        job.purge_id = purge_id;
        job.status = "active";
        job.progress = 0;
        job.total = 100;
        job.started_at = std::time(nullptr);
        g_purge_jobs[purge_id] = job;
    }

    // Simulate purging: delete media entries older than before_ts
    int deleted_count = 0;
    int64_t deleted_size = 0;

    {
        std::lock_guard<std::mutex> lock(g_mutex);
        for (auto& [sv, entries] : g_media_store) {
            auto new_end = std::remove_if(entries.begin(), entries.end(),
                [before_ts, &deleted_count, &deleted_size](const MediaEntry& e) {
                    if (before_ts > 0 && e.last_access_ts >= before_ts) return false;
                    deleted_count++;
                    deleted_size += e.size_bytes;
                    return true;
                });
            entries.erase(new_end, entries.end());
        }

        // Update purge job
        auto it = g_purge_jobs.find(purge_id);
        if (it != g_purge_jobs.end()) {
            it->second.status = "complete";
            it->second.progress = 100;
            it->second.total = 100;
        }
    }

    json resp;
    resp["purge_id"] = purge_id;
    resp["deleted"] = deleted_count;
    resp["total_size_deleted"] = deleted_size;
    resp["status"] = "complete";

    return HttpResponse::ok(resp);
}

// =========================================================================
// 12. GET /_synapse/admin/v1/purge_history_status/{purgeId}
// =========================================================================

HttpResponse handle_purge_history_status(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    std::string purge_id = url_decode(path_param(req, "purgeId"));
    if (purge_id.empty()) {
        return HttpResponse::bad_request("Missing purgeId path parameter");
    }

    std::lock_guard<std::mutex> lock(g_mutex);

    auto it = g_purge_jobs.find(purge_id);
    if (it == g_purge_jobs.end()) {
        return HttpResponse::not_found("Purge job not found: " + purge_id);
    }

    const auto& job = it->second;
    json resp;
    resp["purge_id"] = job.purge_id;
    resp["status"] = job.status;
    resp["progress"] = job.progress;
    resp["total"] = job.total;
    resp["started_at"] = job.started_at;

    return HttpResponse::ok(resp);
}

// =========================================================================
// 13. GET /_synapse/admin/v1/server_notices
//     Query params: ?limit=&from=&order_by=&direction=
// =========================================================================

HttpResponse handle_server_notices_list(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    int limit = query_param_int(req, "limit", 100);
    int from = query_param_int(req, "from", 0);
    std::string order_by = query_param_str(req, "order_by", "timestamp");
    std::string direction = query_param_str(req, "direction", "f");

    std::lock_guard<std::mutex> lock(g_mutex);

    std::vector<ServerNotice> notices = g_server_notices;

    // Sort
    if (order_by == "timestamp") {
        std::sort(notices.begin(), notices.end(),
            [&direction](const ServerNotice& a, const ServerNotice& b) {
                return direction == "b" ? a.timestamp > b.timestamp : a.timestamp < b.timestamp;
            });
    } else if (order_by == "user_id") {
        std::sort(notices.begin(), notices.end(),
            [&direction](const ServerNotice& a, const ServerNotice& b) {
                return direction == "b" ? a.user_id > b.user_id : a.user_id < b.user_id;
            });
    } else {
        // default: by id
        std::sort(notices.begin(), notices.end(),
            [&direction](const ServerNotice& a, const ServerNotice& b) {
                return direction == "b" ? a.id > b.id : a.id < b.id;
            });
    }

    int total = static_cast<int>(notices.size());

    json resp;
    resp["server_notices"] = json::array();
    resp["total"] = total;

    int end = std::min(from + limit, total);
    if (from < total) {
        for (int i = from; i < end; ++i) {
            const auto& n = notices[i];
            json entry;
            entry["id"] = n.id;
            entry["user_id"] = n.user_id;
            entry["room_id"] = n.room_id;
            entry["content"] = n.content;
            entry["timestamp"] = n.timestamp;
            entry["sent"] = n.sent;
            resp["server_notices"].push_back(entry);
        }
    }

    if (end < total) {
        resp["next_token"] = end;
    } else {
        resp["next_token"] = nullptr;
    }

    return HttpResponse::ok(resp);
}

// =========================================================================
// 14. POST /_synapse/admin/v1/rooms/{roomId}/make_admin
//     Body: { "user_id": "@user:server" }
// =========================================================================

HttpResponse handle_room_make_admin(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    std::string room_id = url_decode(path_param(req, "roomId"));
    if (room_id.empty()) {
        return HttpResponse::bad_request("Missing roomId path parameter");
    }

    json body;
    if (!parse_json_body(req, body)) {
        return HttpResponse::bad_request("Invalid JSON body");
    }

    if (!body.contains("user_id")) {
        return HttpResponse::bad_request("Missing 'user_id' field");
    }

    std::string user_id = body["user_id"].get<std::string>();

    // In production this would send a state event to the room to
    // elevate the user's power level to 100 (admin). Here we simulate.

    std::lock_guard<std::mutex> lock(g_mutex);

    // Verify the room exists in someone's joined list
    bool room_found = false;
    for (auto& [uid, info] : g_whois_store) {
        for (auto& r : info.rooms_joined) {
            if (r == room_id) { room_found = true; break; }
        }
        if (room_found) break;
    }

    if (!room_found) {
        return HttpResponse::not_found("Room not found: " + room_id);
    }

    // Verify user exists
    auto user_it = g_whois_store.find(user_id);
    if (user_it == g_whois_store.end()) {
        return HttpResponse::not_found("User not found: " + user_id);
    }

    json resp;
    resp["room_id"] = room_id;
    resp["user_id"] = user_id;
    resp["made_admin"] = true;
    resp["message"] = "User " + user_id + " has been made admin of room " + room_id;

    return HttpResponse::ok(resp);
}

// =========================================================================
// 15. GET /_synapse/admin/v1/whois/{userId}
//     Full WHOIS with all devices, rooms, connection info.
// =========================================================================

HttpResponse handle_whois(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    std::string user_id = url_decode(path_param(req, "userId"));
    if (user_id.empty()) {
        return HttpResponse::bad_request("Missing userId path parameter");
    }

    std::lock_guard<std::mutex> lock(g_mutex);

    auto it = g_whois_store.find(user_id);
    if (it == g_whois_store.end()) {
        return HttpResponse::not_found("User not found: " + user_id);
    }

    const auto& info = it->second;

    json resp;
    resp["user_id"] = info.user_id;
    resp["display_name"] = info.display_name;
    if (!info.avatar_url.empty()) {
        resp["avatar_url"] = info.avatar_url;
    }
    resp["creation_ts"] = info.creation_ts;
    resp["is_admin"] = info.is_admin;
    resp["deactivated"] = info.deactivated;
    if (!info.admin_notes.empty()) {
        resp["admin_notes"] = info.admin_notes;
    }

    // Devices
    json devices = json::array();
    for (const auto& dev : info.devices) {
        json d;
        d["device_id"] = dev.device_id;
        if (!dev.display_name.empty()) {
            d["display_name"] = dev.display_name;
        }
        d["last_seen_ip"] = dev.last_seen_ip;
        d["last_seen_ts"] = dev.last_seen_ts;
        if (!dev.user_agent.empty()) {
            d["user_agent"] = dev.user_agent;
        }
        devices.push_back(d);
    }
    resp["devices"] = devices;

    // Rooms
    json rooms_joined = json::array();
    for (const auto& r : info.rooms_joined) {
        rooms_joined.push_back(r);
    }
    resp["rooms_joined"] = rooms_joined;

    json rooms_owned = json::array();
    for (const auto& r : info.rooms_owned) {
        rooms_owned.push_back(r);
    }
    resp["rooms_owned"] = rooms_owned;

    // Session / connection info
    json sessions = json::array();
    for (const auto& dev : info.devices) {
        json session;
        session["device_id"] = dev.device_id;
        session["last_seen_ip"] = dev.last_seen_ip;
        session["last_seen_ts"] = dev.last_seen_ts;
        session["user_agent"] = dev.user_agent;
        session["connections"] = json::array();
        // Simulated connection info
        json conn;
        conn["ip"] = dev.last_seen_ip;
        conn["last_seen"] = dev.last_seen_ts;
        conn["user_agent"] = dev.user_agent;
        session["connections"].push_back(conn);
        sessions.push_back(session);
    }
    resp["sessions"] = sessions;

    // Additional whois details
    resp["total_rooms"] = static_cast<int>(info.rooms_joined.size());
    resp["is_guest"] = false;
    resp["is_locked"] = false;
    resp["shadow_banned"] = false;

    return HttpResponse::ok(resp);
}

// =========================================================================
// 16. POST /_synapse/admin/v1/deactivate/{userId}
//     Body: { "erase": false } (optional)
// =========================================================================

HttpResponse handle_deactivate_user(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    std::string user_id = url_decode(path_param(req, "userId"));
    if (user_id.empty()) {
        return HttpResponse::bad_request("Missing userId path parameter");
    }

    json body;
    bool erase = false;
    if (parse_json_body(req, body) && body.contains("erase")) {
        erase = body["erase"].get<bool>();
    }

    std::lock_guard<std::mutex> lock(g_mutex);

    auto it = g_whois_store.find(user_id);
    if (it == g_whois_store.end()) {
        return HttpResponse::not_found("User not found: " + user_id);
    }

    if (it->second.deactivated) {
        return HttpResponse::bad_request("User is already deactivated");
    }

    it->second.deactivated = true;
    it->second.devices.clear();

    json resp;
    resp["user_id"] = user_id;
    resp["deactivated"] = true;
    resp["erased"] = erase;
    resp["id_server_result"] = "success";
    resp["message"] = std::string("User deactivated") + (erase ? " and erased" : "");

    return HttpResponse::ok(resp);
}

// =========================================================================
// 17. POST /_synapse/admin/v1/reactivate/{userId}
// =========================================================================

HttpResponse handle_reactivate_user(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    std::string user_id = url_decode(path_param(req, "userId"));
    if (user_id.empty()) {
        return HttpResponse::bad_request("Missing userId path parameter");
    }

    // Optional password in body
    json body;
    std::string new_password;
    if (parse_json_body(req, body) && body.contains("password")) {
        new_password = body["password"].get<std::string>();
    }

    std::lock_guard<std::mutex> lock(g_mutex);

    auto it = g_whois_store.find(user_id);
    if (it == g_whois_store.end()) {
        return HttpResponse::not_found("User not found: " + user_id);
    }

    if (!it->second.deactivated) {
        return HttpResponse::bad_request("User is not deactivated");
    }

    it->second.deactivated = false;

    if (!new_password.empty()) {
        g_user_passwords[user_id] = "hashed_" + new_password;
    }

    json resp;
    resp["user_id"] = user_id;
    resp["reactivated"] = true;
    resp["password_changed"] = !new_password.empty();
    resp["message"] = "User reactivated successfully";

    return HttpResponse::ok(resp);
}

// =========================================================================
// 18. POST /_synapse/admin/v1/override_ratelimit
//     Body: {
//       "user_id": "@user:server",
//       "messages_per_second": 0,   // 0 to disable override
//       "burst_count": 0
//     }
// =========================================================================

HttpResponse handle_override_ratelimit(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    json body;
    if (!parse_json_body(req, body)) {
        return HttpResponse::bad_request("Invalid JSON body");
    }

    if (!body.contains("user_id")) {
        return HttpResponse::bad_request("Missing 'user_id' field");
    }

    std::string user_id = body["user_id"].get<std::string>();
    int messages_per_second = body.value("messages_per_second", 0);
    int burst_count = body.value("burst_count", 0);

    std::lock_guard<std::mutex> lock(g_mutex);

    // Verify user exists
    if (g_whois_store.find(user_id) == g_whois_store.end()) {
        return HttpResponse::not_found("User not found: " + user_id);
    }

    if (messages_per_second == 0 && burst_count == 0) {
        // Remove the override
        g_rate_limit_overrides.erase(user_id);
        json resp;
        resp["user_id"] = user_id;
        resp["override_removed"] = true;
        resp["message"] = "Rate limit override removed for " + user_id;
        return HttpResponse::ok(resp);
    }

    RateLimitOverride rlo;
    rlo.user_id = user_id;
    rlo.messages_per_second = messages_per_second;
    rlo.burst_count = burst_count;
    rlo.expires_at = std::time(nullptr) + 86400; // 24 hours default
    g_rate_limit_overrides[user_id] = rlo;

    json resp;
    resp["user_id"] = user_id;
    resp["messages_per_second"] = messages_per_second;
    resp["burst_count"] = burst_count;
    resp["override_set"] = true;
    resp["expires_at"] = rlo.expires_at;
    resp["message"] = "Rate limit override set for " + user_id;

    return HttpResponse::ok(resp);
}

// =========================================================================
// 19. POST /_synapse/admin/v1/delete_group
//     Body: { "group_id": "+groupname:server" }
// =========================================================================

HttpResponse handle_delete_group(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    json body;
    if (!parse_json_body(req, body)) {
        return HttpResponse::bad_request("Invalid JSON body");
    }

    if (!body.contains("group_id")) {
        return HttpResponse::bad_request("Missing 'group_id' field");
    }

    std::string group_id = body["group_id"].get<std::string>();

    std::lock_guard<std::mutex> lock(g_mutex);

    auto it = std::find(g_groups.begin(), g_groups.end(), group_id);
    if (it == g_groups.end()) {
        return HttpResponse::not_found("Group not found: " + group_id);
    }

    g_groups.erase(it);

    json resp;
    resp["group_id"] = group_id;
    resp["deleted"] = true;
    resp["message"] = "Group deleted: " + group_id;

    return HttpResponse::ok(resp);
}

// =========================================================================
// 20. POST /_synapse/admin/v1/reset_password/{userId}
//     Body: { "new_password": "the_new_password", "logout_devices": false }
// =========================================================================

HttpResponse handle_reset_password(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    std::string user_id = url_decode(path_param(req, "userId"));
    if (user_id.empty()) {
        return HttpResponse::bad_request("Missing userId path parameter");
    }

    json body;
    if (!parse_json_body(req, body)) {
        return HttpResponse::bad_request("Invalid JSON body");
    }

    if (!body.contains("new_password")) {
        return HttpResponse::bad_request("Missing 'new_password' field");
    }

    std::string new_password = body["new_password"].get<std::string>();
    bool logout_devices = body.value("logout_devices", false);

    if (new_password.empty()) {
        return HttpResponse::bad_request("new_password must not be empty");
    }

    std::lock_guard<std::mutex> lock(g_mutex);

    auto it = g_whois_store.find(user_id);
    if (it == g_whois_store.end()) {
        return HttpResponse::not_found("User not found: " + user_id);
    }

    // In production this would hash the password with bcrypt.
    g_user_passwords[user_id] = "hashed_" + new_password;

    if (logout_devices) {
        it->second.devices.clear();
    }

    json resp;
    resp["user_id"] = user_id;
    resp["password_reset"] = true;
    resp["devices_logged_out"] = logout_devices;
    resp["message"] = std::string("Password reset for ") + user_id +
                      (logout_devices ? " and all devices logged out" : "");

    return HttpResponse::ok(resp);
}

// =========================================================================
// Additional admin monitoring endpoints
// =========================================================================

// -------------------------------------------------------------------------
// GET /_synapse/admin/v2/users
//   Query: ?from=&limit=&name=&guests=&deactivated=&order_by=&direction=
// -------------------------------------------------------------------------

HttpResponse handle_v2_users(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    int from = query_param_int(req, "from", 0);
    int limit = query_param_int(req, "limit", 100);
    std::string name_filter = query_param_str(req, "name", "");
    std::string guests = query_param_str(req, "guests", "false");
    std::string deactivated = query_param_str(req, "deactivated", "false");
    std::string order_by = query_param_str(req, "order_by", "name");
    std::string direction = query_param_str(req, "direction", "f");

    std::lock_guard<std::mutex> lock(g_mutex);

    std::vector<WhoisInfo> users;
    for (const auto& [uid, info] : g_whois_store) {
        // Filter deactivated
        if (deactivated == "true" && !info.deactivated) continue;
        if (deactivated == "false" && info.deactivated) continue;

        // Filter name
        if (!name_filter.empty()) {
            bool match_uid = uid.find(name_filter) != std::string::npos;
            bool match_dn = info.display_name.find(name_filter) != std::string::npos;
            if (!match_uid && !match_dn) continue;
        }

        // Guests filter: assume no guests in demo
        if (guests == "true") continue;

        users.push_back(info);
    }

    // Sort
    if (order_by == "name" || order_by == "displayname") {
        std::sort(users.begin(), users.end(),
            [&direction](const WhoisInfo& a, const WhoisInfo& b) {
                return direction == "b" ? a.display_name > b.display_name : a.display_name < b.display_name;
            });
    } else if (order_by == "user_id") {
        std::sort(users.begin(), users.end(),
            [&direction](const WhoisInfo& a, const WhoisInfo& b) {
                return direction == "b" ? a.user_id > b.user_id : a.user_id < b.user_id;
            });
    } else if (order_by == "creation_ts") {
        std::sort(users.begin(), users.end(),
            [&direction](const WhoisInfo& a, const WhoisInfo& b) {
                return direction == "b" ? a.creation_ts > b.creation_ts : a.creation_ts < b.creation_ts;
            });
    }

    int total = static_cast<int>(users.size());
    json resp;
    resp["users"] = json::array();
    resp["total"] = total;

    int end = std::min(from + limit, total);
    if (from < total) {
        for (int i = from; i < end; ++i) {
            const auto& u = users[i];
            json user;
            user["name"] = u.user_id;
            user["displayname"] = u.display_name;
            user["avatar_url"] = u.avatar_url.empty() ? json(nullptr) : json(u.avatar_url);
            user["is_guest"] = false;
            user["admin"] = u.is_admin;
            user["deactivated"] = u.deactivated;
            user["creation_ts"] = std::stoll(u.creation_ts);
            resp["users"].push_back(user);
        }
    }

    if (end < total) {
        resp["next_token"] = std::to_string(end);
    } else {
        resp["next_token"] = nullptr;
    }

    return HttpResponse::ok(resp);
}

// -------------------------------------------------------------------------
// GET /_synapse/admin/v1/rooms
//   Query: ?from=&limit=&search_term=&order_by=&direction=
// -------------------------------------------------------------------------

HttpResponse handle_rooms_list(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    int from = query_param_int(req, "from", 0);
    int limit = query_param_int(req, "limit", 100);
    std::string search_term = query_param_str(req, "search_term", "");
    std::string order_by = query_param_str(req, "order_by", "name");
    std::string direction = query_param_str(req, "direction", "f");

    std::lock_guard<std::mutex> lock(g_mutex);

    // Collect all unique rooms across all users
    std::set<std::string> room_set;
    std::map<std::string, int> room_member_counts;
    for (const auto& [uid, info] : g_whois_store) {
        for (const auto& r : info.rooms_joined) {
            room_set.insert(r);
            room_member_counts[r]++;
        }
    }

    struct RoomInfo {
        std::string room_id;
        std::string name;
        std::string canonical_alias;
        int joined_members = 0;
        int joined_local_members = 0;
        std::string version;
        std::string creator;
        bool encrypted = false;
        bool federatable = true;
        bool public_room = true;
        int64_t creation_ts = 0;
    };

    std::vector<RoomInfo> rooms;
    for (const auto& r : room_set) {
        RoomInfo ri;
        ri.room_id = r;
        ri.name = "Room " + r.substr(1, 8);
        ri.canonical_alias = "#" + r.substr(1, 8) + ":localhost";
        ri.joined_members = room_member_counts[r];
        ri.joined_local_members = room_member_counts[r];
        ri.version = "10";
        ri.creator = "@admin:localhost";
        ri.encrypted = true;
        ri.creation_ts = 1675000000000;
        rooms.push_back(ri);
    }

    // Filter
    if (!search_term.empty()) {
        rooms.erase(std::remove_if(rooms.begin(), rooms.end(),
            [&search_term](const RoomInfo& r) {
                return r.room_id.find(search_term) == std::string::npos &&
                       r.name.find(search_term) == std::string::npos &&
                       r.canonical_alias.find(search_term) == std::string::npos;
            }), rooms.end());
    }

    // Sort
    if (order_by == "name") {
        std::sort(rooms.begin(), rooms.end(),
            [&direction](const RoomInfo& a, const RoomInfo& b) {
                return direction == "b" ? a.name > b.name : a.name < b.name;
            });
    } else if (order_by == "joined_members") {
        std::sort(rooms.begin(), rooms.end(),
            [&direction](const RoomInfo& a, const RoomInfo& b) {
                return direction == "b" ? a.joined_members > b.joined_members :
                                          a.joined_members < b.joined_members;
            });
    } else {
        std::sort(rooms.begin(), rooms.end(),
            [&direction](const RoomInfo& a, const RoomInfo& b) {
                return direction == "b" ? a.room_id > b.room_id : a.room_id < b.room_id;
            });
    }

    int total = static_cast<int>(rooms.size());
    json resp;
    resp["rooms"] = json::array();
    resp["total_rooms"] = total;
    resp["offset"] = from;

    int end = std::min(from + limit, total);
    if (from < total) {
        for (int i = from; i < end; ++i) {
            const auto& r = rooms[i];
            json room;
            room["room_id"] = r.room_id;
            room["name"] = r.name;
            room["canonical_alias"] = r.canonical_alias;
            room["joined_members"] = r.joined_members;
            room["joined_local_members"] = r.joined_local_members;
            room["version"] = r.version;
            room["creator"] = r.creator;
            room["encryption"] = r.encrypted ? "E2EE" : nullptr;
            room["federatable"] = r.federatable;
            room["public"] = r.public_room;
            room["creation_ts"] = r.creation_ts;
            resp["rooms"].push_back(room);
        }
    }

    if (end < total) {
        resp["next_batch"] = end;
    } else {
        resp["next_batch"] = nullptr;
    }

    return HttpResponse::ok(resp);
}

// -------------------------------------------------------------------------
// GET /_synapse/admin/v1/rooms/{roomId}/members
//   Query: ?from=&limit=
// -------------------------------------------------------------------------

HttpResponse handle_room_members(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    std::string room_id = url_decode(path_param(req, "roomId"));
    if (room_id.empty()) {
        return HttpResponse::bad_request("Missing roomId path parameter");
    }

    int from = query_param_int(req, "from", 0);
    int limit = query_param_int(req, "limit", 100);

    std::lock_guard<std::mutex> lock(g_mutex);

    std::vector<std::string> members;
    std::vector<std::string> display_names;
    for (const auto& [uid, info] : g_whois_store) {
        for (const auto& r : info.rooms_joined) {
            if (r == room_id) {
                members.push_back(uid);
                display_names.push_back(info.display_name);
                break;
            }
        }
    }

    int total = static_cast<int>(members.size());
    json resp;
    resp["members"] = json::array();
    resp["total"] = total;
    resp["room_id"] = room_id;

    int end = std::min(from + limit, total);
    if (from < total) {
        for (int i = from; i < end; ++i) {
            json member;
            member["user_id"] = members[i];
            member["display_name"] = display_names[i];
            resp["members"].push_back(member);
        }
    }

    if (end < total) {
        resp["next_token"] = end;
    } else {
        resp["next_token"] = nullptr;
    }

    return HttpResponse::ok(resp);
}

// -------------------------------------------------------------------------
// GET /_synapse/admin/v1/rooms/{roomId}/state
// -------------------------------------------------------------------------

HttpResponse handle_room_state(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    std::string room_id = url_decode(path_param(req, "roomId"));
    if (room_id.empty()) {
        return HttpResponse::bad_request("Missing roomId path parameter");
    }

    // Return simulated state events for the room
    json resp;
    resp["room_id"] = room_id;
    resp["state"] = json::array();

    // m.room.create
    json create;
    create["type"] = "m.room.create";
    create["state_key"] = "";
    create["content"] = {{"creator", "@admin:localhost"}, {"room_version", "10"}, {"m.federate", true}};
    create["origin_server_ts"] = 1675000000000;
    create["sender"] = "@admin:localhost";
    create["event_id"] = "$create_event_" + room_id.substr(1, 8);
    resp["state"].push_back(create);

    // m.room.name
    json name;
    name["type"] = "m.room.name";
    name["state_key"] = "";
    name["content"] = {{"name", "Room " + room_id.substr(1, 8)}};
    name["origin_server_ts"] = 1675000001000;
    name["sender"] = "@admin:localhost";
    name["event_id"] = "$name_event_" + room_id.substr(1, 8);
    resp["state"].push_back(name);

    // m.room.member for each known member
    std::lock_guard<std::mutex> lock(g_mutex);
    for (const auto& [uid, info] : g_whois_store) {
        for (const auto& r : info.rooms_joined) {
            if (r == room_id) {
                json member;
                member["type"] = "m.room.member";
                member["state_key"] = uid;
                member["content"] = {
                    {"membership", "join"},
                    {"displayname", info.display_name},
                };
                if (!info.avatar_url.empty()) {
                    member["content"]["avatar_url"] = info.avatar_url;
                }
                member["origin_server_ts"] = 1675000002000;
                member["sender"] = uid;
                member["event_id"] = "$member_" + uid.substr(1, 6) + "_" + room_id.substr(1, 4);
                resp["state"].push_back(member);
                break;
            }
        }
    }

    return HttpResponse::ok(resp);
}

// -------------------------------------------------------------------------
// GET /_synapse/admin/v1/rooms/{roomId}/delete
//   POST body: { "block": false, "purge": true, "message": "reason" }
// -------------------------------------------------------------------------

HttpResponse handle_room_delete(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    std::string room_id = url_decode(path_param(req, "roomId"));
    if (room_id.empty()) {
        return HttpResponse::bad_request("Missing roomId path parameter");
    }

    json body;
    bool block = false;
    bool purge = true;
    std::string message;
    if (parse_json_body(req, body)) {
        block = body.value("block", false);
        purge = body.value("purge", true);
        message = body.value("message", "");
    }

    std::lock_guard<std::mutex> lock(g_mutex);

    // Remove the room from all user join lists
    bool found = false;
    for (auto& [uid, info] : g_whois_store) {
        auto& joined = info.rooms_joined;
        auto it = std::remove(joined.begin(), joined.end(), room_id);
        if (it != joined.end()) {
            found = true;
            joined.erase(it, joined.end());
        }
        auto& owned = info.rooms_owned;
        auto it2 = std::remove(owned.begin(), owned.end(), room_id);
        if (it2 != owned.end()) {
            owned.erase(it2, owned.end());
        }
    }

    if (!found) {
        return HttpResponse::not_found("Room not found: " + room_id);
    }

    json resp;
    resp["room_id"] = room_id;
    resp["deleted"] = true;
    resp["block"] = block;
    resp["purge"] = purge;
    resp["kicked_users"] = json::array();
    resp["local_aliases"] = json::array();
    resp["new_room_id"] = nullptr;
    if (!message.empty()) {
        resp["message"] = message;
    }

    return HttpResponse::ok(resp);
}

// -------------------------------------------------------------------------
// PUT /_synapse/admin/v2/users/{userId}
//   Body: { "displayname": "...", "avatar_url": "...", "admin": false,
//           "deactivated": false, "password": "..." }
// -------------------------------------------------------------------------

HttpResponse handle_v2_user_upsert(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    std::string user_id = url_decode(path_param(req, "userId"));
    if (user_id.empty()) {
        return HttpResponse::bad_request("Missing userId path parameter");
    }

    json body;
    if (!parse_json_body(req, body)) {
        return HttpResponse::bad_request("Invalid JSON body");
    }

    std::lock_guard<std::mutex> lock(g_mutex);

    bool is_new = (g_whois_store.find(user_id) == g_whois_store.end());

    WhoisInfo& info = g_whois_store[user_id];
    if (is_new) {
        info.user_id = user_id;
        info.creation_ts = std::to_string(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count());
    }

    if (body.contains("displayname")) {
        info.display_name = body["displayname"].get<std::string>();
    }
    if (body.contains("avatar_url")) {
        info.avatar_url = body["avatar_url"].get<std::string>();
    }
    if (body.contains("admin")) {
        info.is_admin = body["admin"].get<bool>();
    }
    if (body.contains("deactivated")) {
        info.deactivated = body["deactivated"].get<bool>();
    }
    if (body.contains("password")) {
        g_user_passwords[user_id] = "hashed_" + body["password"].get<std::string>();
    }

    json resp;
    resp["user_id"] = user_id;
    resp["created"] = is_new;
    resp["displayname"] = info.display_name;
    resp["avatar_url"] = info.avatar_url.empty() ? json(nullptr) : json(info.avatar_url);
    resp["admin"] = info.is_admin;
    resp["deactivated"] = info.deactivated;

    return HttpResponse::ok(resp);
}

// -------------------------------------------------------------------------
// GET /_synapse/admin/v1/statistics/users/media
// -------------------------------------------------------------------------

HttpResponse handle_statistics_users_media(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    std::lock_guard<std::mutex> lock(g_mutex);

    int total_media_count = 0;
    int64_t total_media_size = 0;
    std::map<std::string, int64_t> per_user_size;
    std::map<std::string, int> per_user_count;

    for (const auto& [sv, entries] : g_media_store) {
        for (const auto& m : entries) {
            total_media_count++;
            total_media_size += m.size_bytes;
            per_user_size[m.uploader_user_id] += m.size_bytes;
            per_user_count[m.uploader_user_id]++;
        }
    }

    json resp;
    resp["total_media_count"] = total_media_count;
    resp["total_media_size"] = total_media_size;
    resp["users"] = json::array();

    for (const auto& [uid, size] : per_user_size) {
        json user;
        user["user_id"] = uid;
        user["media_count"] = per_user_count[uid];
        user["media_size"] = size;
        resp["users"].push_back(user);
    }

    return HttpResponse::ok(resp);
}

// -------------------------------------------------------------------------
// GET /_synapse/admin/v1/statistics/database/rooms
// -------------------------------------------------------------------------

HttpResponse handle_statistics_database_rooms(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    std::lock_guard<std::mutex> lock(g_mutex);

    std::set<std::string> rooms;
    for (const auto& [uid, info] : g_whois_store) {
        for (const auto& r : info.rooms_joined) rooms.insert(r);
    }

    json resp;
    resp["total_rooms"] = rooms.size();
    resp["rooms"] = json::array();

    for (const auto& r : rooms) {
        json room;
        room["room_id"] = r;
        room["estimated_size"] = 10240;
        room["state_events"] = 12;
        resp["rooms"].push_back(room);
    }

    return HttpResponse::ok(resp);
}

// -------------------------------------------------------------------------
// POST /_synapse/admin/v1/join/{roomIdOrAlias}
//   Body: { "user_id": "@user:server" }
// -------------------------------------------------------------------------

HttpResponse handle_admin_join(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    std::string room_id_or_alias = url_decode(path_param(req, "roomIdOrAlias"));
    if (room_id_or_alias.empty()) {
        return HttpResponse::bad_request("Missing roomIdOrAlias path parameter");
    }

    json body;
    if (!parse_json_body(req, body) || !body.contains("user_id")) {
        return HttpResponse::bad_request("Missing 'user_id' in body");
    }

    std::string user_id = body["user_id"].get<std::string>();

    std::lock_guard<std::mutex> lock(g_mutex);

    auto it = g_whois_store.find(user_id);
    if (it == g_whois_store.end()) {
        return HttpResponse::not_found("User not found: " + user_id);
    }

    // Check if already joined
    for (const auto& r : it->second.rooms_joined) {
        if (r == room_id_or_alias) {
            json resp;
            resp["room_id"] = room_id_or_alias;
            resp["user_id"] = user_id;
            resp["already_joined"] = true;
            return HttpResponse::ok(resp);
        }
    }

    it->second.rooms_joined.push_back(room_id_or_alias);

    json resp;
    resp["room_id"] = room_id_or_alias;
    resp["user_id"] = user_id;
    resp["joined"] = true;

    return HttpResponse::ok(resp);
}

// -------------------------------------------------------------------------
// GET /_synapse/admin/v1/registration_tokens
// -------------------------------------------------------------------------

HttpResponse handle_registration_tokens(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    // Simulated registration tokens
    json resp;
    resp["registration_tokens"] = json::array();

    json token1;
    token1["token"] = "abc123regtoken";
    token1["uses_allowed"] = 10;
    token1["pending"] = 0;
    token1["completed"] = 3;
    token1["expiry_time"] = std::time(nullptr) + 86400 * 30;
    resp["registration_tokens"].push_back(token1);

    json token2;
    token2["token"] = "def456regtoken";
    token2["uses_allowed"] = nullptr;
    token2["pending"] = 1;
    token2["completed"] = 5;
    token2["expiry_time"] = nullptr;
    resp["registration_tokens"].push_back(token2);

    return HttpResponse::ok(resp);
}

// -------------------------------------------------------------------------
// POST /_synapse/admin/v1/registration_tokens/new
//   Body: { "token": "...", "uses_allowed": 10, "expiry_time": ... }
// -------------------------------------------------------------------------

HttpResponse handle_registration_tokens_new(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    json body;
    if (!parse_json_body(req, body)) {
        return HttpResponse::bad_request("Invalid JSON body");
    }

    std::string token = body.value("token", random_hex(16));
    int uses_allowed = body.value("uses_allowed", -1);
    int64_t expiry_time = body.value("expiry_time", static_cast<int64_t>(0));

    json resp;
    resp["token"] = token;
    resp["uses_allowed"] = uses_allowed > 0 ? json(uses_allowed) : json(nullptr);
    resp["pending"] = 0;
    resp["completed"] = 0;
    resp["expiry_time"] = expiry_time > 0 ? json(expiry_time) : json(nullptr);

    return HttpResponse::ok(resp);
}

// -------------------------------------------------------------------------
// GET /_synapse/admin/v1/event_reports
//   Query: ?from=&limit=&order_by=&direction=&room_id=&user_id=
// -------------------------------------------------------------------------

HttpResponse handle_event_reports(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    int from = query_param_int(req, "from", 0);
    int limit = query_param_int(req, "limit", 100);
    std::string order_by = query_param_str(req, "order_by", "received_ts");
    std::string direction = query_param_str(req, "direction", "b");
    std::string room_filter = query_param_str(req, "room_id", "");
    std::string user_filter = query_param_str(req, "user_id", "");

    // Simulated event reports
    struct EventReport {
        int64_t id;
        int64_t received_ts;
        std::string room_id;
        std::string event_id;
        std::string user_id;
        std::string reason;
        std::string sender;
        bool can_see_sender;
    };

    std::vector<EventReport> reports = {
        {1, 1685000000000, "!general:localhost", "$event123", "@alice:localhost",
         "Spam content", "@moderator:localhost", true},
        {2, 1685001000000, "!devchat:localhost", "$event456", "@bob:localhost",
         "Inappropriate language", "@moderator:localhost", true},
    };

    // Filter
    if (!room_filter.empty()) {
        reports.erase(std::remove_if(reports.begin(), reports.end(),
            [&room_filter](const EventReport& r) { return r.room_id != room_filter; }),
            reports.end());
    }
    if (!user_filter.empty()) {
        reports.erase(std::remove_if(reports.begin(), reports.end(),
            [&user_filter](const EventReport& r) { return r.user_id != user_filter; }),
            reports.end());
    }

    // Sort
    std::sort(reports.begin(), reports.end(),
        [&](const EventReport& a, const EventReport& b) {
            if (order_by == "received_ts")
                return direction == "b" ? a.received_ts > b.received_ts : a.received_ts < b.received_ts;
            if (order_by == "room_id")
                return direction == "b" ? a.room_id > b.room_id : a.room_id < b.room_id;
            if (order_by == "user_id")
                return direction == "b" ? a.user_id > b.user_id : a.user_id < b.user_id;
            return direction == "b" ? a.id > b.id : a.id < b.id;
        });

    int total = static_cast<int>(reports.size());
    json resp;
    resp["event_reports"] = json::array();
    resp["total"] = total;

    int end = std::min(from + limit, total);
    if (from < total) {
        for (int i = from; i < end; ++i) {
            const auto& r = reports[i];
            json entry;
            entry["id"] = r.id;
            entry["received_ts"] = r.received_ts;
            entry["room_id"] = r.room_id;
            entry["event_id"] = r.event_id;
            entry["user_id"] = r.user_id;
            entry["reason"] = r.reason;
            entry["sender"] = r.sender;
            entry["can_see_sender"] = r.can_see_sender;
            resp["event_reports"].push_back(entry);
        }
    }

    if (end < total) {
        resp["next_token"] = end;
    } else {
        resp["next_token"] = nullptr;
    }

    return HttpResponse::ok(resp);
}

// -------------------------------------------------------------------------
// GET /_synapse/admin/v1/event_reports/{reportId}
// -------------------------------------------------------------------------

HttpResponse handle_event_report_detail(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    std::string report_id_str = url_decode(path_param(req, "reportId"));
    if (report_id_str.empty()) {
        return HttpResponse::bad_request("Missing reportId path parameter");
    }

    int64_t report_id = 0;
    try { report_id = std::stoll(report_id_str); }
    catch (...) { return HttpResponse::bad_request("Invalid reportId"); }

    // Simulated lookup
    if (report_id == 1) {
        json resp;
        resp["id"] = 1;
        resp["received_ts"] = 1685000000000;
        resp["room_id"] = "!general:localhost";
        resp["event_id"] = "$event123";
        resp["user_id"] = "@alice:localhost";
        resp["reason"] = "Spam content";
        resp["sender"] = "@moderator:localhost";
        resp["can_see_sender"] = true;
        resp["score"] = 50;
        resp["event_json"] = json::object({{"type", "m.room.message"},
                                            {"content", {{"msgtype", "m.text"}, {"body", "spam message"}}}});
        return HttpResponse::ok(resp);
    }

    if (report_id == 2) {
        json resp;
        resp["id"] = 2;
        resp["received_ts"] = 1685001000000;
        resp["room_id"] = "!devchat:localhost";
        resp["event_id"] = "$event456";
        resp["user_id"] = "@bob:localhost";
        resp["reason"] = "Inappropriate language";
        resp["sender"] = "@moderator:localhost";
        resp["can_see_sender"] = true;
        resp["score"] = 75;
        resp["event_json"] = json::object({{"type", "m.room.message"},
                                            {"content", {{"msgtype", "m.text"}, {"body", "bad words"}}}});
        return HttpResponse::ok(resp);
    }

    return HttpResponse::not_found("Event report not found");
}

// -------------------------------------------------------------------------
// GET /_synapse/admin/v1/experimental_features
// -------------------------------------------------------------------------

HttpResponse handle_experimental_features(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    json resp;
    resp["features"] = json::object();
    resp["features"]["msc3026"] = true;  // busy presence
    resp["features"]["msc3881"] = false; // reminder
    resp["features"]["msc3967"] = false; // slow mode with power levels
    resp["features"]["msc2654"] = true;  // unread counts
    resp["features"]["msc2403"] = false; // add EDUs to sync
    resp["features"]["msc2716"] = false; // batch sending

    return HttpResponse::ok(resp);
}

// =========================================================================
// Server monitoring / health endpoints
// =========================================================================

// -------------------------------------------------------------------------
// GET /health
//   Basic health-check, no auth required.
// -------------------------------------------------------------------------

HttpResponse handle_health(const HttpRequest& req) {
    (void)req;

    json resp;
    resp["status"] = "ok";
    resp["server_name"] = SERVER_NAME;
    resp["version"] = SERVER_VERSION;
    resp["uptime_seconds"] = std::time(nullptr) - 1670000000;

    return HttpResponse::ok(resp);
}

// -------------------------------------------------------------------------
// GET /_synapse/admin/v1/server_notices/status
// -------------------------------------------------------------------------

HttpResponse handle_server_notices_status(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    std::lock_guard<std::mutex> lock(g_mutex);

    int total = static_cast<int>(g_server_notices.size());
    int sent = 0;
    int pending = 0;
    for (const auto& n : g_server_notices) {
        if (n.sent) sent++; else pending++;
    }

    json resp;
    resp["total_notices"] = total;
    resp["sent"] = sent;
    resp["pending"] = pending;
    resp["enabled"] = true;

    return HttpResponse::ok(resp);
}

// -------------------------------------------------------------------------
// POST /_synapse/admin/v1/send_server_notice
//   Body: { "user_id": "@user:server", "content": { ... } }
// -------------------------------------------------------------------------

HttpResponse handle_send_server_notice(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    json body;
    if (!parse_json_body(req, body)) {
        return HttpResponse::bad_request("Invalid JSON body");
    }

    if (!body.contains("user_id")) {
        return HttpResponse::bad_request("Missing 'user_id' field");
    }
    if (!body.contains("content")) {
        return HttpResponse::bad_request("Missing 'content' field");
    }

    std::string user_id = body["user_id"].get<std::string>();
    json content = body["content"];

    std::lock_guard<std::mutex> lock(g_mutex);

    ServerNotice notice;
    notice.id = random_hex(8);
    notice.user_id = user_id;
    notice.room_id = "!server:localhost";
    notice.content = content.dump();
    notice.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    notice.sent = true;
    g_server_notices.push_back(notice);

    json resp;
    resp["notice_id"] = notice.id;
    resp["user_id"] = user_id;
    resp["sent"] = true;
    resp["event_id"] = "$notice_" + notice.id;

    return HttpResponse::ok(resp);
}

// -------------------------------------------------------------------------
// GET /_synapse/admin/v1/version  (alias for server_version)
// -------------------------------------------------------------------------

HttpResponse handle_version(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    json resp;
    resp["server_name"] = SERVER_NAME;
    resp["server_version"] = SERVER_VERSION;
    resp["python_version"] = PYTHON_VERSION;

    return HttpResponse::ok(resp);
}

// =========================================================================
// Route dispatcher
// =========================================================================

/**
 * Route an admin request to the appropriate handler.
 * Returns the HTTP response to send back.
 *
 * This function parses the path and dispatches to one of the 20+ handlers
 * implemented above. It also handles OPTIONS preflight requests.
 */
HttpResponse dispatch_admin_request(const HttpRequest& req) {
    // Ensure demo state is initialized
    init_demo_state();

    // Handle CORS preflight
    if (req.method == "OPTIONS") {
        HttpResponse resp;
        resp.status_code = 204;
        resp.headers["Allow"] = "GET, POST, PUT, DELETE, OPTIONS";
        resp.headers["Access-Control-Allow-Origin"] = "*";
        resp.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS";
        resp.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization";
        resp.headers["Access-Control-Max-Age"] = "86400";
        resp.body = "";
        return resp;
    }

    const std::string& path = req.path;
    const std::string& method = req.method;

    // -----------------------------------------------------------------------
    // Health (no auth)
    // -----------------------------------------------------------------------
    if (path == "/health" && method == "GET") {
        return handle_health(req);
    }

    // -----------------------------------------------------------------------
    // Server version
    // -----------------------------------------------------------------------
    if (path == "/_synapse/admin/v1/server_version" && method == "GET") {
        return handle_server_version(req);
    }

    // -----------------------------------------------------------------------
    // Federation destinations
    // -----------------------------------------------------------------------
    if (path == "/_synapse/admin/v1/federation/destinations" && method == "GET") {
        return handle_federation_destinations(req);
    }

    // -----------------------------------------------------------------------
    // Federation status
    // -----------------------------------------------------------------------
    if (path == "/_synapse/admin/v1/federation/status" && method == "GET") {
        return handle_federation_status(req);
    }

    // -----------------------------------------------------------------------
    // Reset connection timeout
    // -----------------------------------------------------------------------
    if (path == "/_synapse/admin/v1/reset_connection_timeout" && method == "POST") {
        return handle_reset_connection_timeout(req);
    }

    // -----------------------------------------------------------------------
    // Purge media cache
    // -----------------------------------------------------------------------
    if (path == "/_synapse/admin/v1/purge_media_cache" && method == "POST") {
        return handle_purge_media_cache(req);
    }

    // -----------------------------------------------------------------------
    // Override rate limit
    // -----------------------------------------------------------------------
    if (path == "/_synapse/admin/v1/override_ratelimit" && method == "POST") {
        return handle_override_ratelimit(req);
    }

    // -----------------------------------------------------------------------
    // Delete group
    // -----------------------------------------------------------------------
    if (path == "/_synapse/admin/v1/delete_group" && method == "POST") {
        return handle_delete_group(req);
    }

    // -----------------------------------------------------------------------
    // Background updates
    // -----------------------------------------------------------------------
    if (path == "/_synapse/admin/v1/background_updates" && method == "GET") {
        return handle_background_updates_list(req);
    }
    if (path == "/_synapse/admin/v1/background_updates/status" && method == "GET") {
        return handle_background_updates_status(req);
    }

    // -----------------------------------------------------------------------
    // Server notices
    // -----------------------------------------------------------------------
    if (path == "/_synapse/admin/v1/server_notices" && method == "GET") {
        return handle_server_notices_list(req);
    }
    if (path == "/_synapse/admin/v1/server_notices/status" && method == "GET") {
        return handle_server_notices_status(req);
    }
    if (path == "/_synapse/admin/v1/send_server_notice" && method == "POST") {
        return handle_send_server_notice(req);
    }

    // -----------------------------------------------------------------------
    // Users (v2)
    // -----------------------------------------------------------------------
    if (path == "/_synapse/admin/v2/users" && method == "GET") {
        return handle_v2_users(req);
    }

    // -----------------------------------------------------------------------
    // Rooms
    // -----------------------------------------------------------------------
    if (path == "/_synapse/admin/v1/rooms" && method == "GET") {
        return handle_rooms_list(req);
    }

    // -----------------------------------------------------------------------
    // Statistics
    // -----------------------------------------------------------------------
    if (path == "/_synapse/admin/v1/statistics/users/media" && method == "GET") {
        return handle_statistics_users_media(req);
    }
    if (path == "/_synapse/admin/v1/statistics/database/rooms" && method == "GET") {
        return handle_statistics_database_rooms(req);
    }

    // -----------------------------------------------------------------------
    // Registration tokens
    // -----------------------------------------------------------------------
    if (path == "/_synapse/admin/v1/registration_tokens" && method == "GET") {
        return handle_registration_tokens(req);
    }
    if (path == "/_synapse/admin/v1/registration_tokens/new" && method == "POST") {
        return handle_registration_tokens_new(req);
    }

    // -----------------------------------------------------------------------
    // Event reports
    // -----------------------------------------------------------------------
    if (path == "/_synapse/admin/v1/event_reports" && method == "GET") {
        return handle_event_reports(req);
    }

    // -----------------------------------------------------------------------
    // Experimental features
    // -----------------------------------------------------------------------
    if (path == "/_synapse/admin/v1/experimental_features" && method == "GET") {
        return handle_experimental_features(req);
    }

    // -----------------------------------------------------------------------
    // Version alias
    // -----------------------------------------------------------------------
    if (path == "/_synapse/admin/v1/version" && method == "GET") {
        return handle_version(req);
    }

    // -----------------------------------------------------------------------
    // Dynamic-path endpoints (use prefix matching)
    // -----------------------------------------------------------------------

    // /_synapse/admin/v1/media/{serverName}/list
    if (path.find("/_synapse/admin/v1/media/") == 0 && path.find("/list") != std::string::npos && method == "GET") {
        // Extract serverName between /media/ and /list
        size_t start = std::string("/_synapse/admin/v1/media/").size();
        size_t end = path.find("/list");
        if (end != std::string::npos && end > start) {
            HttpRequest mutable_req = req;
            mutable_req.path_params["serverName"] = path.substr(start, end - start);
            return handle_media_list(mutable_req);
        }
    }

    // /_synapse/admin/v1/media/{serverName}/quarantine/{mediaId}
    if (path.find("/_synapse/admin/v1/media/") == 0 && path.find("/quarantine/") != std::string::npos && method == "POST") {
        size_t media_start = std::string("/_synapse/admin/v1/media/").size();
        size_t quar_start = path.find("/quarantine/");
        if (quar_start != std::string::npos && quar_start > media_start) {
            HttpRequest mutable_req = req;
            mutable_req.path_params["serverName"] = path.substr(media_start, quar_start - media_start);
            mutable_req.path_params["mediaId"] = path.substr(quar_start + std::string("/quarantine/").size());
            return handle_media_quarantine(mutable_req);
        }
    }

    // /_synapse/admin/v1/media/{serverName}/delete/{mediaId}
    if (path.find("/_synapse/admin/v1/media/") == 0 && path.find("/delete/") != std::string::npos && method == "POST") {
        size_t media_start = std::string("/_synapse/admin/v1/media/").size();
        size_t del_start = path.find("/delete/");
        if (del_start != std::string::npos && del_start > media_start) {
            HttpRequest mutable_req = req;
            mutable_req.path_params["serverName"] = path.substr(media_start, del_start - media_start);
            mutable_req.path_params["mediaId"] = path.substr(del_start + std::string("/delete/").size());
            return handle_media_delete(mutable_req);
        }
    }

    // /_synapse/admin/v1/purge_history_status/{purgeId}
    if (path.find("/_synapse/admin/v1/purge_history_status/") == 0 && method == "GET") {
        size_t start = std::string("/_synapse/admin/v1/purge_history_status/").size();
        HttpRequest mutable_req = req;
        mutable_req.path_params["purgeId"] = path.substr(start);
        return handle_purge_history_status(mutable_req);
    }

    // /_synapse/admin/v1/background_updates/{updateName}
    if (path.find("/_synapse/admin/v1/background_updates/") == 0 &&
        path != "/_synapse/admin/v1/background_updates/status" &&
        path != "/_synapse/admin/v1/background_updates" && method == "POST") {
        size_t start = std::string("/_synapse/admin/v1/background_updates/").size();
        HttpRequest mutable_req = req;
        mutable_req.path_params["updateName"] = path.substr(start);
        return handle_background_update_run(mutable_req);
    }

    // /_synapse/admin/v1/rooms/{roomId}/make_admin
    if (path.find("/_synapse/admin/v1/rooms/") == 0 && path.find("/make_admin") != std::string::npos && method == "POST") {
        size_t start = std::string("/_synapse/admin/v1/rooms/").size();
        size_t end = path.find("/make_admin");
        HttpRequest mutable_req = req;
        mutable_req.path_params["roomId"] = path.substr(start, end - start);
        return handle_room_make_admin(mutable_req);
    }

    // /_synapse/admin/v1/rooms/{roomId}/members
    if (path.find("/_synapse/admin/v1/rooms/") == 0 && path.find("/members") != std::string::npos && method == "GET") {
        size_t start = std::string("/_synapse/admin/v1/rooms/").size();
        size_t end = path.find("/members");
        HttpRequest mutable_req = req;
        mutable_req.path_params["roomId"] = path.substr(start, end - start);
        return handle_room_members(mutable_req);
    }

    // /_synapse/admin/v1/rooms/{roomId}/state
    if (path.find("/_synapse/admin/v1/rooms/") == 0 && path.find("/state") != std::string::npos && method == "GET") {
        size_t start = std::string("/_synapse/admin/v1/rooms/").size();
        size_t end = path.find("/state");
        HttpRequest mutable_req = req;
        mutable_req.path_params["roomId"] = path.substr(start, end - start);
        return handle_room_state(mutable_req);
    }

    // /_synapse/admin/v1/rooms/{roomId}/delete
    if (path.find("/_synapse/admin/v1/rooms/") == 0 && path.find("/delete") != std::string::npos && method == "POST") {
        size_t start = std::string("/_synapse/admin/v1/rooms/").size();
        size_t end = path.find("/delete");
        HttpRequest mutable_req = req;
        mutable_req.path_params["roomId"] = path.substr(start, end - start);
        return handle_room_delete(mutable_req);
    }

    // /_synapse/admin/v1/whois/{userId}
    if (path.find("/_synapse/admin/v1/whois/") == 0 && method == "GET") {
        size_t start = std::string("/_synapse/admin/v1/whois/").size();
        HttpRequest mutable_req = req;
        mutable_req.path_params["userId"] = path.substr(start);
        return handle_whois(mutable_req);
    }

    // /_synapse/admin/v1/deactivate/{userId}
    if (path.find("/_synapse/admin/v1/deactivate/") == 0 && method == "POST") {
        size_t start = std::string("/_synapse/admin/v1/deactivate/").size();
        HttpRequest mutable_req = req;
        mutable_req.path_params["userId"] = path.substr(start);
        return handle_deactivate_user(mutable_req);
    }

    // /_synapse/admin/v1/reactivate/{userId}
    if (path.find("/_synapse/admin/v1/reactivate/") == 0 && method == "POST") {
        size_t start = std::string("/_synapse/admin/v1/reactivate/").size();
        HttpRequest mutable_req = req;
        mutable_req.path_params["userId"] = path.substr(start);
        return handle_reactivate_user(mutable_req);
    }

    // /_synapse/admin/v1/reset_password/{userId}
    if (path.find("/_synapse/admin/v1/reset_password/") == 0 && method == "POST") {
        size_t start = std::string("/_synapse/admin/v1/reset_password/").size();
        HttpRequest mutable_req = req;
        mutable_req.path_params["userId"] = path.substr(start);
        return handle_reset_password(mutable_req);
    }

    // /_synapse/admin/v2/users/{userId}
    if (path.find("/_synapse/admin/v2/users/") == 0 && method == "PUT") {
        size_t start = std::string("/_synapse/admin/v2/users/").size();
        HttpRequest mutable_req = req;
        mutable_req.path_params["userId"] = path.substr(start);
        return handle_v2_user_upsert(mutable_req);
    }

    // /_synapse/admin/v1/join/{roomIdOrAlias}
    if (path.find("/_synapse/admin/v1/join/") == 0 && method == "POST") {
        size_t start = std::string("/_synapse/admin/v1/join/").size();
        HttpRequest mutable_req = req;
        mutable_req.path_params["roomIdOrAlias"] = path.substr(start);
        return handle_admin_join(mutable_req);
    }

    // /_synapse/admin/v1/event_reports/{reportId}
    if (path.find("/_synapse/admin/v1/event_reports/") == 0 &&
        path != "/_synapse/admin/v1/event_reports" && method == "GET") {
        size_t start = std::string("/_synapse/admin/v1/event_reports/").size();
        HttpRequest mutable_req = req;
        mutable_req.path_params["reportId"] = path.substr(start);
        return handle_event_report_detail(mutable_req);
    }

    // -----------------------------------------------------------------------
    // Fallback: not found
    // -----------------------------------------------------------------------
    return HttpResponse::not_found("Admin endpoint not found: " + method + " " + path);
}

// =========================================================================
// Public API: handler registration helper
// =========================================================================

/**
 * Register all admin monitoring endpoints with the server router.
 *
 * In production this would call server.add_route(...) for each endpoint.
 * For demonstration we provide a function that returns a list of
 * {method, path, handler} tuples that can be iterated over.
 */
struct RouteEntry {
    std::string method;
    std::string path;
    std::function<HttpResponse(const HttpRequest&)> handler;
};

std::vector<RouteEntry> get_admin_routes() {
    init_demo_state();

    return {
        // Health
        {"GET",    "/health",                                                     handle_health},

        // Core admin v1
        {"GET",    "/_synapse/admin/v1/server_version",                           handle_server_version},
        {"GET",    "/_synapse/admin/v1/version",                                  handle_version},
        {"GET",    "/_synapse/admin/v1/federation/destinations",                  handle_federation_destinations},
        {"GET",    "/_synapse/admin/v1/federation/status",                        handle_federation_status},
        {"POST",   "/_synapse/admin/v1/reset_connection_timeout",                 handle_reset_connection_timeout},
        {"GET",    "/_synapse/admin/v1/background_updates",                       handle_background_updates_list},
        {"GET",    "/_synapse/admin/v1/background_updates/status",                handle_background_updates_status},
        {"POST",   "/_synapse/admin/v1/purge_media_cache",                        handle_purge_media_cache},
        {"GET",    "/_synapse/admin/v1/server_notices",                           handle_server_notices_list},
        {"GET",    "/_synapse/admin/v1/server_notices/status",                    handle_server_notices_status},
        {"POST",   "/_synapse/admin/v1/send_server_notice",                       handle_send_server_notice},
        {"POST",   "/_synapse/admin/v1/override_ratelimit",                       handle_override_ratelimit},
        {"POST",   "/_synapse/admin/v1/delete_group",                             handle_delete_group},

        // Users v2
        {"GET",    "/_synapse/admin/v2/users",                                    handle_v2_users},

        // Rooms
        {"GET",    "/_synapse/admin/v1/rooms",                                    handle_rooms_list},

        // Event reports
        {"GET",    "/_synapse/admin/v1/event_reports",                            handle_event_reports},

        // Registration tokens
        {"GET",    "/_synapse/admin/v1/registration_tokens",                      handle_registration_tokens},
        {"POST",   "/_synapse/admin/v1/registration_tokens/new",                  handle_registration_tokens_new},

        // Statistics
        {"GET",    "/_synapse/admin/v1/statistics/users/media",                   handle_statistics_users_media},
        {"GET",    "/_synapse/admin/v1/statistics/database/rooms",                handle_statistics_database_rooms},

        // Experimental
        {"GET",    "/_synapse/admin/v1/experimental_features",                    handle_experimental_features},
    };
}

// =========================================================================
// Additional monitoring, debug, and management endpoints
// =========================================================================

// -------------------------------------------------------------------------
// GET /_synapse/admin/v1/server_metrics
//   Returns runtime metrics: memory, CPU, connections, DB pool, etc.
// -------------------------------------------------------------------------

HttpResponse handle_server_metrics(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    json resp;
    resp["timestamp"] = std::time(nullptr);

    // Memory metrics (simulated)
    json memory;
    memory["rss_bytes"] = 256 * 1024 * 1024;  // 256 MB
    memory["heap_used_bytes"] = 128 * 1024 * 1024;
    memory["heap_total_bytes"] = 512 * 1024 * 1024;
    memory["external_bytes"] = 64 * 1024 * 1024;
    resp["memory"] = memory;

    // CPU metrics (simulated)
    json cpu;
    cpu["user_percent"] = 12.5;
    cpu["system_percent"] = 3.2;
    cpu["total_percent"] = 15.7;
    cpu["num_cpus"] = 8;
    resp["cpu"] = cpu;

    // Connection metrics (simulated)
    json connections;
    connections["active"] = 46;
    connections["idle"] = 12;
    connections["total"] = 58;
    connections["max"] = 200;
    connections["rejected"] = 0;
    resp["connections"] = connections;

    // Event loop metrics
    json event_loop;
    event_loop["pending_tasks"] = 3;
    event_loop["avg_task_latency_ms"] = 0.42;
    event_loop["max_task_latency_ms"] = 12.3;
    resp["event_loop"] = event_loop;

    // DB pool (simulated)
    json db_pool;
    db_pool["active"] = 8;
    db_pool["idle"] = 4;
    db_pool["total"] = 12;
    db_pool["max"] = 20;
    db_pool["overflow"] = 0;
    db_pool["avg_query_time_ms"] = 2.34;
    db_pool["queries_per_second"] = 342.1;
    resp["database_pool"] = db_pool;

    // Cache metrics (simulated)
    json cache;
    cache["event_cache_hits"] = 15234;
    cache["event_cache_misses"] = 123;
    cache["event_cache_size"] = 10240;
    cache["state_cache_hits"] = 8932;
    cache["state_cache_misses"] = 45;
    cache["state_cache_size"] = 5120;
    cache["user_cache_hits"] = 4210;
    cache["user_cache_misses"] = 12;
    cache["user_cache_size"] = 1024;
    resp["caches"] = cache;

    // Federation metrics
    json federation;
    federation["inbound_transactions_per_second"] = 5.2;
    federation["outbound_transactions_per_second"] = 3.8;
    federation["total_destinations"] = static_cast<int>(g_federation_destinations.size());
    federation["up_destinations"] = 0;
    federation["down_destinations"] = 0;
    for (const auto& d : g_federation_destinations) {
        if (d.state == "ok") federation["up_destinations"] = federation["up_destinations"].get<int>() + 1;
        else federation["down_destinations"] = federation["down_destinations"].get<int>() + 1;
    }
    federation["pending_edus"] = 0;
    federation["pending_pdus"] = 0;
    resp["federation"] = federation;

    return HttpResponse::ok(resp);
}

// -------------------------------------------------------------------------
// GET /_synapse/admin/v1/caches/clear
//   POST - Clears specific or all caches.
//   Body: { "cache": "events" | "state" | "users" | "all" }
// -------------------------------------------------------------------------

HttpResponse handle_caches_clear(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    json body;
    std::string cache_name = "all";
    if (parse_json_body(req, body) && body.contains("cache")) {
        cache_name = body["cache"].get<std::string>();
    }

    json resp;
    resp["cleared"] = json::array();

    if (cache_name == "all" || cache_name == "events") {
        resp["cleared"].push_back("event_cache");
    }
    if (cache_name == "all" || cache_name == "state") {
        resp["cleared"].push_back("state_cache");
    }
    if (cache_name == "all" || cache_name == "users") {
        resp["cleared"].push_back("user_cache");
    }
    if (cache_name == "all" || cache_name == "devices") {
        resp["cleared"].push_back("device_cache");
    }

    resp["message"] = "Caches cleared: " + cache_name;
    return HttpResponse::ok(resp);
}

// -------------------------------------------------------------------------
// GET /_synapse/admin/v1/forward_extremities
//   Lists rooms with forward extremity counts above threshold.
//   Query: ?limit=&from=&min_count=
// -------------------------------------------------------------------------

HttpResponse handle_forward_extremities(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    int from = query_param_int(req, "from", 0);
    int limit = query_param_int(req, "limit", 100);
    int min_count = query_param_int(req, "min_count", 10);

    // Simulated forward extremity data
    struct FwdExtremity {
        std::string room_id;
        int count;
        int max_depth;
        int min_depth;
    };

    std::vector<FwdExtremity> extremities = {
        {"!large_room:localhost",      42, 1500, 1200},
        {"!stuck_room:localhost",      128, 5000, 4800},
        {"!general:localhost",         3, 200, 180},
        {"!devchat:localhost",         7, 350, 300},
        {"!problematic:localhost",     256, 10000, 9500},
    };

    // Filter by min_count
    extremities.erase(std::remove_if(extremities.begin(), extremities.end(),
        [min_count](const FwdExtremity& e) { return e.count < min_count; }),
        extremities.end());

    // Sort by count descending
    std::sort(extremities.begin(), extremities.end(),
        [](const FwdExtremity& a, const FwdExtremity& b) { return a.count > b.count; });

    int total = static_cast<int>(extremities.size());
    json resp;
    resp["results"] = json::array();
    resp["total"] = total;

    int end = std::min(from + limit, total);
    if (from < total) {
        for (int i = from; i < end; ++i) {
            const auto& e = extremities[i];
            json entry;
            entry["room_id"] = e.room_id;
            entry["count"] = e.count;
            entry["max_depth"] = e.max_depth;
            entry["min_depth"] = e.min_depth;
            entry["delta"] = e.max_depth - e.min_depth;
            resp["results"].push_back(entry);
        }
    }

    return HttpResponse::ok(resp);
}

// -------------------------------------------------------------------------
// POST /_synapse/admin/v1/forward_extremities/{roomId}/delete
//   Deletes forward extremities for a room.
// -------------------------------------------------------------------------

HttpResponse handle_forward_extremities_delete(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    std::string room_id = url_decode(path_param(req, "roomId"));
    if (room_id.empty()) {
        return HttpResponse::bad_request("Missing roomId path parameter");
    }

    json resp;
    resp["room_id"] = room_id;
    resp["deleted"] = 42;
    resp["message"] = "Forward extremities cleaned for room " + room_id;

    return HttpResponse::ok(resp);
}

// -------------------------------------------------------------------------
// GET /_synapse/admin/v1/rooms/{roomId}/timeline/purge
//   POST - Purges historical messages from a room before a given event.
//   Body: { "before_event_id": "$event_id" }
// -------------------------------------------------------------------------

HttpResponse handle_room_timeline_purge(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    std::string room_id = url_decode(path_param(req, "roomId"));
    if (room_id.empty()) {
        return HttpResponse::bad_request("Missing roomId path parameter");
    }

    json body;
    std::string before_event_id;
    if (parse_json_body(req, body) && body.contains("before_event_id")) {
        before_event_id = body["before_event_id"].get<std::string>();
    }

    std::string purge_id = random_hex(16);

    {
        std::lock_guard<std::mutex> lock(g_mutex);
        PurgeJob job;
        job.purge_id = purge_id;
        job.status = "active";
        job.progress = 0;
        job.total = 5000;
        job.started_at = std::time(nullptr);
        g_purge_jobs[purge_id] = job;
    }

    // Complete immediately for demo
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        auto it = g_purge_jobs.find(purge_id);
        if (it != g_purge_jobs.end()) {
            it->second.status = "complete";
            it->second.progress = 5000;
        }
    }

    json resp;
    resp["purge_id"] = purge_id;
    resp["room_id"] = room_id;
    resp["before_event_id"] = before_event_id.empty() ? json(nullptr) : json(before_event_id);
    resp["status"] = "complete";
    resp["events_purged"] = 5000;

    return HttpResponse::ok(resp);
}

// -------------------------------------------------------------------------
// GET /_synapse/admin/v1/rooms/{roomId}/block
//   POST - Blocks or unblocks a room.
//   Body: { "block": true }
// -------------------------------------------------------------------------

HttpResponse handle_room_block(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    std::string room_id = url_decode(path_param(req, "roomId"));
    if (room_id.empty()) {
        return HttpResponse::bad_request("Missing roomId path parameter");
    }

    json body;
    bool block = true;
    if (parse_json_body(req, body) && body.contains("block")) {
        block = body["block"].get<bool>();
    }

    json resp;
    resp["room_id"] = room_id;
    resp["blocked"] = block;
    resp["message"] = block ?
        "Room blocked: " + room_id :
        "Room unblocked: " + room_id;

    return HttpResponse::ok(resp);
}

// -------------------------------------------------------------------------
// GET /_synapse/admin/v1/rooms/{roomId}/media
//   Lists all media in a room.
//   Query: ?from=&limit=
// -------------------------------------------------------------------------

HttpResponse handle_room_media_list(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    std::string room_id = url_decode(path_param(req, "roomId"));
    if (room_id.empty()) {
        return HttpResponse::bad_request("Missing roomId path parameter");
    }

    int from = query_param_int(req, "from", 0);
    int limit = query_param_int(req, "limit", 100);

    std::lock_guard<std::mutex> lock(g_mutex);

    // Return media associated with the room (simulated)
    json resp;
    resp["room_id"] = room_id;
    resp["local"] = json::array();
    resp["remote"] = json::array();
    resp["total"] = 0;

    int total = 0;
    for (const auto& [sv, entries] : g_media_store) {
        for (const auto& m : entries) {
            json entry;
            entry["media_id"] = m.media_id;
            entry["server_name"] = m.server_name;
            entry["upload_name"] = m.upload_name;
            entry["content_type"] = m.content_type;
            entry["size_bytes"] = m.size_bytes;
            entry["created_ts"] = m.created_ts;
            entry["uploader"] = m.uploader_user_id;
            if (sv == "localhost") {
                resp["local"].push_back(entry);
            } else {
                resp["remote"].push_back(entry);
            }
            total++;
        }
    }

    resp["total"] = total;

    return HttpResponse::ok(resp);
}

// -------------------------------------------------------------------------
// GET /_synapse/admin/v1/user/{userId}/media
//   Lists all media uploaded by a specific user.
//   Query: ?from=&limit=&order_by=&direction=
// -------------------------------------------------------------------------

HttpResponse handle_user_media_list(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    std::string user_id = url_decode(path_param(req, "userId"));
    if (user_id.empty()) {
        return HttpResponse::bad_request("Missing userId path parameter");
    }

    int from = query_param_int(req, "from", 0);
    int limit = query_param_int(req, "limit", 100);
    std::string order_by = query_param_str(req, "order_by", "created_ts");
    std::string direction = query_param_str(req, "direction", "f");

    std::lock_guard<std::mutex> lock(g_mutex);

    std::vector<MediaEntry> user_media;
    for (const auto& [sv, entries] : g_media_store) {
        for (const auto& m : entries) {
            if (m.uploader_user_id == user_id) {
                user_media.push_back(m);
            }
        }
    }

    // Sort
    if (order_by == "size_bytes") {
        std::sort(user_media.begin(), user_media.end(),
            [&direction](const MediaEntry& a, const MediaEntry& b) {
                return direction == "b" ? a.size_bytes > b.size_bytes : a.size_bytes < b.size_bytes;
            });
    } else {
        std::sort(user_media.begin(), user_media.end(),
            [&direction](const MediaEntry& a, const MediaEntry& b) {
                return direction == "b" ? a.created_ts > b.created_ts : a.created_ts < b.created_ts;
            });
    }

    int64_t total_size = 0;
    for (const auto& m : user_media) total_size += m.size_bytes;

    int total = static_cast<int>(user_media.size());
    json resp;
    resp["user_id"] = user_id;
    resp["media"] = json::array();
    resp["total"] = total;
    resp["total_size_bytes"] = total_size;

    int end = std::min(from + limit, total);
    if (from < total) {
        for (int i = from; i < end; ++i) {
            const auto& m = user_media[i];
            json entry;
            entry["media_id"] = m.media_id;
            entry["server_name"] = m.server_name;
            entry["upload_name"] = m.upload_name;
            entry["content_type"] = m.content_type;
            entry["size_bytes"] = m.size_bytes;
            entry["created_ts"] = m.created_ts;
            entry["last_access_ts"] = m.last_access_ts;
            entry["quarantined"] = m.quarantined;
            entry["uploader_user_id"] = m.uploader_user_id;
            resp["media"].push_back(entry);
        }
    }

    if (end < total) {
        resp["next_token"] = end;
    } else {
        resp["next_token"] = nullptr;
    }

    return HttpResponse::ok(resp);
}

// -------------------------------------------------------------------------
// POST /_synapse/admin/v1/user/{userId}/shadow_ban
//   Body: { "shadow_ban": true }
// -------------------------------------------------------------------------

HttpResponse handle_user_shadow_ban(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    std::string user_id = url_decode(path_param(req, "userId"));
    if (user_id.empty()) {
        return HttpResponse::bad_request("Missing userId path parameter");
    }

    json body;
    bool shadow_ban = true;
    if (parse_json_body(req, body) && body.contains("shadow_ban")) {
        shadow_ban = body["shadow_ban"].get<bool>();
    }

    std::lock_guard<std::mutex> lock(g_mutex);

    auto it = g_whois_store.find(user_id);
    if (it == g_whois_store.end()) {
        return HttpResponse::not_found("User not found: " + user_id);
    }

    json resp;
    resp["user_id"] = user_id;
    resp["shadow_banned"] = shadow_ban;
    resp["message"] = shadow_ban ?
        "User shadow-banned: " + user_id :
        "User un-shadow-banned: " + user_id;

    return HttpResponse::ok(resp);
}

// -------------------------------------------------------------------------
// POST /_synapse/admin/v1/user/{userId}/lock
//   Body: { "lock": true }
// -------------------------------------------------------------------------

HttpResponse handle_user_lock(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    std::string user_id = url_decode(path_param(req, "userId"));
    if (user_id.empty()) {
        return HttpResponse::bad_request("Missing userId path parameter");
    }

    json body;
    bool lock = true;
    if (parse_json_body(req, body) && body.contains("lock")) {
        lock = body["lock"].get<bool>();
    }

    std::lock_guard<std::mutex> lock_guard(g_mutex);

    auto it = g_whois_store.find(user_id);
    if (it == g_whois_store.end()) {
        return HttpResponse::not_found("User not found: " + user_id);
    }

    json resp;
    resp["user_id"] = user_id;
    resp["locked"] = lock;
    resp["message"] = lock ?
        "User account locked: " + user_id :
        "User account unlocked: " + user_id;

    return HttpResponse::ok(resp);
}

// -------------------------------------------------------------------------
// GET /_synapse/admin/v1/user/{userId}/admin
//   Returns whether the user is a server admin.
// -------------------------------------------------------------------------

HttpResponse handle_user_admin_status(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    std::string user_id = url_decode(path_param(req, "userId"));
    if (user_id.empty()) {
        return HttpResponse::bad_request("Missing userId path parameter");
    }

    std::lock_guard<std::mutex> lock(g_mutex);

    auto it = g_whois_store.find(user_id);
    if (it == g_whois_store.end()) {
        return HttpResponse::not_found("User not found: " + user_id);
    }

    json resp;
    resp["user_id"] = user_id;
    resp["admin"] = it->second.is_admin;

    return HttpResponse::ok(resp);
}

// -------------------------------------------------------------------------
// POST /_synapse/admin/v1/user/{userId}/admin
//   Body: { "admin": true }
// -------------------------------------------------------------------------

HttpResponse handle_user_admin_set(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    std::string user_id = url_decode(path_param(req, "userId"));
    if (user_id.empty()) {
        return HttpResponse::bad_request("Missing userId path parameter");
    }

    json body;
    if (!parse_json_body(req, body) || !body.contains("admin")) {
        return HttpResponse::bad_request("Missing 'admin' field in body");
    }

    bool admin_status = body["admin"].get<bool>();

    std::lock_guard<std::mutex> lock(g_mutex);

    auto it = g_whois_store.find(user_id);
    if (it == g_whois_store.end()) {
        return HttpResponse::not_found("User not found: " + user_id);
    }

    it->second.is_admin = admin_status;

    json resp;
    resp["user_id"] = user_id;
    resp["admin"] = admin_status;
    resp["message"] = admin_status ?
        "User promoted to admin: " + user_id :
        "User demoted from admin: " + user_id;

    return HttpResponse::ok(resp);
}

// -------------------------------------------------------------------------
// GET /_synapse/admin/v1/pushers
//   Lists all pushers.
//   Query: ?from=&limit=
// -------------------------------------------------------------------------

HttpResponse handle_pushers_list(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    int from = query_param_int(req, "from", 0);
    int limit = query_param_int(req, "limit", 100);

    // Simulated pushers
    struct Pusher {
        std::string pusher_id;
        std::string user_id;
        std::string app_id;
        std::string pushkey;
        std::string app_display_name;
        std::string device_display_name;
        std::string kind;
        std::string lang;
        bool enabled;
    };

    std::vector<Pusher> pushers = {
        {"pusher1", "@alice:localhost", "org.matrix.matrix_client.Element.android",
         "APA91bHPRgkF3JUikC4ENAHEeMrdgZxv3hVWpagkAVmMrDjfU3HXG9nciYZ_9iF3G",
         "Element Android", "Alice's Phone", "http", "en", true},
        {"pusher2", "@alice:localhost", "org.matrix.matrix_client.Element.ios",
         "production_com_apple_apns_12345",
         "Element iOS", "Alice's iPad", "http", "en", true},
        {"pusher3", "@admin:localhost", "org.matrix.matrix_client.Element.linux",
         "email_admin@localhost",
         "Element Desktop", "Admin Workstation", "email", "en", false},
    };

    int total = static_cast<int>(pushers.size());
    json resp;
    resp["pushers"] = json::array();
    resp["total"] = total;

    int end = std::min(from + limit, total);
    if (from < total) {
        for (int i = from; i < end; ++i) {
            const auto& p = pushers[i];
            json entry;
            entry["pushkey"] = p.pushkey;
            entry["kind"] = p.kind;
            entry["app_id"] = p.app_id;
            entry["app_display_name"] = p.app_display_name;
            entry["device_display_name"] = p.device_display_name;
            entry["profile_tag"] = "";
            entry["lang"] = p.lang;
            entry["data"] = json::object();
            entry["user_id"] = p.user_id;
            entry["enabled"] = p.enabled;
            entry["pusher_id"] = p.pusher_id;
            resp["pushers"].push_back(entry);
        }
    }

    if (end < total) {
        resp["next_token"] = end;
    } else {
        resp["next_token"] = nullptr;
    }

    return HttpResponse::ok(resp);
}

// -------------------------------------------------------------------------
// GET /_synapse/admin/v1/users/{userId}/pushers
//   Lists pushers for a specific user.
// -------------------------------------------------------------------------

HttpResponse handle_user_pushers(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    std::string user_id = url_decode(path_param(req, "userId"));
    if (user_id.empty()) {
        return HttpResponse::bad_request("Missing userId path parameter");
    }

    json resp;
    resp["user_id"] = user_id;
    resp["pushers"] = json::array();
    resp["total"] = 0;

    // Simulated: return pushers only for known users
    if (user_id == "@alice:localhost") {
        json p1;
        p1["pusher_id"] = "pusher1";
        p1["app_id"] = "org.matrix.matrix_client.Element.android";
        p1["kind"] = "http";
        p1["enabled"] = true;
        resp["pushers"].push_back(p1);

        json p2;
        p2["pusher_id"] = "pusher2";
        p2["app_id"] = "org.matrix.matrix_client.Element.ios";
        p2["kind"] = "http";
        p2["enabled"] = true;
        resp["pushers"].push_back(p2);

        resp["total"] = 2;
    }

    return HttpResponse::ok(resp);
}

// -------------------------------------------------------------------------
// GET /_synapse/admin/v1/config
//   Returns the server config (admin view).
// -------------------------------------------------------------------------

HttpResponse handle_server_config(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    json resp;
    resp["server_name"] = SERVER_NAME;
    resp["pid"] = 12345;
    resp["config"] = json::object();

    // Server config section
    json server;
    server["server_name"] = SERVER_NAME;
    server["web_client_location"] = "/_matrix/client";
    server["soft_file_limit"] = 65536;
    server["hard_file_limit"] = 65536;
    server["daemonize"] = false;
    server["cpu_affinity"] = 0;
    server["use_presence"] = true;
    server["presence_router"] = "presence_router";
    server["federation_rc_window_size"] = 1000;
    server["federation_rc_sleep_limit"] = 10;
    server["federation_rc_sleep_delay"] = 500;
    server["federation_rc_reject_limit"] = 50;
    server["federation_rc_concurrent"] = 3;
    resp["config"]["server"] = server;

    // Database config
    json database;
    database["name"] = "psycopg2";
    database["args"]["database"] = "synapse";
    database["args"]["user"] = "synapse_user";
    database["args"]["host"] = "localhost";
    database["args"]["port"] = 5432;
    database["args"]["cp_min"] = 5;
    database["args"]["cp_max"] = 20;
    resp["config"]["database"] = database;

    // Logging config
    json logging;
    logging["log_level"] = "INFO";
    logging["log_file"] = "/var/log/synapse/homeserver.log";
    logging["structured"] = true;
    resp["config"]["logging"] = logging;

    // Rate limiting
    json ratelimiting;
    ratelimiting["messages_per_second"] = 10;
    ratelimiting["burst_count"] = 20;
    ratelimiting["rc_messages_per_second"] = 10;
    ratelimiting["rc_message_burst_count"] = 20;
    ratelimiting["rc_registration"] = json::object({{"per_second", 0.17}, {"burst_count", 3}});
    ratelimiting["rc_login"] = json::object({{"address", {{"per_second", 0.17}, {"burst_count", 3}}},
                                              {"account", {{"per_second", 0.17}, {"burst_count", 3}}}});
    resp["config"]["rate_limiting"] = ratelimiting;

    // Media config
    json media;
    media["max_upload_size"] = "50M";
    media["max_image_pixels"] = "32M";
    media["media_store_path"] = "/var/lib/synapse/media_store";
    media["dynamic_thumbnails"] = true;
    media["thumbnail_sizes"] = json::array({
        {{"width", 32}, {"height", 32}, {"method", "crop"}},
        {{"width", 96}, {"height", 96}, {"method", "crop"}},
        {{"width", 320}, {"height", 240}, {"method", "scale"}},
        {{"width", 640}, {"height", 480}, {"method", "scale"}},
        {{"width", 800}, {"height", 600}, {"method", "scale"}},
    });
    resp["config"]["media"] = media;

    // Registration config
    json registration;
    registration["enable_registration"] = true;
    registration["registrations_require_3pid"] = false;
    registration["disable_msisdn_registration"] = false;
    registration["allowed_local_3pids"] = json::array({"email"});
    registration["enable_registration_captcha"] = false;
    registration["user_consent"] = json::object({
        {"require_at_registration", false},
        {"policy_name", "Privacy Policy"},
        {"template_dir", "res/templates/privacy"},
    });
    resp["config"]["registration"] = registration;

    // Retention config
    json retention;
    retention["default_policy"] = json::object({
        {"min_lifetime", 86400000},
        {"max_lifetime", 2592000000},
    });
    retention["allowed_lifetime_min"] = 86400000;
    retention["allowed_lifetime_max"] = 31536000000;
    resp["config"]["retention"] = retention;

    // TLS config
    json tls;
    tls["tls_certificate_path"] = "/etc/synapse/tls.crt";
    tls["tls_private_key_path"] = "/etc/synapse/tls.key";
    tls["tls_dh_params_path"] = nullptr;
    tls["federation_verify_certificates"] = true;
    resp["config"]["tls"] = tls;

    return HttpResponse::ok(resp);
}

// -------------------------------------------------------------------------
// POST /_synapse/admin/v1/config/reload
//   Reloads the server configuration.
// -------------------------------------------------------------------------

HttpResponse handle_config_reload(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    json resp;
    resp["reloaded"] = true;
    resp["server_name"] = SERVER_NAME;
    resp["message"] = "Server configuration reloaded successfully";

    return HttpResponse::ok(resp);
}

// -------------------------------------------------------------------------
// POST /_synapse/admin/v1/shutdown
//   Gracefully shuts down the server.
//   Body: { "pid": 12345 } (must match actual PID)
// -------------------------------------------------------------------------

HttpResponse handle_server_shutdown(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    json body;
    if (!parse_json_body(req, body) || !body.contains("pid")) {
        return HttpResponse::bad_request("Missing 'pid' field in body");
    }

    int pid = body["pid"].get<int>();

    json resp;
    resp["shutdown"] = true;
    resp["pid"] = pid;
    resp["message"] = "Server shutdown initiated";

    // In production this would trigger an actual shutdown sequence.
    // For demo we just acknowledge.

    return HttpResponse::ok(resp);
}

// -------------------------------------------------------------------------
// GET /_synapse/admin/v1/rooms/{roomId}/event/{eventId}
//   Retrieves a single event by ID.
// -------------------------------------------------------------------------

HttpResponse handle_room_event_detail(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    std::string room_id = url_decode(path_param(req, "roomId"));
    std::string event_id = url_decode(path_param(req, "eventId"));

    if (room_id.empty() || event_id.empty()) {
        return HttpResponse::bad_request("Missing roomId or eventId path parameter");
    }

    // Simulated event
    json resp;
    resp["event_id"] = event_id;
    resp["room_id"] = room_id;
    resp["type"] = "m.room.message";
    resp["sender"] = "@alice:localhost";
    resp["origin_server_ts"] = 1685100000000;
    resp["content"] = json::object({
        {"msgtype", "m.text"},
        {"body", "Hello from admin view"},
    });
    resp["unsigned"] = json::object({
        {"age", 123456},
        {"transaction_id", "txn_abc123"},
    });

    return HttpResponse::ok(resp);
}

// -------------------------------------------------------------------------
// GET /_synapse/admin/v1/account_validity
//   Lists account validity information.
// -------------------------------------------------------------------------

HttpResponse handle_account_validity(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    json resp;
    resp["account_validity"] = json::object();
    resp["account_validity"]["enabled"] = true;
    resp["account_validity"]["period"] = 604800000; // 7 days in ms
    resp["account_validity"]["renew_at"] = 259200000; // 3 days
    resp["account_validity"]["renew_by_email_enabled"] = true;
    resp["account_validity"]["startup_job_max_delta"] = 86400000;
    resp["account_validity"]["users"] = json::array();

    for (const auto& [uid, info] : g_whois_store) {
        json user;
        user["user_id"] = uid;
        user["expiration_ts"] = static_cast<int64_t>(
            std::stoll(info.creation_ts) + 604800000);
        user["expired"] = info.deactivated;
        user["renewed"] = !info.deactivated;
        resp["account_validity"]["users"].push_back(user);
    }

    resp["account_validity"]["total"] = static_cast<int>(g_whois_store.size());

    return HttpResponse::ok(resp);
}

// -------------------------------------------------------------------------
// GET /_synapse/admin/v1/devices/{userId}
//   Lists all devices for a user.
// -------------------------------------------------------------------------

HttpResponse handle_user_devices(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    std::string user_id = url_decode(path_param(req, "userId"));
    if (user_id.empty()) {
        return HttpResponse::bad_request("Missing userId path parameter");
    }

    std::lock_guard<std::mutex> lock(g_mutex);

    auto it = g_whois_store.find(user_id);
    if (it == g_whois_store.end()) {
        return HttpResponse::not_found("User not found: " + user_id);
    }

    json resp;
    resp["user_id"] = user_id;
    resp["devices"] = json::array();
    resp["total"] = static_cast<int>(it->second.devices.size());

    for (const auto& dev : it->second.devices) {
        json d;
        d["device_id"] = dev.device_id;
        d["display_name"] = dev.display_name;
        d["last_seen_ip"] = dev.last_seen_ip;
        d["last_seen_ts"] = dev.last_seen_ts;
        d["user_agent"] = dev.user_agent;
        resp["devices"].push_back(d);
    }

    return HttpResponse::ok(resp);
}

// -------------------------------------------------------------------------
// POST /_synapse/admin/v1/devices/{userId}/delete/{deviceId}
//   Deletes a specific device.
// -------------------------------------------------------------------------

HttpResponse handle_device_delete(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    std::string user_id = url_decode(path_param(req, "userId"));
    std::string device_id = url_decode(path_param(req, "deviceId"));

    if (user_id.empty() || device_id.empty()) {
        return HttpResponse::bad_request("Missing userId or deviceId path parameter");
    }

    std::lock_guard<std::mutex> lock(g_mutex);

    auto it = g_whois_store.find(user_id);
    if (it == g_whois_store.end()) {
        return HttpResponse::not_found("User not found: " + user_id);
    }

    auto& devices = it->second.devices;
    auto dev_it = std::find_if(devices.begin(), devices.end(),
        [&device_id](const DeviceInfo& d) { return d.device_id == device_id; });

    if (dev_it == devices.end()) {
        return HttpResponse::not_found("Device not found: " + device_id);
    }

    devices.erase(dev_it);

    json resp;
    resp["user_id"] = user_id;
    resp["device_id"] = device_id;
    resp["deleted"] = true;
    resp["message"] = "Device deleted: " + device_id;

    return HttpResponse::ok(resp);
}

// -------------------------------------------------------------------------
// POST /_synapse/admin/v1/devices/{userId}/delete_all
//   Deletes all devices for a user.
// -------------------------------------------------------------------------

HttpResponse handle_device_delete_all(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    std::string user_id = url_decode(path_param(req, "userId"));
    if (user_id.empty()) {
        return HttpResponse::bad_request("Missing userId path parameter");
    }

    std::lock_guard<std::mutex> lock(g_mutex);

    auto it = g_whois_store.find(user_id);
    if (it == g_whois_store.end()) {
        return HttpResponse::not_found("User not found: " + user_id);
    }

    int count = static_cast<int>(it->second.devices.size());
    it->second.devices.clear();

    json resp;
    resp["user_id"] = user_id;
    resp["deleted"] = count;
    resp["message"] = std::to_string(count) + " devices deleted for " + user_id;

    return HttpResponse::ok(resp);
}

// -------------------------------------------------------------------------
// POST /_synapse/admin/v1/user/{userId}/threepid/delete
//   Deletes a third-party identifier (email, phone) from a user.
//   Body: { "medium": "email", "address": "user@example.com" }
// -------------------------------------------------------------------------

HttpResponse handle_threepid_delete(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    std::string user_id = url_decode(path_param(req, "userId"));
    if (user_id.empty()) {
        return HttpResponse::bad_request("Missing userId path parameter");
    }

    json body;
    if (!parse_json_body(req, body)) {
        return HttpResponse::bad_request("Invalid JSON body");
    }

    if (!body.contains("medium") || !body.contains("address")) {
        return HttpResponse::bad_request("Missing 'medium' or 'address' fields");
    }

    std::string medium = body["medium"].get<std::string>();
    std::string address = body["address"].get<std::string>();

    json resp;
    resp["user_id"] = user_id;
    resp["medium"] = medium;
    resp["address"] = address;
    resp["deleted"] = true;
    resp["message"] = "Third-party identifier deleted: " + address;

    return HttpResponse::ok(resp);
}

// -------------------------------------------------------------------------
// GET /_synapse/admin/v1/rooms/{roomId}/messages
//   Returns recent messages from a room (admin view).
//   Query: ?from=&limit=&filter=&dir=
// -------------------------------------------------------------------------

HttpResponse handle_room_messages(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    std::string room_id = url_decode(path_param(req, "roomId"));
    if (room_id.empty()) {
        return HttpResponse::bad_request("Missing roomId path parameter");
    }

    int limit = query_param_int(req, "limit", 10);
    std::string dir = query_param_str(req, "dir", "b");

    // Simulated messages
    json resp;
    resp["chunk"] = json::array();
    resp["room_id"] = room_id;

    for (int i = 0; i < limit; ++i) {
        json event;
        event["event_id"] = "$admin_view_event_" + std::to_string(i);
        event["room_id"] = room_id;
        event["type"] = "m.room.message";
        event["sender"] = "@alice:localhost";
        event["origin_server_ts"] = 1685100000000 - i * 1000;
        event["content"] = json::object({
            {"msgtype", "m.text"},
            {"body", "Message " + std::to_string(i) + " from admin view"},
        });
        event["unsigned"] = json::object({{"age", i * 1000}});
        resp["chunk"].push_back(event);
    }

    resp["start"] = "start_token_abc";
    resp["end"] = "end_token_xyz";

    return HttpResponse::ok(resp);
}

// -------------------------------------------------------------------------
// GET /_synapse/admin/v1/rooms/{roomId}/timestamp_to_event
//   Query: ?ts=1685100000000&dir=f
//   Returns the event ID closest to the given timestamp.
// -------------------------------------------------------------------------

HttpResponse handle_timestamp_to_event(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    std::string room_id = url_decode(path_param(req, "roomId"));
    if (room_id.empty()) {
        return HttpResponse::bad_request("Missing roomId path parameter");
    }

    int64_t ts = query_param_int(req, "ts", 0);
    std::string dir = query_param_str(req, "dir", "f");

    json resp;
    resp["event_id"] = "$event_timestamp_" + std::to_string(ts);
    resp["origin_server_ts"] = ts;
    resp["room_id"] = room_id;
    resp["dir"] = dir;

    return HttpResponse::ok(resp);
}

// -------------------------------------------------------------------------
// GET /_synapse/admin/v1/debug/state_resolution
//   Query: ?room_id=!room:server&limit=50
//   Returns state resolution debug info.
// -------------------------------------------------------------------------

HttpResponse handle_debug_state_resolution(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    std::string room_filter = query_param_str(req, "room_id", "");
    int limit = query_param_int(req, "limit", 50);

    json resp;
    resp["results"] = json::array();
    resp["total"] = 0;

    // Simulated state resolution debug entries
    std::vector<std::string> rooms;
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        for (const auto& [uid, info] : g_whois_store) {
            for (const auto& r : info.rooms_joined) {
                if (std::find(rooms.begin(), rooms.end(), r) == rooms.end()) {
                    rooms.push_back(r);
                }
            }
        }
    }

    if (!room_filter.empty()) {
        rooms.erase(std::remove_if(rooms.begin(), rooms.end(),
            [&room_filter](const std::string& r) { return r != room_filter; }),
            rooms.end());
    }

    int count = 0;
    for (const auto& r : rooms) {
        if (count >= limit) break;
        json entry;
        entry["room_id"] = r;
        entry["state_group"] = 1000 + count;
        entry["state_resolutions"] = count * 3;
        entry["avg_resolution_time_ms"] = 0.5 + count * 0.1;
        entry["max_resolution_time_ms"] = 5.0 + count * 0.5;
        entry["conflicts_resolved"] = count * 10;
        resp["results"].push_back(entry);
        count++;
    }
    resp["total"] = count;

    return HttpResponse::ok(resp);
}

// -------------------------------------------------------------------------
// GET /_synapse/admin/v1/debug/state_groups
//   Query: ?room_id=!room:server
//   Returns state group debug info for a room.
// -------------------------------------------------------------------------

HttpResponse handle_debug_state_groups(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    std::string room_filter = query_param_str(req, "room_id", "");

    json resp;
    resp["state_groups"] = json::array();

    if (!room_filter.empty()) {
        for (int i = 0; i < 10; ++i) {
            json sg;
            sg["state_group"] = 1000 + i;
            sg["room_id"] = room_filter;
            sg["event_types"] = 6;
            sg["total_state_events"] = 12 + i * 2;
            resp["state_groups"].push_back(sg);
        }
    }

    resp["total"] = room_filter.empty() ? 0 : 10;

    return HttpResponse::ok(resp);
}

// -------------------------------------------------------------------------
// GET /_synapse/admin/v1/debug/event_auth
//   Query: ?event_id=$event123
//   Returns auth chain info for an event.
// -------------------------------------------------------------------------

HttpResponse handle_debug_event_auth(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    std::string event_id = query_param_str(req, "event_id", "");

    if (event_id.empty()) {
        return HttpResponse::bad_request("Missing 'event_id' query parameter");
    }

    json resp;
    resp["event_id"] = event_id;
    resp["auth_events"] = json::array();

    // Simulated auth chain
    for (int i = 0; i < 5; ++i) {
        json ae;
        ae["event_id"] = "$auth_event_" + std::to_string(i);
        ae["type"] = i == 0 ? "m.room.create" :
                     i == 1 ? "m.room.member" :
                     i == 2 ? "m.room.power_levels" :
                     i == 3 ? "m.room.join_rules" :
                              "m.room.history_visibility";
        ae["state_key"] = "";
        ae["room_id"] = "!room:localhost";
        resp["auth_events"].push_back(ae);
    }

    resp["auth_chain_length"] = 5;

    return HttpResponse::ok(resp);
}

// -------------------------------------------------------------------------
// POST /_synapse/admin/v1/media/preview_url/delete
//   Deletes a URL preview cache entry.
//   Body: { "url": "https://example.com/page" }
// -------------------------------------------------------------------------

HttpResponse handle_preview_url_delete(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    json body;
    if (!parse_json_body(req, body) || !body.contains("url")) {
        return HttpResponse::bad_request("Missing 'url' field in body");
    }

    std::string url = body["url"].get<std::string>();

    json resp;
    resp["url"] = url;
    resp["deleted"] = true;
    resp["message"] = "URL preview cache deleted for: " + url;

    return HttpResponse::ok(resp);
}

// -------------------------------------------------------------------------
// POST /_synapse/admin/v1/user/{userId}/consent
//   Grants or withdraws user consent.
//   Body: { "consent": true }
// -------------------------------------------------------------------------

HttpResponse handle_user_consent(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    std::string user_id = url_decode(path_param(req, "userId"));
    if (user_id.empty()) {
        return HttpResponse::bad_request("Missing userId path parameter");
    }

    json body;
    bool consent = true;
    if (parse_json_body(req, body) && body.contains("consent")) {
        consent = body["consent"].get<bool>();
    }

    json resp;
    resp["user_id"] = user_id;
    resp["consent_granted"] = consent;
    resp["message"] = consent ?
        "User consent granted for: " + user_id :
        "User consent withdrawn for: " + user_id;

    return HttpResponse::ok(resp);
}

// -------------------------------------------------------------------------
// GET /_synapse/admin/v1/user/{userId}/joined_rooms
//   Returns all rooms the user is joined to.
// -------------------------------------------------------------------------

HttpResponse handle_user_joined_rooms(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    std::string user_id = url_decode(path_param(req, "userId"));
    if (user_id.empty()) {
        return HttpResponse::bad_request("Missing userId path parameter");
    }

    std::lock_guard<std::mutex> lock(g_mutex);

    auto it = g_whois_store.find(user_id);
    if (it == g_whois_store.end()) {
        return HttpResponse::not_found("User not found: " + user_id);
    }

    json resp;
    resp["user_id"] = user_id;
    resp["joined_rooms"] = json::array();
    resp["total"] = static_cast<int>(it->second.rooms_joined.size());

    for (const auto& r : it->second.rooms_joined) {
        resp["joined_rooms"].push_back(r);
    }

    return HttpResponse::ok(resp);
}

// -------------------------------------------------------------------------
// GET /_synapse/admin/v1/debug/complement
//   Debug endpoint for complement testing: returns basic server info.
// -------------------------------------------------------------------------

HttpResponse handle_debug_complement(const HttpRequest& req) {
    (void)req;
    // No admin auth required for this debug endpoint

    json resp;
    resp["server_name"] = SERVER_NAME;
    resp["uptime_ms"] = (std::time(nullptr) - 1670000000) * 1000;
    resp["features"] = json::object({
        {"msc3026", true},
        {"msc3881", false},
    });

    return HttpResponse::ok(resp);
}

// -------------------------------------------------------------------------
// GET /_synapse/admin/v1/workers
//   Returns information about all worker processes.
// -------------------------------------------------------------------------

HttpResponse handle_workers(const HttpRequest& req) {
    auto auth = require_admin(req);
    if (auth) return *auth;

    json resp;
    resp["workers"] = json::array();

    // Main process
    json main;
    main["name"] = "master";
    main["pid"] = 12345;
    main["cpu_percent"] = 15.2;
    main["memory_rss_bytes"] = 256 * 1024 * 1024;
    main["last_seen"] = std::time(nullptr);
    main["connections"] = 42;
    resp["workers"].push_back(main);

    // Worker processes (simulated)
    json worker1;
    worker1["name"] = "synapse.app.generic_worker1";
    worker1["pid"] = 12346;
    worker1["cpu_percent"] = 8.7;
    worker1["memory_rss_bytes"] = 128 * 1024 * 1024;
    worker1["last_seen"] = std::time(nullptr);
    worker1["connections"] = 18;
    resp["workers"].push_back(worker1);

    json worker2;
    worker2["name"] = "synapse.app.generic_worker2";
    worker2["pid"] = 12347;
    worker2["cpu_percent"] = 7.3;
    worker2["memory_rss_bytes"] = 120 * 1024 * 1024;
    worker2["last_seen"] = std::time(nullptr);
    worker2["connections"] = 15;
    resp["workers"].push_back(worker2);

    json media_worker;
    media_worker["name"] = "synapse.app.media_repository";
    media_worker["pid"] = 12348;
    media_worker["cpu_percent"] = 3.1;
    media_worker["memory_rss_bytes"] = 96 * 1024 * 1024;
    media_worker["last_seen"] = std::time(nullptr);
    media_worker["connections"] = 8;
    resp["workers"].push_back(media_worker);

    resp["total_workers"] = 4;

    return HttpResponse::ok(resp);
}

// -------------------------------------------------------------------------
// Extended route registration: add all new endpoints to the route table
// -------------------------------------------------------------------------

// Update get_admin_routes() to include all new endpoints
std::vector<RouteEntry> get_admin_routes() {
    init_demo_state();

    return {
        // Health
        {"GET",    "/health",                                                     handle_health},

        // Core admin v1
        {"GET",    "/_synapse/admin/v1/server_version",                           handle_server_version},
        {"GET",    "/_synapse/admin/v1/version",                                  handle_version},
        {"GET",    "/_synapse/admin/v1/federation/destinations",                  handle_federation_destinations},
        {"GET",    "/_synapse/admin/v1/federation/status",                        handle_federation_status},
        {"POST",   "/_synapse/admin/v1/reset_connection_timeout",                 handle_reset_connection_timeout},
        {"GET",    "/_synapse/admin/v1/background_updates",                       handle_background_updates_list},
        {"GET",    "/_synapse/admin/v1/background_updates/status",                handle_background_updates_status},
        {"POST",   "/_synapse/admin/v1/purge_media_cache",                        handle_purge_media_cache},
        {"GET",    "/_synapse/admin/v1/server_notices",                           handle_server_notices_list},
        {"GET",    "/_synapse/admin/v1/server_notices/status",                    handle_server_notices_status},
        {"POST",   "/_synapse/admin/v1/send_server_notice",                       handle_send_server_notice},
        {"POST",   "/_synapse/admin/v1/override_ratelimit",                       handle_override_ratelimit},
        {"POST",   "/_synapse/admin/v1/delete_group",                             handle_delete_group},

        // Users v2
        {"GET",    "/_synapse/admin/v2/users",                                    handle_v2_users},

        // Rooms
        {"GET",    "/_synapse/admin/v1/rooms",                                    handle_rooms_list},

        // Event reports
        {"GET",    "/_synapse/admin/v1/event_reports",                            handle_event_reports},

        // Registration tokens
        {"GET",    "/_synapse/admin/v1/registration_tokens",                      handle_registration_tokens},
        {"POST",   "/_synapse/admin/v1/registration_tokens/new",                  handle_registration_tokens_new},

        // Statistics
        {"GET",    "/_synapse/admin/v1/statistics/users/media",                   handle_statistics_users_media},
        {"GET",    "/_synapse/admin/v1/statistics/database/rooms",                handle_statistics_database_rooms},

        // Experimental
        {"GET",    "/_synapse/admin/v1/experimental_features",                    handle_experimental_features},

        // Server metrics and monitoring
        {"GET",    "/_synapse/admin/v1/server_metrics",                           handle_server_metrics},
        {"GET",    "/_synapse/admin/v1/forward_extremities",                      handle_forward_extremities},
        {"GET",    "/_synapse/admin/v1/pushers",                                  handle_pushers_list},
        {"GET",    "/_synapse/admin/v1/config",                                   handle_server_config},
        {"POST",   "/_synapse/admin/v1/config/reload",                            handle_config_reload},
        {"POST",   "/_synapse/admin/v1/shutdown",                                 handle_server_shutdown},
        {"GET",    "/_synapse/admin/v1/account_validity",                         handle_account_validity},
        {"GET",    "/_synapse/admin/v1/workers",                                  handle_workers},
        {"POST",   "/_synapse/admin/v1/caches/clear",                             handle_caches_clear},
        {"POST",   "/_synapse/admin/v1/media/preview_url/delete",                 handle_preview_url_delete},

        // Debug endpoints
        {"GET",    "/_synapse/admin/v1/debug/state_resolution",                   handle_debug_state_resolution},
        {"GET",    "/_synapse/admin/v1/debug/state_groups",                       handle_debug_state_groups},
        {"GET",    "/_synapse/admin/v1/debug/event_auth",                         handle_debug_event_auth},
        {"GET",    "/_synapse/admin/v1/debug/complement",                         handle_debug_complement},
    };
}

} // anonymous namespace

} // namespace admin
} // namespace progressive
