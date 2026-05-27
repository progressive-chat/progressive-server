// ============================================================================
// admin_media_tools.cpp - Matrix Admin Media Management Tools (3500+ lines)
// Comprehensive media administration: listing, details, quarantine,
// deletion, purge, statistics, cleanup, retention policies, URL preview
// cache, and thumbnail cache management for the progressive-server.
//
// Namespace: progressive::admin
// Include:   ../json.hpp
//
// Endpoint coverage:
//   1.  GET    /_synapse/admin/v1/media                            - List media
//          Query: room_id, user_id, kind, origin, from, limit,
//                  order_by, dir, include_quarantined, before_ts, after_ts
//   2.  GET    /_synapse/admin/v1/media/{origin}/{media_id}        - Media details
//   3.  POST   /_synapse/admin/v1/media/{origin}/{media_id}/quarantine
//   4.  POST   /_synapse/admin/v1/media/{origin}/{media_id}/unquarantine
//   5.  DELETE /_synapse/admin/v1/media/{origin}/{media_id}/delete
//   6.  POST   /_synapse/admin/v1/media/{origin}/{media_id}/soft_delete
//   7.  DELETE /_synapse/admin/v1/media/{origin}/{media_id}        - Hard delete
//   8.  POST   /_synapse/admin/v1/media/purge_remote              - Purge remote
//   9.  GET    /_synapse/admin/v1/media/statistics                - Media stats
//  10.  POST   /_synapse/admin/v1/media/cleanup                   - Orphan/expire
//  11.  GET    /_synapse/admin/v1/media/retention_policy          - Get policy
//  12.  POST   /_synapse/admin/v1/media/retention_policy          - Set policy
//  13.  GET    /_synapse/admin/v1/media/url_previews              - URL previews
//  14.  DELETE /_synapse/admin/v1/media/url_previews              - Clear cache
//  15.  GET    /_synapse/admin/v1/media/thumbnails                - Thumbnail list
//  16.  DELETE /_synapse/admin/v1/media/thumbnails                - Clear thumbs
//  17.  POST   /_synapse/admin/v1/media/bulk_quarantine           - Bulk ops
//  18.  POST   /_synapse/admin/v1/media/bulk_delete               - Bulk delete
//  19.  GET    /_synapse/admin/v1/media/top_media                 - Top by size
//  20.  GET    /_synapse/admin/v1/media/recently_accessed         - Recent access
//  21.  POST   /_synapse/admin/v1/media/quarantine_room           - Quarantine room
// ============================================================================

#include "../json.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdint>
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
// Forward type alias
// ============================================================================

using json = nlohmann::json;

// ============================================================================
// Internal database structures and in-memory stores for media management
// ============================================================================

namespace db {

// --- Media record ---
struct MediaRecord {
    std::string media_id;                    // opaque media identifier
    std::string origin;                      // origin server name
    std::string media_type;                  // MIME type (image/png, etc.)
    std::string upload_name;                 // original filename
    std::string user_id;                     // who uploaded it
    std::string room_id;                     // room context (may be empty)
    std::string created_ts;                  // epoch ms upload time
    std::string last_access_ts;              // epoch ms last download
    std::string etag;                        // content hash for caching
    int64_t media_length = 0;               // size in bytes
    int64_t access_count = 0;               // number of downloads
    int64_t thumbnail_count = 0;            // number of thumbnails generated
    bool quarantined = false;               // whether media is quarantined
    std::string quarantined_by;             // admin who quarantined
    std::string quarantined_ts;             // when quarantined
    std::string quarantine_reason;          // reason for quarantine
    bool safe_from_quarantine = false;      // protected from being quarantined
    bool is_remote = false;                 // media from another server
    std::string remote_server;              // remote origin (if is_remote)
    bool soft_deleted = false;              // soft-deleted, recoverable
    bool hard_deleted = false;              // permanently removed
    std::string deleted_by;
    std::string deleted_ts;
    bool has_preview = false;               // URL preview generated
    int duration_ms = 0;                    // for audio/video
    int width = 0;
    int height = 0;
    std::string content_disposition;        // "inline" or "attachment"
    std::string file_hash_sha256;
    std::string blurhash;                   // for image placeholders
    std::string thumbnail_mxc;              // MXC URI of thumbnail
};

// --- URL Preview Cache entry ---
struct UrlPreviewRecord {
    std::string url;                        // original URL
    std::string url_hash;                   // hash of URL for lookup
    std::string title;                      // og:title
    std::string description;                // og:description
    std::string image_url;                  // og:image
    std::string image_mxc;                  // MXC URI of cached image
    int64_t image_size = 0;                 // cached image bytes
    int64_t image_width = 0;
    int64_t image_height = 0;
    std::string type;                       // "og", "oembed", "twitter_card"
    std::string site_name;
    std::string fetched_ts;                 // epoch ms last fetch
    std::string expires_ts;                 // epoch ms expiry
    int64_t response_time_ms = 0;          // fetch latency
    int http_status = 0;
    std::string error;                      // if fetch failed
    int access_count = 0;
    std::string last_access_ts;
    int64_t ttl_ms = 3600000;              // time-to-live in ms (default 1h)
    bool stale = false;
};

// --- Thumbnail cache entry ---
struct ThumbnailRecord {
    std::string thumbnail_id;
    std::string media_id;                   // parent media
    std::string origin;
    std::string method;                     // "scale" or "crop"
    int width = 0;
    int height = 0;
    int64_t file_size = 0;
    std::string content_type;
    std::string created_ts;
    std::string last_access_ts;
    int access_count = 0;
    bool is_remote = false;
    bool soft_deleted = false;
};

// --- Media retention policy ---
struct MediaRetentionPolicy {
    std::string policy_id;
    std::string name;
    std::string description;
    bool enabled = true;
    std::string applies_to;                 // "all", "room", "user", "mime_type"
    std::string target;                     // room_id, user_id, or mime_type pattern
    int64_t max_lifetime_ms = 0;           // 0 = no limit (infinite)
    int64_t max_idle_ms = 0;               // 0 = no limit
    int64_t max_size_bytes = 0;            // 0 = no limit
    bool delete_remote = true;
    bool delete_quarantined = false;
    bool delete_thumbnails = true;
    std::string created_ts;
    std::string updated_ts;
    int media_deleted_count = 0;           // how many media this policy has removed
    int64_t bytes_deleted = 0;
    std::string last_run_ts;
};

// --- Media quarantine room entry ---
struct QuarantineRoomEntry {
    std::string room_id;
    std::string quarantined_by;
    std::string quarantined_ts;
    std::string reason;
    int media_quarantined = 0;
};

// --- Media cleanup log entry ---
struct CleanupLogEntry {
    std::string log_id;
    std::string run_ts;
    std::string triggered_by;
    std::string reason;                     // "manual", "policy", "scheduled"
    int media_scanned = 0;
    int media_deleted = 0;
    int thumbnails_deleted = 0;
    int previews_deleted = 0;
    int errors = 0;
    int64_t bytes_freed = 0;
    std::string duration_ms;
    std::string status;                     // "running", "complete", "failed"
    std::string error_message;
};

// --- Media access log entry (for tracking downloads) ---
struct MediaAccessLog {
    std::string log_id;
    std::string media_id;
    std::string origin;
    std::string user_id;
    std::string access_ts;
    std::string ip_address;
    std::string user_agent;
    std::string room_id;
    int64_t bytes_transferred = 0;
    int http_status = 200;
};

// In-memory stores
extern std::mutex media_mutex;
extern std::mutex previews_mutex;
extern std::mutex thumbnails_mutex;
extern std::mutex policy_mutex;
extern std::mutex quarantine_room_mutex;
extern std::mutex cleanup_log_mutex;
extern std::mutex media_access_log_mutex;

extern std::unordered_map<std::string, MediaRecord> media;              // "origin/media_id" -> record
extern std::unordered_map<std::string, std::vector<std::string>> room_media;    // room_id -> media keys
extern std::unordered_map<std::string, std::vector<std::string>> user_media;    // user_id -> media keys
extern std::unordered_map<std::string, UrlPreviewRecord> url_previews;          // url_hash -> record
extern std::unordered_map<std::string, ThumbnailRecord> thumbnails;             // thumbnail_id -> record
extern std::unordered_map<std::string, std::vector<std::string>> media_thumbnails; // media_key -> thumbnail_ids
extern std::unordered_map<std::string, MediaRetentionPolicy> retention_policies;
extern std::unordered_map<std::string, QuarantineRoomEntry> quarantine_rooms;
extern std::vector<CleanupLogEntry> cleanup_log;
extern std::vector<MediaAccessLog> media_access_log;

} // namespace db

// ============================================================================
// Mutex definitions
// ============================================================================

std::mutex db::media_mutex;
std::mutex db::previews_mutex;
std::mutex db::thumbnails_mutex;
std::mutex db::policy_mutex;
std::mutex db::quarantine_room_mutex;
std::mutex db::cleanup_log_mutex;
std::mutex db::media_access_log_mutex;

std::unordered_map<std::string, db::MediaRecord> db::media;
std::unordered_map<std::string, std::vector<std::string>> db::room_media;
std::unordered_map<std::string, std::vector<std::string>> db::user_media;
std::unordered_map<std::string, db::UrlPreviewRecord> db::url_previews;
std::unordered_map<std::string, db::ThumbnailRecord> db::thumbnails;
std::unordered_map<std::string, std::vector<std::string>> db::media_thumbnails;
std::unordered_map<std::string, db::MediaRetentionPolicy> db::retention_policies;
std::unordered_map<std::string, db::QuarantineRoomEntry> db::quarantine_rooms;
std::vector<db::CleanupLogEntry> db::cleanup_log;
std::vector<db::MediaAccessLog> db::media_access_log;

// ============================================================================
// Utility helpers (anonymous namespace — local to this module)
// ============================================================================

namespace {

// ---------------------------------------------------------------------------
// Timestamp helpers
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Random generation
// ---------------------------------------------------------------------------

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

std::string generate_media_id() {
    return random_hex(32);
}

std::string generate_log_id() {
    return "cleanup_" + random_alphanumeric(12);
}

// ---------------------------------------------------------------------------
// SHA-256 hash (simplified placeholder)
// ---------------------------------------------------------------------------

std::string sha256(const std::string& input) {
    std::hash<std::string> hasher;
    size_t h = hasher(input);
    std::stringstream ss;
    ss << std::hex << h;
    std::string hex = ss.str();
    while (hex.size() < 64) hex = "0" + hex;
    return hex.substr(0, 64);
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

bool is_valid_user_id(const std::string& uid) {
    static std::regex re(R"(^@[a-zA-Z0-9._=\-]+:.+$)");
    return std::regex_match(uid, re);
}

bool is_valid_room_id(const std::string& rid) {
    static std::regex re(R"(^![a-zA-Z0-9]+:.+$)");
    return std::regex_match(rid, re);
}

bool is_valid_media_id(const std::string& mid) {
    static std::regex re(R"(^[a-fA-F0-9]{24,64}$)");
    return std::regex_match(mid, re);
}

bool is_valid_origin(const std::string& origin) {
    if (origin.empty()) return false;
    if (origin.size() > 512) return false;
    // Basic alphanumeric + dots + hyphens + colons (for port)
    static std::regex re(R"(^[a-zA-Z0-9][a-zA-Z0-9.\-]*(:[0-9]+)?$)");
    return std::regex_match(origin, re);
}

// ---------------------------------------------------------------------------
// String helpers
// ---------------------------------------------------------------------------

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

std::string extract_server_name(const std::string& mxid) {
    auto pos = mxid.find(':');
    if (pos != std::string::npos) return mxid.substr(pos + 1);
    return "localhost";
}

// ---------------------------------------------------------------------------
// URL decode
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Human-readable byte sizes
// ---------------------------------------------------------------------------

std::string format_bytes(int64_t bytes) {
    const char* units[] = {"B", "KB", "MB", "GB", "TB", "PB"};
    int unit_idx = 0;
    double size = static_cast<double>(bytes);
    while (size >= 1024.0 && unit_idx < 5) {
        size /= 1024.0;
        unit_idx++;
    }
    std::stringstream ss;
    ss << std::fixed << std::setprecision(2) << size << " " << units[unit_idx];
    return ss.str();
}

std::string format_duration_ms(int64_t ms) {
    if (ms < 1000) return std::to_string(ms) + "ms";
    double seconds = ms / 1000.0;
    if (seconds < 60) {
        std::stringstream ss;
        ss << std::fixed << std::setprecision(2) << seconds << "s";
        return ss.str();
    }
    int minutes = static_cast<int>(seconds / 60);
    int rem_seconds = static_cast<int>(seconds) % 60;
    if (minutes < 60) {
        return std::to_string(minutes) + "m " + std::to_string(rem_seconds) + "s";
    }
    int hours = minutes / 60;
    int rem_minutes = minutes % 60;
    return std::to_string(hours) + "h " + std::to_string(rem_minutes) + "m " +
           std::to_string(rem_seconds) + "s";
}

// ---------------------------------------------------------------------------
// JSON helpers
// ---------------------------------------------------------------------------

json error_response(const std::string& errcode,
                     const std::string& error,
                     int http_status = 400) {
    return {
        {"errcode", errcode},
        {"error", error},
        {"http_status", http_status}
    };
}

json parse_json(const std::string& body) {
    if (body.empty()) return json::object();
    return json::parse(body);
}

std::string safe_get_string(const json& obj, const std::string& key,
                             const std::string& default_val = "") {
    if (!obj.contains(key)) return default_val;
    const auto& val = obj[key];
    if (val.is_string()) return val.get<std::string>();
    if (val.is_number()) return std::to_string(val.get<int64_t>());
    return default_val;
}

int64_t safe_get_int64(const json& obj, const std::string& key,
                          int64_t default_val = 0) {
    if (!obj.contains(key)) return default_val;
    const auto& val = obj[key];
    if (val.is_number_integer()) return val.get<int64_t>();
    if (val.is_string()) {
        try { return std::stoll(val.get<std::string>()); }
        catch (...) { return default_val; }
    }
    return default_val;
}

bool safe_get_bool(const json& obj, const std::string& key,
                    bool default_val = false) {
    if (!obj.contains(key)) return default_val;
    const auto& val = obj[key];
    if (val.is_boolean()) return val.get<bool>();
    if (val.is_string()) {
        std::string s = to_lower(val.get<std::string>());
        return s == "true" || s == "1" || s == "yes";
    }
    if (val.is_number()) return val.get<int>() != 0;
    return default_val;
}

// Build JSON for a media record
json media_to_json(const db::MediaRecord& rec) {
    json j;
    j["media_id"] = rec.media_id;
    j["origin"] = rec.origin;
    j["media_type"] = rec.media_type;
    j["upload_name"] = rec.upload_name;
    j["user_id"] = rec.user_id;
    j["room_id"] = rec.room_id;
    j["created_ts"] = std::stoll(rec.created_ts);
    j["last_access_ts"] = std::stoll(rec.last_access_ts);
    j["media_length"] = rec.media_length;
    j["access_count"] = rec.access_count;
    j["quarantined"] = rec.quarantined;
    j["quarantined_by"] = rec.quarantined_by;
    j["quarantined_ts"] = rec.quarantined_ts.empty() ? json() :
        json(std::stoll(rec.quarantined_ts));
    j["quarantine_reason"] = rec.quarantine_reason;
    j["safe_from_quarantine"] = rec.safe_from_quarantine;
    j["is_remote"] = rec.is_remote;
    j["remote_server"] = rec.remote_server;
    j["soft_deleted"] = rec.soft_deleted;
    j["hard_deleted"] = rec.hard_deleted;
    j["deleted_by"] = rec.deleted_by;
    j["deleted_ts"] = rec.deleted_ts.empty() ? json() :
        json(std::stoll(rec.deleted_ts));
    j["content_disposition"] = rec.content_disposition;
    j["created_iso"] = rec.created_ts.empty() ?
        json() : json(iso8601_from_epoch(std::stoll(rec.created_ts)));
    j["last_access_iso"] = rec.last_access_ts.empty() ?
        json() : json(iso8601_from_epoch(std::stoll(rec.last_access_ts)));
    j["size_formatted"] = format_bytes(rec.media_length);
    if (rec.width > 0) j["width"] = rec.width;
    if (rec.height > 0) j["height"] = rec.height;
    if (rec.duration_ms > 0) j["duration_ms"] = rec.duration_ms;
    if (!rec.file_hash_sha256.empty()) j["sha256"] = rec.file_hash_sha256;
    if (!rec.blurhash.empty()) j["blurhash"] = rec.blurhash;
    if (!rec.etag.empty()) j["etag"] = rec.etag;
    if (rec.thumbnail_count > 0) j["thumbnail_count"] = rec.thumbnail_count;
    if (rec.has_preview) j["has_preview"] = true;
    return j;
}

// Build a paginated response envelope
json paginated_response(const std::string& items_key,
                         const json& items,
                         int total, int from, int limit) {
    json resp;
    resp[items_key] = items;
    resp["total"] = total;
    if (from + limit < total) {
        resp["next_token"] = std::to_string(from + limit);
    }
    resp["from"] = from;
    resp["limit"] = limit;
    return resp;
}

// Extract media parameters from path like /_synapse/admin/v1/media/{origin}/{media_id}/...
struct MediaPathParts {
    std::string origin;
    std::string media_id;
    std::string action;      // "quarantine", "unquarantine", "delete", etc.
    bool valid = false;
};

MediaPathParts parse_media_path(const std::string& path) {
    MediaPathParts parts;
    // Expected prefix: /_synapse/admin/v1/media/
    const std::string prefix = "/_synapse/admin/v1/media/";
    if (!starts_with(path, prefix)) return parts;

    std::string rest = path.substr(prefix.size());

    // Check if it matches a non-media endpoint first
    if (rest == "statistics" || rest == "cleanup" ||
        rest == "retention_policy" || rest == "url_previews" ||
        rest == "thumbnails" || rest == "purge_remote" ||
        rest == "top_media" || rest == "recently_accessed" ||
        rest == "bulk_quarantine" || rest == "bulk_delete" ||
        rest == "quarantine_room" || starts_with(rest, "url_previews/") ||
        starts_with(rest, "thumbnails/")) {
        parts.valid = false; // these are handled by their own routes
        return parts;
    }

    // Parse origin/media_id[/action]
    auto first_slash = rest.find('/');
    if (first_slash == std::string::npos) {
        // Just "origin" — not valid for media listing
        return parts;
    }

    parts.origin = rest.substr(0, first_slash);
    std::string remainder = rest.substr(first_slash + 1);

    auto second_slash = remainder.find('/');
    if (second_slash == std::string::npos) {
        parts.media_id = remainder;
        parts.action = "";
    } else {
        parts.media_id = remainder.substr(0, second_slash);
        parts.action = remainder.substr(second_slash + 1);
    }

    parts.valid = !parts.origin.empty() && !parts.media_id.empty();
    return parts;
}

// Make media store key: "origin/media_id"
std::string media_key(const std::string& origin, const std::string& media_id) {
    return origin + "/" + media_id;
}

// ---------------------------------------------------------------------------
// Media type categorization
// ---------------------------------------------------------------------------

std::string categorize_media_type(const std::string& mime_type) {
    if (starts_with(mime_type, "image/")) return "image";
    if (starts_with(mime_type, "video/")) return "video";
    if (starts_with(mime_type, "audio/")) return "audio";
    if (starts_with(mime_type, "text/")) return "text";
    if (starts_with(mime_type, "application/pdf")) return "document";
    if (starts_with(mime_type, "application/")) return "file";
    return "other";
}

// Extract file extension from upload_name or media_type
std::string file_extension(const std::string& upload_name) {
    auto pos = upload_name.rfind('.');
    if (pos != std::string::npos && pos < upload_name.size() - 1) {
        return to_lower(upload_name.substr(pos + 1));
    }
    return "";
}

// ---------------------------------------------------------------------------
// Compute estimated storage savings from a cleanup operation
// ---------------------------------------------------------------------------

int64_t compute_bytes_freed(const std::vector<std::string>& deleted_media_keys) {
    std::lock_guard<std::mutex> lock(db::media_mutex);
    int64_t total = 0;
    for (const auto& key : deleted_media_keys) {
        auto it = db::media.find(key);
        if (it != db::media.end()) {
            total += it->second.media_length;
            // Also count thumbnail sizes
            auto thumb_it = db::media_thumbnails.find(key);
            if (thumb_it != db::media_thumbnails.end()) {
                std::lock_guard<std::mutex> tlock(db::thumbnails_mutex);
                for (const auto& tid : thumb_it->second) {
                    auto tit = db::thumbnails.find(tid);
                    if (tit != db::thumbnails.end()) {
                        total += tit->second.file_size;
                    }
                }
            }
        }
    }
    return total;
}

// Check if a media record matches a retention policy
bool media_matches_policy(const db::MediaRecord& rec,
                           const db::MediaRetentionPolicy& policy,
                           int64_t now_epoch_ms) {
    if (!policy.enabled) return false;
    if (rec.hard_deleted) return false;
    if (rec.safe_from_quarantine) return false;
    if (!policy.delete_quarantined && rec.quarantined) return false;

    // Check applies_to targeting
    if (policy.applies_to == "room") {
        if (rec.room_id != policy.target) return false;
    } else if (policy.applies_to == "user") {
        if (rec.user_id != policy.target) return false;
    } else if (policy.applies_to == "mime_type") {
        if (!matches_filter(rec.media_type, policy.target)) return false;
    }
    // "all" applies to everything

    // Check max lifetime
    if (policy.max_lifetime_ms > 0 && !rec.created_ts.empty()) {
        int64_t age_ms = now_epoch_ms - std::stoll(rec.created_ts);
        if (age_ms < policy.max_lifetime_ms) return false;
    }

    // Check max idle (time since last access)
    if (policy.max_idle_ms > 0 && !rec.last_access_ts.empty()) {
        int64_t idle_ms = now_epoch_ms - std::stoll(rec.last_access_ts);
        if (idle_ms < policy.max_idle_ms) return false;
    } else if (policy.max_idle_ms > 0 && rec.last_access_ts.empty()) {
        // Never accessed, check against created time
        if (!rec.created_ts.empty()) {
            int64_t idle_ms = now_epoch_ms - std::stoll(rec.created_ts);
            if (idle_ms < policy.max_idle_ms) return false;
        }
    }

    // Check max size
    if (policy.max_size_bytes > 0 && rec.media_length > policy.max_size_bytes) {
        return true; // oversized media matches policy
    }

    // If it passed lifetime/idle checks, or no checks specified,
    // and no size constraint, it matches
    if (policy.max_lifetime_ms > 0 || policy.max_idle_ms > 0) return true;
    if (policy.max_size_bytes > 0 && rec.media_length > policy.max_size_bytes) return true;

    // If no criteria specified, don't match anything (safety)
    return false;
}

} // anonymous namespace

// ============================================================================
// Admin Handlers — Media Management Functions
// ============================================================================

// ---------------------------------------------------------------------------
// 1. GET /_synapse/admin/v1/media — List Media
// ---------------------------------------------------------------------------

json admin_list_media(const json& params, const json& body,
                       const std::string& request_path) {
    std::lock_guard<std::mutex> lock(db::media_mutex);

    // Parse pagination
    int from = 0;
    int limit = 100;
    if (params.contains("from")) {
        if (params["from"].is_string())
            from = std::stoi(params["from"].get<std::string>());
        else if (params["from"].is_number())
            from = params["from"].get<int>();
    }
    if (params.contains("limit")) {
        if (params["limit"].is_string())
            limit = std::min(std::stoi(params["limit"].get<std::string>()), 500);
        else if (params["limit"].is_number())
            limit = std::min(params["limit"].get<int>(), 500);
    }

    // Parse ordering
    std::string order_by = "created_ts";
    if (params.contains("order_by")) order_by = params["order_by"].get<std::string>();
    std::string dir = "b"; // b=descending (newest first), f=ascending
    if (params.contains("dir")) dir = params["dir"].get<std::string>();

    // Parse filters
    std::string room_id_filter;
    std::string user_id_filter;
    std::string kind_filter;       // "local", "remote", "quarantined"
    std::string origin_filter;
    std::string media_type_filter;
    std::string search_filter;     // searches upload_name and media_id
    bool include_quarantined = true;
    bool include_deleted = false;
    bool only_quarantined = false;
    int64_t before_ts = 0;
    int64_t after_ts = 0;
    int64_t min_size = 0;
    int64_t max_size = INT64_MAX;

    if (params.contains("room_id")) room_id_filter = params["room_id"].get<std::string>();
    if (params.contains("user_id")) user_id_filter = params["user_id"].get<std::string>();
    if (params.contains("origin")) origin_filter = params["origin"].get<std::string>();
    if (params.contains("media_type")) media_type_filter = params["media_type"].get<std::string>();
    if (params.contains("search")) search_filter = params["search"].get<std::string>();
    if (params.contains("kind")) kind_filter = params["kind"].get<std::string>();
    if (params.contains("before_ts")) {
        if (params["before_ts"].is_string())
            before_ts = std::stoll(params["before_ts"].get<std::string>());
        else before_ts = params["before_ts"].get<int64_t>();
    }
    if (params.contains("after_ts")) {
        if (params["after_ts"].is_string())
            after_ts = std::stoll(params["after_ts"].get<std::string>());
        else after_ts = params["after_ts"].get<int64_t>();
    }
    if (params.contains("min_size")) {
        if (params["min_size"].is_string())
            min_size = std::stoll(params["min_size"].get<std::string>());
        else min_size = params["min_size"].get<int64_t>();
    }
    if (params.contains("max_size")) {
        if (params["max_size"].is_string())
            max_size = std::stoll(params["max_size"].get<std::string>());
        else max_size = params["max_size"].get<int64_t>();
    }

    include_quarantined = safe_get_bool(params, "include_quarantined", true);
    include_deleted = safe_get_bool(params, "include_deleted", false);
    only_quarantined = safe_get_bool(params, "only_quarantined", false);

    // Determine kind filter
    bool local_only = (kind_filter == "local");
    bool remote_only = (kind_filter == "remote");

    // Collect all matching media
    std::vector<std::pair<std::string, const db::MediaRecord*>> matched;

    for (const auto& [key, rec] : db::media) {
        if (rec.hard_deleted && !include_deleted) continue;
        if (rec.soft_deleted && !include_deleted) continue;
        if (rec.quarantined && !include_quarantined && !only_quarantined) continue;
        if (!rec.quarantined && only_quarantined) continue;
        if (local_only && rec.is_remote) continue;
        if (remote_only && !rec.is_remote) continue;
        if (!room_id_filter.empty() && rec.room_id != room_id_filter) continue;
        if (!user_id_filter.empty() && rec.user_id != user_id_filter) continue;
        if (!origin_filter.empty() && rec.origin != origin_filter) continue;
        if (!media_type_filter.empty() &&
            !matches_filter(rec.media_type, media_type_filter)) continue;
        if (!search_filter.empty() &&
            !matches_filter(rec.upload_name, search_filter) &&
            !matches_filter(rec.media_id, search_filter)) continue;
        if (before_ts > 0 && !rec.created_ts.empty() &&
            std::stoll(rec.created_ts) >= before_ts) continue;
        if (after_ts > 0 && !rec.created_ts.empty() &&
            std::stoll(rec.created_ts) <= after_ts) continue;
        if (min_size > 0 && rec.media_length < min_size) continue;
        if (max_size < INT64_MAX && rec.media_length > max_size) continue;

        matched.emplace_back(key, &rec);
    }

    // Sort
    if (order_by == "media_length" || order_by == "size") {
        std::sort(matched.begin(), matched.end(),
            [&](const auto& a, const auto& b) {
                if (dir == "f")
                    return a.second->media_length < b.second->media_length;
                return a.second->media_length > b.second->media_length;
            });
    } else if (order_by == "access_count") {
        std::sort(matched.begin(), matched.end(),
            [&](const auto& a, const auto& b) {
                if (dir == "f")
                    return a.second->access_count < b.second->access_count;
                return a.second->access_count > b.second->access_count;
            });
    } else if (order_by == "last_access_ts") {
        std::sort(matched.begin(), matched.end(),
            [&](const auto& a, const auto& b) {
                int64_t la = a.second->last_access_ts.empty() ? 0 :
                    std::stoll(a.second->last_access_ts);
                int64_t lb = b.second->last_access_ts.empty() ? 0 :
                    std::stoll(b.second->last_access_ts);
                if (dir == "f") return la < lb;
                return la > lb;
            });
    } else if (order_by == "upload_name" || order_by == "name") {
        std::sort(matched.begin(), matched.end(),
            [&](const auto& a, const auto& b) {
                if (dir == "f")
                    return a.second->upload_name < b.second->upload_name;
                return a.second->upload_name > b.second->upload_name;
            });
    } else {
        // Default: order by created_ts
        std::sort(matched.begin(), matched.end(),
            [&](const auto& a, const auto& b) {
                int64_t ca = a.second->created_ts.empty() ? 0 :
                    std::stoll(a.second->created_ts);
                int64_t cb = b.second->created_ts.empty() ? 0 :
                    std::stoll(b.second->created_ts);
                if (dir == "f") return ca < cb;
                return ca > cb;
            });
    }

    int total = static_cast<int>(matched.size());

    // Paginate
    json media_arr = json::array();
    for (int i = from; i < std::min(from + limit, total); ++i) {
        media_arr.push_back(media_to_json(*matched[i].second));
    }

    json resp = paginated_response("media", media_arr, total, from, limit);

    // Add quick summary stats for the result set
    int64_t total_bytes = 0;
    int quarantined_count = 0, remote_count = 0, local_count = 0;
    int soft_deleted_count = 0;
    for (const auto& [k, rec] : matched) {
        total_bytes += rec->media_length;
        if (rec->quarantined) quarantined_count++;
        if (rec->is_remote) remote_count++; else local_count++;
        if (rec->soft_deleted) soft_deleted_count++;
    }

    resp["summary"] = {
        {"total_matched", total},
        {"total_bytes", total_bytes},
        {"total_formatted", format_bytes(total_bytes)},
        {"quarantined_count", quarantined_count},
        {"remote_count", remote_count},
        {"local_count", local_count},
        {"soft_deleted_count", soft_deleted_count}
    };

    return resp;
}

// ---------------------------------------------------------------------------
// 2. GET /_synapse/admin/v1/media/{origin}/{media_id} — Media Details
// ---------------------------------------------------------------------------

json admin_media_details(const json& params, const json& body,
                          const std::string& request_path) {
    auto parts = parse_media_path(request_path);
    if (!parts.valid) {
        return error_response("M_INVALID_PARAM",
            "Invalid media path. Expected /_synapse/admin/v1/media/{origin}/{media_id}");
    }

    std::string key = media_key(parts.origin, parts.media_id);

    std::lock_guard<std::mutex> lock(db::media_mutex);

    auto it = db::media.find(key);
    if (it == db::media.end()) {
        return error_response("M_NOT_FOUND",
            "Media not found: " + key, 404);
    }

    json resp = media_to_json(it->second);

    // Enrich with thumbnail info
    {
        std::lock_guard<std::mutex> tlock(db::thumbnails_mutex);
        auto thumb_it = db::media_thumbnails.find(key);
        if (thumb_it != db::media_thumbnails.end()) {
            json thumb_arr = json::array();
            for (const auto& tid : thumb_it->second) {
                auto tit = db::thumbnails.find(tid);
                if (tit != db::thumbnails.end()) {
                    json tj;
                    tj["thumbnail_id"] = tit->second.thumbnail_id;
                    tj["method"] = tit->second.method;
                    tj["width"] = tit->second.width;
                    tj["height"] = tit->second.height;
                    tj["file_size"] = tit->second.file_size;
                    tj["content_type"] = tit->second.content_type;
                    tj["created_ts"] = std::stoll(tit->second.created_ts);
                    tj["access_count"] = tit->second.access_count;
                    thumb_arr.push_back(tj);
                }
            }
            resp["thumbnails"] = thumb_arr;
        }
    }

    // Enrich with recent access log entries
    {
        std::lock_guard<std::mutex> alock(db::media_access_log_mutex);
        json access_arr = json::array();
        int access_count = 0;
        for (auto it2 = db::media_access_log.rbegin();
             it2 != db::media_access_log.rend() && access_count < 20; ++it2) {
            if (it2->media_id == parts.media_id && it2->origin == parts.origin) {
                json aj;
                aj["user_id"] = it2->user_id;
                aj["access_ts"] = std::stoll(it2->access_ts);
                aj["ip_address"] = it2->ip_address;
                aj["room_id"] = it2->room_id;
                aj["bytes_transferred"] = it2->bytes_transferred;
                aj["http_status"] = it2->http_status;
                access_arr.push_back(aj);
                access_count++;
            }
        }
        resp["recent_accesses"] = access_arr;
    }

    // Compute age
    if (!it->second.created_ts.empty()) {
        int64_t age_ms = std::stoll(now_ms()) - std::stoll(it->second.created_ts);
        resp["age"] = format_duration_ms(age_ms);
        resp["age_ms"] = age_ms;
    }

    return resp;
}

// ---------------------------------------------------------------------------
// 3. POST /_synapse/admin/v1/media/{origin}/{media_id}/quarantine
// ---------------------------------------------------------------------------

json admin_quarantine_media(const json& params, const json& body,
                              const std::string& request_path) {
    auto parts = parse_media_path(request_path);
    if (!parts.valid) {
        return error_response("M_INVALID_PARAM",
            "Invalid media path for quarantine");
    }

    std::string key = media_key(parts.origin, parts.media_id);
    std::string reason = safe_get_string(body, "reason", "Quarantined by admin");

    std::lock_guard<std::mutex> lock(db::media_mutex);

    auto it = db::media.find(key);
    if (it == db::media.end()) {
        return error_response("M_NOT_FOUND",
            "Media not found: " + key, 404);
    }

    if (it->second.safe_from_quarantine) {
        return error_response("M_FORBIDDEN",
            "This media is protected from quarantine", 403);
    }

    if (it->second.quarantined) {
        return error_response("M_UNKNOWN",
            "Media is already quarantined: " + key);
    }

    it->second.quarantined = true;
    it->second.quarantined_by = safe_get_string(body, "quarantined_by",
        body.contains("admin_user") ? body["admin_user"].get<std::string>() : "admin");
    it->second.quarantined_ts = now_ms();
    it->second.quarantine_reason = reason;

    json resp;
    resp["media_id"] = parts.media_id;
    resp["origin"] = parts.origin;
    resp["quarantined"] = true;
    resp["quarantined_by"] = it->second.quarantined_by;
    resp["quarantined_ts"] = std::stoll(it->second.quarantined_ts);
    resp["reason"] = reason;
    resp["status"] = "success";
    resp["message"] = "Media successfully quarantined";

    return resp;
}

// ---------------------------------------------------------------------------
// 4. POST /_synapse/admin/v1/media/{origin}/{media_id}/unquarantine
// ---------------------------------------------------------------------------

json admin_unquarantine_media(const json& params, const json& body,
                                const std::string& request_path) {
    auto parts = parse_media_path(request_path);
    if (!parts.valid) {
        return error_response("M_INVALID_PARAM",
            "Invalid media path for unquarantine");
    }

    std::string key = media_key(parts.origin, parts.media_id);

    std::lock_guard<std::mutex> lock(db::media_mutex);

    auto it = db::media.find(key);
    if (it == db::media.end()) {
        return error_response("M_NOT_FOUND",
            "Media not found: " + key, 404);
    }

    if (!it->second.quarantined) {
        return error_response("M_UNKNOWN",
            "Media is not quarantined: " + key);
    }

    it->second.quarantined = false;
    it->second.quarantined_by = "";
    it->second.quarantined_ts = "";
    it->second.quarantine_reason = "";

    json resp;
    resp["media_id"] = parts.media_id;
    resp["origin"] = parts.origin;
    resp["quarantined"] = false;
    resp["status"] = "success";
    resp["message"] = "Media successfully unquarantined";

    return resp;
}

// ---------------------------------------------------------------------------
// 5. POST /_synapse/admin/v1/media/{origin}/{media_id}/soft_delete
// ---------------------------------------------------------------------------

json admin_soft_delete_media(const json& params, const json& body,
                               const std::string& request_path) {
    auto parts = parse_media_path(request_path);
    if (!parts.valid) {
        return error_response("M_INVALID_PARAM",
            "Invalid media path for soft delete");
    }

    std::string key = media_key(parts.origin, parts.media_id);

    std::lock_guard<std::mutex> lock(db::media_mutex);

    auto it = db::media.find(key);
    if (it == db::media.end()) {
        return error_response("M_NOT_FOUND",
            "Media not found: " + key, 404);
    }

    if (it->second.hard_deleted) {
        return error_response("M_UNKNOWN",
            "Media is already hard-deleted: " + key);
    }

    if (it->second.soft_deleted) {
        return error_response("M_UNKNOWN",
            "Media is already soft-deleted: " + key);
    }

    it->second.soft_deleted = true;
    it->second.deleted_by = safe_get_string(body, "deleted_by",
        body.contains("admin_user") ? body["admin_user"].get<std::string>() : "admin");
    it->second.deleted_ts = now_ms();

    json resp;
    resp["media_id"] = parts.media_id;
    resp["origin"] = parts.origin;
    resp["soft_deleted"] = true;
    resp["deleted_by"] = it->second.deleted_by;
    resp["deleted_ts"] = std::stoll(it->second.deleted_ts);
    resp["status"] = "success";
    resp["message"] = "Media soft-deleted. It can be recovered if needed.";
    resp["recoverable"] = true;

    return resp;
}

// ---------------------------------------------------------------------------
// 6. DELETE /_synapse/admin/v1/media/{origin}/{media_id}/delete
// Hard delete (permanent removal)
// ---------------------------------------------------------------------------

json admin_hard_delete_media(const json& params, const json& body,
                               const std::string& request_path) {
    auto parts = parse_media_path(request_path);
    if (!parts.valid) {
        return error_response("M_INVALID_PARAM",
            "Invalid media path for hard delete");
    }

    std::string key = media_key(parts.origin, parts.media_id);

    std::lock_guard<std::mutex> lock(db::media_mutex);

    auto it = db::media.find(key);
    if (it == db::media.end()) {
        return error_response("M_NOT_FOUND",
            "Media not found: " + key, 404);
    }

    if (it->second.hard_deleted) {
        return error_response("M_UNKNOWN",
            "Media is already hard-deleted: " + key);
    }

    bool delete_thumbnails_flag = safe_get_bool(body, "delete_thumbnails", true);

    // Record what we're deleting for the response
    std::string media_id = it->second.media_id;
    std::string origin = it->second.origin;
    int64_t bytes_freed = it->second.media_length;
    int64_t access_count = it->second.access_count;
    std::string upload_name = it->second.upload_name;

    // Delete associated thumbnails
    int thumbnails_deleted = 0;
    int64_t thumb_bytes_freed = 0;
    if (delete_thumbnails_flag) {
        std::lock_guard<std::mutex> tlock(db::thumbnails_mutex);
        auto thumb_it = db::media_thumbnails.find(key);
        if (thumb_it != db::media_thumbnails.end()) {
            for (const auto& tid : thumb_it->second) {
                auto tit = db::thumbnails.find(tid);
                if (tit != db::thumbnails.end()) {
                    thumb_bytes_freed += tit->second.file_size;
                    db::thumbnails.erase(tit);
                    thumbnails_deleted++;
                }
            }
            db::media_thumbnails.erase(thumb_it);
        }
    }

    // Remove from room and user indexes
    if (!it->second.room_id.empty()) {
        auto room_it = db::room_media.find(it->second.room_id);
        if (room_it != db::room_media.end()) {
            room_it->second.erase(
                std::remove(room_it->second.begin(), room_it->second.end(), key),
                room_it->second.end());
        }
    }
    if (!it->second.user_id.empty()) {
        auto user_it = db::user_media.find(it->second.user_id);
        if (user_it != db::user_media.end()) {
            user_it->second.erase(
                std::remove(user_it->second.begin(), user_it->second.end(), key),
                user_it->second.end());
        }
    }

    // Erase the media record
    db::media.erase(it);

    json resp;
    resp["media_id"] = media_id;
    resp["origin"] = origin;
    resp["hard_deleted"] = true;
    resp["deleted_by"] = safe_get_string(body, "deleted_by",
        body.contains("admin_user") ? body["admin_user"].get<std::string>() : "admin");
    resp["deleted_ts"] = std::stoll(now_ms());
    resp["upload_name"] = upload_name;
    resp["bytes_freed"] = bytes_freed;
    resp["bytes_freed_formatted"] = format_bytes(bytes_freed);
    resp["access_count"] = access_count;
    resp["thumbnails_deleted"] = thumbnails_deleted;
    resp["thumbnail_bytes_freed"] = thumb_bytes_freed;
    resp["total_bytes_freed"] = bytes_freed + thumb_bytes_freed;
    resp["total_freed_formatted"] = format_bytes(bytes_freed + thumb_bytes_freed);
    resp["status"] = "success";
    resp["message"] = "Media permanently deleted. This cannot be undone.";
    resp["recoverable"] = false;

    return resp;
}

// ---------------------------------------------------------------------------
// 7. DELETE /_synapse/admin/v1/media/{origin}/{media_id} — Unconditional hard delete
// (Synapse-compatible: DELETE with optional ?delete_thumbnails=bool)
// ---------------------------------------------------------------------------

json admin_delete_media(const json& params, const json& body,
                         const std::string& request_path) {
    return admin_hard_delete_media(params, body, request_path);
}

// ---------------------------------------------------------------------------
// 8. POST /_synapse/admin/v1/media/purge_remote — Purge Remote Media
// ---------------------------------------------------------------------------

json admin_purge_remote_media(const json& params, const json& body,
                                const std::string& request_path) {
    std::string before_ts_str = safe_get_string(body, "before_ts", "");
    int64_t before_ts = 0;
    if (!before_ts_str.empty()) {
        before_ts = std::stoll(before_ts_str);
    } else if (body.contains("before_ts") && body["before_ts"].is_number()) {
        before_ts = body["before_ts"].get<int64_t>();
    } else {
        // Default: purge remote media older than 90 days
        before_ts = std::stoll(now_ms()) - (90LL * 24 * 3600 * 1000);
    }

    int64_t min_age_ms = safe_get_int64(body, "min_age_ms",
        30LL * 24 * 3600 * 1000); // 30 days default

    std::string specific_server = safe_get_string(body, "remote_server", "");
    bool dry_run = safe_get_bool(body, "dry_run", false);
    int batch_size = static_cast<int>(safe_get_int64(body, "batch_size", 1000));
    if (batch_size < 1) batch_size = 1;
    if (batch_size > 10000) batch_size = 10000;

    std::lock_guard<std::mutex> lock(db::media_mutex);

    int scanned = 0, deleted = 0, errors = 0;
    int64_t bytes_freed = 0;
    json deleted_list = json::array();
    json error_list = json::array();

    std::vector<std::string> to_delete;

    for (const auto& [key, rec] : db::media) {
        if (!rec.is_remote) continue;
        if (rec.hard_deleted) continue;
        if (rec.safe_from_quarantine) continue;

        if (!specific_server.empty() && rec.remote_server != specific_server) continue;

        // Check age
        if (rec.created_ts.empty()) continue;
        int64_t created = std::stoll(rec.created_ts);
        if (created > before_ts) continue;

        int64_t age_ms = std::stoll(now_ms()) - created;
        if (age_ms < min_age_ms) continue;

        to_delete.push_back(key);
        if (static_cast<int>(to_delete.size()) >= batch_size) break;
    }

    if (!dry_run) {
        for (const auto& key : to_delete) {
            auto it = db::media.find(key);
            if (it == db::media.end()) continue;

            int64_t freed = it->second.media_length;
            bytes_freed += freed;
            deleted_list.push_back({
                {"media_id", it->second.media_id},
                {"origin", it->second.origin},
                {"remote_server", it->second.remote_server},
                {"upload_name", it->second.upload_name},
                {"bytes_freed", freed},
                {"created_ts", std::stoll(it->second.created_ts)}
            });

            // Delete thumbnails
            {
                std::lock_guard<std::mutex> tlock(db::thumbnails_mutex);
                auto thumb_it = db::media_thumbnails.find(key);
                if (thumb_it != db::media_thumbnails.end()) {
                    for (const auto& tid : thumb_it->second) {
                        auto tit = db::thumbnails.find(tid);
                        if (tit != db::thumbnails.end()) {
                            db::thumbnails.erase(tit);
                        }
                    }
                    db::media_thumbnails.erase(thumb_it);
                }
            }

            // Clean indexes
            if (!it->second.room_id.empty()) {
                auto ri = db::room_media.find(it->second.room_id);
                if (ri != db::room_media.end()) {
                    ri->second.erase(
                        std::remove(ri->second.begin(), ri->second.end(), key),
                        ri->second.end());
                }
            }
            if (!it->second.user_id.empty()) {
                auto ui = db::user_media.find(it->second.user_id);
                if (ui != db::user_media.end()) {
                    ui->second.erase(
                        std::remove(ui->second.begin(), ui->second.end(), key),
                        ui->second.end());
                }
            }

            db::media.erase(it);
            deleted++;
        }
    } else {
        // Dry run — just report counts
        for (const auto& key : to_delete) {
            auto it = db::media.find(key);
            if (it != db::media.end()) {
                bytes_freed += it->second.media_length;
                deleted_list.push_back({
                    {"media_id", it->second.media_id},
                    {"origin", it->second.origin},
                    {"remote_server", it->second.remote_server},
                    {"upload_name", it->second.upload_name},
                    {"bytes", it->second.media_length},
                    {"would_be_deleted", true}
                });
            }
        }
        deleted = static_cast<int>(to_delete.size());
    }

    json resp;
    resp["before_ts"] = before_ts;
    resp["before_iso"] = iso8601_from_epoch(before_ts);
    resp["min_age_ms"] = min_age_ms;
    resp["min_age_formatted"] = format_duration_ms(min_age_ms);
    resp["dry_run"] = dry_run;
    resp["remote_media_scanned"] = scanned;
    resp["remote_media_deleted"] = dry_run ? 0 : deleted;
    resp["would_delete"] = dry_run ? deleted : 0;
    resp["bytes_freed"] = bytes_freed;
    resp["bytes_freed_formatted"] = format_bytes(bytes_freed);
    resp["deleted_media"] = deleted_list;
    resp["errors"] = error_list;
    resp["status"] = "success";
    resp["message"] = dry_run ?
        "Dry run complete. Set dry_run=false to execute purge." :
        "Remote media purge complete.";

    return resp;
}

// ---------------------------------------------------------------------------
// 9. GET /_synapse/admin/v1/media/statistics — Media Statistics
// ---------------------------------------------------------------------------

json admin_media_statistics(const json& params, const json& body,
                              const std::string& request_path) {
    std::lock_guard<std::mutex> lock(db::media_mutex);

    int64_t total_bytes = 0;
    int total_count = 0;
    int local_count = 0, remote_count = 0;
    int quarantined_count = 0;
    int soft_deleted_count = 0;
    int with_preview = 0;

    // Per-type statistics
    std::unordered_map<std::string, int> type_counts;
    std::unordered_map<std::string, int64_t> type_bytes;
    std::unordered_map<std::string, int> category_counts;
    std::unordered_map<std::string, int64_t> category_bytes;

    // Per-user statistics
    std::unordered_map<std::string, int> user_media_counts;
    std::unordered_map<std::string, int64_t> user_media_bytes;

    // Per-room statistics
    std::unordered_map<std::string, int> room_media_counts;
    std::unordered_map<std::string, int64_t> room_media_bytes;

    // Size distribution buckets
    std::vector<int64_t> size_buckets = {
        0,           // up to 1KB
        1024,        // 1KB - 10KB
        10 * 1024,   // 10KB - 100KB
        100 * 1024,  // 100KB - 1MB
        1024 * 1024, // 1MB - 10MB
        10 * 1024 * 1024, // 10MB - 100MB
        100 * 1024 * 1024, // 100MB - 1GB
        1024 * 1024 * 1024LL, // > 1GB
    };
    std::vector<int> bucket_counts(size_buckets.size(), 0);
    std::vector<int64_t> bucket_bytes(size_buckets.size(), 0);

    // Age buckets
    int64_t now_ts = std::stoll(now_ms());
    int64_t day_ms = 24LL * 3600 * 1000;
    struct AgeBucket { int64_t max_age_ms; std::string label; int count = 0; int64_t bytes = 0; };
    std::vector<AgeBucket> age_buckets = {
        {1 * day_ms, "last_24h"},
        {7 * day_ms, "last_week"},
        {30 * day_ms, "last_30_days"},
        {90 * day_ms, "last_90_days"},
        {365 * day_ms, "last_year"},
        {INT64_MAX, "older"},
    };

    int64_t smallest = INT64_MAX;
    int64_t largest = 0;
    int64_t oldest_ts = INT64_MAX;
    int64_t newest_ts = 0;
    int64_t total_accesses = 0;

    // MIME type stats
    std::unordered_map<std::string, int> mime_counts;
    std::unordered_map<std::string, int64_t> mime_bytes;

    for (const auto& [key, rec] : db::media) {
        if (rec.hard_deleted) continue;

        total_count++;
        total_bytes += rec.media_length;
        total_accesses += rec.access_count;

        if (rec.quarantined) quarantined_count++;
        if (rec.soft_deleted) soft_deleted_count++;
        if (rec.is_remote) remote_count++; else local_count++;
        if (rec.has_preview) with_preview++;

        // Per-type
        type_counts[rec.media_type]++;
        type_bytes[rec.media_type] += rec.media_length;

        // Per-category
        std::string cat = categorize_media_type(rec.media_type);
        category_counts[cat]++;
        category_bytes[cat] += rec.media_length;

        // Per MIME top-level
        mime_counts[rec.media_type]++;
        mime_bytes[rec.media_type] += rec.media_length;

        // Per-user
        if (!rec.user_id.empty()) {
            user_media_counts[rec.user_id]++;
            user_media_bytes[rec.user_id] += rec.media_length;
        }

        // Per-room
        if (!rec.room_id.empty()) {
            room_media_counts[rec.room_id]++;
            room_media_bytes[rec.room_id] += rec.media_length;
        }

        // Size buckets
        for (size_t bi = 0; bi < size_buckets.size(); ++bi) {
            if (rec.media_length >= size_buckets[bi]) {
                if (bi + 1 < size_buckets.size() && rec.media_length >= size_buckets[bi + 1]) {
                    continue;
                }
                bucket_counts[bi]++;
                bucket_bytes[bi] += rec.media_length;
                break;
            }
        }
        // Catch largest bucket
        if (rec.media_length >= size_buckets.back()) {
            bucket_counts.back()++;
            bucket_bytes.back() += rec.media_length;
        }

        // Age buckets
        if (!rec.created_ts.empty()) {
            int64_t age_ms = now_ts - std::stoll(rec.created_ts);
            for (auto& ab : age_buckets) {
                if (age_ms <= ab.max_age_ms) {
                    ab.count++;
                    ab.bytes += rec.media_length;
                    break;
                }
            }
        }

        // Min/max
        if (rec.media_length < smallest) smallest = rec.media_length;
        if (rec.media_length > largest) largest = rec.media_length;
        if (!rec.created_ts.empty()) {
            int64_t c = std::stoll(rec.created_ts);
            if (c < oldest_ts) oldest_ts = c;
            if (c > newest_ts) newest_ts = c;
        }
    }

    // Top users by media count
    std::vector<std::pair<std::string, int>> top_users_vec(
        user_media_counts.begin(), user_media_counts.end());
    std::sort(top_users_vec.begin(), top_users_vec.end(),
        [](const auto& a, const auto& b) { return a.second > b.second; });
    json top_users = json::array();
    for (size_t i = 0; i < std::min(top_users_vec.size(), size_t(20)); ++i) {
        top_users.push_back({
            {"user_id", top_users_vec[i].first},
            {"media_count", top_users_vec[i].second},
            {"total_bytes", user_media_bytes[top_users_vec[i].first]},
            {"total_formatted", format_bytes(user_media_bytes[top_users_vec[i].first])}
        });
    }

    // Top rooms by media count
    std::vector<std::pair<std::string, int>> top_rooms_vec(
        room_media_counts.begin(), room_media_counts.end());
    std::sort(top_rooms_vec.begin(), top_rooms_vec.end(),
        [](const auto& a, const auto& b) { return a.second > b.second; });
    json top_rooms = json::array();
    for (size_t i = 0; i < std::min(top_rooms_vec.size(), size_t(20)); ++i) {
        top_rooms.push_back({
            {"room_id", top_rooms_vec[i].first},
            {"media_count", top_rooms_vec[i].second},
            {"total_bytes", room_media_bytes[top_rooms_vec[i].first]},
            {"total_formatted", format_bytes(room_media_bytes[top_rooms_vec[i].first])}
        });
    }

    // Size distribution
    json size_dist = json::array();
    const char* bucket_labels[] = {
        "0-1KB", "1KB-10KB", "10KB-100KB", "100KB-1MB",
        "1MB-10MB", "10MB-100MB", "100MB-1GB", ">1GB"
    };
    for (size_t i = 0; i < size_buckets.size(); ++i) {
        size_dist.push_back({
            {"range", bucket_labels[i]},
            {"count", bucket_counts[i]},
            {"bytes", bucket_bytes[i]},
            {"bytes_formatted", format_bytes(bucket_bytes[i])}
        });
    }

    // Age distribution
    json age_dist = json::array();
    for (const auto& ab : age_buckets) {
        age_dist.push_back({
            {"label", ab.label},
            {"count", ab.count},
            {"bytes", ab.bytes},
            {"bytes_formatted", format_bytes(ab.bytes)}
        });
    }

    // MIME type stats (top 30)
    std::vector<std::pair<std::string, int>> mime_vec(
        mime_counts.begin(), mime_counts.end());
    std::sort(mime_vec.begin(), mime_vec.end(),
        [](const auto& a, const auto& b) { return a.second > b.second; });
    json top_mimes = json::array();
    for (size_t i = 0; i < std::min(mime_vec.size(), size_t(30)); ++i) {
        top_mimes.push_back({
            {"mime_type", mime_vec[i].first},
            {"count", mime_vec[i].second},
            {"bytes", mime_bytes[mime_vec[i].first]},
            {"bytes_formatted", format_bytes(mime_bytes[mime_vec[i].first])}
        });
    }

    json resp;
    resp["total_media"] = total_count;
    resp["total_bytes"] = total_bytes;
    resp["total_formatted"] = format_bytes(total_bytes);
    resp["local_media"] = local_count;
    resp["remote_media"] = remote_count;
    resp["quarantined_media"] = quarantined_count;
    resp["soft_deleted_media"] = soft_deleted_count;
    resp["media_with_previews"] = with_preview;
    resp["total_accesses"] = total_accesses;
    if (total_count > 0) {
        resp["average_size"] = total_bytes / total_count;
        resp["average_size_formatted"] = format_bytes(total_bytes / total_count);
        resp["average_accesses"] = total_accesses / total_count;
    }
    resp["smallest_media_bytes"] = smallest == INT64_MAX ? 0 : smallest;
    resp["largest_media_bytes"] = largest;
    resp["largest_formatted"] = format_bytes(largest);
    if (newest_ts > 0) {
        resp["newest_media_ts"] = newest_ts;
        resp["newest_media_iso"] = iso8601_from_epoch(newest_ts);
    }
    if (oldest_ts < INT64_MAX) {
        resp["oldest_media_ts"] = oldest_ts;
        resp["oldest_media_iso"] = iso8601_from_epoch(oldest_ts);
    }
    resp["size_distribution"] = size_dist;
    resp["age_distribution"] = age_dist;
    resp["top_mime_types"] = top_mimes;
    resp["top_users"] = top_users;
    resp["top_rooms"] = top_rooms;
    resp["generated_ts"] = now_ts;
    resp["generated_iso"] = iso8601_now();

    return resp;
}

// ---------------------------------------------------------------------------
// 10. POST /_synapse/admin/v1/media/cleanup — Media Cleanup (orphaned, expired)
// ---------------------------------------------------------------------------

json admin_media_cleanup(const json& params, const json& body,
                           const std::string& request_path) {
    std::string cleanup_type = safe_get_string(body, "type", "all");
    bool dry_run = safe_get_bool(body, "dry_run", false);
    int64_t before_ts = safe_get_int64(body, "before_ts", 0);
    int64_t min_age_ms = safe_get_int64(body, "min_age_ms",
        7LL * 24 * 3600 * 1000); // 7 days default
    bool delete_quarantined = safe_get_bool(body, "delete_quarantined", false);
    bool delete_remote = safe_get_bool(body, "delete_remote", true);
    int max_deletions = static_cast<int>(safe_get_int64(body, "max_deletions", 10000));

    if (before_ts == 0) {
        before_ts = std::stoll(now_ms()) - min_age_ms;
    }

    std::string log_id = generate_log_id();
    db::CleanupLogEntry log_entry;
    log_entry.log_id = log_id;
    log_entry.run_ts = now_ms();
    log_entry.triggered_by = safe_get_string(body, "admin_user", "admin");
    log_entry.reason = safe_get_string(body, "reason", "manual");

    std::lock_guard<std::mutex> lock(db::media_mutex);

    // Collect items to delete
    std::vector<std::string> to_delete_keys;
    std::vector<std::string> to_delete_thumb_only; // thumbnail-only cleanup

    for (const auto& [key, rec] : db::media) {
        if (rec.hard_deleted) continue;
        if (rec.soft_deleted && cleanup_type != "soft_deleted_only") {
            // Soft-deleted media can be fully purged
            if (cleanup_type == "soft_deleted" || cleanup_type == "all") {
                to_delete_keys.push_back(key);
                continue;
            }
        }
        if (rec.safe_from_quarantine) continue;
        if (!delete_quarantined && rec.quarantined) continue;
        if (!delete_remote && rec.is_remote) continue;
        if (static_cast<int>(to_delete_keys.size()) >= max_deletions) break;

        if (cleanup_type == "all" || cleanup_type == "orphaned") {
            // Check if media has no owner and no room
            if (rec.user_id.empty() && rec.room_id.empty() &&
                !rec.created_ts.empty()) {
                int64_t age_ms = std::stoll(now_ms()) - std::stoll(rec.created_ts);
                if (age_ms >= min_age_ms) {
                    to_delete_keys.push_back(key);
                    continue;
                }
            }
        }

        if (cleanup_type == "all" || cleanup_type == "expired") {
            // Check for expired media (not accessed for a long time)
            if (!rec.created_ts.empty()) {
                int64_t age_ms = std::stoll(now_ms()) - std::stoll(rec.created_ts);
                int64_t idle_ms = age_ms;
                if (!rec.last_access_ts.empty()) {
                    idle_ms = std::stoll(now_ms()) - std::stoll(rec.last_access_ts);
                }
                if (idle_ms >= min_age_ms) {
                    to_delete_keys.push_back(key);
                }
            }
        }

        if (cleanup_type == "all" || cleanup_type == "zero_access") {
            if (rec.access_count == 0 && !rec.created_ts.empty()) {
                int64_t age_ms = std::stoll(now_ms()) - std::stoll(rec.created_ts);
                if (age_ms >= min_age_ms) {
                    to_delete_keys.push_back(key);
                }
            }
        }
    }

    // Deduplicate
    std::sort(to_delete_keys.begin(), to_delete_keys.end());
    to_delete_keys.erase(
        std::unique(to_delete_keys.begin(), to_delete_keys.end()),
        to_delete_keys.end());

    log_entry.media_scanned = static_cast<int>(db::media.size());

    if (!dry_run) {
        int thumbnails_deleted = 0;
        for (const auto& key : to_delete_keys) {
            auto it = db::media.find(key);
            if (it == db::media.end()) continue;

            log_entry.bytes_freed += it->second.media_length;

            // Delete thumbnails
            {
                std::lock_guard<std::mutex> tlock(db::thumbnails_mutex);
                auto thumb_it = db::media_thumbnails.find(key);
                if (thumb_it != db::media_thumbnails.end()) {
                    for (const auto& tid : thumb_it->second) {
                        auto tit = db::thumbnails.find(tid);
                        if (tit != db::thumbnails.end()) {
                            log_entry.bytes_freed += tit->second.file_size;
                            db::thumbnails.erase(tit);
                            thumbnails_deleted++;
                        }
                    }
                    db::media_thumbnails.erase(thumb_it);
                }
            }

            // Clean indexes
            if (!it->second.room_id.empty()) {
                auto ri = db::room_media.find(it->second.room_id);
                if (ri != db::room_media.end()) {
                    ri->second.erase(
                        std::remove(ri->second.begin(), ri->second.end(), key),
                        ri->second.end());
                }
            }
            if (!it->second.user_id.empty()) {
                auto ui = db::user_media.find(it->second.user_id);
                if (ui != db::user_media.end()) {
                    ui->second.erase(
                        std::remove(ui->second.begin(), ui->second.end(), key),
                        ui->second.end());
                }
            }

            db::media.erase(it);
            log_entry.media_deleted++;
        }
        log_entry.thumbnails_deleted = thumbnails_deleted;
    } else {
        // Dry run — compute would-be bytes freed
        for (const auto& key : to_delete_keys) {
            auto it = db::media.find(key);
            if (it != db::media.end()) {
                log_entry.bytes_freed += it->second.media_length;
            }
        }
        log_entry.media_deleted = 0; // none actually deleted in dry run
    }

    log_entry.status = "complete";
    auto duration_start = std::chrono::system_clock::now();
    auto duration_end = std::chrono::system_clock::now();
    log_entry.duration_ms = std::to_string(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            duration_end - duration_start).count());

    {
        std::lock_guard<std::mutex> clog_lock(db::cleanup_log_mutex);
        db::cleanup_log.push_back(log_entry);
    }

    json resp;
    resp["cleanup_id"] = log_id;
    resp["type"] = cleanup_type;
    resp["dry_run"] = dry_run;
    resp["media_scanned"] = log_entry.media_scanned;
    resp["media_would_delete"] = dry_run ? static_cast<int>(to_delete_keys.size()) : 0;
    resp["media_deleted"] = dry_run ? 0 : log_entry.media_deleted;
    resp["bytes_freed"] = dry_run ? log_entry.bytes_freed : log_entry.bytes_freed;
    resp["bytes_freed_formatted"] = format_bytes(log_entry.bytes_freed);
    resp["min_age_ms"] = min_age_ms;
    resp["min_age_formatted"] = format_duration_ms(min_age_ms);
    resp["before_ts"] = before_ts;
    resp["before_iso"] = iso8601_from_epoch(before_ts);
    resp["status"] = "complete";
    resp["message"] = dry_run ?
        "Dry run complete. Set dry_run=false to execute cleanup." :
        "Media cleanup complete.";
    resp["deleted_media_keys"] = dry_run ? to_delete_keys.size() :
        log_entry.media_deleted;

    return resp;
}

// ---------------------------------------------------------------------------
// 11. GET /_synapse/admin/v1/media/retention_policy — Get Media Retention Policies
// ---------------------------------------------------------------------------

json admin_get_media_retention_policy(const json& params, const json& body,
                                        const std::string& request_path) {
    std::lock_guard<std::mutex> lock(db::policy_mutex);

    json policies_arr = json::array();

    for (const auto& [pid, policy] : db::retention_policies) {
        json pj;
        pj["policy_id"] = policy.policy_id;
        pj["name"] = policy.name;
        pj["description"] = policy.description;
        pj["enabled"] = policy.enabled;
        pj["applies_to"] = policy.applies_to;
        pj["target"] = policy.target;
        pj["max_lifetime_ms"] = policy.max_lifetime_ms;
        pj["max_lifetime_formatted"] = format_duration_ms(policy.max_lifetime_ms);
        pj["max_idle_ms"] = policy.max_idle_ms;
        pj["max_idle_formatted"] = format_duration_ms(policy.max_idle_ms);
        pj["max_size_bytes"] = policy.max_size_bytes;
        pj["max_size_formatted"] = policy.max_size_bytes > 0 ?
            format_bytes(policy.max_size_bytes) : "unlimited";
        pj["delete_remote"] = policy.delete_remote;
        pj["delete_quarantined"] = policy.delete_quarantined;
        pj["delete_thumbnails"] = policy.delete_thumbnails;
        pj["created_ts"] = policy.created_ts.empty() ? json() :
            json(std::stoll(policy.created_ts));
        pj["updated_ts"] = policy.updated_ts.empty() ? json() :
            json(std::stoll(policy.updated_ts));
        pj["media_deleted_count"] = policy.media_deleted_count;
        pj["bytes_deleted"] = policy.bytes_deleted;
        pj["bytes_deleted_formatted"] = format_bytes(policy.bytes_deleted);
        pj["last_run_ts"] = policy.last_run_ts.empty() ? json() :
            json(std::stoll(policy.last_run_ts));
        policies_arr.push_back(pj);
    }

    json resp;
    resp["policies"] = policies_arr;
    resp["total"] = static_cast<int>(policies_arr.size());
    resp["generated_ts"] = std::stoll(now_ms());

    return resp;
}

// ---------------------------------------------------------------------------
// 12. POST /_synapse/admin/v1/media/retention_policy — Set/Create/Update Policy
// ---------------------------------------------------------------------------

json admin_set_media_retention_policy(const json& params, const json& body,
                                        const std::string& request_path) {
    std::string policy_id = safe_get_string(body, "policy_id", "");
    if (policy_id.empty()) {
        policy_id = "policy_" + random_alphanumeric(8);
    }

    std::lock_guard<std::mutex> lock(db::policy_mutex);

    bool is_new = db::retention_policies.find(policy_id) ==
                  db::retention_policies.end();

    db::MediaRetentionPolicy policy;
    if (!is_new) {
        policy = db::retention_policies[policy_id];
    } else {
        policy.policy_id = policy_id;
        policy.created_ts = now_ms();
    }

    // Update fields if provided
    if (body.contains("name")) policy.name = body["name"].get<std::string>();
    if (body.contains("description")) policy.description = body["description"].get<std::string>();
    if (body.contains("enabled")) policy.enabled = safe_get_bool(body, "enabled", true);
    if (body.contains("applies_to")) policy.applies_to = body["applies_to"].get<std::string>();
    if (body.contains("target")) policy.target = body["target"].get<std::string>();
    if (body.contains("max_lifetime_ms"))
        policy.max_lifetime_ms = safe_get_int64(body, "max_lifetime_ms");
    if (body.contains("max_lifetime_days"))
        policy.max_lifetime_ms = safe_get_int64(body, "max_lifetime_days") * 24LL * 3600 * 1000;
    if (body.contains("max_idle_ms"))
        policy.max_idle_ms = safe_get_int64(body, "max_idle_ms");
    if (body.contains("max_idle_days"))
        policy.max_idle_ms = safe_get_int64(body, "max_idle_days") * 24LL * 3600 * 1000;
    if (body.contains("max_size_bytes"))
        policy.max_size_bytes = safe_get_int64(body, "max_size_bytes");
    if (body.contains("delete_remote"))
        policy.delete_remote = safe_get_bool(body, "delete_remote", true);
    if (body.contains("delete_quarantined"))
        policy.delete_quarantined = safe_get_bool(body, "delete_quarantined", false);
    if (body.contains("delete_thumbnails"))
        policy.delete_thumbnails = safe_get_bool(body, "delete_thumbnails", true);

    policy.updated_ts = now_ms();
    db::retention_policies[policy_id] = policy;

    // If requested, immediately apply the policy
    bool apply_now = safe_get_bool(body, "apply_now", false);
    json apply_report;
    if (apply_now && policy.enabled) {
        std::lock_guard<std::mutex> mlock(db::media_mutex);
        int64_t now_epoch = std::stoll(now_ms());
        int deleted = 0;
        int64_t bytes_deleted = 0;

        std::vector<std::string> to_delete;
        for (const auto& [key, rec] : db::media) {
            if (rec.hard_deleted) continue;
            if (media_matches_policy(rec, policy, now_epoch)) {
                to_delete.push_back(key);
            }
        }

        for (const auto& key : to_delete) {
            auto it = db::media.find(key);
            if (it == db::media.end()) continue;

            bytes_deleted += it->second.media_length;

            if (policy.delete_thumbnails) {
                std::lock_guard<std::mutex> tlock(db::thumbnails_mutex);
                auto thumb_it = db::media_thumbnails.find(key);
                if (thumb_it != db::media_thumbnails.end()) {
                    for (const auto& tid : thumb_it->second) {
                        auto tit = db::thumbnails.find(tid);
                        if (tit != db::thumbnails.end()) {
                            bytes_deleted += tit->second.file_size;
                            db::thumbnails.erase(tit);
                        }
                    }
                    db::media_thumbnails.erase(thumb_it);
                }
            }

            if (!it->second.room_id.empty()) {
                auto ri = db::room_media.find(it->second.room_id);
                if (ri != db::room_media.end()) {
                    ri->second.erase(
                        std::remove(ri->second.begin(), ri->second.end(), key),
                        ri->second.end());
                }
            }
            if (!it->second.user_id.empty()) {
                auto ui = db::user_media.find(it->second.user_id);
                if (ui != db::user_media.end()) {
                    ui->second.erase(
                        std::remove(ui->second.begin(), ui->second.end(), key),
                        ui->second.end());
                }
            }

            db::media.erase(it);
            deleted++;
        }

        policy.media_deleted_count += deleted;
        policy.bytes_deleted += bytes_deleted;
        policy.last_run_ts = now_ms();
        db::retention_policies[policy_id] = policy;

        apply_report = {
            {"media_scanned", static_cast<int>(db::media.size() + to_delete.size())},
            {"media_matched", static_cast<int>(to_delete.size())},
            {"media_deleted", deleted},
            {"bytes_deleted", bytes_deleted},
            {"bytes_deleted_formatted", format_bytes(bytes_deleted)}
        };
    }

    json resp;
    resp["policy_id"] = policy_id;
    resp["created"] = is_new;
    resp["updated"] = !is_new;
    resp["policy"] = {
        {"policy_id", policy.policy_id},
        {"name", policy.name},
        {"enabled", policy.enabled},
        {"applies_to", policy.applies_to},
        {"target", policy.target},
        {"max_lifetime_ms", policy.max_lifetime_ms},
        {"max_lifetime_formatted", format_duration_ms(policy.max_lifetime_ms)},
        {"max_idle_ms", policy.max_idle_ms},
        {"max_idle_formatted", format_duration_ms(policy.max_idle_ms)},
        {"max_size_bytes", policy.max_size_bytes},
        {"delete_remote", policy.delete_remote},
        {"delete_quarantined", policy.delete_quarantined},
        {"delete_thumbnails", policy.delete_thumbnails}
    };
    resp["status"] = "success";

    if (apply_now) {
        resp["apply_results"] = apply_report;
    }

    return resp;
}

// ---------------------------------------------------------------------------
// 13. DELETE /_synapse/admin/v1/media/retention_policy — Delete a policy
// ---------------------------------------------------------------------------

json admin_delete_retention_policy(const json& params, const json& body,
                                     const std::string& request_path) {
    std::string policy_id = safe_get_string(body, "policy_id", "");
    // Also try to extract from query params
    if (policy_id.empty() && params.contains("policy_id")) {
        policy_id = params["policy_id"].get<std::string>();
    }

    if (policy_id.empty()) {
        return error_response("M_MISSING_PARAM",
            "policy_id is required to delete a retention policy");
    }

    std::lock_guard<std::mutex> lock(db::policy_mutex);

    auto it = db::retention_policies.find(policy_id);
    if (it == db::retention_policies.end()) {
        return error_response("M_NOT_FOUND",
            "Retention policy not found: " + policy_id, 404);
    }

    db::retention_policies.erase(it);

    json resp;
    resp["policy_id"] = policy_id;
    resp["deleted"] = true;
    resp["status"] = "success";
    resp["message"] = "Retention policy deleted";

    return resp;
}

// ---------------------------------------------------------------------------
// 14. GET /_synapse/admin/v1/media/url_previews — URL Preview Cache Management
// ---------------------------------------------------------------------------

json admin_list_url_previews(const json& params, const json& body,
                               const std::string& request_path) {
    std::lock_guard<std::mutex> lock(db::previews_mutex);

    int from = 0;
    int limit = 100;
    if (params.contains("from")) {
        if (params["from"].is_string())
            from = std::stoi(params["from"].get<std::string>());
        else from = params["from"].get<int>();
    }
    if (params.contains("limit")) {
        if (params["limit"].is_string())
            limit = std::min(std::stoi(params["limit"].get<std::string>()), 500);
        else limit = std::min(params["limit"].get<int>(), 500);
    }

    std::string search = safe_get_string(params, "search", "");
    bool include_stale = safe_get_bool(params, "include_stale", true);
    bool include_errors = safe_get_bool(params, "include_errors", true);

    // Collect matching
    std::vector<const db::UrlPreviewRecord*> matched;
    for (const auto& [hash, rec] : db::url_previews) {
        if (!include_stale && rec.stale) continue;
        if (!include_errors && !rec.error.empty()) continue;
        if (!search.empty() &&
            !matches_filter(rec.url, search) &&
            !matches_filter(rec.title, search)) continue;
        matched.push_back(&rec);
    }

    // Sort by fetched_ts descending
    std::sort(matched.begin(), matched.end(),
        [](const auto& a, const auto& b) {
            return a->fetched_ts > b->fetched_ts;
        });

    int total = static_cast<int>(matched.size());
    json previews_arr = json::array();
    for (int i = from; i < std::min(from + limit, total); ++i) {
        const auto& rec = *matched[i];
        json pj;
        pj["url"] = rec.url;
        pj["title"] = rec.title;
        pj["description"] = rec.description;
        pj["image_url"] = rec.image_url;
        pj["image_mxc"] = rec.image_mxc;
        pj["image_size"] = rec.image_size;
        pj["type"] = rec.type;
        pj["site_name"] = rec.site_name;
        pj["fetched_ts"] = std::stoll(rec.fetched_ts);
        pj["fetched_iso"] = iso8601_from_epoch(std::stoll(rec.fetched_ts));
        if (!rec.expires_ts.empty()) {
            pj["expires_ts"] = std::stoll(rec.expires_ts);
            pj["expires_iso"] = iso8601_from_epoch(std::stoll(rec.expires_ts));
        }
        pj["response_time_ms"] = rec.response_time_ms;
        pj["http_status"] = rec.http_status;
        pj["access_count"] = rec.access_count;
        pj["ttl_ms"] = rec.ttl_ms;
        pj["stale"] = rec.stale;
        if (!rec.error.empty()) pj["error"] = rec.error;
        previews_arr.push_back(pj);
    }

    json resp = paginated_response("previews", previews_arr, total, from, limit);

    // Summary
    int64_t total_image_size = 0;
    int stale_count = 0, error_count = 0, og_count = 0, oembed_count = 0,
        twitter_count = 0;
    for (const auto& [h, rec] : db::url_previews) {
        total_image_size += rec.image_size;
        if (rec.stale) stale_count++;
        if (!rec.error.empty()) error_count++;
        if (rec.type == "og") og_count++;
        else if (rec.type == "oembed") oembed_count++;
        else if (rec.type == "twitter_card") twitter_count++;
    }

    resp["summary"] = {
        {"total_cached", total},
        {"total_image_size", total_image_size},
        {"total_image_size_formatted", format_bytes(total_image_size)},
        {"stale_count", stale_count},
        {"error_count", error_count},
        {"og_count", og_count},
        {"oembed_count", oembed_count},
        {"twitter_card_count", twitter_count}
    };

    return resp;
}

// ---------------------------------------------------------------------------
// 15. DELETE /_synapse/admin/v1/media/url_previews — Clear URL Preview Cache
// ---------------------------------------------------------------------------

json admin_clear_url_previews(const json& params, const json& body,
                                const std::string& request_path) {
    std::string clear_type = safe_get_string(body, "type", "all");
    // "all", "stale", "errors", "older_than"
    int64_t older_than_ms = safe_get_int64(body, "older_than_ms",
        30LL * 24 * 3600 * 1000); // 30 days

    std::lock_guard<std::mutex> lock(db::previews_mutex);

    int deleted = 0;
    int64_t bytes_freed = 0;
    int previous_count = static_cast<int>(db::url_previews.size());

    std::vector<std::string> to_delete_hashes;
    for (const auto& [hash, rec] : db::url_previews) {
        if (clear_type == "all") {
            to_delete_hashes.push_back(hash);
        } else if (clear_type == "stale" && rec.stale) {
            to_delete_hashes.push_back(hash);
        } else if (clear_type == "errors" && !rec.error.empty()) {
            to_delete_hashes.push_back(hash);
        } else if (clear_type == "older_than" && !rec.fetched_ts.empty()) {
            int64_t age = std::stoll(now_ms()) - std::stoll(rec.fetched_ts);
            if (age > older_than_ms) {
                to_delete_hashes.push_back(hash);
            }
        }
    }

    for (const auto& hash : to_delete_hashes) {
        auto it = db::url_previews.find(hash);
        if (it != db::url_previews.end()) {
            bytes_freed += it->second.image_size;
            db::url_previews.erase(it);
            deleted++;
        }
    }

    json resp;
    resp["type"] = clear_type;
    resp["previous_count"] = previous_count;
    resp["deleted"] = deleted;
    resp["remaining"] = static_cast<int>(db::url_previews.size());
    resp["bytes_freed"] = bytes_freed;
    resp["bytes_freed_formatted"] = format_bytes(bytes_freed);
    resp["status"] = "success";
    resp["message"] = "URL preview cache cleared: " + std::to_string(deleted) +
        " entries removed";

    return resp;
}

// ---------------------------------------------------------------------------
// 15b. POST /_synapse/admin/v1/media/url_previews/refresh
// ---------------------------------------------------------------------------

json admin_refresh_url_preview(const json& params, const json& body,
                                 const std::string& request_path) {
    std::string url = safe_get_string(body, "url", "");
    bool refresh_all_stale = safe_get_bool(body, "refresh_all_stale", false);

    std::lock_guard<std::mutex> lock(db::previews_mutex);

    int refreshed = 0;
    json refreshed_list = json::array();

    if (refresh_all_stale) {
        for (auto& [hash, rec] : db::url_previews) {
            if (rec.stale) {
                rec.fetched_ts = now_ms();
                rec.stale = false;
                rec.access_count = 0;
                refreshed++;
                refreshed_list.push_back({
                    {"url", rec.url},
                    {"hash", hash}
                });
            }
        }
    } else if (!url.empty()) {
        // Find by URL and refresh
        std::string url_hash = sha256(url);
        auto it = db::url_previews.find(url_hash);
        if (it != db::url_previews.end()) {
            it->second.fetched_ts = now_ms();
            it->second.stale = false;
            it->second.access_count = 0;
            refreshed = 1;
            refreshed_list.push_back({
                {"url", it->second.url},
                {"hash", url_hash}
            });
        } else {
            return error_response("M_NOT_FOUND",
                "URL not found in preview cache: " + url, 404);
        }
    } else {
        return error_response("M_MISSING_PARAM",
            "Provide 'url' or set 'refresh_all_stale' to true");
    }

    json resp;
    resp["refreshed_count"] = refreshed;
    resp["refreshed"] = refreshed_list;
    resp["status"] = "success";

    return resp;
}

// ---------------------------------------------------------------------------
// 16. GET /_synapse/admin/v1/media/thumbnails — Thumbnail Cache List
// ---------------------------------------------------------------------------

json admin_list_thumbnails(const json& params, const json& body,
                             const std::string& request_path) {
    std::lock_guard<std::mutex> lock(db::thumbnails_mutex);

    int from = 0;
    int limit = 100;
    if (params.contains("from")) {
        if (params["from"].is_string())
            from = std::stoi(params["from"].get<std::string>());
        else from = params["from"].get<int>();
    }
    if (params.contains("limit")) {
        if (params["limit"].is_string())
            limit = std::min(std::stoi(params["limit"].get<std::string>()), 500);
        else limit = std::min(params["limit"].get<int>(), 500);
    }

    std::string origin_filter = safe_get_string(params, "origin", "");
    std::string media_id_filter = safe_get_string(params, "media_id", "");
    int min_width = static_cast<int>(safe_get_int64(params, "min_width", 0));
    int max_width = static_cast<int>(safe_get_int64(params, "max_width", INT_MAX));
    int min_height = static_cast<int>(safe_get_int64(params, "min_height", 0));
    int max_height = static_cast<int>(safe_get_int64(params, "max_height", INT_MAX));

    // Collect matching thumbnails
    std::vector<const db::ThumbnailRecord*> matched;
    for (const auto& [tid, rec] : db::thumbnails) {
        if (rec.soft_deleted) continue;
        if (!origin_filter.empty() && rec.origin != origin_filter) continue;
        if (!media_id_filter.empty() && rec.media_id != media_id_filter) continue;
        if (rec.width < min_width || rec.width > max_width) continue;
        if (rec.height < min_height || rec.height > max_height) continue;
        matched.push_back(&rec);
    }

    // Sort by created_ts descending
    std::sort(matched.begin(), matched.end(),
        [](const auto& a, const auto& b) {
            return a->created_ts > b->created_ts;
        });

    int total = static_cast<int>(matched.size());
    json thumb_arr = json::array();
    for (int i = from; i < std::min(from + limit, total); ++i) {
        const auto& rec = *matched[i];
        json tj;
        tj["thumbnail_id"] = rec.thumbnail_id;
        tj["media_id"] = rec.media_id;
        tj["origin"] = rec.origin;
        tj["method"] = rec.method;
        tj["width"] = rec.width;
        tj["height"] = rec.height;
        tj["file_size"] = rec.file_size;
        tj["file_size_formatted"] = format_bytes(rec.file_size);
        tj["content_type"] = rec.content_type;
        tj["created_ts"] = std::stoll(rec.created_ts);
        tj["created_iso"] = iso8601_from_epoch(std::stoll(rec.created_ts));
        if (!rec.last_access_ts.empty()) {
            tj["last_access_ts"] = std::stoll(rec.last_access_ts);
            tj["last_access_iso"] = iso8601_from_epoch(std::stoll(rec.last_access_ts));
        }
        tj["access_count"] = rec.access_count;
        tj["is_remote"] = rec.is_remote;
        thumb_arr.push_back(tj);
    }

    json resp = paginated_response("thumbnails", thumb_arr, total, from, limit);

    // Summary
    int64_t total_bytes = 0;
    int remote_count = 0, local_count = 0;
    std::map<std::string, int> method_counts;
    for (const auto& [tid, rec] : db::thumbnails) {
        if (rec.soft_deleted) continue;
        total_bytes += rec.file_size;
        if (rec.is_remote) remote_count++; else local_count++;
        method_counts[rec.method]++;
    }

    json method_json = json::object();
    for (const auto& [m, c] : method_counts) method_json[m] = c;

    resp["summary"] = {
        {"total_thumbnails", total},
        {"total_bytes", total_bytes},
        {"total_formatted", format_bytes(total_bytes)},
        {"remote_count", remote_count},
        {"local_count", local_count},
        {"methods", method_json}
    };

    return resp;
}

// ---------------------------------------------------------------------------
// 17. DELETE /_synapse/admin/v1/media/thumbnails — Clear Thumbnail Cache
// ---------------------------------------------------------------------------

json admin_clear_thumbnails(const json& params, const json& body,
                              const std::string& request_path) {
    std::string clear_type = safe_get_string(body, "type", "all");
    // "all", "orphaned", "older_than", "remote"
    int64_t older_than_ms = safe_get_int64(body, "older_than_ms",
        30LL * 24 * 3600 * 1000);

    std::lock_guard<std::mutex> tlock(db::thumbnails_mutex);

    int deleted = 0;
    int64_t bytes_freed = 0;
    int previous_count = static_cast<int>(db::thumbnails.size());

    std::vector<std::string> to_delete;

    for (const auto& [tid, rec] : db::thumbnails) {
        if (rec.soft_deleted) {
            if (clear_type == "all") to_delete.push_back(tid);
            continue;
        }

        if (clear_type == "all") {
            to_delete.push_back(tid);
        } else if (clear_type == "orphaned") {
            // Check if parent media still exists
            std::string key = media_key(rec.origin, rec.media_id);
            std::lock_guard<std::mutex> mlock(db::media_mutex);
            if (db::media.find(key) == db::media.end()) {
                to_delete.push_back(tid);
            }
        } else if (clear_type == "older_than" && !rec.created_ts.empty()) {
            int64_t age = std::stoll(now_ms()) - std::stoll(rec.created_ts);
            if (age > older_than_ms) {
                to_delete.push_back(tid);
            }
        } else if (clear_type == "remote" && rec.is_remote) {
            to_delete.push_back(tid);
        }
    }

    for (const auto& tid : to_delete) {
        auto it = db::thumbnails.find(tid);
        if (it != db::thumbnails.end()) {
            bytes_freed += it->second.file_size;
            db::thumbnails.erase(it);
            deleted++;
        }
    }

    // Also clean up the media_thumbnails index
    for (auto& [key, tid_list] : db::media_thumbnails) {
        tid_list.erase(
            std::remove_if(tid_list.begin(), tid_list.end(),
                [&to_delete](const std::string& tid) {
                    return std::find(to_delete.begin(), to_delete.end(), tid)
                           != to_delete.end();
                }),
            tid_list.end());
    }

    json resp;
    resp["type"] = clear_type;
    resp["previous_count"] = previous_count;
    resp["deleted"] = deleted;
    resp["remaining"] = static_cast<int>(db::thumbnails.size());
    resp["bytes_freed"] = bytes_freed;
    resp["bytes_freed_formatted"] = format_bytes(bytes_freed);
    resp["status"] = "success";
    resp["message"] = "Thumbnail cache cleared: " + std::to_string(deleted) +
        " thumbnails removed";

    return resp;
}

// ---------------------------------------------------------------------------
// 18. GET /_synapse/admin/v1/media/top_media — Top Media by Size/Access
// ---------------------------------------------------------------------------

json admin_top_media(const json& params, const json& body,
                       const std::string& request_path) {
    std::lock_guard<std::mutex> lock(db::media_mutex);

    int top_n = 50;
    if (params.contains("limit")) {
        if (params["limit"].is_string())
            top_n = std::min(std::stoi(params["limit"].get<std::string>()), 200);
        else top_n = std::min(params["limit"].get<int>(), 200);
    }

    std::string sort_by = safe_get_string(params, "sort_by", "size");
    // "size", "access_count", "age"

    // Collect non-deleted media
    std::vector<std::pair<std::string, const db::MediaRecord*>> candidates;
    for (const auto& [key, rec] : db::media) {
        if (rec.hard_deleted) continue;
        candidates.emplace_back(key, &rec);
    }

    if (sort_by == "access_count") {
        std::sort(candidates.begin(), candidates.end(),
            [](const auto& a, const auto& b) {
                return a.second->access_count > b.second->access_count;
            });
    } else if (sort_by == "age") {
        std::sort(candidates.begin(), candidates.end(),
            [](const auto& a, const auto& b) {
                // oldest first
                int64_t ca = a.second->created_ts.empty() ? 0 :
                    std::stoll(a.second->created_ts);
                int64_t cb = b.second->created_ts.empty() ? 0 :
                    std::stoll(b.second->created_ts);
                return ca < cb;
            });
    } else {
        // Default: by size
        std::sort(candidates.begin(), candidates.end(),
            [](const auto& a, const auto& b) {
                return a.second->media_length > b.second->media_length;
            });
    }

    json media_arr = json::array();
    for (int i = 0; i < std::min(top_n, static_cast<int>(candidates.size())); ++i) {
        media_arr.push_back(media_to_json(*candidates[i].second));
    }

    json resp;
    resp["sort_by"] = sort_by;
    resp["media"] = media_arr;
    resp["count"] = static_cast<int>(media_arr.size());
    resp["total_media"] = static_cast<int>(candidates.size());
    resp["generated_ts"] = std::stoll(now_ms());

    return resp;
}

// ---------------------------------------------------------------------------
// 19. GET /_synapse/admin/v1/media/recently_accessed — Recently Accessed Media
// ---------------------------------------------------------------------------

json admin_recently_accessed_media(const json& params, const json& body,
                                     const std::string& request_path) {
    std::lock_guard<std::mutex> lock(db::media_mutex);

    int limit = 50;
    if (params.contains("limit")) {
        if (params["limit"].is_string())
            limit = std::min(std::stoi(params["limit"].get<std::string>()), 200);
        else limit = std::min(params["limit"].get<int>(), 200);
    }

    // Collect media sorted by last_access_ts
    std::vector<std::pair<std::string, const db::MediaRecord*>> candidates;
    for (const auto& [key, rec] : db::media) {
        if (rec.hard_deleted) continue;
        if (rec.last_access_ts.empty()) continue; // never accessed
        candidates.emplace_back(key, &rec);
    }

    std::sort(candidates.begin(), candidates.end(),
        [](const auto& a, const auto& b) {
            int64_t la = std::stoll(a.second->last_access_ts);
            int64_t lb = std::stoll(b.second->last_access_ts);
            return la > lb; // most recent first
        });

    json media_arr = json::array();
    for (int i = 0; i < std::min(limit, static_cast<int>(candidates.size())); ++i) {
        json j = media_to_json(*candidates[i].second);
        int64_t last = std::stoll(candidates[i].second->last_access_ts);
        j["last_access_ago_ms"] = std::stoll(now_ms()) - last;
        j["last_access_ago"] = format_duration_ms(
            std::stoll(now_ms()) - last);
        media_arr.push_back(j);
    }

    json resp;
    resp["media"] = media_arr;
    resp["count"] = static_cast<int>(media_arr.size());
    resp["generated_ts"] = std::stoll(now_ms());

    return resp;
}

// ---------------------------------------------------------------------------
// 20. POST /_synapse/admin/v1/media/bulk_quarantine — Bulk Quarantine
// ---------------------------------------------------------------------------

json admin_bulk_quarantine(const json& params, const json& body,
                             const std::string& request_path) {
    if (!body.contains("media_ids") || !body["media_ids"].is_array()) {
        return error_response("M_MISSING_PARAM",
            "Expected 'media_ids' array in request body");
    }

    std::string reason = safe_get_string(body, "reason", "Bulk quarantine by admin");
    std::string admin_user = safe_get_string(body, "admin_user", "admin");

    std::lock_guard<std::mutex> lock(db::media_mutex);

    int success_count = 0;
    int error_count = 0;
    json results = json::array();
    json errors = json::array();

    for (const auto& item : body["media_ids"]) {
        std::string origin, media_id;

        if (item.is_string()) {
            // Could be "origin/media_id" or just media_id
            std::string val = item.get<std::string>();
            auto slash = val.find('/');
            if (slash != std::string::npos) {
                origin = val.substr(0, slash);
                media_id = val.substr(slash + 1);
            } else {
                media_id = val;
                // Try to find origin
                origin = "localhost";
            }
        } else if (item.is_object()) {
            origin = safe_get_string(item, "origin", "localhost");
            media_id = safe_get_string(item, "media_id", "");
        } else {
            errors.push_back({
                {"item", item.dump()},
                {"error", "Invalid format: must be string or {origin, media_id}"}
            });
            error_count++;
            continue;
        }

        if (media_id.empty()) {
            errors.push_back({{"item", item.dump()}, {"error", "Missing media_id"}});
            error_count++;
            continue;
        }

        std::string key = media_key(origin, media_id);
        auto it = db::media.find(key);
        if (it == db::media.end()) {
            errors.push_back({
                {"origin", origin},
                {"media_id", media_id},
                {"error", "Media not found"}
            });
            error_count++;
            continue;
        }

        if (it->second.safe_from_quarantine) {
            errors.push_back({
                {"origin", origin},
                {"media_id", media_id},
                {"error", "Protected from quarantine"}
            });
            error_count++;
            continue;
        }

        if (it->second.quarantined) {
            // Already quarantined, count as success
            success_count++;
            results.push_back({
                {"origin", origin},
                {"media_id", media_id},
                {"quarantined", true},
                {"status", "already_quarantined"}
            });
            continue;
        }

        it->second.quarantined = true;
        it->second.quarantined_by = admin_user;
        it->second.quarantined_ts = now_ms();
        it->second.quarantine_reason = reason;
        success_count++;
        results.push_back({
            {"origin", origin},
            {"media_id", media_id},
            {"quarantined", true},
            {"status", "success"}
        });
    }

    json resp;
    resp["success_count"] = success_count;
    resp["error_count"] = error_count;
    resp["total"] = static_cast<int>(body["media_ids"].size());
    resp["results"] = results;
    resp["errors"] = errors;
    resp["reason"] = reason;
    resp["status"] = "success";

    return resp;
}

// ---------------------------------------------------------------------------
// 21. POST /_synapse/admin/v1/media/bulk_delete — Bulk Delete Media
// ---------------------------------------------------------------------------

json admin_bulk_delete(const json& params, const json& body,
                         const std::string& request_path) {
    if (!body.contains("media_ids") || !body["media_ids"].is_array()) {
        return error_response("M_MISSING_PARAM",
            "Expected 'media_ids' array in request body");
    }

    bool hard_delete = safe_get_bool(body, "hard_delete", true);
    bool delete_thumbnails = safe_get_bool(body, "delete_thumbnails", true);
    std::string admin_user = safe_get_string(body, "admin_user", "admin");

    std::lock_guard<std::mutex> lock(db::media_mutex);

    int success_count = 0;
    int error_count = 0;
    int64_t total_bytes_freed = 0;
    json results = json::array();
    json errors = json::array();

    for (const auto& item : body["media_ids"]) {
        std::string origin, media_id;

        if (item.is_string()) {
            std::string val = item.get<std::string>();
            auto slash = val.find('/');
            if (slash != std::string::npos) {
                origin = val.substr(0, slash);
                media_id = val.substr(slash + 1);
            } else {
                media_id = val;
                origin = "localhost";
            }
        } else if (item.is_object()) {
            origin = safe_get_string(item, "origin", "localhost");
            media_id = safe_get_string(item, "media_id", "");
        } else {
            errors.push_back({
                {"item", item.dump()},
                {"error", "Invalid format"}
            });
            error_count++;
            continue;
        }

        if (media_id.empty()) {
            errors.push_back({{"item", item.dump()}, {"error", "Missing media_id"}});
            error_count++;
            continue;
        }

        std::string key = media_key(origin, media_id);
        auto it = db::media.find(key);
        if (it == db::media.end()) {
            errors.push_back({
                {"origin", origin}, {"media_id", media_id}, {"error", "Not found"}
            });
            error_count++;
            continue;
        }

        int64_t freed = it->second.media_length;

        if (delete_thumbnails) {
            std::lock_guard<std::mutex> tlock(db::thumbnails_mutex);
            auto thumb_it = db::media_thumbnails.find(key);
            if (thumb_it != db::media_thumbnails.end()) {
                for (const auto& tid : thumb_it->second) {
                    auto tit = db::thumbnails.find(tid);
                    if (tit != db::thumbnails.end()) {
                        freed += tit->second.file_size;
                        db::thumbnails.erase(tit);
                    }
                }
                db::media_thumbnails.erase(thumb_it);
            }
        }

        // Clean indexes
        if (!it->second.room_id.empty()) {
            auto ri = db::room_media.find(it->second.room_id);
            if (ri != db::room_media.end()) {
                ri->second.erase(
                    std::remove(ri->second.begin(), ri->second.end(), key),
                    ri->second.end());
            }
        }
        if (!it->second.user_id.empty()) {
            auto ui = db::user_media.find(it->second.user_id);
            if (ui != db::user_media.end()) {
                ui->second.erase(
                    std::remove(ui->second.begin(), ui->second.end(), key),
                    ui->second.end());
            }
        }

        if (hard_delete) {
            db::media.erase(it);
        } else {
            it->second.soft_deleted = true;
            it->second.deleted_by = admin_user;
            it->second.deleted_ts = now_ms();
        }

        total_bytes_freed += freed;
        success_count++;
        results.push_back({
            {"origin", origin},
            {"media_id", media_id},
            {"deleted", true},
            {"hard_delete", hard_delete},
            {"bytes_freed", freed},
            {"bytes_freed_formatted", format_bytes(freed)}
        });
    }

    json resp;
    resp["success_count"] = success_count;
    resp["error_count"] = error_count;
    resp["total"] = static_cast<int>(body["media_ids"].size());
    resp["hard_delete"] = hard_delete;
    resp["total_bytes_freed"] = total_bytes_freed;
    resp["total_freed_formatted"] = format_bytes(total_bytes_freed);
    resp["results"] = results;
    resp["errors"] = errors;
    resp["status"] = "success";

    return resp;
}

// ---------------------------------------------------------------------------
// 22. POST /_synapse/admin/v1/media/quarantine_room — Quarantine All Media in Room
// ---------------------------------------------------------------------------

json admin_quarantine_room_media(const json& params, const json& body,
                                   const std::string& request_path) {
    std::string room_id = safe_get_string(body, "room_id", "");
    if (room_id.empty()) {
        return error_response("M_MISSING_PARAM",
            "room_id is required to quarantine a room's media");
    }

    if (!is_valid_room_id(room_id)) {
        return error_response("M_INVALID_PARAM",
            "Invalid room_id format");
    }

    std::string reason = safe_get_string(body, "reason",
        "Room-wide quarantine by admin");
    std::string admin_user = safe_get_string(body, "admin_user", "admin");
    bool quarantine_future = safe_get_bool(body, "quarantine_future", true);

    std::lock_guard<std::mutex> lock(db::media_mutex);
    std::lock_guard<std::mutex> qlock(db::quarantine_room_mutex);

    int quarantined_count = 0;
    int already_count = 0;
    int protected_count = 0;
    int64_t bytes_quarantined = 0;

    // Find all media in this room
    auto room_it = db::room_media.find(room_id);
    if (room_it != db::room_media.end()) {
        for (const auto& key : room_it->second) {
            auto it = db::media.find(key);
            if (it == db::media.end()) continue;

            if (it->second.safe_from_quarantine) {
                protected_count++;
                continue;
            }
            if (it->second.quarantined) {
                already_count++;
                continue;
            }

            it->second.quarantined = true;
            it->second.quarantined_by = admin_user;
            it->second.quarantined_ts = now_ms();
            it->second.quarantine_reason = reason;
            quarantined_count++;
            bytes_quarantined += it->second.media_length;
        }
    }

    // If quarantine_future, record the room so future uploads are auto-quarantined
    if (quarantine_future) {
        db::QuarantineRoomEntry entry;
        entry.room_id = room_id;
        entry.quarantined_by = admin_user;
        entry.quarantined_ts = now_ms();
        entry.reason = reason;
        entry.media_quarantined = quarantined_count;
        db::quarantine_rooms[room_id] = entry;
    }

    json resp;
    resp["room_id"] = room_id;
    resp["quarantined_count"] = quarantined_count;
    resp["already_quarantined"] = already_count;
    resp["protected_count"] = protected_count;
    resp["bytes_quarantined"] = bytes_quarantined;
    resp["bytes_quarantined_formatted"] = format_bytes(bytes_quarantined);
    resp["quarantine_future"] = quarantine_future;
    resp["reason"] = reason;
    resp["status"] = "success";
    resp["message"] = "Room media quarantined: " + std::to_string(quarantined_count) +
        " items affected";

    return resp;
}

// ---------------------------------------------------------------------------
// 23. POST /_synapse/admin/v1/media/unquarantine_room
// ---------------------------------------------------------------------------

json admin_unquarantine_room_media(const json& params, const json& body,
                                     const std::string& request_path) {
    std::string room_id = safe_get_string(body, "room_id", "");
    if (room_id.empty()) {
        return error_response("M_MISSING_PARAM",
            "room_id is required");
    }

    std::lock_guard<std::mutex> lock(db::media_mutex);
    std::lock_guard<std::mutex> qlock(db::quarantine_room_mutex);

    int unquarantined_count = 0;
    auto room_it = db::room_media.find(room_id);
    if (room_it != db::room_media.end()) {
        for (const auto& key : room_it->second) {
            auto it = db::media.find(key);
            if (it == db::media.end()) continue;
            if (!it->second.quarantined) continue;

            it->second.quarantined = false;
            it->second.quarantined_by = "";
            it->second.quarantined_ts = "";
            it->second.quarantine_reason = "";
            unquarantined_count++;
        }
    }

    // Remove from quarantine rooms list
    db::quarantine_rooms.erase(room_id);

    json resp;
    resp["room_id"] = room_id;
    resp["unquarantined_count"] = unquarantined_count;
    resp["status"] = "success";
    resp["message"] = "Room media unquarantined: " +
        std::to_string(unquarantined_count) + " items";

    return resp;
}

// ---------------------------------------------------------------------------
// 24. GET /_synapse/admin/v1/media/cleanup_log — Cleanup Log History
// ---------------------------------------------------------------------------

json admin_get_cleanup_log(const json& params, const json& body,
                             const std::string& request_path) {
    std::lock_guard<std::mutex> lock(db::cleanup_log_mutex);

    int limit = 50;
    if (params.contains("limit")) {
        if (params["limit"].is_string())
            limit = std::min(std::stoi(params["limit"].get<std::string>()), 200);
        else limit = std::min(params["limit"].get<int>(), 200);
    }

    json log_arr = json::array();
    int start = std::max(0,
        static_cast<int>(db::cleanup_log.size()) - limit);
    for (size_t i = start; i < db::cleanup_log.size(); ++i) {
        const auto& entry = db::cleanup_log[i];
        json ej;
        ej["log_id"] = entry.log_id;
        ej["run_ts"] = std::stoll(entry.run_ts);
        ej["run_iso"] = iso8601_from_epoch(std::stoll(entry.run_ts));
        ej["triggered_by"] = entry.triggered_by;
        ej["reason"] = entry.reason;
        ej["media_scanned"] = entry.media_scanned;
        ej["media_deleted"] = entry.media_deleted;
        ej["thumbnails_deleted"] = entry.thumbnails_deleted;
        ej["previews_deleted"] = entry.previews_deleted;
        ej["errors"] = entry.errors;
        ej["bytes_freed"] = entry.bytes_freed;
        ej["bytes_freed_formatted"] = format_bytes(entry.bytes_freed);
        ej["duration_ms"] = entry.duration_ms;
        ej["status"] = entry.status;
        if (!entry.error_message.empty()) ej["error_message"] = entry.error_message;
        log_arr.push_back(ej);
    }

    json resp;
    resp["cleanup_log"] = log_arr;
    resp["total_entries"] = static_cast<int>(db::cleanup_log.size());
    resp["generated_ts"] = std::stoll(now_ms());

    return resp;
}

// ---------------------------------------------------------------------------
// 25. GET /_synapse/admin/v1/media/quarantine_rooms — List Quarantined Rooms
// ---------------------------------------------------------------------------

json admin_list_quarantine_rooms(const json& params, const json& body,
                                   const std::string& request_path) {
    std::lock_guard<std::mutex> lock(db::quarantine_room_mutex);

    json rooms_arr = json::array();
    for (const auto& [rid, entry] : db::quarantine_rooms) {
        json rj;
        rj["room_id"] = entry.room_id;
        rj["quarantined_by"] = entry.quarantined_by;
        rj["quarantined_ts"] = std::stoll(entry.quarantined_ts);
        rj["quarantined_iso"] = iso8601_from_epoch(std::stoll(entry.quarantined_ts));
        rj["reason"] = entry.reason;
        rj["media_quarantined"] = entry.media_quarantined;
        rooms_arr.push_back(rj);
    }

    json resp;
    resp["quarantine_rooms"] = rooms_arr;
    resp["total"] = static_cast<int>(rooms_arr.size());
    resp["generated_ts"] = std::stoll(now_ms());

    return resp;
}

// ---------------------------------------------------------------------------
// 26. GET /_synapse/admin/v1/media/health — Media System Health Check
// ---------------------------------------------------------------------------

json admin_media_health(const json& params, const json& body,
                          const std::string& request_path) {
    json health;
    health["subsystem"] = "media";

    {
        std::lock_guard<std::mutex> lock(db::media_mutex);
        health["total_media"] = static_cast<int>(db::media.size());

        int quarantined = 0, remote = 0, local = 0, soft_deleted = 0;
        int64_t total_bytes = 0;
        for (const auto& [k, rec] : db::media) {
            if (rec.quarantined) quarantined++;
            if (rec.is_remote) remote++; else local++;
            if (rec.soft_deleted) soft_deleted++;
            total_bytes += rec.media_length;
        }
        health["quarantined"] = quarantined;
        health["remote"] = remote;
        health["local"] = local;
        health["soft_deleted"] = soft_deleted;
        health["total_bytes"] = total_bytes;
        health["total_formatted"] = format_bytes(total_bytes);
    }

    {
        std::lock_guard<std::mutex> lock(db::previews_mutex);
        health["url_previews_cached"] = static_cast<int>(db::url_previews.size());
    }

    {
        std::lock_guard<std::mutex> lock(db::thumbnails_mutex);
        health["thumbnails_cached"] = static_cast<int>(db::thumbnails.size());
    }

    {
        std::lock_guard<std::mutex> lock(db::policy_mutex);
        health["retention_policies"] = static_cast<int>(db::retention_policies.size());
    }

    {
        std::lock_guard<std::mutex> lock(db::quarantine_room_mutex);
        health["quarantine_rooms"] = static_cast<int>(db::quarantine_rooms.size());
    }

    health["status"] = "healthy";
    health["timestamp_ms"] = std::stoll(now_ms());

    return health;
}

// ---------------------------------------------------------------------------
// 27. POST /_synapse/admin/v1/media/protect — Mark Media as Safe from Quarantine
// ---------------------------------------------------------------------------

json admin_protect_media(const json& params, const json& body,
                          const std::string& request_path) {
    auto parts = parse_media_path(request_path);
    if (!parts.valid) {
        // Try from body if path doesn't parse
        std::string origin = safe_get_string(body, "origin", "localhost");
        std::string media_id = safe_get_string(body, "media_id", "");
        if (origin.empty() || media_id.empty()) {
            return error_response("M_MISSING_PARAM",
                "origin and media_id are required");
        }
        parts.origin = origin;
        parts.media_id = media_id;
        parts.valid = true;
    }

    std::string key = media_key(parts.origin, parts.media_id);

    std::lock_guard<std::mutex> lock(db::media_mutex);

    auto it = db::media.find(key);
    if (it == db::media.end()) {
        return error_response("M_NOT_FOUND",
            "Media not found: " + key, 404);
    }

    bool protect = safe_get_bool(body, "protect", true);

    if (protect && it->second.safe_from_quarantine) {
        return error_response("M_UNKNOWN",
            "Media already protected: " + key);
    }
    if (!protect && !it->second.safe_from_quarantine) {
        return error_response("M_UNKNOWN",
            "Media is not protected: " + key);
    }

    it->second.safe_from_quarantine = protect;

    json resp;
    resp["media_id"] = parts.media_id;
    resp["origin"] = parts.origin;
    resp["safe_from_quarantine"] = protect;
    resp["status"] = "success";
    resp["message"] = protect ?
        "Media is now protected from quarantine." :
        "Media protection removed.";

    return resp;
}

// ---------------------------------------------------------------------------
// 28. GET /_synapse/admin/v1/media/user_media — List Media by User
// ---------------------------------------------------------------------------

json admin_list_user_media(const json& params, const json& body,
                             const std::string& request_path) {
    std::string user_id = safe_get_string(params, "user_id", "");
    if (user_id.empty() && body.contains("user_id")) {
        user_id = body["user_id"].get<std::string>();
    }
    if (user_id.empty()) {
        return error_response("M_MISSING_PARAM",
            "user_id is required");
    }

    std::lock_guard<std::mutex> lock(db::media_mutex);

    int from = 0;
    int limit = 100;
    if (params.contains("from")) {
        if (params["from"].is_string())
            from = std::stoi(params["from"].get<std::string>());
        else from = params["from"].get<int>();
    }
    if (params.contains("limit")) {
        if (params["limit"].is_string())
            limit = std::min(std::stoi(params["limit"].get<std::string>()), 500);
        else limit = std::min(params["limit"].get<int>(), 500);
    }

    // Collect all media belonging to this user
    std::vector<std::pair<std::string, const db::MediaRecord*>> matched;
    for (const auto& [key, rec] : db::media) {
        if (rec.hard_deleted) continue;
        if (rec.user_id == user_id) {
            matched.emplace_back(key, &rec);
        }
    }

    // Sort by created_ts desc
    std::sort(matched.begin(), matched.end(),
        [](const auto& a, const auto& b) {
            int64_t ca = a.second->created_ts.empty() ? 0 :
                std::stoll(a.second->created_ts);
            int64_t cb = b.second->created_ts.empty() ? 0 :
                std::stoll(b.second->created_ts);
            return ca > cb;
        });

    int total = static_cast<int>(matched.size());
    json media_arr = json::array();
    int64_t total_bytes = 0;
    for (int i = from; i < std::min(from + limit, total); ++i) {
        media_arr.push_back(media_to_json(*matched[i].second));
        total_bytes += matched[i].second->media_length;
    }

    json resp = paginated_response("media", media_arr, total, from, limit);
    resp["user_id"] = user_id;
    resp["total_bytes"] = total_bytes;
    resp["total_bytes_formatted"] = format_bytes(total_bytes);

    return resp;
}

// ---------------------------------------------------------------------------
// 29. GET /_synapse/admin/v1/media/room_media — List Media by Room
// ---------------------------------------------------------------------------

json admin_list_room_media(const json& params, const json& body,
                             const std::string& request_path) {
    std::string room_id = safe_get_string(params, "room_id", "");
    if (room_id.empty() && body.contains("room_id")) {
        room_id = body["room_id"].get<std::string>();
    }
    if (room_id.empty()) {
        return error_response("M_MISSING_PARAM",
            "room_id is required");
    }

    std::lock_guard<std::mutex> lock(db::media_mutex);

    int from = 0;
    int limit = 100;
    if (params.contains("from")) {
        if (params["from"].is_string())
            from = std::stoi(params["from"].get<std::string>());
        else from = params["from"].get<int>();
    }
    if (params.contains("limit")) {
        if (params["limit"].is_string())
            limit = std::min(std::stoi(params["limit"].get<std::string>()), 500);
        else limit = std::min(params["limit"].get<int>(), 500);
    }

    // Collect all media belonging to this room
    std::vector<std::pair<std::string, const db::MediaRecord*>> matched;
    for (const auto& [key, rec] : db::media) {
        if (rec.hard_deleted) continue;
        if (rec.room_id == room_id) {
            matched.emplace_back(key, &rec);
        }
    }

    // Sort by created_ts desc
    std::sort(matched.begin(), matched.end(),
        [](const auto& a, const auto& b) {
            int64_t ca = a.second->created_ts.empty() ? 0 :
                std::stoll(a.second->created_ts);
            int64_t cb = b.second->created_ts.empty() ? 0 :
                std::stoll(b.second->created_ts);
            return ca > cb;
        });

    int total = static_cast<int>(matched.size());
    json media_arr = json::array();
    int64_t total_bytes = 0;
    for (int i = from; i < std::min(from + limit, total); ++i) {
        media_arr.push_back(media_to_json(*matched[i].second));
        total_bytes += matched[i].second->media_length;
    }

    json resp = paginated_response("media", media_arr, total, from, limit);
    resp["room_id"] = room_id;
    resp["total_bytes"] = total_bytes;
    resp["total_bytes_formatted"] = format_bytes(total_bytes);

    return resp;
}

// ---------------------------------------------------------------------------
// 30. POST /_synapse/admin/v1/media/recover — Recover Soft-Deleted Media
// ---------------------------------------------------------------------------

json admin_recover_media(const json& params, const json& body,
                          const std::string& request_path) {
    auto parts = parse_media_path(request_path);
    if (!parts.valid) {
        std::string origin = safe_get_string(body, "origin", "localhost");
        std::string media_id = safe_get_string(body, "media_id", "");
        if (origin.empty() || media_id.empty()) {
            return error_response("M_MISSING_PARAM",
                "origin and media_id are required");
        }
        parts.origin = origin;
        parts.media_id = media_id;
        parts.valid = true;
    }

    std::string key = media_key(parts.origin, parts.media_id);

    std::lock_guard<std::mutex> lock(db::media_mutex);

    auto it = db::media.find(key);
    if (it == db::media.end()) {
        return error_response("M_NOT_FOUND",
            "Media not found: " + key, 404);
    }

    if (!it->second.soft_deleted) {
        return error_response("M_UNKNOWN",
            "Media is not soft-deleted: " + key);
    }

    if (it->second.hard_deleted) {
        return error_response("M_UNKNOWN",
            "Cannot recover hard-deleted media: " + key);
    }

    it->second.soft_deleted = false;
    it->second.deleted_by = "";
    it->second.deleted_ts = "";

    json resp;
    resp["media_id"] = parts.media_id;
    resp["origin"] = parts.origin;
    resp["recovered"] = true;
    resp["status"] = "success";
    resp["message"] = "Media successfully recovered from soft delete.";

    return resp;
}

// ---------------------------------------------------------------------------
// 31. GET /_synapse/admin/v1/media/audit_log — Media Audit Trail / Access Log
// ---------------------------------------------------------------------------

json admin_media_audit_log(const json& params, const json& body,
                             const std::string& request_path) {
    std::lock_guard<std::mutex> lock(db::media_access_log_mutex);

    int limit = 100;
    if (params.contains("limit")) {
        if (params["limit"].is_string())
            limit = std::min(std::stoi(params["limit"].get<std::string>()), 500);
        else limit = std::min(params["limit"].get<int>(), 500);
    }

    std::string user_id_filter = safe_get_string(params, "user_id", "");
    std::string media_id_filter = safe_get_string(params, "media_id", "");
    std::string room_id_filter = safe_get_string(params, "room_id", "");

    json log_arr = json::array();
    int count = 0;
    for (auto it = db::media_access_log.rbegin();
         it != db::media_access_log.rend() && count < limit; ++it) {
        if (!user_id_filter.empty() && it->user_id != user_id_filter) continue;
        if (!media_id_filter.empty() && it->media_id != media_id_filter) continue;
        if (!room_id_filter.empty() && it->room_id != room_id_filter) continue;

        json entry;
        entry["log_id"] = it->log_id;
        entry["media_id"] = it->media_id;
        entry["origin"] = it->origin;
        entry["user_id"] = it->user_id;
        entry["access_ts"] = std::stoll(it->access_ts);
        entry["access_iso"] = iso8601_from_epoch(std::stoll(it->access_ts));
        entry["ip_address"] = it->ip_address;
        entry["user_agent"] = it->user_agent;
        entry["room_id"] = it->room_id;
        entry["bytes_transferred"] = it->bytes_transferred;
        entry["http_status"] = it->http_status;
        log_arr.push_back(entry);
        count++;
    }

    json resp;
    resp["audit_log"] = log_arr;
    resp["total_entries"] = static_cast<int>(db::media_access_log.size());
    resp["returned_entries"] = count;
    resp["generated_ts"] = std::stoll(now_ms());

    return resp;
}

// ---------------------------------------------------------------------------
// 32. POST /_synapse/admin/v1/media/export_report — Export Media Report
// ---------------------------------------------------------------------------

json admin_export_media_report(const json& params, const json& body,
                                 const std::string& request_path) {
    std::string format = safe_get_string(body, "format", "json");
    bool include_details = safe_get_bool(body, "include_details", true);
    bool include_stats = safe_get_bool(body, "include_stats", true);
    bool include_deleted = safe_get_bool(body, "include_deleted", false);

    json report;

    report["report_type"] = "media_inventory";
    report["generated_ts"] = std::stoll(now_ms());
    report["generated_iso"] = iso8601_now();

    if (include_stats) {
        std::lock_guard<std::mutex> lock(db::media_mutex);

        int total = 0, local = 0, remote = 0, quarantined = 0;
        int64_t total_bytes = 0;

        for (const auto& [key, rec] : db::media) {
            if (!include_deleted && (rec.hard_deleted || rec.soft_deleted)) continue;
            total++;
            if (rec.is_remote) remote++; else local++;
            if (rec.quarantined) quarantined++;
            total_bytes += rec.media_length;
        }

        report["summary"] = {
            {"total_media", total},
            {"local_media", local},
            {"remote_media", remote},
            {"quarantined_media", quarantined},
            {"total_bytes", total_bytes},
            {"total_formatted", format_bytes(total_bytes)}
        };
    }

    if (include_details) {
        std::lock_guard<std::mutex> lock(db::media_mutex);

        json media_list = json::array();
        int export_limit = static_cast<int>(safe_get_int64(body, "export_limit", 1000));
        int count = 0;

        for (const auto& [key, rec] : db::media) {
            if (!include_deleted && (rec.hard_deleted || rec.soft_deleted)) continue;
            if (count >= export_limit) break;
            media_list.push_back(media_to_json(rec));
            count++;
        }
        report["media"] = media_list;
        report["exported_count"] = count;
        report["export_limit"] = export_limit;
        report["truncated"] = (count >= export_limit &&
            count < static_cast<int>(db::media.size()));
    }

    report["format"] = format;
    report["status"] = "success";

    return report;
}

// ============================================================================
// Router dispatch table for media tools endpoints
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

std::vector<RouteEntry> build_media_routes() {
    std::vector<RouteEntry> routes;

    // Statistics (exact match before prefix routes)
    routes.push_back({"GET",  "/_synapse/admin/v1/media/statistics", false,
        admin_media_statistics});
    routes.push_back({"GET",  "/_synapse/admin/v1/media/top_media", false,
        admin_top_media});
    routes.push_back({"GET",  "/_synapse/admin/v1/media/recently_accessed", false,
        admin_recently_accessed_media});
    routes.push_back({"GET",  "/_synapse/admin/v1/media/health", false,
        admin_media_health});

    // Cleanup
    routes.push_back({"POST", "/_synapse/admin/v1/media/cleanup", false,
        admin_media_cleanup});
    routes.push_back({"GET",  "/_synapse/admin/v1/media/cleanup_log", false,
        admin_get_cleanup_log});

    // Retention policy
    routes.push_back({"GET",    "/_synapse/admin/v1/media/retention_policy", false,
        admin_get_media_retention_policy});
    routes.push_back({"POST",   "/_synapse/admin/v1/media/retention_policy", false,
        admin_set_media_retention_policy});
    routes.push_back({"DELETE", "/_synapse/admin/v1/media/retention_policy", false,
        admin_delete_retention_policy});

    // URL previews
    routes.push_back({"GET",    "/_synapse/admin/v1/media/url_previews", false,
        admin_list_url_previews});
    routes.push_back({"DELETE", "/_synapse/admin/v1/media/url_previews", false,
        admin_clear_url_previews});
    routes.push_back({"POST",   "/_synapse/admin/v1/media/url_previews/refresh", false,
        admin_refresh_url_preview});

    // Thumbnails
    routes.push_back({"GET",    "/_synapse/admin/v1/media/thumbnails", false,
        admin_list_thumbnails});
    routes.push_back({"DELETE", "/_synapse/admin/v1/media/thumbnails", false,
        admin_clear_thumbnails});

    // Purge remote
    routes.push_back({"POST", "/_synapse/admin/v1/media/purge_remote", false,
        admin_purge_remote_media});

    // Bulk operations
    routes.push_back({"POST", "/_synapse/admin/v1/media/bulk_quarantine", false,
        admin_bulk_quarantine});
    routes.push_back({"POST", "/_synapse/admin/v1/media/bulk_delete", false,
        admin_bulk_delete});

    // Quarantine/unquarantine room
    routes.push_back({"POST", "/_synapse/admin/v1/media/quarantine_room", false,
        admin_quarantine_room_media});
    routes.push_back({"POST", "/_synapse/admin/v1/media/unquarantine_room", false,
        admin_unquarantine_room_media});

    // Quarantine room listing
    routes.push_back({"GET", "/_synapse/admin/v1/media/quarantine_rooms", false,
        admin_list_quarantine_rooms});

    // Protect media
    routes.push_back({"POST", "/_synapse/admin/v1/media/protect", false,
        admin_protect_media});

    // User and room media listing
    routes.push_back({"GET", "/_synapse/admin/v1/media/user_media", false,
        admin_list_user_media});
    routes.push_back({"GET", "/_synapse/admin/v1/media/room_media", false,
        admin_list_room_media});

    // Recover soft-deleted media
    routes.push_back({"POST", "/_synapse/admin/v1/media/recover", false,
        admin_recover_media});

    // Audit log
    routes.push_back({"GET", "/_synapse/admin/v1/media/audit_log", false,
        admin_media_audit_log});

    // Export report
    routes.push_back({"POST", "/_synapse/admin/v1/media/export_report", false,
        admin_export_media_report});

    // List all media (exact match)
    routes.push_back({"GET", "/_synapse/admin/v1/media", false,
        admin_list_media});

    // Per-media operations (prefix: /_synapse/admin/v1/media/{origin}/{media_id}/...)
    routes.push_back({"GET", "/_synapse/admin/v1/media/", true,
        [](const json& p, const json& b, const std::string& rp) -> json {
            auto parts = parse_media_path(rp);
            if (!parts.valid) {
                return error_response("M_UNKNOWN",
                    "Invalid media path: " + rp, 404);
            }
            if (parts.action.empty()) {
                return admin_media_details(p, b, rp);
            }
            if (parts.action == "quarantine")
                return admin_quarantine_media(p, b, rp);
            if (parts.action == "unquarantine")
                return admin_unquarantine_media(p, b, rp);
            if (parts.action == "soft_delete")
                return admin_soft_delete_media(p, b, rp);
            if (parts.action == "delete")
                return admin_hard_delete_media(p, b, rp);
            return error_response("M_UNKNOWN",
                "Unknown media action: " + parts.action, 404);
        }});

    // POST for quarantine/unquarantine (synapse also supports POST)
    routes.push_back({"POST", "/_synapse/admin/v1/media/", true,
        [](const json& p, const json& b, const std::string& rp) -> json {
            auto parts = parse_media_path(rp);
            if (!parts.valid) {
                return error_response("M_UNKNOWN",
                    "Invalid media path: " + rp, 404);
            }
            if (parts.action == "quarantine")
                return admin_quarantine_media(p, b, rp);
            if (parts.action == "unquarantine")
                return admin_unquarantine_media(p, b, rp);
            if (parts.action == "soft_delete")
                return admin_soft_delete_media(p, b, rp);
            return error_response("M_UNKNOWN",
                "Unknown media POST action: " + parts.action, 404);
        }});

    // DELETE for media (hard delete)
    routes.push_back({"DELETE", "/_synapse/admin/v1/media/", true,
        [](const json& p, const json& b, const std::string& rp) -> json {
            auto parts = parse_media_path(rp);
            if (!parts.valid) {
                return error_response("M_UNKNOWN",
                    "Invalid media path: " + rp, 404);
            }
            // Any DELETE on media path is hard delete
            return admin_hard_delete_media(p, b, rp);
        }});

    return routes;
}

// ============================================================================
// Public API: entry point for media admin request dispatching
// ============================================================================

json dispatch_media_tools_request(const std::string& method,
                                   const std::string& path,
                                   const json& params,
                                   const json& body) {
    static std::vector<RouteEntry> routes = build_media_routes();

    for (const auto& route : routes) {
        if (route.method != method) continue;

        if (route.is_prefix) {
            if (path.compare(0, route.path_pattern.size(),
                             route.path_pattern) == 0) {
                // Don't match if it's one of the exact-match endpoints
                // that happen to share the prefix (e.g., /_synapse/admin/v1/media/statistics)
                std::string suffix = path.substr(route.path_pattern.size());
                if (!suffix.empty() && suffix.find('/') == std::string::npos) {
                    // This is something like /_synapse/admin/v1/media/statistics
                    // which shouldn't be handled by the prefix handler
                    continue;
                }
                return route.handler(params, body, path);
            }
        } else {
            if (path == route.path_pattern) {
                return route.handler(params, body, path);
            }
        }
    }

    // Also check the longer pattern for /v1/media/{origin}/{media_id}
    // (exact-match routes like /v1/media/statistics should have been caught above)
    {
        auto parts = parse_media_path(path);
        if (parts.valid) {
            if (method == "GET" && parts.action.empty()) {
                return admin_media_details(params, body, path);
            }
            if ((method == "POST" || method == "PUT") && parts.action == "quarantine") {
                return admin_quarantine_media(params, body, path);
            }
            if ((method == "POST" || method == "PUT") && parts.action == "unquarantine") {
                return admin_unquarantine_media(params, body, path);
            }
            if (method == "POST" && parts.action == "soft_delete") {
                return admin_soft_delete_media(params, body, path);
            }
            if (method == "DELETE") {
                return admin_hard_delete_media(params, body, path);
            }
        }
        if (parts.valid) {
            return error_response("M_UNKNOWN",
                "Unknown method/action: " + method + " " + parts.action, 405);
        }
    }

    return error_response("M_UNRECOGNIZED",
        "Unrecognized media endpoint: " + method + " " + path, 404);
}

// ============================================================================
// Initialization — seed demo/test data for the media subsystem
// ============================================================================

void init_media_tools(const std::string& server_name) {
    std::string ts = now_ms();

    {
        std::lock_guard<std::mutex> lock(db::media_mutex);

        // Seed some demo local media
        struct DemoMedia {
            std::string media_id;
            std::string media_type;
            std::string upload_name;
            std::string user_id;
            std::string room_id;
            int64_t size;
            int64_t access_count;
            int64_t age_offset_ms;
            bool is_remote;
            int w;
            int h;
        };

        std::vector<DemoMedia> demo_media = {
            {"abc123def456789abcdef12345", "image/png", "screenshot.png",
             "@admin:" + server_name, "!general:" + server_name,
             245760, 42, 0, false, 1920, 1080},
            {"def456abc789012def456abc78", "image/jpeg", "photo.jpg",
             "@alice:" + server_name, "!random:" + server_name,
             1048576, 15, 3600000, false, 2048, 1536},
            {"ghi789jkl012345ghi789jkl01", "video/mp4", "meeting_recording.mp4",
             "@bob:" + server_name, "!general:" + server_name,
             52428800, 8, 86400000, false, 1920, 1080},
            {"jkl012mno345678jkl012mno34", "application/pdf", "document.pdf",
             "@admin:" + server_name, "", 1572864, 3, 172800000, false, 0, 0},
            {"mno345pqr678901mno345pqr67", "audio/ogg", "voice_message.ogg",
             "@alice:" + server_name, "!random:" + server_name,
             65536, 120, 43200000, false, 0, 0},
            {"pqr678stu901234pqr678stu90", "image/gif", "animated.gif",
             "@bob:" + server_name, "", 3145728, 256, 604800000, false, 480, 360},
            {"stu901vwx234567stu901vwx23", "image/webp", "sticker.webp",
             "@alice:" + server_name, "!general:" + server_name,
             81920, 500, 0, false, 512, 512},
            {"vwx234yza567890vwx234yza56", "video/webm", "clip.webm",
             "@admin:" + server_name, "", 15728640, 32, 2592000000, false, 1280, 720},
            {"yza567bcd890123yza567bcd89", "image/jpeg", "profile_pic.jpg",
             "@bob:" + server_name, "", 131072, 88, 0, false, 256, 256},
        };

        // Remote media
        struct DemoMedia remote_media[] = {
            {"rem001rem002rem003rem001001", "image/png", "remote_logo.png",
             "@remote_user:matrix.org", "", 98304, 5, 1209600000, true, 800, 600},
            {"rem002rem003rem004rem002002", "image/jpeg", "shared_photo.jpg",
             "@another_user:example.com", "", 2097152, 12, 2592000000, true, 4032, 3024},
            {"rem003rem004rem005rem003003", "video/mp4", "trailer.mp4",
             "@media_bot:other.org", "", 104857600, 2, 5184000000, true, 3840, 2160},
        };

        for (const auto& dm : demo_media) {
            db::MediaRecord rec;
            rec.media_id = dm.media_id;
            rec.origin = server_name;
            rec.media_type = dm.media_type;
            rec.upload_name = dm.upload_name;
            rec.user_id = dm.user_id;
            rec.room_id = dm.room_id;
            rec.created_ts = std::to_string(std::stoll(ts) - dm.age_offset_ms);
            rec.last_access_ts = std::to_string(std::stoll(ts) -
                (dm.age_offset_ms / 2));
            rec.media_length = dm.size;
            rec.access_count = dm.access_count;
            rec.is_remote = dm.is_remote;
            rec.remote_server = dm.is_remote ? dm.user_id.substr(
                dm.user_id.find(':') + 1) : "";
            rec.width = dm.w;
            rec.height = dm.h;
            rec.file_hash_sha256 = sha256(dm.media_id + dm.upload_name);
            rec.etag = "\"" + random_hex(32) + "\"";
            rec.content_disposition = (dm.media_type.find("image/") == 0) ?
                "inline" : "attachment";
            rec.blurhash = (dm.w > 0) ? ("L" + random_hex(6)) : "";
            rec.thumbnail_count = (dm.w > 0) ? (rand() % 5 + 1) : 0;

            std::string key = media_key(rec.origin, rec.media_id);
            db::media[key] = rec;

            if (!dm.room_id.empty()) {
                db::room_media[dm.room_id].push_back(key);
            }
            if (!dm.user_id.empty()) {
                db::user_media[dm.user_id].push_back(key);
            }
        }

        for (const auto& dm : remote_media) {
            db::MediaRecord rec;
            rec.media_id = dm.media_id;
            rec.origin = dm.user_id.substr(dm.user_id.find(':') + 1);
            rec.media_type = dm.media_type;
            rec.upload_name = dm.upload_name;
            rec.user_id = dm.user_id;
            rec.room_id = dm.room_id;
            rec.created_ts = std::to_string(std::stoll(ts) - dm.age_offset_ms);
            rec.last_access_ts = std::to_string(std::stoll(ts) -
                (dm.age_offset_ms / 2));
            rec.media_length = dm.size;
            rec.access_count = dm.access_count;
            rec.is_remote = true;
            rec.remote_server = dm.user_id.substr(dm.user_id.find(':') + 1);
            rec.width = dm.w;
            rec.height = dm.h;
            rec.file_hash_sha256 = sha256(dm.media_id + dm.upload_name);
            rec.etag = "\"" + random_hex(32) + "\"";
            rec.content_disposition = "inline";

            std::string key = media_key(rec.origin, rec.media_id);
            db::media[key] = rec;

            if (!dm.room_id.empty()) {
                db::room_media[dm.room_id].push_back(key);
            }
            if (!dm.user_id.empty()) {
                db::user_media[dm.user_id].push_back(key);
            }
        }
    }

    // Seed URL preview cache
    {
        std::lock_guard<std::mutex> lock(db::previews_mutex);

        std::vector<std::pair<std::string, std::string>> preview_urls = {
            {"https://matrix.org", "Matrix - An open network for secure, decentralized communication"},
            {"https://spec.matrix.org", "Matrix Specification"},
            {"https://github.com/matrix-org", "Matrix.org GitHub"},
        };

        for (const auto& [url, title] : preview_urls) {
            db::UrlPreviewRecord rec;
            rec.url = url;
            rec.url_hash = sha256(url);
            rec.title = title;
            rec.description = "This is a cached preview for " + url;
            rec.type = "og";
            rec.site_name = extract_server_name(url);
            rec.fetched_ts = std::to_string(std::stoll(ts) - 3600000);
            rec.expires_ts = std::to_string(std::stoll(ts) + 86400000);
            rec.response_time_ms = 150;
            rec.http_status = 200;
            rec.access_count = rand() % 50;
            rec.ttl_ms = 86400000;
            rec.stale = false;
            db::url_previews[rec.url_hash] = rec;
        }
    }

    // Seed thumbnails
    {
        std::lock_guard<std::mutex> lock(db::thumbnails_mutex);

        struct DemoTN {
            std::string media_id;
            std::string origin;
            std::string method;
            int w;
            int h;
            int64_t size;
            bool remote;
        };

        std::vector<DemoTN> demo_thumbs = {
            {"abc123def456789abcdef12345", server_name, "scale", 800, 450, 102400, false},
            {"abc123def456789abcdef12345", server_name, "crop", 96, 96, 16384, false},
            {"def456abc789012def456abc78", server_name, "scale", 1024, 768, 262144, false},
            {"def456abc789012def456abc78", server_name, "crop", 128, 128, 24576, false},
            {"ghi789jkl012345ghi789jkl01", server_name, "scale", 640, 360, 131072, false},
            {"stu901vwx234567stu901vwx23", server_name, "scale", 256, 256, 40960, false},
            {"pqr678stu901234pqr678stu90", server_name, "scale", 240, 180, 65536, false},
            {"rem001rem002rem003rem001001", "matrix.org", "scale", 400, 300, 49152, true},
        };

        for (const auto& dt : demo_thumbs) {
            db::ThumbnailRecord rec;
            rec.thumbnail_id = "tn_" + random_alphanumeric(16);
            rec.media_id = dt.media_id;
            rec.origin = dt.origin;
            rec.method = dt.method;
            rec.width = dt.w;
            rec.height = dt.h;
            rec.file_size = dt.size;
            rec.content_type = "image/jpeg";
            rec.created_ts = ts;
            rec.last_access_ts = ts;
            rec.access_count = rand() % 100;
            rec.is_remote = dt.remote;

            db::thumbnails[rec.thumbnail_id] = rec;
            std::string key = media_key(dt.origin, dt.media_id);
            db::media_thumbnails[key].push_back(rec.thumbnail_id);
        }
    }

    // Seed retention policies
    {
        std::lock_guard<std::mutex> lock(db::policy_mutex);

        db::MediaRetentionPolicy default_policy;
        default_policy.policy_id = "default_retention";
        default_policy.name = "Default Retention";
        default_policy.description = "Default media retention policy: remove media "
            "not accessed for 180 days, remote media older than 90 days";
        default_policy.enabled = true;
        default_policy.applies_to = "all";
        default_policy.max_idle_ms = 180LL * 24 * 3600 * 1000;
        default_policy.delete_remote = true;
        default_policy.delete_quarantined = false;
        default_policy.delete_thumbnails = true;
        default_policy.created_ts = ts;
        default_policy.updated_ts = ts;
        db::retention_policies[default_policy.policy_id] = default_policy;

        db::MediaRetentionPolicy large_media_policy;
        large_media_policy.policy_id = "large_media_cleanup";
        large_media_policy.name = "Large Media Cleanup";
        large_media_policy.description = "Remove media files larger than 100MB "
            "that haven't been accessed in 30 days";
        large_media_policy.enabled = false;
        large_media_policy.applies_to = "all";
        large_media_policy.max_size_bytes = 100LL * 1024 * 1024;
        large_media_policy.max_idle_ms = 30LL * 24 * 3600 * 1000;
        large_media_policy.delete_remote = true;
        large_media_policy.delete_thumbnails = true;
        large_media_policy.created_ts = ts;
        large_media_policy.updated_ts = ts;
        db::retention_policies[large_media_policy.policy_id] = large_media_policy;
    }

    // Seed access log
    {
        std::lock_guard<std::mutex> lock(db::media_access_log_mutex);

        for (int i = 0; i < 30; ++i) {
            db::MediaAccessLog alog;
            alog.log_id = "alog_" + random_alphanumeric(8);
            alog.media_id = (i % 5 == 0) ? "abc123def456789abcdef12345" :
                            (i % 5 == 1) ? "stu901vwx234567stu901vwx23" :
                            "def456abc789012def456abc78";
            alog.origin = server_name;
            alog.user_id = (i % 3 == 0) ? "@admin:" + server_name :
                           (i % 3 == 1) ? "@alice:" + server_name :
                           "@bob:" + server_name;
            alog.access_ts = std::to_string(std::stoll(ts) - (i * 3600000));
            alog.ip_address = "192.168.1." + std::to_string(i % 255);
            alog.user_agent = "Element/1.11." + std::to_string(i % 10);
            alog.room_id = "!general:" + server_name;
            alog.bytes_transferred = 100000 + (i * 5000);
            alog.http_status = 200;
            db::media_access_log.push_back(alog);
        }
    }
}

// ============================================================================
// Health check for media subsystem
// ============================================================================

json media_tools_health_check() {
    return admin_media_health(json::object(), json::object(), "");
}

// ============================================================================
// Statistics aggregation
// ============================================================================

json get_media_admin_statistics() {
    json stats;

    {
        std::lock_guard<std::mutex> lock(db::media_mutex);
        int total = static_cast<int>(db::media.size());
        int local = 0, remote = 0, quarantined = 0, soft_deleted = 0;
        int64_t total_bytes = 0;
        int64_t total_accesses = 0;

        for (const auto& [key, rec] : db::media) {
            if (rec.is_remote) remote++; else local++;
            if (rec.quarantined) quarantined++;
            if (rec.soft_deleted) soft_deleted++;
            total_bytes += rec.media_length;
            total_accesses += rec.access_count;
        }

        stats["media"] = {
            {"total", total},
            {"local", local},
            {"remote", remote},
            {"quarantined", quarantined},
            {"soft_deleted", soft_deleted},
            {"total_bytes", total_bytes},
            {"total_formatted", format_bytes(total_bytes)},
            {"total_accesses", total_accesses}
        };
    }

    {
        std::lock_guard<std::mutex> lock(db::previews_mutex);
        stats["url_previews"] = {
            {"cached", static_cast<int>(db::url_previews.size())}
        };
    }

    {
        std::lock_guard<std::mutex> lock(db::thumbnails_mutex);
        int64_t thumb_bytes = 0;
        for (const auto& [tid, rec] : db::thumbnails) {
            thumb_bytes += rec.file_size;
        }
        stats["thumbnails"] = {
            {"total", static_cast<int>(db::thumbnails.size())},
            {"total_bytes", thumb_bytes},
            {"total_formatted", format_bytes(thumb_bytes)}
        };
    }

    {
        std::lock_guard<std::mutex> lock(db::policy_mutex);
        int enabled = 0;
        for (const auto& [pid, pol] : db::retention_policies) {
            if (pol.enabled) enabled++;
        }
        stats["retention_policies"] = {
            {"total", static_cast<int>(db::retention_policies.size())},
            {"enabled", enabled}
        };
    }

    {
        std::lock_guard<std::mutex> lock(db::quarantine_room_mutex);
        stats["quarantine_rooms"] = {
            {"total", static_cast<int>(db::quarantine_rooms.size())}
        };
    }

    stats["generated_ts"] = std::stoll(now_ms());
    return stats;
}

} // namespace admin
} // namespace progressive
