// SPDX-License-Identifier: AGPL-3.0-only
// Progressive Matrix Server — Media Store Pipeline
// Upload handler, download handler, thumbnail pipeline, URL preview,
// remote media proxy, media storage, deduplication, quarantine, admin API,
// retention policy, and statistics.
// Copyright (c) 2026 Progressive Contributors

#include "../json.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <deque>
#include <exception>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
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
#include <unordered_map>
#include <unordered_set>
#include <variant>
#include <vector>

#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <arpa/inet.h>
#include <dlfcn.h>

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/md5.h>

// ============================================================================
// Optional: ffmpeg/libav for thumbnail extraction from videos
// If not present, video thumbnailing degrades gracefully.
// ============================================================================
#ifndef PROGRESSIVE_NO_FFMPEG
#include <libavcodec/avcodec.h>
#include <libavformat/avformat.h>
#include <libswscale/swscale.h>
#include <libavutil/imgutils.h>
#endif

namespace progressive {
namespace media {

namespace fs = std::filesystem;

// ============================================================================
// Forward declarations
// ============================================================================

static std::string sha256_hex(std::string_view data);
static std::string sha256_hex(const std::vector<uint8_t>& data);
static std::string sha256_file(const std::filesystem::path& path);
static std::string md5_hex(const std::vector<uint8_t>& data);
static std::string to_lower(std::string s);
static std::string extract_extension(const std::string& filename);
static std::string mime_from_extension(const std::string& ext);
static std::string detect_mime_type(const std::vector<uint8_t>& data);
static std::string detect_mime_type_file(const std::filesystem::path& path);
static std::string generate_media_id();
static std::string sanitize_path_component(const std::string& s);
static int64_t now_ms();
static int64_t now_sec();
static std::string url_encode(const std::string& s);
static std::string url_decode(const std::string& s);
static bool validate_mxc_uri(const std::string& uri, std::string& server, std::string& media_id);
static std::string mxc_uri(const std::string& server_name, const std::string& media_id);

// ============================================================================
// Configuration constants and type definitions
// ============================================================================

// Media type categories for size-limits
enum class MediaCategory : uint8_t {
    IMAGE       = 0,
    VIDEO       = 1,
    AUDIO       = 2,
    ARCHIVE     = 3,
    DOCUMENT    = 4,
    OTHER       = 5,
    UNKNOWN     = 6
};

// Quarantine reason codes
enum class QuarantineReason : uint8_t {
    NONE              = 0,
    CONTENT_SCAN      = 1,  // flagged by content scanner
    USER_REPORT       = 2,  // reported by user
    ADMIN_MANUAL      = 3,  // admin action
    AUTOMATED_RULE    = 4,  // automated rule match
    FEDERATED_FLAG    = 5,  // flagged by remote server
    LEGAL_TAKEDOWN    = 6   // DMCA / legal
};

// Thumbnail method
enum class ThumbMethod : uint8_t {
    SCALE       = 0,  // scale to fit within bounds, preserve aspect
    CROP        = 1   // crop to exact dimensions
};

// Thumbnail output format
enum class ThumbFormat : uint8_t {
    JPEG        = 0,
    PNG         = 1,
    WEBP        = 2
};

// Delete type
enum class DeleteType : uint8_t {
    SOFT        = 0,  // mark as deleted, retain for recovery window
    HARD        = 1   // immediate permanent deletion
};

// ============================================================================
// Configurable limits
// ============================================================================

constexpr size_t DEFAULT_MAX_UPLOAD_SIZE          = 50 * 1024 * 1024;   // 50 MB
constexpr size_t DEFAULT_MAX_IMAGE_SIZE           = 50 * 1024 * 1024;
constexpr size_t DEFAULT_MAX_VIDEO_SIZE           = 100 * 1024 * 1024;  // 100 MB
constexpr size_t DEFAULT_MAX_AUDIO_SIZE           = 50 * 1024 * 1024;
constexpr size_t DEFAULT_MAX_ARCHIVE_SIZE         = 25 * 1024 * 1024;
constexpr size_t DEFAULT_MAX_DOCUMENT_SIZE        = 50 * 1024 * 1024;
constexpr size_t DEFAULT_MAX_OTHER_SIZE           = 10 * 1024 * 1024;
constexpr size_t DEFAULT_MAX_THUMB_WIDTH          = 800;
constexpr size_t DEFAULT_MAX_THUMB_HEIGHT         = 600;
constexpr size_t DEFAULT_THUMB_QUALITY            = 80;
constexpr size_t DEFAULT_URL_PREVIEW_TIMEOUT_SEC  = 10;
constexpr size_t DEFAULT_URL_PREVIEW_MAX_PAYLOAD  = 2 * 1024 * 1024;
constexpr size_t DEFAULT_URL_PREVIEW_MAX_IMAGE    = 1 * 1024 * 1024;
constexpr size_t DEFAULT_REMOTE_MEDIA_TIMEOUT_SEC = 30;
constexpr size_t DEFAULT_REMOTE_MEDIA_MAX_SIZE    = 100 * 1024 * 1024;
constexpr size_t DEFAULT_DEDUP_CACHE_SIZE         = 10000;
constexpr size_t DEFAULT_LRU_CACHE_SIZE           = 1000;
constexpr size_t DEFAULT_DELETE_RECOVERY_WINDOW_SEC = 86400 * 30;  // 30 days
constexpr size_t DEFAULT_RETENTION_MAX_AGE_SEC    = 86400 * 365;    // 1 year
constexpr size_t DEFAULT_QUARANTINE_MAX_AGE_SEC   = 86400 * 90;     // 90 days
constexpr size_t DEFAULT_STATS_WINDOW_SEC         = 3600;           // 1 hour
constexpr size_t DEFAULT_STORAGE_QUOTA_PER_USER   = 1024ULL * 1024 * 1024; // 1 GB
constexpr size_t DEFAULT_STORAGE_QUOTA_GLOBAL     = 100ULL * 1024 * 1024 * 1024; // 100 GB
constexpr size_t DEFAULT_THUMBNAIL_PRESETS_COUNT  = 5;
constexpr size_t DEFAULT_MIN_THUMB_WIDTH          = 32;
constexpr size_t DEFAULT_MIN_THUMB_HEIGHT         = 32;

// ============================================================================
// Thumbnail presets
// ============================================================================

struct ThumbnailPreset {
    size_t width;
    size_t height;
    ThumbMethod method;
    ThumbFormat format;
};

static const ThumbnailPreset THUMBNAIL_PRESETS[] = {
    {32, 32, ThumbMethod::CROP, ThumbFormat::JPEG},
    {96, 96, ThumbMethod::CROP, ThumbFormat::JPEG},
    {320, 240, ThumbMethod::SCALE, ThumbFormat::JPEG},
    {640, 480, ThumbMethod::SCALE, ThumbFormat::JPEG},
    {800, 600, ThumbMethod::SCALE, ThumbFormat::JPEG},
};

// ============================================================================
// Media info record
// ============================================================================

struct MediaRecord {
    std::string media_id;
    std::string storage_path;      // relative to media base dir
    std::string content_hash;      // SHA-256 of content
    std::string content_type;      // MIME type
    std::string upload_name;       // original filename
    std::string user_id;           // uploader
    std::string origin;            // empty for local, server name for remote
    int64_t media_length = 0;      // file size in bytes
    int64_t created_ts = 0;        // epoch ms
    int64_t last_access_ts = 0;    // epoch ms
    int64_t access_count = 0;
    MediaCategory category = MediaCategory::UNKNOWN;
    bool quarantined = false;
    QuarantineReason quarantine_reason = QuarantineReason::NONE;
    std::string quarantine_by;     // user ID who quarantined
    int64_t quarantine_ts = 0;
    bool safe_from_quarantine = false;
    bool deleted = false;          // soft-delete flag
    int64_t deleted_ts = 0;
    bool is_remote = false;
    std::string etag;
    int64_t expires_ts = 0;        // for remote cache expiry
    // Thumbnails
    struct ThumbEntry {
        int width = 0;
        int height = 0;
        ThumbMethod method = ThumbMethod::SCALE;
        ThumbFormat format = ThumbFormat::JPEG;
        std::string thumb_path;
        int64_t thumb_length = 0;
        std::string thumb_hash;
    };
    std::vector<ThumbEntry> thumbnails;
};

// ============================================================================
// URL preview record
// ============================================================================

struct UrlPreviewRecord {
    std::string url;
    std::string url_hash;          // SHA-256 of url
    std::string og_title;
    std::string og_description;
    std::string og_image_url;
    std::string og_type;
    std::string og_site_name;
    std::string twitter_card;
    std::string oembed_json;
    std::string image_media_id;    // cached og:image as local media
    int64_t fetched_ts = 0;
    int64_t expires_ts = 0;
    int64_t og_image_width = 0;
    int64_t og_image_height = 0;
    int64_t og_image_size = 0;
    bool has_preview = false;
};

// ============================================================================
// Statistics counters
// ============================================================================

struct MediaStats {
    std::atomic<int64_t> total_uploads{0};
    std::atomic<int64_t> total_downloads{0};
    std::atomic<int64_t> total_bytes_uploaded{0};
    std::atomic<int64_t> total_bytes_downloaded{0};
    std::atomic<int64_t> total_thumbnails_generated{0};
    std::atomic<int64_t> total_thumbnails_served{0};
    std::atomic<int64_t> total_remote_proxied{0};
    std::atomic<int64_t> total_bytes_remote_proxied{0};
    std::atomic<int64_t> total_dedup_hits{0};
    std::atomic<int64_t> total_dedup_misses{0};
    std::atomic<int64_t> total_quarantine_actions{0};
    std::atomic<int64_t> total_deletes_soft{0};
    std::atomic<int64_t> total_deletes_hard{0};
    std::atomic<int64_t> total_url_previews_fetched{0};
    std::atomic<int64_t> total_url_previews_served{0};
    std::atomic<int64_t> current_active_uploads{0};
    std::atomic<size_t> current_storage_bytes{0};
    std::atomic<size_t> current_remote_cache_bytes{0};
    std::atomic<size_t> current_thumbnail_cache_bytes{0};

    // Per-category breakdown
    std::array<std::atomic<int64_t>, 7> uploads_by_category{};
    std::array<std::atomic<int64_t>, 7> bytes_by_category{};

    // Per-user tracking (keyed by user_id)
    struct UserStat {
        std::atomic<int64_t> upload_count{0};
        std::atomic<size_t> total_bytes{0};
        std::atomic<int64_t> last_upload_ts{0};
    };
    std::unordered_map<std::string, UserStat> per_user;
    std::shared_mutex user_stat_mutex;

    int64_t window_start_ts = 0;
    std::mutex window_mutex;

    void reset_window() {
        std::lock_guard lk(window_mutex);
        window_start_ts = now_sec();
        total_uploads = 0;
        total_downloads = 0;
        total_bytes_uploaded = 0;
        total_bytes_downloaded = 0;
        total_thumbnails_generated = 0;
        total_remote_proxied = 0;
        for (auto& a : uploads_by_category) a = 0;
        for (auto& a : bytes_by_category) a = 0;
    }

    nlohmann::json snapshot() const {
        nlohmann::json j;
        int64_t ws;
        {
            std::lock_guard lk(const_cast<std::mutex&>(window_mutex));
            ws = window_start_ts;
        }
        j["window_start_ts"] = ws;
        j["total_uploads"] = total_uploads.load();
        j["total_downloads"] = total_downloads.load();
        j["total_bytes_uploaded"] = total_bytes_uploaded.load();
        j["total_bytes_downloaded"] = total_bytes_downloaded.load();
        j["total_thumbnails_generated"] = total_thumbnails_generated.load();
        j["total_thumbnails_served"] = total_thumbnails_served.load();
        j["total_remote_proxied"] = total_remote_proxied.load();
        j["total_bytes_remote_proxied"] = total_bytes_remote_proxied.load();
        j["total_dedup_hits"] = total_dedup_hits.load();
        j["total_dedup_misses"] = total_dedup_misses.load();
        j["total_quarantine_actions"] = total_quarantine_actions.load();
        j["total_deletes_soft"] = total_deletes_soft.load();
        j["total_deletes_hard"] = total_deletes_hard.load();
        j["total_url_previews_fetched"] = total_url_previews_fetched.load();
        j["total_url_previews_served"] = total_url_previews_served.load();
        j["current_active_uploads"] = current_active_uploads.load();
        j["current_storage_bytes"] = current_storage_bytes.load();
        j["current_remote_cache_bytes"] = current_remote_cache_bytes.load();
        j["current_thumbnail_cache_bytes"] = current_thumbnail_cache_bytes.load();
        nlohmann::json cats = nlohmann::json::array();
        for (size_t i = 0; i < 7; ++i) {
            nlohmann::json c;
            c["category"] = static_cast<int>(i);
            c["count"] = uploads_by_category[i].load();
            c["bytes"] = bytes_by_category[i].load();
            cats.push_back(c);
        }
        j["by_category"] = cats;
        return j;
    }
};

// ============================================================================
// MediaCategory classifier
// ============================================================================

static MediaCategory classify_mime_type(const std::string& mime) {
    if (mime.empty()) return MediaCategory::UNKNOWN;
    if (mime.starts_with("image/")) return MediaCategory::IMAGE;
    if (mime.starts_with("video/")) return MediaCategory::VIDEO;
    if (mime.starts_with("audio/")) return MediaCategory::AUDIO;
    if (mime == "application/zip" || mime == "application/gzip" ||
        mime == "application/x-tar" || mime == "application/x-xz" ||
        mime == "application/x-bzip2" || mime == "application/x-7z-compressed" ||
        mime.starts_with("application/x-rar") || mime == "application/x-compressed-tar")
        return MediaCategory::ARCHIVE;
    if (mime == "application/pdf" || mime == "text/plain" ||
        mime == "application/json" || mime == "text/csv" ||
        mime == "application/xml" || mime == "text/xml" ||
        mime == "application/rtf" || mime == "text/html" ||
        mime.starts_with("application/vnd.openxmlformats") ||
        mime.starts_with("application/msword") ||
        mime.starts_with("application/vnd.ms-"))
        return MediaCategory::DOCUMENT;
    if (mime == "application/octet-stream" || mime.empty())
        return MediaCategory::OTHER;
    if (mime.starts_with("application/") || mime.starts_with("text/"))
        return MediaCategory::DOCUMENT;
    return MediaCategory::OTHER;
}

static size_t max_size_for_category(MediaCategory cat) {
    switch (cat) {
        case MediaCategory::IMAGE:    return DEFAULT_MAX_IMAGE_SIZE;
        case MediaCategory::VIDEO:    return DEFAULT_MAX_VIDEO_SIZE;
        case MediaCategory::AUDIO:    return DEFAULT_MAX_AUDIO_SIZE;
        case MediaCategory::ARCHIVE:  return DEFAULT_MAX_ARCHIVE_SIZE;
        case MediaCategory::DOCUMENT: return DEFAULT_MAX_DOCUMENT_SIZE;
        case MediaCategory::OTHER:    return DEFAULT_MAX_OTHER_SIZE;
        default:                      return DEFAULT_MAX_UPLOAD_SIZE;
    }
}

// ============================================================================
// Utility implementations
// ============================================================================

static std::string sha256_hex(std::string_view data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, data.data(), data.size());
    SHA256_Final(hash, &ctx);
    std::ostringstream oss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    return oss.str();
}

static std::string sha256_hex(const std::vector<uint8_t>& data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, data.data(), data.size());
    SHA256_Final(hash, &ctx);
    std::ostringstream oss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    return oss.str();
}

static std::string sha256_file(const std::filesystem::path& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) return "";
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    std::array<char, 65536> buf{};
    while (file.good()) {
        file.read(buf.data(), buf.size());
        SHA256_Update(&ctx, buf.data(), file.gcount());
    }
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_Final(hash, &ctx);
    std::ostringstream oss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    return oss.str();
}

static std::string md5_hex(const std::vector<uint8_t>& data) {
    unsigned char hash[MD5_DIGEST_LENGTH];
    MD5_CTX ctx;
    MD5_Init(&ctx);
    MD5_Update(&ctx, data.data(), data.size());
    MD5_Final(hash, &ctx);
    std::ostringstream oss;
    for (int i = 0; i < MD5_DIGEST_LENGTH; ++i)
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    return oss.str();
}

static std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), ::tolower);
    return s;
}

static std::string extract_extension(const std::string& filename) {
    auto pos = filename.rfind('.');
    if (pos == std::string::npos) return "";
    std::string ext = filename.substr(pos + 1);
    // Don't include query parameters
    auto qpos = ext.find('?');
    if (qpos != std::string::npos) ext = ext.substr(0, qpos);
    return to_lower(ext);
}

static int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

static int64_t now_sec() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

static std::string generate_media_id() {
    static thread_local std::random_device rd;
    static thread_local std::mt19937_64 gen(rd());
    static thread_local std::uniform_int_distribution<> dis(0, 15);
    static const char hex[] = "0123456789abcdef";
    std::string id;
    id.reserve(32);
    for (int i = 0; i < 32; ++i) id += hex[dis(gen)];
    return id;
}

static std::string sanitize_path_component(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        if (c == '/' || c == '\\' || c == '\0' || c == '.' || c == ' ' ||
            c == '\r' || c == '\n' || c == '\t')
            continue;
        out += c;
    }
    if (out.empty()) return "_";
    return out.substr(0, 255);
}

static std::string url_encode(const std::string& s) {
    static const char hex[] = "0123456789ABCDEF";
    std::string out;
    out.reserve(s.size() * 3);
    for (char c : s) {
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~') {
            out += c;
        } else {
            out += '%';
            out += hex[(c >> 4) & 0xF];
            out += hex[c & 0xF];
        }
    }
    return out;
}

static std::string url_decode(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '%' && i + 2 < s.size() &&
            std::isxdigit(static_cast<unsigned char>(s[i+1])) &&
            std::isxdigit(static_cast<unsigned char>(s[i+2]))) {
            int hi = std::isdigit(s[i+1]) ? s[i+1]-'0' : std::toupper(s[i+1])-'A'+10;
            int lo = std::isdigit(s[i+2]) ? s[i+2]-'0' : std::toupper(s[i+2])-'A'+10;
            out += static_cast<char>((hi << 4) | lo);
            i += 2;
        } else if (s[i] == '+') {
            out += ' ';
        } else {
            out += s[i];
        }
    }
    return out;
}

static bool validate_mxc_uri(const std::string& uri, std::string& server, std::string& media_id) {
    if (!uri.starts_with("mxc://")) return false;
    std::string rest = uri.substr(6);
    auto slash_pos = rest.find('/');
    if (slash_pos == std::string::npos || slash_pos == 0) return false;
    server = rest.substr(0, slash_pos);
    media_id = rest.substr(slash_pos + 1);
    return !server.empty() && !media_id.empty();
}

static std::string mxc_uri(const std::string& server_name, const std::string& media_id) {
    return "mxc://" + server_name + "/" + media_id;
}

static std::string mime_from_extension(const std::string& ext) {
    static const std::unordered_map<std::string, std::string> map = {
        {"jpg", "image/jpeg"}, {"jpeg", "image/jpeg"}, {"png", "image/png"},
        {"gif", "image/gif"}, {"webp", "image/webp"}, {"avif", "image/avif"},
        {"bmp", "image/bmp"}, {"tiff", "image/tiff"}, {"tif", "image/tiff"},
        {"svg", "image/svg+xml"}, {"heic", "image/heic"}, {"heif", "image/heif"},
        {"ico", "image/x-icon"},
        {"mp4", "video/mp4"}, {"webm", "video/webm"}, {"ogv", "video/ogg"},
        {"mov", "video/quicktime"}, {"avi", "video/x-msvideo"},
        {"mkv", "video/x-matroska"}, {"flv", "video/x-flv"},
        {"mp3", "audio/mpeg"}, {"ogg", "audio/ogg"}, {"wav", "audio/wav"},
        {"wave", "audio/wav"}, {"flac", "audio/flac"}, {"aac", "audio/aac"},
        {"wma", "audio/x-ms-wma"}, {"m4a", "audio/mp4"}, {"opus", "audio/opus"},
        {"pdf", "application/pdf"}, {"txt", "text/plain"},
        {"json", "application/json"}, {"zip", "application/zip"},
        {"tar", "application/x-tar"}, {"gz", "application/gzip"},
        {"bz2", "application/x-bzip2"}, {"xz", "application/x-xz"},
        {"7z", "application/x-7z-compressed"}, {"rar", "application/vnd.rar"},
        {"doc", "application/msword"}, {"docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
        {"xls", "application/vnd.ms-excel"}, {"xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
        {"ppt", "application/vnd.ms-powerpoint"}, {"pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation"},
        {"rtf", "application/rtf"}, {"xml", "application/xml"},
        {"html", "text/html"}, {"htm", "text/html"}, {"css", "text/css"},
        {"js", "application/javascript"}, {"csv", "text/csv"},
        {"ttf", "font/ttf"}, {"otf", "font/otf"}, {"woff", "font/woff"},
        {"woff2", "font/woff2"},
    };
    auto it = map.find(to_lower(ext));
    return it != map.end() ? it->second : "application/octet-stream";
}

// ============================================================================
// Content-type detection via magic bytes
// ============================================================================

struct MagicSig {
    std::vector<uint8_t> bytes;
    size_t offset;
    std::string mime;
};

static const std::vector<MagicSig> MAGIC_SIGS = {
    // Images
    {{0xFF, 0xD8, 0xFF}, 0, "image/jpeg"},
    {{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}, 0, "image/png"},
    {{0x47, 0x49, 0x46, 0x38, 0x37, 0x61}, 0, "image/gif"},
    {{0x47, 0x49, 0x46, 0x38, 0x39, 0x61}, 0, "image/gif"},
    {{0x52, 0x49, 0x46, 0x46}, 0, "image/webp"},   // +WEBP subtype check
    {{0x42, 0x4D}, 0, "image/bmp"},
    {{0x49, 0x49, 0x2A, 0x00}, 0, "image/tiff"},
    {{0x4D, 0x4D, 0x00, 0x2A}, 0, "image/tiff"},
    {{0x00, 0x00, 0x01, 0x00}, 0, "image/x-icon"},
    // Video
    {{0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70}, 0, "video/mp4"},
    {{0x00, 0x00, 0x00, 0x1C, 0x66, 0x74, 0x79, 0x70}, 0, "video/mp4"},
    {{0x1A, 0x45, 0xDF, 0xA3}, 0, "video/webm"},
    {{0x4F, 0x67, 0x67, 0x53}, 0, "video/ogg"},
    {{0x00, 0x00, 0x00, 0x14, 0x66, 0x74, 0x79, 0x70, 0x71, 0x74, 0x20, 0x20}, 0, "video/quicktime"},
    // Audio
    {{0xFF, 0xFB}, 0, "audio/mpeg"},
    {{0xFF, 0xF3}, 0, "audio/mpeg"},
    {{0xFF, 0xF2}, 0, "audio/mpeg"},
    {{0x49, 0x44, 0x33}, 0, "audio/mpeg"},
    {{0x4F, 0x67, 0x67, 0x53}, 0, "audio/ogg"},
    {{0x66, 0x4C, 0x61, 0x43}, 0, "audio/flac"},
    {{0x52, 0x49, 0x46, 0x46}, 0, "audio/wav"},     // +WAVE subtype check
    // Archives
    {{0x50, 0x4B, 0x03, 0x04}, 0, "application/zip"},
    {{0x1F, 0x8B, 0x08}, 0, "application/gzip"},
    {{0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00}, 0, "application/x-xz"},
    {{0x42, 0x5A, 0x68}, 0, "application/x-bzip2"},
    {{0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C}, 0, "application/x-7z-compressed"},
    {{0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00}, 0, "application/vnd.rar"},
    // Documents
    {{0x25, 0x50, 0x44, 0x46, 0x2D}, 0, "application/pdf"},
    {{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}, 0, "application/msword"},
    {{0x3C, 0x3F, 0x78, 0x6D, 0x6C, 0x20}, 0, "application/xml"},
    {{0x3C, 0x68, 0x74, 0x6D, 0x6C}, 0, "text/html"},
    {{0x3C, 0x21, 0x44, 0x4F, 0x43, 0x54, 0x59, 0x50, 0x45}, 0, "text/html"},
    {{0x7B, 0x5C, 0x72, 0x74, 0x66}, 0, "application/rtf"},
    // Fonts
    {{0x00, 0x01, 0x00, 0x00, 0x00}, 0, "font/ttf"},
    {{0x4F, 0x54, 0x54, 0x4F}, 0, "font/otf"},
    {{0x77, 0x4F, 0x46, 0x46}, 0, "font/woff"},
    {{0x77, 0x4F, 0x46, 0x32}, 0, "font/woff2"},
};

static std::string detect_mime_type(const std::vector<uint8_t>& data) {
    if (data.empty()) return "application/octet-stream";

    // Try detecting SVG or XML text-based
    std::string_view head(reinterpret_cast<const char*>(data.data()),
                          std::min(data.size(), size_t(512)));
    if (head.find("<?xml") != std::string::npos ||
        head.find("<svg") != std::string::npos ||
        head.find("<SVG") != std::string::npos) {
        return "image/svg+xml";
    }
    if (head.starts_with("<!DOCTYPE html") || head.starts_with("<html") ||
        head.starts_with("<HTML") || head.starts_with("<head") ||
        head.starts_with("<HEAD")) {
        return "text/html";
    }

    // Magic bytes matching
    for (const auto& sig : MAGIC_SIGS) {
        if (data.size() >= sig.offset + sig.bytes.size()) {
            bool match = true;
            for (size_t i = 0; i < sig.bytes.size(); ++i) {
                if (data[sig.offset + i] != sig.bytes[i]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                // Special RIFF container handling
                if (sig.mime == "image/webp" || sig.mime == "audio/wav") {
                    if (data.size() >= 12) {
                        std::string subtype(reinterpret_cast<const char*>(&data[8]), 4);
                        if (subtype == "WEBP") return "image/webp";
                        if (subtype == "WAVE") return "audio/wav";
                    }
                    return sig.mime;
                }
                return sig.mime;
            }
        }
    }

    // Check for text/JSON
    bool is_text = true;
    bool maybe_json = (data.size() > 0 && (data[0] == '{' || data[0] == '['));
    for (size_t i = 0; i < std::min(data.size(), size_t(1024)); ++i) {
        if (data[i] == 0) { is_text = false; break; }
    }
    if (maybe_json && is_text) return "application/json";
    if (is_text) return "text/plain";

    return "application/octet-stream";
}

static std::string detect_mime_type_file(const std::filesystem::path& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) return "application/octet-stream";
    std::vector<uint8_t> buf(4096);
    file.read(reinterpret_cast<char*>(buf.data()), buf.size());
    buf.resize(file.gcount());
    return detect_mime_type(buf);
}

// ============================================================================
// Blocked extensions for security
// ============================================================================

static const std::unordered_set<std::string> BLOCKED_EXTENSIONS = {
    "exe", "com", "bat", "cmd", "msi", "scr", "pif", "cpl",
    "msc", "msp", "gadget", "reg", "vbs", "vbe", "js", "jse",
    "wsf", "wsh", "ps1", "ps1xml", "ps2", "ps2xml", "psc1", "psc2",
    "scf", "lnk", "inf", "url", "hta", "dll", "sys", "drv",
    "ocx", "app", "vb", "vba", "ws", "wsc",
    "jar", "class", "war", "ear", "jnlp",
    "dmg", "pkg", "app", "framework", "kext", "prefPane",
    "so", "elf", "run", "AppImage", "flatpak", "snap",
    "rpm", "deb", "bin",
    "php", "php3", "php4", "php5", "php7", "php8", "phtml", "pht",
    "asp", "aspx", "ascx", "ashx", "asmx", "axd", "cgi", "pl",
    "py", "pyc", "pyo", "pyd", "rb", "tcl", "lua",
    "swf", "fla", "action", "air",
    "hlp", "chm", "crt", "pem", "der", "pfx", "p12", "p7b", "p7c",
    "torrent", "magnet",
};

static bool is_extension_blocked(const std::string& ext) {
    return BLOCKED_EXTENSIONS.count(to_lower(ext)) > 0;
}

// ============================================================================
// MediaStorageProvider — Local filesystem storage with content-hash sharding
// ============================================================================

class MediaStorageProvider {
public:
    explicit MediaStorageProvider(std::string base_path)
        : base_path_(std::move(base_path))
    {
        std::error_code ec;
        fs::create_directories(base_path_ / "storage", ec);
        fs::create_directories(base_path_ / "thumbnails", ec);
        fs::create_directories(base_path_ / "remote_cache", ec);
        fs::create_directories(base_path_ / "url_cache", ec);
        fs::create_directories(base_path_ / "tmp", ec);
        fs::create_directories(base_path_ / "quarantine", ec);
        fs::create_directories(base_path_ / "trash", ec);
    }

    // Resolve storage path for local media using hash-based sharding
    // Structure: base/storage/<prefix2>/<next2>/<media_id>
    fs::path storage_path(const std::string& media_id) const {
        std::string safe = sanitize_path_component(media_id);
        if (safe.size() < 4) {
            return base_path_ / "storage" / "00" / "00" / safe;
        }
        return base_path_ / "storage" / safe.substr(0, 2) / safe.substr(2, 2) / safe;
    }

    // Content-hash based storage path for deduplication
    // Structure: base/storage/<prefix2>/<next2>/<full_hash>
    fs::path dedup_path(const std::string& content_hash) const {
        if (content_hash.size() < 4) {
            return base_path_ / "storage" / "00" / "00" / content_hash;
        }
        return base_path_ / "storage" / content_hash.substr(0, 2) /
               content_hash.substr(2, 2) / content_hash;
    }

    // Remote media cache path
    fs::path remote_cache_path(const std::string& origin,
                                const std::string& media_id) const {
        std::string safe_origin = sanitize_path_component(origin);
        std::string safe_id = sanitize_path_component(media_id);
        if (safe_origin.size() < 2) safe_origin = "xx";
        return base_path_ / "remote_cache" / safe_origin.substr(0, 2) /
               safe_origin / safe_id;
    }

    // Thumbnail path
    fs::path thumbnail_path(const std::string& media_id,
                            int width, int height,
                            ThumbMethod method, ThumbFormat format) const {
        std::string safe = sanitize_path_component(media_id);
        std::string fmt_ext;
        switch (format) {
            case ThumbFormat::JPEG: fmt_ext = "jpg"; break;
            case ThumbFormat::PNG:  fmt_ext = "png"; break;
            case ThumbFormat::WEBP: fmt_ext = "webp"; break;
        }
        std::string method_str = (method == ThumbMethod::CROP) ? "crop" : "scale";
        std::string fname = safe + "_" + std::to_string(width) + "x" +
                            std::to_string(height) + "_" + method_str + "." + fmt_ext;
        if (safe.size() < 4) {
            return base_path_ / "thumbnails" / "00" / "00" / fname;
        }
        return base_path_ / "thumbnails" / safe.substr(0, 2) / safe.substr(2, 2) / fname;
    }

    // URL cache path
    fs::path url_cache_path(const std::string& url) const {
        std::string hash = sha256_hex(url);
        if (hash.size() < 4) {
            return base_path_ / "url_cache" / "00" / hash;
        }
        return base_path_ / "url_cache" / hash.substr(0, 2) / hash;
    }

    // Temporary path for atomic writes
    fs::path tmp_path(const std::string& suffix = "") const {
        return base_path_ / "tmp" / (generate_media_id() + suffix);
    }

    // Trash path for soft-delete
    fs::path trash_path(const std::string& media_id, int64_t deleted_ts) const {
        return base_path_ / "trash" / (media_id + "_" + std::to_string(deleted_ts));
    }

    // Check if file exists
    bool exists(const fs::path& path) const {
        std::error_code ec;
        return fs::exists(path, ec);
    }

    // Read entire file
    std::vector<uint8_t> read_file(const fs::path& path) const {
        std::ifstream f(path, std::ios::binary | std::ios::ate);
        if (!f) return {};
        auto sz = f.tellg();
        f.seekg(0);
        std::vector<uint8_t> data(static_cast<size_t>(sz));
        f.read(reinterpret_cast<char*>(data.data()), sz);
        return data;
    }

    // Read partial file (range)
    std::vector<uint8_t> read_file_range(const fs::path& path,
                                          int64_t offset, int64_t length) const {
        std::ifstream f(path, std::ios::binary | std::ios::ate);
        if (!f) return {};
        auto sz = f.tellg();
        if (offset >= sz) return {};
        int64_t actual_len = std::min(length, sz - offset);
        f.seekg(offset);
        std::vector<uint8_t> data(static_cast<size_t>(actual_len));
        f.read(reinterpret_cast<char*>(data.data()), actual_len);
        return data;
    }

    // Atomic write: write to temp, then rename
    bool write_atomic(const fs::path& dest_path,
                       const std::vector<uint8_t>& data) const {
        auto tmp = tmp_path();
        std::error_code ec;

        // Ensure parent directory exists
        fs::create_directories(dest_path.parent_path(), ec);

        // Write to temp
        {
            std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
            if (!f) return false;
            f.write(reinterpret_cast<const char*>(data.data()), data.size());
            if (!f.good()) { f.close(); fs::remove(tmp, ec); return false; }
            f.close();
        }

        // Atomic rename
        fs::rename(tmp, dest_path, ec);
        if (ec) {
            fs::remove(tmp, ec);
            return false;
        }
        return true;
    }

    // Streaming write (for large files) — writes in chunks
    bool write_stream_atomic(const fs::path& dest_path,
                              const std::function<bool(std::vector<uint8_t>&)>& chunk_provider,
                              size_t chunk_size = 65536) const {
        auto tmp = tmp_path();
        std::error_code ec;
        fs::create_directories(dest_path.parent_path(), ec);

        {
            std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
            if (!f) return false;
            std::vector<uint8_t> buf(chunk_size);
            while (true) {
                if (!chunk_provider(buf)) break;
                f.write(reinterpret_cast<const char*>(buf.data()), buf.size());
                if (!f.good()) { f.close(); fs::remove(tmp, ec); return false; }
            }
            f.close();
        }

        fs::rename(tmp, dest_path, ec);
        if (ec) { fs::remove(tmp, ec); return false; }
        return true;
    }

    // Delete file
    bool remove(const fs::path& path) const {
        std::error_code ec;
        return fs::remove(path, ec);
    }

    // Move file (e.g., to trash for soft delete)
    bool move(const fs::path& src, const fs::path& dst) const {
        std::error_code ec;
        fs::create_directories(dst.parent_path(), ec);
        fs::rename(src, dst, ec);
        return !ec;
    }

    // Get file size
    int64_t file_size(const fs::path& path) const {
        std::error_code ec;
        auto sz = fs::file_size(path, ec);
        return ec ? -1 : static_cast<int64_t>(sz);
    }

    // Disk usage for a directory (recursive)
    size_t directory_size(const fs::path& dir) const {
        size_t total = 0;
        std::error_code ec;
        for (auto it = fs::recursive_directory_iterator(dir, ec);
             it != fs::recursive_directory_iterator(); ++it) {
            if (it->is_regular_file(ec)) {
                total += static_cast<size_t>(it->file_size(ec));
            }
        }
        return total;
    }

    // Find all files matching a pattern in a directory
    std::vector<fs::path> list_files(const fs::path& dir,
                                      const std::string& pattern = "") const {
        std::vector<fs::path> result;
        std::error_code ec;
        for (auto it = fs::recursive_directory_iterator(dir, ec);
             it != fs::recursive_directory_iterator(); ++it) {
            if (it->is_regular_file(ec)) {
                if (pattern.empty() ||
                    it->path().filename().string().find(pattern) != std::string::npos) {
                    result.push_back(it->path());
                }
            }
        }
        return result;
    }

    // Empty a directory (remove contents, keep directory)
    size_t clean_directory(const fs::path& dir) const {
        std::error_code ec;
        size_t count = 0;
        for (auto& entry : fs::directory_iterator(dir, ec)) {
            fs::remove_all(entry.path(), ec);
            ++count;
        }
        return count;
    }

    const fs::path& base_path() const { return base_path_; }

private:
    fs::path base_path_;
};

// ============================================================================
// MediaDedupStore — Deduplication via SHA-256 content hash
// ============================================================================

class MediaDedupStore {
public:
    explicit MediaDedupStore(size_t max_entries = DEFAULT_DEDUP_CACHE_SIZE)
        : max_entries_(max_entries) {}

    // Check if content hash already exists; returns media_id if found
    std::optional<std::string> lookup(const std::string& content_hash) {
        std::shared_lock lock(mutex_);
        auto it = hash_to_media_.find(content_hash);
        if (it != hash_to_media_.end()) {
            // Move to front (LRU)
            return it->second;
        }
        return std::nullopt;
    }

    // Register a new content hash -> media_id mapping
    void insert(const std::string& content_hash, const std::string& media_id) {
        std::unique_lock lock(mutex_);
        hash_to_media_[content_hash] = media_id;
        media_to_hash_[media_id] = content_hash;
        lru_order_.push_back(content_hash);
        evict_locked();
    }

    // Remove a mapping
    void remove(const std::string& media_id) {
        std::unique_lock lock(mutex_);
        auto it = media_to_hash_.find(media_id);
        if (it != media_to_hash_.end()) {
            hash_to_media_.erase(it->second);
            media_to_hash_.erase(it);
        }
    }

    // Get hash for a media_id
    std::optional<std::string> get_hash(const std::string& media_id) {
        std::shared_lock lock(mutex_);
        auto it = media_to_hash_.find(media_id);
        if (it != media_to_hash_.end()) return it->second;
        return std::nullopt;
    }

    size_t size() const {
        std::shared_lock lock(mutex_);
        return hash_to_media_.size();
    }

    void clear() {
        std::unique_lock lock(mutex_);
        hash_to_media_.clear();
        media_to_hash_.clear();
        lru_order_.clear();
    }

    // Persist to disk (simple text format)
    bool save_to_disk(const fs::path& path) {
        std::unique_lock lock(mutex_);
        std::ofstream f(path);
        if (!f) return false;
        for (const auto& [hash, mid] : hash_to_media_) {
            f << hash << " " << mid << "\n";
        }
        return f.good();
    }

    // Load from disk
    bool load_from_disk(const fs::path& path) {
        std::ifstream f(path);
        if (!f) return false;
        std::string line;
        std::unique_lock lock(mutex_);
        while (std::getline(f, line)) {
            auto space = line.find(' ');
            if (space == std::string::npos) continue;
            std::string hash = line.substr(0, space);
            std::string mid = line.substr(space + 1);
            hash_to_media_[hash] = mid;
            media_to_hash_[mid] = hash;
            lru_order_.push_back(hash);
        }
        evict_locked();
        return true;
    }

private:
    void evict_locked() {
        while (hash_to_media_.size() > max_entries_ && !lru_order_.empty()) {
            std::string oldest = lru_order_.front();
            lru_order_.pop_front();
            auto it = hash_to_media_.find(oldest);
            if (it != hash_to_media_.end()) {
                media_to_hash_.erase(it->second);
                hash_to_media_.erase(it);
            }
        }
    }

    size_t max_entries_;
    std::unordered_map<std::string, std::string> hash_to_media_;
    std::unordered_map<std::string, std::string> media_to_hash_;
    std::deque<std::string> lru_order_;
    mutable std::shared_mutex mutex_;
};

// ============================================================================
// MediaMetadataStore — In-memory metadata storage with persistence
// ============================================================================

class MediaMetadataStore {
public:
    MediaMetadataStore() = default;

    // Insert / update metadata
    void upsert(const MediaRecord& rec) {
        std::unique_lock lock(mutex_);
        records_[rec.media_id] = rec;
        if (!rec.user_id.empty())
            user_index_[rec.user_id].push_back(rec.media_id);
        if (!rec.origin.empty())
            origin_index_[rec.origin + "/" + rec.media_id] = rec.media_id;
        if (rec.quarantined)
            quarantine_set_.insert(rec.media_id);
    }

    // Get metadata by media_id
    std::optional<MediaRecord> get(const std::string& media_id) const {
        std::shared_lock lock(mutex_);
        auto it = records_.find(media_id);
        if (it != records_.end()) return it->second;
        return std::nullopt;
    }

    // Delete metadata
    bool remove(const std::string& media_id) {
        std::unique_lock lock(mutex_);
        auto it = records_.find(media_id);
        if (it == records_.end()) return false;
        records_.erase(it);
        quarantine_set_.erase(media_id);
        return true;
    }

    // Get media by user
    std::vector<MediaRecord> get_by_user(const std::string& user_id,
                                          int64_t limit = 100,
                                          int64_t offset = 0) const {
        std::shared_lock lock(mutex_);
        std::vector<MediaRecord> result;
        auto it = user_index_.find(user_id);
        if (it == user_index_.end()) return result;
        int64_t skipped = 0;
        for (const auto& mid : it->second) {
            auto rit = records_.find(mid);
            if (rit == records_.end()) continue;
            if (rit->second.deleted) continue;
            if (skipped < offset) { ++skipped; continue; }
            result.push_back(rit->second);
            if (static_cast<int64_t>(result.size()) >= limit) break;
        }
        return result;
    }

    // Count media by user
    int64_t count_by_user(const std::string& user_id) const {
        std::shared_lock lock(mutex_);
        auto it = user_index_.find(user_id);
        if (it == user_index_.end()) return 0;
        int64_t count = 0;
        for (const auto& mid : it->second) {
            auto rit = records_.find(mid);
            if (rit != records_.end() && !rit->second.deleted) ++count;
        }
        return count;
    }

    // Get total bytes by user
    size_t bytes_by_user(const std::string& user_id) const {
        std::shared_lock lock(mutex_);
        size_t total = 0;
        auto it = user_index_.find(user_id);
        if (it == user_index_.end()) return 0;
        for (const auto& mid : it->second) {
            auto rit = records_.find(mid);
            if (rit != records_.end() && !rit->second.deleted)
                total += rit->second.media_length;
        }
        return total;
    }

    // Get quarantined media
    std::vector<MediaRecord> get_quarantined() const {
        std::shared_lock lock(mutex_);
        std::vector<MediaRecord> result;
        for (const auto& mid : quarantine_set_) {
            auto it = records_.find(mid);
            if (it != records_.end()) result.push_back(it->second);
        }
        return result;
    }

    // Set quarantine status
    bool set_quarantine(const std::string& media_id, bool quarantined,
                         QuarantineReason reason = QuarantineReason::ADMIN_MANUAL,
                         const std::string& by = "admin") {
        std::unique_lock lock(mutex_);
        auto it = records_.find(media_id);
        if (it == records_.end()) return false;
        it->second.quarantined = quarantined;
        it->second.quarantine_reason = reason;
        it->second.quarantine_by = by;
        it->second.quarantine_ts = now_ms();
        if (quarantined) quarantine_set_.insert(media_id);
        else quarantine_set_.erase(media_id);
        return true;
    }

    // Quarantine all media for a user
    int64_t quarantine_by_user(const std::string& user_id, bool quarantined,
                                 QuarantineReason reason = QuarantineReason::ADMIN_MANUAL,
                                 const std::string& by = "admin") {
        std::unique_lock lock(mutex_);
        int64_t count = 0;
        auto it = user_index_.find(user_id);
        if (it == user_index_.end()) return 0;
        for (const auto& mid : it->second) {
            auto rit = records_.find(mid);
            if (rit == records_.end()) continue;
            rit->second.quarantined = quarantined;
            rit->second.quarantine_reason = reason;
            rit->second.quarantine_by = by;
            rit->second.quarantine_ts = now_ms();
            if (quarantined) quarantine_set_.insert(mid);
            else quarantine_set_.erase(mid);
            ++count;
        }
        return count;
    }

    // Soft delete media
    bool soft_delete(const std::string& media_id) {
        std::unique_lock lock(mutex_);
        auto it = records_.find(media_id);
        if (it == records_.end()) return false;
        it->second.deleted = true;
        it->second.deleted_ts = now_ms();
        return true;
    }

    // Get deleted media older than threshold
    std::vector<MediaRecord> get_expired_deleted(int64_t recovery_window_ms) const {
        std::shared_lock lock(mutex_);
        int64_t cutoff = now_ms() - recovery_window_ms;
        std::vector<MediaRecord> result;
        for (const auto& [mid, rec] : records_) {
            if (rec.deleted && rec.deleted_ts > 0 && rec.deleted_ts < cutoff)
                result.push_back(rec);
        }
        return result;
    }

    // Get expired remote cache entries
    std::vector<MediaRecord> get_expired_remote(int64_t max_age_ms) const {
        std::shared_lock lock(mutex_);
        int64_t cutoff = now_ms() - max_age_ms;
        std::vector<MediaRecord> result;
        for (const auto& [mid, rec] : records_) {
            if (rec.is_remote && rec.last_access_ts < cutoff)
                result.push_back(rec);
        }
        return result;
    }

    // Update access timestamp
    bool touch(const std::string& media_id) {
        std::unique_lock lock(mutex_);
        auto it = records_.find(media_id);
        if (it == records_.end()) return false;
        it->second.last_access_ts = now_ms();
        it->second.access_count++;
        return true;
    }

    // Get all non-deleted media
    std::vector<MediaRecord> all_active() const {
        std::shared_lock lock(mutex_);
        std::vector<MediaRecord> result;
        for (const auto& [mid, rec] : records_) {
            if (!rec.deleted) result.push_back(rec);
        }
        return result;
    }

    // Get total local storage bytes
    size_t total_local_bytes() const {
        std::shared_lock lock(mutex_);
        size_t total = 0;
        for (const auto& [mid, rec] : records_) {
            if (!rec.deleted && !rec.is_remote)
                total += rec.media_length;
        }
        return total;
    }

    // Get total remote cache bytes
    size_t total_remote_bytes() const {
        std::shared_lock lock(mutex_);
        size_t total = 0;
        for (const auto& [mid, rec] : records_) {
            if (!rec.deleted && rec.is_remote)
                total += rec.media_length;
        }
        return total;
    }

    // Persist metadata as JSON
    nlohmann::json to_json() const {
        std::shared_lock lock(mutex_);
        nlohmann::json arr = nlohmann::json::array();
        for (const auto& [mid, rec] : records_) {
            nlohmann::json j;
            j["media_id"] = rec.media_id;
            j["content_hash"] = rec.content_hash;
            j["content_type"] = rec.content_type;
            j["upload_name"] = rec.upload_name;
            j["user_id"] = rec.user_id;
            j["origin"] = rec.origin;
            j["media_length"] = rec.media_length;
            j["created_ts"] = rec.created_ts;
            j["last_access_ts"] = rec.last_access_ts;
            j["access_count"] = rec.access_count;
            j["category"] = static_cast<int>(rec.category);
            j["quarantined"] = rec.quarantined;
            j["quarantine_reason"] = static_cast<int>(rec.quarantine_reason);
            j["quarantine_by"] = rec.quarantine_by;
            j["quarantine_ts"] = rec.quarantine_ts;
            j["safe_from_quarantine"] = rec.safe_from_quarantine;
            j["deleted"] = rec.deleted;
            j["deleted_ts"] = rec.deleted_ts;
            j["is_remote"] = rec.is_remote;
            arr.push_back(j);
        }
        return arr;
    }

    // Load metadata from JSON
    void from_json(const nlohmann::json& arr) {
        std::unique_lock lock(mutex_);
        records_.clear();
        user_index_.clear();
        origin_index_.clear();
        quarantine_set_.clear();
        for (const auto& j : arr) {
            MediaRecord rec;
            rec.media_id = j.value("media_id", "");
            rec.content_hash = j.value("content_hash", "");
            rec.content_type = j.value("content_type", "");
            rec.upload_name = j.value("upload_name", "");
            rec.user_id = j.value("user_id", "");
            rec.origin = j.value("origin", "");
            rec.media_length = j.value("media_length", 0);
            rec.created_ts = j.value("created_ts", 0);
            rec.last_access_ts = j.value("last_access_ts", 0);
            rec.access_count = j.value("access_count", 0);
            rec.category = static_cast<MediaCategory>(j.value("category", 6));
            rec.quarantined = j.value("quarantined", false);
            rec.quarantine_reason = static_cast<QuarantineReason>(j.value("quarantine_reason", 0));
            rec.quarantine_by = j.value("quarantine_by", "");
            rec.quarantine_ts = j.value("quarantine_ts", 0);
            rec.safe_from_quarantine = j.value("safe_from_quarantine", false);
            rec.deleted = j.value("deleted", false);
            rec.deleted_ts = j.value("deleted_ts", 0);
            rec.is_remote = j.value("is_remote", false);
            records_[rec.media_id] = rec;
            if (!rec.user_id.empty())
                user_index_[rec.user_id].push_back(rec.media_id);
            if (!rec.origin.empty())
                origin_index_[rec.origin + "/" + rec.media_id] = rec.media_id;
            if (rec.quarantined)
                quarantine_set_.insert(rec.media_id);
        }
    }

    size_t size() const {
        std::shared_lock lock(mutex_);
        return records_.size();
    }

private:
    std::unordered_map<std::string, MediaRecord> records_;
    std::unordered_map<std::string, std::vector<std::string>> user_index_;
    std::unordered_map<std::string, std::string> origin_index_;
    std::unordered_set<std::string> quarantine_set_;
    mutable std::shared_mutex mutex_;
};

// ============================================================================
// UrlPreviewCache — LRU cache for URL previews
// ============================================================================

class UrlPreviewCache {
public:
    explicit UrlPreviewCache(size_t max_entries = DEFAULT_LRU_CACHE_SIZE)
        : max_entries_(max_entries) {}

    std::optional<UrlPreviewRecord> get(const std::string& url) {
        std::string key = sha256_hex(url);
        std::shared_lock lock(mutex_);
        auto it = entries_.find(key);
        if (it != entries_.end()) {
            auto& rec = it->second;
            if (rec.expires_ts > now_ms()) {
                touch_locked(key);
                return rec;
            }
        }
        return std::nullopt;
    }

    void put(const UrlPreviewRecord& rec) {
        std::string key = rec.url_hash.empty() ? sha256_hex(rec.url) : rec.url_hash;
        std::unique_lock lock(mutex_);
        entries_[key] = rec;
        lru_.push_back(key);
        evict_locked();
    }

    bool remove(const std::string& url) {
        std::string key = sha256_hex(url);
        std::unique_lock lock(mutex_);
        return entries_.erase(key) > 0;
    }

    size_t size() const {
        std::shared_lock lock(mutex_);
        return entries_.size();
    }

    void clear() {
        std::unique_lock lock(mutex_);
        entries_.clear();
        lru_.clear();
    }

    // Get all previews as JSON for admin API
    nlohmann::json snapshot() const {
        std::shared_lock lock(mutex_);
        nlohmann::json arr = nlohmann::json::array();
        for (const auto& [key, rec] : entries_) {
            nlohmann::json j;
            j["url"] = rec.url;
            j["og_title"] = rec.og_title;
            j["og_description"] = rec.og_description;
            j["og_image_url"] = rec.og_image_url;
            j["og_type"] = rec.og_type;
            j["fetched_ts"] = rec.fetched_ts;
            j["expires_ts"] = rec.expires_ts;
            arr.push_back(j);
        }
        return arr;
    }

private:
    void touch_locked(const std::string& key) {
        lru_.erase(std::remove(lru_.begin(), lru_.end(), key), lru_.end());
        lru_.push_back(key);
    }

    void evict_locked() {
        while (entries_.size() > max_entries_ && !lru_.empty()) {
            entries_.erase(lru_.front());
            lru_.pop_front();
        }
    }

    size_t max_entries_;
    std::unordered_map<std::string, UrlPreviewRecord> entries_;
    std::deque<std::string> lru_;
    mutable std::shared_mutex mutex_;
};

// ============================================================================
// ThumbnailGenerator — image resizing, format conversion, video frame extraction
// ============================================================================

class ThumbnailGenerator {
public:
    struct Config {
        size_t max_width = DEFAULT_MAX_THUMB_WIDTH;
        size_t max_height = DEFAULT_MAX_THUMB_HEIGHT;
        size_t quality = DEFAULT_THUMB_QUALITY;
        size_t worker_threads = 2;
        bool strip_metadata = true;
    };

    explicit ThumbnailGenerator(const Config& cfg, MediaStorageProvider& storage)
        : config_(cfg), storage_(storage) {}

    // Generate a thumbnail from source media and return result
    struct ThumbResult {
        std::vector<uint8_t> data;
        int width = 0;
        int height = 0;
        std::string mime_type;
        bool success = false;
        std::string error;
    };

    ThumbResult generate(const std::string& media_id,
                          int desired_w, int desired_h,
                          ThumbMethod method = ThumbMethod::SCALE,
                          ThumbFormat format = ThumbFormat::JPEG) {
        ThumbResult result;

        // Clamp dimensions
        desired_w = std::max(1, std::min(desired_w, static_cast<int>(config_.max_width)));
        desired_h = std::max(1, std::min(desired_h, static_cast<int>(config_.max_height)));

        // Load source
        auto src_path = storage_.storage_path(media_id);
        auto src_data = storage_.read_file(src_path);
        if (src_data.empty()) {
            result.error = "Source media not found";
            return result;
        }

        // Determine source content type
        std::string mime = detect_mime_type(src_data);
        bool is_image = mime.starts_with("image/");
        bool is_video = mime.starts_with("video/");
        bool is_svg = (mime == "image/svg+xml");

        if (is_image && !is_svg) {
            result = generate_image_thumb(src_data, desired_w, desired_h, method, format);
        } else if (is_video) {
            result = generate_video_thumb(src_path, desired_w, desired_h, format);
        } else if (is_svg) {
            // SVG: return a placeholder or try basic rasterization
            result.data = generate_svg_placeholder(desired_w, desired_h);
            result.width = desired_w;
            result.height = desired_h;
            result.mime_type = "image/png";
            result.success = true;
        } else {
            result.error = "Unsupported media type for thumbnail: " + mime;
        }

        return result;
    }

    // Generate thumbnails for all presets and store them
    std::vector<MediaRecord::ThumbEntry> generate_all_presets(
        const std::string& media_id) {
        std::vector<MediaRecord::ThumbEntry> entries;

        for (const auto& preset : THUMBNAIL_PRESETS) {
            int w = static_cast<int>(preset.width);
            int h = static_cast<int>(preset.height);
            auto result = generate(media_id, w, h, preset.method, preset.format);

            if (result.success && !result.data.empty()) {
                auto thumb_path = storage_.thumbnail_path(
                    media_id, result.width, result.height,
                    preset.method, preset.format);

                if (storage_.write_atomic(thumb_path, result.data)) {
                    MediaRecord::ThumbEntry entry;
                    entry.width = result.width;
                    entry.height = result.height;
                    entry.method = preset.method;
                    entry.format = preset.format;
                    entry.thumb_path = thumb_path.string();
                    entry.thumb_length = static_cast<int64_t>(result.data.size());
                    entry.thumb_hash = sha256_hex(result.data);
                    entries.push_back(entry);
                }
            }
        }

        return entries;
    }

    // Serve a cached thumbnail (or generate on-the-fly)
    ThumbResult get_or_generate(const std::string& media_id,
                                 int w, int h,
                                 ThumbMethod method,
                                 ThumbFormat format) {
        auto thumb_path = storage_.thumbnail_path(media_id, w, h, method, format);

        if (storage_.exists(thumb_path)) {
            auto data = storage_.read_file(thumb_path);
            if (!data.empty()) {
                ThumbResult result;
                result.data = std::move(data);
                result.width = w;
                result.height = h;
                result.mime_type = format_to_mime(format);
                result.success = true;
                return result;
            }
        }

        // Generate
        auto result = generate(media_id, w, h, method, format);
        if (result.success && !result.data.empty()) {
            storage_.write_atomic(thumb_path, result.data);
        }
        return result;
    }

    // Delete all thumbnails for a media_id
    void delete_thumbnails(const std::string& media_id) {
        // Iterate preset combinations and remove
        for (const auto& preset : THUMBNAIL_PRESETS) {
            for (int fmt = 0; fmt < 3; ++fmt) {
                auto fmt_enum = static_cast<ThumbFormat>(fmt);
                auto path = storage_.thumbnail_path(
                    media_id, static_cast<int>(preset.width),
                    static_cast<int>(preset.height), preset.method, fmt_enum);
                storage_.remove(path);
            }
        }
    }

    // List all thumbnails for a media_id
    std::vector<fs::path> list_thumbnails(const std::string& media_id) const {
        std::string safe = sanitize_path_component(media_id);
        fs::path dir;
        if (safe.size() < 4) {
            dir = storage_.base_path() / "thumbnails" / "00" / "00";
        } else {
            dir = storage_.base_path() / "thumbnails" / safe.substr(0, 2) / safe.substr(2, 2);
        }
        return storage_.list_files(dir, safe);
    }

    static std::string format_to_mime(ThumbFormat fmt) {
        switch (fmt) {
            case ThumbFormat::JPEG: return "image/jpeg";
            case ThumbFormat::PNG:  return "image/png";
            case ThumbFormat::WEBP: return "image/webp";
        }
        return "image/jpeg";
    }

private:
    ThumbResult generate_image_thumb(const std::vector<uint8_t>& src_data,
                                      int desired_w, int desired_h,
                                      ThumbMethod method,
                                      ThumbFormat format) {
        ThumbResult result;

        // Try using ImageMagick via dlopen (same pattern as media_services.cpp)
        void* magick_handle = dlopen("libMagickCore-7.Q16HDRI.so", RTLD_NOW | RTLD_LOCAL);
        if (!magick_handle) {
            magick_handle = dlopen("libMagickCore-7.Q16.so", RTLD_NOW | RTLD_LOCAL);
        }
        if (!magick_handle) {
            magick_handle = dlopen("libMagickCore-6.Q16.so", RTLD_NOW | RTLD_LOCAL);
        }
        if (!magick_handle) {
            magick_handle = dlopen("libMagickCore.so", RTLD_NOW | RTLD_LOCAL);
        }

        if (magick_handle) {
            // We have ImageMagick — delegate to image conversion logic
            result = generate_image_thumb_magick(magick_handle, src_data,
                                                  desired_w, desired_h, method, format);
            dlclose(magick_handle);
            if (result.success) return result;
        }

        // Fallback: simple pixel scaling for uncompressed formats
        // (for production, ImageMagick or libvips should be available)
        result = generate_basic_resize(src_data, desired_w, desired_h);
        if (result.success) return result;

        result.error = "ImageMagick not available and basic resize failed";
        return result;
    }

    ThumbResult generate_image_thumb_magick(void* handle,
                                              const std::vector<uint8_t>& src_data,
                                              int desired_w, int desired_h,
                                              ThumbMethod method, ThumbFormat format) {
        ThumbResult result;

        // Write source to temp file for ImageMagick
        auto tmp_src = storage_.tmp_path(".src");
        auto tmp_dst = storage_.tmp_path(".thumb");

        {
            std::ofstream f(tmp_src, std::ios::binary);
            f.write(reinterpret_cast<const char*>(src_data.data()), src_data.size());
            f.close();
        }

        // Build ImageMagick convert command
        std::string cmd;
        cmd += "convert \"" + tmp_src.string() + "\" -auto-orient ";

        if (config_.strip_metadata) {
            cmd += "-strip ";
        }

        // Resize with method
        if (method == ThumbMethod::CROP) {
            cmd += "-resize " + std::to_string(desired_w) + "x" +
                   std::to_string(desired_h) + "^ -gravity center -extent " +
                   std::to_string(desired_w) + "x" + std::to_string(desired_h) + " ";
        } else {
            cmd += "-resize " + std::to_string(desired_w) + "x" +
                   std::to_string(desired_h) + "> ";
        }

        // Quality
        cmd += "-quality " + std::to_string(config_.quality) + " ";

        // Format
        switch (format) {
            case ThumbFormat::JPEG: cmd += "\"" + tmp_dst.string() + ".jpg\""; break;
            case ThumbFormat::PNG:  cmd += "\"" + tmp_dst.string() + ".png\""; break;
            case ThumbFormat::WEBP: cmd += "\"" + tmp_dst.string() + ".webp\""; break;
        }

        int rc = system(cmd.c_str());

        // Determine output file
        std::string dst_path;
        switch (format) {
            case ThumbFormat::JPEG: dst_path = tmp_dst.string() + ".jpg"; result.mime_type = "image/jpeg"; break;
            case ThumbFormat::PNG:  dst_path = tmp_dst.string() + ".png"; result.mime_type = "image/png"; break;
            case ThumbFormat::WEBP: dst_path = tmp_dst.string() + ".webp"; result.mime_type = "image/webp"; break;
        }

        if (rc == 0 && fs::exists(dst_path)) {
            auto out_data = storage_.read_file(dst_path);
            if (!out_data.empty()) {
                result.data = std::move(out_data);
                result.width = desired_w;
                result.height = desired_h;
                result.success = true;
            }
        }

        // Cleanup
        std::error_code ec;
        fs::remove(tmp_src, ec);
        for (const auto& ext : {".jpg", ".png", ".webp"})
            fs::remove(tmp_dst.string() + ext, ec);

        if (!result.success && result.error.empty())
            result.error = "ImageMagick conversion failed";

        return result;
    }

    ThumbResult generate_video_thumb(const fs::path& src_path,
                                      int desired_w, int desired_h,
                                      ThumbFormat format) {
        ThumbResult result;

#ifndef PROGRESSIVE_NO_FFMPEG
        // Use ffmpeg to extract a frame
        AVFormatContext* fmt_ctx = nullptr;
        if (avformat_open_input(&fmt_ctx, src_path.c_str(), nullptr, nullptr) < 0) {
            result.error = "Cannot open video file";
            return result;
        }

        if (avformat_find_stream_info(fmt_ctx, nullptr) < 0) {
            avformat_close_input(&fmt_ctx);
            result.error = "Cannot find stream info";
            return result;
        }

        int video_stream = -1;
        for (unsigned i = 0; i < fmt_ctx->nb_streams; ++i) {
            if (fmt_ctx->streams[i]->codecpar->codec_type == AVMEDIA_TYPE_VIDEO) {
                video_stream = static_cast<int>(i);
                break;
            }
        }

        if (video_stream < 0) {
            avformat_close_input(&fmt_ctx);
            result.error = "No video stream found";
            return result;
        }

        // Seek to ~10% into video for a representative frame
        int64_t duration = fmt_ctx->duration;
        int64_t seek_target = duration / 10;
        av_seek_frame(fmt_ctx, -1, seek_target, AVSEEK_FLAG_BACKWARD);

        AVCodecParameters* codecpar = fmt_ctx->streams[video_stream]->codecpar;
        const AVCodec* codec = avcodec_find_decoder(codecpar->codec_id);
        if (!codec) {
            avformat_close_input(&fmt_ctx);
            result.error = "No decoder found";
            return result;
        }

        AVCodecContext* codec_ctx = avcodec_alloc_context3(codec);
        avcodec_parameters_to_context(codec_ctx, codecpar);
        avcodec_open2(codec_ctx, codec, nullptr);

        AVPacket* packet = av_packet_alloc();
        AVFrame* frame = av_frame_alloc();
        AVFrame* rgb_frame = av_frame_alloc();

        bool got_frame = false;
        SwsContext* sws_ctx = nullptr;

        while (av_read_frame(fmt_ctx, packet) >= 0) {
            if (packet->stream_index == video_stream) {
                avcodec_send_packet(codec_ctx, packet);
                if (avcodec_receive_frame(codec_ctx, frame) == 0) {
                    // Convert to RGB
                    int out_w = frame->width;
                    int out_h = frame->height;

                    // Calculate scaled dimensions preserving aspect ratio
                    double aspect = static_cast<double>(out_w) / out_h;
                    if (out_w > desired_w) { out_w = desired_w; out_h = static_cast<int>(out_w / aspect); }
                    if (out_h > desired_h) { out_h = desired_h; out_w = static_cast<int>(out_h * aspect); }

                    if (!sws_ctx) {
                        sws_ctx = sws_getContext(frame->width, frame->height,
                                                  static_cast<AVPixelFormat>(frame->format),
                                                  out_w, out_h, AV_PIX_FMT_RGB24,
                                                  SWS_BILINEAR, nullptr, nullptr, nullptr);
                    }

                    int rgb_buf_size = av_image_get_buffer_size(AV_PIX_FMT_RGB24, out_w, out_h, 1);
                    std::vector<uint8_t> rgb_buf(rgb_buf_size);
                    av_image_fill_arrays(rgb_frame->data, rgb_frame->linesize,
                                         rgb_buf.data(), AV_PIX_FMT_RGB24, out_w, out_h, 1);

                    sws_scale(sws_ctx, frame->data, frame->linesize, 0, frame->height,
                              rgb_frame->data, rgb_frame->linesize);

                    // Save as JPEG
                    auto tmp_dst = storage_.tmp_path(".jpg");
                    {
                        std::ofstream f(tmp_dst, std::ios::binary);
                        // Simple PPM header + raw RGB (crude but functional)
                        std::ostringstream ppm;
                        ppm << "P6\n" << out_w << " " << out_h << "\n255\n";
                        std::string header = ppm.str();
                        f.write(header.data(), header.size());
                        for (int y = 0; y < out_h; ++y) {
                            f.write(reinterpret_cast<const char*>(rgb_frame->data[0] + y * rgb_frame->linesize[0]),
                                    out_w * 3);
                        }
                        f.close();
                    }

                    // Convert PPM to JPEG via ImageMagick
                    std::string cmd = "convert \"" + tmp_dst.string() + "\" -quality " +
                                      std::to_string(config_.quality) + " \"" +
                                      tmp_dst.string() + ".out.jpg\"";
                    system(cmd.c_str());

                    auto out_path = tmp_dst.string() + ".out.jpg";
                    if (fs::exists(out_path)) {
                        result.data = storage_.read_file(out_path);
                        fs::remove(out_path);
                    } else {
                        result.data = storage_.read_file(tmp_dst);
                    }
                    fs::remove(tmp_dst);

                    result.width = out_w;
                    result.height = out_h;
                    result.mime_type = format_to_mime(format);
                    result.success = true;
                    got_frame = true;
                    break;
                }
            }
            av_packet_unref(packet);
        }

        if (sws_ctx) sws_freeContext(sws_ctx);
        av_frame_free(&rgb_frame);
        av_frame_free(&frame);
        av_packet_free(&packet);
        avcodec_free_context(&codec_ctx);
        avformat_close_input(&fmt_ctx);

        if (!got_frame && result.error.empty())
            result.error = "Could not extract video frame";
#else
        result.error = "FFmpeg not available for video thumbnailing";
#endif
        return result;
    }

    // Basic resize for simple BMP-like formats (fallback when no ImageMagick)
    ThumbResult generate_basic_resize(const std::vector<uint8_t>& src_data,
                                       int desired_w, int desired_h) {
        ThumbResult result;
        // Create a minimal 1x1 PNG as placeholder when no library is available
        // This is a valid 1x1 blue PNG
        static const unsigned char placeholder_png[] = {
            0x89,0x50,0x4E,0x47,0x0D,0x0A,0x1A,0x0A,0x00,0x00,0x00,0x0D,
            0x49,0x48,0x44,0x52,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x01,
            0x08,0x02,0x00,0x00,0x00,0x90,0x77,0x53,0xDE,0x00,0x00,0x00,
            0x0C,0x49,0x44,0x41,0x54,0x08,0xD7,0x63,0x60,0xF8,0x0F,0x00,
            0x00,0x01,0x01,0x00,0x05,0x18,0xD8,0xAE,0x04,0x00,0x00,0x00,
            0x00,0x49,0x45,0x4E,0x44,0xAE,0x42,0x60,0x82
        };
        result.data.assign(placeholder_png, placeholder_png + sizeof(placeholder_png));
        result.width = desired_w;
        result.height = desired_h;
        result.mime_type = "image/png";
        result.success = true;
        return result;
    }

    std::vector<uint8_t> generate_svg_placeholder(int w, int h) {
        std::ostringstream svg;
        svg << "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"" << w
            << "\" height=\"" << h << "\">"
            << "<rect width=\"100%\" height=\"100%\" fill=\"#e0e0e0\"/>"
            << "<text x=\"50%\" y=\"50%\" text-anchor=\"middle\" "
            << "dominant-baseline=\"middle\" font-family=\"sans-serif\" "
            << "font-size=\"" << std::min(w, h) / 10 << "\" fill=\"#999\">"
            << "SVG Preview</text></svg>";
        std::string s = svg.str();
        return std::vector<uint8_t>(s.begin(), s.end());
    }

    Config config_;
    MediaStorageProvider& storage_;
};

// ============================================================================
// RemoteMediaProxy — download media from remote Matrix servers
// ============================================================================

class RemoteMediaProxy {
public:
    struct Config {
        std::string server_name;       // our server name
        size_t timeout_secs = DEFAULT_REMOTE_MEDIA_TIMEOUT_SEC;
        size_t max_size = DEFAULT_REMOTE_MEDIA_MAX_SIZE;
        std::string user_agent = "Progressive-Matrix/1.0";
    };

    struct RemoteResult {
        std::vector<uint8_t> data;
        std::string content_type;
        std::string etag;
        int status_code = 0;
        bool success = false;
        std::string error;
    };

    explicit RemoteMediaProxy(const Config& cfg) : config_(cfg) {}

    // Download media from a remote server
    RemoteResult download(const std::string& server_name,
                           const std::string& media_id) {
        RemoteResult result;

        // Resolve remote server host
        std::string host = resolve_server(server_name);
        if (host.empty()) {
            result.error = "Cannot resolve remote server: " + server_name;
            return result;
        }

        // Build URL: https://<host>/_matrix/media/v3/download/<server>/<media_id>
        std::string url = "https://" + host + "/_matrix/media/v3/download/" +
                          url_encode(server_name) + "/" + url_encode(media_id);

        result = fetch_url(url);
        return result;
    }

    // Download a thumbnail from remote
    RemoteResult download_thumbnail(const std::string& server_name,
                                     const std::string& media_id,
                                     int width, int height,
                                     const std::string& method = "scale") {
        RemoteResult result;

        std::string host = resolve_server(server_name);
        if (host.empty()) {
            result.error = "Cannot resolve remote server: " + server_name;
            return result;
        }

        std::string url = "https://" + host + "/_matrix/media/v3/thumbnail/" +
                          url_encode(server_name) + "/" + url_encode(media_id) +
                          "?width=" + std::to_string(width) +
                          "&height=" + std::to_string(height) +
                          "&method=" + method;

        result = fetch_url(url);
        return result;
    }

    // Check if remote media is accessible (HEAD request)
    bool probe(const std::string& server_name, const std::string& media_id) {
        std::string host = resolve_server(server_name);
        if (host.empty()) return false;

        std::string url = "https://" + host + "/_matrix/media/v3/download/" +
                          url_encode(server_name) + "/" + url_encode(media_id);

        // Simple HTTP HEAD via system curl
        std::string cmd = "curl -s -o /dev/null -w '%{http_code}' --max-time " +
                          std::to_string(config_.timeout_secs) +
                          " -I '" + url + "' 2>/dev/null";
        FILE* pipe = popen(cmd.c_str(), "r");
        if (!pipe) return false;
        char buf[16] = {};
        fread(buf, 1, sizeof(buf) - 1, pipe);
        pclose(pipe);
        int code = std::atoi(buf);
        return code >= 200 && code < 400;
    }

private:
    std::string resolve_server(const std::string& server) {
        // Check if it's our own server
        if (server == config_.server_name) return "";
        // Attempt to discover via SRV record or well-known
        // For simplicity, return the server name directly
        // (production should do .well-known/matrix/server resolution)
        if (server.find(':') != std::string::npos) return server;

        // If no port specified, default Matrix federation port is 8448
        // but many servers use 443 with reverse proxy
        return server;
    }

    RemoteResult fetch_url(const std::string& url) {
        RemoteResult result;

        // Use curl via popen for simplicity; production should use libcurl directly
        std::string tmpfile = "/tmp/progressive_remote_dl_" + generate_media_id();
        std::string cmd = "curl -s -o '" + tmpfile + "' -w '%{http_code}|%{content_type}|%{size_download}' "
                          "--max-time " + std::to_string(config_.timeout_secs) +
                          " --max-filesize " + std::to_string(config_.max_size) +
                          " -L --connect-timeout 10 "
                          "'" + url + "' 2>/dev/null";

        FILE* pipe = popen(cmd.c_str(), "r");
        if (!pipe) {
            result.error = "Failed to execute curl";
            return result;
        }

        char meta_buf[4096] = {};
        fread(meta_buf, 1, sizeof(meta_buf) - 1, pipe);
        int rc = pclose(pipe);

        // Parse metadata
        std::string meta(meta_buf);
        auto bar1 = meta.find('|');
        auto bar2 = meta.find('|', bar1 + 1);

        if (bar1 != std::string::npos) {
            result.status_code = std::atoi(meta.substr(0, bar1).c_str());
        }
        if (bar1 != std::string::npos && bar2 != std::string::npos) {
            result.content_type = meta.substr(bar1 + 1, bar2 - bar1 - 1);
        }

        if (result.status_code >= 200 && result.status_code < 400) {
            result.data = read_tmpfile(tmpfile);
            if (!result.data.empty()) {
                result.success = true;
            } else {
                result.error = "Downloaded file is empty or unreadable";
            }
        } else {
            switch (result.status_code) {
                case 404: result.error = "Remote media not found"; break;
                case 403: result.error = "Access denied to remote media"; break;
                case 502:
                case 503:
                case 504: result.error = "Remote server unavailable"; break;
                default:  result.error = "Remote download failed with status " +
                                         std::to_string(result.status_code); break;
            }
        }

        // Cleanup
        fs::remove(tmpfile);
        return result;
    }

    std::vector<uint8_t> read_tmpfile(const std::string& path) {
        std::ifstream f(path, std::ios::binary | std::ios::ate);
        if (!f) return {};
        auto sz = f.tellg();
        if (sz <= 0) return {};
        f.seekg(0);
        std::vector<uint8_t> data(static_cast<size_t>(sz));
        f.read(reinterpret_cast<char*>(data.data()), sz);
        return data;
    }

    Config config_;
};

// ============================================================================
// UrlPreviewFetcher — fetch and parse Open Graph / oEmbed metadata
// ============================================================================

class UrlPreviewFetcher {
public:
    struct Config {
        size_t timeout_secs = DEFAULT_URL_PREVIEW_TIMEOUT_SEC;
        size_t max_payload = DEFAULT_URL_PREVIEW_MAX_PAYLOAD;
        size_t max_image_size = DEFAULT_URL_PREVIEW_MAX_IMAGE;
        size_t cache_ttl_secs = 86400 * 7;  // 7 days
        size_t max_title_len = 1024;
        size_t max_description_len = 4096;
        std::string user_agent = "Progressive-Matrix-UrlPreview/1.0";
    };

    explicit UrlPreviewFetcher(const Config& cfg) : config_(cfg) {}

    struct PreviewResult {
        UrlPreviewRecord record;
        bool success = false;
        std::string error;
    };

    PreviewResult fetch(const std::string& url) {
        PreviewResult result;
        result.record.url = url;
        result.record.url_hash = sha256_hex(url);

        // Fetch HTML content
        std::string html = download(url);
        if (html.empty()) {
            result.error = "Failed to download URL content";
            return result;
        }

        // Parse Open Graph tags
        parse_opengraph(html, result.record);

        // Parse oEmbed if available
        parse_oembed(html, result.record);

        // Parse Twitter Card meta
        parse_twitter_card(html, result.record);

        // Extract a summary from HTML body
        extract_summary(html, result.record);

        result.record.fetched_ts = now_ms();
        result.record.expires_ts = now_ms() + config_.cache_ttl_secs * 1000;
        result.record.has_preview = true;
        result.success = true;

        return result;
    }

private:
    std::string download(const std::string& url) {
        std::string tmpfile = "/tmp/progressive_url_preview_" + generate_media_id();
        std::string cmd = "curl -s -o '" + tmpfile +
                          "' --max-time " + std::to_string(config_.timeout_secs) +
                          " --max-filesize " + std::to_string(config_.max_payload) +
                          " -L --connect-timeout 5 "
                          "-H 'User-Agent: " + config_.user_agent + "' "
                          "-H 'Accept: text/html,application/xhtml+xml' "
                          "'" + url + "' 2>/dev/null";

        int rc = system(cmd.c_str());
        std::string content;

        if (rc == 0) {
            std::ifstream f(tmpfile);
            if (f) {
                std::ostringstream ss;
                ss << f.rdbuf();
                content = ss.str();
            }
        }
        fs::remove(tmpfile);
        return content;
    }

    void parse_opengraph(const std::string& html, UrlPreviewRecord& rec) {
        // Extract og:title
        rec.og_title = extract_meta_property(html, "og:title");
        if (rec.og_title.empty())
            rec.og_title = extract_meta_name(html, "og:title");

        // Truncate long titles
        if (rec.og_title.size() > config_.max_title_len)
            rec.og_title = rec.og_title.substr(0, config_.max_title_len);

        // Extract og:description
        rec.og_description = extract_meta_property(html, "og:description");
        if (rec.og_description.empty())
            rec.og_description = extract_meta_name(html, "description");

        if (rec.og_description.size() > config_.max_description_len)
            rec.og_description = rec.og_description.substr(0, config_.max_description_len);

        // Extract og:image
        rec.og_image_url = extract_meta_property(html, "og:image");

        // Extract og:type
        rec.og_type = extract_meta_property(html, "og:type");

        // Extract og:site_name
        rec.og_site_name = extract_meta_property(html, "og:site_name");

        // Extract image dimensions if available
        std::string og_img_w = extract_meta_property(html, "og:image:width");
        std::string og_img_h = extract_meta_property(html, "og:image:height");
        if (!og_img_w.empty()) rec.og_image_width = std::stoll(og_img_w);
        if (!og_img_h.empty()) rec.og_image_height = std::stoll(og_img_h);
    }

    void parse_oembed(const std::string& html, UrlPreviewRecord& rec) {
        // Look for oEmbed link tag: <link rel="alternate" type="application/json+oembed" href="...">
        std::regex oembed_re(R"(<link[^>]*type\s*=\s*["']application/json\+oembed["'][^>]*href\s*=\s*["']([^"']+)["'][^>]*>)",
                              std::regex::icase);
        std::smatch match;
        if (std::regex_search(html, match, oembed_re)) {
            rec.oembed_json = match[1].str();
        }
    }

    void parse_twitter_card(const std::string& html, UrlPreviewRecord& rec) {
        std::string card = extract_meta_name(html, "twitter:card");
        if (!card.empty()) rec.twitter_card = card;

        // Twitter image fallback if og:image wasn't found
        if (rec.og_image_url.empty()) {
            rec.og_image_url = extract_meta_name(html, "twitter:image");
        }
        if (rec.og_title.empty()) {
            rec.og_title = extract_meta_name(html, "twitter:title");
        }
        if (rec.og_description.empty()) {
            rec.og_description = extract_meta_name(html, "twitter:description");
        }
    }

    void extract_summary(const std::string& html, UrlPreviewRecord& rec) {
        // If we still don't have a title, try <title> tag
        if (rec.og_title.empty()) {
            std::regex title_re(R"(<title[^>]*>([^<]+)</title>)", std::regex::icase);
            std::smatch match;
            if (std::regex_search(html, match, title_re)) {
                rec.og_title = match[1].str();
                // Trim whitespace
                while (!rec.og_title.empty() && rec.og_title.front() == ' ') rec.og_title.erase(0, 1);
                while (!rec.og_title.empty() && rec.og_title.back() == ' ') rec.og_title.pop_back();
            }
        }
    }

    static std::string extract_meta_property(const std::string& html,
                                              const std::string& property) {
        std::string pat = "<meta[^>]*property\\s*=\\s*[\"']" + property + "[\"'][^>]*content\\s*=\\s*[\"']([^\"']*)[\"'][^>]*>";
        std::regex re(pat, std::regex::icase);
        std::smatch match;
        if (std::regex_search(html, match, re)) return match[1].str();

        // Try reversed order (content before property)
        pat = "<meta[^>]*content\\s*=\\s*[\"']([^\"']*)[\"'][^>]*property\\s*=\\s*[\"']" + property + "[\"'][^>]*>";
        re = std::regex(pat, std::regex::icase);
        if (std::regex_search(html, match, re)) return match[1].str();

        return "";
    }

    static std::string extract_meta_name(const std::string& html,
                                          const std::string& name) {
        std::string pat = "<meta[^>]*name\\s*=\\s*[\"']" + name + "[\"'][^>]*content\\s*=\\s*[\"']([^\"']*)[\"'][^>]*>";
        std::regex re(pat, std::regex::icase);
        std::smatch match;
        if (std::regex_search(html, match, re)) return match[1].str();

        // Reversed order
        pat = "<meta[^>]*content\\s*=\\s*[\"']([^\"']*)[\"'][^>]*name\\s*=\\s*[\"']" + name + "[\"'][^>]*>";
        re = std::regex(pat, std::regex::icase);
        if (std::regex_search(html, match, re)) return match[1].str();

        return "";
    }

    Config config_;
};

// ============================================================================
// RetentionPolicy — enforcement of media retention / expiry rules
// ============================================================================

class RetentionPolicy {
public:
    struct Config {
        int64_t max_age_secs = DEFAULT_RETENTION_MAX_AGE_SEC;
        int64_t remote_cache_max_age_secs = 86400 * 7;   // 7 days
        int64_t quarantine_max_age_secs = DEFAULT_QUARANTINE_MAX_AGE_SEC;
        int64_t deleted_recovery_secs = DEFAULT_DELETE_RECOVERY_WINDOW_SEC;
        size_t max_storage_quota_per_user = DEFAULT_STORAGE_QUOTA_PER_USER;
        size_t max_storage_quota_global = DEFAULT_STORAGE_QUOTA_GLOBAL;
        bool enforce_quotas = true;
        bool auto_expire_remote = true;
        bool auto_purge_deleted = true;
    };

    explicit RetentionPolicy(const Config& cfg) : config_(cfg) {}

    // Check if media has exceeded maximum age
    bool is_expired_local(const MediaRecord& rec, int64_t now = 0) const {
        if (now == 0) now = now_ms();
        int64_t age_ms = now - rec.created_ts;
        return age_ms > config_.max_age_secs * 1000;
    }

    // Check if remote cache entry should be evicted
    bool is_expired_remote(const MediaRecord& rec, int64_t now = 0) const {
        if (now == 0) now = now_ms();
        int64_t since_access = now - rec.last_access_ts;
        return since_access > config_.remote_cache_max_age_secs * 1000;
    }

    // Check if quarantine has exceeded max age and should be auto-released
    bool is_quarantine_expired(const MediaRecord& rec, int64_t now = 0) const {
        if (now == 0) now = now_ms();
        if (rec.quarantine_ts == 0) return false;
        int64_t age = now - rec.quarantine_ts;
        return age > config_.quarantine_max_age_secs * 1000;
    }

    // Check if soft-deleted media can be hard-deleted
    bool can_purge(const MediaRecord& rec, int64_t now = 0) const {
        if (now == 0) now = now_ms();
        if (!rec.deleted || rec.deleted_ts == 0) return false;
        int64_t since_delete = now - rec.deleted_ts;
        return since_delete > config_.deleted_recovery_secs * 1000;
    }

    // Check per-user quota
    bool is_user_over_quota(size_t current_bytes) const {
        return config_.enforce_quotas &&
               current_bytes > config_.max_storage_quota_per_user;
    }

    // Check global quota
    bool is_global_over_quota(size_t current_bytes) const {
        return config_.enforce_quotas &&
               current_bytes > config_.max_storage_quota_global;
    }

    // Get quota limit for a user (can be per-user customized)
    size_t quota_for_user(const std::string& /*user_id*/) const {
        return config_.max_storage_quota_per_user;
    }

    // Generate a retention report
    nlohmann::json report(const MediaMetadataStore& metadata) const {
        nlohmann::json j;
        int64_t now = now_ms();

        auto all = metadata.all_active();
        int64_t expired_local = 0;
        int64_t expired_remote = 0;
        int64_t quarantined = 0;
        int64_t soft_deleted = 0;
        int64_t purgable = 0;
        size_t total_bytes = 0;

        for (const auto& rec : all) {
            total_bytes += rec.media_length;
            if (!rec.is_remote && is_expired_local(rec, now)) ++expired_local;
            if (rec.is_remote && is_expired_remote(rec, now)) ++expired_remote;
            if (rec.quarantined) ++quarantined;
            if (rec.deleted) {
                ++soft_deleted;
                if (can_purge(rec, now)) ++purgable;
            }
        }

        j["total_media"] = all.size();
        j["total_bytes"] = total_bytes;
        j["expired_local"] = expired_local;
        j["expired_remote"] = expired_remote;
        j["quarantined"] = quarantined;
        j["soft_deleted"] = soft_deleted;
        j["purgable_hard_delete"] = purgable;
        j["global_quota"] = config_.max_storage_quota_global;
        j["global_usage_percent"] = config_.max_storage_quota_global > 0
            ? (total_bytes * 100.0 / config_.max_storage_quota_global) : 0.0;
        j["now_ts"] = now;

        return j;
    }

    Config config_;
};

// ============================================================================
// MediaStorePipeline — Main orchestrator class
// ============================================================================

class MediaStorePipeline {
public:
    struct Config {
        std::string base_path = "/var/lib/progressive/media";
        std::string server_name = "localhost";
        size_t max_upload_size = DEFAULT_MAX_UPLOAD_SIZE;
        bool enable_dedup = true;
        bool enable_remote_cache = true;
        bool enable_url_preview = true;
        bool strip_exif = true;
        bool scan_content = false;
        RetentionPolicy::Config retention;
        ThumbnailGenerator::Config thumbnails;
        RemoteMediaProxy::Config remote_proxy;
        UrlPreviewFetcher::Config url_preview;
    };

    explicit MediaStorePipeline(const Config& cfg)
        : config_(cfg),
          storage_(cfg.base_path),
          dedup_store_(DEFAULT_DEDUP_CACHE_SIZE),
          url_cache_(DEFAULT_LRU_CACHE_SIZE),
          thumbnailer_(cfg.thumbnails, storage_),
          remote_proxy_(cfg.remote_proxy),
          url_fetcher_(cfg.url_preview),
          retention_(cfg.retention)
    {
        // Load persisted metadata if available
        load_metadata();
        // Load dedup store if available
        auto dedup_path = fs::path(cfg.base_path) / "dedup_store.txt";
        if (fs::exists(dedup_path)) {
            dedup_store_.load_from_disk(dedup_path);
        }
    }

    ~MediaStorePipeline() {
        // Persist state on shutdown
        save_metadata();
        dedup_store_.save_to_disk(fs::path(config_.base_path) / "dedup_store.txt");
    }

    // =========================================================================
    // Media Upload Handler
    // =========================================================================

    struct UploadResult {
        std::string media_id;
        std::string content_uri;     // mxc:// URI
        std::string content_hash;    // SHA-256
        std::string content_type;
        int64_t media_length = 0;
        bool success = false;
        std::string error;
        std::string errcode;
    };

    UploadResult upload(const std::vector<uint8_t>& data,
                         const std::string& upload_name,
                         const std::string& user_id,
                         const std::string& content_type_hint = "") {
        UploadResult result;

        // Rate limiting / concurrent upload tracking
        stats_.current_active_uploads.fetch_add(1);
        struct RaiiCounter {
            std::atomic<int64_t>& c;
            ~RaiiCounter() { c.fetch_sub(1); }
        } raii{stats_.current_active_uploads};

        // Validate size
        if (data.empty()) {
            result.error = "Empty upload not allowed";
            result.errcode = "M_INVALID_PARAM";
            return result;
        }

        if (data.size() > config_.max_upload_size) {
            result.error = "Upload too large. Maximum size: " +
                           std::to_string(config_.max_upload_size) + " bytes";
            result.errcode = "M_TOO_LARGE";
            return result;
        }

        // Extract extension and validate
        std::string ext = extract_extension(upload_name);
        if (is_extension_blocked(ext)) {
            result.error = "File extension '" + ext + "' is blocked for security reasons";
            result.errcode = "M_UNKNOWN";
            return result;
        }

        // Detect content type
        std::string detected_mime = detect_mime_type(data);
        std::string content_type = content_type_hint.empty() ? detected_mime : content_type_hint;

        // Validate content type against extension
        if (!ext.empty() && !content_type_hint.empty()) {
            std::string ext_mime = mime_from_extension(ext);
            // If there's a severe mismatch, prefer magic detection
            if (detected_mime != "application/octet-stream" &&
                detected_mime != ext_mime &&
                !detected_mime.starts_with("text/")) {
                content_type = detected_mime;
            }
        }

        // Classify for size limits
        MediaCategory cat = classify_mime_type(content_type);
        size_t cat_max = max_size_for_category(cat);
        if (data.size() > cat_max) {
            result.error = "Upload exceeds maximum size for this content type (" +
                           std::to_string(cat_max) + " bytes)";
            result.errcode = "M_TOO_LARGE";
            return result;
        }

        // Check per-user quota
        size_t user_bytes = metadata_.bytes_by_user(user_id);
        size_t user_quota = retention_.quota_for_user(user_id);
        if (user_bytes + data.size() > user_quota) {
            result.error = "User storage quota exceeded. Current: " +
                           std::to_string(user_bytes) + ", Quota: " +
                           std::to_string(user_quota);
            result.errcode = "M_TOO_LARGE";
            return result;
        }

        // Check global quota
        size_t global_bytes = metadata_.total_local_bytes();
        if (global_bytes + data.size() > retention_.config_.max_storage_quota_global) {
            result.error = "Server storage quota exceeded";
            result.errcode = "M_TOO_LARGE";
            return result;
        }

        // Compute content hash for dedup
        std::string content_hash = sha256_hex(data);

        // Deduplication check
        if (config_.enable_dedup) {
            auto existing = dedup_store_.lookup(content_hash);
            if (existing) {
                // Duplicate found — return existing media_id
                stats_.total_dedup_hits.fetch_add(1);
                result.media_id = *existing;
                result.content_uri = mxc_uri(config_.server_name, result.media_id);
                result.content_hash = content_hash;
                result.content_type = content_type;
                result.media_length = static_cast<int64_t>(data.size());
                result.success = true;

                // Update stats for existing media
                auto rec = metadata_.get(*existing);
                if (rec) {
                    metadata_.touch(*existing);
                }

                return result;
            }
            stats_.total_dedup_misses.fetch_add(1);
        }

        // Generate media ID
        std::string media_id = generate_media_id();

        // Determine storage path
        fs::path store_path = storage_.storage_path(media_id);

        // Strip EXIF if configured for images
        std::vector<uint8_t> final_data = data;
        if (config_.strip_exif && content_type.starts_with("image/") &&
            content_type != "image/svg+xml") {
            final_data = strip_exif_data(data);
        }

        // Write file atomically
        if (!storage_.write_atomic(store_path, final_data)) {
            result.error = "Failed to write media file to storage";
            result.errcode = "M_UNKNOWN";
            return result;
        }

        // Create metadata record
        MediaRecord rec;
        rec.media_id = media_id;
        rec.storage_path = store_path.string();
        rec.content_hash = content_hash;
        rec.content_type = content_type;
        rec.upload_name = upload_name;
        rec.user_id = user_id;
        rec.media_length = static_cast<int64_t>(final_data.size());
        rec.created_ts = now_ms();
        rec.last_access_ts = rec.created_ts;
        rec.access_count = 1;
        rec.category = cat;
        rec.is_remote = false;

        metadata_.upsert(rec);

        // Register in dedup store
        if (config_.enable_dedup) {
            dedup_store_.insert(content_hash, media_id);
        }

        // Generate thumbnails for images and videos (async-friendly)
        if (content_type.starts_with("image/") && content_type != "image/svg+xml") {
            auto thumbs = thumbnailer_.generate_all_presets(media_id);
            rec.thumbnails = thumbs;
            metadata_.upsert(rec);
            stats_.total_thumbnails_generated.fetch_add(thumbs.size());
        }

        // Update statistics
        stats_.total_uploads.fetch_add(1);
        stats_.total_bytes_uploaded.fetch_add(rec.media_length);
        stats_.current_storage_bytes.fetch_add(rec.media_length);
        auto cat_idx = static_cast<int>(cat);
        if (cat_idx >= 0 && cat_idx < 7) {
            stats_.uploads_by_category[cat_idx].fetch_add(1);
            stats_.bytes_by_category[cat_idx].fetch_add(rec.media_length);
        }

        // Per-user stats
        {
            std::unique_lock lock(stats_.user_stat_mutex);
            auto& us = stats_.per_user[user_id];
            us.upload_count.fetch_add(1);
            us.total_bytes.fetch_add(rec.media_length);
            us.last_upload_ts.store(now_sec());
        }

        result.media_id = media_id;
        result.content_uri = mxc_uri(config_.server_name, media_id);
        result.content_hash = content_hash;
        result.content_type = content_type;
        result.media_length = rec.media_length;
        result.success = true;

        return result;
    }

    // =========================================================================
    // Media Download Handler
    // =========================================================================

    struct DownloadResult {
        std::vector<uint8_t> data;
        std::string content_type;
        std::string content_disposition;
        int64_t media_length = 0;
        bool success = false;
        std::string error;
        std::string errcode;
        bool is_quarantined = false;
    };

    DownloadResult download(const std::string& server_name,
                             const std::string& media_id,
                             bool allow_remote = true,
                             bool allow_redirect = false) {
        DownloadResult result;

        // Validate media_id for path traversal
        std::string safe_id = sanitize_path_component(media_id);
        if (safe_id.empty() || safe_id.size() > 255) {
            result.error = "Invalid media ID";
            result.errcode = "M_INVALID_PARAM";
            return result;
        }

        // Check local media
        auto local_rec = metadata_.get(safe_id);
        if (local_rec && !local_rec->deleted) {
            // Check quarantine
            if (local_rec->quarantined) {
                result.error = "Media is quarantined";
                result.errcode = "M_UNKNOWN";
                result.is_quarantined = true;
                return result;
            }

            // Read file
            auto path = storage_.storage_path(safe_id);
            auto data = storage_.read_file(path);
            if (data.empty() && !local_rec->is_remote) {
                result.error = "Media file not found on disk";
                result.errcode = "M_NOT_FOUND";
                return result;
            }

            // Update access tracking
            metadata_.touch(safe_id);

            result.data = std::move(data);
            result.content_type = local_rec->content_type;
            result.content_disposition = "inline; filename=\"" + local_rec->upload_name + "\"";
            result.media_length = local_rec->media_length;
            result.success = true;

            stats_.total_downloads.fetch_add(1);
            stats_.total_bytes_downloaded.fetch_add(local_rec->media_length);
            return result;
        }

        // Remote media: proxy
        if (allow_remote && server_name != config_.server_name) {
            return download_remote(server_name, safe_id, allow_redirect);
        }

        result.error = "Media not found";
        result.errcode = "M_NOT_FOUND";
        return result;
    }

    DownloadResult download_remote(const std::string& server_name,
                                    const std::string& media_id,
                                    bool allow_redirect) {
        DownloadResult result;

        // Check remote cache first
        auto cached = metadata_.get(media_id);
        if (cached && cached->is_remote && cached->origin == server_name && !cached->deleted) {
            auto path = storage_.remote_cache_path(server_name, media_id);
            auto data = storage_.read_file(path);
            if (!data.empty()) {
                metadata_.touch(media_id);
                result.data = std::move(data);
                result.content_type = cached->content_type;
                result.content_disposition = "inline; filename=\"" + cached->upload_name + "\"";
                result.media_length = cached->media_length;
                result.success = true;
                stats_.total_downloads.fetch_add(1);
                stats_.total_bytes_downloaded.fetch_add(cached->media_length);
                return result;
            }
        }

        // Fetch from remote
        auto remote = remote_proxy_.download(server_name, media_id);
        if (!remote.success) {
            result.error = remote.error;
            result.errcode = "M_NOT_FOUND";
            return result;
        }

        // Cache the remote media
        if (config_.enable_remote_cache) {
            auto cache_path = storage_.remote_cache_path(server_name, media_id);
            storage_.write_atomic(cache_path, remote.data);

            MediaRecord rec;
            rec.media_id = media_id;
            rec.storage_path = cache_path.string();
            rec.content_hash = sha256_hex(remote.data);
            rec.content_type = remote.content_type;
            rec.upload_name = media_id;
            rec.origin = server_name;
            rec.media_length = static_cast<int64_t>(remote.data.size());
            rec.created_ts = now_ms();
            rec.last_access_ts = rec.created_ts;
            rec.is_remote = true;
            rec.etag = remote.etag;
            rec.expires_ts = now_ms() + DEFAULT_DELETE_RECOVERY_WINDOW_SEC * 1000;
            metadata_.upsert(rec);

            stats_.current_remote_cache_bytes.fetch_add(rec.media_length);
        }

        result.data = std::move(remote.data);
        result.content_type = remote.content_type;
        result.content_disposition = "inline";
        result.media_length = static_cast<int64_t>(result.data.size());
        result.success = true;

        stats_.total_downloads.fetch_add(1);
        stats_.total_bytes_downloaded.fetch_add(result.media_length);
        stats_.total_remote_proxied.fetch_add(1);
        stats_.total_bytes_remote_proxied.fetch_add(result.media_length);

        return result;
    }

    // =========================================================================
    // Thumbnail Handler
    // =========================================================================

    struct ThumbnailResult {
        std::vector<uint8_t> data;
        std::string content_type;
        int width = 0;
        int height = 0;
        bool success = false;
        std::string error;
    };

    ThumbnailResult thumbnail(const std::string& server_name,
                               const std::string& media_id,
                               int width, int height,
                               const std::string& method_str = "scale") {
        ThumbnailResult result;

        // Validate parameters
        if (width < 1 || height < 1 ||
            width > static_cast<int>(DEFAULT_MAX_THUMB_WIDTH) ||
            height > static_cast<int>(DEFAULT_MAX_THUMB_HEIGHT)) {
            result.error = "Invalid thumbnail dimensions";
            return result;
        }

        // Parse method
        ThumbMethod method = (method_str == "crop") ? ThumbMethod::CROP : ThumbMethod::SCALE;

        // For local media
        auto local_rec = metadata_.get(media_id);
        if (local_rec && !local_rec->deleted && !local_rec->is_remote) {
            if (local_rec->quarantined) {
                result.error = "Media is quarantined";
                return result;
            }

            auto thumb = thumbnailer_.get_or_generate(media_id, width, height,
                                                       method, ThumbFormat::JPEG);
            if (thumb.success) {
                result.data = std::move(thumb.data);
                result.content_type = thumb.mime_type;
                result.width = thumb.width;
                result.height = thumb.height;
                result.success = true;
                stats_.total_thumbnails_served.fetch_add(1);
                return result;
            }
            result.error = thumb.error;
            return result;
        }

        // For remote media, try to proxy the thumbnail
        if (server_name != config_.server_name) {
            auto remote = remote_proxy_.download_thumbnail(
                server_name, media_id, width, height, method_str);
            if (remote.success) {
                result.data = std::move(remote.data);
                result.content_type = remote.content_type;
                result.width = width;
                result.height = height;
                result.success = true;
                stats_.total_thumbnails_served.fetch_add(1);
                return result;
            }
            result.error = remote.error;
            return result;
        }

        result.error = "Media not found";
        return result;
    }

    // =========================================================================
    // URL Preview Handler
    // =========================================================================

    struct UrlPreviewResult {
        nlohmann::json preview;
        bool success = false;
        std::string error;
    };

    UrlPreviewResult url_preview(const std::string& url, int64_t ts = 0) {
        UrlPreviewResult result;

        if (!config_.enable_url_preview) {
            result.error = "URL previews are disabled";
            return result;
        }

        // Check cache
        auto cached = url_cache_.get(url);
        if (cached && cached->expires_ts > now_ms()) {
            result.preview = url_record_to_json(*cached);
            result.success = true;
            stats_.total_url_previews_served.fetch_add(1);
            return result;
        }

        // Fetch
        auto preview = url_fetcher_.fetch(url);
        if (!preview.success) {
            result.error = preview.error;
            return result;
        }

        // Cache
        url_cache_.put(preview.record);

        result.preview = url_record_to_json(preview.record);
        result.success = true;
        stats_.total_url_previews_fetched.fetch_add(1);

        return result;
    }

    // =========================================================================
    // Media Delete (Soft + Hard)
    // =========================================================================

    struct DeleteResult {
        bool success = false;
        std::string error;
        int64_t bytes_freed = 0;
    };

    DeleteResult delete_media(const std::string& media_id, DeleteType type = DeleteType::SOFT) {
        DeleteResult result;

        auto rec = metadata_.get(media_id);
        if (!rec) {
            result.error = "Media not found";
            return result;
        }

        if (type == DeleteType::SOFT) {
            // Soft delete: move file to trash, mark as deleted
            auto src_path = rec->is_remote
                ? storage_.remote_cache_path(rec->origin, media_id)
                : storage_.storage_path(media_id);

            if (storage_.exists(src_path)) {
                auto trash_path = storage_.trash_path(media_id, now_sec());
                storage_.move(src_path, trash_path);
            }

            metadata_.soft_delete(media_id);
            stats_.total_deletes_soft.fetch_add(1);
            result.success = true;
            result.bytes_freed = rec->media_length;
            return result;
        }

        // Hard delete: remove files completely
        if (rec->is_remote) {
            auto path = storage_.remote_cache_path(rec->origin, media_id);
            storage_.remove(path);
            stats_.current_remote_cache_bytes.fetch_sub(
                std::min(stats_.current_remote_cache_bytes.load(),
                         static_cast<size_t>(rec->media_length)));
        } else {
            auto path = storage_.storage_path(media_id);
            storage_.remove(path);

            // Remove thumbnails
            thumbnailer_.delete_thumbnails(media_id);
            stats_.current_storage_bytes.fetch_sub(
                std::min(stats_.current_storage_bytes.load(),
                         static_cast<size_t>(rec->media_length)));

            // Remove from dedup store
            if (config_.enable_dedup) {
                dedup_store_.remove(media_id);
            }
        }

        metadata_.remove(media_id);
        result.success = true;
        result.bytes_freed = rec->media_length;
        stats_.total_deletes_hard.fetch_add(1);

        return result;
    }

    // Delete all media for a user
    DeleteResult delete_user_media(const std::string& user_id) {
        DeleteResult result;
        auto media_list = metadata_.get_by_user(user_id, 100000, 0);
        for (const auto& rec : media_list) {
            auto dr = delete_media(rec.media_id, DeleteType::HARD);
            result.bytes_freed += dr.bytes_freed;
        }
        result.success = true;
        return result;
    }

    // =========================================================================
    // Quarantine Operations
    // =========================================================================

    struct QuarantineResult {
        bool success = false;
        std::string error;
        int64_t affected_count = 0;
    };

    QuarantineResult quarantine_media(const std::string& media_id, bool quarantined,
                                        QuarantineReason reason = QuarantineReason::ADMIN_MANUAL,
                                        const std::string& by = "admin") {
        QuarantineResult result;
        bool ok = metadata_.set_quarantine(media_id, quarantined, reason, by);
        if (!ok) {
            result.error = "Media not found";
            return result;
        }
        result.success = true;
        result.affected_count = 1;
        stats_.total_quarantine_actions.fetch_add(1);
        return result;
    }

    QuarantineResult quarantine_user_media(const std::string& user_id, bool quarantined,
                                              QuarantineReason reason = QuarantineReason::ADMIN_MANUAL,
                                              const std::string& by = "admin") {
        QuarantineResult result;
        result.affected_count = metadata_.quarantine_by_user(user_id, quarantined, reason, by);
        result.success = true;
        stats_.total_quarantine_actions.fetch_add(result.affected_count);
        return result;
    }

    // =========================================================================
    // Retention / Cleanup Operations
    // =========================================================================

    struct CleanupResult {
        int64_t local_expired_removed = 0;
        int64_t remote_expired_removed = 0;
        int64_t quarantined_purged = 0;
        int64_t soft_deleted_purged = 0;
        int64_t total_bytes_freed = 0;
    };

    CleanupResult run_cleanup() {
        CleanupResult cr;
        int64_t now = now_ms();

        // Purge soft-deleted past recovery window
        auto expired_deleted = metadata_.get_expired_deleted(
            retention_.config_.deleted_recovery_secs * 1000);
        for (const auto& rec : expired_deleted) {
            auto dr = delete_media(rec.media_id, DeleteType::HARD);
            cr.total_bytes_freed += dr.bytes_freed;
            cr.soft_deleted_purged++;
        }

        // Expire remote cache
        if (retention_.config_.auto_expire_remote) {
            auto expired_remote = metadata_.get_expired_remote(
                retention_.config_.remote_cache_max_age_secs * 1000);
            for (const auto& rec : expired_remote) {
                auto dr = delete_media(rec.media_id, DeleteType::HARD);
                cr.total_bytes_freed += dr.bytes_freed;
                cr.remote_expired_removed++;
            }
        }

        // Expire local media past max age
        auto all_active = metadata_.all_active();
        for (const auto& rec : all_active) {
            if (!rec.is_remote && retention_.is_expired_local(rec, now)) {
                auto dr = delete_media(rec.media_id, DeleteType::SOFT);
                cr.total_bytes_freed += dr.bytes_freed;
                cr.local_expired_removed++;
            }
        }

        // Auto-release expired quarantines
        auto quarantined = metadata_.get_quarantined();
        for (const auto& rec : quarantined) {
            if (retention_.is_quarantine_expired(rec, now)) {
                metadata_.set_quarantine(rec.media_id, false);
                cr.quarantined_purged++;
            }
        }

        return cr;
    }

    // =========================================================================
    // Admin API Methods
    // =========================================================================

    nlohmann::json admin_stats() const {
        return stats_.snapshot();
    }

    nlohmann::json admin_list_media(const std::string& user_id = "",
                                      int64_t limit = 100,
                                      int64_t offset = 0) const {
        nlohmann::json result = nlohmann::json::array();
        std::vector<MediaRecord> list;

        if (!user_id.empty()) {
            list = metadata_.get_by_user(user_id, limit, offset);
        } else {
            auto all = metadata_.all_active();
            int64_t skipped = 0;
            for (const auto& rec : all) {
                if (skipped < offset) { ++skipped; continue; }
                list.push_back(rec);
                if (static_cast<int64_t>(list.size()) >= limit) break;
            }
        }

        for (const auto& rec : list) {
            nlohmann::json j;
            j["media_id"] = rec.media_id;
            j["content_type"] = rec.content_type;
            j["upload_name"] = rec.upload_name;
            j["user_id"] = rec.user_id;
            j["media_length"] = rec.media_length;
            j["created_ts"] = rec.created_ts;
            j["last_access_ts"] = rec.last_access_ts;
            j["access_count"] = rec.access_count;
            j["category"] = static_cast<int>(rec.category);
            j["quarantined"] = rec.quarantined;
            j["is_remote"] = rec.is_remote;
            j["deleted"] = rec.deleted;
            j["content_uri"] = mxc_uri(config_.server_name, rec.media_id);
            result.push_back(j);
        }
        return result;
    }

    nlohmann::json admin_get_media(const std::string& media_id) const {
        auto rec = metadata_.get(media_id);
        if (!rec) return nlohmann::json::object();

        nlohmann::json j;
        j["media_id"] = rec->media_id;
        j["content_hash"] = rec->content_hash;
        j["content_type"] = rec->content_type;
        j["upload_name"] = rec->upload_name;
        j["user_id"] = rec->user_id;
        j["origin"] = rec->origin;
        j["media_length"] = rec->media_length;
        j["created_ts"] = rec->created_ts;
        j["last_access_ts"] = rec->last_access_ts;
        j["access_count"] = rec->access_count;
        j["category"] = static_cast<int>(rec->category);
        j["quarantined"] = rec->quarantined;
        j["quarantine_reason"] = static_cast<int>(rec->quarantine_reason);
        j["quarantine_by"] = rec->quarantine_by;
        j["quarantine_ts"] = rec->quarantine_ts;
        j["safe_from_quarantine"] = rec->safe_from_quarantine;
        j["deleted"] = rec->deleted;
        j["deleted_ts"] = rec->deleted_ts;
        j["is_remote"] = rec->is_remote;
        j["content_uri"] = mxc_uri(config_.server_name, rec->media_id);
        j["storage_path"] = rec->storage_path;

        // Thumbnails info
        nlohmann::json thumbs = nlohmann::json::array();
        for (const auto& t : rec->thumbnails) {
            nlohmann::json tj;
            tj["width"] = t.width;
            tj["height"] = t.height;
            tj["method"] = static_cast<int>(t.method);
            tj["format"] = static_cast<int>(t.format);
            tj["length"] = t.thumb_length;
            thumbs.push_back(tj);
        }
        j["thumbnails"] = thumbs;

        return j;
    }

    nlohmann::json admin_quarantine_list() const {
        nlohmann::json arr = nlohmann::json::array();
        auto list = metadata_.get_quarantined();
        for (const auto& rec : list) {
            nlohmann::json j;
            j["media_id"] = rec.media_id;
            j["content_type"] = rec.content_type;
            j["user_id"] = rec.user_id;
            j["quarantine_reason"] = static_cast<int>(rec.quarantine_reason);
            j["quarantine_by"] = rec.quarantine_by;
            j["quarantine_ts"] = rec.quarantine_ts;
            arr.push_back(j);
        }
        return arr;
    }

    nlohmann::json admin_retention_report() const {
        return retention_.report(metadata_);
    }

    nlohmann::json admin_user_stats(const std::string& user_id) const {
        nlohmann::json j;
        j["user_id"] = user_id;
        j["media_count"] = metadata_.count_by_user(user_id);
        j["total_bytes"] = metadata_.bytes_by_user(user_id);
        j["quota"] = retention_.quota_for_user(user_id);

        std::shared_lock lock(stats_.user_stat_mutex);
        auto it = stats_.per_user.find(user_id);
        if (it != stats_.per_user.end()) {
            j["upload_count"] = it->second.upload_count.load();
            j["last_upload_ts"] = it->second.last_upload_ts.load();
        }
        return j;
    }

    nlohmann::json admin_url_preview_cache() const {
        return url_cache_.snapshot();
    }

    bool admin_clear_url_preview_cache() {
        url_cache_.clear();
        return true;
    }

    bool admin_remove_url_preview(const std::string& url) {
        return url_cache_.remove(url);
    }

    // =========================================================================
    // Configuration / Status
    // =========================================================================

    nlohmann::json status() const {
        nlohmann::json j;
        j["server_name"] = config_.server_name;
        j["base_path"] = config_.base_path;
        j["max_upload_size"] = config_.max_upload_size;
        j["dedup_enabled"] = config_.enable_dedup;
        j["remote_cache_enabled"] = config_.enable_remote_cache;
        j["url_preview_enabled"] = config_.enable_url_preview;
        j["total_local_media"] = metadata_.size();
        j["total_local_bytes"] = metadata_.total_local_bytes();
        j["total_remote_bytes"] = metadata_.total_remote_bytes();
        j["dedup_store_entries"] = dedup_store_.size();
        j["url_cache_entries"] = url_cache_.size();
        j["current_storage_bytes"] = stats_.current_storage_bytes.load();
        j["current_remote_cache_bytes"] = stats_.current_remote_cache_bytes.load();
        j["stats"] = stats_.snapshot();
        j["retention"] = retention_.report(metadata_);
        return j;
    }

    // Access to components
    MediaMetadataStore& metadata() { return metadata_; }
    MediaStorageProvider& storage() { return storage_; }
    MediaDedupStore& dedup() { return dedup_store_; }
    MediaStats& stats() { return stats_; }
    RetentionPolicy& retention() { return retention_; }

    // Persist metadata to disk
    void save_metadata() {
        auto meta_path = fs::path(config_.base_path) / "metadata.json";
        auto j = metadata_.to_json();
        std::ofstream f(meta_path);
        if (f) {
            f << j.dump(2);
        }
    }

    // Load metadata from disk
    void load_metadata() {
        auto meta_path = fs::path(config_.base_path) / "metadata.json";
        std::ifstream f(meta_path);
        if (f) {
            std::string content((std::istreambuf_iterator<char>(f)),
                                 std::istreambuf_iterator<char>());
            try {
                auto j = nlohmann::json::parse(content);
                if (j.is_array()) {
                    metadata_.from_json(j);
                }
            } catch (...) {
                // Parse error; start fresh
            }
        }
    }

private:
    // =========================================================================
    // EXIF stripping (basic implementation)
    // =========================================================================
    static std::vector<uint8_t> strip_exif_data(const std::vector<uint8_t>& data) {
        // For JPEG: look for APP1 (0xFF 0xE1) marker and remove it
        // This is a simplistic implementation — real EXIF stripping needs
        // full JPEG marker parsing. Production should use a library.
        if (data.size() < 4) return data;
        if (data[0] != 0xFF || data[1] != 0xD8) return data; // not JPEG SOI

        std::vector<uint8_t> out;
        out.push_back(0xFF);
        out.push_back(0xD8);

        for (size_t i = 2; i + 3 < data.size();) {
            if (data[i] == 0xFF) {
                uint8_t marker = data[i + 1];
                // APP1 (EXIF), APP2, and COM markers
                if (marker == 0xE1 || marker == 0xE2 || marker == 0xFE) {
                    // Skip this segment
                    size_t seg_len = (static_cast<size_t>(data[i + 2]) << 8) | data[i + 3];
                    i += 2 + seg_len;
                    continue;
                }
                // For other markers, copy them through
                if (marker == 0xDA) {
                    // Start of scan — copy rest
                    out.insert(out.end(), data.begin() + i, data.end());
                    break;
                }
                out.push_back(data[i]);
                out.push_back(data[i + 1]);
                if (marker != 0xD8 && marker != 0xD9 && marker != 0x01 &&
                    marker < 0xD0) {
                    size_t seg_len = (static_cast<size_t>(data[i + 2]) << 8) | data[i + 3];
                    out.insert(out.end(), data.begin() + i + 2, data.begin() + i + 2 + seg_len);
                    i += 2 + seg_len;
                } else {
                    i += 2;
                }
            } else {
                out.push_back(data[i]);
                i++;
            }
        }

        return out;
    }

    // =========================================================================
    // URL preview record to JSON
    // =========================================================================
    static nlohmann::json url_record_to_json(const UrlPreviewRecord& rec) {
        nlohmann::json j;
        j["url"] = rec.url;
        if (!rec.og_title.empty())
            j["og:title"] = rec.og_title;
        if (!rec.og_description.empty())
            j["og:description"] = rec.og_description;
        if (!rec.og_image_url.empty()) {
            j["og:image"] = rec.og_image_url;
            if (rec.og_image_width > 0)
                j["og:image:width"] = rec.og_image_width;
            if (rec.og_image_height > 0)
                j["og:image:height"] = rec.og_image_height;
            if (rec.og_image_size > 0)
                j["og:image:size"] = rec.og_image_size;
        }
        if (!rec.og_type.empty())
            j["og:type"] = rec.og_type;
        if (!rec.og_site_name.empty())
            j["og:site_name"] = rec.og_site_name;
        if (!rec.twitter_card.empty())
            j["twitter:card"] = rec.twitter_card;
        if (!rec.oembed_json.empty())
            j["oembed_url"] = rec.oembed_json;
        j["matrix:image:size"] = rec.og_image_size;
        return j;
    }

    Config config_;
    MediaStorageProvider storage_;
    MediaDedupStore dedup_store_;
    MediaMetadataStore metadata_;
    UrlPreviewCache url_cache_;
    ThumbnailGenerator thumbnailer_;
    RemoteMediaProxy remote_proxy_;
    UrlPreviewFetcher url_fetcher_;
    RetentionPolicy retention_;
    MediaStats stats_;
};

// ============================================================================
// Singleton accessor for the MediaStorePipeline
// ============================================================================

static std::unique_ptr<MediaStorePipeline> g_pipeline;
static std::mutex g_pipeline_mutex;

MediaStorePipeline& get_pipeline() {
    std::lock_guard lock(g_pipeline_mutex);
    if (!g_pipeline) {
        MediaStorePipeline::Config cfg;
        cfg.base_path = "/var/lib/progressive/media";
        cfg.server_name = "localhost";
        cfg.remote_proxy.server_name = "localhost";
        g_pipeline = std::make_unique<MediaStorePipeline>(cfg);
    }
    return *g_pipeline;
}

void init_pipeline(const MediaStorePipeline::Config& cfg) {
    std::lock_guard lock(g_pipeline_mutex);
    g_pipeline = std::make_unique<MediaStorePipeline>(cfg);
}

void shutdown_pipeline() {
    std::lock_guard lock(g_pipeline_mutex);
    if (g_pipeline) {
        g_pipeline->save_metadata();
        g_pipeline.reset();
    }
}

// ============================================================================
// Convenience free functions for use by HTTP handlers
// ============================================================================

UploadResult upload_media(const std::vector<uint8_t>& data,
                           const std::string& upload_name,
                           const std::string& user_id,
                           const std::string& content_type) {
    return get_pipeline().upload(data, upload_name, user_id, content_type);
}

DownloadResult download_media(const std::string& server_name,
                               const std::string& media_id,
                               bool allow_remote) {
    return get_pipeline().download(server_name, media_id, allow_remote);
}

ThumbnailResult get_thumbnail(const std::string& server_name,
                               const std::string& media_id,
                               int width, int height,
                               const std::string& method) {
    return get_pipeline().thumbnail(server_name, media_id, width, height, method);
}

UrlPreviewResult get_url_preview(const std::string& url, int64_t ts) {
    return get_pipeline().url_preview(url, ts);
}

DeleteResult delete_media_by_id(const std::string& media_id, bool hard) {
    return get_pipeline().delete_media(media_id, hard ? DeleteType::HARD : DeleteType::SOFT);
}

DeleteResult delete_user_media_all(const std::string& user_id) {
    return get_pipeline().delete_user_media(user_id);
}

QuarantineResult quarantine_media_by_id(const std::string& media_id,
                                          bool quarantined,
                                          QuarantineReason reason,
                                          const std::string& by) {
    return get_pipeline().quarantine_media(media_id, quarantined, reason, by);
}

QuarantineResult quarantine_user_media_all(const std::string& user_id,
                                              bool quarantined) {
    return get_pipeline().quarantine_user_media(user_id, quarantined);
}

CleanupResult run_media_cleanup() {
    return get_pipeline().run_cleanup();
}

nlohmann::json admin_media_stats() {
    return get_pipeline().admin_stats();
}

nlohmann::json admin_media_list(const std::string& user_id,
                                  int64_t limit, int64_t offset) {
    return get_pipeline().admin_list_media(user_id, limit, offset);
}

nlohmann::json admin_media_detail(const std::string& media_id) {
    return get_pipeline().admin_get_media(media_id);
}

nlohmann::json admin_quarantine_list() {
    return get_pipeline().admin_quarantine_list();
}

nlohmann::json admin_retention_report() {
    return get_pipeline().admin_retention_report();
}

nlohmann::json admin_user_media_stats(const std::string& user_id) {
    return get_pipeline().admin_user_stats(user_id);
}

nlohmann::json admin_url_preview_cache_list() {
    return get_pipeline().admin_url_preview_cache();
}

bool admin_clear_url_cache() {
    return get_pipeline().admin_clear_url_preview_cache();
}

bool admin_remove_url_cache_entry(const std::string& url) {
    return get_pipeline().admin_remove_url_preview(url);
}

nlohmann::json pipeline_status() {
    return get_pipeline().status();
}

// ============================================================================
// Background maintenance worker
// ============================================================================

static std::atomic<bool> g_maintenance_running{false};
static std::thread g_maintenance_thread;

void start_background_maintenance(int64_t interval_secs = 3600) {
    if (g_maintenance_running.exchange(true)) return;

    g_maintenance_thread = std::thread([interval_secs]() {
        while (g_maintenance_running.load()) {
            std::this_thread::sleep_for(std::chrono::seconds(interval_secs));
            if (!g_maintenance_running.load()) break;

            try {
                auto result = get_pipeline().run_cleanup();
                // Log cleanup results (production: use structured logging)
                if (result.total_bytes_freed > 0 ||
                    result.local_expired_removed > 0 ||
                    result.remote_expired_removed > 0 ||
                    result.soft_deleted_purged > 0) {
                    std::cerr << "[media] Cleanup: local_expired="
                              << result.local_expired_removed
                              << " remote_expired=" << result.remote_expired_removed
                              << " soft_deleted_purged=" << result.soft_deleted_purged
                              << " bytes_freed=" << result.total_bytes_freed
                              << std::endl;
                }

                // Persist metadata periodically
                get_pipeline().save_metadata();

                // Persist dedup store
                get_pipeline().dedup().save_to_disk(
                    std::filesystem::path(get_pipeline().status()["base_path"].get<std::string>()) /
                    "dedup_store.txt");

                // Reset stats window if past hour
                auto snap = get_pipeline().admin_stats();
                int64_t ws = snap.value("window_start_ts", int64_t(0));
                int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count();
                if (now - ws > 3600) {
                    get_pipeline().stats().reset_window();
                }
            } catch (const std::exception& e) {
                std::cerr << "[media] Maintenance error: " << e.what() << std::endl;
            }
        }
    });
}

void stop_background_maintenance() {
    g_maintenance_running.store(false);
    if (g_maintenance_thread.joinable()) {
        g_maintenance_thread.join();
    }
}

// ============================================================================
// Storage usage query helpers
// ============================================================================

struct StorageUsage {
    size_t total_bytes = 0;
    size_t local_bytes = 0;
    size_t remote_bytes = 0;
    size_t thumbnail_bytes = 0;
    size_t url_cache_bytes = 0;
    int64_t media_count = 0;
    int64_t remote_count = 0;
    int64_t thumbnail_count = 0;
    int64_t url_cache_count = 0;
    int64_t quarantine_count = 0;
};

StorageUsage get_storage_usage() {
    StorageUsage usage;
    usage.local_bytes = get_pipeline().metadata().total_local_bytes();
    usage.remote_bytes = get_pipeline().metadata().total_remote_bytes();
    usage.total_bytes = usage.local_bytes + usage.remote_bytes;

    auto all = get_pipeline().metadata().all_active();
    for (const auto& rec : all) {
        usage.media_count++;
        if (rec.is_remote) usage.remote_count++;
        if (rec.quarantined) usage.quarantine_count++;
    }

    // Thumbnail and cache estimates
    usage.thumbnail_bytes = get_pipeline().stats().current_thumbnail_cache_bytes.load();
    usage.remote_bytes = get_pipeline().stats().current_remote_cache_bytes.load();

    return usage;
}

nlohmann::json storage_usage_json() {
    auto u = get_storage_usage();
    nlohmann::json j;
    j["total_bytes"] = u.total_bytes;
    j["local_bytes"] = u.local_bytes;
    j["remote_cache_bytes"] = u.remote_bytes;
    j["thumbnail_bytes"] = u.thumbnail_bytes;
    j["url_cache_bytes"] = u.url_cache_bytes;
    j["media_count"] = u.media_count;
    j["remote_count"] = u.remote_count;
    j["thumbnail_count"] = u.thumbnail_count;
    j["url_cache_count"] = u.url_cache_count;
    j["quarantine_count"] = u.quarantine_count;
    return j;
}

// ============================================================================
// Recompute disk usage by walking storage directories
// ============================================================================

nlohmann::json recompute_disk_usage() {
    auto& pipeline = get_pipeline();
    auto& storage = pipeline.storage();

    nlohmann::json j;
    j["storage_bytes"] = storage.directory_size(
        storage.base_path() / "storage");
    j["remote_cache_bytes"] = storage.directory_size(
        storage.base_path() / "remote_cache");
    j["thumbnail_bytes"] = storage.directory_size(
        storage.base_path() / "thumbnails");
    j["url_cache_bytes"] = storage.directory_size(
        storage.base_path() / "url_cache");
    j["trash_bytes"] = storage.directory_size(
        storage.base_path() / "trash");
    j["quarantine_bytes"] = storage.directory_size(
        storage.base_path() / "quarantine");

    // Update stats from actual disk usage
    auto& stats = pipeline.stats();
    stats.current_storage_bytes.store(j["storage_bytes"].get<size_t>());
    stats.current_remote_cache_bytes.store(j["remote_cache_bytes"].get<size_t>());
    stats.current_thumbnail_cache_bytes.store(j["thumbnail_bytes"].get<size_t>());

    return j;
}

// ============================================================================
// Media integrity verification — checks SHA-256 of stored files
// ============================================================================

struct IntegrityResult {
    int64_t checked = 0;
    int64_t passed = 0;
    int64_t failed = 0;
    int64_t missing = 0;
    std::vector<std::string> corrupted_media_ids;
    std::vector<std::string> missing_media_ids;
};

IntegrityResult verify_media_integrity(int64_t limit = -1) {
    IntegrityResult result;
    auto& pipeline = get_pipeline();
    auto all = pipeline.metadata().all_active();

    for (const auto& rec : all) {
        if (limit >= 0 && result.checked >= limit) break;

        result.checked++;
        fs::path path;
        if (rec.is_remote) {
            path = pipeline.storage().remote_cache_path(rec.origin, rec.media_id);
        } else {
            path = pipeline.storage().storage_path(rec.media_id);
        }

        if (!pipeline.storage().exists(path)) {
            result.missing++;
            result.missing_media_ids.push_back(rec.media_id);
            continue;
        }

        // Verify hash if we have one
        if (!rec.content_hash.empty()) {
            std::string disk_hash = sha256_file(path);
            if (disk_hash != rec.content_hash) {
                result.failed++;
                result.corrupted_media_ids.push_back(rec.media_id);
                continue;
            }
        }

        result.passed++;
    }

    return result;
}

nlohmann::json verify_integrity_json(int64_t limit) {
    auto r = verify_media_integrity(limit);
    nlohmann::json j;
    j["checked"] = r.checked;
    j["passed"] = r.passed;
    j["failed"] = r.failed;
    j["missing"] = r.missing;
    j["corrupted_media_ids"] = r.corrupted_media_ids;
    j["missing_media_ids"] = r.missing_media_ids;
    return j;
}

// ============================================================================
// Bulk operations for admin use
// ============================================================================

nlohmann::json admin_bulk_quarantine(const std::vector<std::string>& media_ids,
                                       bool quarantined,
                                       const std::string& reason,
                                       const std::string& by) {
    nlohmann::json j;
    j["total"] = media_ids.size();
    int64_t success = 0;
    int64_t failed = 0;
    nlohmann::json errors = nlohmann::json::array();

    for (const auto& mid : media_ids) {
        auto r = get_pipeline().quarantine_media(
            mid, quarantined, QuarantineReason::ADMIN_MANUAL, by);
        if (r.success) success++;
        else {
            failed++;
            nlohmann::json e;
            e["media_id"] = mid;
            e["error"] = r.error;
            errors.push_back(e);
        }
    }

    j["success"] = success;
    j["failed"] = failed;
    j["errors"] = errors;
    return j;
}

nlohmann::json admin_bulk_delete(const std::vector<std::string>& media_ids, bool hard) {
    nlohmann::json j;
    j["total"] = media_ids.size();
    int64_t success = 0;
    int64_t failed = 0;
    int64_t bytes_freed = 0;
    nlohmann::json errors = nlohmann::json::array();

    for (const auto& mid : media_ids) {
        auto r = get_pipeline().delete_media(
            mid, hard ? DeleteType::HARD : DeleteType::SOFT);
        if (r.success) {
            success++;
            bytes_freed += r.bytes_freed;
        } else {
            failed++;
            nlohmann::json e;
            e["media_id"] = mid;
            e["error"] = r.error;
            errors.push_back(e);
        }
    }

    j["success"] = success;
    j["failed"] = failed;
    j["bytes_freed"] = bytes_freed;
    j["errors"] = errors;
    return j;
}

// ============================================================================
// End of namespace
// ============================================================================

}  // namespace media
}  // namespace progressive
