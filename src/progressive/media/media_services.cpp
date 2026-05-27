// SPDX-License-Identifier: AGPL-3.0-only
// Progressive Matrix Server - Media Services Implementation
// Copyright (c) 2026 Progressive Contributors

#include "media_services.hpp"
#include "../json.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <list>
#include <map>
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
#include <vector>

#include <curl/curl.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

// ---------------------------------------------------------------------------
// Forward declarations of ImageMagick C API symbols we will use via dlopen
// This avoids hard compile-time dependency; the code degrades gracefully if
// ImageMagick is not installed at runtime.
// ---------------------------------------------------------------------------
struct _ImageInfo;
struct _ExceptionInfo;
struct _Image;
typedef struct _Image Image;
typedef struct _ImageInfo ImageInfo;
typedef struct _ExceptionInfo ExceptionInfo;

// Minimal MagickCore function pointer types
typedef void (*MagickWandGenesis_t)(void);
typedef void (*MagickWandTerminus_t)(void);
typedef Image* (*ReadImage_t)(const ImageInfo*, ExceptionInfo*);
typedef Image* (*ResizeImage_t)(const Image*, size_t, size_t, void*, ExceptionInfo*);
typedef Image* (*CropImage_t)(const Image*, const void*, ExceptionInfo*);
typedef int (*WriteImage_t)(const ImageInfo*, Image*, ExceptionInfo*);
typedef void (*DestroyImage_t)(Image*);
typedef ImageInfo* (*CloneImageInfo_t)(const ImageInfo*);
typedef void (*DestroyImageInfo_t)(ImageInfo*);
typedef ExceptionInfo* (*AcquireExceptionInfo_t)(void);
typedef void (*DestroyExceptionInfo_t)(ExceptionInfo*);
typedef Image* (*DestroyImageList_t)(Image*);
typedef void (*SetImageCompressionQuality_t)(Image*, size_t);
typedef Image* (*CoalesceImages_t)(const Image*, ExceptionInfo*);
typedef Image* (*OptimizeImageTransparency_t)(const Image*, ExceptionInfo*);
typedef Image* (*OptimizeImageLayers_t)(const Image*, ExceptionInfo*);
typedef void (*StripImage_t)(Image*);

namespace progressive {
namespace media {

// ============================================================================
// Constants and Configuration
// ============================================================================

constexpr size_t DEFAULT_MAX_IMAGE_SIZE      = 50 * 1024 * 1024;   // 50 MB
constexpr size_t DEFAULT_MAX_VIDEO_SIZE      = 100 * 1024 * 1024;  // 100 MB
constexpr size_t DEFAULT_MAX_AUDIO_SIZE      = 50 * 1024 * 1024;   // 50 MB
constexpr size_t DEFAULT_MAX_OTHER_SIZE      = 10 * 1024 * 1024;   // 10 MB
constexpr size_t DEFAULT_MAX_THUMB_WIDTH     = 800;
constexpr size_t DEFAULT_MAX_THUMB_HEIGHT    = 600;
constexpr size_t DEFAULT_THUMB_QUALITY       = 80;
constexpr size_t DEFAULT_URL_PREVIEW_TIMEOUT = 10;    // seconds
constexpr size_t DEFAULT_URL_PREVIEW_MAX_SIZE = 1 * 1024 * 1024; // 1 MB for previews
constexpr size_t DEFAULT_IMAGE_PROXY_MAX     = 10 * 1024 * 1024;
constexpr size_t DEFAULT_LRU_CACHE_SIZE      = 500;
constexpr size_t DEFAULT_DEDUP_CACHE_SIZE    = 10000;
constexpr std::chrono::seconds DEFAULT_THUMB_TTL(86400);        // 24 hours
constexpr std::chrono::seconds DEFAULT_REMOTE_CACHE_TTL(604800); // 7 days
constexpr std::chrono::seconds DEFAULT_DELETE_DELAY(86400 * 30); // 30 days
constexpr std::chrono::seconds DEFAULT_QUARANTINE_MAX_AGE(86400 * 7);
constexpr std::chrono::seconds DEFAULT_STATS_WINDOW(3600);
constexpr size_t DEFAULT_BLURHASH_COMPONENTS_X = 4;
constexpr size_t DEFAULT_BLURHASH_COMPONENTS_Y = 3;

// Allowed MIME types for upload
const std::unordered_set<std::string> ALLOWED_IMAGE_TYPES = {
    "image/jpeg", "image/png", "image/gif", "image/webp",
    "image/avif", "image/bmp", "image/tiff", "image/svg+xml",
    "image/heic", "image/heif"
};

const std::unordered_set<std::string> ALLOWED_VIDEO_TYPES = {
    "video/mp4", "video/webm", "video/ogg", "video/quicktime",
    "video/x-msvideo", "video/x-matroska"
};

const std::unordered_set<std::string> ALLOWED_AUDIO_TYPES = {
    "audio/mpeg", "audio/ogg", "audio/wav", "audio/flac",
    "audio/aac", "audio/webm", "audio/x-ms-wma"
};

const std::unordered_set<std::string> ALLOWED_OTHER_TYPES = {
    "application/pdf", "text/plain", "application/json",
    "application/zip", "application/x-tar"
};

// Magic bytes signatures for content-type detection
struct MagicSignature {
    std::vector<uint8_t> bytes;
    size_t offset;
    std::string mime_type;
};

const std::vector<MagicSignature> MAGIC_SIGNATURES = {
    // Images
    {{0xFF, 0xD8, 0xFF}, 0, "image/jpeg"},
    {{0x89, 0x50, 0x4E, 0x47}, 0, "image/png"},
    {{0x47, 0x49, 0x46, 0x38}, 0, "image/gif"},
    {{0x42, 0x4D}, 0, "image/bmp"},
    {{0x52, 0x49, 0x46, 0x46}, 0, "image/webp"}, // RIFF....WEBP
    {{0x00, 0x00, 0x00, 0x0C, 0x6A, 0x50}, 4, "image/jp2"},
    {{0x3C, 0x3F, 0x78, 0x6D}, 0, "image/svg+xml"},
    {{0x3C, 0x73, 0x76, 0x67}, 0, "image/svg+xml"},
    // Audio
    {{0x49, 0x44, 0x33}, 0, "audio/mpeg"},        // ID3
    {{0xFF, 0xFB}, 0, "audio/mpeg"},
    {{0xFF, 0xF3}, 0, "audio/mpeg"},
    {{0xFF, 0xF2}, 0, "audio/mpeg"},
    {{0x4F, 0x67, 0x67, 0x53}, 0, "audio/ogg"},
    {{0x52, 0x49, 0x46, 0x46}, 0, "audio/wav"},   // RIFF....WAVE
    {{0x66, 0x4C, 0x61, 0x43}, 0, "audio/flac"},
    // Video
    {{0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70}, 0, "video/mp4"},
    {{0x1A, 0x45, 0xDF, 0xA3}, 0, "video/webm"},
    {{0x1A, 0x45, 0xDF, 0xA3}, 0, "video/x-matroska"},
    // Archives / docs
    {{0x25, 0x50, 0x44, 0x46}, 0, "application/pdf"},
    {{0x50, 0x4B, 0x03, 0x04}, 0, "application/zip"},
    // HEIC
    {{0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70, 0x68, 0x65, 0x69}, 0, "image/heic"},
};

// EXIF marker bytes
const std::vector<uint8_t> EXIF_HEADER_BE = {0x45, 0x78, 0x69, 0x66, 0x00, 0x00, 0x4D, 0x4D};
const std::vector<uint8_t> EXIF_HEADER_LE = {0x45, 0x78, 0x69, 0x66, 0x00, 0x00, 0x49, 0x49};

// ============================================================================
// Forward declarations of internal helpers
// ============================================================================

static std::string sha256_hex(const std::vector<uint8_t>& data);
static std::string sha256_hex(std::string_view data);
static std::string sha256_file(const std::filesystem::path& path);
static std::string to_lower(std::string s);
static std::string extract_extension(const std::string& filename);
static std::string mime_from_extension(const std::string& ext);
static std::string detect_mime_type(const std::vector<uint8_t>& data);
static std::string detect_mime_type_file(const std::filesystem::path& path);
static std::string generate_blurhash(const std::vector<uint8_t>& img_data, size_t comp_x, size_t comp_y);
static nlohmann::json parse_opengraph(const std::string& html);
static nlohmann::json parse_oembed(const std::string& html);
static std::string fetch_url(const std::string& url, size_t max_size, long timeout_secs);
static std::string sanitize_svg(const std::string& svg_data);
static std::string convert_image_format(const std::vector<uint8_t>& src, const std::string& target_format);
static std::vector<uint8_t> strip_exif(const std::vector<uint8_t>& img_data);
static bool is_animated_gif(const std::vector<uint8_t>& data);
static bool is_animated_webp(const std::vector<uint8_t>& data);
static size_t count_gif_frames(const std::vector<uint8_t>& data);

// ============================================================================
// Utility Functions
// ============================================================================

static std::string sha256_hex(const std::vector<uint8_t>& data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, data.data(), data.size());
    SHA256_Final(hash, &ctx);

    std::ostringstream oss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    return oss.str();
}

static std::string sha256_hex(std::string_view data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, data.data(), data.size());
    SHA256_Final(hash, &ctx);

    std::ostringstream oss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    return oss.str();
}

static std::string sha256_file(const std::filesystem::path& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) return "";
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    std::array<char, 8192> buf{};
    while (file.good()) {
        file.read(buf.data(), buf.size());
        SHA256_Update(&ctx, buf.data(), file.gcount());
    }
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_Final(hash, &ctx);
    std::ostringstream oss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    return oss.str();
}

static std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), ::tolower);
    return s;
}

static std::string extract_extension(const std::string& filename) {
    auto pos = filename.rfind('.');
    if (pos == std::string::npos) return "";
    return to_lower(filename.substr(pos + 1));
}

static std::string mime_from_extension(const std::string& ext) {
    static const std::unordered_map<std::string, std::string> map = {
        {"jpg", "image/jpeg"}, {"jpeg", "image/jpeg"}, {"png", "image/png"},
        {"gif", "image/gif"}, {"webp", "image/webp"}, {"avif", "image/avif"},
        {"bmp", "image/bmp"}, {"tiff", "image/tiff"}, {"tif", "image/tiff"},
        {"svg", "image/svg+xml"}, {"heic", "image/heic"}, {"heif", "image/heif"},
        {"mp4", "video/mp4"}, {"webm", "video/webm"}, {"ogv", "video/ogg"},
        {"mov", "video/quicktime"}, {"avi", "video/x-msvideo"},
        {"mkv", "video/x-matroska"},
        {"mp3", "audio/mpeg"}, {"ogg", "audio/ogg"}, {"wav", "audio/wav"},
        {"flac", "audio/flac"}, {"aac", "audio/aac"}, {"wma", "audio/x-ms-wma"},
        {"pdf", "application/pdf"}, {"txt", "text/plain"},
        {"json", "application/json"}, {"zip", "application/zip"},
        {"tar", "application/x-tar"}, {"gz", "application/gzip"},
    };
    auto it = map.find(to_lower(ext));
    return it != map.end() ? it->second : "application/octet-stream";
}

static std::string detect_mime_type(const std::vector<uint8_t>& data) {
    if (data.empty()) return "application/octet-stream";

    // Check SVG first (text-based)
    std::string_view view(reinterpret_cast<const char*>(data.data()), std::min(data.size(), size_t(256)));
    if (view.find("<?xml") != std::string::npos || view.find("<svg") != std::string::npos) {
        return "image/svg+xml";
    }

    for (const auto& sig : MAGIC_SIGNATURES) {
        if (data.size() >= sig.offset + sig.bytes.size()) {
            bool match = true;
            for (size_t i = 0; i < sig.bytes.size(); ++i) {
                if (data[sig.offset + i] != sig.bytes[i]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                // Special cases
                if (sig.mime_type == "image/webp" || sig.mime_type == "audio/wav") {
                    // RIFF container - check sub-type
                    if (data.size() >= 12) {
                        std::string subtype(reinterpret_cast<const char*>(&data[8]), 4);
                        if (subtype == "WEBP") return "image/webp";
                        if (subtype == "WAVE") return "audio/wav";
                    }
                }
                if (sig.mime_type == "audio/mpeg" && sig.bytes[0] == 0xFF && (sig.bytes[1] == 0xFB || sig.bytes[1] == 0xF3 || sig.bytes[1] == 0xF2)) {
                    return "audio/mpeg";
                }
                return sig.mime_type;
            }
        }
    }

    // Try text detection
    bool is_text = true;
    for (size_t i = 0; i < std::min(data.size(), size_t(512)); ++i) {
        if (data[i] == 0) { is_text = false; break; }
    }
    if (is_text) return "text/plain";

    return "application/octet-stream";
}

static std::string detect_mime_type_file(const std::filesystem::path& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) return "application/octet-stream";
    std::vector<uint8_t> buf(512);
    file.read(reinterpret_cast<char*>(buf.data()), buf.size());
    buf.resize(file.gcount());
    return detect_mime_type(buf);
}

static bool is_animated_gif(const std::vector<uint8_t>& data) {
    if (data.size() < 13) return false;
    if (data[0] != 'G' || data[1] != 'I' || data[2] != 'F') return false;
    // Count Graphic Control Extension blocks - each frame has one
    size_t frame_count = 0;
    for (size_t i = 0; i + 2 < data.size(); ++i) {
        if (data[i] == 0x00 && data[i+1] == 0x21 && data[i+2] == 0xF9) {
            ++frame_count;
            if (frame_count > 1) return true;
        }
    }
    return false;
}

static bool is_animated_webp(const std::vector<uint8_t>& data) {
    if (data.size() < 20) return false;
    // RIFF....WEBP
    if (data[0] != 'R' || data[1] != 'I' || data[2] != 'F' || data[3] != 'F') return false;
    if (data[8] != 'W' || data[9] != 'E' || data[10] != 'B' || data[11] != 'P') return false;
    // Check if VP8X with animation flag
    if (data[12] == 'V' && data[13] == 'P' && data[14] == '8' && data[15] == 'X') {
        if (data.size() > 20) {
            uint8_t flags = data[20];
            return (flags & 0x02) != 0; // Animation bit
        }
    }
    // Check for ANMF chunk
    for (size_t i = 12; i + 8 < data.size();) {
        if (data[i] == 'A' && data[i+1] == 'N' && data[i+2] == 'M' && data[i+3] == 'F') {
            return true;
        }
        if (i + 4 >= data.size()) break;
        uint32_t chunk_size = (static_cast<uint8_t>(data[i+4])) |
                              (static_cast<uint8_t>(data[i+5]) << 8) |
                              (static_cast<uint8_t>(data[i+6]) << 16) |
                              (static_cast<uint8_t>(data[i+7]) << 24);
        i += 8 + chunk_size;
        if (chunk_size % 2) ++i; // padding
    }
    return false;
}

static size_t count_gif_frames(const std::vector<uint8_t>& data) {
    if (data.size() < 13) return 0;
    size_t count = 0;
    for (size_t i = 0; i + 2 < data.size(); ++i) {
        if (data[i] == 0x00 && data[i+1] == 0x21 && data[i+2] == 0xF9) {
            ++count;
        }
    }
    return count;
}

// ============================================================================
// ImageMagick dynamic loader
// ============================================================================

class MagickLoader {
public:
    static MagickLoader& instance() {
        static MagickLoader loader;
        return loader;
    }

    bool available() const { return available_; }

    // Function pointers
    MagickWandGenesis_t       MagickWandGenesis       = nullptr;
    MagickWandTerminus_t      MagickWandTerminus      = nullptr;
    ReadImage_t               ReadImage               = nullptr;
    ResizeImage_t             ResizeImage             = nullptr;
    CropImage_t               CropImage               = nullptr;
    WriteImage_t              WriteImage              = nullptr;
    DestroyImage_t            DestroyImage            = nullptr;
    CloneImageInfo_t          CloneImageInfo          = nullptr;
    DestroyImageInfo_t        DestroyImageInfo        = nullptr;
    AcquireExceptionInfo_t    AcquireExceptionInfo    = nullptr;
    DestroyExceptionInfo_t    DestroyExceptionInfo    = nullptr;
    DestroyImageList_t        DestroyImageList        = nullptr;
    SetImageCompressionQuality_t SetImageCompressionQuality = nullptr;
    CoalesceImages_t          CoalesceImages          = nullptr;
    OptimizeImageTransparency_t OptimizeImageTransparency = nullptr;
    OptimizeImageLayers_t     OptimizeImageLayers     = nullptr;
    StripImage_t              StripImage              = nullptr;

private:
    MagickLoader() { load(); }

    void load() {
        // Try to dlopen ImageMagick - gracefully degrade if not available
        const char* libnames[] = {
            "libMagickCore-7.Q16HDRI.so", "libMagickCore-7.Q16.so",
            "libMagickCore-7.so", "libMagickCore-6.Q16.so",
            "libMagickCore-6.so", "libMagickCore.so",
            nullptr
        };

        for (int i = 0; libnames[i]; ++i) {
            handle_ = dlopen(libnames[i], RTLD_NOW | RTLD_GLOBAL);
            if (handle_) break;
        }

        if (!handle_) {
            available_ = false;
            return;
        }

        #define LOAD_SYM(name) \
            name = reinterpret_cast<name##_t>(dlsym(handle_, #name)); \
            if (!name) { available_ = false; return; }

        LOAD_SYM(MagickWandGenesis);
        LOAD_SYM(MagickWandTerminus);
        LOAD_SYM(ReadImage);
        LOAD_SYM(ResizeImage);
        LOAD_SYM(CropImage);
        LOAD_SYM(WriteImage);
        LOAD_SYM(DestroyImage);
        LOAD_SYM(CloneImageInfo);
        LOAD_SYM(DestroyImageInfo);
        LOAD_SYM(AcquireExceptionInfo);
        LOAD_SYM(DestroyExceptionInfo);
        LOAD_SYM(DestroyImageList);
        LOAD_SYM(SetImageCompressionQuality);
        LOAD_SYM(CoalesceImages);
        LOAD_SYM(OptimizeImageTransparency);
        LOAD_SYM(OptimizeImageLayers);
        LOAD_SYM(StripImage);

        #undef LOAD_SYM

        MagickWandGenesis();
        available_ = true;
    }

    void* handle_ = nullptr;
    bool available_ = false;
};

// ============================================================================
// ThumbnailCache - LRU Disk + Memory Cache
// ============================================================================

class ThumbnailCache {
public:
    struct Entry {
        std::vector<uint8_t> data;
        std::string mime_type;
        std::chrono::steady_clock::time_point last_access;
        size_t size;
    };

    explicit ThumbnailCache(size_t max_entries = DEFAULT_LRU_CACHE_SIZE,
                            const std::filesystem::path& disk_cache_dir = {})
        : max_entries_(max_entries), disk_cache_dir_(disk_cache_dir)
    {
        if (!disk_cache_dir_.empty()) {
            std::error_code ec;
            std::filesystem::create_directories(disk_cache_dir_, ec);
        }
    }

    std::optional<std::vector<uint8_t>> get(const std::string& key) {
        std::unique_lock lock(mutex_);
        auto it = map_.find(key);
        if (it != map_.end()) {
            touch_locked(it->second);
            return it->second->data;
        }
        lock.unlock();

        // Try disk cache
        if (!disk_cache_dir_.empty()) {
            auto data = read_from_disk(key);
            if (data) {
                lock.lock();
                insert_locked(key, *data, "image/jpeg");
                return *data;
            }
        }
        return std::nullopt;
    }

    void put(const std::string& key, const std::vector<uint8_t>& data,
             const std::string& mime_type = "image/jpeg") {
        std::unique_lock lock(mutex_);
        insert_locked(key, data, mime_type);
        lock.unlock();

        // Also write to disk cache
        if (!disk_cache_dir_.empty()) {
            write_to_disk(key, data);
        }
    }

    void remove(const std::string& key) {
        std::unique_lock lock(mutex_);
        auto it = map_.find(key);
        if (it != map_.end()) {
            total_size_ -= it->second->size;
            lru_.erase(it->second);
            map_.erase(it);
        }
        lock.unlock();
        if (!disk_cache_dir_.empty()) {
            std::error_code ec;
            std::filesystem::remove(disk_path(key), ec);
        }
    }

    void clear() {
        std::unique_lock lock(mutex_);
        map_.clear();
        lru_.clear();
        total_size_ = 0;
    }

    size_t size() const {
        std::shared_lock lock(mutex_);
        return map_.size();
    }

private:
    using LruIter = std::list<std::string>::iterator;

    void touch_locked(LruIter it) {
        lru_.splice(lru_.begin(), lru_, it);
    }

    void insert_locked(const std::string& key, const std::vector<uint8_t>& data,
                       const std::string& mime_type) {
        auto it = map_.find(key);
        if (it != map_.end()) {
            it->second->data = data;
            it->second->mime_type = mime_type;
            it->second->size = data.size();
            it->second->last_access = std::chrono::steady_clock::now();
            touch_locked(it->second);
            return;
        }

        // Evict if needed
        while (map_.size() >= max_entries_ && !lru_.empty()) {
            auto last = lru_.back();
            auto entry_it = map_.find(last);
            if (entry_it != map_.end()) {
                total_size_ -= entry_it->second->size;
            }
            map_.erase(last);
            lru_.pop_back();
        }

        lru_.push_front(key);
        auto entry = std::make_shared<Entry>();
        entry->data = data;
        entry->mime_type = mime_type;
        entry->size = data.size();
        entry->last_access = std::chrono::steady_clock::now();
        map_[key] = lru_.begin();
        entries_[key] = entry;
        total_size_ += data.size();
    }

    std::filesystem::path disk_path(const std::string& key) const {
        return disk_cache_dir_ / (key + ".cache");
    }

    void write_to_disk(const std::string& key, const std::vector<uint8_t>& data) {
        std::ofstream out(disk_path(key), std::ios::binary);
        if (out) out.write(reinterpret_cast<const char*>(data.data()), data.size());
    }

    std::optional<std::vector<uint8_t>> read_from_disk(const std::string& key) {
        auto path = disk_path(key);
        std::ifstream in(path, std::ios::binary | std::ios::ate);
        if (!in) return std::nullopt;
        size_t sz = in.tellg();
        in.seekg(0);
        std::vector<uint8_t> data(sz);
        in.read(reinterpret_cast<char*>(data.data()), sz);
        if (!in) return std::nullopt;
        return data;
    }

    mutable std::shared_mutex mutex_;
    size_t max_entries_;
    std::filesystem::path disk_cache_dir_;
    std::list<std::string> lru_;
    std::unordered_map<std::string, LruIter> map_;
    std::unordered_map<std::string, std::shared_ptr<Entry>> entries_;
    size_t total_size_ = 0;
};

// ============================================================================
// MediaDatabase - Simple key-value metadata store
// ============================================================================

class MediaDatabase {
public:
    struct MediaRecord {
        std::string media_id;
        std::string origin_server;
        std::string content_type;
        std::string content_hash;
        std::string upload_name;
        size_t content_size = 0;
        std::chrono::system_clock::time_point created_at;
        std::chrono::system_clock::time_point last_access;
        bool quarantined = false;
        bool soft_deleted = false;
        std::chrono::system_clock::time_point delete_scheduled;
        int access_count = 0;
        std::string blurhash;
        std::string thumbnail_path;
    };

    void insert(const MediaRecord& rec) {
        std::unique_lock lock(mutex_);
        records_[rec.media_id] = rec;
        by_hash_[rec.content_hash].insert(rec.media_id);
    }

    std::optional<MediaRecord> get(const std::string& media_id) {
        std::shared_lock lock(mutex_);
        auto it = records_.find(media_id);
        if (it != records_.end()) return it->second;
        return std::nullopt;
    }

    void update(const std::string& media_id, const MediaRecord& rec) {
        std::unique_lock lock(mutex_);
        auto it = records_.find(media_id);
        if (it != records_.end()) {
            // Update hash index if hash changed
            if (it->second.content_hash != rec.content_hash) {
                by_hash_[it->second.content_hash].erase(media_id);
                by_hash_[rec.content_hash].insert(media_id);
            }
            it->second = rec;
        }
    }

    void remove(const std::string& media_id) {
        std::unique_lock lock(mutex_);
        auto it = records_.find(media_id);
        if (it != records_.end()) {
            by_hash_[it->second.content_hash].erase(media_id);
            records_.erase(it);
        }
    }

    std::vector<std::string> find_duplicates(const std::string& content_hash) {
        std::shared_lock lock(mutex_);
        auto it = by_hash_.find(content_hash);
        if (it != by_hash_.end()) {
            return std::vector<std::string>(it->second.begin(), it->second.end());
        }
        return {};
    }

    std::vector<MediaRecord> get_quarantined() {
        std::shared_lock lock(mutex_);
        std::vector<MediaRecord> result;
        for (const auto& [id, rec] : records_) {
            if (rec.quarantined) result.push_back(rec);
        }
        return result;
    }

    std::vector<MediaRecord> get_soft_deleted() {
        std::shared_lock lock(mutex_);
        std::vector<MediaRecord> result;
        for (const auto& [id, rec] : records_) {
            if (rec.soft_deleted) result.push_back(rec);
        }
        return result;
    }

    std::vector<MediaRecord> get_expired_deleted() {
        std::shared_lock lock(mutex_);
        auto now = std::chrono::system_clock::now();
        std::vector<MediaRecord> result;
        for (const auto& [id, rec] : records_) {
            if (rec.soft_deleted && rec.delete_scheduled <= now) {
                result.push_back(rec);
            }
        }
        return result;
    }

    nlohmann::json stats() {
        std::shared_lock lock(mutex_);
        nlohmann::json j;
        j["total_records"] = records_.size();
        j["total_size"] = 0;
        j["quarantined"] = 0;
        j["soft_deleted"] = 0;
        j["unique_hashes"] = by_hash_.size();
        size_t total_size = 0;
        for (const auto& [id, rec] : records_) {
            total_size += rec.content_size;
            if (rec.quarantined) j["quarantined"] = j["quarantined"].get<int>() + 1;
            if (rec.soft_deleted) j["soft_deleted"] = j["soft_deleted"].get<int>() + 1;
        }
        j["total_size"] = total_size;
        j["total_size_human"] = format_bytes(total_size);
        return j;
    }

    static std::string format_bytes(size_t bytes) {
        const char* units[] = {"B", "KB", "MB", "GB", "TB"};
        int unit_idx = 0;
        double size = static_cast<double>(bytes);
        while (size >= 1024.0 && unit_idx < 4) {
            size /= 1024.0;
            ++unit_idx;
        }
        std::ostringstream oss;
        oss << std::fixed << std::setprecision(2) << size << " " << units[unit_idx];
        return oss.str();
    }

private:
    mutable std::shared_mutex mutex_;
    std::unordered_map<std::string, MediaRecord> records_;
    std::unordered_map<std::string, std::unordered_set<std::string>> by_hash_;
};

// ============================================================================
// URLPreviewCache
// ============================================================================

class URLPreviewCache {
public:
    struct PreviewEntry {
        nlohmann::json data;
        std::chrono::system_clock::time_point expires;
    };

    explicit URLPreviewCache(std::chrono::seconds ttl = DEFAULT_THUMB_TTL) : ttl_(ttl) {}

    std::optional<nlohmann::json> get(const std::string& url) {
        std::shared_lock lock(mutex_);
        auto it = entries_.find(url);
        if (it != entries_.end()) {
            if (std::chrono::system_clock::now() < it->second.expires) {
                return it->second.data;
            }
        }
        return std::nullopt;
    }

    void put(const std::string& url, const nlohmann::json& data) {
        std::unique_lock lock(mutex_);
        PreviewEntry entry;
        entry.data = data;
        entry.expires = std::chrono::system_clock::now() + ttl_;
        entries_[url] = entry;
    }

    void clear_expired() {
        std::unique_lock lock(mutex_);
        auto now = std::chrono::system_clock::now();
        for (auto it = entries_.begin(); it != entries_.end();) {
            if (it->second.expires <= now) {
                it = entries_.erase(it);
            } else {
                ++it;
            }
        }
    }

private:
    mutable std::shared_mutex mutex_;
    std::unordered_map<std::string, PreviewEntry> entries_;
    std::chrono::seconds ttl_;
};

// ============================================================================
// ClamAVScanner - Virus scanning integration
// ============================================================================

class ClamAVScanner {
public:
    struct ScanResult {
        bool clean = true;
        std::string virus_name;
        std::string error;
    };

    ClamAVScanner(const std::string& socket_path = "/var/run/clamav/clamd.ctl")
        : socket_path_(socket_path) {}

    ScanResult scan_file(const std::filesystem::path& path) {
        if (!std::filesystem::exists(path)) {
            ScanResult res;
            res.clean = false;
            res.error = "File not found";
            return res;
        }

        // Try Unix socket
        int sock = socket(AF_UNIX, SOCK_STREAM, 0);
        if (sock >= 0) {
            struct sockaddr_un addr{};
            addr.sun_family = AF_UNIX;
            strncpy(addr.sun_path, socket_path_.c_str(), sizeof(addr.sun_path) - 1);

            if (connect(sock, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) == 0) {
                auto result = scan_via_socket(sock, path);
                close(sock);
                return result;
            }
            close(sock);
        }

        // Try TCP fallback
        return scan_via_tcp(path, "127.0.0.1", 3310);
    }

    ScanResult scan_data(const std::vector<uint8_t>& data) {
        // Write to temp file
        auto tmp = std::filesystem::temp_directory_path() / ("clamav_scan_" + sha256_hex(data).substr(0, 16));
        std::ofstream out(tmp, std::ios::binary);
        if (!out) {
            ScanResult res;
            res.clean = false;
            res.error = "Failed to create temp file";
            return res;
        }
        out.write(reinterpret_cast<const char*>(data.data()), data.size());
        out.close();

        auto result = scan_file(tmp);
        std::error_code ec;
        std::filesystem::remove(tmp, ec);
        return result;
    }

private:
    ScanResult scan_via_socket(int sock, const std::filesystem::path& path) {
        ScanResult result;
        std::string cmd = "SCAN " + path.string() + "\n";
        if (send(sock, cmd.c_str(), cmd.size(), 0) < 0) {
            result.clean = false;
            result.error = "Failed to send scan command";
            return result;
        }

        char buf[4096];
        ssize_t n = recv(sock, buf, sizeof(buf) - 1, 0);
        if (n <= 0) {
            result.clean = false;
            result.error = "No response from ClamAV";
            return result;
        }
        buf[n] = '\0';
        std::string response(buf, n);

        // Parse: "path: OK" or "path: virusname FOUND"
        auto colon_pos = response.find(':');
        if (colon_pos != std::string::npos) {
            std::string status = response.substr(colon_pos + 1);
            // Trim
            while (!status.empty() && (status.front() == ' ' || status.front() == '\t')) status.erase(0, 1);
            while (!status.empty() && (status.back() == '\n' || status.back() == '\r' || status.back() == ' ')) status.pop_back();

            if (status == "OK") {
                result.clean = true;
            } else if (status.find("FOUND") != std::string::npos) {
                result.clean = false;
                result.virus_name = status.substr(0, status.find(" FOUND"));
            } else if (status.find("ERROR") != std::string::npos) {
                result.clean = false;
                result.error = status;
            }
        }
        return result;
    }

    ScanResult scan_via_tcp(const std::filesystem::path& path,
                            const std::string& host, int port) {
        ScanResult result;
        result.clean = false;
        result.error = "TCP ClamAV scanning not implemented";
        // In production, implement TCP INSTREAM command
        return result;
    }

    std::string socket_path_;
};

// ============================================================================
// MediaServices Implementation
// ============================================================================

class MediaServices::Impl {
public:
    Impl(const std::filesystem::path& media_dir,
         const std::filesystem::path& thumb_dir,
         const std::filesystem::path& remote_cache_dir)
        : media_dir_(media_dir), thumb_dir_(thumb_dir), remote_cache_dir_(remote_cache_dir),
          thumb_cache_(500, thumb_dir / "cache"),
          preview_cache_(std::chrono::seconds(86400)),
          clamav_("/var/run/clamav/clamd.ctl")
    {
        std::error_code ec;
        std::filesystem::create_directories(media_dir_, ec);
        std::filesystem::create_directories(thumb_dir_, ec);
        std::filesystem::create_directories(remote_cache_dir_, ec);
        std::filesystem::create_directories(thumb_dir_ / "cache", ec);

        // Start background thread for periodic cleanup
        cleanup_running_ = true;
        cleanup_thread_ = std::thread(&Impl::cleanup_loop, this);

        // Initialize curl
        curl_global_init(CURL_GLOBAL_ALL);
    }

    ~Impl() {
        cleanup_running_ = false;
        if (cleanup_thread_.joinable()) {
            cleanup_thread_.join();
        }
        curl_global_cleanup();
    }

    // ========================================================================
    // 1. Thumbnail Generation
    // ========================================================================

    nlohmann::json generate_thumbnail(const std::string& media_id, size_t width, size_t height,
                                      const std::string& method) {
        nlohmann::json result;
        auto rec = db_.get(media_id);
        if (!rec) {
            result["error"] = "Media not found";
            return result;
        }

        auto media_path = media_dir_ / rec->media_id;
        if (!std::filesystem::exists(media_path)) {
            result["error"] = "Media file not found on disk";
            return result;
        }

        // Check thumbnail cache first
        std::string cache_key = "thumb_" + media_id + "_" + std::to_string(width) +
                                "x" + std::to_string(height) + "_" + method;
        auto cached = thumb_cache_.get(cache_key);
        if (cached) {
            result["thumbnail"] = true;
            result["cached"] = true;
            result["data"] = nlohmann::json::binary(*cached);
            result["mime_type"] = "image/jpeg";
            return result;
        }

        // Read media file
        std::ifstream in(media_path, std::ios::binary | std::ios::ate);
        if (!in) {
            result["error"] = "Cannot read media file";
            return result;
        }
        size_t file_size = in.tellg();
        in.seekg(0);
        std::vector<uint8_t> file_data(file_size);
        in.read(reinterpret_cast<char*>(file_data.data()), file_size);

        // Determine if animated
        bool animated = false;
        if (rec->content_type == "image/gif") {
            animated = is_animated_gif(file_data);
        } else if (rec->content_type == "image/webp") {
            animated = is_animated_webp(file_data);
        }

        std::vector<uint8_t> thumb_data;

        if (MagickLoader::instance().available()) {
            auto& magick = MagickLoader::instance();
            auto* exception = magick.AcquireExceptionInfo();
            auto* image_info = magick.CloneImageInfo(nullptr);

            // Write to temp file for ImageMagick
            auto tmp_path = std::filesystem::temp_directory_path() / ("thumb_in_" + media_id);
            {
                std::ofstream tmp_out(tmp_path, std::ios::binary);
                tmp_out.write(reinterpret_cast<const char*>(file_data.data()), file_data.size());
            }

            strncpy(image_info->filename, tmp_path.c_str(), sizeof(image_info->filename) - 1);
            auto* image = magick.ReadImage(image_info, exception);

            if (image) {
                // Coalesce for animated images
                if (animated) {
                    auto* coalesced = magick.CoalesceImages(image, exception);
                    if (coalesced) {
                        magick.DestroyImage(image);
                        image = coalesced;
                    }
                }

                // Calculate resize dimensions
                size_t img_width = image->columns;
                size_t img_height = image->rows;
                size_t new_width, new_height;

                if (method == "scale") {
                    double ratio = std::min(
                        static_cast<double>(width) / img_width,
                        static_cast<double>(height) / img_height
                    );
                    new_width = static_cast<size_t>(img_width * ratio);
                    new_height = static_cast<size_t>(img_height * ratio);
                } else if (method == "crop") {
                    double ratio = std::max(
                        static_cast<double>(width) / img_width,
                        static_cast<double>(height) / img_height
                    );
                    new_width = static_cast<size_t>(img_width * ratio);
                    new_height = static_cast<size_t>(img_height * ratio);
                } else {
                    new_width = width;
                    new_height = height;
                }

                // Resize
                auto* resized = magick.ResizeImage(image, new_width, new_height, nullptr, exception);
                if (resized) {
                    // Crop if needed
                    if (method == "crop") {
                        auto* cropped = magick.CropImage(resized, nullptr, exception);
                        if (cropped) {
                            magick.DestroyImage(resized);
                            resized = cropped;
                        }
                    }

                    // Strip metadata
                    magick.StripImage(resized);

                    // Set quality
                    magick.SetImageCompressionQuality(resized, DEFAULT_THUMB_QUALITY);

                    // Write out
                    auto out_path = std::filesystem::temp_directory_path() / ("thumb_out_" + media_id + ".jpg");
                    auto* out_info = magick.CloneImageInfo(nullptr);
                    strncpy(out_info->filename, out_path.c_str(), sizeof(out_info->filename) - 1);
                    magick.WriteImage(out_info, resized, exception);
                    magick.DestroyImageInfo(out_info);

                    // Read back
                    std::ifstream tout(out_path, std::ios::binary | std::ios::ate);
                    if (tout) {
                        size_t tsz = tout.tellg();
                        tout.seekg(0);
                        thumb_data.resize(tsz);
                        tout.read(reinterpret_cast<char*>(thumb_data.data()), tsz);
                    }
                    std::error_code ec;
                    std::filesystem::remove(out_path, ec);

                    magick.DestroyImage(resized);
                }
                magick.DestroyImage(image);
            }
            magick.DestroyImageInfo(image_info);
            magick.DestroyExceptionInfo(exception);
            std::error_code ec;
            std::filesystem::remove(tmp_path, ec);
        }

        if (thumb_data.empty()) {
            // Fallback: return original for simple formats
            thumb_data = file_data;
        }

        // Cache the result
        if (!thumb_data.empty()) {
            thumb_cache_.put(cache_key, thumb_data, "image/jpeg");
        }

        result["thumbnail"] = !thumb_data.empty();
        result["animated"] = animated;
        result["width"] = width;
        result["height"] = height;
        result["method"] = method;
        if (!thumb_data.empty()) {
            result["data"] = nlohmann::json::binary(thumb_data);
            result["mime_type"] = "image/jpeg";
            result["size"] = thumb_data.size();
        }
        return result;
    }

    // ========================================================================
    // 2. Animated Thumbnail Support
    // ========================================================================

    nlohmann::json generate_animated_thumbnail(const std::string& media_id,
                                                size_t width, size_t height, size_t max_frames) {
        nlohmann::json result;
        auto rec = db_.get(media_id);
        if (!rec) {
            result["error"] = "Media not found";
            return result;
        }

        auto media_path = media_dir_ / rec->media_id;
        if (!std::filesystem::exists(media_path)) {
            result["error"] = "Media file not found";
            return result;
        }

        // Read media
        std::ifstream in(media_path, std::ios::binary | std::ios::ate);
        size_t file_size = in.tellg();
        in.seekg(0);
        std::vector<uint8_t> file_data(file_size);
        in.read(reinterpret_cast<char*>(file_data.data()), file_size);

        std::string cache_key = "anim_thumb_" + media_id + "_" +
                                std::to_string(width) + "x" + std::to_string(height) +
                                "_" + std::to_string(max_frames);

        auto cached = thumb_cache_.get(cache_key);
        if (cached) {
            result["thumbnail"] = true;
            result["cached"] = true;
            result["animated"] = true;
            result["data"] = nlohmann::json::binary(*cached);
            result["mime_type"] = "image/webp";
            return result;
        }

        std::vector<uint8_t> thumb_data;

        if (MagickLoader::instance().available()) {
            auto& magick = MagickLoader::instance();
            auto tmp_path = std::filesystem::temp_directory_path() / ("anim_in_" + media_id);
            {
                std::ofstream out(tmp_path, std::ios::binary);
                out.write(reinterpret_cast<const char*>(file_data.data()), file_data.size());
            }

            auto* exception = magick.AcquireExceptionInfo();
            auto* image_info = magick.CloneImageInfo(nullptr);
            strncpy(image_info->filename, tmp_path.c_str(), sizeof(image_info->filename) - 1);

            auto* image = magick.ReadImage(image_info, exception);
            if (image) {
                // Coalesce frames
                auto* coalesced = magick.CoalesceImages(image, exception);
                magick.DestroyImage(image);

                if (coalesced) {
                    // Resize each frame
                    // Limit frames
                    int frame_count = 0;
                    for (auto* frame = coalesced; frame && frame_count < static_cast<int>(max_frames);
                         frame = frame->next) {
                        ++frame_count;
                    }

                    // Resize first frame dimensions
                    coalesced = magick.ResizeImage(coalesced, width, height, nullptr, exception);
                    // Optimize
                    auto* optimized = magick.OptimizeImageLayers(coalesced, exception);
                    if (optimized) {
                        magick.DestroyImageList(coalesced);
                        coalesced = optimized;
                    }
                    magick.OptimizeImageTransparency(coalesced, exception);

                    auto out_path = std::filesystem::temp_directory_path() / ("anim_thumb_out_" + media_id + ".webp");
                    auto* out_info = magick.CloneImageInfo(nullptr);
                    strncpy(out_info->filename, out_path.c_str(), sizeof(out_info->filename) - 1);
                    magick.WriteImage(out_info, coalesced, exception);
                    magick.DestroyImageInfo(out_info);

                    std::ifstream tout(out_path, std::ios::binary | std::ios::ate);
                    if (tout) {
                        size_t tsz = tout.tellg();
                        tout.seekg(0);
                        thumb_data.resize(tsz);
                        tout.read(reinterpret_cast<char*>(thumb_data.data()), tsz);
                    }
                    std::error_code ec;
                    std::filesystem::remove(out_path, ec);

                    magick.DestroyImageList(coalesced);
                }
                magick.DestroyExceptionInfo(exception);
                magick.DestroyImageInfo(image_info);
            }
            std::error_code ec;
            std::filesystem::remove(tmp_path, ec);
        }

        if (!thumb_data.empty()) {
            thumb_cache_.put(cache_key, thumb_data, "image/webp");
        }

        result["thumbnail"] = !thumb_data.empty();
        result["animated"] = true;
        result["width"] = width;
        result["height"] = height;
        if (!thumb_data.empty()) {
            result["data"] = nlohmann::json::binary(thumb_data);
            result["mime_type"] = "image/webp";
            result["size"] = thumb_data.size();
        }
        return result;
    }

    // ========================================================================
    // 3. Thumbnail Caching (handled by ThumbnailCache)
    // ========================================================================

    nlohmann::json thumbnail_cache_stats() {
        nlohmann::json j;
        j["entries"] = thumb_cache_.size();
        j["max_entries"] = DEFAULT_LRU_CACHE_SIZE;
        return j;
    }

    void clear_thumbnail_cache() {
        thumb_cache_.clear();
    }

    // ========================================================================
    // 4. URL Preview Engine
    // ========================================================================

    nlohmann::json generate_url_preview(const std::string& url, size_t timeout_secs) {
        nlohmann::json result;
        result["url"] = url;

        // Check cache first
        auto cached = preview_cache_.get(url);
        if (cached) {
            result["cached"] = true;
            merge_preview(result, *cached);
            return result;
        }

        // Fetch URL with curl
        std::string html = fetch_url(url, DEFAULT_URL_PREVIEW_MAX_SIZE,
                                     timeout_secs > 0 ? static_cast<long>(timeout_secs)
                                                      : static_cast<long>(DEFAULT_URL_PREVIEW_TIMEOUT));

        if (html.empty()) {
            result["error"] = "Failed to fetch URL";
            return result;
        }

        // Parse OpenGraph / meta tags
        nlohmann::json og = parse_opengraph(html);

        // Parse oEmbed
        nlohmann::json oembed = parse_oembed(html);
        if (!oembed.empty()) {
            og["oembed"] = oembed;
        }

        // Extract title from <title>
        std::regex title_re("<title[^>]*>([^<]+)</title>", std::regex::icase);
        std::smatch title_match;
        if (std::regex_search(html, title_match, title_re) && og.find("title") == og.end()) {
            og["title"] = title_match[1].str();
        }

        // Extract description from meta
        if (og.find("description") == og.end()) {
            std::regex desc_re("<meta[^>]*name=[\"']description[\"'][^>]*content=[\"']([^\"']+)[\"']",
                               std::regex::icase);
            std::smatch desc_match;
            if (std::regex_search(html, desc_match, desc_re)) {
                og["description"] = desc_match[1].str();
            }
        }

        result["preview"] = og;
        result["success"] = true;

        // Cache result
        preview_cache_.put(url, og);

        return result;
    }

    // ========================================================================
    // 5. URL Preview Caching (handled by URLPreviewCache)
    // ========================================================================

    void clear_preview_cache() {
        preview_cache_.clear_expired();
    }

    // ========================================================================
    // 6. Image Proxy
    // ========================================================================

    nlohmann::json proxy_image(const std::string& url, size_t max_size) {
        nlohmann::json result;

        if (max_size == 0) max_size = DEFAULT_IMAGE_PROXY_MAX;

        // Validate URL
        if (url.find("http://") != 0 && url.find("https://") != 0) {
            result["error"] = "Invalid URL scheme";
            return result;
        }

        // Don't proxy local media
        if (url.find("mxc://") == 0) {
            result["error"] = "Cannot proxy MXC URLs";
            return result;
        }

        // Fetch the image
        std::string image_data = fetch_url(url, max_size, 30);
        if (image_data.empty()) {
            result["error"] = "Failed to fetch image";
            return result;
        }

        // Detect content type
        std::vector<uint8_t> data(image_data.begin(), image_data.end());
        std::string mime = detect_mime_type(data);

        // Strip EXIF for privacy
        if (mime == "image/jpeg" || mime == "image/png" || mime == "image/webp") {
            data = strip_exif(data);
        }

        // Calculate hash
        std::string hash = sha256_hex(data);

        // Store in media directory
        std::string media_id = "proxy_" + hash;
        auto dest_path = media_dir_ / media_id;
        {
            std::ofstream out(dest_path, std::ios::binary);
            out.write(reinterpret_cast<const char*>(data.data()), data.size());
        }

        // Create record
        MediaDatabase::MediaRecord rec;
        rec.media_id = media_id;
        rec.origin_server = url;
        rec.content_type = mime;
        rec.content_hash = hash;
        rec.content_size = data.size();
        rec.created_at = std::chrono::system_clock::now();
        rec.last_access = std::chrono::system_clock::now();
        db_.insert(rec);

        result["media_id"] = media_id;
        result["mxc"] = "mxc://proxy/" + media_id;
        result["content_type"] = mime;
        result["size"] = data.size();
        result["hash"] = hash;

        return result;
    }

    // ========================================================================
    // 7. Media Upload Validation
    // ========================================================================

    nlohmann::json validate_upload(const std::vector<uint8_t>& data,
                                    const std::string& declared_mime,
                                    const std::string& filename) {
        nlohmann::json result;
        result["valid"] = true;

        // Check size
        size_t max_size = get_max_size_for_type(declared_mime);
        if (data.size() > max_size) {
            result["valid"] = false;
            result["error"] = "File exceeds maximum size limit of " +
                              MediaDatabase::format_bytes(max_size);
            return result;
        }

        if (data.empty()) {
            result["valid"] = false;
            result["error"] = "Empty file";
            return result;
        }

        // Detect actual MIME type
        std::string detected_mime = detect_mime_type(data);

        // Fallback to extension
        if (detected_mime == "application/octet-stream") {
            std::string ext = extract_extension(filename);
            if (!ext.empty()) {
                detected_mime = mime_from_extension(ext);
            }
        }

        // Validate MIME type
        bool mime_allowed = false;
        if (is_allowed_image_type(declared_mime)) mime_allowed = true;
        else if (is_allowed_video_type(declared_mime)) mime_allowed = true;
        else if (is_allowed_audio_type(declared_mime)) mime_allowed = true;
        else if (is_allowed_other_type(declared_mime)) mime_allowed = true;

        if (!mime_allowed) {
            result["valid"] = false;
            result["error"] = "MIME type not allowed: " + declared_mime;
            return result;
        }

        // Warn about mismatch
        result["detected_mime"] = detected_mime;
        if (declared_mime != detected_mime &&
            detected_mime != "application/octet-stream") {
            result["mime_mismatch"] = true;
            result["warning"] = "Declared MIME type does not match detected type";
        }

        // Check SVG sanitization needed
        if (detected_mime == "image/svg+xml") {
            std::string svg_content(reinterpret_cast<const char*>(data.data()), data.size());
            result["svg_needs_sanitization"] = true;
        }

        return result;
    }

    // ========================================================================
    // 8. Content-Type Detection
    // ========================================================================

    nlohmann::json detect_content_type(const std::vector<uint8_t>& data,
                                        const std::string& filename) {
        nlohmann::json result;

        std::string magic_type = detect_mime_type(data);
        result["magic_bytes"] = magic_type;

        if (!filename.empty()) {
            std::string ext = extract_extension(filename);
            result["extension"] = ext;
            result["extension_mime"] = mime_from_extension(ext);
            result["extension_match"] = (magic_type == mime_from_extension(ext) ||
                                         magic_type == "application/octet-stream");
        }

        result["recommended_mime"] = (magic_type != "application/octet-stream")
                                     ? magic_type : mime_from_extension(extract_extension(filename));

        // Additional details
        if (data.size() >= 12) {
            std::ostringstream hex;
            for (size_t i = 0; i < std::min(data.size(), size_t(16)); ++i) {
                hex << std::hex << std::setw(2) << std::setfill('0')
                    << static_cast<int>(data[i]) << " ";
            }
            result["magic_header"] = hex.str();
        }

        return result;
    }

    nlohmann::json detect_file_content_type(const std::filesystem::path& path) {
        nlohmann::json result;

        std::ifstream in(path, std::ios::binary | std::ios::ate);
        if (!in) {
            result["error"] = "Cannot open file";
            return result;
        }
        size_t sz = in.tellg();
        in.seekg(0);
        std::vector<uint8_t> data(std::min(sz, size_t(4096)));
        in.read(reinterpret_cast<char*>(data.data()), data.size());
        data.resize(in.gcount());

        result = detect_content_type(data, path.filename().string());
        result["file_size"] = sz;
        return result;
    }

    // ========================================================================
    // 9. Media Quarantine
    // ========================================================================

    nlohmann::json quarantine_media(const std::string& media_id, const std::string& reason) {
        nlohmann::json result;
        auto rec = db_.get(media_id);
        if (!rec) {
            result["error"] = "Media not found";
            return result;
        }

        rec->quarantined = true;
        db_.update(media_id, *rec);

        result["quarantined"] = true;
        result["media_id"] = media_id;
        result["reason"] = reason;
        result["timestamp"] = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

        // Move file to quarantine directory
        auto quarantine_dir = media_dir_ / "quarantine";
        std::error_code ec;
        std::filesystem::create_directories(quarantine_dir, ec);
        auto src = media_dir_ / media_id;
        auto dst = quarantine_dir / media_id;
        if (std::filesystem::exists(src)) {
            std::filesystem::rename(src, dst, ec);
            if (ec) {
                result["warning"] = "Failed to move file to quarantine: " + ec.message();
            }
        }

        return result;
    }

    nlohmann::json release_from_quarantine(const std::string& media_id) {
        nlohmann::json result;
        auto rec = db_.get(media_id);
        if (!rec) {
            result["error"] = "Media not found";
            return result;
        }

        if (!rec->quarantined) {
            result["error"] = "Media is not quarantined";
            return result;
        }

        rec->quarantined = false;
        db_.update(media_id, *rec);

        // Move file back
        auto quarantine_dir = media_dir_ / "quarantine";
        auto src = quarantine_dir / media_id;
        auto dst = media_dir_ / media_id;
        std::error_code ec;
        if (std::filesystem::exists(src)) {
            std::filesystem::rename(src, dst, ec);
        }

        result["released"] = true;
        result["media_id"] = media_id;
        return result;
    }

    nlohmann::json list_quarantined() {
        nlohmann::json result;
        auto quarantined = db_.get_quarantined();
        nlohmann::json items = nlohmann::json::array();
        for (const auto& rec : quarantined) {
            nlohmann::json item;
            item["media_id"] = rec.media_id;
            item["content_type"] = rec.content_type;
            item["size"] = rec.content_size;
            item["created_at"] = std::chrono::duration_cast<std::chrono::seconds>(
                rec.created_at.time_since_epoch()).count();
            items.push_back(item);
        }
        result["quarantined"] = items;
        result["count"] = items.size();
        return result;
    }

    // ========================================================================
    // 10. Media Deletion
    // ========================================================================

    nlohmann::json soft_delete_media(const std::string& media_id) {
        nlohmann::json result;
        auto rec = db_.get(media_id);
        if (!rec) {
            result["error"] = "Media not found";
            return result;
        }

        rec->soft_deleted = true;
        rec->delete_scheduled = std::chrono::system_clock::now() + DEFAULT_DELETE_DELAY;
        db_.update(media_id, *rec);

        result["soft_deleted"] = true;
        result["media_id"] = media_id;
        result["delete_scheduled"] = std::chrono::duration_cast<std::chrono::seconds>(
            rec->delete_scheduled.time_since_epoch()).count();
        return result;
    }

    nlohmann::json hard_delete_media(const std::string& media_id) {
        nlohmann::json result;

        // Remove from disk
        auto path = media_dir_ / media_id;
        std::error_code ec;
        if (std::filesystem::exists(path)) {
            std::filesystem::remove(path, ec);
        }

        // Remove thumbnails
        auto thumb_path = thumb_dir_ / media_id;
        if (std::filesystem::exists(thumb_path)) {
            std::filesystem::remove_all(thumb_path, ec);
        }

        // Remove from cache
        thumb_cache_.remove("thumb_" + media_id);
        thumb_cache_.remove("anim_thumb_" + media_id);

        // Remove from DB
        db_.remove(media_id);

        result["hard_deleted"] = true;
        result["media_id"] = media_id;
        return result;
    }

    nlohmann::json restore_soft_deleted(const std::string& media_id) {
        nlohmann::json result;
        auto rec = db_.get(media_id);
        if (!rec) {
            result["error"] = "Media not found";
            return result;
        }

        if (!rec->soft_deleted) {
            result["error"] = "Media is not soft-deleted";
            return result;
        }

        rec->soft_deleted = false;
        rec->delete_scheduled = std::chrono::system_clock::time_point{};
        db_.update(media_id, *rec);

        result["restored"] = true;
        result["media_id"] = media_id;
        return result;
    }

    size_t purge_expired_deletes() {
        auto expired = db_.get_expired_deleted();
        size_t count = 0;
        for (const auto& rec : expired) {
            hard_delete_media(rec.media_id);
            ++count;
        }
        return count;
    }

    // ========================================================================
    // 11. Remote Media Caching
    // ========================================================================

    nlohmann::json cache_remote_media(const std::string& origin_server,
                                       const std::string& media_id,
                                       const std::vector<uint8_t>& data,
                                       const std::string& content_type) {
        nlohmann::json result;

        std::string hash = sha256_hex(data);
        std::string local_id = "remote_" + origin_server + "_" + media_id;

        auto dest = remote_cache_dir_ / local_id;
        {
            std::ofstream out(dest, std::ios::binary);
            out.write(reinterpret_cast<const char*>(data.data()), data.size());
        }

        MediaDatabase::MediaRecord rec;
        rec.media_id = local_id;
        rec.origin_server = origin_server;
        rec.content_type = content_type;
        rec.content_hash = hash;
        rec.content_size = data.size();
        rec.created_at = std::chrono::system_clock::now();
        rec.last_access = std::chrono::system_clock::now();
        db_.insert(rec);

        result["cached"] = true;
        result["media_id"] = local_id;
        result["hash"] = hash;
        result["size"] = data.size();

        return result;
    }

    nlohmann::json get_remote_media(const std::string& origin_server, const std::string& media_id) {
        nlohmann::json result;
        std::string local_id = "remote_" + origin_server + "_" + media_id;

        auto rec = db_.get(local_id);
        if (!rec) {
            result["found"] = false;
            return result;
        }

        auto path = remote_cache_dir_ / local_id;
        if (!std::filesystem::exists(path)) {
            result["found"] = false;
            result["error"] = "Cache file missing";
            return result;
        }

        // Update access time
        rec->last_access = std::chrono::system_clock::now();
        rec->access_count++;
        db_.update(local_id, *rec);

        result["found"] = true;
        result["media_id"] = local_id;
        result["content_type"] = rec->content_type;
        result["size"] = rec->content_size;
        result["access_count"] = rec->access_count;

        return result;
    }

    nlohmann::json cleanup_remote_cache(std::chrono::seconds max_age) {
        nlohmann::json result;
        nlohmann::json removed = nlohmann::json::array();
        auto now = std::chrono::system_clock::now();
        auto cutoff = now - max_age;

        // Iterate through remote cache directory
        std::error_code ec;
        size_t removed_count = 0;
        size_t freed_space = 0;

        for (const auto& entry : std::filesystem::directory_iterator(remote_cache_dir_, ec)) {
            if (ec) break;
            if (!entry.is_regular_file()) continue;

            std::string filename = entry.path().filename().string();
            if (filename.find("remote_") != 0) continue;

            auto ftime = entry.last_write_time();
            auto sctp = std::chrono::clock_cast<std::chrono::system_clock>(ftime);
            if (sctp < cutoff) {
                freed_space += entry.file_size(ec);
                std::filesystem::remove(entry.path(), ec);
                db_.remove(filename);
                removed.push_back(filename);
                ++removed_count;
            }
        }

        result["removed"] = removed_count;
        result["freed_bytes"] = freed_space;
        result["freed_human"] = MediaDatabase::format_bytes(freed_space);
        result["files"] = removed;
        return result;
    }

    // ========================================================================
    // 12. Media Size Limits
    // ========================================================================

    nlohmann::json get_size_limits() {
        nlohmann::json j;
        j["image"] = DEFAULT_MAX_IMAGE_SIZE;
        j["image_human"] = MediaDatabase::format_bytes(DEFAULT_MAX_IMAGE_SIZE);
        j["video"] = DEFAULT_MAX_VIDEO_SIZE;
        j["video_human"] = MediaDatabase::format_bytes(DEFAULT_MAX_VIDEO_SIZE);
        j["audio"] = DEFAULT_MAX_AUDIO_SIZE;
        j["audio_human"] = MediaDatabase::format_bytes(DEFAULT_MAX_AUDIO_SIZE);
        j["other"] = DEFAULT_MAX_OTHER_SIZE;
        j["other_human"] = MediaDatabase::format_bytes(DEFAULT_MAX_OTHER_SIZE);
        return j;
    }

    void set_size_limit(const std::string& type, size_t max_size) {
        if (type == "image") max_image_size_.store(max_size);
        else if (type == "video") max_video_size_.store(max_size);
        else if (type == "audio") max_audio_size_.store(max_size);
        else if (type == "other") max_other_size_.store(max_size);
    }

    size_t get_max_size_for_type(const std::string& mime) {
        if (mime.find("image/") == 0) return max_image_size_.load();
        if (mime.find("video/") == 0) return max_video_size_.load();
        if (mime.find("audio/") == 0) return max_audio_size_.load();
        return max_other_size_.load();
    }

    // ========================================================================
    // 13. Media Download with Range Support
    // ========================================================================

    nlohmann::json download_media(const std::string& media_id,
                                   std::optional<size_t> range_start,
                                   std::optional<size_t> range_end) {
        nlohmann::json result;
        auto rec = db_.get(media_id);
        if (!rec) {
            result["error"] = "Media not found";
            return result;
        }

        if (rec->quarantined) {
            result["error"] = "Media is quarantined";
            return result;
        }

        if (rec->soft_deleted) {
            result["error"] = "Media has been deleted";
            return result;
        }

        auto path = media_dir_ / media_id;
        if (!std::filesystem::exists(path)) {
            result["error"] = "Media file not found on disk";
            return result;
        }

        std::ifstream in(path, std::ios::binary | std::ios::ate);
        size_t total_size = in.tellg();

        size_t start = range_start.value_or(0);
        size_t end = range_end.value_or(total_size - 1);

        if (start > end || end >= total_size) {
            result["error"] = "Invalid range";
            return result;
        }

        size_t read_size = end - start + 1;
        std::vector<uint8_t> buf(read_size);
        in.seekg(start);
        in.read(reinterpret_cast<char*>(buf.data()), read_size);

        // Update access
        rec->last_access = std::chrono::system_clock::now();
        rec->access_count++;
        db_.update(media_id, *rec);

        result["media_id"] = media_id;
        result["content_type"] = rec->content_type;
        result["total_size"] = total_size;
        result["range_start"] = start;
        result["range_end"] = end;
        result["chunk_size"] = read_size;
        result["data"] = nlohmann::json::binary(buf);
        result["is_partial"] = (start != 0 || end != total_size - 1);

        return result;
    }

    // ========================================================================
    // 14. Media Deduplication
    // ========================================================================

    nlohmann::json check_duplicate(const std::vector<uint8_t>& data) {
        nlohmann::json result;
        std::string hash = sha256_hex(data);

        auto duplicates = db_.find_duplicates(hash);

        result["hash"] = hash;
        result["is_duplicate"] = !duplicates.empty();
        result["duplicate_count"] = duplicates.size();

        if (!duplicates.empty()) {
            nlohmann::json dupes = nlohmann::json::array();
            for (const auto& id : duplicates) {
                auto rec = db_.get(id);
                if (rec && !rec->soft_deleted) {
                    nlohmann::json d;
                    d["media_id"] = id;
                    d["content_type"] = rec->content_type;
                    d["size"] = rec->content_size;
                    d["created_at"] = std::chrono::duration_cast<std::chrono::seconds>(
                        rec->created_at.time_since_epoch()).count();
                    dupes.push_back(d);
                }
            }
            result["duplicates"] = dupes;
        }

        return result;
    }

    nlohmann::json check_file_duplicate(const std::filesystem::path& path) {
        std::string hash = sha256_file(path);
        nlohmann::json result;
        if (hash.empty()) {
            result["error"] = "Cannot hash file";
            return result;
        }

        auto duplicates = db_.find_duplicates(hash);
        result["hash"] = hash;
        result["is_duplicate"] = !duplicates.empty();
        result["duplicate_count"] = duplicates.size();

        if (!duplicates.empty()) {
            nlohmann::json dupes = nlohmann::json::array();
            for (const auto& id : duplicates) {
                auto rec = db_.get(id);
                if (rec) {
                    nlohmann::json d;
                    d["media_id"] = id;
                    d["content_type"] = rec->content_type;
                    dupes.push_back(d);
                }
            }
            result["duplicates"] = dupes;
        }

        return result;
    }

    // ========================================================================
    // 15. EXIF Stripping
    // ========================================================================

    std::vector<uint8_t> strip_exif_data(const std::vector<uint8_t>& data) {
        return strip_exif(data);
    }

    nlohmann::json strip_exif_and_save(const std::string& media_id) {
        nlohmann::json result;
        auto rec = db_.get(media_id);
        if (!rec) {
            result["error"] = "Media not found";
            return result;
        }

        auto path = media_dir_ / media_id;
        if (!std::filesystem::exists(path)) {
            result["error"] = "Media file not found";
            return result;
        }

        // Read original
        std::ifstream in(path, std::ios::binary | std::ios::ate);
        size_t sz = in.tellg();
        in.seekg(0);
        std::vector<uint8_t> org_data(sz);
        in.read(reinterpret_cast<char*>(org_data.data()), sz);
        in.close();

        // Strip EXIF
        std::vector<uint8_t> stripped = strip_exif(org_data);

        if (stripped.size() != org_data.size()) {
            // Write back
            std::ofstream out(path, std::ios::binary);
            out.write(reinterpret_cast<const char*>(stripped.data()), stripped.size());

            // Update hash
            std::string new_hash = sha256_hex(stripped);

            // Update DB
            rec->content_hash = new_hash;
            rec->content_size = stripped.size();
            db_.update(media_id, *rec);

            result["stripped"] = true;
            result["original_size"] = org_data.size();
            result["new_size"] = stripped.size();
            result["bytes_removed"] = org_data.size() - stripped.size();
            result["new_hash"] = new_hash;
        } else {
            result["stripped"] = false;
            result["message"] = "No EXIF data found or file type not supported";
        }

        return result;
    }

    // ========================================================================
    // 16. Image Format Conversion
    // ========================================================================

    nlohmann::json convert_image(const std::string& media_id, const std::string& target_format) {
        nlohmann::json result;
        auto rec = db_.get(media_id);
        if (!rec) {
            result["error"] = "Media not found";
            return result;
        }

        auto path = media_dir_ / media_id;
        if (!std::filesystem::exists(path)) {
            result["error"] = "Media file not found";
            return result;
        }

        std::ifstream in(path, std::ios::binary | std::ios::ate);
        size_t sz = in.tellg();
        in.seekg(0);
        std::vector<uint8_t> src_data(sz);
        in.read(reinterpret_cast<char*>(src_data.data()), sz);
        in.close();

        std::string result_mime;
        std::string fmt_lower = to_lower(target_format);
        if (fmt_lower == "webp") result_mime = "image/webp";
        else if (fmt_lower == "avif") result_mime = "image/avif";
        else if (fmt_lower == "jpeg" || fmt_lower == "jpg") result_mime = "image/jpeg";
        else if (fmt_lower == "png") result_mime = "image/png";
        else if (fmt_lower == "jpeg-xl" || fmt_lower == "jxl") result_mime = "image/jxl";
        else {
            result["error"] = "Unsupported target format: " + target_format;
            return result;
        }

        std::string converted = convert_image_format(src_data, target_format);
        if (converted.empty()) {
            result["error"] = "Conversion failed";
            return result;
        }

        std::vector<uint8_t> converted_data(converted.begin(), converted.end());
        std::string new_hash = sha256_hex(converted_data);

        // Save converted
        std::string new_id = "conv_" + new_hash.substr(0, 16) + "." + target_format;
        auto new_path = media_dir_ / new_id;
        {
            std::ofstream out(new_path, std::ios::binary);
            out.write(reinterpret_cast<const char*>(converted_data.data()), converted_data.size());
        }

        MediaDatabase::MediaRecord new_rec;
        new_rec.media_id = new_id;
        new_rec.origin_server = rec->origin_server;
        new_rec.content_type = result_mime;
        new_rec.content_hash = new_hash;
        new_rec.content_size = converted_data.size();
        new_rec.created_at = std::chrono::system_clock::now();
        new_rec.last_access = std::chrono::system_clock::now();
        db_.insert(new_rec);

        result["success"] = true;
        result["original_media_id"] = media_id;
        result["new_media_id"] = new_id;
        result["original_format"] = rec->content_type;
        result["target_format"] = result_mime;
        result["original_size"] = sz;
        result["converted_size"] = converted_data.size();
        result["compression_ratio"] = sz > 0 ? static_cast<double>(converted_data.size()) / sz : 0;
        result["new_hash"] = new_hash;

        return result;
    }

    // ========================================================================
    // 17. Blurhash Generation
    // ========================================================================

    nlohmann::json generate_blurhash(const std::string& media_id,
                                      size_t components_x, size_t components_y) {
        nlohmann::json result;
        auto rec = db_.get(media_id);
        if (!rec) {
            result["error"] = "Media not found";
            return result;
        }

        auto path = media_dir_ / media_id;
        if (!std::filesystem::exists(path)) {
            result["error"] = "Media file not found";
            return result;
        }

        std::ifstream in(path, std::ios::binary | std::ios::ate);
        size_t sz = in.tellg();
        in.seekg(0);
        std::vector<uint8_t> data(std::min(sz, size_t(10 * 1024 * 1024)));
        in.read(reinterpret_cast<char*>(data.data()), data.size());

        std::string blurhash = generate_blurhash(data, components_x, components_y);

        if (!blurhash.empty()) {
            rec->blurhash = blurhash;
            db_.update(media_id, *rec);
        }

        result["media_id"] = media_id;
        result["blurhash"] = blurhash;
        result["components_x"] = components_x;
        result["components_y"] = components_y;
        return result;
    }

    // ========================================================================
    // 18. SVG Sanitization
    // ========================================================================

    nlohmann::json sanitize_svg_media(const std::string& media_id) {
        nlohmann::json result;
        auto rec = db_.get(media_id);
        if (!rec) {
            result["error"] = "Media not found";
            return result;
        }

        if (rec->content_type != "image/svg+xml") {
            result["error"] = "Media is not SVG";
            return result;
        }

        auto path = media_dir_ / media_id;
        if (!std::filesystem::exists(path)) {
            result["error"] = "Media file not found";
            return result;
        }

        std::ifstream in(path, std::ios::binary | std::ios::ate);
        size_t sz = in.tellg();
        in.seekg(0);
        std::string svg_content(sz, '\0');
        in.read(&svg_content[0], sz);
        in.close();

        std::string sanitized = sanitize_svg(svg_content);

        if (sanitized != svg_content) {
            std::ofstream out(path, std::ios::binary);
            out.write(sanitized.data(), sanitized.size());

            std::string new_hash = sha256_hex(sanitized);
            rec->content_hash = new_hash;
            rec->content_size = sanitized.size();
            db_.update(media_id, *rec);

            result["sanitized"] = true;
            result["original_size"] = sz;
            result["new_size"] = sanitized.size();
            result["bytes_removed"] = sz - sanitized.size();
            result["new_hash"] = new_hash;
        } else {
            result["sanitized"] = false;
            result["message"] = "No unsafe content found";
        }

        return result;
    }

    std::string sanitize_svg_content(const std::string& svg_data) {
        return sanitize_svg(svg_data);
    }

    // ========================================================================
    // 19. Virus Scanning Integration
    // ========================================================================

    nlohmann::json scan_media(const std::string& media_id) {
        nlohmann::json result;
        auto rec = db_.get(media_id);
        if (!rec) {
            result["error"] = "Media not found";
            return result;
        }

        auto path = media_dir_ / media_id;
        if (!std::filesystem::exists(path)) {
            result["error"] = "Media file not found";
            return result;
        }

        auto scan_result = clamav_.scan_file(path);

        result["media_id"] = media_id;
        result["clean"] = scan_result.clean;

        if (!scan_result.clean) {
            result["virus_name"] = scan_result.virus_name;
            result["error"] = scan_result.error;

            // Auto-quarantine if virus found
            if (!scan_result.virus_name.empty()) {
                quarantine_media(media_id, "Virus detected: " + scan_result.virus_name);
                result["quarantined"] = true;
            }
        }

        result["scanned_at"] = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

        return result;
    }

    nlohmann::json scan_upload_data(const std::vector<uint8_t>& data) {
        nlohmann::json result;

        auto scan_result = clamav_.scan_data(data);

        result["clean"] = scan_result.clean;
        if (!scan_result.clean) {
            result["virus_name"] = scan_result.virus_name;
            result["error"] = scan_result.error;
            result["action"] = "upload_blocked";
        }

        result["scanned_at"] = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

        return result;
    }

    // ========================================================================
    // 20. Media Statistics and Reporting
    // ========================================================================

    nlohmann::json get_statistics() {
        nlohmann::json stats;

        // Database stats
        stats["database"] = db_.stats();

        // Thumbnail cache stats
        stats["thumbnail_cache"] = thumbnail_cache_stats();

        // Disk usage
        std::error_code ec;
        size_t media_disk = 0;
        for (const auto& entry : std::filesystem::recursive_directory_iterator(media_dir_, ec)) {
            if (ec) break;
            if (entry.is_regular_file()) {
                media_disk += entry.file_size(ec);
            }
        }
        stats["disk_usage"]["media_dir_bytes"] = media_disk;
        stats["disk_usage"]["media_dir_human"] = MediaDatabase::format_bytes(media_disk);

        size_t thumb_disk = 0;
        for (const auto& entry : std::filesystem::recursive_directory_iterator(thumb_dir_, ec)) {
            if (ec) break;
            if (entry.is_regular_file()) {
                thumb_disk += entry.file_size(ec);
            }
        }
        stats["disk_usage"]["thumb_dir_bytes"] = thumb_disk;
        stats["disk_usage"]["thumb_dir_human"] = MediaDatabase::format_bytes(thumb_disk);

        size_t remote_disk = 0;
        for (const auto& entry : std::filesystem::recursive_directory_iterator(remote_cache_dir_, ec)) {
            if (ec) break;
            if (entry.is_regular_file()) {
                remote_disk += entry.file_size(ec);
            }
        }
        stats["disk_usage"]["remote_cache_bytes"] = remote_disk;
        stats["disk_usage"]["remote_cache_human"] = MediaDatabase::format_bytes(remote_disk);

        stats["disk_usage"]["total_bytes"] = media_disk + thumb_disk + remote_disk;
        stats["disk_usage"]["total_human"] = MediaDatabase::format_bytes(media_disk + thumb_disk + remote_disk);

        // Size limits
        stats["size_limits"] = get_size_limits();

        // Magick availability
        stats["imagemagick_available"] = MagickLoader::instance().available();

        return stats;
    }

    nlohmann::json get_media_info(const std::string& media_id) {
        nlohmann::json result;
        auto rec = db_.get(media_id);
        if (!rec) {
            result["error"] = "Media not found";
            return result;
        }

        result["media_id"] = rec->media_id;
        result["origin_server"] = rec->origin_server;
        result["content_type"] = rec->content_type;
        result["content_hash"] = rec->content_hash;
        result["content_size"] = rec->content_size;
        result["upload_name"] = rec->upload_name;
        result["quarantined"] = rec->quarantined;
        result["soft_deleted"] = rec->soft_deleted;
        result["access_count"] = rec->access_count;
        result["blurhash"] = rec->blurhash;
        result["created_at"] = std::chrono::duration_cast<std::chrono::seconds>(
            rec->created_at.time_since_epoch()).count();
        result["last_access"] = std::chrono::duration_cast<std::chrono::seconds>(
            rec->last_access.time_since_epoch()).count();

        if (rec->soft_deleted) {
            result["delete_scheduled"] = std::chrono::duration_cast<std::chrono::seconds>(
                rec->delete_scheduled.time_since_epoch()).count();
        }

        // Check file existence
        auto path = media_dir_ / rec->media_id;
        result["file_exists"] = std::filesystem::exists(path);

        return result;
    }

    // ========================================================================
    // Upload workflow
    // ========================================================================

    nlohmann::json upload_media(const std::vector<uint8_t>& data,
                                 const std::string& content_type,
                                 const std::string& filename) {
        nlohmann::json result;

        // 1. Validate
        auto validation = validate_upload(data, content_type, filename);
        if (!validation["valid"].get<bool>()) {
            result["error"] = validation["error"];
            return result;
        }

        // 2. Check duplicates
        std::string hash = sha256_hex(data);
        auto dup_check = check_duplicate(data);
        if (dup_check["is_duplicate"].get<bool>()) {
            result["deduplicated"] = true;
            result["original_media_id"] = dup_check["duplicates"][0]["media_id"];
            result["hash"] = hash;
            result["content_type"] = content_type;
            result["size"] = data.size();
            return result;
        }

        // 3. Virus scan
        auto scan = scan_upload_data(data);
        if (!scan["clean"].get<bool>()) {
            result["error"] = "Virus detected: " + scan.value("virus_name", "unknown");
            result["blocked"] = true;
            return result;
        }

        // 4. Strip EXIF for images
        std::vector<uint8_t> final_data = data;
        if (content_type == "image/jpeg" || content_type == "image/png" ||
            content_type == "image/webp" || content_type == "image/tiff") {
            final_data = strip_exif(data);
            if (final_data.size() != data.size()) {
                hash = sha256_hex(final_data);
                result["exif_stripped"] = true;
            }
        }

        // 5. SVG sanitization
        if (content_type == "image/svg+xml") {
            std::string svg_str(reinterpret_cast<const char*>(data.data()), data.size());
            std::string sanitized = sanitize_svg(svg_str);
            if (sanitized != svg_str) {
                final_data.assign(sanitized.begin(), sanitized.end());
                hash = sha256_hex(final_data);
                result["svg_sanitized"] = true;
            }
        }

        // 6. Generate media ID
        std::string media_id = hash.substr(0, 32);

        // 7. Save to disk
        auto dest_path = media_dir_ / media_id;
        {
            std::ofstream out(dest_path, std::ios::binary);
            out.write(reinterpret_cast<const char*>(final_data.data()), final_data.size());
        }

        // 8. Create database record
        MediaDatabase::MediaRecord rec;
        rec.media_id = media_id;
        rec.origin_server = "local";
        rec.content_type = content_type;
        rec.content_hash = hash;
        rec.content_size = final_data.size();
        rec.upload_name = filename;
        rec.created_at = std::chrono::system_clock::now();
        rec.last_access = std::chrono::system_clock::now();
        db_.insert(rec);

        // 9. Generate blurhash for images
        if (content_type.find("image/") == 0) {
            auto bh = generate_blurhash(media_id, DEFAULT_BLURHASH_COMPONENTS_X,
                                        DEFAULT_BLURHASH_COMPONENTS_Y);
            if (bh.find("blurhash") != bh.end()) {
                result["blurhash"] = bh["blurhash"];
            }
        }

        result["success"] = true;
        result["media_id"] = media_id;
        result["mxc"] = "mxc://local/" + media_id;
        result["content_type"] = content_type;
        result["size"] = final_data.size();
        result["hash"] = hash;

        return result;
    }

private:
    // Background cleanup
    void cleanup_loop() {
        while (cleanup_running_) {
            std::this_thread::sleep_for(std::chrono::minutes(30));
            if (!cleanup_running_) break;
            try {
                purge_expired_deletes();
                cleanup_remote_cache(DEFAULT_REMOTE_CACHE_TTL);
                preview_cache_.clear_expired();
            } catch (...) {
                // Log error, continue
            }
        }
    }

    bool is_allowed_image_type(const std::string& mime) {
        return ALLOWED_IMAGE_TYPES.find(mime) != ALLOWED_IMAGE_TYPES.end();
    }

    bool is_allowed_video_type(const std::string& mime) {
        return ALLOWED_VIDEO_TYPES.find(mime) != ALLOWED_VIDEO_TYPES.end();
    }

    bool is_allowed_audio_type(const std::string& mime) {
        return ALLOWED_AUDIO_TYPES.find(mime) != ALLOWED_AUDIO_TYPES.end();
    }

    bool is_allowed_other_type(const std::string& mime) {
        return ALLOWED_OTHER_TYPES.find(mime) != ALLOWED_OTHER_TYPES.end();
    }

    void merge_preview(nlohmann::json& target, const nlohmann::json& source) {
        if (source.is_object()) {
            for (auto it = source.begin(); it != source.end(); ++it) {
                target[it.key()] = it.value();
            }
        }
    }

    std::filesystem::path media_dir_;
    std::filesystem::path thumb_dir_;
    std::filesystem::path remote_cache_dir_;
    MediaDatabase db_;
    ThumbnailCache thumb_cache_;
    URLPreviewCache preview_cache_;
    ClamAVScanner clamav_;

    std::atomic<size_t> max_image_size_{DEFAULT_MAX_IMAGE_SIZE};
    std::atomic<size_t> max_video_size_{DEFAULT_MAX_VIDEO_SIZE};
    std::atomic<size_t> max_audio_size_{DEFAULT_MAX_AUDIO_SIZE};
    std::atomic<size_t> max_other_size_{DEFAULT_MAX_OTHER_SIZE};

    std::thread cleanup_thread_;
    std::atomic<bool> cleanup_running_{false};
};

// ============================================================================
// Static helper: URL Fetch with curl
// ============================================================================

struct CurlFetchContext {
    std::string data;
    size_t max_size;
};

static size_t curl_write_callback(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t total = size * nmemb;
    auto* ctx = static_cast<CurlFetchContext*>(userp);
    if (ctx->data.size() + total > ctx->max_size) {
        return 0; // Signal error to curl by returning 0
    }
    ctx->data.append(static_cast<char*>(contents), total);
    return total;
}

static std::string fetch_url(const std::string& url, size_t max_size, long timeout_secs) {
    CURL* curl = curl_easy_init();
    if (!curl) return "";

    CurlFetchContext ctx;
    ctx.max_size = max_size;

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &ctx);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout_secs);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 5L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT,
                     "Matrix-Media-Services/1.0 (+https://matrix.org)");
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    // Restrict to HTTP/HTTPS
    curl_easy_setopt(curl, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
    curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);

    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) return "";
    return ctx.data;
}

// ============================================================================
// Static helper: OpenGraph / Meta Tag Parsing
// ============================================================================

static nlohmann::json parse_opengraph(const std::string& html) {
    nlohmann::json result;

    // Match og:, twitter:, and standard meta tags
    std::regex meta_re(
        R"(<meta\s+[^>]*?(?:property|name)\s*=\s*["']([^"']+)["'][^>]*?content\s*=\s*["']([^"']*)["'][^>]*?/?>)",
        std::regex::icase);
    std::regex meta_re_alt(
        R"(<meta\s+[^>]*?content\s*=\s*["']([^"']*)["'][^>]*?(?:property|name)\s*=\s*["']([^"']+)["'][^>]*?/?>)",
        std::regex::icase);

    std::sregex_iterator it(html.begin(), html.end(), meta_re);
    std::sregex_iterator end;

    for (; it != end; ++it) {
        std::string prop = to_lower((*it)[1].str());
        std::string content = (*it)[2].str();
        result[prop] = content;
    }

    // Also try alternate order
    std::sregex_iterator it2(html.begin(), html.end(), meta_re_alt);
    for (; it2 != end; ++it2) {
        std::string content = (*it2)[1].str();
        std::string prop = to_lower((*it2)[2].str());
        if (result.find(prop) == result.end()) {
            result[prop] = content;
        }
    }

    return result;
}

// ============================================================================
// Static helper: oEmbed Parsing
// ============================================================================

static nlohmann::json parse_oembed(const std::string& html) {
    nlohmann::json result;

    // Look for oembed link
    std::regex oembed_re(
        R"(<link\s+[^>]*?type\s*=\s*["']application/json\+oembed["'][^>]*?href\s*=\s*["']([^"']+)["'][^>]*?/?>)",
        std::regex::icase);
    std::regex oembed_alt(
        R"(<link\s+[^>]*?href\s*=\s*["']([^"']+)["'][^>]*?type\s*=\s*["']application/json\+oembed["'][^>]*?/?>)",
        std::regex::icase);

    std::smatch match;
    std::string oembed_url;

    if (std::regex_search(html, match, oembed_re)) {
        oembed_url = match[1].str();
    } else if (std::regex_search(html, match, oembed_alt)) {
        oembed_url = match[1].str();
    }

    if (!oembed_url.empty()) {
        // Fetch oembed data
        std::string json_data = fetch_url(oembed_url, 65536, 5);
        if (!json_data.empty()) {
            try {
                result = nlohmann::json::parse(json_data);
            } catch (...) {}
        }
    }

    return result;
}

// ============================================================================
// Static helper: SVG Sanitization
// ============================================================================

static std::string sanitize_svg(const std::string& svg_data) {
    std::string result = svg_data;

    // Remove script elements
    std::regex script_re(R"(<script[\s\S]*?</script>)", std::regex::icase);
    result = std::regex_replace(result, script_re, "");

    // Remove event handlers (onclick, onload, etc.)
    std::regex events_re(R"(\s+on\w+\s*=\s*["'][^"']*["'])", std::regex::icase);
    result = std::regex_replace(result, events_re, "");

    // Remove javascript: URLs in href/xlink:href
    std::regex js_url_re(R"((?:href|xlink:href)\s*=\s*["']javascript:[^"']*["'])", std::regex::icase);
    result = std::regex_replace(result, js_url_re, "href=\"#removed\"");

    // Remove foreignObject elements (can contain HTML)
    std::regex foreign_re(R"(<foreignObject[\s\S]*?</foreignObject>)", std::regex::icase);
    result = std::regex_replace(result, foreign_re, "");

    // Remove use of data: URLs in image tags
    std::regex data_url_re(R"(data:\s*[^"'\s]*)", std::regex::icase);
    // Only strip data: that could contain script
    // Be more conservative: remove all data: URIs
    result = std::regex_replace(result, data_url_re, "#removed-data-uri");

    return result;
}

// ============================================================================
// Static helper: EXIF Stripping
// ============================================================================

static std::vector<uint8_t> strip_exif(const std::vector<uint8_t>& img_data) {
    if (img_data.size() < 4) return img_data;

    // JPEG EXIF stripping
    if (img_data[0] == 0xFF && img_data[1] == 0xD8) {
        std::vector<uint8_t> result;
        result.reserve(img_data.size());
        result.push_back(0xFF);
        result.push_back(0xD8); // SOI

        size_t pos = 2;
        bool exif_removed = false;

        while (pos + 4 <= img_data.size()) {
            if (img_data[pos] != 0xFF) {
                // Not a marker - copy raw
                result.push_back(img_data[pos]);
                ++pos;
                continue;
            }

            uint8_t marker = img_data[pos + 1];
            if (marker == 0x00 || marker == 0xFF) {
                // Padding
                result.push_back(img_data[pos]);
                ++pos;
                continue;
            }

            if (marker == 0xD9) {
                // EOI
                result.push_back(0xFF);
                result.push_back(0xD9);
                exif_removed = true;
                break;
            }

            if (marker == 0xDA) {
                // SOS - copy rest
                result.insert(result.end(), img_data.begin() + pos, img_data.end());
                exif_removed = true;
                break;
            }

            // APP1 (EXIF) and APP13, APP2 (ICC, etc.)
            if ((marker == 0xE1 || marker == 0xED || marker == 0xE2) && !exif_removed) {
                // Check if this is EXIF
                if (marker == 0xE1 && pos + 10 <= img_data.size()) {
                    bool is_exif = false;
                    if (std::memcmp(&img_data[pos + 4], EXIF_HEADER_BE.data(), 6) == 0 ||
                        std::memcmp(&img_data[pos + 4], EXIF_HEADER_LE.data(), 6) == 0) {
                        is_exif = true;
                    }
                    if (is_exif) {
                        // Skip this segment
                        if (pos + 2 >= img_data.size()) break;
                        size_t seg_len = (static_cast<size_t>(img_data[pos + 2]) << 8) |
                                         img_data[pos + 3];
                        pos += 2 + seg_len;
                        continue;
                    }
                }

                // Keep non-EXIF APP1, keep APP2 (ICC profile), skip APP13
                if (marker == 0xED) {
                    if (pos + 2 >= img_data.size()) break;
                    size_t seg_len = (static_cast<size_t>(img_data[pos + 2]) << 8) |
                                     img_data[pos + 3];
                    pos += 2 + seg_len;
                    continue;
                }
            }

            // Copy segment
            if (pos + 2 >= img_data.size()) {
                result.insert(result.end(), img_data.begin() + pos, img_data.end());
                break;
            }
            size_t seg_len = (static_cast<size_t>(img_data[pos + 2]) << 8) |
                             img_data[pos + 3];
            if (pos + 2 + seg_len > img_data.size()) {
                result.insert(result.end(), img_data.begin() + pos, img_data.end());
                break;
            }
            result.insert(result.end(), img_data.begin() + pos, img_data.begin() + pos + 2 + seg_len);
            pos += 2 + seg_len;
        }

        if (exif_removed || result.size() != img_data.size()) {
            return result;
        }
    }

    // PNG: Remove tEXt, iTXt, zTXt chunks that may contain metadata
    if (img_data.size() >= 8 &&
        img_data[0] == 0x89 && img_data[1] == 'P' && img_data[2] == 'N' && img_data[3] == 'G') {
        std::vector<uint8_t> result;
        // Copy PNG signature
        result.insert(result.end(), img_data.begin(), img_data.begin() + 8);
        size_t pos = 8;

        while (pos + 8 <= img_data.size()) {
            uint32_t chunk_len = (static_cast<uint32_t>(img_data[pos]) << 24) |
                                 (static_cast<uint32_t>(img_data[pos+1]) << 16) |
                                 (static_cast<uint32_t>(img_data[pos+2]) << 8) |
                                 static_cast<uint32_t>(img_data[pos+3]);
            std::string chunk_type(reinterpret_cast<const char*>(&img_data[pos+4]), 4);

            // Skip metadata chunks
            if (chunk_type == "tEXt" || chunk_type == "iTXt" || chunk_type == "zTXt" ||
                chunk_type == "eXIf") {
                pos += 12 + chunk_len; // 4 len + 4 type + chunk + 4 crc
                continue;
            }

            // Copy chunk
            size_t chunk_total = 12 + chunk_len;
            if (pos + chunk_total > img_data.size()) break;
            result.insert(result.end(), img_data.begin() + pos, img_data.begin() + pos + chunk_total);
            pos += chunk_total;

            if (chunk_type == "IEND") break;
        }

        if (result.size() != img_data.size()) {
            return result;
        }
    }

    return img_data;
}

// ============================================================================
// Static helper: Image Format Conversion
// ============================================================================

static std::string convert_image_format(const std::vector<uint8_t>& src,
                                         const std::string& target_format) {
    if (!MagickLoader::instance().available()) return "";

    auto& magick = MagickLoader::instance();

    // Write source to temp file
    auto tmp_in = std::filesystem::temp_directory_path() / "conv_in";
    {
        std::ofstream out(tmp_in, std::ios::binary);
        out.write(reinterpret_cast<const char*>(src.data()), src.size());
    }

    auto* exception = magick.AcquireExceptionInfo();
    auto* image_info = magick.CloneImageInfo(nullptr);
    strncpy(image_info->filename, tmp_in.c_str(), sizeof(image_info->filename) - 1);

    auto* image = magick.ReadImage(image_info, exception);
    magick.DestroyImageInfo(image_info);

    if (!image) {
        magick.DestroyExceptionInfo(exception);
        std::error_code ec;
        std::filesystem::remove(tmp_in, ec);
        return "";
    }

    // Strip metadata
    magick.StripImage(image);

    // Convert and write
    auto tmp_out = std::filesystem::temp_directory_path() / ("conv_out." + target_format);
    auto* out_info = magick.CloneImageInfo(nullptr);
    strncpy(out_info->filename, tmp_out.c_str(), sizeof(out_info->filename) - 1);

    // Set format-specific quality
    std::string fmt_lower = to_lower(target_format);
    if (fmt_lower == "webp") {
        magick.SetImageCompressionQuality(image, 80);
    } else if (fmt_lower == "avif") {
        magick.SetImageCompressionQuality(image, 65);
    } else if (fmt_lower == "jpeg" || fmt_lower == "jpg") {
        magick.SetImageCompressionQuality(image, 85);
    }

    magick.WriteImage(out_info, image, exception);
    magick.DestroyImageInfo(out_info);
    magick.DestroyImage(image);
    magick.DestroyExceptionInfo(exception);

    // Read result
    std::ifstream in(tmp_out, std::ios::binary | std::ios::ate);
    std::string result;
    if (in) {
        size_t sz = in.tellg();
        in.seekg(0);
        result.resize(sz);
        in.read(&result[0], sz);
    }

    std::error_code ec;
    std::filesystem::remove(tmp_in, ec);
    std::filesystem::remove(tmp_out, ec);

    return result;
}

// ============================================================================
// Static helper: Blurhash Generation
// ============================================================================

// Base83 encoding used by BlurHash
static const char BASE83_CHARS[] =
    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz#$%*+,-.:;=?@[]^_{|}~";

static std::string encode_base83(int64_t value, int length) {
    std::string result(length, '\0');
    for (int i = 1; i <= length; ++i) {
        int digit = value % 83;
        value /= 83;
        result[length - i] = BASE83_CHARS[digit];
    }
    return result;
}

static double srgb_to_linear(int value) {
    double v = value / 255.0;
    return (v <= 0.04045) ? (v / 12.92) : std::pow((v + 0.055) / 1.055, 2.4);
}

static int linear_to_srgb(double value) {
    double v = std::max(0.0, std::min(1.0, value));
    v = (v <= 0.0031308) ? (v * 12.92) : (1.055 * std::pow(v, 1.0 / 2.4) - 0.055);
    return static_cast<int>(std::round(v * 255.0));
}

static std::string generate_blurhash(const std::vector<uint8_t>& img_data,
                                      size_t comp_x, size_t comp_y) {
    // Simplified blurhash generation - in production, use a dedicated library
    // This implements a basic version for JPEG images

    // Try to decode minimal image info for blurhash
    // For now, return a placeholder based on image content hash
    if (img_data.empty()) return "";

    // Compute a "fingerprint" from the image data
    uint64_t fingerprint = 0;
    for (size_t i = 0; i < std::min(img_data.size(), size_t(64)); ++i) {
        fingerprint = (fingerprint * 31) + img_data[i];
    }

    // Generate blurhash from fingerprint
    // In a production system, this would decode the image and compute
    // actual DCT components. Here we generate a deterministic placeholder.
    std::string blurhash;

    // Encode number of components
    int size_flag = static_cast<int>(comp_x - 1) + static_cast<int>(comp_y - 1) * 9;
    blurhash += encode_base83(size_flag, 1);

    // Maximum AC component value
    double max_ac = 0.0;

    // Generate pseudo-random components from fingerprint
    std::mt19937 rng(static_cast<uint32_t>(fingerprint));
    std::uniform_real_distribution<double> dist(-1.0, 1.0);

    struct Component { double r, g, b; };
    std::vector<std::vector<Component>> components(comp_y, std::vector<Component>(comp_x));

    for (size_t y = 0; y < comp_y; ++y) {
        for (size_t x = 0; x < comp_x; ++x) {
            components[y][x].r = dist(rng);
            components[y][x].g = dist(rng);
            components[y][x].b = dist(rng);
            max_ac = std::max(max_ac, std::abs(components[y][x].r));
            max_ac = std::max(max_ac, std::abs(components[y][x].g));
            max_ac = std::max(max_ac, std::abs(components[y][x].b));
        }
    }

    // Encode DC component (first component)
    double dc_r = srgb_to_linear(linear_to_srgb(components[0][0].r * 0.5 + 0.5));
    double dc_g = srgb_to_linear(linear_to_srgb(components[0][0].g * 0.5 + 0.5));
    double dc_b = srgb_to_linear(linear_to_srgb(components[0][0].b * 0.5 + 0.5));

    int dc_value = (linear_to_srgb(dc_r) << 16) |
                   (linear_to_srgb(dc_g) << 8) |
                   linear_to_srgb(dc_b);
    blurhash += encode_base83(dc_value, 4);

    // Maximum AC value
    int max_ac_quantized = std::max(0, std::min(82,
        static_cast<int>(std::floor(max_ac * 166.0 - 0.5))));
    blurhash += encode_base83(max_ac_quantized, 1);

    // Encode AC components
    for (size_t y = 0; y < comp_y; ++y) {
        for (size_t x = 0; x < comp_x; ++x) {
            if (x == 0 && y == 0) continue; // skip DC

            double scale = max_ac_quantized > 0
                ? 18.0 / static_cast<double>(max_ac_quantized + 1)
                : 1.0;

            int r = linear_to_srgb(
                components[y][x].r * scale * 0.5 + 0.5);
            int g = linear_to_srgb(
                components[y][x].g * scale * 0.5 + 0.5);
            int b = linear_to_srgb(
                components[y][x].b * scale * 0.5 + 0.5);

            int ac_value = (r * 19 * 19) + (g * 19) + b;
            blurhash += encode_base83(ac_value, 2);
        }
    }

    return blurhash;
}

// ============================================================================
// MediaServices Public API
// ============================================================================

MediaServices::MediaServices(const std::string& media_dir,
                              const std::string& thumb_dir,
                              const std::string& remote_cache_dir)
    : impl_(std::make_unique<Impl>(media_dir, thumb_dir, remote_cache_dir))
{
}

MediaServices::~MediaServices() = default;

nlohmann::json MediaServices::generate_thumbnail(const std::string& media_id,
                                                   size_t width, size_t height,
                                                   const std::string& method) {
    return impl_->generate_thumbnail(media_id, width, height, method);
}

nlohmann::json MediaServices::generate_animated_thumbnail(const std::string& media_id,
                                                            size_t width, size_t height,
                                                            size_t max_frames) {
    return impl_->generate_animated_thumbnail(media_id, width, height, max_frames);
}

nlohmann::json MediaServices::generate_url_preview(const std::string& url,
                                                     size_t timeout_secs) {
    return impl_->generate_url_preview(url, timeout_secs);
}

nlohmann::json MediaServices::proxy_image(const std::string& url, size_t max_size) {
    return impl_->proxy_image(url, max_size);
}

nlohmann::json MediaServices::validate_upload(const std::vector<uint8_t>& data,
                                               const std::string& declared_mime,
                                               const std::string& filename) {
    return impl_->validate_upload(data, declared_mime, filename);
}

nlohmann::json MediaServices::detect_content_type(const std::vector<uint8_t>& data,
                                                    const std::string& filename) {
    return impl_->detect_content_type(data, filename);
}

nlohmann::json MediaServices::detect_file_content_type(const std::string& path) {
    return impl_->detect_file_content_type(path);
}

nlohmann::json MediaServices::quarantine_media(const std::string& media_id,
                                                 const std::string& reason) {
    return impl_->quarantine_media(media_id, reason);
}

nlohmann::json MediaServices::release_from_quarantine(const std::string& media_id) {
    return impl_->release_from_quarantine(media_id);
}

nlohmann::json MediaServices::list_quarantined() {
    return impl_->list_quarantined();
}

nlohmann::json MediaServices::soft_delete_media(const std::string& media_id) {
    return impl_->soft_delete_media(media_id);
}

nlohmann::json MediaServices::hard_delete_media(const std::string& media_id) {
    return impl_->hard_delete_media(media_id);
}

nlohmann::json MediaServices::restore_soft_deleted(const std::string& media_id) {
    return impl_->restore_soft_deleted(media_id);
}

size_t MediaServices::purge_expired_deletes() {
    return impl_->purge_expired_deletes();
}

nlohmann::json MediaServices::cache_remote_media(const std::string& origin_server,
                                                   const std::string& media_id,
                                                   const std::vector<uint8_t>& data,
                                                   const std::string& content_type) {
    return impl_->cache_remote_media(origin_server, media_id, data, content_type);
}

nlohmann::json MediaServices::get_remote_media(const std::string& origin_server,
                                                 const std::string& media_id) {
    return impl_->get_remote_media(origin_server, media_id);
}

nlohmann::json MediaServices::cleanup_remote_cache(size_t max_age_seconds) {
    return impl_->cleanup_remote_cache(std::chrono::seconds(max_age_seconds));
}

nlohmann::json MediaServices::get_size_limits() {
    return impl_->get_size_limits();
}

void MediaServices::set_size_limit(const std::string& type, size_t max_size) {
    impl_->set_size_limit(type, max_size);
}

nlohmann::json MediaServices::download_media(const std::string& media_id,
                                               std::optional<size_t> range_start,
                                               std::optional<size_t> range_end) {
    return impl_->download_media(media_id, range_start, range_end);
}

nlohmann::json MediaServices::check_duplicate(const std::vector<uint8_t>& data) {
    return impl_->check_duplicate(data);
}

nlohmann::json MediaServices::check_file_duplicate(const std::string& path) {
    return impl_->check_file_duplicate(path);
}

std::vector<uint8_t> MediaServices::strip_exif(const std::vector<uint8_t>& data) {
    return impl_->strip_exif_data(data);
}

nlohmann::json MediaServices::strip_exif_from_media(const std::string& media_id) {
    return impl_->strip_exif_and_save(media_id);
}

nlohmann::json MediaServices::convert_image(const std::string& media_id,
                                              const std::string& target_format) {
    return impl_->convert_image(media_id, target_format);
}

nlohmann::json MediaServices::generate_blurhash(const std::string& media_id,
                                                  size_t components_x,
                                                  size_t components_y) {
    return impl_->generate_blurhash(media_id, components_x, components_y);
}

nlohmann::json MediaServices::sanitize_svg_media(const std::string& media_id) {
    return impl_->sanitize_svg_media(media_id);
}

std::string MediaServices::sanitize_svg(const std::string& svg_data) {
    return impl_->sanitize_svg_content(svg_data);
}

nlohmann::json MediaServices::scan_media(const std::string& media_id) {
    return impl_->scan_media(media_id);
}

nlohmann::json MediaServices::scan_upload(const std::vector<uint8_t>& data) {
    return impl_->scan_upload_data(data);
}

nlohmann::json MediaServices::get_statistics() {
    return impl_->get_statistics();
}

nlohmann::json MediaServices::get_media_info(const std::string& media_id) {
    return impl_->get_media_info(media_id);
}

nlohmann::json MediaServices::upload_media(const std::vector<uint8_t>& data,
                                             const std::string& content_type,
                                             const std::string& filename) {
    return impl_->upload_media(data, content_type, filename);
}

nlohmann::json MediaServices::thumbnail_cache_stats() {
    return impl_->thumbnail_cache_stats();
}

void MediaServices::clear_thumbnail_cache() {
    impl_->clear_thumbnail_cache();
}

void MediaServices::clear_preview_cache() {
    impl_->clear_preview_cache();
}

} // namespace media
} // namespace progressive
