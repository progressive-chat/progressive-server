// SPDX-License-Identifier: AGPL-3.0-only
// Progressive Matrix Server — Complete Content Scanner
// ClamAV integration, file validation, sanitization, quarantine, and admin API
// Copyright (c) 2026 Progressive Contributors

#include "content_scanner_complete.hpp"
#include "../json.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cmath>
#include <cstring>
#include <ctime>
#include <deque>
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
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <arpa/inet.h>

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/md5.h>

namespace progressive {
namespace media {

// ============================================================================
// Forward declarations
// ============================================================================

static std::string sha256_hex(std::string_view data);
static std::string sha256_file(const std::filesystem::path& path);
static std::string md5_hex(const std::vector<uint8_t>& data);
static std::string to_lower(std::string s);
static std::string extract_extension(const std::string& filename);

// ============================================================================
// Constants
// ============================================================================

// Default limits
constexpr size_t DEFAULT_MAX_ATTACHMENT_SIZE      = 50 * 1024 * 1024;   // 50 MB
constexpr size_t DEFAULT_MAX_IMAGE_SIZE           = 50 * 1024 * 1024;   // 50 MB
constexpr size_t DEFAULT_MAX_VIDEO_SIZE           = 100 * 1024 * 1024;  // 100 MB
constexpr size_t DEFAULT_MAX_AUDIO_SIZE           = 50 * 1024 * 1024;   // 50 MB
constexpr size_t DEFAULT_MAX_ARCHIVE_SIZE         = 25 * 1024 * 1024;   // 25 MB
constexpr size_t DEFAULT_MAX_OTHER_SIZE           = 10 * 1024 * 1024;   // 10 MB
constexpr size_t DEFAULT_MAX_IMAGE_WIDTH          = 8192;
constexpr size_t DEFAULT_MAX_IMAGE_HEIGHT         = 8192;
constexpr size_t DEFAULT_MAX_IMAGE_PIXELS         = 80000000;  // 80 MP
constexpr size_t DEFAULT_MAX_THUMB_WIDTH          = 800;
constexpr size_t DEFAULT_MAX_THUMB_HEIGHT         = 600;
constexpr size_t DEFAULT_CLAMD_TIMEOUT_SECONDS    = 30;
constexpr size_t DEFAULT_CLAMD_CHUNK_SIZE         = 8192;
constexpr size_t DEFAULT_CLAMD_MAX_FILE_SIZE      = 100 * 1024 * 1024;  // 100 MB
constexpr size_t DEFAULT_ARCHIVE_MAX_DEPTH        = 5;
constexpr size_t DEFAULT_ARCHIVE_MAX_ENTRIES      = 10000;
constexpr size_t DEFAULT_ARCHIVE_MAX_UNCOMPRESSED = 500 * 1024 * 1024;  // 500 MB
constexpr size_t DEFAULT_ARCHIVE_COMPRESSION_RATIO = 100;  // 100:1 max ratio
constexpr size_t DEFAULT_SCAN_CACHE_SIZE          = 10000;
constexpr size_t DEFAULT_SCAN_CACHE_TTL_SECONDS   = 3600;   // 1 hour
constexpr size_t DEFAULT_QUARANTINE_MAX_AGE       = 86400 * 30;  // 30 days
constexpr size_t DEFAULT_SCAN_QUEUE_SIZE          = 1000;
constexpr size_t DEFAULT_SCAN_WORKER_THREADS      = 2;
constexpr size_t DEFAULT_MAX_SVG_SIZE             = 1024 * 1024;   // 1 MB
constexpr size_t DEFAULT_MAX_PDF_SIZE             = 50 * 1024 * 1024;
constexpr size_t DEFAULT_MAX_HTML_SIZE            = 5 * 1024 * 1024;

// ============================================================================
// Magic number signatures for file type detection
// ============================================================================

struct MagicSignature {
    std::vector<uint8_t> bytes;
    size_t offset;
    std::string mime_type;
    std::string extension;
    std::string description;
};

static const std::vector<MagicSignature> MAGIC_SIGNATURES = {
    // Images
    {{0xFF, 0xD8, 0xFF}, 0, "image/jpeg", "jpg", "JPEG image"},
    {{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}, 0, "image/png", "png", "PNG image"},
    {{0x47, 0x49, 0x46, 0x38}, 0, "image/gif", "gif", "GIF image"},
    {{0x52, 0x49, 0x46, 0x46}, 0, "image/webp", "webp", "WebP image (RIFF)"},
    {{0x42, 0x4D}, 0, "image/bmp", "bmp", "BMP image"},
    {{0x49, 0x49, 0x2A, 0x00}, 0, "image/tiff", "tiff", "TIFF image (LE)"},
    {{0x4D, 0x4D, 0x00, 0x2A}, 0, "image/tiff", "tiff", "TIFF image (BE)"},
    {{0x00, 0x00, 0x01, 0x00}, 0, "image/x-icon", "ico", "ICO icon"},
    {{0x00, 0x00, 0x01, 0x00}, 0, "image/vnd.microsoft.icon", "ico", "ICO icon v2"},

    // Video
    {{0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70}, 0, "video/mp4", "mp4", "MP4 video"},
    {{0x00, 0x00, 0x00, 0x20, 0x66, 0x74, 0x79, 0x70}, 0, "video/mp4", "mp4", "MP4 video (wide)"},
    {{0x1A, 0x45, 0xDF, 0xA3}, 0, "video/webm", "webm", "WebM video (Matroska)"},
    {{0x4F, 0x67, 0x67, 0x53}, 0, "video/ogg", "ogv", "OGV video"},
    {{0x52, 0x49, 0x46, 0x46}, 0, "video/avi", "avi", "AVI video (RIFF)"},
    {{0x00, 0x00, 0x00, 0x14, 0x66, 0x74, 0x79, 0x70, 0x71, 0x74}, 0, "video/quicktime", "mov", "QuickTime MOV"},

    // Audio
    {{0xFF, 0xFB}, 0, "audio/mpeg", "mp3", "MP3 audio (MPEGv1)"},
    {{0xFF, 0xF3}, 0, "audio/mpeg", "mp3", "MP3 audio (MPEGv2)"},
    {{0xFF, 0xF2}, 0, "audio/mpeg", "mp3", "MP3 audio (MPEGv2.5)"},
    {{0x49, 0x44, 0x33}, 0, "audio/mpeg", "mp3", "MP3 audio (ID3)"},
    {{0x4F, 0x67, 0x67, 0x53}, 0, "audio/ogg", "ogg", "OGG audio"},
    {{0x66, 0x4C, 0x61, 0x43}, 0, "audio/flac", "flac", "FLAC audio"},
    {{0x52, 0x49, 0x46, 0x46}, 0, "audio/wav", "wav", "WAV audio (RIFF)"},
    {{0xFF, 0xF1}, 0, "audio/aac", "aac", "AAC audio"},

    // Archives
    {{0x50, 0x4B, 0x03, 0x04}, 0, "application/zip", "zip", "ZIP archive"},
    {{0x50, 0x4B, 0x05, 0x06}, 0, "application/zip", "zip", "ZIP archive (empty)"},
    {{0x50, 0x4B, 0x07, 0x08}, 0, "application/zip", "zip", "ZIP archive (spanned)"},
    {{0x1F, 0x8B, 0x08}, 0, "application/gzip", "gz", "GZip archive"},
    {{0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00}, 0, "application/x-xz", "xz", "XZ archive"},
    {{0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00}, 0, "application/vnd.rar", "rar", "RAR archive (v1.5)"},
    {{0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00}, 0, "application/vnd.rar", "rar", "RAR archive (v5)"},
    {{0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C}, 0, "application/x-7z-compressed", "7z", "7-Zip archive"},
    {{0x42, 0x5A, 0x68}, 0, "application/x-bzip2", "bz2", "BZip2 archive"},
    {{0x75, 0x73, 0x74, 0x61, 0x72}, 257, "application/x-tar", "tar", "TAR archive (POSIX)"},

    // Documents
    {{0x25, 0x50, 0x44, 0x46, 0x2D}, 0, "application/pdf", "pdf", "PDF document"},
    {{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}, 0, "application/msword", "doc", "MS Word document"},
    {{0x50, 0x4B, 0x03, 0x04}, 0, "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "docx", "MS Word (OOXML)"},

    // Other
    {{0x3C, 0x3F, 0x78, 0x6D, 0x6C}, 0, "application/xml", "xml", "XML document"},
    {{0x3C, 0x73, 0x76, 0x67}, 0, "image/svg+xml", "svg", "SVG image"},
    {{0x3C, 0x21, 0x44, 0x4F, 0x43, 0x54, 0x59, 0x50, 0x45, 0x20, 0x68, 0x74, 0x6D, 0x6C}, 0, "text/html", "html", "HTML document"},
    {{0x3C, 0x68, 0x74, 0x6D, 0x6C}, 0, "text/html", "html", "HTML document"},
    {{0x7B, 0x5C, 0x72, 0x74, 0x66}, 0, "application/rtf", "rtf", "RTF document"},
    {{0x00, 0x01, 0x00, 0x00, 0x00}, 0, "application/x-font-ttf", "ttf", "TrueType font"},
    {{0x4F, 0x54, 0x54, 0x4F}, 0, "application/x-font-otf", "otf", "OpenType font"},
    {{0x77, 0x4F, 0x46, 0x46}, 0, "application/font-woff", "woff", "WOFF font"},
    {{0x77, 0x4F, 0x46, 0x32}, 0, "application/font-woff2", "woff2", "WOFF2 font"},
    {{0x1A, 0x45, 0xDF, 0xA3}, 0, "application/x-matroska", "mkv", "Matroska container"},
};

// ============================================================================
// Dangerous file extensions that should be blocked
// ============================================================================

static const std::unordered_set<std::string> BLOCKED_EXTENSIONS = {
    // Executables
    "exe", "com", "bat", "cmd", "msi", "scr", "pif", "cpl",
    "msc", "msp", "gadget", "reg", "vbs", "vbe", "js", "jse",
    "wsf", "wsh", "ps1", "ps1xml", "ps2", "ps2xml", "psc1", "psc2",
    "scf", "lnk", "inf", "url", "hta", "dll", "sys", "drv",
    "ocx", "app", "vb", "vba", "ws", "wsc",

    // Java
    "jar", "class", "war", "ear", "jnlp",

    // Mac
    "dmg", "pkg", "app", "framework", "kext", "prefPane", "saver",
    "plugin", "xpc",

    // Linux
    "so", "elf", "run", "AppImage", "flatpak", "snap",
    "rpm", "deb", "bin",

    // Scripts
    "php", "php3", "php4", "php5", "php7", "php8", "phtml", "pht",
    "asp", "aspx", "ascx", "ashx", "asmx", "axd", "cgi", "pl",
    "py", "pyc", "pyo", "pyd", "rb", "tcl", "lua",
    "swf", "fla", "action", "air",

    // Other dangerous
    "hlp", "chm", "crt", "pem", "der", "pfx", "p12", "p7b", "p7c",
    "torrent", "magnet",

    // Encrypted / password-protected containers we want to block
    "kdbx", "enc", "gpg", "pgp",

    // Windows installer
    "appx", "appxbundle", "msix", "msixbundle",

    // Dangerous document forms
    "mht", "mhtml",
};

// ============================================================================
// Allowed MIME type categories
// ============================================================================

static const std::unordered_set<std::string> ALLOWED_IMAGE_TYPES = {
    "image/jpeg", "image/png", "image/gif", "image/webp",
    "image/avif", "image/bmp", "image/tiff", "image/svg+xml",
    "image/heic", "image/heif",
};

static const std::unordered_set<std::string> ALLOWED_VIDEO_TYPES = {
    "video/mp4", "video/webm", "video/ogg", "video/quicktime",
    "video/x-msvideo", "video/x-matroska",
};

static const std::unordered_set<std::string> ALLOWED_AUDIO_TYPES = {
    "audio/mpeg", "audio/ogg", "audio/wav", "audio/wave",
    "audio/x-wav", "audio/flac", "audio/aac", "audio/x-m4a",
    "audio/mp4", "audio/opus",
};

static const std::unordered_set<std::string> ALLOWED_DOCUMENT_TYPES = {
    "application/pdf", "text/plain", "application/json",
    "text/csv", "text/xml", "application/xml",
    "application/rtf",
};

static const std::unordered_set<std::string> ALLOWED_ARCHIVE_TYPES = {
    "application/zip", "application/gzip", "application/x-tar",
    "application/x-compressed-tar", "application/x-xz",
};

// ============================================================================
// MIME-to-extension mapping for validation
// ============================================================================

static std::string mime_to_extension(const std::string& mime) {
    static const std::unordered_map<std::string, std::string> map = {
        {"image/jpeg", "jpg"}, {"image/png", "png"}, {"image/gif", "gif"},
        {"image/webp", "webp"}, {"image/avif", "avif"}, {"image/bmp", "bmp"},
        {"image/tiff", "tiff"}, {"image/svg+xml", "svg"},
        {"video/mp4", "mp4"}, {"video/webm", "webm"}, {"video/ogg", "ogv"},
        {"video/quicktime", "mov"}, {"video/x-matroska", "mkv"},
        {"audio/mpeg", "mp3"}, {"audio/ogg", "ogg"}, {"audio/wav", "wav"},
        {"audio/flac", "flac"}, {"audio/aac", "aac"},
        {"application/pdf", "pdf"}, {"text/plain", "txt"},
        {"application/json", "json"},
        {"application/zip", "zip"}, {"application/gzip", "gz"},
        {"application/x-tar", "tar"},
    };
    auto it = map.find(mime);
    return it != map.end() ? it->second : "";
}

// ============================================================================
// Utility functions
// ============================================================================

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

static std::string md5_hex(const std::vector<uint8_t>& data) {
    unsigned char hash[MD5_DIGEST_LENGTH];
    MD5_CTX ctx;
    MD5_Init(&ctx);
    MD5_Update(&ctx, data.data(), data.size());
    MD5_Final(hash, &ctx);
    std::ostringstream oss;
    for (int i = 0; i < MD5_DIGEST_LENGTH; ++i) {
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

static std::string extract_filename(const std::string& path) {
    auto pos = path.rfind('/');
    if (pos != std::string::npos) return path.substr(pos + 1);
    pos = path.rfind('\\');
    if (pos != std::string::npos) return path.substr(pos + 1);
    return path;
}

// ============================================================================
// ScanResult
// ============================================================================

struct ScanResult {
    enum class Status {
        CLEAN,
        INFECTED,
        ERROR,
        ENCRYPTED,
        ARCHIVE_BOMB,
        SANITIZED,
        BLOCKED,
        SIZE_EXCEEDED,
        INVALID_TYPE,
        DANGEROUS_EXTENSION,
        CORRUPTED,
    };

    Status status = Status::CLEAN;
    std::string message;
    std::string virus_name;
    std::string file_hash;        // SHA-256
    std::string detected_mime;    // MIME from magic bytes
    std::string claimed_mime;     // MIME from upload metadata
    std::string file_extension;
    size_t file_size = 0;
    bool was_sanitized = false;
    std::string original_file_path;
    std::string quarantined_path;
    std::chrono::system_clock::time_point scan_time;
    double scan_duration_ms = 0.0;

    nlohmann::json to_json() const {
        nlohmann::json j;
        j["status"] = status_to_string();
        j["message"] = message;
        j["virus_name"] = virus_name;
        j["file_hash"] = file_hash;
        j["detected_mime"] = detected_mime;
        j["claimed_mime"] = claimed_mime;
        j["file_extension"] = file_extension;
        j["file_size"] = file_size;
        j["was_sanitized"] = was_sanitized;
        j["scan_time"] = std::chrono::duration_cast<std::chrono::seconds>(
            scan_time.time_since_epoch()).count();
        j["scan_duration_ms"] = scan_duration_ms;
        return j;
    }

    std::string status_to_string() const {
        switch (status) {
            case Status::CLEAN:              return "clean";
            case Status::INFECTED:           return "infected";
            case Status::ERROR:              return "error";
            case Status::ENCRYPTED:          return "encrypted";
            case Status::ARCHIVE_BOMB:       return "archive_bomb";
            case Status::SANITIZED:          return "sanitized";
            case Status::BLOCKED:            return "blocked";
            case Status::SIZE_EXCEEDED:      return "size_exceeded";
            case Status::INVALID_TYPE:       return "invalid_type";
            case Status::DANGEROUS_EXTENSION: return "dangerous_extension";
            case Status::CORRUPTED:          return "corrupted";
        }
        return "unknown";
    }
};

// ============================================================================
// ClamAV Socket Connection
// ============================================================================

class ClamdConnection {
public:
    ClamdConnection(std::string socket_path, size_t timeout_secs)
        : socket_path_(std::move(socket_path))
        , timeout_secs_(timeout_secs)
        , fd_(-1)
    {}

    ~ClamdConnection() {
        disconnect();
    }

    bool connect() {
        fd_ = ::socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd_ < 0) return false;

        struct sockaddr_un addr{};
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, socket_path_.c_str(), sizeof(addr.sun_path) - 1);

        // Set non-blocking for connect with timeout
        int flags = fcntl(fd_, F_GETFL, 0);
        fcntl(fd_, F_SETFL, flags | O_NONBLOCK);

        int ret = ::connect(fd_, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));
        if (ret < 0 && errno == EINPROGRESS) {
            // Wait for connection with poll
            struct pollfd pfd;
            pfd.fd = fd_;
            pfd.events = POLLOUT;
            int poll_ret = poll(&pfd, 1, static_cast<int>(timeout_secs_ * 1000));
            if (poll_ret <= 0) {
                disconnect();
                return false;
            }
            // Check socket error
            int so_error = 0;
            socklen_t len = sizeof(so_error);
            getsockopt(fd_, SOL_SOCKET, SO_ERROR, &so_error, &len);
            if (so_error != 0) {
                disconnect();
                return false;
            }
        } else if (ret < 0) {
            disconnect();
            return false;
        }

        // Set blocking mode back
        fcntl(fd_, F_SETFL, flags);

        // Set read timeout
        struct timeval tv;
        tv.tv_sec = static_cast<time_t>(timeout_secs_);
        tv.tv_usec = 0;
        setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(fd_, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        return true;
    }

    void disconnect() {
        if (fd_ >= 0) {
            ::close(fd_);
            fd_ = -1;
        }
    }

    bool is_connected() const { return fd_ >= 0; }

    // Send a command and read the response
    // Returns the full response string
    std::string send_command(const std::string& cmd) {
        if (!is_connected()) return "";

        // Send command
        std::string data = "n" + cmd + "\n";
        ssize_t sent = ::send(fd_, data.c_str(), data.size(), 0);
        if (sent < 0) return "";

        // Read response
        std::string response;
        char buf[DEFAULT_CLAMD_CHUNK_SIZE];
        while (true) {
            ssize_t n = ::recv(fd_, buf, sizeof(buf) - 1, 0);
            if (n <= 0) break;
            buf[n] = '\0';
            response += buf;

            // Check if we have a complete response
            // Look for newlines indicating end of stream
            if (response.size() >= 2 &&
                response[response.size() - 1] == '\n') {
                // Could still be streaming (INSTREAM)
                break;
            }
        }
        return response;
    }

    // Scan data via INSTREAM command
    std::string scan_stream(const std::vector<uint8_t>& data) {
        if (!is_connected()) return "ERROR: Not connected";

        // Send INSTREAM command
        std::string cmd = "zINSTREAM\0";
        // nINSTREAM\n in line-delimited mode
        std::string header = "nINSTREAM\n";
        ssize_t sent = ::send(fd_, header.c_str(), header.size(), 0);
        if (sent < 0) return "ERROR: Send failed";

        // Send data chunks
        size_t offset = 0;
        while (offset < data.size()) {
            size_t chunk_size = std::min(data.size() - offset, DEFAULT_CLAMD_CHUNK_SIZE);
            uint32_t net_chunk_size = htonl(static_cast<uint32_t>(chunk_size));

            // Send chunk size
            ssize_t sz_sent = ::send(fd_, &net_chunk_size, 4, 0);
            if (sz_sent != 4) return "ERROR: Send chunk size failed";

            // Send chunk data
            ssize_t d_sent = ::send(fd_, &data[offset], chunk_size, 0);
            if (d_sent < 0) return "ERROR: Send chunk data failed";

            offset += chunk_size;
        }

        // Send zero-length chunk to signal end
        uint32_t zero = 0;
        ::send(fd_, &zero, 4, 0);

        // Read response
        std::string response;
        char buf[DEFAULT_CLAMD_CHUNK_SIZE];
        while (true) {
            ssize_t n = ::recv(fd_, buf, sizeof(buf) - 1, 0);
            if (n <= 0) break;
            buf[n] = '\0';
            response += buf;
            if (n == 0 || (response.size() > 0 && response.back() == '\n' &&
                response.find("stream:") != std::string::npos)) {
                break;
            }
        }
        return response;
    }

    // Scan a file via SCAN command
    std::string scan_file(const std::filesystem::path& path) {
        if (!is_connected()) return "ERROR: Not connected";

        std::string cmd = "SCAN " + std::string(path.c_str()) + "\n";
        ssize_t sent = ::send(fd_, cmd.c_str(), cmd.size(), 0);
        if (sent < 0) return "ERROR: Send failed";

        std::string response;
        char buf[DEFAULT_CLAMD_CHUNK_SIZE];
        while (true) {
            ssize_t n = ::recv(fd_, buf, sizeof(buf) - 1, 0);
            if (n <= 0) break;
            buf[n] = '\0';
            response += buf;
            if (!response.empty() && response.back() == '\n') break;
        }
        return response;
    }

    // Send a PING to check if clamd is alive
    bool ping() {
        std::string resp = send_command("PING");
        return resp.find("PONG") != std::string::npos;
    }

    // Get version
    std::string version() {
        std::string resp = send_command("VERSION");
        // Strip leading newline
        if (!resp.empty() && resp[0] == '\n') resp = resp.substr(1);
        // Remove trailing newline
        while (!resp.empty() && resp.back() == '\n') resp.pop_back();
        return resp;
    }

private:
    std::string socket_path_;
    size_t timeout_secs_;
    int fd_;
};

// ============================================================================
// Parse clamd scan results
// ============================================================================

static bool parse_scan_result(const std::string& response, std::string& virus_name) {
    // ClamAV returns something like:
    //   stream: VIRUS_NAME FOUND
    //   stream: OK
    //   /path/to/file: VIRUS_NAME FOUND
    //   /path/to/file: OK
    //   ERROR: message

    if (response.empty()) return false; // Error

    std::string trimmed = response;
    while (!trimmed.empty() && (trimmed.back() == '\n' || trimmed.back() == '\r'))
        trimmed.pop_back();

    if (trimmed.empty()) return false;

    // Check for explicit error
    if (trimmed.find("ERROR:") == 0) {
        virus_name = trimmed;
        return false;
    }

    // Look for " FOUND" pattern
    auto found_pos = trimmed.find(" FOUND");
    if (found_pos != std::string::npos) {
        // Extract virus name: everything after the colon and before " FOUND"
        auto colon_pos = trimmed.rfind(':', found_pos);
        if (colon_pos != std::string::npos) {
            virus_name = trimmed.substr(colon_pos + 2, found_pos - colon_pos - 2);
        } else {
            virus_name = trimmed.substr(0, found_pos);
        }
        return true; // Infected
    }

    // Check for OK
    if (trimmed.find("OK") != std::string::npos ||
        trimmed.find("ok") != std::string::npos) {
        return false; // Clean
    }

    return false; // Assume error if unknown format
}

// ============================================================================
// Quarantine Manager
// ============================================================================

class QuarantineManager {
public:
    explicit QuarantineManager(std::filesystem::path quarantine_dir)
        : quarantine_dir_(std::move(quarantine_dir))
    {
        std::filesystem::create_directories(quarantine_dir_);
        load_index();
    }

    // Move a file to quarantine
    bool quarantine_file(const std::filesystem::path& source_path,
                        const std::string& file_hash,
                        const ScanResult& result,
                        std::string& quarantine_path_out)
    {
        std::lock_guard<std::mutex> lock(mutex_);

        // Create quarantine filename: hash_first8_timestamp_uuid
        std::string safe_name = file_hash.substr(0, 16) + "_" +
            std::to_string(std::chrono::system_clock::now().time_since_epoch().count());
        std::filesystem::path dest = quarantine_dir_ / safe_name;

        try {
            std::filesystem::copy(source_path, dest,
                std::filesystem::copy_options::overwrite_existing);
        } catch (const std::filesystem::filesystem_error& e) {
            return false;
        }

        quarantine_path_out = dest.string();

        // Record in index
        QuarantineEntry entry;
        entry.original_path = source_path.string();
        entry.quarantine_path = dest.string();
        entry.file_hash = file_hash;
        entry.virus_name = result.virus_name;
        entry.detected_mime = result.detected_mime;
        entry.claimed_mime = result.claimed_mime;
        entry.file_size = result.file_size;
        entry.quarantine_time = std::chrono::system_clock::now();
        entry.reason = result.message;
        entry.status_result = result.status;

        entries_.push_back(entry);
        save_index();
        return true;
    }

    // List all quarantined files
    std::vector<QuarantineEntry> list_entries() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return entries_;
    }

    // Get a specific entry by hash
    std::optional<QuarantineEntry> get_entry(const std::string& file_hash) const {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& e : entries_) {
            if (e.file_hash == file_hash) return e;
        }
        return std::nullopt;
    }

    // Delete a quarantined file
    bool delete_entry(const std::string& file_hash) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = std::find_if(entries_.begin(), entries_.end(),
            [&](const QuarantineEntry& e) { return e.file_hash == file_hash; });
        if (it == entries_.end()) return false;

        try {
            std::filesystem::remove(it->quarantine_path);
        } catch (const std::filesystem::filesystem_error&) {
            return false;
        }
        entries_.erase(it);
        save_index();
        return true;
    }

    // Restore a file from quarantine
    bool restore_entry(const std::string& file_hash) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = std::find_if(entries_.begin(), entries_.end(),
            [&](const QuarantineEntry& e) { return e.file_hash == file_hash; });
        if (it == entries_.end()) return false;

        try {
            std::filesystem::copy(it->quarantine_path, it->original_path,
                std::filesystem::copy_options::overwrite_existing);
            std::filesystem::remove(it->quarantine_path);
        } catch (const std::filesystem::filesystem_error&) {
            return false;
        }
        entries_.erase(it);
        save_index();
        return true;
    }

    // Clean up old quarantined files
    size_t clean_old_entries(size_t max_age_seconds) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto now = std::chrono::system_clock::now();
        size_t removed = 0;

        auto it = entries_.begin();
        while (it != entries_.end()) {
            auto age = std::chrono::duration_cast<std::chrono::seconds>(now - it->quarantine_time).count();
            if (static_cast<size_t>(age) > max_age_seconds) {
                try {
                    std::filesystem::remove(it->quarantine_path);
                } catch (...) {}
                it = entries_.erase(it);
                ++removed;
            } else {
                ++it;
            }
        }
        if (removed > 0) save_index();
        return removed;
    }

    size_t entry_count() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return entries_.size();
    }

    nlohmann::json to_json() const {
        std::lock_guard<std::mutex> lock(mutex_);
        nlohmann::json j = nlohmann::json::array();
        for (const auto& e : entries_) {
            nlohmann::json ej;
            ej["file_hash"] = e.file_hash;
            ej["original_path"] = e.original_path;
            ej["quarantine_path"] = e.quarantine_path;
            ej["virus_name"] = e.virus_name;
            ej["detected_mime"] = e.detected_mime;
            ej["claimed_mime"] = e.claimed_mime;
            ej["file_size"] = e.file_size;
            ej["reason"] = e.reason;
            ej["quarantine_time"] = std::chrono::duration_cast<std::chrono::seconds>(
                e.quarantine_time.time_since_epoch()).count();
            j.push_back(ej);
        }
        return j;
    }

private:
    struct QuarantineEntry {
        std::string original_path;
        std::string quarantine_path;
        std::string file_hash;
        std::string virus_name;
        std::string detected_mime;
        std::string claimed_mime;
        size_t file_size = 0;
        std::string reason;
        ScanResult::Status status_result = ScanResult::Status::ERROR;
        std::chrono::system_clock::time_point quarantine_time;
    };

    std::filesystem::path quarantine_dir_;
    mutable std::mutex mutex_;
    std::vector<QuarantineEntry> entries_;

    void save_index() {
        nlohmann::json j = nlohmann::json::array();
        for (const auto& e : entries_) {
            nlohmann::json ej;
            ej["original_path"] = e.original_path;
            ej["quarantine_path"] = e.quarantine_path;
            ej["file_hash"] = e.file_hash;
            ej["virus_name"] = e.virus_name;
            ej["detected_mime"] = e.detected_mime;
            ej["claimed_mime"] = e.claimed_mime;
            ej["file_size"] = e.file_size;
            ej["reason"] = e.reason;
            ej["status"] = static_cast<int>(e.status_result);
            ej["quarantine_time"] = std::chrono::duration_cast<std::chrono::seconds>(
                e.quarantine_time.time_since_epoch()).count();
            j.push_back(ej);
        }
        std::filesystem::path index_path = quarantine_dir_ / "index.json";
        std::ofstream out(index_path);
        if (out) {
            out << j.dump(2);
        }
    }

    void load_index() {
        std::filesystem::path index_path = quarantine_dir_ / "index.json";
        if (!std::filesystem::exists(index_path)) return;

        std::ifstream in(index_path);
        if (!in) return;

        try {
            nlohmann::json j;
            in >> j;
            if (!j.is_array()) return;

            for (const auto& ej : j) {
                QuarantineEntry e;
                e.original_path = ej.value("original_path", "");
                e.quarantine_path = ej.value("quarantine_path", "");
                e.file_hash = ej.value("file_hash", "");
                e.virus_name = ej.value("virus_name", "");
                e.detected_mime = ej.value("detected_mime", "");
                e.claimed_mime = ej.value("claimed_mime", "");
                e.file_size = ej.value("file_size", size_t(0));
                e.reason = ej.value("reason", "");
                e.status_result = static_cast<ScanResult::Status>(
                    ej.value("status", static_cast<int>(ScanResult::Status::ERROR)));

                auto qt = ej.value("quarantine_time", int64_t(0));
                e.quarantine_time = std::chrono::system_clock::from_time_t(
                    static_cast<time_t>(qt));

                // Only add if the file still exists
                if (std::filesystem::exists(e.quarantine_path)) {
                    entries_.push_back(e);
                }
            }
        } catch (...) {
            // Corrupted index — start fresh
            entries_.clear();
        }
    }
};

// ============================================================================
// Scan Metrics
// ============================================================================

class ScanMetrics {
public:
    struct Snapshot {
        size_t total_scans = 0;
        size_t clean_count = 0;
        size_t infected_count = 0;
        size_t error_count = 0;
        size_t encrypted_count = 0;
        size_t archive_bomb_count = 0;
        size_t sanitized_count = 0;
        size_t blocked_count = 0;
        size_t size_exceeded_count = 0;
        size_t invalid_type_count = 0;
        size_t dangerous_extension_count = 0;
        double total_scan_time_ms = 0.0;
        double avg_scan_time_ms = 0.0;
        double max_scan_time_ms = 0.0;
        double min_scan_time_ms = std::numeric_limits<double>::max();
        size_t cache_hits = 0;
        size_t cache_misses = 0;
        size_t clamd_errors = 0;
        size_t bytes_scanned = 0;
        size_t queue_current_size = 0;
        size_t queue_total_processed = 0;
        size_t quarantine_total = 0;
        std::chrono::system_clock::time_point snapshot_time;
    };

    void record_scan(const ScanResult& result) {
        std::lock_guard<std::mutex> lock(mutex_);
        ++snapshot_.total_scans;

        switch (result.status) {
            case ScanResult::Status::CLEAN:              ++snapshot_.clean_count; break;
            case ScanResult::Status::INFECTED:           ++snapshot_.infected_count; break;
            case ScanResult::Status::ERROR:              ++snapshot_.error_count; break;
            case ScanResult::Status::ENCRYPTED:          ++snapshot_.encrypted_count; break;
            case ScanResult::Status::ARCHIVE_BOMB:       ++snapshot_.archive_bomb_count; break;
            case ScanResult::Status::SANITIZED:          ++snapshot_.sanitized_count; break;
            case ScanResult::Status::BLOCKED:            ++snapshot_.blocked_count; break;
            case ScanResult::Status::SIZE_EXCEEDED:      ++snapshot_.size_exceeded_count; break;
            case ScanResult::Status::INVALID_TYPE:       ++snapshot_.invalid_type_count; break;
            case ScanResult::Status::DANGEROUS_EXTENSION: ++snapshot_.dangerous_extension_count; break;
            default: break;
        }

        snapshot_.total_scan_time_ms += result.scan_duration_ms;
        snapshot_.bytes_scanned += result.file_size;
        if (result.scan_duration_ms > snapshot_.max_scan_time_ms)
            snapshot_.max_scan_time_ms = result.scan_duration_ms;
        if (result.scan_duration_ms < snapshot_.min_scan_time_ms)
            snapshot_.min_scan_time_ms = result.scan_duration_ms;

        if (snapshot_.total_scans > 0)
            snapshot_.avg_scan_time_ms = snapshot_.total_scan_time_ms / snapshot_.total_scans;
    }

    void record_cache_hit() {
        std::lock_guard<std::mutex> lock(mutex_);
        ++snapshot_.cache_hits;
    }

    void record_cache_miss() {
        std::lock_guard<std::mutex> lock(mutex_);
        ++snapshot_.cache_misses;
    }

    void record_clamd_error() {
        std::lock_guard<std::mutex> lock(mutex_);
        ++snapshot_.clamd_errors;
    }

    void set_queue_size(size_t s) {
        std::lock_guard<std::mutex> lock(mutex_);
        snapshot_.queue_current_size = s;
    }

    void increment_processed() {
        std::lock_guard<std::mutex> lock(mutex_);
        ++snapshot_.queue_total_processed;
    }

    void record_quarantined() {
        std::lock_guard<std::mutex> lock(mutex_);
        ++snapshot_.quarantine_total;
    }

    Snapshot get_snapshot() const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto s = snapshot_;
        s.snapshot_time = std::chrono::system_clock::now();
        return s;
    }

    nlohmann::json get_json() const {
        auto s = get_snapshot();
        nlohmann::json j;
        j["total_scans"] = s.total_scans;
        j["clean"] = s.clean_count;
        j["infected"] = s.infected_count;
        j["error"] = s.error_count;
        j["encrypted"] = s.encrypted_count;
        j["archive_bomb"] = s.archive_bomb_count;
        j["sanitized"] = s.sanitized_count;
        j["blocked"] = s.blocked_count;
        j["size_exceeded"] = s.size_exceeded_count;
        j["invalid_type"] = s.invalid_type_count;
        j["dangerous_extension"] = s.dangerous_extension_count;
        j["avg_scan_time_ms"] = s.avg_scan_time_ms;
        j["max_scan_time_ms"] = s.max_scan_time_ms;
        j["min_scan_time_ms"] = (s.min_scan_time_ms == std::numeric_limits<double>::max())
            ? 0.0 : s.min_scan_time_ms;
        j["cache_hits"] = s.cache_hits;
        j["cache_misses"] = s.cache_misses;
        j["clamd_errors"] = s.clamd_errors;
        j["bytes_scanned"] = s.bytes_scanned;
        j["queue_current_size"] = s.queue_current_size;
        j["queue_total_processed"] = s.queue_total_processed;
        j["quarantine_total"] = s.quarantine_total;
        j["snapshot_time"] = std::chrono::duration_cast<std::chrono::seconds>(
            s.snapshot_time.time_since_epoch()).count();
        return j;
    }

    void reset() {
        std::lock_guard<std::mutex> lock(mutex_);
        snapshot_ = Snapshot{};
    }

private:
    mutable std::mutex mutex_;
    Snapshot snapshot_;
};

// ============================================================================
// Scan Cache
// ============================================================================

class ScanCache {
public:
    explicit ScanCache(size_t max_size = DEFAULT_SCAN_CACHE_SIZE,
                      size_t ttl_seconds = DEFAULT_SCAN_CACHE_TTL_SECONDS)
        : max_size_(max_size), ttl_seconds_(ttl_seconds) {}

    std::optional<ScanResult> get(const std::string& file_hash) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = cache_map_.find(file_hash);
        if (it == cache_map_.end()) return std::nullopt;

        // Check TTL
        auto age = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now() - it->second.scan_time).count();
        if (static_cast<size_t>(age) > ttl_seconds_) {
            cache_map_.erase(it);
            return std::nullopt;
        }

        // Move to front of LRU list
        auto lru_it = std::find(lru_list_.begin(), lru_list_.end(), file_hash);
        if (lru_it != lru_list_.end()) {
            lru_list_.erase(lru_it);
            lru_list_.push_front(file_hash);
        }

        return it->second;
    }

    void put(const std::string& file_hash, const ScanResult& result) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = cache_map_.find(file_hash);

        if (it != cache_map_.end()) {
            // Update existing
            it->second = result;
            auto lru_it = std::find(lru_list_.begin(), lru_list_.end(), file_hash);
            if (lru_it != lru_list_.end()) {
                lru_list_.erase(lru_it);
                lru_list_.push_front(file_hash);
            }
            return;
        }

        // Evict if at capacity
        while (cache_map_.size() >= max_size_ && !lru_list_.empty()) {
            std::string oldest = lru_list_.back();
            lru_list_.pop_back();
            cache_map_.erase(oldest);
        }

        cache_map_[file_hash] = result;
        lru_list_.push_front(file_hash);
    }

    bool contains(const std::string& file_hash) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = cache_map_.find(file_hash);
        if (it == cache_map_.end()) return false;

        auto age = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now() - it->second.scan_time).count();
        if (static_cast<size_t>(age) > ttl_seconds_) {
            auto lru_it = std::find(lru_list_.begin(), lru_list_.end(), file_hash);
            if (lru_it != lru_list_.end()) lru_list_.erase(lru_it);
            cache_map_.erase(it);
            return false;
        }
        return true;
    }

    void clear() {
        std::lock_guard<std::mutex> lock(mutex_);
        cache_map_.clear();
        lru_list_.clear();
    }

    void clean_expired() {
        std::lock_guard<std::mutex> lock(mutex_);
        auto now = std::chrono::system_clock::now();
        auto it = cache_map_.begin();
        while (it != cache_map_.end()) {
            auto age = std::chrono::duration_cast<std::chrono::seconds>(
                now - it->second.scan_time).count();
            if (static_cast<size_t>(age) > ttl_seconds_) {
                auto lru_it = std::find(lru_list_.begin(), lru_list_.end(), it->first);
                if (lru_it != lru_list_.end()) lru_list_.erase(lru_it);
                it = cache_map_.erase(it);
            } else {
                ++it;
            }
        }
    }

    size_t size() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return cache_map_.size();
    }

private:
    size_t max_size_;
    size_t ttl_seconds_;
    mutable std::mutex mutex_;
    std::unordered_map<std::string, ScanResult> cache_map_;
    std::list<std::string> lru_list_;
};

// ============================================================================
// Scanning Queue (Async)
// ============================================================================

using ScanCallback = std::function<void(const ScanResult&)>;

struct ScanJob {
    std::string job_id;
    std::vector<uint8_t> data;
    std::string file_path;
    std::string claimed_mime;
    std::string original_filename;
    bool is_file = false;  // true = scan from file_path, false = scan in-memory data
    ScanCallback callback;
    std::chrono::system_clock::time_point enqueue_time;
    int priority = 0;  // lower = higher priority
};

class ScanQueue {
public:
    explicit ScanQueue(size_t max_size = DEFAULT_SCAN_QUEUE_SIZE)
        : max_size_(max_size), running_(false) {}

    ~ScanQueue() {
        stop();
    }

    bool enqueue(const ScanJob& job) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (queue_.size() >= max_size_) return false;
        queue_.push_back(job);
        // Sort by priority (lower = higher)
        std::sort(queue_.begin(), queue_.end(),
            [](const ScanJob& a, const ScanJob& b) { return a.priority < b.priority; });
        cv_.notify_one();
        return true;
    }

    void start_workers(ScanMetrics* metrics,
                       ClamdConnection* clamd,
                       ScanCache* cache,
                       QuarantineManager* quarantine,
                       size_t num_threads = DEFAULT_SCAN_WORKER_THREADS)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (running_) return;
        running_ = true;

        for (size_t i = 0; i < num_threads; ++i) {
            workers_.emplace_back(&ScanQueue::worker_loop, this,
                                 metrics, clamd, cache, quarantine);
        }
    }

    void stop() {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!running_) return;
            running_ = false;
            cv_.notify_all();
        }
        for (auto& w : workers_) {
            if (w.joinable()) w.join();
        }
        workers_.clear();
    }

    size_t queue_size() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_.size();
    }

private:
    size_t max_size_;
    mutable std::mutex mutex_;
    std::condition_variable cv_;
    std::vector<ScanJob> queue_;
    std::vector<std::thread> workers_;
    std::atomic<bool> running_;

    void worker_loop(ScanMetrics* metrics, ClamdConnection* clamd,
                     ScanCache* cache, QuarantineManager* quarantine)
    {
        while (true) {
            ScanJob job;
            {
                std::unique_lock<std::mutex> lock(mutex_);
                cv_.wait(lock, [this] { return !queue_.empty() || !running_; });
                if (!running_ && queue_.empty()) return;
                if (queue_.empty()) continue;
                job = std::move(queue_.front());
                queue_.pop_front();
            }

            if (metrics) metrics->set_queue_size(queue_.size());

            // Process the job
            ScanResult result;
            auto start = std::chrono::steady_clock::now();

            // Check cache first
            std::string file_hash;
            if (job.is_file && !job.file_path.empty()) {
                file_hash = sha256_file(job.file_path);
            } else {
                file_hash = sha256_hex(std::string_view(
                    reinterpret_cast<const char*>(job.data.data()), job.data.size()));
            }
            result.file_hash = file_hash;

            if (cache && cache->contains(file_hash)) {
                auto cached = cache->get(file_hash);
                if (cached) {
                    result = *cached;
                    if (metrics) metrics->record_cache_hit();
                    auto end = std::chrono::steady_clock::now();
                    result.scan_duration_ms = std::chrono::duration<double, std::milli>(end - start).count();
                    if (job.callback) job.callback(result);
                    if (metrics) {
                        metrics->record_scan(result);
                        metrics->set_queue_size(queue_.size());
                        metrics->increment_processed();
                    }
                    continue;
                }
            }
            if (metrics) metrics->record_cache_miss();

            // Scan
            if (job.is_file) {
                result = scan_file_internal(job.file_path, job.claimed_mime,
                                           job.original_filename, clamd, quarantine);
            } else {
                result = scan_data_internal(job.data, job.claimed_mime,
                                           job.original_filename, clamd, quarantine);
            }

            auto end = std::chrono::steady_clock::now();
            result.scan_duration_ms = std::chrono::duration<double, std::milli>(end - start).count();

            // Update cache
            if (cache) cache->put(file_hash, result);

            // Callback
            if (job.callback) job.callback(result);

            // Update metrics
            if (metrics) {
                metrics->record_scan(result);
                metrics->set_queue_size(queue_.size());
                metrics->increment_processed();
            }
        }
    }

    ScanResult scan_file_internal(const std::string& file_path,
                                  const std::string& claimed_mime,
                                  const std::string& original_filename,
                                  ClamdConnection* clamd,
                                  QuarantineManager* quarantine)
    {
        ScanResult result;
        result.claimed_mime = claimed_mime;
        result.original_file_path = file_path;

        // Get file info
        std::error_code ec;
        auto file_size = std::filesystem::file_size(file_path, ec);
        if (ec) {
            result.status = ScanResult::Status::ERROR;
            result.message = "Cannot read file: " + ec.message();
            return result;
        }
        result.file_size = file_size;

        // Extract extension
        result.file_extension = extract_extension(original_filename.empty()
            ? file_path : original_filename);

        // Step 1: File extension validation
        if (!result.file_extension.empty()) {
            if (BLOCKED_EXTENSIONS.count(to_lower(result.file_extension))) {
                result.status = ScanResult::Status::DANGEROUS_EXTENSION;
                result.message = "File extension '" + result.file_extension +
                    "' is blocked for security reasons";
                if (quarantine) {
                    std::string qpath;
                    quarantine->quarantine_file(file_path, result.file_hash, result, qpath);
                    result.quarantined_path = qpath;
                }
                return result;
            }
        }

        // Step 2: Size limits check
        std::string file_mime_lower = to_lower(claimed_mime);
        size_t max_size = DEFAULT_MAX_OTHER_SIZE;

        if (ALLOWED_IMAGE_TYPES.count(file_mime_lower)) {
            max_size = DEFAULT_MAX_IMAGE_SIZE;
        } else if (ALLOWED_VIDEO_TYPES.count(file_mime_lower)) {
            max_size = DEFAULT_MAX_VIDEO_SIZE;
        } else if (ALLOWED_AUDIO_TYPES.count(file_mime_lower)) {
            max_size = DEFAULT_MAX_AUDIO_SIZE;
        } else if (ALLOWED_ARCHIVE_TYPES.count(file_mime_lower)) {
            max_size = DEFAULT_MAX_ARCHIVE_SIZE;
        }

        if (file_size > max_size) {
            result.status = ScanResult::Status::SIZE_EXCEEDED;
            result.message = "File size " + std::to_string(file_size) +
                " exceeds maximum " + std::to_string(max_size) + " bytes";
            return result;
        }

        // Step 3: Detect real MIME type from magic bytes
        std::ifstream file(file_path, std::ios::binary);
        if (!file) {
            result.status = ScanResult::Status::ERROR;
            result.message = "Cannot open file for scanning";
            return result;
        }
        std::vector<uint8_t> header(512);
        file.read(reinterpret_cast<char*>(header.data()), header.size());
        header.resize(file.gcount());
        result.detected_mime = detect_magic_mime(header);

        // Step 4: MIME type validation
        if (!validate_mime_match(result.detected_mime, claimed_mime)) {
            result.status = ScanResult::Status::INVALID_TYPE;
            result.message = "Detected MIME type '" + result.detected_mime +
                "' does not match claimed type '" + claimed_mime + "'";
            if (quarantine) {
                std::string qpath;
                quarantine->quarantine_file(file_path, result.file_hash, result, qpath);
                result.quarantined_path = qpath;
            }
            return result;
        }

        // Step 5: Special content validation
        auto special_result = validate_special_content_type(
            header, result.detected_mime, file_path, result.file_size);
        if (special_result.status != ScanResult::Status::CLEAN) {
            if (special_result.status == ScanResult::Status::BLOCKED ||
                special_result.status == ScanResult::Status::ARCHIVE_BOMB ||
                special_result.status == ScanResult::Status::ENCRYPTED) {
                result.status = special_result.status;
                result.message = special_result.message;
                result.was_sanitized = special_result.was_sanitized;
                if (quarantine) {
                    std::string qpath;
                    quarantine->quarantine_file(file_path, result.file_hash, result, qpath);
                    result.quarantined_path = qpath;
                }
                return result;
            }
            if (special_result.status == ScanResult::Status::SANITIZED) {
                result.was_sanitized = true;
            }
        }

        // Step 6: Image dimension validation
        if (ALLOWED_IMAGE_TYPES.count(result.detected_mime) &&
            result.detected_mime != "image/svg+xml") {
            auto dims = detect_image_dimensions(file_path, header);
            if (dims.first > DEFAULT_MAX_IMAGE_WIDTH || dims.second > DEFAULT_MAX_IMAGE_HEIGHT) {
                result.status = ScanResult::Status::SIZE_EXCEEDED;
                result.message = "Image dimensions " + std::to_string(dims.first) + "x" +
                    std::to_string(dims.second) + " exceed maximum " +
                    std::to_string(DEFAULT_MAX_IMAGE_WIDTH) + "x" +
                    std::to_string(DEFAULT_MAX_IMAGE_HEIGHT);
                return result;
            }
            if (dims.first * dims.second > DEFAULT_MAX_IMAGE_PIXELS) {
                result.status = ScanResult::Status::SIZE_EXCEEDED;
                result.message = "Image pixel count " + std::to_string(dims.first * dims.second) +
                    " exceeds maximum " + std::to_string(DEFAULT_MAX_IMAGE_PIXELS);
                return result;
            }
        }

        // Step 7: EXIF stripping
        if (result.detected_mime == "image/jpeg" && !result.was_sanitized) {
            bool stripped = strip_exif_from_file(file_path);
            if (stripped) result.was_sanitized = true;
        }

        // Step 8: ClamAV scan
        if (clamd && clamd->is_connected()) {
            std::string clamd_response = clamd->scan_file(file_path);
            std::string virus_name;
            if (parse_scan_result(clamd_response, virus_name)) {
                result.status = ScanResult::Status::INFECTED;
                result.virus_name = virus_name;
                result.message = "Virus detected: " + virus_name;
                if (quarantine) {
                    std::string qpath;
                    quarantine->quarantine_file(file_path, result.file_hash, result, qpath);
                    result.quarantined_path = qpath;
                }
                return result;
            }
            if (clamd_response.find("ERROR") != std::string::npos) {
                // ClamAV error — log but don't block
                result.message = "ClamAV scan warning: " + clamd_response;
            }
        }

        result.status = result.was_sanitized ?
            ScanResult::Status::SANITIZED : ScanResult::Status::CLEAN;
        result.message = result.was_sanitized ?
            "File scanned and sanitized successfully" :
            "File scanned successfully";
        return result;
    }

    ScanResult scan_data_internal(const std::vector<uint8_t>& data,
                                  const std::string& claimed_mime,
                                  const std::string& original_filename,
                                  ClamdConnection* clamd,
                                  QuarantineManager* quarantine)
    {
        ScanResult result;
        result.claimed_mime = claimed_mime;
        result.file_size = data.size();

        // Extract extension
        result.file_extension = extract_extension(original_filename);

        // Step 1: Extension validation
        if (!result.file_extension.empty()) {
            if (BLOCKED_EXTENSIONS.count(to_lower(result.file_extension))) {
                result.status = ScanResult::Status::DANGEROUS_EXTENSION;
                result.message = "File extension '" + result.file_extension +
                    "' is blocked for security reasons";
                return result;
            }
        }

        // Step 2: Size check
        std::string file_mime_lower = to_lower(claimed_mime);
        size_t max_size = DEFAULT_MAX_OTHER_SIZE;

        if (ALLOWED_IMAGE_TYPES.count(file_mime_lower)) {
            max_size = DEFAULT_MAX_IMAGE_SIZE;
        } else if (ALLOWED_VIDEO_TYPES.count(file_mime_lower)) {
            max_size = DEFAULT_MAX_VIDEO_SIZE;
        } else if (ALLOWED_AUDIO_TYPES.count(file_mime_lower)) {
            max_size = DEFAULT_MAX_AUDIO_SIZE;
        } else if (ALLOWED_ARCHIVE_TYPES.count(file_mime_lower)) {
            max_size = DEFAULT_MAX_ARCHIVE_SIZE;
        }

        if (data.size() > max_size) {
            result.status = ScanResult::Status::SIZE_EXCEEDED;
            result.message = "Data size " + std::to_string(data.size()) +
                " exceeds maximum " + std::to_string(max_size) + " bytes";
            return result;
        }

        // Step 3: Magic number detection
        result.detected_mime = detect_magic_mime(data);

        // Step 4: MIME type validation
        if (!validate_mime_match(result.detected_mime, claimed_mime)) {
            result.status = ScanResult::Status::INVALID_TYPE;
            result.message = "Detected MIME type '" + result.detected_mime +
                "' does not match claimed type '" + claimed_mime + "'";
            return result;
        }

        // Step 5: Special content validation
        auto special_result = validate_special_content_data(data, result.detected_mime);
        if (special_result.status != ScanResult::Status::CLEAN) {
            result = special_result;
            result.claimed_mime = claimed_mime;
            return result;
        }

        // Step 6: Image dimension check
        if (ALLOWED_IMAGE_TYPES.count(result.detected_mime) &&
            result.detected_mime != "image/svg+xml") {
            auto dims = detect_image_dimensions_from_data(data);
            if (dims.first > DEFAULT_MAX_IMAGE_WIDTH || dims.second > DEFAULT_MAX_IMAGE_HEIGHT) {
                result.status = ScanResult::Status::SIZE_EXCEEDED;
                result.message = "Image dimensions exceed maximum";
                return result;
            }
            if (dims.first * dims.second > DEFAULT_MAX_IMAGE_PIXELS) {
                result.status = ScanResult::Status::SIZE_EXCEEDED;
                result.message = "Image pixel count exceeds maximum";
                return result;
            }
        }

        // Step 7: ClamAV scan (in-memory via INSTREAM)
        if (clamd && clamd->is_connected()) {
            std::string clamd_response = clamd->scan_stream(data);
            std::string virus_name;
            if (parse_scan_result(clamd_response, virus_name)) {
                result.status = ScanResult::Status::INFECTED;
                result.virus_name = virus_name;
                result.message = "Virus detected: " + virus_name;
                return result;
            }
            if (clamd_response.find("ERROR") != std::string::npos) {
                result.message = "ClamAV scan warning: " + clamd_response;
            }
        }

        result.status = ScanResult::Status::CLEAN;
        result.message = "File scanned successfully";
        return result;
    }
};

// ============================================================================
// MIME detection via magic numbers
// ============================================================================

static std::string detect_magic_mime(const std::vector<uint8_t>& data) {
    if (data.empty()) return "application/octet-stream";

    // Check SVG first (text-based, may have whitespace/comments before root)
    std::string_view view(reinterpret_cast<const char*>(data.data()),
                          std::min(data.size(), size_t(1024)));

    // Look for SVG pattern
    if (view.find("<svg") != std::string::npos ||
        (view.find("<?xml") != std::string::npos && view.find("<svg") != std::string::npos)) {
        return "image/svg+xml";
    }

    // Look for HTML pattern
    if (view.find("<html") != std::string::npos ||
        view.find("<!doctype html") != std::string::npos ||
        view.find("<!DOCTYPE html") != std::string::npos ||
        view.find("<!DOCTYPE HTML") != std::string::npos) {
        return "text/html";
    }

    // Look for XML
    if (view.find("<?xml") != std::string::npos) {
        return "application/xml";
    }

    // Check PDF header (can be at various offsets due to comments)
    for (size_t i = 0; i + 5 <= std::min(data.size(), size_t(1024)); ++i) {
        if (data[i] == '%' && data[i+1] == 'P' && data[i+2] == 'D' &&
            data[i+3] == 'F' && data[i+4] == '-') {
            return "application/pdf";
        }
    }

    // Check magic signatures
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
                // Handle RIFF container
                if (sig.mime_type == "image/webp" || sig.mime_type == "audio/wav" ||
                    sig.mime_type == "video/avi") {
                    if (data.size() >= 12) {
                        std::string subtype(reinterpret_cast<const char*>(&data[8]), 4);
                        if (subtype == "WEBP") return "image/webp";
                        if (subtype == "WAVE") return "audio/wav";
                        if (subtype == "AVI ") return "video/avi";
                        return sig.mime_type;
                    }
                }
                // Handle MP3 variants
                if (sig.mime_type == "audio/mpeg" && data.size() >= 2) {
                    uint8_t byte1 = data[0];
                    uint8_t byte2 = data[1];
                    if (byte1 == 0xFF && (byte2 == 0xFB || byte2 == 0xF3 ||
                        byte2 == 0xF2 || byte2 == 0xFA || byte2 == 0xFD)) {
                        return "audio/mpeg";
                    }
                    if (sig.bytes[0] == 0xFF && sig.bytes[1] == 0xFB &&
                        data[0] == 0x49 && data[1] == 0x44 && data[2] == 0x33) {
                        continue; // ID3 tag — check next sig
                    }
                    return sig.mime_type;
                }
                // Handle MP4 variants
                if (sig.mime_type == "video/mp4") {
                    if (data.size() >= 12) {
                        // Check for ftyp box
                        std::string brand(reinterpret_cast<const char*>(&data[4]), 4);
                        if (brand == "ftyp") {
                            return "video/mp4";
                        }
                    }
                    return "video/mp4";
                }
                return sig.mime_type;
            }
        }
    }

    // Try text detection
    bool is_text = true;
    size_t check_limit = std::min(data.size(), size_t(512));
    for (size_t i = 0; i < check_limit; ++i) {
        if (data[i] == 0) { is_text = false; break; }
    }
    if (is_text && !data.empty()) return "text/plain";

    return "application/octet-stream";
}

// ============================================================================
// MIME type validation (cross-check detected vs claimed)
// ============================================================================

static bool validate_mime_match(const std::string& detected, const std::string& claimed) {
    if (detected.empty() || claimed.empty()) return true;  // Can't validate
    if (detected == claimed) return true;
    if (detected == "application/octet-stream") return true;  // Unknown type, skip

    std::string d = to_lower(detected);
    std::string c = to_lower(claimed);

    // Direct match
    if (d == c) return true;

    // Same category
    std::string d_cat = d.substr(0, d.find('/'));
    std::string c_cat = c.substr(0, c.find('/'));
    if (d_cat != c_cat) return false;  // Different categories entirely

    // Same main type — some flexibility
    // image/* -> image/*, video/* -> video/*, audio/* -> audio/*
    if (d_cat == "image" && c_cat == "image") {
        // TIFF variants
        if ((d == "image/tiff" && c == "image/tiff") ||
            (d.find("tiff") != std::string::npos && c.find("tiff") != std::string::npos))
            return true;
    }

    if (d_cat == "video" && c_cat == "video") {
        // MP4/quicktime variants often confused
        if ((d.find("mp4") != std::string::npos || d.find("quicktime") != std::string::npos) &&
            (c.find("mp4") != std::string::npos || c.find("quicktime") != std::string::npos))
            return true;
    }

    if (d_cat == "text" && c_cat == "text") return true;

    // Allow some common mismatches
    static const std::set<std::pair<std::string, std::string>> ALLOWED_MISMATCHES = {
        {"text/plain", "application/json"},
        {"text/plain", "application/xml"},
        {"text/plain", "text/csv"},
        {"application/json", "text/plain"},
        {"application/xml", "text/plain"},
        {"application/xml", "text/xml"},
        {"text/xml", "application/xml"},
        {"audio/wav", "audio/wave"},
        {"audio/wave", "audio/wav"},
        {"audio/wav", "audio/x-wav"},
        {"audio/x-wav", "audio/wav"},
    };

    return ALLOWED_MISMATCHES.count({d, c}) > 0;
}

// ============================================================================
// Image dimension detection
// ============================================================================

static std::pair<size_t, size_t> detect_image_dimensions(
    const std::filesystem::path& path, const std::vector<uint8_t>& header)
{
    return detect_image_dimensions_from_data(header);
}

static std::pair<size_t, size_t> detect_image_dimensions_from_data(
    const std::vector<uint8_t>& data)
{
    if (data.size() < 8) return {0, 0};

    // JPEG
    if (data[0] == 0xFF && data[1] == 0xD8) {
        size_t i = 2;
        while (i + 8 < data.size()) {
            if (data[i] != 0xFF) break;
            uint8_t marker = data[i + 1];
            if (marker == 0xC0 || marker == 0xC1 || marker == 0xC2 ||
                (marker >= 0xDA && marker <= 0xDB)) {
                // SOF markers
                if (i + 8 < data.size()) {
                    size_t h = (data[i + 5] << 8) | data[i + 6];
                    size_t w = (data[i + 7] << 8) | data[i + 8];
                    return {w, h};
                }
            }
            size_t seg_len = (data[i + 2] << 8) | data[i + 3];
            i += 2 + seg_len;
            if (i >= data.size()) break;
        }
        return {0, 0};
    }

    // PNG
    if (data.size() >= 24 &&
        data[0] == 0x89 && data[1] == 'P' && data[2] == 'N' && data[3] == 'G') {
        size_t w = (static_cast<size_t>(data[16]) << 24) |
                   (static_cast<size_t>(data[17]) << 16) |
                   (static_cast<size_t>(data[18]) << 8) |
                    static_cast<size_t>(data[19]);
        size_t h = (static_cast<size_t>(data[20]) << 24) |
                   (static_cast<size_t>(data[21]) << 16) |
                   (static_cast<size_t>(data[22]) << 8) |
                    static_cast<size_t>(data[23]);
        return {w, h};
    }

    // GIF
    if (data.size() >= 10 &&
        data[0] == 'G' && data[1] == 'I' && data[2] == 'F') {
        size_t w = data[6] | (static_cast<size_t>(data[7]) << 8);
        size_t h = data[8] | (static_cast<size_t>(data[9]) << 8);
        return {w, h};
    }

    // BMP
    if (data[0] == 'B' && data[1] == 'M' && data.size() >= 26) {
        size_t w = data[18] | (static_cast<size_t>(data[19]) << 8) |
                   (static_cast<size_t>(data[20]) << 16) | (static_cast<size_t>(data[21]) << 24);
        size_t h = data[22] | (static_cast<size_t>(data[23]) << 8) |
                   (static_cast<size_t>(data[24]) << 16) | (static_cast<size_t>(data[25]) << 24);
        return {w, h};
    }

    // WebP (VP8/VP8L/VP8X)
    if (data.size() >= 30 &&
        data[0] == 'R' && data[1] == 'I' && data[2] == 'F' && data[3] == 'F' &&
        data[8] == 'W' && data[9] == 'E' && data[10] == 'B' && data[11] == 'P') {
        if (data[12] == 'V' && data[13] == 'P' && data[14] == '8' && data[15] == ' ') {
            // VP8 lossy
            if (data.size() >= 30) {
                size_t w = data[26] | (static_cast<size_t>(data[27]) << 8);
                size_t h = data[28] | (static_cast<size_t>(data[29]) << 8);
                return {w & 0x3FFF, h & 0x3FFF};
            }
        } else if (data[12] == 'V' && data[13] == 'P' && data[14] == '8' && data[15] == 'L') {
            // VP8L lossless
            if (data.size() >= 25) {
                uint32_t bits = data[21] | (static_cast<uint32_t>(data[22]) << 8) |
                                (static_cast<uint32_t>(data[23]) << 16) | (static_cast<uint32_t>(data[24]) << 24);
                size_t w = (bits & 0x3FFF) + 1;
                size_t h = ((bits >> 14) & 0x3FFF) + 1;
                return {w, h};
            }
        } else if (data[12] == 'V' && data[13] == 'P' && data[14] == '8' && data[15] == 'X') {
            // VP8X extended
            if (data.size() >= 30) {
                uint32_t w = data[24] | (static_cast<uint32_t>(data[25]) << 8) |
                             (static_cast<uint32_t>(data[26]) << 16);
                uint32_t h = data[27] | (static_cast<uint32_t>(data[28]) << 8) |
                             (static_cast<uint32_t>(data[29]) << 16);
                return {w + 1, h + 1};
            }
        }
    }

    return {0, 0};
}

// ============================================================================
// Special content type validation
// ============================================================================

static ScanResult validate_special_content_type(
    const std::vector<uint8_t>& header,
    const std::string& mime_type,
    const std::filesystem::path& file_path,
    size_t file_size)
{
    ScanResult result;
    result.status = ScanResult::Status::CLEAN;
    std::string mime_lower = to_lower(mime_type);

    // SVG sanitization
    if (mime_lower == "image/svg+xml") {
        if (file_size > DEFAULT_MAX_SVG_SIZE) {
            result.status = ScanResult::Status::SIZE_EXCEEDED;
            result.message = "SVG file too large: " + std::to_string(file_size) + " bytes";
            return result;
        }
        auto svg_result = sanitize_svg_file(file_path, header);
        if (svg_result.status != ScanResult::Status::CLEAN) return svg_result;
    }

    // PDF validation
    if (mime_lower == "application/pdf") {
        if (file_size > DEFAULT_MAX_PDF_SIZE) {
            result.status = ScanResult::Status::SIZE_EXCEEDED;
            result.message = "PDF file too large: " + std::to_string(file_size) + " bytes";
            return result;
        }
        auto pdf_result = validate_pdf_file(file_path, header);
        if (pdf_result.status != ScanResult::Status::CLEAN) return pdf_result;
    }

    // HTML sanitization
    if (mime_lower == "text/html") {
        if (file_size > DEFAULT_MAX_HTML_SIZE) {
            result.status = ScanResult::Status::SIZE_EXCEEDED;
            result.message = "HTML file too large: " + std::to_string(file_size) + " bytes";
            return result;
        }
        auto html_result = sanitize_html_file(file_path, header);
        if (html_result.status != ScanResult::Status::CLEAN) return html_result;
    }

    // Archive validation
    if (mime_lower == "application/zip" || mime_lower == "application/gzip" ||
        mime_lower == "application/x-tar" || mime_lower == "application/x-compressed-tar" ||
        mime_lower == "application/vnd.rar" || mime_lower == "application/x-7z-compressed" ||
        mime_lower == "application/x-bzip2") {
        auto archive_result = validate_archive(file_path, mime_lower);
        if (archive_result.status != ScanResult::Status::CLEAN) return archive_result;
    }

    return result;
}

static ScanResult validate_special_content_data(
    const std::vector<uint8_t>& data, const std::string& mime_type)
{
    ScanResult result;
    result.status = ScanResult::Status::CLEAN;
    result.file_size = data.size();
    std::string mime_lower = to_lower(mime_type);

    if (mime_lower == "image/svg+xml") {
        if (data.size() > DEFAULT_MAX_SVG_SIZE) {
            result.status = ScanResult::Status::SIZE_EXCEEDED;
            result.message = "SVG too large";
            return result;
        }
        return sanitize_svg_data(data);
    }

    if (mime_lower == "text/html") {
        if (data.size() > DEFAULT_MAX_HTML_SIZE) {
            result.status = ScanResult::Status::SIZE_EXCEEDED;
            result.message = "HTML too large";
            return result;
        }
        return sanitize_html_data(data);
    }

    if (mime_lower == "application/pdf") {
        if (data.size() > DEFAULT_MAX_PDF_SIZE) {
            result.status = ScanResult::Status::SIZE_EXCEEDED;
            result.message = "PDF too large";
            return result;
        }
        return validate_pdf_data(data);
    }

    return result;
}

// ============================================================================
// SVG Sanitization
// ============================================================================

static const std::unordered_set<std::string> SVG_DANGEROUS_ELEMENTS = {
    "script", "foreignObject", "use", "image",
    "iframe", "object", "embed", "video", "audio",
    "animate", "animateMotion", "animateTransform",
    "set", "handler", "listener",
};

static const std::unordered_set<std::string> SVG_DANGEROUS_ATTRIBUTES = {
    "onload", "onerror", "onclick", "onmouseover", "onmouseout",
    "onfocus", "onblur", "onchange", "onsubmit", "onreset",
    "onabort", "onkeydown", "onkeypress", "onkeyup",
    "ondblclick", "onmousedown", "onmousemove", "onmouseup",
    "onresize", "onscroll", "onunload", "onbegin", "onend",
    "onrepeat", "onactivate", "onfocusin", "onfocusout",
    "href", "xlink:href",
};

static std::string strip_svg_scripts(std::string_view svg_content) {
    std::string result;
    result.reserve(svg_content.size());

    bool in_tag = false;
    bool in_string = false;
    char string_char = 0;
    std::string current_tag;
    std::string current_attr;

    for (size_t i = 0; i < svg_content.size(); ++i) {
        char c = svg_content[i];

        if (in_string) {
            result += c;
            if (c == string_char && (i == 0 || svg_content[i-1] != '\\')) {
                in_string = false;
                string_char = 0;
            }
            continue;
        }

        if (c == '"' || c == '\'') {
            in_string = true;
            string_char = c;
            result += c;
            continue;
        }

        if (c == '<') {
            in_tag = true;
            current_tag.clear();
            result += c;

            // Check if this is a comment
            if (i + 3 < svg_content.size() &&
                svg_content[i+1] == '!' && svg_content[i+2] == '-' && svg_content[i+3] == '-') {
                // Skip until -->
                result += svg_content.substr(i+1, 3);
                i += 3;
                while (i + 2 < svg_content.size()) {
                    ++i;
                    result += svg_content[i];
                    if (svg_content[i] == '-' && svg_content[i+1] == '-' && svg_content[i+2] == '>') {
                        result += svg_content.substr(i+1, 2);
                        i += 2;
                        break;
                    }
                }
                in_tag = false;
                continue;
            }
            continue;
        }

        if (in_tag) {
            if (c == '>') {
                in_tag = false;
                // Check if current_tag is a dangerous element
                std::string tag_name;
                bool is_closing = false;
                size_t tag_start = 0;

                if (current_tag.size() > 0 && current_tag[0] == '/') {
                    is_closing = true;
                    tag_start = 1;
                }

                // Extract tag name (alphanumeric only)
                while (tag_start < current_tag.size() &&
                       (std::isalnum(static_cast<unsigned char>(current_tag[tag_start])) ||
                        current_tag[tag_start] == '_' || current_tag[tag_start] == '-')) {
                    tag_name += std::tolower(static_cast<unsigned char>(current_tag[tag_start]));
                    ++tag_start;
                }

                if (!tag_name.empty() && SVG_DANGEROUS_ELEMENTS.count(tag_name)) {
                    // Replace with empty tag
                    result.pop_back();
                    // Remove everything since the '<'
                    while (!result.empty() && result.back() != '<') result.pop_back();
                    if (!result.empty()) result.pop_back(); // Remove '<'
                    result += "<!-- removed dangerous element -->";
                } else {
                    result += c;
                }

                current_tag.clear();
                continue;
            }

            // Collect tag content
            current_tag += c;

            // Check for dangerous attributes within the tag
            // Only scan attributes, not tag name
            std::string attr_lower;
            bool in_attr_name = !std::isspace(static_cast<unsigned char>(c));
            if (in_attr_name) {
                current_attr += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            } else {
                current_attr.clear();
            }

            // Check if we've found a dangerous attribute
            if (!current_attr.empty()) {
                for (const auto& da : SVG_DANGEROUS_ATTRIBUTES) {
                    if (current_attr == da || current_attr.find(da) != std::string::npos) {
                        // Remove this attribute from current_tag
                        // Find start of attribute in current_tag
                        auto pos = current_tag.rfind(da);
                        if (pos != std::string::npos) {
                            // Remove everything back to '='
                            current_tag = current_tag.substr(0, pos);
                            // Also remove the value
                            current_attr.clear();
                            // We'll strip on output
                            result += current_tag;
                            current_tag.clear();
                            break;
                        }
                    }
                }
            }

            result += c;
            continue;
        }

        result += c;
    }

    return result;
}

static ScanResult sanitize_svg_file(const std::filesystem::path& path,
                                    const std::vector<uint8_t>& header)
{
    ScanResult result;
    result.status = ScanResult::Status::CLEAN;

    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file) {
        result.status = ScanResult::Status::ERROR;
        result.message = "Cannot read SVG file for sanitization";
        return result;
    }

    size_t size = file.tellg();
    file.seekg(0);
    std::string content(size, '\0');
    file.read(content.data(), size);

    // Check for dangerous content
    bool has_dangerous = false;
    std::string content_lower = to_lower(content);

    for (const auto& elem : SVG_DANGEROUS_ELEMENTS) {
        if (content_lower.find("<" + elem) != std::string::npos ||
            content_lower.find("</" + elem) != std::string::npos) {
            has_dangerous = true;
            break;
        }
    }

    if (!has_dangerous) {
        for (const auto& attr : SVG_DANGEROUS_ATTRIBUTES) {
            if (content_lower.find(attr + "=") != std::string::npos) {
                has_dangerous = true;
                break;
            }
        }
    }

    if (!has_dangerous) {
        // Check for javascript: URLs
        if (content_lower.find("javascript:") != std::string::npos) {
            has_dangerous = true;
        }
        // Check for data: URLs (could contain scripts)
        if (content_lower.find("data:text/html") != std::string::npos) {
            has_dangerous = true;
        }
    }

    if (has_dangerous) {
        std::string sanitized = strip_svg_scripts(content);
        // Write back
        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        if (!out) {
            result.status = ScanResult::Status::ERROR;
            result.message = "Cannot write sanitized SVG";
            return result;
        }
        out.write(sanitized.data(), sanitized.size());
        out.close();

        result.status = ScanResult::Status::SANITIZED;
        result.was_sanitized = true;
        result.message = "SVG sanitized: removed dangerous elements/attributes";
    }

    return result;
}

static ScanResult sanitize_svg_data(const std::vector<uint8_t>& data) {
    ScanResult result;
    result.status = ScanResult::Status::CLEAN;

    std::string content(reinterpret_cast<const char*>(data.data()), data.size());
    std::string content_lower = to_lower(content);

    bool has_dangerous = false;
    for (const auto& elem : SVG_DANGEROUS_ELEMENTS) {
        if (content_lower.find("<" + elem) != std::string::npos) {
            has_dangerous = true;
            break;
        }
    }

    if (!has_dangerous) {
        for (const auto& attr : SVG_DANGEROUS_ATTRIBUTES) {
            if (content_lower.find(attr + "=") != std::string::npos) {
                has_dangerous = true;
                break;
            }
        }
    }

    if (!has_dangerous) {
        if (content_lower.find("javascript:") != std::string::npos ||
            content_lower.find("data:text/html") != std::string::npos) {
            has_dangerous = true;
        }
    }

    if (has_dangerous) {
        result.status = ScanResult::Status::BLOCKED;
        result.message = "SVG contains dangerous elements that cannot be sanitized in-memory";
        return result;
    }

    return result;
}

// ============================================================================
// PDF Validation
// ============================================================================

static ScanResult validate_pdf_file(const std::filesystem::path& path,
                                    const std::vector<uint8_t>& header)
{
    ScanResult result;
    result.status = ScanResult::Status::CLEAN;

    // Read the full file looking for JavaScript
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file) {
        result.status = ScanResult::Status::ERROR;
        result.message = "Cannot read PDF for validation";
        return result;
    }

    size_t size = file.tellg();
    file.seekg(0);

    // Check file size
    if (size == 0) {
        result.status = ScanResult::Status::CORRUPTED;
        result.message = "Empty PDF file";
        return result;
    }

    // Read in chunks to look for dangerous patterns
    std::vector<char> buffer(std::min(size, DEFAULT_MAX_PDF_SIZE));
    file.read(buffer.data(), buffer.size());
    std::string_view content(buffer.data(), buffer.size());

    // Check for /JavaScript marker
    if (content.find("/JavaScript") != std::string::npos ||
        content.find("/JS") != std::string::npos) {
        result.status = ScanResult::Status::BLOCKED;
        result.message = "PDF contains embedded JavaScript";
        return result;
    }

    // Check for /Launch (can execute programs)
    if (content.find("/Launch") != std::string::npos) {
        result.status = ScanResult::Status::BLOCKED;
        result.message = "PDF contains /Launch action";
        return result;
    }

    // Check for /RichMedia
    if (content.find("/RichMedia") != std::string::npos) {
        result.status = ScanResult::Status::BLOCKED;
        result.message = "PDF contains embedded RichMedia";
        return result;
    }

    // Check for /EmbeddedFiles
    if (content.find("/EmbeddedFiles") != std::string::npos ||
        content.find("/EmbeddedFile") != std::string::npos) {
        result.status = ScanResult::Status::BLOCKED;
        result.message = "PDF contains embedded files";
        return result;
    }

    // Check for /XFA (XML Forms Architecture — can contain scripts)
    if (content.find("/XFA") != std::string::npos) {
        result.status = ScanResult::Status::BLOCKED;
        result.message = "PDF contains XFA forms";
        return result;
    }

    // Check for /OpenAction (auto-execute on open)
    if (content.find("/OpenAction") != std::string::npos) {
        result.status = ScanResult::Status::BLOCKED;
        result.message = "PDF contains /OpenAction auto-execute";
        return result;
    }

    // Check for /AA (Additional Actions)
    if (content.find("/AA") != std::string::npos) {
        result.status = ScanResult::Status::BLOCKED;
        result.message = "PDF contains additional actions (/AA)";
        return result;
    }

    // Check for /AcroForm (AcroForm can contain JS)
    bool has_acroform = content.find("/AcroForm") != std::string::npos;

    // Check for /ObjStm (object streams — opaque binary)
    if (content.find("/ObjStm") != std::string::npos) {
        // ObjStm alone isn't necessarily dangerous, but combined with
        // other indicators it's suspicious
    }

    // Basic structure validation
    bool has_trailer = content.find("trailer") != std::string::npos ||
                       content.find("startxref") != std::string::npos;

    if (!has_trailer && size < 1024) {
        // Very small files might be truncated — still valid PDF header
    }

    return result;
}

static ScanResult validate_pdf_data(const std::vector<uint8_t>& data) {
    ScanResult result;
    result.status = ScanResult::Status::CLEAN;

    if (data.empty()) {
        result.status = ScanResult::Status::CORRUPTED;
        result.message = "Empty PDF data";
        return result;
    }

    std::string_view content(reinterpret_cast<const char*>(data.data()), data.size());

    if (content.find("/JavaScript") != std::string::npos ||
        content.find("/JS") != std::string::npos) {
        result.status = ScanResult::Status::BLOCKED;
        result.message = "PDF contains embedded JavaScript";
        return result;
    }

    if (content.find("/Launch") != std::string::npos) {
        result.status = ScanResult::Status::BLOCKED;
        result.message = "PDF contains /Launch action";
        return result;
    }

    if (content.find("/RichMedia") != std::string::npos) {
        result.status = ScanResult::Status::BLOCKED;
        result.message = "PDF contains embedded RichMedia";
        return result;
    }

    if (content.find("/EmbeddedFiles") != std::string::npos ||
        content.find("/EmbeddedFile") != std::string::npos) {
        result.status = ScanResult::Status::BLOCKED;
        result.message = "PDF contains embedded files";
        return result;
    }

    if (content.find("/XFA") != std::string::npos) {
        result.status = ScanResult::Status::BLOCKED;
        result.message = "PDF contains XFA forms";
        return result;
    }

    if (content.find("/OpenAction") != std::string::npos) {
        result.status = ScanResult::Status::BLOCKED;
        result.message = "PDF contains /OpenAction";
        return result;
    }

    if (content.find("/AA") != std::string::npos) {
        result.status = ScanResult::Status::BLOCKED;
        result.message = "PDF contains additional actions (/AA)";
        return result;
    }

    return result;
}

// ============================================================================
// HTML Sanitization
// ============================================================================

static const std::unordered_set<std::string> HTML_DANGEROUS_ELEMENTS = {
    "script", "iframe", "object", "embed", "applet",
    "form", "input", "button", "textarea", "select",
    "link", "meta", "base", "frame", "frameset",
    "svg", "math", "video", "audio", "source",
    "track", "canvas",
};

static const std::unordered_set<std::string> HTML_DANGEROUS_ATTRIBUTES = {
    "onload", "onerror", "onclick", "onmouseover", "onmouseout",
    "onfocus", "onblur", "onchange", "onsubmit", "onreset",
    "onabort", "onkeydown", "onkeypress", "onkeyup",
    "ondblclick", "onmousedown", "onmousemove", "onmouseup",
    "onresize", "onscroll", "onunload", "onbeforeunload",
    "oncontextmenu", "ondrag", "ondragend", "ondragenter",
    "ondragleave", "ondragover", "ondragstart", "ondrop",
    "oninput", "oninvalid", "onsearch", "onselect",
    "ontoggle", "onwheel", "oncopy", "oncut", "onpaste",
};

static std::string sanitize_html_content(std::string_view html) {
    std::string result;
    result.reserve(html.size());

    bool in_tag = false;
    bool in_string = false;
    char string_char = 0;
    bool in_comment = false;
    std::string current_tag_name;
    std::string accumulated_tag;
    bool skip_this_tag = false;

    for (size_t i = 0; i < html.size(); ++i) {
        char c = html[i];

        if (in_comment) {
            result += c;
            if (c == '-' && i + 2 < html.size() &&
                html[i+1] == '-' && html[i+2] == '>') {
                result += html[i+1];
                result += html[i+2];
                i += 2;
                in_comment = false;
            }
            continue;
        }

        if (in_string) {
            result += c;
            if (c == string_char && (i == 0 || html[i-1] != '\\')) {
                in_string = false;
                string_char = 0;
            }
            continue;
        }

        if (c == '"' || c == '\'') {
            in_string = true;
            string_char = c;
            result += c;
            continue;
        }

        if (c == '<') {
            // Check for comment
            if (i + 3 < html.size() &&
                html[i+1] == '!' && html[i+2] == '-' && html[i+3] == '-') {
                in_comment = true;
                result += "<!--";
                i += 3;
                continue;
            }

            // Check for CDATA
            if (i + 8 < html.size() &&
                html.substr(i+1, 7) == "![CDATA[") {
                // Skip CDATA
                result += html[i];
                continue;
            }

            // Check for DOCTYPE
            if (i + 8 < html.size() &&
                (html.substr(i+1, 7) == "!DOCTYP" || html.substr(i+1, 7) == "!doctyp")) {
                // Pass through DOCTYPE
                result += '<';
                continue;
            }

            in_tag = true;
            current_tag_name.clear();
            accumulated_tag.clear();
            skip_this_tag = false;
            result += c;
            continue;
        }

        if (in_tag) {
            if (c == '>') {
                in_tag = false;

                if (skip_this_tag) {
                    // Remove the tag we accumulated
                    while (!result.empty() && result.back() != '<')
                        result.pop_back();
                    if (!result.empty()) result.pop_back();
                    result += "<!-- removed -->";
                    accumulated_tag.clear();
                    continue;
                }

                // Check accumulated tag for dangerous attributes
                std::string acc_lower = to_lower(accumulated_tag);
                bool has_dangerous_attr = false;
                for (const auto& attr : HTML_DANGEROUS_ATTRIBUTES) {
                    if (acc_lower.find(attr + "=") != std::string::npos ||
                        acc_lower.find(attr + " =") != std::string::npos) {
                        has_dangerous_attr = true;
                        break;
                    }
                }

                // Check for javascript: in any attribute
                if (acc_lower.find("javascript:") != std::string::npos) {
                    has_dangerous_attr = true;
                }

                if (has_dangerous_attr) {
                    while (!result.empty() && result.back() != '<')
                        result.pop_back();
                    if (!result.empty()) result.pop_back();
                    result += "<!-- removed -->";
                } else {
                    result += c;
                }

                accumulated_tag.clear();
                continue;
            }

            accumulated_tag += c;

            // Build tag name
            if (current_tag_name.empty() || !std::isspace(static_cast<unsigned char>(c))) {
                if (c == '/') {
                    // Closing tag
                    if (accumulated_tag.size() == 1) {
                        current_tag_name += '/';
                    }
                } else if (!std::isspace(static_cast<unsigned char>(c)) && current_tag_name.find('/') == 0) {
                    current_tag_name += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
                } else if (!std::isspace(static_cast<unsigned char>(c)) && current_tag_name.empty()) {
                    current_tag_name += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
                }
            }

            // Check if tag name matches dangerous elements
            if (!skip_this_tag && !current_tag_name.empty()) {
                std::string clean_tag = current_tag_name;
                if (!clean_tag.empty() && clean_tag[0] == '/')
                    clean_tag = clean_tag.substr(1);

                if (HTML_DANGEROUS_ELEMENTS.count(clean_tag)) {
                    skip_this_tag = true;
                }
            }

            result += c;
            continue;
        }

        result += c;
    }

    return result;
}

static ScanResult sanitize_html_file(const std::filesystem::path& path,
                                     const std::vector<uint8_t>& header)
{
    ScanResult result;
    result.status = ScanResult::Status::CLEAN;

    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file) {
        result.status = ScanResult::Status::ERROR;
        result.message = "Cannot read HTML for sanitization";
        return result;
    }

    size_t size = file.tellg();
    file.seekg(0);
    std::string content(size, '\0');
    file.read(content.data(), size);

    std::string content_lower = to_lower(content);
    bool needs_sanitization = false;

    // Check for dangerous elements
    for (const auto& elem : HTML_DANGEROUS_ELEMENTS) {
        if (content_lower.find("<" + elem) != std::string::npos ||
            content_lower.find("</" + elem) != std::string::npos) {
            needs_sanitization = true;
            break;
        }
    }

    // Check for event handlers
    if (!needs_sanitization) {
        for (const auto& attr : HTML_DANGEROUS_ATTRIBUTES) {
            if (content_lower.find(attr + "=") != std::string::npos) {
                needs_sanitization = true;
                break;
            }
        }
    }

    // Check for javascript: URLs
    if (!needs_sanitization && content_lower.find("javascript:") != std::string::npos) {
        needs_sanitization = true;
    }

    if (needs_sanitization) {
        std::string sanitized = sanitize_html_content(content);
        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        if (!out) {
            result.status = ScanResult::Status::ERROR;
            result.message = "Cannot write sanitized HTML";
            return result;
        }
        out.write(sanitized.data(), sanitized.size());
        out.close();

        result.status = ScanResult::Status::SANITIZED;
        result.was_sanitized = true;
        result.message = "HTML sanitized: removed scripts, iframes, and dangerous attributes";
    }

    return result;
}

static ScanResult sanitize_html_data(const std::vector<uint8_t>& data) {
    ScanResult result;
    result.status = ScanResult::Status::CLEAN;

    std::string content(reinterpret_cast<const char*>(data.data()), data.size());
    std::string content_lower = to_lower(content);
    bool needs_sanitization = false;

    for (const auto& elem : HTML_DANGEROUS_ELEMENTS) {
        if (content_lower.find("<" + elem) != std::string::npos) {
            needs_sanitization = true;
            break;
        }
    }

    if (!needs_sanitization) {
        for (const auto& attr : HTML_DANGEROUS_ATTRIBUTES) {
            if (content_lower.find(attr + "=") != std::string::npos) {
                needs_sanitization = true;
                break;
            }
        }
    }

    if (!needs_sanitization && content_lower.find("javascript:") != std::string::npos) {
        needs_sanitization = true;
    }

    if (needs_sanitization) {
        result.status = ScanResult::Status::BLOCKED;
        result.message = "HTML contains dangerous elements";
    }

    return result;
}

// ============================================================================
// Archive bomb / encrypted detection
// ============================================================================

static ScanResult validate_archive(const std::filesystem::path& path,
                                   const std::string& mime_type)
{
    ScanResult result;
    result.status = ScanResult::Status::CLEAN;

    std::string mime_lower = to_lower(mime_type);

    // Check file size before deeper inspection
    std::error_code ec;
    auto file_size = std::filesystem::file_size(path, ec);
    if (ec) {
        result.status = ScanResult::Status::ERROR;
        result.message = "Cannot read archive file";
        return result;
    }

    if (file_size > DEFAULT_MAX_ARCHIVE_SIZE) {
        result.status = ScanResult::Status::SIZE_EXCEEDED;
        result.message = "Archive exceeds maximum size: " + std::to_string(file_size) + " bytes";
        return result;
    }

    if (mime_lower == "application/zip") {
        return validate_zip_archive(path);
    }

    if (mime_lower == "application/gzip") {
        return validate_gzip_archive(path);
    }

    if (mime_lower == "application/x-tar" || mime_lower == "application/x-compressed-tar") {
        return validate_tar_archive(path);
    }

    // For other archive types, do basic checks
    // Check compression ratio (file size vs header-reported uncompressed size)
    // This is a heuristic for archive bombs

    return result;
}

static ScanResult validate_zip_archive(const std::filesystem::path& path) {
    ScanResult result;
    result.status = ScanResult::Status::CLEAN;

    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file) {
        result.status = ScanResult::Status::ERROR;
        result.message = "Cannot open ZIP archive";
        return result;
    }

    size_t file_size = file.tellg();
    file.seekg(0);

    // Read EOCD (End of Central Directory) record
    // EOCD signature: 0x50 0x4B 0x05 0x06
    // Minimum EOCD size is 22 bytes
    std::vector<uint8_t> eocd_buf(std::min(file_size, size_t(65557))); // Max comment size + EOCD
    file.seekg(file_size - eocd_buf.size());
    file.read(reinterpret_cast<char*>(eocd_buf.data()), eocd_buf.size());

    // Search for EOCD signature
    bool found_eocd = false;
    size_t eocd_offset = 0;
    int64_t total_entries = 0;
    uint64_t cd_size = 0;
    uint64_t cd_offset = 0;
    bool encrypted = false;

    for (size_t i = 0; i + 22 <= eocd_buf.size(); ++i) {
        if (eocd_buf[i] == 0x50 && eocd_buf[i+1] == 0x4B &&
            eocd_buf[i+2] == 0x05 && eocd_buf[i+3] == 0x06) {
            found_eocd = true;
            eocd_offset = (file_size - eocd_buf.size()) + i;

            // Read entry counts
            total_entries = eocd_buf[i+8] | (eocd_buf[i+9] << 8) |
                            (eocd_buf[i+10] << 16) | (eocd_buf[i+11] << 24);
            cd_size = eocd_buf[i+12] | (static_cast<uint64_t>(eocd_buf[i+13]) << 8) |
                      (static_cast<uint64_t>(eocd_buf[i+14]) << 16) | (static_cast<uint64_t>(eocd_buf[i+15]) << 24);
            cd_offset = eocd_buf[i+16] | (static_cast<uint64_t>(eocd_buf[i+17]) << 8) |
                        (static_cast<uint64_t>(eocd_buf[i+18]) << 16) | (static_cast<uint64_t>(eocd_buf[i+19]) << 24);

            break;
        }
    }

    if (!found_eocd) {
        result.status = ScanResult::Status::CORRUPTED;
        result.message = "Invalid ZIP archive: missing end-of-central-directory";
        return result;
    }

    // Check for excessive entries (ZIP bomb indicator)
    if (total_entries > static_cast<int64_t>(DEFAULT_ARCHIVE_MAX_ENTRIES)) {
        result.status = ScanResult::Status::ARCHIVE_BOMB;
        result.message = "ZIP archive contains " + std::to_string(total_entries) +
            " entries, exceeding limit of " + std::to_string(DEFAULT_ARCHIVE_MAX_ENTRIES);
        return result;
    }

    // Check compression ratio
    if (file_size > 0 && cd_size > 0) {
        double ratio = static_cast<double>(cd_size) / static_cast<double>(file_size);
        if (ratio > DEFAULT_ARCHIVE_COMPRESSION_RATIO) {
            result.status = ScanResult::Status::ARCHIVE_BOMB;
            result.message = "Suspicious compression ratio: " + std::to_string(ratio) + ":1";
            return result;
        }
    }

    // Check if any entry is encrypted
    // Read central directory entries
    file.seekg(cd_offset);
    std::vector<uint8_t> cd_data(cd_size);
    file.read(reinterpret_cast<char*>(cd_data.data()), cd_size);

    size_t pos = 0;
    int64_t entries_checked = 0;
    while (pos + 46 <= cd_data.size() && entries_checked < total_entries) {
        // Central directory file header signature: 0x50 0x4B 0x01 0x02
        if (cd_data[pos] == 0x50 && cd_data[pos+1] == 0x4B &&
            cd_data[pos+2] == 0x01 && cd_data[pos+3] == 0x02) {

            // General purpose bit flag at offset 8 (2 bytes)
            uint16_t gp_flag = cd_data[pos+8] | (cd_data[pos+9] << 8);

            // Bit 0: encrypted
            if (gp_flag & 0x01) {
                encrypted = true;
                break;
            }

            // Compression method at offset 10
            uint16_t comp_method = cd_data[pos+10] | (cd_data[pos+11] << 8);
            // Method 99 = AES encrypted
            if (comp_method == 99) {
                encrypted = true;
                break;
            }

            // Get lengths
            uint16_t filename_len = cd_data[pos+28] | (cd_data[pos+29] << 8);
            uint16_t extra_len = cd_data[pos+30] | (cd_data[pos+31] << 8);
            uint16_t comment_len = cd_data[pos+32] | (cd_data[pos+33] << 8);

            pos += 46 + filename_len + extra_len + comment_len;
            ++entries_checked;
        } else {
            break; // Invalid entry
        }
    }

    if (encrypted) {
        result.status = ScanResult::Status::ENCRYPTED;
        result.message = "ZIP archive contains encrypted/password-protected entries";
        return result;
    }

    return result;
}

static ScanResult validate_gzip_archive(const std::filesystem::path& path) {
    ScanResult result;
    result.status = ScanResult::Status::CLEAN;

    std::ifstream file(path, std::ios::binary);
    if (!file) {
        result.status = ScanResult::Status::ERROR;
        result.message = "Cannot open GZip archive";
        return result;
    }

    // Read GZip header
    uint8_t header[10];
    file.read(reinterpret_cast<char*>(header), 10);

    if (header[0] != 0x1F || header[1] != 0x8B) {
        result.status = ScanResult::Status::CORRUPTED;
        result.message = "Invalid GZip header";
        return result;
    }

    // Check if encrypted (bit 5 of FLG is reserved/encrypted)
    uint8_t flg = header[3];
    if (flg & 0x20) {
        result.status = ScanResult::Status::ENCRYPTED;
        result.message = "GZip archive appears to be encrypted";
        return result;
    }

    // Read ISIZE (last 4 bytes of file) for compression ratio check
    file.seekg(-4, std::ios::end);
    uint8_t isize_bytes[4];
    file.read(reinterpret_cast<char*>(isize_bytes), 4);
    uint32_t uncompressed_size = isize_bytes[0] | (static_cast<uint32_t>(isize_bytes[1]) << 8) |
                                 (static_cast<uint32_t>(isize_bytes[2]) << 16) | (static_cast<uint32_t>(isize_bytes[3]) << 24);

    auto file_size = std::filesystem::file_size(path);
    if (file_size > 0 && uncompressed_size > 0) {
        double ratio = static_cast<double>(uncompressed_size) / static_cast<double>(file_size);
        if (ratio > DEFAULT_ARCHIVE_COMPRESSION_RATIO) {
            result.status = ScanResult::Status::ARCHIVE_BOMB;
            result.message = "Suspicious GZip compression ratio: " + std::to_string(ratio) + ":1";
            return result;
        }
    }

    // Check uncompressed size
    if (uncompressed_size > DEFAULT_ARCHIVE_MAX_UNCOMPRESSED) {
        result.status = ScanResult::Status::ARCHIVE_BOMB;
        result.message = "GZip uncompressed size " + std::to_string(uncompressed_size) +
            " exceeds maximum " + std::to_string(DEFAULT_ARCHIVE_MAX_UNCOMPRESSED);
        return result;
    }

    return result;
}

static ScanResult validate_tar_archive(const std::filesystem::path& path) {
    ScanResult result;
    result.status = ScanResult::Status::CLEAN;

    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file) {
        result.status = ScanResult::Status::ERROR;
        result.message = "Cannot open TAR archive";
        return result;
    }

    size_t file_size = file.tellg();
    file.seekg(0);

    // Read and count entries
    size_t entries = 0;
    size_t total_uncompressed = 0;
    uint8_t block[512];

    while (file.read(reinterpret_cast<char*>(block), 512)) {
        // Check for end-of-archive (two zero blocks)
        bool all_zero = true;
        for (int i = 0; i < 512; ++i) {
            if (block[i] != 0) { all_zero = false; break; }
        }
        if (all_zero) break;

        ++entries;
        if (entries > DEFAULT_ARCHIVE_MAX_ENTRIES) {
            result.status = ScanResult::Status::ARCHIVE_BOMB;
            result.message = "TAR archive contains too many entries: " +
                std::to_string(entries);
            return result;
        }

        // Get file size (12-byte octal at offset 124)
        char size_str[13] = {0};
        memcpy(size_str, block + 124, 12);
        uint64_t entry_size = 0;
        try {
            entry_size = std::stoull(std::string(size_str), nullptr, 8);
        } catch (...) {
            entry_size = 0;
        }

        total_uncompressed += entry_size;
        if (total_uncompressed > DEFAULT_ARCHIVE_MAX_UNCOMPRESSED) {
            result.status = ScanResult::Status::ARCHIVE_BOMB;
            result.message = "TAR archive extracted size exceeds maximum";
            return result;
        }

        // Skip past the file content
        size_t blocks_to_skip = (entry_size + 511) / 512;
        file.seekg(blocks_to_skip * 512, std::ios::cur);
    }

    // Check compression ratio for compressed tars (.tar.gz)
    if (file_size > 0 && total_uncompressed > 0) {
        double ratio = static_cast<double>(total_uncompressed) / static_cast<double>(file_size);
        if (ratio > DEFAULT_ARCHIVE_COMPRESSION_RATIO) {
            result.status = ScanResult::Status::ARCHIVE_BOMB;
            result.message = "Suspicious TAR compression ratio: " + std::to_string(ratio) + ":1";
            return result;
        }
    }

    return result;
}

// ============================================================================
// EXIF Stripping
// ============================================================================

static bool strip_exif_from_file(const std::filesystem::path& path) {
    // Read file
    std::ifstream in(path, std::ios::binary | std::ios::ate);
    if (!in) return false;

    size_t size = in.tellg();
    in.seekg(0);
    std::vector<uint8_t> data(size);
    in.read(reinterpret_cast<char*>(data.data()), size);
    in.close();

    // Check if it's JPEG
    if (data.size() < 4 || data[0] != 0xFF || data[1] != 0xD8) return false;

    // Find APP1 (EXIF) marker
    bool has_exif = false;
    for (size_t i = 2; i + 4 <= data.size();) {
        if (data[i] != 0xFF) break;
        uint8_t marker = data[i + 1];
        if (marker == 0xDA || marker == 0xD9) break; // SOS or EOI

        if (marker == 0xE1) {
            // APP1 marker (EXIF)
            has_exif = true;
            uint16_t seg_len = (data[i + 2] << 8) | data[i + 3];
            size_t seg_start = i;
            size_t seg_end = i + 2 + seg_len;

            if (seg_end <= data.size()) {
                // Remove this segment
                data.erase(data.begin() + seg_start, data.begin() + seg_end);
                break; // Only strip first EXIF
            } else {
                break;
            }
        } else {
            if (marker == 0xD8 || marker == 0x00) {
                ++i;
                continue;
            }
            if (i + 2 >= data.size()) break;
            uint16_t seg_len = (data[i + 2] << 8) | data[i + 3];
            i += 2 + seg_len;
        }
    }

    if (has_exif) {
        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        if (!out) return false;
        out.write(reinterpret_cast<const char*>(data.data()), data.size());
        out.close();
        return true;
    }

    return false;
}

// ============================================================================
// Thumbnail Generation Safety (ImageTragick prevention)
// ============================================================================

// Probes for known ImageMagick/ImageTragick exploit patterns
static bool detect_imagetragick_exploit(const std::vector<uint8_t>& data) {
    if (data.size() < 4) return false;

    // Check for MVG/MSL/SVG content disguised in image headers
    std::string_view view(reinterpret_cast<const char*>(data.data()),
                          std::min(data.size(), size_t(512)));

    // MSL (Magick Scripting Language) embedded in comment
    if (view.find("<msl") != std::string::npos ||
        view.find("<image") != std::string::npos) {
        return true;
    }

    // MVG (Magick Vector Graphics) content
    if (view.find("push graphic-context") != std::string::npos) {
        return true;
    }

    // URL-based delegates
    if (view.find("https://") != std::string::npos ||
        view.find("http://") != std::string::npos ||
        view.find("ftp://") != std::string::npos) {

        // Check if this is in a context that could be interpreted as a delegate
        std::string lower;
        lower.reserve(view.size());
        for (char c : view) lower += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

        if (lower.find("|") != std::string::npos ||
            lower.find("`") != std::string::npos ||
            lower.find("$(") != std::string::npos ||
            lower.find("&&") != std::string::npos ||
            lower.find(";") != std::string::npos) {
            return true;
        }
    }

    // Shell injection patterns
    std::string lower;
    lower.reserve(view.size());
    for (char c : view) lower += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

    if (lower.find("|") != std::string::npos ||
        lower.find("$((") != std::string::npos ||
        lower.find("`") != std::string::npos) {
        return true;
    }

    return false;
}

// Check if the file is safe for thumbnail generation
static bool is_safe_for_thumbnail(const std::string& mime_type, size_t file_size) {
    if (mime_type == "image/svg+xml") return false;  // SVG can be dangerous
    if (mime_type == "application/pdf") return false;
    if (mime_type == "text/html") return false;

    // Size limits for thumbnailing
    if (file_size > DEFAULT_MAX_IMAGE_SIZE) return false;

    return true;
}

static ScanResult check_thumbnail_safety(const std::filesystem::path& path,
                                         const std::string& mime_type,
                                         size_t file_size)
{
    ScanResult result;
    result.status = ScanResult::Status::CLEAN;

    if (!is_safe_for_thumbnail(mime_type, file_size)) {
        result.status = ScanResult::Status::BLOCKED;
        result.message = "File type not safe for thumbnail generation";
        return result;
    }

    // Read header to check for ImageTragick exploits
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        result.status = ScanResult::Status::ERROR;
        result.message = "Cannot read file for thumbnail safety check";
        return result;
    }

    std::vector<uint8_t> header(4096);
    file.read(reinterpret_cast<char*>(header.data()), header.size());
    header.resize(file.gcount());

    if (detect_imagetragick_exploit(header)) {
        result.status = ScanResult::Status::BLOCKED;
        result.message = "Potential ImageTragick exploit detected";
        return result;
    }

    return result;
}

// ============================================================================
// ContentScanner — Main Interface
// ============================================================================

class ContentScannerImpl {
public:
    struct Config {
        std::string clamd_socket_path = "/var/run/clamav/clamd.ctl";
        bool clamd_enabled = true;
        size_t clamd_timeout_secs = DEFAULT_CLAMD_TIMEOUT_SECONDS;
        std::string quarantine_dir;
        size_t max_attachment_size = DEFAULT_MAX_ATTACHMENT_SIZE;
        size_t max_image_size = DEFAULT_MAX_IMAGE_SIZE;
        size_t max_video_size = DEFAULT_MAX_VIDEO_SIZE;
        size_t max_audio_size = DEFAULT_MAX_AUDIO_SIZE;
        size_t max_other_size = DEFAULT_MAX_OTHER_SIZE;
        size_t max_image_width = DEFAULT_MAX_IMAGE_WIDTH;
        size_t max_image_height = DEFAULT_MAX_IMAGE_HEIGHT;
        size_t max_image_pixels = DEFAULT_MAX_IMAGE_PIXELS;
        size_t max_thumbnail_width = DEFAULT_MAX_THUMB_WIDTH;
        size_t max_thumbnail_height = DEFAULT_MAX_THUMB_HEIGHT;
        size_t scan_cache_size = DEFAULT_SCAN_CACHE_SIZE;
        size_t scan_cache_ttl = DEFAULT_SCAN_CACHE_TTL_SECONDS;
        size_t quarantine_max_age = DEFAULT_QUARANTINE_MAX_AGE;
        size_t queue_size = DEFAULT_SCAN_QUEUE_SIZE;
        size_t worker_threads = DEFAULT_SCAN_WORKER_THREADS;
        bool enable_svg_sanitization = true;
        bool enable_pdf_validation = true;
        bool enable_html_sanitization = true;
        bool enable_archive_validation = true;
        bool enable_exif_stripping = true;
        bool enable_thumbnail_safety = true;
    };

    explicit ContentScannerImpl(Config config)
        : config_(std::move(config))
        , metrics_()
        , scan_cache_(config_.scan_cache_size, config_.scan_cache_ttl)
        , quarantine_(config_.quarantine_dir)
        , scan_queue_(config_.queue_size)
    {
        // Initialize ClamAV connection
        if (config_.clamd_enabled && !config_.clamd_socket_path.empty()) {
            clamd_conn_ = std::make_unique<ClamdConnection>(
                config_.clamd_socket_path, config_.clamd_timeout_secs);
            if (!clamd_conn_->connect()) {
                std::cerr << "[ContentScanner] Warning: Failed to connect to clamd at "
                          << config_.clamd_socket_path << std::endl;
                clamd_conn_.reset();
            } else {
                std::string version = clamd_conn_->version();
                std::cerr << "[ContentScanner] Connected to ClamAV: " << version << std::endl;
            }
        }

        // Start async workers (even without clamd, they handle other checks)
        scan_queue_.start_workers(&metrics_,
            clamd_conn_.get(),
            &scan_cache_,
            &quarantine_,
            config_.worker_threads);
    }

    ~ContentScannerImpl() {
        scan_queue_.stop();
        if (clamd_conn_) clamd_conn_->disconnect();
    }

    // ========================================================================
    // Synchronous scan of a file
    // ========================================================================
    ScanResult scan_file_sync(const std::string& file_path,
                              const std::string& claimed_mime = "",
                              const std::string& original_filename = "")
    {
        auto start = std::chrono::steady_clock::now();

        // Compute hash for cache lookup
        std::string file_hash = sha256_file(file_path);
        if (!file_hash.empty()) {
            auto cached = scan_cache_.get(file_hash);
            if (cached) {
                metrics_.record_cache_hit();
                auto end = std::chrono::steady_clock::now();
                auto result = *cached;
                result.scan_duration_ms = std::chrono::duration<double, std::milli>(end - start).count();
                return result;
            }
            metrics_.record_cache_miss();
        }

        // Perform scan
        ScanResult result;
        result.claimed_mime = claimed_mime;
        result.original_file_path = file_path;
        result.file_hash = file_hash;

        std::error_code ec;
        auto file_size = std::filesystem::file_size(file_path, ec);
        if (ec) {
            result.status = ScanResult::Status::ERROR;
            result.message = "Cannot read file: " + ec.message();
            metrics_.record_scan(result);
            return result;
        }
        result.file_size = file_size;

        // Extract extension
        std::string filename = original_filename.empty() ?
            extract_filename(file_path) : original_filename;
        result.file_extension = extract_extension(filename);

        // Step 1: Extension validation
        if (!result.file_extension.empty() &&
            BLOCKED_EXTENSIONS.count(to_lower(result.file_extension))) {
            result.status = ScanResult::Status::DANGEROUS_EXTENSION;
            result.message = "Blocked file extension: " + result.file_extension;
            quarantine_file(file_path, result);
            auto end = std::chrono::steady_clock::now();
            result.scan_duration_ms = std::chrono::duration<double, std::milli>(end - start).count();
            scan_cache_.put(file_hash, result);
            metrics_.record_scan(result);
            return result;
        }

        // Step 2: Size check
        size_t max_size = get_max_size_for_type(claimed_mime);
        if (file_size > max_size) {
            result.status = ScanResult::Status::SIZE_EXCEEDED;
            result.message = "File size " + std::to_string(file_size) +
                " exceeds maximum " + std::to_string(max_size);
            auto end = std::chrono::steady_clock::now();
            result.scan_duration_ms = std::chrono::duration<double, std::milli>(end - start).count();
            metrics_.record_scan(result);
            return result;
        }

        // Step 3: Detect MIME from magic
        result.detected_mime = detect_mime_from_file(file_path);

        // Step 4: MIME validation
        if (!claimed_mime.empty() && !validate_mime_match(result.detected_mime, claimed_mime)) {
            result.status = ScanResult::Status::INVALID_TYPE;
            result.message = "MIME type mismatch: detected " + result.detected_mime +
                ", claimed " + claimed_mime;
            quarantine_file(file_path, result);
            auto end = std::chrono::steady_clock::now();
            result.scan_duration_ms = std::chrono::duration<double, std::milli>(end - start).count();
            scan_cache_.put(file_hash, result);
            metrics_.record_scan(result);
            return result;
        }

        // Step 5: Special content validation
        std::vector<uint8_t> header(512);
        {
            std::ifstream f(file_path, std::ios::binary);
            if (f) {
                f.read(reinterpret_cast<char*>(header.data()), header.size());
                header.resize(f.gcount());
            }
        }

        auto special = validate_special_content_type(header, result.detected_mime,
                                                      file_path, file_size);
        if (special.status == ScanResult::Status::BLOCKED ||
            special.status == ScanResult::Status::ARCHIVE_BOMB ||
            special.status == ScanResult::Status::ENCRYPTED) {
            result.status = special.status;
            result.message = special.message;
            quarantine_file(file_path, result);
            auto end = std::chrono::steady_clock::now();
            result.scan_duration_ms = std::chrono::duration<double, std::milli>(end - start).count();
            scan_cache_.put(file_hash, result);
            metrics_.record_scan(result);
            return result;
        }
        if (special.status == ScanResult::Status::SANITIZED) {
            result.was_sanitized = true;
        }

        // Step 6: Image dimension check
        if (ALLOWED_IMAGE_TYPES.count(result.detected_mime) &&
            result.detected_mime != "image/svg+xml") {
            auto dims = detect_image_dimensions(file_path, header);
            if (dims.first > config_.max_image_width ||
                dims.second > config_.max_image_height) {
                result.status = ScanResult::Status::SIZE_EXCEEDED;
                result.message = "Image dimensions " + std::to_string(dims.first) + "x" +
                    std::to_string(dims.second) + " exceed maximum";
                auto end = std::chrono::steady_clock::now();
                result.scan_duration_ms = std::chrono::duration<double, std::milli>(end - start).count();
                metrics_.record_scan(result);
                return result;
            }
            if (dims.first * dims.second > config_.max_image_pixels) {
                result.status = ScanResult::Status::SIZE_EXCEEDED;
                result.message = "Image pixel count exceeds maximum";
                auto end = std::chrono::steady_clock::now();
                result.scan_duration_ms = std::chrono::duration<double, std::milli>(end - start).count();
                metrics_.record_scan(result);
                return result;
            }
        }

        // Step 7: EXIF stripping
        if (config_.enable_exif_stripping &&
            result.detected_mime == "image/jpeg" && !result.was_sanitized) {
            if (strip_exif_from_file(file_path)) {
                result.was_sanitized = true;
            }
        }

        // Step 8: ClamAV scan
        if (clamd_conn_ && clamd_conn_->is_connected()) {
            std::string resp = clamd_conn_->scan_file(file_path);
            std::string virus_name;
            if (parse_scan_result(resp, virus_name)) {
                result.status = ScanResult::Status::INFECTED;
                result.virus_name = virus_name;
                result.message = "Virus detected: " + virus_name;
                quarantine_file(file_path, result);
                auto end = std::chrono::steady_clock::now();
                result.scan_duration_ms = std::chrono::duration<double, std::milli>(end - start).count();
                scan_cache_.put(file_hash, result);
                metrics_.record_scan(result);
                return result;
            }
            if (resp.find("ERROR") != std::string::npos) {
                metrics_.record_clamd_error();
            }
        }

        result.status = result.was_sanitized ?
            ScanResult::Status::SANITIZED : ScanResult::Status::CLEAN;
        result.message = result.was_sanitized ?
            "File scanned and sanitized" : "File clean";

        auto end = std::chrono::steady_clock::now();
        result.scan_duration_ms = std::chrono::duration<double, std::milli>(end - start).count();
        scan_cache_.put(file_hash, result);
        metrics_.record_scan(result);
        return result;
    }

    // ========================================================================
    // Synchronous scan of in-memory data
    // ========================================================================
    ScanResult scan_data_sync(const std::vector<uint8_t>& data,
                              const std::string& claimed_mime = "",
                              const std::string& original_filename = "")
    {
        auto start = std::chrono::steady_clock::now();

        std::string file_hash = sha256_hex(std::string_view(
            reinterpret_cast<const char*>(data.data()), data.size()));

        if (!file_hash.empty()) {
            auto cached = scan_cache_.get(file_hash);
            if (cached) {
                metrics_.record_cache_hit();
                auto end = std::chrono::steady_clock::now();
                auto result = *cached;
                result.scan_duration_ms = std::chrono::duration<double, std::milli>(end - start).count();
                return result;
            }
            metrics_.record_cache_miss();
        }

        ScanResult result;
        result.claimed_mime = claimed_mime;
        result.file_hash = file_hash;
        result.file_size = data.size();
        result.file_extension = extract_extension(original_filename);

        // Extension check
        if (!result.file_extension.empty() &&
            BLOCKED_EXTENSIONS.count(to_lower(result.file_extension))) {
            result.status = ScanResult::Status::DANGEROUS_EXTENSION;
            result.message = "Blocked extension: " + result.file_extension;
            auto end = std::chrono::steady_clock::now();
            result.scan_duration_ms = std::chrono::duration<double, std::milli>(end - start).count();
            scan_cache_.put(file_hash, result);
            metrics_.record_scan(result);
            return result;
        }

        // Size check
        size_t max_size = get_max_size_for_type(claimed_mime);
        if (data.size() > max_size) {
            result.status = ScanResult::Status::SIZE_EXCEEDED;
            result.message = "Data exceeds size limit";
            auto end = std::chrono::steady_clock::now();
            result.scan_duration_ms = std::chrono::duration<double, std::milli>(end - start).count();
            metrics_.record_scan(result);
            return result;
        }

        // Magic detection
        result.detected_mime = detect_magic_mime(data);

        // MIME validation
        if (!claimed_mime.empty() && !validate_mime_match(result.detected_mime, claimed_mime)) {
            result.status = ScanResult::Status::INVALID_TYPE;
            result.message = "MIME mismatch";
            auto end = std::chrono::steady_clock::now();
            result.scan_duration_ms = std::chrono::duration<double, std::milli>(end - start).count();
            scan_cache_.put(file_hash, result);
            metrics_.record_scan(result);
            return result;
        }

        // Special content validation
        auto special = validate_special_content_data(data, result.detected_mime);
        if (special.status != ScanResult::Status::CLEAN) {
            auto end = std::chrono::steady_clock::now();
            special.scan_duration_ms = std::chrono::duration<double, std::milli>(end - start).count();
            special.file_hash = file_hash;
            special.claimed_mime = claimed_mime;
            special.file_size = data.size();
            scan_cache_.put(file_hash, special);
            metrics_.record_scan(special);
            return special;
        }

        // Image dimensions
        if (ALLOWED_IMAGE_TYPES.count(result.detected_mime) &&
            result.detected_mime != "image/svg+xml") {
            auto dims = detect_image_dimensions_from_data(data);
            if (dims.first > config_.max_image_width ||
                dims.second > config_.max_image_height ||
                dims.first * dims.second > config_.max_image_pixels) {
                result.status = ScanResult::Status::SIZE_EXCEEDED;
                result.message = "Image dimensions exceed limits";
                auto end = std::chrono::steady_clock::now();
                result.scan_duration_ms = std::chrono::duration<double, std::milli>(end - start).count();
                metrics_.record_scan(result);
                return result;
            }
        }

        // ClamAV scan
        if (clamd_conn_ && clamd_conn_->is_connected()) {
            std::string resp = clamd_conn_->scan_stream(data);
            std::string virus_name;
            if (parse_scan_result(resp, virus_name)) {
                result.status = ScanResult::Status::INFECTED;
                result.virus_name = virus_name;
                result.message = "Virus detected: " + virus_name;
                auto end = std::chrono::steady_clock::now();
                result.scan_duration_ms = std::chrono::duration<double, std::milli>(end - start).count();
                scan_cache_.put(file_hash, result);
                metrics_.record_scan(result);
                return result;
            }
            if (resp.find("ERROR") != std::string::npos) {
                metrics_.record_clamd_error();
            }
        }

        result.status = ScanResult::Status::CLEAN;
        result.message = "Data clean";

        auto end = std::chrono::steady_clock::now();
        result.scan_duration_ms = std::chrono::duration<double, std::milli>(end - start).count();
        scan_cache_.put(file_hash, result);
        metrics_.record_scan(result);
        return result;
    }

    // ========================================================================
    // Async scan (enqueue a job)
    // ========================================================================
    bool scan_file_async(const std::string& file_path,
                         ScanCallback callback,
                         const std::string& claimed_mime = "",
                         const std::string& original_filename = "",
                         int priority = 0)
    {
        ScanJob job;
        job.job_id = sha256_hex(file_path).substr(0, 16);
        job.file_path = file_path;
        job.claimed_mime = claimed_mime;
        job.original_filename = original_filename;
        job.callback = std::move(callback);
        job.is_file = true;
        job.priority = priority;
        job.enqueue_time = std::chrono::system_clock::now();
        return scan_queue_.enqueue(job);
    }

    bool scan_data_async(const std::vector<uint8_t>& data,
                         ScanCallback callback,
                         const std::string& claimed_mime = "",
                         const std::string& original_filename = "",
                         int priority = 0)
    {
        ScanJob job;
        job.job_id = md5_hex(data).substr(0, 16);
        job.data = data;
        job.claimed_mime = claimed_mime;
        job.original_filename = original_filename;
        job.callback = std::move(callback);
        job.is_file = false;
        job.priority = priority;
        job.enqueue_time = std::chrono::system_clock::now();
        return scan_queue_.enqueue(job);
    }

    // ========================================================================
    // Thumbnail safety check
    // ========================================================================
    ScanResult check_thumbnail_safety_sync(const std::string& file_path,
                                           const std::string& mime_type,
                                           size_t file_size)
    {
        if (!config_.enable_thumbnail_safety) {
            ScanResult r;
            r.status = ScanResult::Status::CLEAN;
            r.message = "Thumbnail safety checks disabled";
            return r;
        }
        return check_thumbnail_safety(file_path, mime_type, file_size);
    }

    // ========================================================================
    // Quarantine operations
    // ========================================================================
    bool restore_quarantined(const std::string& file_hash) {
        return quarantine_.restore_entry(file_hash);
    }

    bool delete_quarantined(const std::string& file_hash) {
        return quarantine_.delete_entry(file_hash);
    }

    nlohmann::json list_quarantined() const {
        return quarantine_.to_json();
    }

    size_t clean_quarantine(size_t max_age_seconds) {
        return quarantine_.clean_old_entries(max_age_seconds);
    }

    size_t quarantine_count() const {
        return quarantine_.entry_count();
    }

    // ========================================================================
    // Cache operations
    // ========================================================================
    void clear_cache() {
        scan_cache_.clear();
    }

    void clean_cache() {
        scan_cache_.clean_expired();
    }

    size_t cache_size() const {
        return scan_cache_.size();
    }

    // ========================================================================
    // Queue info
    // ========================================================================
    size_t queue_size() const {
        return scan_queue_.queue_size();
    }

    // ========================================================================
    // Metrics
    // ========================================================================
    nlohmann::json get_metrics() const {
        return metrics_.get_json();
    }

    // ========================================================================
    // ClamAV status
    // ========================================================================
    bool clamd_available() const {
        return clamd_conn_ && clamd_conn_->is_connected();
    }

    bool clamd_ping() {
        if (!clamd_conn_ || !clamd_conn_->is_connected()) {
            // Try reconnecting
            if (config_.clamd_enabled && !config_.clamd_socket_path.empty()) {
                clamd_conn_ = std::make_unique<ClamdConnection>(
                    config_.clamd_socket_path, config_.clamd_timeout_secs);
                if (!clamd_conn_->connect()) {
                    clamd_conn_.reset();
                    return false;
                }
            } else {
                return false;
            }
        }
        return clamd_conn_->ping();
    }

    // ========================================================================
    // Reconnect to clamd
    // ========================================================================
    bool reconnect_clamd() {
        if (clamd_conn_) clamd_conn_->disconnect();
        clamd_conn_.reset();

        if (!config_.clamd_enabled || config_.clamd_socket_path.empty()) return false;

        clamd_conn_ = std::make_unique<ClamdConnection>(
            config_.clamd_socket_path, config_.clamd_timeout_secs);
        return clamd_conn_->connect();
    }

    // ========================================================================
    // Config access
    // ========================================================================
    const Config& config() const { return config_; }

private:
    Config config_;
    ScanMetrics metrics_;
    ScanCache scan_cache_;
    QuarantineManager quarantine_;
    ScanQueue scan_queue_;
    std::unique_ptr<ClamdConnection> clamd_conn_;

    size_t get_max_size_for_type(const std::string& mime) {
        std::string lower = to_lower(mime);
        if (ALLOWED_IMAGE_TYPES.count(lower)) return config_.max_image_size;
        if (ALLOWED_VIDEO_TYPES.count(lower)) return config_.max_video_size;
        if (ALLOWED_AUDIO_TYPES.count(lower)) return config_.max_audio_size;
        if (ALLOWED_ARCHIVE_TYPES.count(lower)) return DEFAULT_MAX_ARCHIVE_SIZE;
        return config_.max_other_size;
    }

    static std::string detect_mime_from_file(const std::filesystem::path& path) {
        std::ifstream file(path, std::ios::binary);
        if (!file) return "application/octet-stream";
        std::vector<uint8_t> header(1024);
        file.read(reinterpret_cast<char*>(header.data()), header.size());
        header.resize(file.gcount());
        return detect_magic_mime(header);
    }

    void quarantine_file(const std::string& file_path, const ScanResult& result) {
        std::string qpath;
        if (quarantine_.quarantine_file(file_path, result.file_hash, result, qpath)) {
            metrics_.record_quarantined();
        }
    }
};

// ============================================================================
// Public ContentScanner interface
// ============================================================================

ContentScanner::ContentScanner(const Config& config)
    : impl_(std::make_unique<ContentScannerImpl>(config))
{
}

ContentScanner::~ContentScanner() = default;

ScanResult ContentScanner::scan_file(const std::string& file_path,
                                      const std::string& claimed_mime,
                                      const std::string& original_filename)
{
    return impl_->scan_file_sync(file_path, claimed_mime, original_filename);
}

ScanResult ContentScanner::scan_data(const std::vector<uint8_t>& data,
                                      const std::string& claimed_mime,
                                      const std::string& original_filename)
{
    return impl_->scan_data_sync(data, claimed_mime, original_filename);
}

bool ContentScanner::scan_file_async(const std::string& file_path,
                                      ScanCallback callback,
                                      const std::string& claimed_mime,
                                      const std::string& original_filename,
                                      int priority)
{
    return impl_->scan_file_async(file_path, std::move(callback),
                                  claimed_mime, original_filename, priority);
}

bool ContentScanner::scan_data_async(const std::vector<uint8_t>& data,
                                      ScanCallback callback,
                                      const std::string& claimed_mime,
                                      const std::string& original_filename,
                                      int priority)
{
    return impl_->scan_data_async(data, std::move(callback),
                                  claimed_mime, original_filename, priority);
}

ScanResult ContentScanner::check_thumbnail_safety(const std::string& file_path,
                                                   const std::string& mime_type,
                                                   size_t file_size)
{
    return impl_->check_thumbnail_safety_sync(file_path, mime_type, file_size);
}

bool ContentScanner::restore_quarantined(const std::string& file_hash) {
    return impl_->restore_quarantined(file_hash);
}

bool ContentScanner::delete_quarantined(const std::string& file_hash) {
    return impl_->delete_quarantined(file_hash);
}

nlohmann::json ContentScanner::list_quarantined() const {
    return impl_->list_quarantined();
}

size_t ContentScanner::clean_quarantine(size_t max_age_seconds) {
    return impl_->clean_quarantine(max_age_seconds);
}

size_t ContentScanner::quarantine_count() const {
    return impl_->quarantine_count();
}

void ContentScanner::clear_cache() {
    impl_->clear_cache();
}

size_t ContentScanner::cache_size() const {
    return impl_->cache_size();
}

size_t ContentScanner::queue_size() const {
    return impl_->queue_size();
}

nlohmann::json ContentScanner::get_metrics() const {
    return impl_->get_metrics();
}

bool ContentScanner::clamd_available() const {
    return impl_->clamd_available();
}

bool ContentScanner::clamd_ping() {
    return impl_->clamd_ping();
}

bool ContentScanner::reconnect_clamd() {
    return impl_->reconnect_clamd();
}

// ============================================================================
// Admin API Handlers for Quarantine Management
// ============================================================================

nlohmann::json AdminQuarantineAPI::handle_list(ContentScanner& scanner) {
    nlohmann::json response;
    response["quarantined_files"] = scanner.list_quarantined();
    response["total_count"] = scanner.quarantine_count();
    return response;
}

nlohmann::json AdminQuarantineAPI::handle_get(ContentScanner& scanner,
                                               const std::string& file_hash)
{
    auto entries = scanner.list_quarantined();
    for (const auto& entry : entries) {
        if (entry.value("file_hash", "") == file_hash) {
            return entry;
        }
    }
    nlohmann::json err;
    err["error"] = "File not found in quarantine";
    err["errcode"] = "M_NOT_FOUND";
    return err;
}

nlohmann::json AdminQuarantineAPI::handle_restore(ContentScanner& scanner,
                                                   const std::string& file_hash)
{
    if (scanner.restore_quarantined(file_hash)) {
        nlohmann::json response;
        response["status"] = "restored";
        response["file_hash"] = file_hash;
        response["message"] = "File restored from quarantine";
        return response;
    }
    nlohmann::json err;
    err["error"] = "Failed to restore file from quarantine";
    err["errcode"] = "M_UNKNOWN";
    return err;
}

nlohmann::json AdminQuarantineAPI::handle_delete(ContentScanner& scanner,
                                                  const std::string& file_hash)
{
    if (scanner.delete_quarantined(file_hash)) {
        nlohmann::json response;
        response["status"] = "deleted";
        response["file_hash"] = file_hash;
        response["message"] = "Quarantined file deleted";
        return response;
    }
    nlohmann::json err;
    err["error"] = "Failed to delete quarantined file";
    err["errcode"] = "M_UNKNOWN";
    return err;
}

nlohmann::json AdminQuarantineAPI::handle_clean(ContentScanner& scanner,
                                                 size_t max_age_seconds)
{
    size_t removed = scanner.clean_quarantine(max_age_seconds);
    nlohmann::json response;
    response["status"] = "cleaned";
    response["removed_count"] = removed;
    response["remaining_count"] = scanner.quarantine_count();
    return response;
}

nlohmann::json AdminQuarantineAPI::handle_stats(ContentScanner& scanner) {
    nlohmann::json stats;
    stats["quarantine_count"] = scanner.quarantine_count();
    stats["cache_size"] = scanner.cache_size();
    stats["queue_size"] = scanner.queue_size();
    stats["clamd_available"] = scanner.clamd_available();
    stats["scan_metrics"] = scanner.get_metrics();
    return stats;
}

nlohmann::json AdminQuarantineAPI::handle_reconnect_clamd(ContentScanner& scanner) {
    bool success = scanner.reconnect_clamd();
    nlohmann::json response;
    if (success) {
        response["status"] = "connected";
        response["message"] = "Successfully reconnected to ClamAV";
    } else {
        response["status"] = "error";
        response["message"] = "Failed to reconnect to ClamAV";
    }
    return response;
}

// ============================================================================
// Utility: Quick file validation helpers
// ============================================================================

bool QuickValidator::is_extension_blocked(const std::string& filename) {
    std::string ext = extract_extension(filename);
    if (ext.empty()) return false;
    return BLOCKED_EXTENSIONS.count(to_lower(ext)) > 0;
}

bool QuickValidator::is_mime_allowed(const std::string& mime_type) {
    std::string lower = to_lower(mime_type);
    return ALLOWED_IMAGE_TYPES.count(lower) ||
           ALLOWED_VIDEO_TYPES.count(lower) ||
           ALLOWED_AUDIO_TYPES.count(lower) ||
           ALLOWED_DOCUMENT_TYPES.count(lower) ||
           ALLOWED_ARCHIVE_TYPES.count(lower);
}

std::string QuickValidator::detect_mime_from_data(const std::vector<uint8_t>& data) {
    return detect_magic_mime(data);
}

std::string QuickValidator::detect_mime_from_file(const std::filesystem::path& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) return "application/octet-stream";
    std::vector<uint8_t> buf(1024);
    file.read(reinterpret_cast<char*>(buf.data()), buf.size());
    buf.resize(file.gcount());
    return detect_magic_mime(buf);
}

bool QuickValidator::detect_imagetragick(const std::vector<uint8_t>& data) {
    return detect_imagetragick_exploit(data);
}

std::pair<size_t, size_t> QuickValidator::image_dimensions(const std::vector<uint8_t>& data) {
    return detect_image_dimensions_from_data(data);
}

bool QuickValidator::is_pdf_safe(const std::vector<uint8_t>& data) {
    auto result = validate_pdf_data(data);
    return result.status == ScanResult::Status::CLEAN;
}

bool QuickValidator::is_svg_safe(const std::vector<uint8_t>& data) {
    auto result = sanitize_svg_data(data);
    return result.status == ScanResult::Status::CLEAN;
}

// ============================================================================
// Periodic maintenance
// ============================================================================

void ContentScanner::run_maintenance() {
    impl_->clean_cache();
    impl_->clean_quarantine(DEFAULT_QUARANTINE_MAX_AGE);
}

// ============================================================================
// Static factory
// ============================================================================

ContentScanner ContentScanner::create_with_defaults(const std::string& quarantine_dir) {
    Config config;
    if (!quarantine_dir.empty()) {
        config.quarantine_dir = quarantine_dir;
    } else {
        config.quarantine_dir = "/tmp/progressive-quarantine";
    }
    return ContentScanner(config);
}

ContentScanner ContentScanner::create_with_clamd(const std::string& socket_path,
                                                  const std::string& quarantine_dir)
{
    Config config;
    config.clamd_enabled = true;
    config.clamd_socket_path = socket_path;
    config.quarantine_dir = quarantine_dir.empty() ?
        "/tmp/progressive-quarantine" : quarantine_dir;
    return ContentScanner(config);
}

}  // namespace media
}  // namespace progressive
