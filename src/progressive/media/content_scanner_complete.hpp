// SPDX-License-Identifier: AGPL-3.0-only
// Progressive Matrix Server — Content Scanner Interface
// Copyright (c) 2026 Progressive Contributors

#pragma once

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "../json.hpp"

namespace progressive {
namespace media {

// ============================================================================
// ScanResult — outcome of a content scan
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
    std::string file_hash;
    std::string detected_mime;
    std::string claimed_mime;
    std::string file_extension;
    size_t file_size = 0;
    bool was_sanitized = false;
    std::string original_file_path;
    std::string quarantined_path;
    std::chrono::system_clock::time_point scan_time;
    double scan_duration_ms = 0.0;

    nlohmann::json to_json() const;
    std::string status_to_string() const;
};

// ============================================================================
// ScanCallback type for async scanning
// ============================================================================

using ScanCallback = std::function<void(const ScanResult&)>;

// ============================================================================
// ContentScanner — main scanning interface
// ============================================================================

class ContentScannerImpl;

class ContentScanner {
public:
    struct Config {
        std::string clamd_socket_path = "/var/run/clamav/clamd.ctl";
        bool clamd_enabled = true;
        size_t clamd_timeout_secs = 30;
        std::string quarantine_dir;
        size_t max_attachment_size = 50 * 1024 * 1024;
        size_t max_image_size = 50 * 1024 * 1024;
        size_t max_video_size = 100 * 1024 * 1024;
        size_t max_audio_size = 50 * 1024 * 1024;
        size_t max_other_size = 10 * 1024 * 1024;
        size_t max_image_width = 8192;
        size_t max_image_height = 8192;
        size_t max_image_pixels = 80000000;
        size_t max_thumbnail_width = 800;
        size_t max_thumbnail_height = 600;
        size_t scan_cache_size = 10000;
        size_t scan_cache_ttl = 3600;
        size_t quarantine_max_age = 86400 * 30;
        size_t queue_size = 1000;
        size_t worker_threads = 2;
        bool enable_svg_sanitization = true;
        bool enable_pdf_validation = true;
        bool enable_html_sanitization = true;
        bool enable_archive_validation = true;
        bool enable_exif_stripping = true;
        bool enable_thumbnail_safety = true;
    };

    explicit ContentScanner(const Config& config);
    ~ContentScanner();

    // Non-copyable, movable
    ContentScanner(const ContentScanner&) = delete;
    ContentScanner& operator=(const ContentScanner&) = delete;
    ContentScanner(ContentScanner&&) noexcept = default;
    ContentScanner& operator=(ContentScanner&&) noexcept = default;

    // Synchronous scans
    ScanResult scan_file(const std::string& file_path,
                         const std::string& claimed_mime = "",
                         const std::string& original_filename = "");

    ScanResult scan_data(const std::vector<uint8_t>& data,
                         const std::string& claimed_mime = "",
                         const std::string& original_filename = "");

    // Asynchronous scans
    bool scan_file_async(const std::string& file_path,
                         ScanCallback callback,
                         const std::string& claimed_mime = "",
                         const std::string& original_filename = "",
                         int priority = 0);

    bool scan_data_async(const std::vector<uint8_t>& data,
                         ScanCallback callback,
                         const std::string& claimed_mime = "",
                         const std::string& original_filename = "",
                         int priority = 0);

    // Thumbnail safety
    ScanResult check_thumbnail_safety(const std::string& file_path,
                                       const std::string& mime_type,
                                       size_t file_size);

    // Quarantine management
    bool restore_quarantined(const std::string& file_hash);
    bool delete_quarantined(const std::string& file_hash);
    nlohmann::json list_quarantined() const;
    size_t clean_quarantine(size_t max_age_seconds);
    size_t quarantine_count() const;

    // Cache management
    void clear_cache();
    size_t cache_size() const;

    // Queue management
    size_t queue_size() const;

    // Metrics
    nlohmann::json get_metrics() const;

    // ClamAV
    bool clamd_available() const;
    bool clamd_ping();
    bool reconnect_clamd();

    // Maintenance
    void run_maintenance();

    // Factory methods
    static ContentScanner create_with_defaults(const std::string& quarantine_dir = "");
    static ContentScanner create_with_clamd(const std::string& socket_path,
                                            const std::string& quarantine_dir = "");

private:
    std::unique_ptr<ContentScannerImpl> impl_;
};

// ============================================================================
// AdminQuarantineAPI — admin handlers for quarantine management
// ============================================================================

class AdminQuarantineAPI {
public:
    static nlohmann::json handle_list(ContentScanner& scanner);
    static nlohmann::json handle_get(ContentScanner& scanner, const std::string& file_hash);
    static nlohmann::json handle_restore(ContentScanner& scanner, const std::string& file_hash);
    static nlohmann::json handle_delete(ContentScanner& scanner, const std::string& file_hash);
    static nlohmann::json handle_clean(ContentScanner& scanner, size_t max_age_seconds);
    static nlohmann::json handle_stats(ContentScanner& scanner);
    static nlohmann::json handle_reconnect_clamd(ContentScanner& scanner);
};

// ============================================================================
// QuickValidator — lightweight validation helpers (no full scan needed)
// ============================================================================

class QuickValidator {
public:
    static bool is_extension_blocked(const std::string& filename);
    static bool is_mime_allowed(const std::string& mime_type);
    static std::string detect_mime_from_data(const std::vector<uint8_t>& data);
    static std::string detect_mime_from_file(const std::filesystem::path& path);
    static bool detect_imagetragick(const std::vector<uint8_t>& data);
    static std::pair<size_t, size_t> image_dimensions(const std::vector<uint8_t>& data);
    static bool is_pdf_safe(const std::vector<uint8_t>& data);
    static bool is_svg_safe(const std::vector<uint8_t>& data);
};

}  // namespace media
}  // namespace progressive
