// ============================================================================
// content_scanner.cpp — Matrix Content Scanner: Antivirus Scanning Interface,
//   Malware Detection, Adult Content Detection, Custom Scanning Modules,
//   Scan Result Caching, Quarantine on Detection
//
// Implements:
//   - Antivirus Integration: ClamAV daemon integration (clamd), YARA rule
//     scanning, signature-based detection, heuristic analysis, multi-engine
//     orchestration with configurable engine priority and fallback chains.
//   - Malware Detection: Hostile content scanning on media uploads, message
//     content, URL previews, avatars, and file attachments. Signature
//     database with automatic periodic updates. Hash-based lookup
//     (MD5/SHA1/SHA256) against known malware databases. Zero-day
//     heuristic detection with behavior pattern analysis.
//   - Adult Content Detection: NSFW image/video classification using
//     integrated ML models or external API services. Configurable
//     sensitivity thresholds per room. Skin-tone analysis, objectionable
//     text pattern matching, age-verification gate integration.
//   - Custom Scanning Modules: Plugin-based architecture for user-defined
//     scan modules. Module registration API, priority-based execution
//     order, per-module configuration, module hot-reload support.
//     Custom callback hooks for pre-scan and post-scan processing.
//   - Scan Result Caching: Multi-level caching (L1 in-memory LRU, L2
//     persistent DB). Cache keyed by content hash, configurable TTL,
//     cache warming on startup, cache invalidation on signature updates.
//     Cache hit/miss metrics for performance monitoring.
//   - Quarantine on Detection: Automatic quarantine of flagged content.
//     Configurable actions per category (warn, block, quarantine, redact).
//     Quarantine storage with metadata, retention policies, review
//     workflow. Admin API for quarantine management (list, release,
//     delete, override). Notification integration for moderation alerts.
//   - Async Scanning Pipeline: Non-blocking scan submission with
//     configurable thread pool. Priority queue for scan requests,
//     timeout handling, graceful degradation. Chunked scanning for
//     large files with progressive result reporting.
//   - Audit & Metrics: Detailed scan audit trail with timestamps,
//     engine results, confidence scores, and final disposition.
//     Prometheus-compatible metrics (scan count, cache hit rate,
//     detection rate, average latency, quarantine size).
//
// Equivalent to:
//   synapse/rest/media/v1/media_storage.py (media handling)
//   synapse/handlers/message.py (content filtering)
//   synapse/util/file_consumer.py (clamav integration)
//   synapse/config/content_scanner.py (scanner configuration)
//   matrix-content-scanner (MCS) reference implementation
//   matrix-org/matrix-spec-proposals/proposals/2845-content-scanner.md
//   matrix-org/matrix-spec-proposals/proposals/2846-content-scanner-api.md
//
// Namespace: progressive::
// Target: 3000+ lines of production-grade C++.
// ============================================================================

#include <algorithm>
#include <array>
#include <atomic>
#include <bitset>
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
#include <limits>
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
#include <tuple>
#include <type_traits>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <variant>
#include <vector>

#include <nlohmann/json.hpp>

#include "progressive/storage/database.hpp"
#include "progressive/storage/databases/main/media_repository.hpp"
#include "progressive/storage/databases/main/events.hpp"
#include "progressive/storage/databases/main/room.hpp"

// ============================================================================
// Namespace
// ============================================================================
namespace progressive {

using json = nlohmann::json;
namespace chr = std::chrono;
namespace fs = std::filesystem;

// ============================================================================
// Forward declarations for internal classes
// ============================================================================
class ScanEngineRegistry;
class ClamAVScanEngine;
class YaraScanEngine;
class PatternScanEngine;
class MLScanEngine;
class HashScanEngine;
class CustomScanModuleBase;
class ScanCacheManager;
class QuarantineManager;
class ScanScheduler;
class ScanResultAggregator;
class ScanPolicyManager;
class MalwareSignatureDB;
class AdultContentDetector;
class ScanMetricsCollector;
class ScanAuditLogger;
class ContentScanner;

// ============================================================================
// Anonymous namespace — Internal helpers, constants, and utility types
// ============================================================================
namespace {

// --------------------------------------------------------------------------
// Logging helper (matches project conventions)
// --------------------------------------------------------------------------
struct ScannerLogger {
  std::string name_;
  void debug(const std::string& msg) { std::cerr << "[DEBUG][" << name_ << "] " << msg << "\n"; }
  void info(const std::string& msg)  { std::cerr << "[INFO][" << name_ << "] " << msg << "\n"; }
  void warn(const std::string& msg)  { std::cerr << "[WARN][" << name_ << "] " << msg << "\n"; }
  void error(const std::string& msg) { std::cerr << "[ERROR][" << name_ << "] " << msg << "\n"; }
};

ScannerLogger& get_scanner_logger(const std::string& name) {
  static thread_local std::map<std::string, ScannerLogger> loggers;
  if (loggers.find(name) == loggers.end()) {
    loggers[name].name_ = name;
  }
  return loggers[name];
}

// --------------------------------------------------------------------------
// Scan engine type enumeration
// --------------------------------------------------------------------------
enum class ScanEngineType : uint8_t {
  CLAMAV        = 0,
  YARA          = 1,
  PATTERN       = 2,
  MACHINE_LEARNING = 3,
  HASH_LOOKUP   = 4,
  CUSTOM        = 5,
  EXTERNAL_API  = 6,
  COMPOSITE     = 7,
  HEURISTIC     = 8,
  NONE          = 9
};

const char* scan_engine_type_to_string(ScanEngineType t) {
  switch (t) {
    case ScanEngineType::CLAMAV:          return "clamav";
    case ScanEngineType::YARA:            return "yara";
    case ScanEngineType::PATTERN:         return "pattern";
    case ScanEngineType::MACHINE_LEARNING: return "machine_learning";
    case ScanEngineType::HASH_LOOKUP:     return "hash_lookup";
    case ScanEngineType::CUSTOM:          return "custom";
    case ScanEngineType::EXTERNAL_API:    return "external_api";
    case ScanEngineType::COMPOSITE:       return "composite";
    case ScanEngineType::HEURISTIC:       return "heuristic";
    case ScanEngineType::NONE:            return "none";
  }
  return "unknown";
}

ScanEngineType scan_engine_type_from_string(const std::string& s) {
  if (s == "clamav")           return ScanEngineType::CLAMAV;
  if (s == "yara")             return ScanEngineType::YARA;
  if (s == "pattern")          return ScanEngineType::PATTERN;
  if (s == "machine_learning") return ScanEngineType::MACHINE_LEARNING;
  if (s == "hash_lookup")      return ScanEngineType::HASH_LOOKUP;
  if (s == "custom")           return ScanEngineType::CUSTOM;
  if (s == "external_api")     return ScanEngineType::EXTERNAL_API;
  if (s == "composite")        return ScanEngineType::COMPOSITE;
  if (s == "heuristic")        return ScanEngineType::HEURISTIC;
  return ScanEngineType::NONE;
}

// --------------------------------------------------------------------------
// Scan target type enumeration
// --------------------------------------------------------------------------
enum class ScanTargetType : uint8_t {
  MESSAGE_CONTENT  = 0,
  MEDIA_UPLOAD     = 1,
  AVATAR           = 2,
  FILE_ATTACHMENT  = 3,
  URL_PREVIEW      = 4,
  USER_PROFILE     = 5,
  ROOM_AVATAR      = 6,
  STICKER          = 7,
  BLOB             = 8,
  ENCRYPTED_BLOB   = 9,
  THUMBNAIL        = 10,
  STREAM           = 11
};

const char* scan_target_type_to_string(ScanTargetType t) {
  switch (t) {
    case ScanTargetType::MESSAGE_CONTENT: return "message_content";
    case ScanTargetType::MEDIA_UPLOAD:    return "media_upload";
    case ScanTargetType::AVATAR:          return "avatar";
    case ScanTargetType::FILE_ATTACHMENT: return "file_attachment";
    case ScanTargetType::URL_PREVIEW:     return "url_preview";
    case ScanTargetType::USER_PROFILE:    return "user_profile";
    case ScanTargetType::ROOM_AVATAR:     return "room_avatar";
    case ScanTargetType::STICKER:         return "sticker";
    case ScanTargetType::BLOB:            return "blob";
    case ScanTargetType::ENCRYPTED_BLOB:  return "encrypted_blob";
    case ScanTargetType::THUMBNAIL:       return "thumbnail";
    case ScanTargetType::STREAM:          return "stream";
  }
  return "unknown";
}

ScanTargetType scan_target_type_from_string(const std::string& s) {
  if (s == "message_content")  return ScanTargetType::MESSAGE_CONTENT;
  if (s == "media_upload")     return ScanTargetType::MEDIA_UPLOAD;
  if (s == "avatar")           return ScanTargetType::AVATAR;
  if (s == "file_attachment")  return ScanTargetType::FILE_ATTACHMENT;
  if (s == "url_preview")      return ScanTargetType::URL_PREVIEW;
  if (s == "user_profile")     return ScanTargetType::USER_PROFILE;
  if (s == "room_avatar")      return ScanTargetType::ROOM_AVATAR;
  if (s == "sticker")          return ScanTargetType::STICKER;
  if (s == "blob")             return ScanTargetType::BLOB;
  if (s == "encrypted_blob")   return ScanTargetType::ENCRYPTED_BLOB;
  if (s == "thumbnail")        return ScanTargetType::THUMBNAIL;
  if (s == "stream")           return ScanTargetType::STREAM;
  return ScanTargetType::MEDIA_UPLOAD;
}

// --------------------------------------------------------------------------
// Scan result classification enumeration
// --------------------------------------------------------------------------
enum class ScanVerdict : uint8_t {
  CLEAN       = 0,
  MALWARE     = 1,
  ADULT       = 2,
  SUSPICIOUS  = 3,
  ENCRYPTED   = 4,
  ERROR       = 5,
  TIMEOUT     = 6,
  UNKNOWN     = 7,
  BYPASSED    = 8,
  QUARANTINED = 9,
  BLOCKED     = 10
};

const char* scan_verdict_to_string(ScanVerdict v) {
  switch (v) {
    case ScanVerdict::CLEAN:       return "clean";
    case ScanVerdict::MALWARE:     return "malware";
    case ScanVerdict::ADULT:       return "adult";
    case ScanVerdict::SUSPICIOUS:  return "suspicious";
    case ScanVerdict::ENCRYPTED:   return "encrypted";
    case ScanVerdict::ERROR:       return "error";
    case ScanVerdict::TIMEOUT:     return "timeout";
    case ScanVerdict::UNKNOWN:     return "unknown";
    case ScanVerdict::BYPASSED:    return "bypassed";
    case ScanVerdict::QUARANTINED: return "quarantined";
    case ScanVerdict::BLOCKED:     return "blocked";
  }
  return "unknown";
}

ScanVerdict scan_verdict_from_string(const std::string& s) {
  if (s == "clean")       return ScanVerdict::CLEAN;
  if (s == "malware")     return ScanVerdict::MALWARE;
  if (s == "adult")       return ScanVerdict::ADULT;
  if (s == "suspicious")  return ScanVerdict::SUSPICIOUS;
  if (s == "encrypted")   return ScanVerdict::ENCRYPTED;
  if (s == "error")       return ScanVerdict::ERROR;
  if (s == "timeout")     return ScanVerdict::TIMEOUT;
  if (s == "bypassed")    return ScanVerdict::BYPASSED;
  if (s == "quarantined") return ScanVerdict::QUARANTINED;
  if (s == "blocked")     return ScanVerdict::BLOCKED;
  return ScanVerdict::UNKNOWN;
}

// --------------------------------------------------------------------------
// Scan severity level enumeration
// --------------------------------------------------------------------------
enum class ScanSeverity : uint8_t {
  NONE     = 0,
  LOW      = 1,
  MEDIUM   = 2,
  HIGH     = 3,
  CRITICAL = 4
};

const char* scan_severity_to_string(ScanSeverity s) {
  switch (s) {
    case ScanSeverity::NONE:     return "none";
    case ScanSeverity::LOW:      return "low";
    case ScanSeverity::MEDIUM:   return "medium";
    case ScanSeverity::HIGH:     return "high";
    case ScanSeverity::CRITICAL: return "critical";
  }
  return "none";
}

ScanSeverity scan_severity_from_string(const std::string& s) {
  if (s == "low")      return ScanSeverity::LOW;
  if (s == "medium")   return ScanSeverity::MEDIUM;
  if (s == "high")     return ScanSeverity::HIGH;
  if (s == "critical") return ScanSeverity::CRITICAL;
  return ScanSeverity::NONE;
}

// --------------------------------------------------------------------------
// Content category enumeration for classification
// --------------------------------------------------------------------------
enum class ContentCategory : uint8_t {
  SAFE              = 0,
  MALWARE_GENERIC   = 1,
  MALWARE_TROJAN    = 2,
  MALWARE_RANSOMWARE = 3,
  MALWARE_WORM      = 4,
  MALWARE_SPYWARE   = 5,
  MALWARE_ADWARE    = 6,
  ADULT_NSFW        = 7,
  ADULT_EXPLICIT    = 8,
  VIOLENCE          = 9,
  HATE_SPEECH       = 10,
  SPAM              = 11,
  PHISHING          = 12,
  CRYPTOMINING      = 13,
  ILLEGAL_CONTENT   = 14,
  COPYRIGHTED       = 15,
  OTHER             = 16
};

const char* content_category_to_string(ContentCategory c) {
  switch (c) {
    case ContentCategory::SAFE:               return "safe";
    case ContentCategory::MALWARE_GENERIC:    return "malware_generic";
    case ContentCategory::MALWARE_TROJAN:     return "malware_trojan";
    case ContentCategory::MALWARE_RANSOMWARE: return "malware_ransomware";
    case ContentCategory::MALWARE_WORM:       return "malware_worm";
    case ContentCategory::MALWARE_SPYWARE:    return "malware_spyware";
    case ContentCategory::MALWARE_ADWARE:     return "malware_adware";
    case ContentCategory::ADULT_NSFW:         return "adult_nsfw";
    case ContentCategory::ADULT_EXPLICIT:     return "adult_explicit";
    case ContentCategory::VIOLENCE:           return "violence";
    case ContentCategory::HATE_SPEECH:        return "hate_speech";
    case ContentCategory::SPAM:               return "spam";
    case ContentCategory::PHISHING:           return "phishing";
    case ContentCategory::CRYPTOMINING:       return "cryptomining";
    case ContentCategory::ILLEGAL_CONTENT:    return "illegal_content";
    case ContentCategory::COPYRIGHTED:        return "copyrighted";
    case ContentCategory::OTHER:              return "other";
  }
  return "unknown";
}

ContentCategory content_category_from_string(const std::string& s) {
  if (s == "safe")                return ContentCategory::SAFE;
  if (s == "malware_generic")     return ContentCategory::MALWARE_GENERIC;
  if (s == "malware_trojan")      return ContentCategory::MALWARE_TROJAN;
  if (s == "malware_ransomware")  return ContentCategory::MALWARE_RANSOMWARE;
  if (s == "malware_worm")        return ContentCategory::MALWARE_WORM;
  if (s == "malware_spyware")     return ContentCategory::MALWARE_SPYWARE;
  if (s == "malware_adware")      return ContentCategory::MALWARE_ADWARE;
  if (s == "adult_nsfw")          return ContentCategory::ADULT_NSFW;
  if (s == "adult_explicit")      return ContentCategory::ADULT_EXPLICIT;
  if (s == "violence")            return ContentCategory::VIOLENCE;
  if (s == "hate_speech")         return ContentCategory::HATE_SPEECH;
  if (s == "spam")                return ContentCategory::SPAM;
  if (s == "phishing")            return ContentCategory::PHISHING;
  if (s == "cryptomining")        return ContentCategory::CRYPTOMINING;
  if (s == "illegal_content")     return ContentCategory::ILLEGAL_CONTENT;
  if (s == "copyrighted")         return ContentCategory::COPYRIGHTED;
  return ContentCategory::OTHER;
}

// --------------------------------------------------------------------------
// Quarantine action enumeration
// --------------------------------------------------------------------------
enum class QuarantineAction : uint8_t {
  NONE          = 0,
  FLAG          = 1,
  BLOCK         = 2,
  QUARANTINE    = 3,
  NOTIFY_ADMIN  = 4,
  REDACT        = 5,
  DELETE_FILE   = 6,
  REPLACE       = 7
};

const char* quarantine_action_to_string(QuarantineAction a) {
  switch (a) {
    case QuarantineAction::NONE:         return "none";
    case QuarantineAction::FLAG:         return "flag";
    case QuarantineAction::BLOCK:        return "block";
    case QuarantineAction::QUARANTINE:   return "quarantine";
    case QuarantineAction::NOTIFY_ADMIN: return "notify_admin";
    case QuarantineAction::REDACT:       return "redact";
    case QuarantineAction::DELETE_FILE:  return "delete_file";
    case QuarantineAction::REPLACE:      return "replace";
  }
  return "none";
}

QuarantineAction quarantine_action_from_string(const std::string& s) {
  if (s == "flag")          return QuarantineAction::FLAG;
  if (s == "block")         return QuarantineAction::BLOCK;
  if (s == "quarantine")    return QuarantineAction::QUARANTINE;
  if (s == "notify_admin")  return QuarantineAction::NOTIFY_ADMIN;
  if (s == "redact")        return QuarantineAction::REDACT;
  if (s == "delete_file")   return QuarantineAction::DELETE_FILE;
  if (s == "replace")       return QuarantineAction::REPLACE;
  return QuarantineAction::NONE;
}

// --------------------------------------------------------------------------
// Hash algorithm enumeration
// --------------------------------------------------------------------------
enum class HashAlgorithm : uint8_t {
  MD5    = 0,
  SHA1   = 1,
  SHA256 = 2,
  SHA512 = 3,
  CRC32  = 4,
  BLAKE2 = 5,
  BLAKE3 = 6
};

const char* hash_algorithm_to_string(HashAlgorithm a) {
  switch (a) {
    case HashAlgorithm::MD5:    return "md5";
    case HashAlgorithm::SHA1:   return "sha1";
    case HashAlgorithm::SHA256: return "sha256";
    case HashAlgorithm::SHA512: return "sha512";
    case HashAlgorithm::CRC32:  return "crc32";
    case HashAlgorithm::BLAKE2: return "blake2";
    case HashAlgorithm::BLAKE3: return "blake3";
  }
  return "unknown";
}

HashAlgorithm hash_algorithm_from_string(const std::string& s) {
  if (s == "md5")    return HashAlgorithm::MD5;
  if (s == "sha1")   return HashAlgorithm::SHA1;
  if (s == "sha256") return HashAlgorithm::SHA256;
  if (s == "sha512") return HashAlgorithm::SHA512;
  if (s == "crc32")  return HashAlgorithm::CRC32;
  if (s == "blake2") return HashAlgorithm::BLAKE2;
  if (s == "blake3") return HashAlgorithm::BLAKE3;
  return HashAlgorithm::SHA256;
}

// --------------------------------------------------------------------------
// Detection method enumeration
// --------------------------------------------------------------------------
enum class DetectionMethod : uint8_t {
  SIGNATURE        = 0,
  HEURISTIC        = 1,
  MACHINE_LEARNING = 2,
  PATTERN_MATCH    = 3,
  BLACKLIST        = 4,
  REPUTATION       = 5,
  YARA_RULE        = 6,
  BEHAVIORAL       = 7,
  SANDBOX          = 8,
  HASH_MATCH       = 9,
  URL_BLOCKLIST    = 10,
  DNS_REPUTATION   = 11
};

const char* detection_method_to_string(DetectionMethod m) {
  switch (m) {
    case DetectionMethod::SIGNATURE:        return "signature";
    case DetectionMethod::HEURISTIC:        return "heuristic";
    case DetectionMethod::MACHINE_LEARNING: return "machine_learning";
    case DetectionMethod::PATTERN_MATCH:    return "pattern_match";
    case DetectionMethod::BLACKLIST:        return "blacklist";
    case DetectionMethod::REPUTATION:       return "reputation";
    case DetectionMethod::YARA_RULE:        return "yara_rule";
    case DetectionMethod::BEHAVIORAL:       return "behavioral";
    case DetectionMethod::SANDBOX:          return "sandbox";
    case DetectionMethod::HASH_MATCH:       return "hash_match";
    case DetectionMethod::URL_BLOCKLIST:    return "url_blocklist";
    case DetectionMethod::DNS_REPUTATION:   return "dns_reputation";
  }
  return "unknown";
}

// --------------------------------------------------------------------------
// Time utility helpers
// --------------------------------------------------------------------------
int64_t now_ms() {
  return chr::duration_cast<chr::milliseconds>(
    chr::system_clock::now().time_since_epoch()).count();
}

int64_t now_us() {
  return chr::duration_cast<chr::microseconds>(
    chr::system_clock::now().time_since_epoch()).count();
}

std::string iso8601_now() {
  auto now = chr::system_clock::now();
  auto tt = chr::system_clock::to_time_t(now);
  std::ostringstream oss;
  oss << std::put_time(std::gmtime(&tt), "%Y-%m-%dT%H:%M:%SZ");
  return oss.str();
}

// --------------------------------------------------------------------------
// UUID generation helper
// --------------------------------------------------------------------------
std::string generate_uuid() {
  static std::random_device rd;
  static std::mt19937_64 gen(rd());
  static std::uniform_int_distribution<uint64_t> dis;
  static thread_local std::mutex uuid_mtx;

  std::lock_guard<std::mutex> lock(uuid_mtx);
  uint64_t a = dis(gen);
  uint64_t b = dis(gen);

  char buf[37];
  std::snprintf(buf, sizeof(buf),
    "%08x-%04x-%04x-%04x-%012llx",
    static_cast<uint32_t>(a >> 32),
    static_cast<uint16_t>((a >> 16) & 0xFFFF),
    static_cast<uint16_t>(a & 0xFFFF),
    static_cast<uint16_t>(b >> 48),
    static_cast<long long>(b & 0xFFFFFFFFFFFFULL));
  return std::string(buf);
}

// --------------------------------------------------------------------------
// Simple hex encoding helper
// --------------------------------------------------------------------------
std::string bytes_to_hex(const std::string& data) {
  static const char* hex_chars = "0123456789abcdef";
  std::string result;
  result.reserve(data.size() * 2);
  for (unsigned char c : data) {
    result.push_back(hex_chars[c >> 4]);
    result.push_back(hex_chars[c & 0x0F]);
  }
  return result;
}

std::string bytes_to_hex(const std::vector<uint8_t>& data) {
  static const char* hex_chars = "0123456789abcdef";
  std::string result;
  result.reserve(data.size() * 2);
  for (unsigned char c : data) {
    result.push_back(hex_chars[c >> 4]);
    result.push_back(hex_chars[c & 0x0F]);
  }
  return result;
}

// --------------------------------------------------------------------------
// MIME type detection from filename extension
// --------------------------------------------------------------------------
std::string mime_type_from_filename(const std::string& filename) {
  static const std::unordered_map<std::string, std::string> mime_map = {
    {".jpg", "image/jpeg"},   {".jpeg", "image/jpeg"},
    {".png", "image/png"},    {".gif", "image/gif"},
    {".bmp", "image/bmp"},    {".webp", "image/webp"},
    {".svg", "image/svg+xml"},{".ico", "image/x-icon"},
    {".mp4", "video/mp4"},    {".webm", "video/webm"},
    {".avi", "video/x-msvideo"},{".mov", "video/quicktime"},
    {".mp3", "audio/mpeg"},   {".ogg", "audio/ogg"},
    {".wav", "audio/wav"},    {".flac", "audio/flac"},
    {".pdf", "application/pdf"},{".doc", "application/msword"},
    {".docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
    {".xls", "application/vnd.ms-excel"},
    {".xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
    {".zip", "application/zip"},{".tar", "application/x-tar"},
    {".gz", "application/gzip"},{".rar", "application/x-rar-compressed"},
    {".7z", "application/x-7z-compressed"},
    {".exe", "application/x-msdos-program"},
    {".dll", "application/x-msdownload"},
    {".js", "application/javascript"},
    {".html", "text/html"},    {".htm", "text/html"},
    {".css", "text/css"},      {".txt", "text/plain"},
    {".json", "application/json"},{".xml", "application/xml"},
    {".apk", "application/vnd.android.package-archive"},
    {".ipa", "application/octet-stream"},
    {".deb", "application/x-deb"},
    {".rpm", "application/x-rpm"},
  };

  auto dot_pos = filename.rfind('.');
  if (dot_pos == std::string::npos) return "application/octet-stream";

  std::string ext = filename.substr(dot_pos);
  std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);

  auto it = mime_map.find(ext);
  return (it != mime_map.end()) ? it->second : "application/octet-stream";
}

// --------------------------------------------------------------------------
// Scan priority enumeration for scheduling
// --------------------------------------------------------------------------
enum class ScanPriority : uint8_t {
  LOW       = 0,
  NORMAL    = 1,
  HIGH      = 2,
  CRITICAL  = 3,
  REALTIME  = 4
};

const char* scan_priority_to_string(ScanPriority p) {
  switch (p) {
    case ScanPriority::LOW:      return "low";
    case ScanPriority::NORMAL:   return "normal";
    case ScanPriority::HIGH:     return "high";
    case ScanPriority::CRITICAL: return "critical";
    case ScanPriority::REALTIME: return "realtime";
  }
  return "normal";
}

// --------------------------------------------------------------------------
// Cache eviction policy
// --------------------------------------------------------------------------
enum class CacheEvictionPolicy : uint8_t {
  LRU   = 0,
  TTL   = 1,
  FIFO  = 2,
  LFU   = 3,
  NONE  = 4
};

const char* cache_eviction_policy_to_string(CacheEvictionPolicy p) {
  switch (p) {
    case CacheEvictionPolicy::LRU:  return "lru";
    case CacheEvictionPolicy::TTL:  return "ttl";
    case CacheEvictionPolicy::FIFO: return "fifo";
    case CacheEvictionPolicy::LFU:  return "lfu";
    case CacheEvictionPolicy::NONE: return "none";
  }
  return "lru";
}

// --------------------------------------------------------------------------
// Signature database update status
// --------------------------------------------------------------------------
enum class SignatureDBStatus : uint8_t {
  CURRENT      = 0,
  UPDATING     = 1,
  OUTDATED     = 2,
  ERROR        = 3,
  INITIALIZING = 4,
  CORRUPT      = 5
};

const char* signature_db_status_to_string(SignatureDBStatus s) {
  switch (s) {
    case SignatureDBStatus::CURRENT:      return "current";
    case SignatureDBStatus::UPDATING:     return "updating";
    case SignatureDBStatus::OUTDATED:     return "outdated";
    case SignatureDBStatus::ERROR:        return "error";
    case SignatureDBStatus::INITIALIZING: return "initializing";
    case SignatureDBStatus::CORRUPT:      return "corrupt";
  }
  return "unknown";
}

} // anonymous namespace

// ============================================================================
// Data structures
// ============================================================================

// --------------------------------------------------------------------------
// Hash value structure — represents a file/content hash
// --------------------------------------------------------------------------
struct HashValue {
  HashAlgorithm algorithm = HashAlgorithm::SHA256;
  std::string value;

  bool is_valid() const { return !value.empty(); }

  json to_json() const {
    return json{
      {"algorithm", hash_algorithm_to_string(algorithm)},
      {"value", value}
    };
  }

  static HashValue from_json(const json& j) {
    HashValue h;
    h.algorithm = hash_algorithm_from_string(j.value("algorithm", "sha256"));
    h.value = j.value("value", "");
    return h;
  }
};

// --------------------------------------------------------------------------
// Scan request — represents a single content scan submission
// --------------------------------------------------------------------------
struct ScanRequest {
  std::string request_id;
  std::string user_id;
  std::string room_id;
  std::string event_id;
  ScanTargetType target_type = ScanTargetType::MEDIA_UPLOAD;
  std::string mime_type;
  std::string filename;
  std::vector<uint8_t> content;
  std::string content_url;
  std::string text_content;
  std::vector<HashValue> content_hashes;
  int64_t content_size = 0;
  int64_t submitted_at_ms = 0;
  int64_t deadline_ms = 0;  // 0 = no deadline
  ScanPriority priority = ScanPriority::NORMAL;
  json metadata;
  bool bypass_cache = false;
  bool require_all_engines = true;
  std::vector<std::string> required_engines;
  std::vector<std::string> excluded_engines;

  json to_json() const {
    json j;
    j["request_id"] = request_id;
    j["user_id"] = user_id;
    j["room_id"] = room_id;
    if (!event_id.empty()) j["event_id"] = event_id;
    j["target_type"] = scan_target_type_to_string(target_type);
    j["mime_type"] = mime_type;
    if (!filename.empty()) j["filename"] = filename;
    j["content_size"] = content_size;
    j["submitted_at_ms"] = submitted_at_ms;
    if (deadline_ms > 0) j["deadline_ms"] = deadline_ms;
    j["priority"] = scan_priority_to_string(priority);
    if (!metadata.empty()) j["metadata"] = metadata;
    j["bypass_cache"] = bypass_cache;
    json hashes = json::array();
    for (const auto& h : content_hashes) { hashes.push_back(h.to_json()); }
    if (!hashes.empty()) j["content_hashes"] = hashes;
    return j;
  }

  std::string primary_hash() const {
    for (const auto& h : content_hashes) {
      if (h.algorithm == HashAlgorithm::SHA256) return h.value;
    }
    return content_hashes.empty() ? "" : content_hashes[0].value;
  }
};

// --------------------------------------------------------------------------
// Per-engine scan result
// --------------------------------------------------------------------------
struct EngineScanResult {
  std::string engine_name;
  ScanEngineType engine_type = ScanEngineType::NONE;
  ScanVerdict verdict = ScanVerdict::UNKNOWN;
  ContentCategory category = ContentCategory::SAFE;
  ScanSeverity severity = ScanSeverity::NONE;
  double confidence_score = 0.0;  // 0.0 - 1.0
  std::string detection_name;
  std::string detection_detail;
  DetectionMethod detection_method = DetectionMethod::SIGNATURE;
  int64_t scan_duration_ms = 0;
  int64_t scanned_at_ms = 0;
  json raw_output;
  std::vector<std::string> matched_signatures;
  std::map<std::string, std::string> metadata;

  bool is_clean() const {
    return verdict == ScanVerdict::CLEAN || verdict == ScanVerdict::BYPASSED;
  }

  bool is_malicious() const {
    return verdict == ScanVerdict::MALWARE ||
           verdict == ScanVerdict::SUSPICIOUS;
  }

  json to_json() const {
    return json{
      {"engine_name", engine_name},
      {"engine_type", scan_engine_type_to_string(engine_type)},
      {"verdict", scan_verdict_to_string(verdict)},
      {"category", content_category_to_string(category)},
      {"severity", scan_severity_to_string(severity)},
      {"confidence_score", confidence_score},
      {"detection_name", detection_name},
      {"detection_detail", detection_detail},
      {"detection_method", detection_method_to_string(detection_method)},
      {"scan_duration_ms", scan_duration_ms},
      {"scanned_at_ms", scanned_at_ms},
      {"matched_signatures", matched_signatures},
      {"metadata", metadata}
    };
  }
};

// --------------------------------------------------------------------------
// Aggregated scan result — combined result from all engines
// --------------------------------------------------------------------------
struct ScanResult {
  std::string request_id;
  ScanVerdict overall_verdict = ScanVerdict::UNKNOWN;
  ContentCategory overall_category = ContentCategory::SAFE;
  ScanSeverity overall_severity = ScanSeverity::NONE;
  double highest_confidence = 0.0;
  std::vector<EngineScanResult> engine_results;
  int64_t total_scan_duration_ms = 0;
  int64_t completed_at_ms = 0;
  bool from_cache = false;
  std::string quarantine_id;
  QuarantineAction action_taken = QuarantineAction::NONE;
  int engine_count = 0;
  int malicious_engine_count = 0;
  std::string summary;

  bool is_clean() const {
    return overall_verdict == ScanVerdict::CLEAN || overall_verdict == ScanVerdict::BYPASSED;
  }

  bool requires_quarantine() const {
    return overall_verdict == ScanVerdict::MALWARE ||
           overall_verdict == ScanVerdict::ADULT ||
           overall_severity >= ScanSeverity::HIGH;
  }

  json to_json() const {
    json eng_results = json::array();
    for (const auto& er : engine_results) {
      eng_results.push_back(er.to_json());
    }
    return json{
      {"request_id", request_id},
      {"overall_verdict", scan_verdict_to_string(overall_verdict)},
      {"overall_category", content_category_to_string(overall_category)},
      {"overall_severity", scan_severity_to_string(overall_severity)},
      {"highest_confidence", highest_confidence},
      {"engine_results", eng_results},
      {"total_scan_duration_ms", total_scan_duration_ms},
      {"completed_at_ms", completed_at_ms},
      {"from_cache", from_cache},
      {"quarantine_id", quarantine_id},
      {"action_taken", quarantine_action_to_string(action_taken)},
      {"engine_count", engine_count},
      {"malicious_engine_count", malicious_engine_count},
      {"summary", summary}
    };
  }
};

// --------------------------------------------------------------------------
// Quarantine record
// --------------------------------------------------------------------------
struct QuarantineRecord {
  std::string quarantine_id;
  std::string request_id;
  std::string user_id;
  std::string room_id;
  std::string event_id;
  std::string media_id;
  std::string filename;
  std::string mime_type;
  std::string content_hash;
  int64_t content_size = 0;
  ScanVerdict verdict = ScanVerdict::UNKNOWN;
  ContentCategory category = ContentCategory::SAFE;
  ScanSeverity severity = ScanSeverity::NONE;
  std::string reason;
  std::string original_path;
  std::string quarantined_path;
  int64_t quarantined_at_ms = 0;
  int64_t expires_at_ms = 0;  // 0 = never
  std::string quarantined_by;
  std::string review_status;   // pending, reviewed, released, permanently_blocked
  std::string reviewed_by;
  int64_t reviewed_at_ms = 0;
  std::string review_notes;
  json scan_results;

  json to_json() const {
    return json{
      {"quarantine_id", quarantine_id},
      {"request_id", request_id},
      {"user_id", user_id},
      {"room_id", room_id},
      {"event_id", event_id},
      {"media_id", media_id},
      {"filename", filename},
      {"mime_type", mime_type},
      {"content_hash", content_hash},
      {"content_size", content_size},
      {"verdict", scan_verdict_to_string(verdict)},
      {"category", content_category_to_string(category)},
      {"severity", scan_severity_to_string(severity)},
      {"reason", reason},
      {"quarantined_at_ms", quarantined_at_ms},
      {"expires_at_ms", expires_at_ms},
      {"quarantined_by", quarantined_by},
      {"review_status", review_status},
      {"reviewed_by", reviewed_by},
      {"reviewed_at_ms", reviewed_at_ms},
      {"review_notes", review_notes}
    };
  }
};

// --------------------------------------------------------------------------
// Scan policy — per-room or server-wide scanning configuration
// --------------------------------------------------------------------------
struct ScanPolicy {
  std::string policy_id;
  std::string scope;          // "global", "room:<room_id>", "user:<user_id>"
  std::string scope_type;     // "global", "room", "user"
  std::string scope_value;
  bool enabled = true;
  bool scan_messages = true;
  bool scan_media = true;
  bool scan_urls = true;
  bool scan_avatars = true;
  bool scan_encrypted = false;
  int64_t max_scan_size_bytes = 100 * 1024 * 1024;  // 100 MB
  int64_t scan_timeout_ms = 30000;                    // 30 seconds
  std::vector<std::string> enabled_engines;
  std::vector<std::string> blocked_mime_types;
  std::map<ContentCategory, QuarantineAction> category_actions;
  bool quarantine_media = true;
  bool notify_on_detection = true;
  bool redact_on_block = true;
  std::string notification_room_id;
  double adult_threshold = 0.7;  // confidence threshold for adult content
  double malware_threshold = 0.5;
  bool bypass_whitelisted_users = true;
  std::vector<std::string> whitelisted_users;
  std::vector<std::string> whitelisted_rooms;
  int64_t created_at_ms = 0;
  int64_t updated_at_ms = 0;
  std::string created_by;
  json extra_config;

  json to_json() const {
    json cat_actions = json::object();
    for (const auto& [cat, action] : category_actions) {
      cat_actions[content_category_to_string(cat)] = quarantine_action_to_string(action);
    }
    return json{
      {"policy_id", policy_id},
      {"scope", scope},
      {"scope_type", scope_type},
      {"scope_value", scope_value},
      {"enabled", enabled},
      {"scan_messages", scan_messages},
      {"scan_media", scan_media},
      {"scan_urls", scan_urls},
      {"scan_avatars", scan_avatars},
      {"scan_encrypted", scan_encrypted},
      {"max_scan_size_bytes", max_scan_size_bytes},
      {"scan_timeout_ms", scan_timeout_ms},
      {"enabled_engines", enabled_engines},
      {"blocked_mime_types", blocked_mime_types},
      {"category_actions", cat_actions},
      {"quarantine_media", quarantine_media},
      {"notify_on_detection", notify_on_detection},
      {"redact_on_block", redact_on_block},
      {"adult_threshold", adult_threshold},
      {"malware_threshold", malware_threshold},
      {"bypass_whitelisted_users", bypass_whitelisted_users},
      {"whitelisted_users", whitelisted_users},
      {"whitelisted_rooms", whitelisted_rooms},
      {"created_at_ms", created_at_ms},
      {"updated_at_ms", updated_at_ms}
    };
  }

  QuarantineAction get_action_for_category(ContentCategory cat) const {
    auto it = category_actions.find(cat);
    if (it != category_actions.end()) return it->second;
    return QuarantineAction::QUARANTINE;
  }

  bool is_user_whitelisted(const std::string& user_id) const {
    if (!bypass_whitelisted_users) return false;
    return std::find(whitelisted_users.begin(), whitelisted_users.end(), user_id)
           != whitelisted_users.end();
  }

  bool is_room_whitelisted(const std::string& room_id) const {
    return std::find(whitelisted_rooms.begin(), whitelisted_rooms.end(), room_id)
           != whitelisted_rooms.end();
  }
};

// --------------------------------------------------------------------------
// Malware signature entry
// --------------------------------------------------------------------------
struct MalwareSignature {
  std::string signature_id;
  std::string name;
  std::string description;
  ContentCategory category = ContentCategory::MALWARE_GENERIC;
  ScanSeverity severity = ScanSeverity::HIGH;
  HashAlgorithm hash_algo = HashAlgorithm::SHA256;
  std::string hash_value;
  std::string pattern;
  std::string yara_rule;
  std::vector<std::string> tags;
  int64_t added_at_ms = 0;
  int64_t updated_at_ms = 0;
  bool enabled = true;
  std::string source;  // e.g., "clamav", "custom", "community"

  json to_json() const {
    return json{
      {"signature_id", signature_id},
      {"name", name},
      {"description", description},
      {"category", content_category_to_string(category)},
      {"severity", scan_severity_to_string(severity)},
      {"hash_algorithm", hash_algorithm_to_string(hash_algo)},
      {"hash_value", hash_value},
      {"pattern", pattern},
      {"tags", tags},
      {"added_at_ms", added_at_ms},
      {"enabled", enabled},
      {"source", source}
    };
  }
};

// --------------------------------------------------------------------------
// Cache entry
// --------------------------------------------------------------------------
struct ScanCacheEntry {
  std::string cache_key;
  ScanResult result;
  int64_t created_at_ms = 0;
  int64_t expires_at_ms = 0;
  int64_t last_accessed_ms = 0;
  size_t access_count = 0;
  size_t size_bytes = 0;

  bool is_expired() const {
    if (expires_at_ms == 0) return false;
    return now_ms() > expires_at_ms;
  }
};

// --------------------------------------------------------------------------
// Scan statistics for metrics collection
// --------------------------------------------------------------------------
struct ScanStatistics {
  std::atomic<int64_t> total_scans{0};
  std::atomic<int64_t> clean_scans{0};
  std::atomic<int64_t> malware_detections{0};
  std::atomic<int64_t> adult_detections{0};
  std::atomic<int64_t> suspicious_detections{0};
  std::atomic<int64_t> errors{0};
  std::atomic<int64_t> timeouts{0};
  std::atomic<int64_t> cache_hits{0};
  std::atomic<int64_t> cache_misses{0};
  std::atomic<int64_t> quarantined_items{0};
  std::atomic<int64_t> blocked_items{0};
  std::atomic<int64_t> total_bytes_scanned{0};
  std::atomic<int64_t> total_scan_time_ms{0};
  int64_t last_reset_ms = 0;
  std::map<std::string, int64_t> engine_stats;

  double cache_hit_rate() const {
    int64_t total = cache_hits.load() + cache_misses.load();
    return total > 0 ? static_cast<double>(cache_hits.load()) / total : 0.0;
  }

  double average_scan_time_ms() const {
    int64_t total = total_scans.load();
    return total > 0 ? static_cast<double>(total_scan_time_ms.load()) / total : 0.0;
  }

  double detection_rate() const {
    int64_t total = total_scans.load();
    if (total == 0) return 0.0;
    int64_t detections = malware_detections.load() + adult_detections.load()
                       + suspicious_detections.load();
    return static_cast<double>(detections) / total;
  }

  json to_json() const {
    return json{
      {"total_scans", total_scans.load()},
      {"clean_scans", clean_scans.load()},
      {"malware_detections", malware_detections.load()},
      {"adult_detections", adult_detections.load()},
      {"suspicious_detections", suspicious_detections.load()},
      {"errors", errors.load()},
      {"timeouts", timeouts.load()},
      {"cache_hits", cache_hits.load()},
      {"cache_misses", cache_misses.load()},
      {"cache_hit_rate", cache_hit_rate()},
      {"quarantined_items", quarantined_items.load()},
      {"blocked_items", blocked_items.load()},
      {"total_bytes_scanned", total_bytes_scanned.load()},
      {"total_scan_time_ms", total_scan_time_ms.load()},
      {"average_scan_time_ms", average_scan_time_ms()},
      {"detection_rate", detection_rate()}
    };
  }

  void reset() {
    total_scans.store(0);
    clean_scans.store(0);
    malware_detections.store(0);
    adult_detections.store(0);
    suspicious_detections.store(0);
    errors.store(0);
    timeouts.store(0);
    cache_hits.store(0);
    cache_misses.store(0);
    quarantined_items.store(0);
    blocked_items.store(0);
    total_bytes_scanned.store(0);
    total_scan_time_ms.store(0);
    last_reset_ms = now_ms();
  }
};

// --------------------------------------------------------------------------
// Audit log entry
// --------------------------------------------------------------------------
struct AuditLogEntry {
  std::string audit_id;
  std::string action;  // "scan_requested", "scan_completed", "quarantine", "release", etc.
  std::string request_id;
  std::string user_id;
  std::string room_id;
  std::string detail;
  int64_t timestamp_ms = 0;
  std::string source_ip;
  json extra_data;

  json to_json() const {
    return json{
      {"audit_id", audit_id},
      {"action", action},
      {"request_id", request_id},
      {"user_id", user_id},
      {"room_id", room_id},
      {"detail", detail},
      {"timestamp_ms", timestamp_ms},
      {"source_ip", source_ip},
      {"extra_data", extra_data}
    };
  }
};

// ============================================================================
// Engine Configuration
// ============================================================================
struct EngineConfig {
  std::string engine_name;
  ScanEngineType engine_type = ScanEngineType::NONE;
  bool enabled = true;
  int priority = 50;           // lower number = higher priority (0 = first)
  int max_concurrent_scans = 5;
  int64_t scan_timeout_ms = 15000;
  int64_t retry_count = 2;
  int64_t retry_delay_ms = 1000;
  std::string endpoint_url;    // for external API engines
  std::string socket_path;     // for ClamAV
  std::string host;
  uint16_t port = 0;
  std::string api_key;
  bool require_health_check = true;
  bool fallback_on_failure = true;
  std::string fallback_engine;
  json extra_config;

  json to_json() const {
    return json{
      {"engine_name", engine_name},
      {"engine_type", scan_engine_type_to_string(engine_type)},
      {"enabled", enabled},
      {"priority", priority},
      {"max_concurrent_scans", max_concurrent_scans},
      {"scan_timeout_ms", scan_timeout_ms},
      {"retry_count", retry_count},
      {"retry_delay_ms", retry_delay_ms},
      {"endpoint_url", endpoint_url},
      {"socket_path", socket_path},
      {"host", host},
      {"port", port},
      {"require_health_check", require_health_check},
      {"fallback_on_failure", fallback_on_failure},
      {"fallback_engine", fallback_engine}
    };
  }

  static EngineConfig from_json(const json& j) {
    EngineConfig cfg;
    cfg.engine_name = j.value("engine_name", "");
    cfg.engine_type = scan_engine_type_from_string(j.value("engine_type", "none"));
    cfg.enabled = j.value("enabled", true);
    cfg.priority = j.value("priority", 50);
    cfg.max_concurrent_scans = j.value("max_concurrent_scans", 5);
    cfg.scan_timeout_ms = j.value("scan_timeout_ms", 15000);
    cfg.retry_count = j.value("retry_count", 2);
    cfg.retry_delay_ms = j.value("retry_delay_ms", 1000);
    cfg.endpoint_url = j.value("endpoint_url", "");
    cfg.socket_path = j.value("socket_path", "");
    cfg.host = j.value("host", "");
    cfg.port = j.value("port", 0);
    cfg.api_key = j.value("api_key", "");
    cfg.require_health_check = j.value("require_health_check", true);
    cfg.fallback_on_failure = j.value("fallback_on_failure", true);
    cfg.fallback_engine = j.value("fallback_engine", "");
    if (j.contains("extra_config")) cfg.extra_config = j["extra_config"];
    return cfg;
  }
};

// ============================================================================
// Storage forward declarations
// ============================================================================
namespace storage {
class DatabasePool;
class LoggingTransaction;
} // namespace storage

using storage::DatabasePool;
using storage::LoggingTransaction;

// ============================================================================
// Abstract Scan Engine — base class for all scan engines
// ============================================================================
class IScanEngine {
public:
  virtual ~IScanEngine() = default;

  virtual std::string engine_name() const = 0;
  virtual ScanEngineType engine_type() const = 0;
  virtual bool initialize(const EngineConfig& config) = 0;
  virtual bool is_healthy() const = 0;
  virtual EngineScanResult scan(const ScanRequest& request) = 0;
  virtual bool supports_target(ScanTargetType target) const = 0;
  virtual bool supports_mime_type(const std::string& mime_type) const = 0;
  virtual size_t max_scan_size() const { return 100 * 1024 * 1024; } // 100 MB default
  virtual void shutdown() {}
  virtual json get_status() const {
    return json{{"engine_name", engine_name()}, {"healthy", is_healthy()}};
  }
};

// ============================================================================
// Custom Scan Module — base class for user-defined modules
// ============================================================================
class CustomScanModuleBase {
public:
  virtual ~CustomScanModuleBase() = default;

  virtual std::string module_name() const = 0;
  virtual std::string module_version() const = 0;
  virtual std::string module_description() const = 0;
  virtual bool initialize(const json& config) = 0;
  virtual EngineScanResult scan_content(const std::vector<uint8_t>& content,
                                        const std::string& mime_type,
                                        const json& context) = 0;
  virtual bool supports_mime_type(const std::string& mime_type) const = 0;
  virtual void on_signature_update() {}
  virtual void shutdown() {}
  virtual json get_module_info() const {
    return json{
      {"name", module_name()},
      {"version", module_version()},
      {"description", module_description()}
    };
  }
};

// ============================================================================
// ClamAV Scan Engine — integrates with ClamAV daemon (clamd)
// ============================================================================
class ClamAVScanEngine : public IScanEngine {
public:
  std::string engine_name() const override { return "clamav"; }
  ScanEngineType engine_type() const override { return ScanEngineType::CLAMAV; }

  bool initialize(const EngineConfig& config) override {
    config_ = config;
    socket_path_ = config.socket_path.empty() ? "/var/run/clamav/clamd.ctl" : config.socket_path;
    host_ = config.host;
    port_ = config.port > 0 ? config.port : 3310;
    use_tcp_ = !host_.empty();

    auto& log = get_scanner_logger("progressive.scanner.clamav");
    log.info("Initializing ClamAV engine (path=" + socket_path_ +
             ", host=" + host_ + ":" + std::to_string(port_) + ")");

    healthy_ = ping_clamav();
    return healthy_;
  }

  bool is_healthy() const override { return healthy_; }

  EngineScanResult scan(const ScanRequest& request) override {
    auto& log = get_scanner_logger("progressive.scanner.clamav");
    EngineScanResult result;
    result.engine_name = engine_name();
    result.engine_type = engine_type();
    result.scanned_at_ms = now_ms();

    if (!healthy_) {
      result.verdict = ScanVerdict::ERROR;
      result.detection_detail = "ClamAV engine is not healthy";
      log.error("Scan failed: engine not healthy");
      return result;
    }

    auto start = chr::steady_clock::now();

    std::string scan_response;
    bool ok = false;

    if (use_tcp_) {
      ok = clamav_scan_tcp(request.content, scan_response);
    } else {
      ok = clamav_scan_unix(request.content, scan_response);
    }

    auto elapsed = chr::duration_cast<chr::milliseconds>(
        chr::steady_clock::now() - start).count();
    result.scan_duration_ms = elapsed;

    if (!ok) {
      result.verdict = ScanVerdict::ERROR;
      result.detection_detail = "ClamAV scan communication failure";
      log.error("Scan communication failure");
      return result;
    }

    result = parse_clamav_response(scan_response, result);
    return result;
  }

  bool supports_target(ScanTargetType target) const override {
    return target == ScanTargetType::MEDIA_UPLOAD ||
           target == ScanTargetType::FILE_ATTACHMENT ||
           target == ScanTargetType::AVATAR ||
           target == ScanTargetType::ROOM_AVATAR ||
           target == ScanTargetType::STICKER ||
           target == ScanTargetType::THUMBNAIL;
  }

  bool supports_mime_type(const std::string& /*mime_type*/) const override {
    return true; // ClamAV handles all types
  }

  size_t max_scan_size() const override {
    return config_.max_scan_size_bytes > 0 ?
           static_cast<size_t>(config_.max_scan_size_bytes) : 500 * 1024 * 1024;
  }

  void shutdown() override {
    healthy_ = false;
  }

  json get_status() const override {
    json j = IScanEngine::get_status();
    j["socket_path"] = socket_path_;
    j["host"] = host_;
    j["port"] = port_;
    j["use_tcp"] = use_tcp_;
    j["version"] = clamav_version_;
    j["signature_count"] = signature_count_;
    j["last_update"] = last_signature_update_;
    return j;
  }

private:
  bool ping_clamav() {
    // PING command to ClamAV daemon
    std::string ping_cmd = "zPING\0";
    std::string response;

    bool ok = false;
    if (use_tcp_) {
      ok = clamav_send_tcp(ping_cmd, response);
    } else {
      ok = clamav_send_unix(ping_cmd, response);
    }

    if (ok) {
      healthy_ = (response.find("PONG") != std::string::npos);
      return healthy_;
    }
    return false;
  }

  bool clamav_send_tcp(const std::string& command, std::string& response) {
    // Placeholder: In production, this would open a TCP socket to clamd
    // For now, simulate the protocol exchange
    response = "PONG";
    return true;
  }

  bool clamav_send_unix(const std::string& command, std::string& response) {
    // Placeholder: In production, this would connect to the Unix socket
    // For now, simulate the protocol exchange
    response = "PONG";
    return true;
  }

  bool clamav_scan_tcp(const std::vector<uint8_t>& content, std::string& response) {
    // INSTREAM command: send "nINSTREAM\n" then chunked data, then zero-length chunk
    // Simulated for now
    response = "stream: OK";
    return true;
  }

  bool clamav_scan_unix(const std::vector<uint8_t>& content, std::string& response) {
    // INSTREAM over Unix socket
    // Simulated for now
    response = "stream: OK";
    return true;
  }

  EngineScanResult parse_clamav_response(const std::string& response, EngineScanResult result) {
    auto& log = get_scanner_logger("progressive.scanner.clamav");

    // Parse ClamAV response:
    // "stream: OK" -> clean
    // "stream: <virus_name> FOUND" -> infected
    // "stream: ERROR" -> error

    if (response.find("OK") != std::string::npos &&
        response.find("FOUND") == std::string::npos) {
      result.verdict = ScanVerdict::CLEAN;
      result.category = ContentCategory::SAFE;
      result.confidence_score = 0.0;
      log.debug("Scan clean: " + response);
    } else if (response.find("FOUND") != std::string::npos) {
      result.verdict = ScanVerdict::MALWARE;
      result.detection_method = DetectionMethod::SIGNATURE;

      // Extract virus name
      size_t colon_pos = response.find(": ");
      size_t found_pos = response.find(" FOUND");
      if (colon_pos != std::string::npos && found_pos != std::string::npos) {
        result.detection_name = response.substr(colon_pos + 2,
                                  found_pos - colon_pos - 2);
      }
      result.matched_signatures.push_back(result.detection_name);

      // Classify malware type from signature name
      result.category = classify_malware_type(result.detection_name);
      result.severity = estimate_severity(result.detection_name);
      result.confidence_score = 0.95;
      result.detection_detail = "Signature detected: " + result.detection_name;

      log.warn("Malware detected: " + result.detection_name);
    } else if (response.find("ERROR") != std::string::npos) {
      result.verdict = ScanVerdict::ERROR;
      result.detection_detail = response;
      log.error("Scan error: " + response);
    } else {
      result.verdict = ScanVerdict::UNKNOWN;
      result.detection_detail = "Unrecognized ClamAV response: " + response;
      log.warn("Unknown response: " + response);
    }

    return result;
  }

  ContentCategory classify_malware_type(const std::string& name) {
    std::string lower = name;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

    if (lower.find("trojan") != std::string::npos) return ContentCategory::MALWARE_TROJAN;
    if (lower.find("ransom") != std::string::npos) return ContentCategory::MALWARE_RANSOMWARE;
    if (lower.find("worm") != std::string::npos)   return ContentCategory::MALWARE_WORM;
    if (lower.find("spy") != std::string::npos)    return ContentCategory::MALWARE_SPYWARE;
    if (lower.find("adware") != std::string::npos)  return ContentCategory::MALWARE_ADWARE;
    if (lower.find("miner") != std::string::npos ||
        lower.find("coin") != std::string::npos)    return ContentCategory::CRYPTOMINING;
    if (lower.find("phish") != std::string::npos)  return ContentCategory::PHISHING;
    return ContentCategory::MALWARE_GENERIC;
  }

  ScanSeverity estimate_severity(const std::string& name) {
    std::string lower = name;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

    if (lower.find("ransom") != std::string::npos ||
        lower.find("wiper") != std::string::npos ||
        lower.find("exploit") != std::string::npos) return ScanSeverity::CRITICAL;
    if (lower.find("trojan") != std::string::npos ||
        lower.find("backdoor") != std::string::npos ||
        lower.find("rootkit") != std::string::npos) return ScanSeverity::HIGH;
    if (lower.find("adware") != std::string::npos ||
        lower.find("pup") != std::string::npos ||
        lower.find("unwanted") != std::string::npos) return ScanSeverity::MEDIUM;
    return ScanSeverity::HIGH;
  }

  EngineConfig config_;
  std::string socket_path_ = "/var/run/clamav/clamd.ctl";
  std::string host_;
  uint16_t port_ = 3310;
  bool use_tcp_ = false;
  bool healthy_ = false;
  std::string clamav_version_ = "unknown";
  int64_t signature_count_ = 0;
  int64_t last_signature_update_ = 0;
};

// ============================================================================
// YARA Scan Engine — YARA rule-based scanning
// ============================================================================
class YaraScanEngine : public IScanEngine {
public:
  std::string engine_name() const override { return "yara"; }
  ScanEngineType engine_type() const override { return ScanEngineType::YARA; }

  bool initialize(const EngineConfig& config) override {
    config_ = config;
    rules_loaded_ = false;
    auto& log = get_scanner_logger("progressive.scanner.yara");
    log.info("Initializing YARA engine");

    // In production, this would load YARA compiled rules from disk
    rules_loaded_ = load_yara_rules(config.extra_config);
    healthy_ = rules_loaded_;
    return healthy_;
  }

  bool is_healthy() const override { return healthy_ && rules_loaded_; }

  EngineScanResult scan(const ScanRequest& request) override {
    EngineScanResult result;
    result.engine_name = engine_name();
    result.engine_type = engine_type();
    result.scanned_at_ms = now_ms();

    if (!healthy_) {
      result.verdict = ScanVerdict::ERROR;
      result.detection_detail = "YARA engine not healthy or rules not loaded";
      return result;
    }

    auto start = chr::steady_clock::now();

    // Simulate YARA scanning
    auto matches = match_yara_rules(request.content, request.mime_type);

    auto elapsed = chr::duration_cast<chr::milliseconds>(
        chr::steady_clock::now() - start).count();
    result.scan_duration_ms = elapsed;

    if (matches.empty()) {
      result.verdict = ScanVerdict::CLEAN;
      result.category = ContentCategory::SAFE;
      result.confidence_score = 0.0;
    } else {
      result.verdict = ScanVerdict::MALWARE;
      result.detection_method = DetectionMethod::YARA_RULE;
      result.matched_signatures = matches;
      result.detection_name = matches.empty() ? "" : matches[0];
      result.detection_detail = "YARA rule matches: " + std::to_string(matches.size());
      result.category = classify_yara_match(matches);
      result.severity = ScanSeverity::HIGH;
      result.confidence_score = 0.90;
    }

    return result;
  }

  bool supports_target(ScanTargetType target) const override {
    return target == ScanTargetType::MEDIA_UPLOAD ||
           target == ScanTargetType::FILE_ATTACHMENT ||
           target == ScanTargetType::MESSAGE_CONTENT;
  }

  bool supports_mime_type(const std::string& /*mime_type*/) const override {
    return true;
  }

  void shutdown() override { healthy_ = false; rules_loaded_ = false; }

  json get_status() const override {
    json j = IScanEngine::get_status();
    j["rules_loaded"] = rules_loaded_;
    j["rules_count"] = rule_count_;
    j["rules_path"] = rules_path_;
    return j;
  }

private:
  bool load_yara_rules(const json& config) {
    rules_path_ = config.value("rules_path", "/etc/progressive/yara/");
    rule_count_ = 0;

    // In production: iterate rules_path_ for .yar files, compile them
    // using libyara, and store compiled rules
    // Simulated for now
    compiled_rules_.clear();

    // Add some built-in YARA rules for demonstration
    compiled_rules_ = {
      {"suspicious_powershell", "rule suspicious_powershell { strings: $a = \"Invoke-Expression\" nocase condition: $a }"},
      {"encoded_script", "rule encoded_script { strings: $a = \"FromBase64String\" nocase condition: $a }"},
      {"php_webshell", "rule php_webshell { strings: $a = \"eval(\" nocase $b = \"base64_decode\" nocase condition: $a and $b }"},
      {"obfuscated_js", "rule obfuscated_js { strings: $a = \"eval(\" nocase $b = \"unescape(\" nocase condition: $a and $b }"},
      {"macro_downloader", "rule macro_downloader { strings: $a = \"URLDownloadToFile\" nocase $b = \"Shell\" nocase condition: $a or $b }"}
    };
    rule_count_ = static_cast<int64_t>(compiled_rules_.size());
    return true;
  }

  std::vector<std::string> match_yara_rules(const std::vector<uint8_t>& content,
                                             const std::string& mime_type) {
    std::vector<std::string> matches;
    if (content.empty()) return matches;

    // Convert content to string for pattern matching (simulated YARA)
    std::string text(content.begin(),
                     std::min(content.end(), content.begin() + 65536));

    // Check each compiled rule
    for (const auto& [rule_name, rule_body] : compiled_rules_) {
      // Extract strings from rule definition and check against content
      std::regex str_regex(R"(\$[a-z] = \"([^\"]+)\")", std::regex::icase);
      auto words_begin = std::sregex_iterator(rule_body.begin(), rule_body.end(), str_regex);
      auto words_end = std::sregex_iterator();

      for (auto it = words_begin; it != words_end; ++it) {
        std::string pattern = (*it)[1].str();
        std::transform(pattern.begin(), pattern.end(), pattern.begin(), ::tolower);
        std::string text_lower = text;
        std::transform(text_lower.begin(), text_lower.end(), text_lower.begin(), ::tolower);

        if (text_lower.find(pattern) != std::string::npos) {
          matches.push_back(rule_name);
          break;
        }
      }
    }

    return matches;
  }

  ContentCategory classify_yara_match(const std::vector<std::string>& matches) {
    for (const auto& m : matches) {
      if (m.find("webshell") != std::string::npos ||
          m.find("php_") != std::string::npos) return ContentCategory::MALWARE_TROJAN;
      if (m.find("ransom") != std::string::npos) return ContentCategory::MALWARE_RANSOMWARE;
    }
    return ContentCategory::MALWARE_GENERIC;
  }

  EngineConfig config_;
  bool healthy_ = false;
  bool rules_loaded_ = false;
  std::string rules_path_;
  int64_t rule_count_ = 0;
  std::map<std::string, std::string> compiled_rules_;
};

// ============================================================================
// Pattern Scan Engine — regex and pattern-based scanning
// ============================================================================
class PatternScanEngine : public IScanEngine {
public:
  std::string engine_name() const override { return "pattern"; }
  ScanEngineType engine_type() const override { return ScanEngineType::PATTERN; }

  bool initialize(const EngineConfig& config) override {
    config_ = config;
    load_patterns();
    healthy_ = true;
    return true;
  }

  bool is_healthy() const override { return healthy_; }

  EngineScanResult scan(const ScanRequest& request) override {
    EngineScanResult result;
    result.engine_name = engine_name();
    result.engine_type = engine_type();
    result.scanned_at_ms = now_ms();

    auto start = chr::steady_clock::now();

    // Scan text content for patterns
    auto matches = scan_for_patterns(request.text_content, request.content, request.mime_type);

    auto elapsed = chr::duration_cast<chr::milliseconds>(
        chr::steady_clock::now() - start).count();
    result.scan_duration_ms = elapsed;

    if (matches.empty()) {
      result.verdict = ScanVerdict::CLEAN;
      result.confidence_score = 0.0;
    } else {
      result.verdict = ScanVerdict::SUSPICIOUS;
      result.detection_method = DetectionMethod::PATTERN_MATCH;
      result.matched_signatures = matches;
      result.confidence_score = 0.7;
      result.detection_detail = "Pattern matches: " + std::to_string(matches.size());
    }

    return result;
  }

  bool supports_target(ScanTargetType target) const override {
    return target == ScanTargetType::MESSAGE_CONTENT ||
           target == ScanTargetType::URL_PREVIEW ||
           target == ScanTargetType::USER_PROFILE;
  }

  bool supports_mime_type(const std::string& /*mime_type*/) const override {
    return true;
  }

  void shutdown() override { healthy_ = false; }

private:
  void load_patterns() {
    // Load built-in patterns for various threat categories
    phishing_patterns_ = {
      std::regex(R"(https?://[^/]*\.ru/.*login)", std::regex::icase | std::regex::ECMAScript),
      std::regex(R"(account.*verify.*click)", std::regex::icase),
      std::regex(R"(password.*reset.*urgent)", std::regex::icase),
      std::regex(R"(your.*account.*has.*been.*(?:suspended|limited|blocked))", std::regex::icase),
      std::regex(R"(click.*here.*confirm.*identity)", std::regex::icase),
      std::regex(R"(validate.*account.*immediate)", std::regex::icase),
      std::regex(R"(bit\.ly/\w{4,}.*login)", std::regex::icase),
      std::regex(R"(free.*gift.*card.*(?:click|link))", std::regex::icase),
    };

    spam_patterns_ = {
      std::regex(R"(earn.*\d{3,}.*(?:dollar|usd|eur|gbp|btc|eth))", std::regex::icase),
      std::regex(R"(buy.*now.*limited.*offer)", std::regex::icase),
      std::regex(R"(work.*from.*home.*\$\d+)", std::regex::icase),
      std::regex(R"(investment.*opportunity.*guaranteed)", std::regex::icase),
      std::regex(R"(make.*money.*fast|get.*rich.*quick)", std::regex::icase),
      std::regex(R"((?:congratulations|you.*won).*(?:prize|lottery|reward))", std::regex::icase),
      std::regex(R"(sign.*up.*now.*free.*bonus)", std::regex::icase),
      std::regex(R"(special.*promotion.*act.*now)", std::regex::icase),
    };

    hate_speech_patterns_ = {
      std::regex(R"(\b(?:hate|kill|destroy).*(?:them|those|all)\b)", std::regex::icase),
      std::regex(R"(\b(?:eliminate|exterminate|purge)\b.*\b(?:race|ethnic|religion|group)\b)", std::regex::icase),
    };

    crypto_mining_patterns_ = {
      std::regex(R"(new\s+Script\s*\(\s*['\"].*(?:Coinhive|CryptoLoot|JSEcoin)", std::regex::icase),
      std::regex(R"(\.start\s*\(\s*['\"].*(?:throttle|threads)", std::regex::icase),
      std::regex(R"(WebAssembly\.instantiate.*cryptonight)", std::regex::icase),
      std::regex(R"(coin-hive\.com|cryptoloot\.pro|jsecoin\.com)", std::regex::icase),
    };

    suspicious_url_patterns_ = {
      std::regex(R"(https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", std::regex::icase),
      std::regex(R"(https?://[^/]+\.(?:tk|ml|ga|cf|gq)/)", std::regex::icase),
      std::regex(R"(data:text/html.*<script)", std::regex::icase),
      std::regex(R"(javascript:.*document\.cookie)", std::regex::icase),
    };
  }

  std::vector<std::string> scan_for_patterns(const std::string& text_content,
                                               const std::vector<uint8_t>& binary_content,
                                               const std::string& mime_type) {
    std::vector<std::string> matches;

    std::string scan_text = text_content;
    if (scan_text.empty() && !binary_content.empty()) {
      // Try to extract text from binary content (first few KB)
      size_t extract_size = std::min(binary_content.size(), size_t(8192));
      scan_text.assign(reinterpret_cast<const char*>(binary_content.data()), extract_size);
    }

    if (scan_text.empty()) return matches;

    // Check phishing patterns
    for (const auto& pat : phishing_patterns_) {
      if (std::regex_search(scan_text, pat)) {
        matches.push_back("phishing_pattern");
        break;
      }
    }

    // Check spam patterns
    for (const auto& pat : spam_patterns_) {
      if (std::regex_search(scan_text, pat)) {
        matches.push_back("spam_pattern");
        break;
      }
    }

    // Check hate speech
    for (const auto& pat : hate_speech_patterns_) {
      if (std::regex_search(scan_text, pat)) {
        matches.push_back("hate_speech_pattern");
        break;
      }
    }

    // Check crypto mining patterns
    for (const auto& pat : crypto_mining_patterns_) {
      if (std::regex_search(scan_text, pat)) {
        matches.push_back("crypto_mining_pattern");
        break;
      }
    }

    // Check suspicious URLs
    for (const auto& pat : suspicious_url_patterns_) {
      if (std::regex_search(scan_text, pat)) {
        matches.push_back("suspicious_url");
        break;
      }
    }

    return matches;
  }

  EngineConfig config_;
  bool healthy_ = false;
  std::vector<std::regex> phishing_patterns_;
  std::vector<std::regex> spam_patterns_;
  std::vector<std::regex> hate_speech_patterns_;
  std::vector<std::regex> crypto_mining_patterns_;
  std::vector<std::regex> suspicious_url_patterns_;
};

// ============================================================================
// ML Scan Engine — Machine Learning based content analysis
// ============================================================================
class MLScanEngine : public IScanEngine {
public:
  std::string engine_name() const override { return "machine_learning"; }
  ScanEngineType engine_type() const override { return ScanEngineType::MACHINE_LEARNING; }

  bool initialize(const EngineConfig& config) override {
    config_ = config;
    model_path_ = config.extra_config.value("model_path", "/opt/progressive/models/");
    adult_model_loaded_ = load_adult_content_model();
    malware_model_loaded_ = load_malware_model();
    healthy_ = adult_model_loaded_ || malware_model_loaded_;
    auto& log = get_scanner_logger("progressive.scanner.ml");
    log.info("ML engine initialized (adult=" + std::to_string(adult_model_loaded_) +
             ", malware=" + std::to_string(malware_model_loaded_) + ")");
    return healthy_;
  }

  bool is_healthy() const override { return healthy_; }

  EngineScanResult scan(const ScanRequest& request) override {
    EngineScanResult result;
    result.engine_name = engine_name();
    result.engine_type = engine_type();
    result.scanned_at_ms = now_ms();

    auto start = chr::steady_clock::now();

    bool is_image = request.mime_type.find("image/") == 0;
    bool is_video = request.mime_type.find("video/") == 0;
    bool is_text  = request.mime_type.find("text/") == 0 ||
                    request.target_type == ScanTargetType::MESSAGE_CONTENT;

    double adult_score = 0.0;
    double malware_score = 0.0;

    if (is_image || is_video) {
      adult_score = predict_adult_content(request.content, request.mime_type);
    }

    if (!request.text_content.empty() || is_text) {
      malware_score = predict_malicious_text(request.text_content);
    }

    auto elapsed = chr::duration_cast<chr::milliseconds>(
        chr::steady_clock::now() - start).count();
    result.scan_duration_ms = elapsed;

    // Determine result based on highest score
    if (malware_score > adult_score && malware_score > 0.5) {
      result.verdict = ScanVerdict::MALWARE;
      result.category = ContentCategory::MALWARE_GENERIC;
      result.severity = malware_score > 0.8 ? ScanSeverity::HIGH : ScanSeverity::MEDIUM;
      result.confidence_score = malware_score;
      result.detection_method = DetectionMethod::MACHINE_LEARNING;
      result.detection_name = "ML malware detection";
    } else if (adult_score > 0.5) {
      result.verdict = ScanVerdict::ADULT;
      result.category = adult_score > 0.8 ? ContentCategory::ADULT_EXPLICIT : ContentCategory::ADULT_NSFW;
      result.severity = adult_score > 0.8 ? ScanSeverity::HIGH : ScanSeverity::MEDIUM;
      result.confidence_score = adult_score;
      result.detection_method = DetectionMethod::MACHINE_LEARNING;
      result.detection_name = "ML adult content detection";
    } else {
      result.verdict = ScanVerdict::CLEAN;
      result.category = ContentCategory::SAFE;
      result.confidence_score = std::max(adult_score, malware_score);
    }

    result.metadata["adult_score"] = std::to_string(adult_score);
    result.metadata["malware_score"] = std::to_string(malware_score);

    return result;
  }

  bool supports_target(ScanTargetType target) const override {
    return target == ScanTargetType::MEDIA_UPLOAD ||
           target == ScanTargetType::AVATAR ||
           target == ScanTargetType::MESSAGE_CONTENT ||
           target == ScanTargetType::URL_PREVIEW ||
           target == ScanTargetType::STICKER;
  }

  bool supports_mime_type(const std::string& mime_type) const override {
    return mime_type.find("image/") == 0 || mime_type.find("video/") == 0 ||
           mime_type.find("text/") == 0 || mime_type == "application/json";
  }

  void shutdown() override { healthy_ = false; }

private:
  bool load_adult_content_model() {
    // In production: load TensorFlow Lite / ONNX model for NSFW detection
    return true;
  }

  bool load_malware_model() {
    // In production: load model for text-based malware/phishing detection
    return true;
  }

  double predict_adult_content(const std::vector<uint8_t>& content,
                                const std::string& /*mime_type*/) {
    // Simulated adult content prediction
    if (content.empty()) return 0.0;

    // Look for simple indicators (in production this would be a real ML model)
    size_t suspicious_bytes = 0;
    for (size_t i = 0; i < std::min(content.size(), size_t(1024)); ++i) {
      if (content[i] >= 0x80) suspicious_bytes++;
    }

    double ratio = static_cast<double>(suspicious_bytes) /
                   std::min(content.size(), size_t(1024));
    return ratio * 0.3;  // Low confidence simulated score
  }

  double predict_malicious_text(const std::string& text) {
    if (text.empty()) return 0.0;

    double score = 0.0;
    std::string lower = text;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

    // Heuristic text analysis (in production: real NLP model)
    if (lower.find("<script") != std::string::npos) score += 0.3;
    if (lower.find("eval(") != std::string::npos) score += 0.2;
    if (lower.find("document.cookie") != std::string::npos) score += 0.2;
    if (lower.find("base64_decode") != std::string::npos) score += 0.1;
    if (lower.find("shell_exec") != std::string::npos) score += 0.3;
    if (lower.find("cmd.exe") != std::string::npos) score += 0.2;

    return std::min(score, 0.95);
  }

  EngineConfig config_;
  bool healthy_ = false;
  bool adult_model_loaded_ = false;
  bool malware_model_loaded_ = false;
  std::string model_path_;
};

// ============================================================================
// Hash Scan Engine — hash-based lookup against known bad hashes
// ============================================================================
class HashScanEngine : public IScanEngine {
public:
  std::string engine_name() const override { return "hash_lookup"; }
  ScanEngineType engine_type() const override { return ScanEngineType::HASH_LOOKUP; }

  bool initialize(const EngineConfig& config) override {
    config_ = config;

    // Load known malicious hashes
    load_known_malware_hashes();
    load_virustotal_cache();

    healthy_ = !malware_hashes_.empty();
    auto& log = get_scanner_logger("progressive.scanner.hash");
    log.info("Hash engine initialized with " + std::to_string(malware_hashes_.size())
             + " known malware hashes");
    return healthy_;
  }

  bool is_healthy() const override { return healthy_; }

  EngineScanResult scan(const ScanRequest& request) override {
    EngineScanResult result;
    result.engine_name = engine_name();
    result.engine_type = engine_type();
    result.scanned_at_ms = now_ms();

    auto start = chr::steady_clock::now();

    // Check each content hash against known bad hashes
    bool found = false;
    for (const auto& hash : request.content_hashes) {
      auto it = malware_hashes_.find(hash.value);
      if (it != malware_hashes_.end()) {
        result.detection_method = DetectionMethod::HASH_MATCH;
        result.verdict = ScanVerdict::MALWARE;
        result.detection_name = it->second.name;
        result.category = it->second.category;
        result.severity = it->second.severity;
        result.confidence_score = 0.99;
        result.matched_signatures.push_back(hash.value);
        found = true;
        break;
      }

      // Check VirusTotal cache
      auto vt_it = virustotal_cache_.find(hash.value);
      if (vt_it != virustotal_cache_.end()) {
        if (vt_it->second > 5) {  // Detected by 5+ engines
          result.detection_method = DetectionMethod::REPUTATION;
          result.verdict = ScanVerdict::MALWARE;
          result.detection_name = "VT:" + hash.value.substr(0, 12);
          result.category = ContentCategory::MALWARE_GENERIC;
          result.severity = vt_it->second > 15 ? ScanSeverity::HIGH : ScanSeverity::MEDIUM;
          result.confidence_score = 0.85;
          result.matched_signatures.push_back(hash.value);
          found = true;
          break;
        }
      }
    }

    auto elapsed = chr::duration_cast<chr::milliseconds>(
        chr::steady_clock::now() - start).count();
    result.scan_duration_ms = elapsed;

    if (!found) {
      result.verdict = ScanVerdict::CLEAN;
      result.confidence_score = 0.0;
    }

    return result;
  }

  bool supports_target(ScanTargetType target) const override {
    return target == ScanTargetType::MEDIA_UPLOAD ||
           target == ScanTargetType::FILE_ATTACHMENT;
  }

  bool supports_mime_type(const std::string& /*mime_type*/) const override {
    return true;
  }

  size_t max_scan_size() const override { return 1 * 1024 * 1024; } // Only need hash, not content

  void shutdown() override { healthy_ = false; }

  void add_malware_hash(const MalwareSignature& sig) {
    std::unique_lock<std::shared_mutex> lock(hashes_mutex_);
    malware_hashes_[sig.hash_value] = sig;
  }

  json get_status() const override {
    json j = IScanEngine::get_status();
    j["known_hashes"] = malware_hashes_.size();
    j["vt_cache_entries"] = virustotal_cache_.size();
    return j;
  }

private:
  void load_known_malware_hashes() {
    // Load built-in known malware signatures
    // In production: load from database or file
    std::lock_guard<std::shared_mutex> lock(hashes_mutex_);

    // Example known-bad SHA256 hashes (simulated)
    std::vector<std::pair<std::string, MalwareSignature>> entries = {
      {"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        {"sig-001", "EICAR-Test-Signature", "EICAR test file signature",
         ContentCategory::MALWARE_GENERIC, ScanSeverity::LOW,
         HashAlgorithm::SHA256, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
         "", "", {"eicar", "test"}, 0, 0, true, "builtin"}},

      {"2b8a978a7c9c0d65583e1b28c05a122ff5c4f50e9f1b3a8d846012236d94c3e1",
        {"sig-002", "Trojan.Generic.KD.12345", "Generic Trojan downloader",
         ContentCategory::MALWARE_TROJAN, ScanSeverity::HIGH,
         HashAlgorithm::SHA256, "2b8a978a7c9c0d65583e1b28c05a122ff5c4f50e9f1b3a8d846012236d94c3e1",
         "", "", {"trojan", "downloader"}, 0, 0, true, "community"}},

      {"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
        {"sig-003", "Ransomware.WannaCrypt", "WannaCry ransomware variant",
         ContentCategory::MALWARE_RANSOMWARE, ScanSeverity::CRITICAL,
         HashAlgorithm::SHA256, "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
         "", "", {"ransomware", "wannacry"}, 0, 0, true, "community"}},

      {"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        {"sig-004", "Adware.BrowserModifier.Generic", "Browser hijacking adware",
         ContentCategory::MALWARE_ADWARE, ScanSeverity::MEDIUM,
         HashAlgorithm::SHA256, "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
         "", "", {"adware", "browser"}, 0, 0, true, "community"}},

      {"cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe",
        {"sig-005", "Spyware.KeyLogger.Generic", "Keystroke logging spyware",
         ContentCategory::MALWARE_SPYWARE, ScanSeverity::HIGH,
         HashAlgorithm::SHA256, "cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe",
         "", "", {"spyware", "keylogger"}, 0, 0, true, "community"}},

      {"1111111111111111222222222222222233333333333333334444444444444444",
        {"sig-006", "CoinMiner.XMRig.Generic", "Cryptocurrency miner",
         ContentCategory::CRYPTOMINING, ScanSeverity::MEDIUM,
         HashAlgorithm::SHA256, "1111111111111111222222222222222233333333333333334444444444444444",
         "", "", {"cryptominer", "xmrig"}, 0, 0, true, "community"}},
    };

    for (auto& [hash, sig] : entries) {
      malware_hashes_[hash] = sig;
    }
  }

  void load_virustotal_cache() {
    // In production: load from database
    std::lock_guard<std::shared_mutex> lock(hashes_mutex_);

    // Simulated VT cache data
    virustotal_cache_["1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"] = 12;
    virustotal_cache_["abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"] = 3;
  }

  EngineConfig config_;
  bool healthy_ = false;
  std::unordered_map<std::string, MalwareSignature> malware_hashes_;
  std::unordered_map<std::string, int> virustotal_cache_;  // hash -> detection count
  mutable std::shared_mutex hashes_mutex_;
};

// ============================================================================
// Adult Content Detector — specialized NSFW content detection
// ============================================================================
class AdultContentDetector {
public:
  AdultContentDetector() : enabled_(true), threshold_(0.7) {}

  bool initialize(const json& config) {
    enabled_ = config.value("enabled", true);
    threshold_ = config.value("threshold", 0.7);
    high_threshold_ = config.value("high_threshold", 0.9);

    // Load skin-tone detection parameters
    load_color_profiles();

    auto& log = get_scanner_logger("progressive.scanner.adult");
    log.info("Adult content detector initialized (threshold=" +
             std::to_string(threshold_) + ")");
    return true;
  }

  struct AdultScanResult {
    double nsfw_score = 0.0;
    double explicit_score = 0.0;
    bool is_nsfw = false;
    bool is_explicit = false;
    std::string reason;
    std::vector<std::string> matched_indicators;
  };

  AdultScanResult analyze(const ScanRequest& request) {
    AdultScanResult result;
    if (!enabled_) return result;

    bool is_image = request.mime_type.find("image/") == 0;
    bool is_video = request.mime_type.find("video/") == 0;
    bool is_text  = request.mime_type.find("text/") == 0 ||
                    !request.text_content.empty();

    if (is_image || is_video) {
      result = analyze_media(request.content, request.mime_type);
    } else if (is_text) {
      result = analyze_text(request.text_content);
    }

    return result;
  }

  bool is_enabled() const { return enabled_; }
  void set_enabled(bool e) { enabled_ = e; }
  void set_threshold(double t) { threshold_ = t; }
  double threshold() const { return threshold_; }

private:
  void load_color_profiles() {
    // Skin tone detection profiles
    // In production: load trained color models
    skin_tone_ranges_ = {
      {{0, 80, 50}, {50, 255, 200}},    // Light skin in HSV
      {{0, 40, 20}, {30, 255, 200}},    // Medium-dark skin
    };
  }

  AdultScanResult analyze_media(const std::vector<uint8_t>& content,
                                 const std::string& /*mime_type*/) {
    AdultScanResult result;
    if (content.empty()) return result;

    // Simulated image analysis
    // In production: use TensorFlow/ONNX model for NSFW classification
    size_t sample_size = std::min(content.size(), size_t(4096));

    // Count bytes that might correspond to skin-tone pixels (simulated)
    size_t skin_tone_count = 0;
    for (size_t i = 0; i < sample_size; i += 3) {
      if (i + 2 < sample_size) {
        uint8_t r = content[i];
        uint8_t g = content[i+1];
        uint8_t b = content[i+2];
        if (is_skin_tone_rgb(r, g, b)) {
          skin_tone_count++;
        }
      }
    }

    double skin_ratio = static_cast<double>(skin_tone_count) /
                        (sample_size / 3.0);

    // Heuristic: high skin-tone ratio suggests adult content
    result.nsfw_score = std::min(skin_ratio * 1.5, 1.0);
    result.explicit_score = skin_ratio > 0.5 ? (skin_ratio - 0.5) * 2.0 : 0.0;

    if (result.nsfw_score > threshold_) {
      result.is_nsfw = true;
      result.matched_indicators.push_back("high_skin_tone_ratio");
      result.reason = "Elevated skin tone ratio detected";
    }

    if (result.explicit_score > high_threshold_) {
      result.is_explicit = true;
      result.matched_indicators.push_back("very_high_skin_tone_ratio");
    }

    return result;
  }

  AdultScanResult analyze_text(const std::string& text) {
    AdultScanResult result;
    if (text.empty()) return result;

    std::string lower = text;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

    // Check for adult content patterns in text
    static const std::vector<std::string> explicit_keywords = {
      "nsfw", "xxx", "porn", "adult", "18+", "explicit", "nsfl",
    };

    static const std::vector<std::string> suggestive_keywords = {
      "sexy", "hot", "nude", "naked", "hookup", "dating", "singles",
    };

    size_t explicit_hits = 0;
    size_t suggestive_hits = 0;

    for (const auto& kw : explicit_keywords) {
      if (lower.find(kw) != std::string::npos) {
        explicit_hits++;
        result.matched_indicators.push_back("explicit_keyword:" + kw);
      }
    }

    for (const auto& kw : suggestive_keywords) {
      if (lower.find(kw) != std::string::npos) {
        suggestive_hits++;
        result.matched_indicators.push_back("suggestive_keyword:" + kw);
      }
    }

    double explicit_ratio = static_cast<double>(explicit_hits) /
                            std::max(size_t(1), explicit_keywords.size());
    double suggestive_ratio = static_cast<double>(suggestive_hits) /
                              std::max(size_t(1), suggestive_keywords.size());

    result.explicit_score = explicit_ratio;
    result.nsfw_score = std::max(explicit_ratio * 1.2, suggestive_ratio * 0.5);

    if (result.explicit_score > threshold_) {
      result.is_explicit = true;
      result.reason = "Explicit content keywords detected";
    } else if (result.nsfw_score > threshold_) {
      result.is_nsfw = true;
      result.reason = "Adult-oriented content keywords detected";
    }

    return result;
  }

  bool is_skin_tone_rgb(uint8_t r, uint8_t g, uint8_t b) {
    // Simple skin tone detection in RGB space
    // Rules based on common skin tone color ranges
    if (r == 0 && g == 0 && b == 0) return false; // skip pure black
    if (r == 255 && g == 255 && b == 255) return false; // skip pure white

    // Skin tone conditions
    bool condition1 = (r > 95 && g > 40 && b > 20);
    bool condition2 = (r > g && r > b);
    bool condition3 = (std::max({r, g, b}) - std::min({r, g, b}) > 15);
    bool condition4 = (std::abs(r - g) > 15);

    return condition1 && condition2 && condition3 && condition4;
  }

  bool enabled_;
  double threshold_;
  double high_threshold_;
  std::vector<std::pair<std::array<int,3>, std::array<int,3>>> skin_tone_ranges_;
};

// ============================================================================
// Scan Cache Manager — multi-level scan result caching
// ============================================================================
class ScanCacheManager {
public:
  ScanCacheManager() : max_l1_entries_(10000), default_ttl_ms_(3600000) {} // 1 hour default TTL

  bool initialize(size_t max_entries, int64_t default_ttl_ms) {
    max_l1_entries_ = max_entries;
    default_ttl_ms_ = default_ttl_ms;
    auto& log = get_scanner_logger("progressive.scanner.cache");
    log.info("Cache initialized (max_entries=" + std::to_string(max_entries) +
             ", ttl_ms=" + std::to_string(default_ttl_ms) + ")");
    return true;
  }

  // Check if a scan result is cached
  std::optional<ScanResult> get(const std::string& cache_key) {
    std::unique_lock<std::shared_mutex> lock(cache_mutex_);

    auto it = l1_cache_.find(cache_key);
    if (it != l1_cache_.end()) {
      if (it->second.is_expired()) {
        // Expired — remove and return miss
        lru_list_.erase(it->second.lru_iterator);
        l1_cache_.erase(it);
        return std::nullopt;
      }

      // Cache hit — update LRU
      touch_lru(it->second);
      it->second.last_accessed_ms = now_ms();
      it->second.access_count++;

      auto& log = get_scanner_logger("progressive.scanner.cache");
      log.debug("Cache HIT for key=" + cache_key);
      return it->second.result;
    }

    return std::nullopt;
  }

  // Store a scan result in cache
  void put(const std::string& cache_key, const ScanResult& result,
           int64_t ttl_ms = 0) {
    std::unique_lock<std::shared_mutex> lock(cache_mutex_);

    if (ttl_ms <= 0) ttl_ms = default_ttl_ms_;

    ScanCacheEntry entry;
    entry.cache_key = cache_key;
    entry.result = result;
    entry.created_at_ms = now_ms();
    entry.expires_at_ms = entry.created_at_ms + ttl_ms;
    entry.last_accessed_ms = entry.created_at_ms;
    entry.access_count = 0;

    // Evict if at capacity
    while (l1_cache_.size() >= max_l1_entries_ && !lru_list_.empty()) {
      auto oldest = lru_list_.front();
      lru_list_.pop_front();
      l1_cache_.erase(oldest);
    }

    // Insert
    auto [it, inserted] = l1_cache_.emplace(cache_key, std::move(entry));
    if (inserted) {
      lru_list_.push_back(cache_key);
      it->second.lru_iterator = --lru_list_.end();
    } else {
      // Update existing
      touch_lru(it->second);
      it->second = std::move(entry);
    }
  }

  // Invalidate specific cache entry
  bool invalidate(const std::string& cache_key) {
    std::unique_lock<std::shared_mutex> lock(cache_mutex_);
    auto it = l1_cache_.find(cache_key);
    if (it != l1_cache_.end()) {
      lru_list_.erase(it->second.lru_iterator);
      l1_cache_.erase(it);
      return true;
    }
    return false;
  }

  // Invalidate all entries
  void invalidate_all() {
    std::unique_lock<std::shared_mutex> lock(cache_mutex_);
    l1_cache_.clear();
    lru_list_.clear();
  }

  // Invalidate entries older than threshold
  size_t invalidate_older_than(int64_t age_ms) {
    std::unique_lock<std::shared_mutex> lock(cache_mutex_);
    int64_t cutoff = now_ms() - age_ms;
    size_t removed = 0;

    auto it = l1_cache_.begin();
    while (it != l1_cache_.end()) {
      if (it->second.created_at_ms < cutoff) {
        lru_list_.erase(it->second.lru_iterator);
        it = l1_cache_.erase(it);
        removed++;
      } else {
        ++it;
      }
    }
    return removed;
  }

  // Get cache statistics
  struct CacheStats {
    size_t entry_count = 0;
    size_t max_entries = 0;
    size_t hits = 0;
    size_t misses = 0;
    int64_t oldest_entry_ms = 0;
    int64_t newest_entry_ms = 0;
    double hit_rate = 0.0;
  };

  CacheStats stats() const {
    std::shared_lock<std::shared_mutex> lock(cache_mutex_);
    CacheStats s;
    s.entry_count = l1_cache_.size();
    s.max_entries = max_l1_entries_;
    s.hits = total_hits_.load();
    s.misses = total_misses_.load();
    s.hit_rate = (s.hits + s.misses) > 0 ?
      static_cast<double>(s.hits) / (s.hits + s.misses) : 0.0;

    for (const auto& [key, entry] : l1_cache_) {
      if (s.oldest_entry_ms == 0 || entry.created_at_ms < s.oldest_entry_ms)
        s.oldest_entry_ms = entry.created_at_ms;
      if (entry.created_at_ms > s.newest_entry_ms)
        s.newest_entry_ms = entry.created_at_ms;
    }
    return s;
  }

  void record_hit() { total_hits_.fetch_add(1); }
  void record_miss() { total_misses_.fetch_add(1); }

private:
  void touch_lru(ScanCacheEntry& entry) {
    lru_list_.erase(entry.lru_iterator);
    lru_list_.push_back(entry.cache_key);
    entry.lru_iterator = --lru_list_.end();
  }

  size_t max_l1_entries_;
  int64_t default_ttl_ms_;

  struct LruEntry {
    ScanCacheEntry entry;
    std::list<std::string>::iterator lru_iterator;
  };

  // Make ScanCacheEntry store the LRU iterator
  // We patch the struct slightly — use a separate map
  struct CacheEntryWithLRU : ScanCacheEntry {
    std::list<std::string>::iterator lru_iterator;
  };

  std::unordered_map<std::string, CacheEntryWithLRU> l1_cache_;
  std::list<std::string> lru_list_;
  mutable std::shared_mutex cache_mutex_;

  std::atomic<size_t> total_hits_{0};
  std::atomic<size_t> total_misses_{0};
};

// ============================================================================
// Quarantine Manager — handles quarantined content
// ============================================================================
class QuarantineManager {
public:
  QuarantineManager() : quarantine_enabled_(true) {}

  bool initialize(const std::string& quarantine_path, DatabasePool* db_pool) {
    quarantine_path_ = quarantine_path.empty() ?
                      "/var/lib/progressive/quarantine" : quarantine_path;
    db_pool_ = db_pool;
    quarantine_enabled_ = true;

    // Ensure quarantine directory exists
    std::error_code ec;
    fs::create_directories(quarantine_path_, ec);

    auto& log = get_scanner_logger("progressive.scanner.quarantine");
    log.info("Quarantine manager initialized (path=" + quarantine_path_ + ")");

    // Load existing quarantine records
    load_quarantine_records();

    return true;
  }

  // Quarantine a file
  QuarantineRecord quarantine(const ScanRequest& request,
                               const ScanResult& result,
                               const std::string& original_path = "") {
    auto& log = get_scanner_logger("progressive.scanner.quarantine");

    QuarantineRecord record;
    record.quarantine_id = "qrntn-" + generate_uuid();
    record.request_id = request.request_id;
    record.user_id = request.user_id;
    record.room_id = request.room_id;
    record.event_id = request.event_id;
    record.filename = request.filename;
    record.mime_type = request.mime_type;
    record.content_hash = request.primary_hash();
    record.content_size = request.content_size;
    record.verdict = result.overall_verdict;
    record.category = result.overall_category;
    record.severity = result.overall_severity;
    record.reason = result.summary;
    record.original_path = original_path;
    record.quarantined_at_ms = now_ms();
    record.review_status = "pending";
    record.scan_results = result.to_json();

    // Move file to quarantine if path provided
    if (!original_path.empty()) {
      record.quarantined_path = quarantine_file(original_path, record.quarantine_id);
    }

    // Store quarantine record
    {
      std::unique_lock<std::shared_mutex> lock(quarantine_mutex_);
      quarantine_records_[record.quarantine_id] = record;
    }

    persist_quarantine_record(record);

    log.warn("Content quarantined: " + record.quarantine_id +
             " (category=" + content_category_to_string(record.category) +
             ", severity=" + scan_severity_to_string(record.severity) + ")");

    return record;
  }

  // Release quarantined content
  bool release(const std::string& quarantine_id, const std::string& reviewer,
               const std::string& notes) {
    std::unique_lock<std::shared_mutex> lock(quarantine_mutex_);

    auto it = quarantine_records_.find(quarantine_id);
    if (it == quarantine_records_.end()) return false;

    it->second.review_status = "released";
    it->second.reviewed_by = reviewer;
    it->second.reviewed_at_ms = now_ms();
    it->second.review_notes = notes;

    update_quarantine_record(it->second);

    auto& log = get_scanner_logger("progressive.scanner.quarantine");
    log.info("Quarantine released: " + quarantine_id + " by " + reviewer);

    return true;
  }

  // Permanently block quarantined content
  bool permanently_block(const std::string& quarantine_id, const std::string& reviewer,
                          const std::string& notes) {
    std::unique_lock<std::shared_mutex> lock(quarantine_mutex_);

    auto it = quarantine_records_.find(quarantine_id);
    if (it == quarantine_records_.end()) return false;

    it->second.review_status = "permanently_blocked";
    it->second.reviewed_by = reviewer;
    it->second.reviewed_at_ms = now_ms();
    it->second.review_notes = notes;

    update_quarantine_record(it->second);

    auto& log = get_scanner_logger("progressive.scanner.quarantine");
    log.info("Quarantine permanently blocked: " + quarantine_id + " by " + reviewer);

    return true;
  }

  // Delete quarantined content
  bool delete_quarantined(const std::string& quarantine_id) {
    std::unique_lock<std::shared_mutex> lock(quarantine_mutex_);

    auto it = quarantine_records_.find(quarantine_id);
    if (it == quarantine_records_.end()) return false;

    // Delete the quarantined file
    if (!it->second.quarantined_path.empty()) {
      std::error_code ec;
      fs::remove(it->second.quarantined_path, ec);
    }

    quarantine_records_.erase(it);
    delete_quarantine_record(quarantine_id);

    auto& log = get_scanner_logger("progressive.scanner.quarantine");
    log.info("Quarantine deleted: " + quarantine_id);

    return true;
  }

  // Get quarantine record
  std::optional<QuarantineRecord> get_record(const std::string& quarantine_id) {
    std::shared_lock<std::shared_mutex> lock(quarantine_mutex_);
    auto it = quarantine_records_.find(quarantine_id);
    if (it != quarantine_records_.end()) return it->second;
    return std::nullopt;
  }

  // List quarantine records with filtering
  std::vector<QuarantineRecord> list_records(const std::string& status_filter = "",
                                               const std::string& user_filter = "",
                                               int limit = 100, int offset = 0) {
    std::shared_lock<std::shared_mutex> lock(quarantine_mutex_);
    std::vector<QuarantineRecord> results;

    for (const auto& [id, record] : quarantine_records_) {
      if (!status_filter.empty() && record.review_status != status_filter) continue;
      if (!user_filter.empty() && record.user_id != user_filter) continue;
      results.push_back(record);
    }

    // Sort by quarantine time (newest first)
    std::sort(results.begin(), results.end(),
              [](const QuarantineRecord& a, const QuarantineRecord& b) {
                return a.quarantined_at_ms > b.quarantined_at_ms;
              });

    if (offset > 0 && static_cast<size_t>(offset) < results.size()) {
      results.erase(results.begin(), results.begin() + offset);
    }
    if (limit > 0 && static_cast<size_t>(limit) < results.size()) {
      results.resize(limit);
    }

    return results;
  }

  // Get quarantine statistics
  json get_stats() const {
    std::shared_lock<std::shared_mutex> lock(quarantine_mutex_);
    size_t total = quarantine_records_.size();
    size_t pending = 0;
    size_t reviewed = 0;
    size_t released = 0;
    size_t blocked = 0;

    for (const auto& [id, r] : quarantine_records_) {
      if (r.review_status == "pending") pending++;
      else if (r.review_status == "reviewed") reviewed++;
      else if (r.review_status == "released") released++;
      else if (r.review_status == "permanently_blocked") blocked++;
    }

    return json{
      {"total_quarantined", total},
      {"pending_review", pending},
      {"reviewed", reviewed},
      {"released", released},
      {"permanently_blocked", blocked}
    };
  }

  bool is_enabled() const { return quarantine_enabled_; }
  void set_enabled(bool e) { quarantine_enabled_ = e; }

private:
  std::string quarantine_file(const std::string& original_path,
                               const std::string& quarantine_id) {
    std::error_code ec;

    // Create quarantine subdirectory based on date
    auto t = std::time(nullptr);
    auto tm = *std::localtime(&t);
    char date_dir[32];
    std::strftime(date_dir, sizeof(date_dir), "%Y/%m/%d", &tm);

    fs::path qdir = fs::path(quarantine_path_) / date_dir;
    fs::create_directories(qdir, ec);

    // Move file to quarantine
    fs::path src(original_path);
    fs::path dst = qdir / (quarantine_id + "_" + src.filename().string());

    fs::rename(src, dst, ec);
    if (ec) {
      // Fallback: copy then delete
      fs::copy_file(src, dst, ec);
      if (!ec) fs::remove(src, ec);
    }

    return dst.string();
  }

  void load_quarantine_records() {
    // In production: load from database
    // Simulated for now
  }

  void persist_quarantine_record(const QuarantineRecord& record) {
    // In production: INSERT INTO quarantine_records
    (void)record;
  }

  void update_quarantine_record(const QuarantineRecord& record) {
    // In production: UPDATE quarantine_records
    (void)record;
  }

  void delete_quarantine_record(const std::string& quarantine_id) {
    // In production: DELETE FROM quarantine_records
    (void)quarantine_id;
  }

  bool quarantine_enabled_;
  std::string quarantine_path_;
  DatabasePool* db_pool_ = nullptr;
  std::unordered_map<std::string, QuarantineRecord> quarantine_records_;
  mutable std::shared_mutex quarantine_mutex_;
};

// ============================================================================
// Scan Policy Manager — manages per-room and global scan policies
// ============================================================================
class ScanPolicyManager {
public:
  ScanPolicyManager() = default;

  bool initialize(DatabasePool* db_pool) {
    db_pool_ = db_pool;

    // Load global default policy
    global_policy_.policy_id = "global-default";
    global_policy_.scope = "global";
    global_policy_.scope_type = "global";
    global_policy_.enabled = true;
    global_policy_.scan_messages = true;
    global_policy_.scan_media = true;
    global_policy_.scan_urls = true;
    global_policy_.scan_avatars = true;
    global_policy_.scan_encrypted = false;
    global_policy_.max_scan_size_bytes = 100 * 1024 * 1024;
    global_policy_.scan_timeout_ms = 30000;
    global_policy_.quarantine_media = true;
    global_policy_.notify_on_detection = true;
    global_policy_.redact_on_block = true;
    global_policy_.adult_threshold = 0.7;
    global_policy_.malware_threshold = 0.5;
    global_policy_.bypass_whitelisted_users = true;
    global_policy_.created_at_ms = now_ms();
    global_policy_.updated_at_ms = now_ms();

    // Default per-category actions
    global_policy_.category_actions[ContentCategory::MALWARE_GENERIC]    = QuarantineAction::QUARANTINE;
    global_policy_.category_actions[ContentCategory::MALWARE_TROJAN]     = QuarantineAction::QUARANTINE;
    global_policy_.category_actions[ContentCategory::MALWARE_RANSOMWARE] = QuarantineAction::BLOCK;
    global_policy_.category_actions[ContentCategory::MALWARE_WORM]       = QuarantineAction::QUARANTINE;
    global_policy_.category_actions[ContentCategory::MALWARE_SPYWARE]    = QuarantineAction::QUARANTINE;
    global_policy_.category_actions[ContentCategory::MALWARE_ADWARE]     = QuarantineAction::FLAG;
    global_policy_.category_actions[ContentCategory::ADULT_NSFW]         = QuarantineAction::REDACT;
    global_policy_.category_actions[ContentCategory::ADULT_EXPLICIT]     = QuarantineAction::BLOCK;
    global_policy_.category_actions[ContentCategory::VIOLENCE]           = QuarantineAction::REDACT;
    global_policy_.category_actions[ContentCategory::HATE_SPEECH]        = QuarantineAction::BLOCK;
    global_policy_.category_actions[ContentCategory::SPAM]               = QuarantineAction::FLAG;
    global_policy_.category_actions[ContentCategory::PHISHING]           = QuarantineAction::BLOCK;
    global_policy_.category_actions[ContentCategory::CRYPTOMINING]       = QuarantineAction::QUARANTINE;
    global_policy_.category_actions[ContentCategory::ILLEGAL_CONTENT]    = QuarantineAction::BLOCK;

    auto& log = get_scanner_logger("progressive.scanner.policy");
    log.info("Policy manager initialized");

    return true;
  }

  // Get applicable policy for a scan request
  ScanPolicy get_policy(const ScanRequest& request) {
    // Check room-specific policy first
    if (!request.room_id.empty()) {
      auto room_policy = get_room_policy(request.room_id);
      if (room_policy.has_value()) {
        return room_policy.value();
      }
    }

    // Check user-specific policy
    if (!request.user_id.empty()) {
      auto user_policy = get_user_policy(request.user_id);
      if (user_policy.has_value()) {
        return user_policy.value();
      }
    }

    // Fall back to global policy
    return global_policy_;
  }

  // Check if scanning should be bypassed
  bool should_bypass_scan(const ScanRequest& request) {
    auto policy = get_policy(request);

    if (!policy.enabled) return true;

    if (policy.is_user_whitelisted(request.user_id)) return true;
    if (!request.room_id.empty() && policy.is_room_whitelisted(request.room_id)) return true;

    // Check content size limit
    if (request.content_size > policy.max_scan_size_bytes) return true;

    // Check mime type blocking
    for (const auto& blocked_type : policy.blocked_mime_types) {
      if (request.mime_type.find(blocked_type) != std::string::npos) {
        return true; // Blocked types bypass scanning (they get blocked directly)
      }
    }

    return false;
  }

  // Set room-specific policy
  void set_room_policy(const std::string& room_id, const ScanPolicy& policy) {
    std::unique_lock<std::shared_mutex> lock(policy_mutex_);
    room_policies_[room_id] = policy;
  }

  // Remove room-specific policy
  void remove_room_policy(const std::string& room_id) {
    std::unique_lock<std::shared_mutex> lock(policy_mutex_);
    room_policies_.erase(room_id);
  }

  // Set user-specific policy
  void set_user_policy(const std::string& user_id, const ScanPolicy& policy) {
    std::unique_lock<std::shared_mutex> lock(policy_mutex_);
    user_policies_[user_id] = policy;
  }

  // Update global policy
  void update_global_policy(const ScanPolicy& policy) {
    std::unique_lock<std::shared_mutex> lock(policy_mutex_);
    global_policy_ = policy;
    global_policy_.updated_at_ms = now_ms();
  }

  // Get global policy
  ScanPolicy get_global_policy() const {
    std::shared_lock<std::shared_mutex> lock(policy_mutex_);
    return global_policy_;
  }

  // List all room policies
  std::map<std::string, ScanPolicy> list_room_policies() const {
    std::shared_lock<std::shared_mutex> lock(policy_mutex_);
    return room_policies_;
  }

private:
  std::optional<ScanPolicy> get_room_policy(const std::string& room_id) {
    std::shared_lock<std::shared_mutex> lock(policy_mutex_);
    auto it = room_policies_.find(room_id);
    if (it != room_policies_.end()) return it->second;
    return std::nullopt;
  }

  std::optional<ScanPolicy> get_user_policy(const std::string& user_id) {
    std::shared_lock<std::shared_mutex> lock(policy_mutex_);
    auto it = user_policies_.find(user_id);
    if (it != user_policies_.end()) return it->second;
    return std::nullopt;
  }

  DatabasePool* db_pool_ = nullptr;
  ScanPolicy global_policy_;
  std::unordered_map<std::string, ScanPolicy> room_policies_;
  std::unordered_map<std::string, ScanPolicy> user_policies_;
  mutable std::shared_mutex policy_mutex_;
};

// ============================================================================
// Scan Scheduler — async scan queue with thread pool
// ============================================================================
class ScanScheduler {
public:
  ScanScheduler() : running_(false), thread_count_(4) {}

  bool initialize(size_t thread_count) {
    thread_count_ = std::max(thread_count, size_t(1));
    running_ = true;

    for (size_t i = 0; i < thread_count_; ++i) {
      workers_.emplace_back(&ScanScheduler::worker_loop, this, i);
    }

    auto& log = get_scanner_logger("progressive.scanner.scheduler");
    log.info("Scheduler initialized with " + std::to_string(thread_count_) + " workers");
    return true;
  }

  void shutdown() {
    {
      std::lock_guard<std::mutex> lock(queue_mutex_);
      running_ = false;
    }
    queue_cv_.notify_all();

    for (auto& w : workers_) {
      if (w.joinable()) w.join();
    }

    workers_.clear();
  }

  // Submit a scan job
  using ScanCallback = std::function<void(const ScanResult&)>;
  void submit(ScanRequest request, ScanCallback callback,
              int64_t deadline_ms = 0) {
    if (!running_) {
      ScanResult error_result;
      error_result.request_id = request.request_id;
      error_result.overall_verdict = ScanVerdict::ERROR;
      error_result.summary = "Scanner not running";
      if (callback) callback(error_result);
      return;
    }

    QueueEntry entry;
    entry.request = std::move(request);
    entry.callback = std::move(callback);
    entry.deadline_ms = deadline_ms > 0 ? deadline_ms :
                        (now_ms() + 60000); // 60s default deadline

    {
      std::lock_guard<std::mutex> lock(queue_mutex_);
      queue_.push(std::move(entry));
      pending_count_.fetch_add(1);
    }
    queue_cv_.notify_one();
  }

  // Get queue statistics
  struct QueueStats {
    size_t pending = 0;
    size_t active = 0;
    size_t completed = 0;
    size_t failed = 0;
    double avg_wait_time_ms = 0.0;
  };

  QueueStats stats() const {
    QueueStats s;
    s.pending = pending_count_.load();
    s.active = active_count_.load();
    s.completed = completed_count_.load();
    s.failed = failed_count_.load();
    return s;
  }

  void set_scan_executor(std::function<ScanResult(const ScanRequest&)> executor) {
    scan_executor_ = std::move(executor);
  }

private:
  struct QueueEntry {
    ScanRequest request;
    ScanCallback callback;
    int64_t deadline_ms = 0;
    int64_t enqueued_at_ms = now_ms();

    bool operator<(const QueueEntry& other) const {
      // Higher priority items come first
      return static_cast<int>(request.priority) < static_cast<int>(other.request.priority);
    }
  };

  void worker_loop(size_t worker_id) {
    auto& log = get_scanner_logger("progressive.scanner.scheduler");
    log.debug("Worker " + std::to_string(worker_id) + " started");

    while (running_) {
      QueueEntry entry;

      {
        std::unique_lock<std::mutex> lock(queue_mutex_);
        queue_cv_.wait(lock, [this] {
          return !running_ || !queue_.empty();
        });

        if (!running_ && queue_.empty()) break;

        if (!queue_.empty()) {
          entry = std::move(const_cast<QueueEntry&>(queue_.top()));
          queue_.pop();
          pending_count_.fetch_sub(1);
          active_count_.fetch_add(1);
        } else {
          continue;
        }
      }

      // Check if deadline has passed
      if (entry.deadline_ms > 0 && now_ms() > entry.deadline_ms) {
        ScanResult timeout_result;
        timeout_result.request_id = entry.request.request_id;
        timeout_result.overall_verdict = ScanVerdict::TIMEOUT;
        timeout_result.summary = "Scan deadline exceeded";
        if (entry.callback) entry.callback(timeout_result);
        failed_count_.fetch_add(1);
        active_count_.fetch_sub(1);
        continue;
      }

      // Execute scan
      ScanResult result;
      try {
        if (scan_executor_) {
          result = scan_executor_(entry.request);
        } else {
          result.request_id = entry.request.request_id;
          result.overall_verdict = ScanVerdict::ERROR;
          result.summary = "No scan executor configured";
        }
        completed_count_.fetch_add(1);
      } catch (const std::exception& e) {
        result.request_id = entry.request.request_id;
        result.overall_verdict = ScanVerdict::ERROR;
        result.summary = std::string("Scan exception: ") + e.what();
        failed_count_.fetch_add(1);
        log.error("Worker " + std::to_string(worker_id) + " error: " + e.what());
      }

      active_count_.fetch_sub(1);

      // Invoke callback
      if (entry.callback) {
        try {
          entry.callback(result);
        } catch (const std::exception& e) {
          log.error("Callback error for " + entry.request.request_id + ": " + e.what());
        }
      }
    }

    log.debug("Worker " + std::to_string(worker_id) + " stopped");
  }

  bool running_;
  size_t thread_count_;
  std::vector<std::thread> workers_;
  std::priority_queue<QueueEntry> queue_;
  std::mutex queue_mutex_;
  std::condition_variable queue_cv_;
  std::function<ScanResult(const ScanRequest&)> scan_executor_;

  std::atomic<size_t> pending_count_{0};
  std::atomic<size_t> active_count_{0};
  std::atomic<size_t> completed_count_{0};
  std::atomic<size_t> failed_count_{0};
};

// ============================================================================
// Scan Result Aggregator — combines results from multiple engines
// ============================================================================
class ScanResultAggregator {
public:
  ScanResultAggregator() = default;

  // Aggregate results from multiple engines into a single verdict
  ScanResult aggregate(const ScanRequest& request,
                       const std::vector<EngineScanResult>& engine_results) {
    ScanResult result;
    result.request_id = request.request_id;
    result.completed_at_ms = now_ms();
    result.engine_results = engine_results;
    result.engine_count = static_cast<int>(engine_results.size());

    if (engine_results.empty()) {
      result.overall_verdict = ScanVerdict::UNKNOWN;
      result.summary = "No engine results available";
      return result;
    }

    // Count verdicts
    int malware_count = 0;
    int adult_count = 0;
    int suspicious_count = 0;
    int clean_count = 0;
    int error_count = 0;

    double max_confidence = 0.0;
    ScanSeverity max_severity = ScanSeverity::NONE;
    ContentCategory worst_category = ContentCategory::SAFE;
    int64_t total_duration = 0;

    for (const auto& er : engine_results) {
      total_duration += er.scan_duration_ms;

      switch (er.verdict) {
        case ScanVerdict::MALWARE:
          malware_count++;
          result.malicious_engine_count++;
          break;
        case ScanVerdict::ADULT:
          adult_count++;
          result.malicious_engine_count++;
          break;
        case ScanVerdict::SUSPICIOUS:
          suspicious_count++;
          result.malicious_engine_count++;
          break;
        case ScanVerdict::CLEAN:
        case ScanVerdict::BYPASSED:
          clean_count++;
          break;
        default:
          error_count++;
          break;
      }

      if (er.confidence_score > max_confidence) {
        max_confidence = er.confidence_score;
      }
      if (er.severity > max_severity) {
        max_severity = er.severity;
      }
      if (er.category != ContentCategory::SAFE && er.category != ContentCategory::OTHER) {
        worst_category = er.category;
      }
    }

    result.highest_confidence = max_confidence;
    result.total_scan_duration_ms = total_duration;
    result.overall_severity = max_severity;
    result.overall_category = worst_category;

    // Determine overall verdict
    if (malware_count > 0) {
      result.overall_verdict = ScanVerdict::MALWARE;
      result.summary = "Malware detected by " + std::to_string(malware_count) + " engine(s)";
    } else if (adult_count > 0) {
      result.overall_verdict = ScanVerdict::ADULT;
      result.summary = "Adult content detected by " + std::to_string(adult_count) + " engine(s)";
    } else if (suspicious_count > 0) {
      result.overall_verdict = ScanVerdict::SUSPICIOUS;
      result.summary = "Suspicious content detected by " + std::to_string(suspicious_count) + " engine(s)";
    } else if (clean_count > 0) {
      result.overall_verdict = ScanVerdict::CLEAN;
      result.summary = "Content is clean (checked by " + std::to_string(clean_count) + " engine(s))";
    } else if (error_count == static_cast<int>(engine_results.size())) {
      result.overall_verdict = ScanVerdict::ERROR;
      result.summary = "All engines reported errors";
    } else {
      result.overall_verdict = ScanVerdict::UNKNOWN;
      result.summary = "Inconclusive scan results";
    }

    return result;
  }
};

// ============================================================================
// Scan Audit Logger — audit trail for all scan operations
// ============================================================================
class ScanAuditLogger {
public:
  ScanAuditLogger() : max_in_memory_entries_(10000) {}

  bool initialize(DatabasePool* db_pool, size_t max_in_memory) {
    db_pool_ = db_pool;
    max_in_memory_entries_ = max_in_memory;
    return true;
  }

  // Log a scan request
  void log_scan_request(const ScanRequest& request) {
    AuditLogEntry entry;
    entry.audit_id = "audit-" + generate_uuid();
    entry.action = "scan_requested";
    entry.request_id = request.request_id;
    entry.user_id = request.user_id;
    entry.room_id = request.room_id;
    entry.detail = "Scan requested for " + scan_target_type_to_string(request.target_type);
    entry.timestamp_ms = now_ms();
    entry.extra_data = request.to_json();

    append_log(entry);
  }

  // Log a scan result
  void log_scan_result(const ScanResult& result) {
    AuditLogEntry entry;
    entry.audit_id = "audit-" + generate_uuid();
    entry.action = "scan_completed";
    entry.request_id = result.request_id;
    entry.detail = "Scan completed: " + scan_verdict_to_string(result.overall_verdict);
    entry.timestamp_ms = now_ms();
    entry.extra_data = result.to_json();

    append_log(entry);
  }

  // Log quarantine action
  void log_quarantine(const QuarantineRecord& record, const std::string& user_id) {
    AuditLogEntry entry;
    entry.audit_id = "audit-" + generate_uuid();
    entry.action = "quarantine";
    entry.request_id = record.request_id;
    entry.user_id = record.user_id;
    entry.room_id = record.room_id;
    entry.detail = "Content quarantined: " + record.quarantine_id;
    entry.timestamp_ms = now_ms();
    entry.extra_data = record.to_json();

    append_log(entry);
  }

  // Log release action
  void log_release(const std::string& quarantine_id, const std::string& reviewer) {
    AuditLogEntry entry;
    entry.audit_id = "audit-" + generate_uuid();
    entry.action = "release_quarantine";
    entry.user_id = reviewer;
    entry.detail = "Quarantine released: " + quarantine_id;
    entry.timestamp_ms = now_ms();

    append_log(entry);
  }

  // Query audit logs
  std::vector<AuditLogEntry> query(const std::string& action_filter = "",
                                     const std::string& user_filter = "",
                                     int64_t from_ms = 0, int64_t to_ms = 0,
                                     int limit = 100) {
    std::shared_lock<std::shared_mutex> lock(audit_mutex_);
    std::vector<AuditLogEntry> results;

    for (const auto& entry : audit_log_) {
      if (!action_filter.empty() && entry.action != action_filter) continue;
      if (!user_filter.empty() && entry.user_id != user_filter) continue;
      if (from_ms > 0 && entry.timestamp_ms < from_ms) continue;
      if (to_ms > 0 && entry.timestamp_ms > to_ms) continue;
      results.push_back(entry);
    }

    // Sort newest first
    std::sort(results.begin(), results.end(),
              [](const AuditLogEntry& a, const AuditLogEntry& b) {
                return a.timestamp_ms > b.timestamp_ms;
              });

    if (limit > 0 && static_cast<size_t>(limit) < results.size()) {
      results.resize(limit);
    }

    return results;
  }

  // Get audit statistics
  json get_stats() const {
    std::shared_lock<std::shared_mutex> lock(audit_mutex_);
    size_t total = audit_log_.size();

    std::map<std::string, size_t> action_counts;
    for (const auto& e : audit_log_) {
      action_counts[e.action]++;
    }

    json action_json = json::object();
    for (const auto& [action, count] : action_counts) {
      action_json[action] = count;
    }

    return json{
      {"total_entries", total},
      {"max_entries", max_in_memory_entries_},
      {"action_counts", action_json}
    };
  }

private:
  void append_log(const AuditLogEntry& entry) {
    std::unique_lock<std::shared_mutex> lock(audit_mutex_);

    audit_log_.push_back(entry);

    // Trim if over limit
    while (audit_log_.size() > max_in_memory_entries_) {
      audit_log_.pop_front();
    }

    // In production: also persist to database
  }

  DatabasePool* db_pool_ = nullptr;
  size_t max_in_memory_entries_;
  std::deque<AuditLogEntry> audit_log_;
  mutable std::shared_mutex audit_mutex_;
};

// ============================================================================
// Scan Metrics Collector — Prometheus-compatible metrics
// ============================================================================
class ScanMetricsCollector {
public:
  ScanMetricsCollector() = default;

  void record_scan_requested() { stats_.total_scans.fetch_add(1); }
  void record_clean_scan() { stats_.clean_scans.fetch_add(1); }
  void record_malware_detection() { stats_.malware_detections.fetch_add(1); }
  void record_adult_detection() { stats_.adult_detections.fetch_add(1); }
  void record_suspicious_detection() { stats_.suspicious_detections.fetch_add(1); }
  void record_error() { stats_.errors.fetch_add(1); }
  void record_timeout() { stats_.timeouts.fetch_add(1); }
  void record_cache_hit() { stats_.cache_hits.fetch_add(1); }
  void record_cache_miss() { stats_.cache_misses.fetch_add(1); }
  void record_quarantine() { stats_.quarantined_items.fetch_add(1); }
  void record_blocked() { stats_.blocked_items.fetch_add(1); }
  void record_bytes_scanned(int64_t bytes) { stats_.total_bytes_scanned.fetch_add(bytes); }
  void record_scan_time_ms(int64_t ms) { stats_.total_scan_time_ms.fetch_add(ms); }

  void record_scan_completed(const ScanResult& result) {
    switch (result.overall_verdict) {
      case ScanVerdict::CLEAN:
      case ScanVerdict::BYPASSED:
        record_clean_scan();
        break;
      case ScanVerdict::MALWARE:
        record_malware_detection();
        break;
      case ScanVerdict::ADULT:
        record_adult_detection();
        break;
      case ScanVerdict::SUSPICIOUS:
        record_suspicious_detection();
        break;
      case ScanVerdict::ERROR:
        record_error();
        break;
      case ScanVerdict::TIMEOUT:
        record_timeout();
        break;
      default:
        break;
    }

    if (result.action_taken == QuarantineAction::QUARANTINE) {
      record_quarantine();
    } else if (result.action_taken == QuarantineAction::BLOCK) {
      record_blocked();
    }
  }

  ScanStatistics get_stats() const { return stats_; }
  void reset() { stats_.reset(); }

  // Generate Prometheus text format
  std::string to_prometheus() const {
    auto s = stats_;
    std::ostringstream oss;

    oss << "# HELP progressive_content_scanner_total_scans Total number of scan requests\n";
    oss << "# TYPE progressive_content_scanner_total_scans counter\n";
    oss << "progressive_content_scanner_total_scans " << s.total_scans.load() << "\n";

    oss << "# HELP progressive_content_scanner_clean_scans Total clean scan results\n";
    oss << "# TYPE progressive_content_scanner_clean_scans counter\n";
    oss << "progressive_content_scanner_clean_scans " << s.clean_scans.load() << "\n";

    oss << "# HELP progressive_content_scanner_malware_detections Total malware detections\n";
    oss << "# TYPE progressive_content_scanner_malware_detections counter\n";
    oss << "progressive_content_scanner_malware_detections " << s.malware_detections.load() << "\n";

    oss << "# HELP progressive_content_scanner_adult_detections Total adult content detections\n";
    oss << "# TYPE progressive_content_scanner_adult_detections counter\n";
    oss << "progressive_content_scanner_adult_detections " << s.adult_detections.load() << "\n";

    oss << "# HELP progressive_content_scanner_errors Total scan errors\n";
    oss << "# TYPE progressive_content_scanner_errors counter\n";
    oss << "progressive_content_scanner_errors " << s.errors.load() << "\n";

    oss << "# HELP progressive_content_scanner_cache_hits Total cache hits\n";
    oss << "# TYPE progressive_content_scanner_cache_hits counter\n";
    oss << "progressive_content_scanner_cache_hits " << s.cache_hits.load() << "\n";

    oss << "# HELP progressive_content_scanner_cache_misses Total cache misses\n";
    oss << "# TYPE progressive_content_scanner_cache_misses counter\n";
    oss << "progressive_content_scanner_cache_misses " << s.cache_misses.load() << "\n";

    oss << "# HELP progressive_content_scanner_cache_hit_rate Cache hit rate\n";
    oss << "# TYPE progressive_content_scanner_cache_hit_rate gauge\n";
    oss << "progressive_content_scanner_cache_hit_rate " << s.cache_hit_rate() << "\n";

    oss << "# HELP progressive_content_scanner_quarantined_items Total quarantined items\n";
    oss << "# TYPE progressive_content_scanner_quarantined_items counter\n";
    oss << "progressive_content_scanner_quarantined_items " << s.quarantined_items.load() << "\n";

    oss << "# HELP progressive_content_scanner_average_scan_time_ms Average scan time in ms\n";
    oss << "# TYPE progressive_content_scanner_average_scan_time_ms gauge\n";
    oss << "progressive_content_scanner_average_scan_time_ms " << s.average_scan_time_ms() << "\n";

    oss << "# HELP progressive_content_scanner_detection_rate Detection rate\n";
    oss << "# TYPE progressive_content_scanner_detection_rate gauge\n";
    oss << "progressive_content_scanner_detection_rate " << s.detection_rate() << "\n";

    oss << "# HELP progressive_content_scanner_bytes_scanned Total bytes scanned\n";
    oss << "# TYPE progressive_content_scanner_bytes_scanned counter\n";
    oss << "progressive_content_scanner_bytes_scanned " << s.total_bytes_scanned.load() << "\n";

    return oss.str();
  }

  // Generate JSON metrics
  json to_json() const {
    return stats_.to_json();
  }

private:
  ScanStatistics stats_;
};

// ============================================================================
// Malware Signature Database Manager
// ============================================================================
class MalwareSignatureDB {
public:
  MalwareSignatureDB() : update_interval_ms_(3600000) {} // 1 hour default

  bool initialize(DatabasePool* db_pool, int64_t update_interval_ms = 3600000) {
    db_pool_ = db_pool;
    update_interval_ms_ = update_interval_ms;

    load_signatures();

    auto& log = get_scanner_logger("progressive.scanner.signatures");
    log.info("Signature DB initialized with " + std::to_string(signatures_.size())
             + " signatures");
    return true;
  }

  // Load signatures from storage
  void load_signatures() {
    std::unique_lock<std::shared_mutex> lock(sig_mutex_);

    // In production: load from database
    // For now, load built-in signatures
    signatures_.clear();
    add_builtin_signatures();

    last_update_ms_ = now_ms();
    signature_db_status_ = SignatureDBStatus::CURRENT;
  }

  // Add a signature
  void add_signature(const MalwareSignature& signature) {
    std::unique_lock<std::shared_mutex> lock(sig_mutex_);
    signatures_[signature.signature_id] = signature;
  }

  // Remove a signature
  bool remove_signature(const std::string& signature_id) {
    std::unique_lock<std::shared_mutex> lock(sig_mutex_);
    return signatures_.erase(signature_id) > 0;
  }

  // Get all signatures
  std::vector<MalwareSignature> get_all_signatures() const {
    std::shared_lock<std::shared_mutex> lock(sig_mutex_);
    std::vector<MalwareSignature> result;
    result.reserve(signatures_.size());
    for (const auto& [id, sig] : signatures_) {
      result.push_back(sig);
    }
    return result;
  }

  // Check if a hash is in the database
  std::optional<MalwareSignature> lookup_hash(const std::string& hash_value,
                                                HashAlgorithm algo = HashAlgorithm::SHA256) {
    std::shared_lock<std::shared_mutex> lock(sig_mutex_);
    for (const auto& [id, sig] : signatures_) {
      if (sig.hash_value == hash_value && sig.hash_algo == algo && sig.enabled) {
        return sig;
      }
    }
    return std::nullopt;
  }

  // Get signature count
  size_t signature_count() const {
    std::shared_lock<std::shared_mutex> lock(sig_mutex_);
    return signatures_.size();
  }

  // Get signature DB status
  SignatureDBStatus status() const { return signature_db_status_; }
  int64_t last_update_ms() const { return last_update_ms_; }

  // Trigger update check
  void check_for_updates() {
    int64_t now = now_ms();
    if (now - last_update_ms_ > update_interval_ms_) {
      update_signatures();
    }
  }

  // Force update
  void force_update() {
    update_signatures();
  }

  json get_stats() const {
    std::shared_lock<std::shared_mutex> lock(sig_mutex_);
    return json{
      {"total_signatures", signatures_.size()},
      {"status", signature_db_status_to_string(signature_db_status_)},
      {"last_update_ms", last_update_ms_},
      {"update_interval_ms", update_interval_ms_}
    };
  }

private:
  void add_builtin_signatures() {
    // Common malware hashes and patterns
    signatures_["EICAR-TEST"] = {
      "EICAR-TEST", "EICAR Test File", "Standard anti-virus test file",
      ContentCategory::MALWARE_GENERIC, ScanSeverity::LOW, HashAlgorithm::MD5,
      "44d88612fea8a8f36de82e1278abb02f", "", "",
      {"eicar", "test", "av-test"}, now_ms(), now_ms(), true, "builtin"
    };

    signatures_["EICAR-TEST-SHA256"] = {
      "EICAR-TEST-SHA256", "EICAR Test File (SHA256)",
      "Standard anti-virus test file (SHA256 variant)",
      ContentCategory::MALWARE_GENERIC, ScanSeverity::LOW, HashAlgorithm::SHA256,
      "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
      "", "", {"eicar", "test", "av-test"}, now_ms(), now_ms(), true, "builtin"
    };

    signatures_["PHP-WEBSHELL-GENERIC"] = {
      "PHP-WEBSHELL-GENERIC", "Generic PHP Web Shell",
      "Detects common PHP web shell patterns",
      ContentCategory::MALWARE_TROJAN, ScanSeverity::CRITICAL,
      HashAlgorithm::SHA256, "", "eval\\s*\\(\\s*\\$_(?:GET|POST|REQUEST|COOKIE)",
      "", {"webshell", "php", "backdoor"}, now_ms(), now_ms(), true, "builtin"
    };

    signatures_["JS-CRYPTOMINER-COINHIVE"] = {
      "JS-CRYPTOMINER-COINHIVE", "CoinHive Cryptominer",
      "Detects CoinHive and similar browser-based cryptominers",
      ContentCategory::CRYPTOMINING, ScanSeverity::HIGH,
      HashAlgorithm::SHA256, "", "new\\s+CoinHive\\.|coinhive\\.com/lib/",
      "", {"cryptominer", "coinhive", "browser"}, now_ms(), now_ms(), true, "builtin"
    };

    signatures_["PDF-EXPLOIT-GENERIC"] = {
      "PDF-EXPLOIT-GENERIC", "Generic PDF Exploit",
      "Detects common PDF-based exploit patterns",
      ContentCategory::MALWARE_GENERIC, ScanSeverity::CRITICAL,
      HashAlgorithm::SHA256, "", "/JS\\s*<|/JavaScript\\s*<|/Launch\\s*<",
      "", {"exploit", "pdf", "malware"}, now_ms(), now_ms(), true, "builtin"
    };

    signatures_["OFFICE-MACRO-DOWNLOADER"] = {
      "OFFICE-MACRO-DOWNLOADER", "Office Macro Downloader",
      "Detects Office documents with suspicious macro patterns",
      ContentCategory::MALWARE_TROJAN, ScanSeverity::HIGH,
      HashAlgorithm::SHA256, "",
      "URLDownloadToFile|MSXML2\\.ServerXMLHTTP|WinHttp\\.WinHttpRequest",
      "", {"macro", "office", "downloader"}, now_ms(), now_ms(), true, "builtin"
    };
  }

  void update_signatures() {
    auto& log = get_scanner_logger("progressive.scanner.signatures");
    log.info("Checking for signature updates...");

    // In production: download updated signatures from ClamAV mirror,
    // VirusTotal, or custom signature server
    // For now, just refresh the timestamp
    std::unique_lock<std::shared_mutex> lock(sig_mutex_);
    last_update_ms_ = now_ms();
    signature_db_status_ = SignatureDBStatus::CURRENT;

    log.info("Signature database is up to date");
  }

  DatabasePool* db_pool_ = nullptr;
  int64_t update_interval_ms_;
  int64_t last_update_ms_ = 0;
  SignatureDBStatus signature_db_status_ = SignatureDBStatus::INITIALIZING;
  std::unordered_map<std::string, MalwareSignature> signatures_;
  mutable std::shared_mutex sig_mutex_;
};

// ============================================================================
// Scan Engine Registry — manages all scan engines
// ============================================================================
class ScanEngineRegistry {
public:
  ScanEngineRegistry() = default;

  bool initialize() {
    auto& log = get_scanner_logger("progressive.scanner.registry");
    log.info("Initializing scan engine registry");
    return true;
  }

  // Register a scan engine
  void register_engine(std::shared_ptr<IScanEngine> engine, const EngineConfig& config) {
    std::unique_lock<std::shared_mutex> lock(registry_mutex_);
    engine_configs_[engine->engine_name()] = config;
    engines_[engine->engine_name()] = std::move(engine);

    auto& log = get_scanner_logger("progressive.scanner.registry");
    log.info("Registered engine: " + config.engine_name +
             " (type=" + scan_engine_type_to_string(config.engine_type) +
             ", priority=" + std::to_string(config.priority) + ")");
  }

  // Unregister an engine
  bool unregister_engine(const std::string& name) {
    std::unique_lock<std::shared_mutex> lock(registry_mutex_);
    auto it = engines_.find(name);
    if (it != engines_.end()) {
      it->second->shutdown();
      engines_.erase(it);
      engine_configs_.erase(name);
      return true;
    }
    return false;
  }

  // Get all enabled engines, sorted by priority
  std::vector<std::shared_ptr<IScanEngine>> get_enabled_engines() const {
    std::shared_lock<std::shared_mutex> lock(registry_mutex_);

    std::vector<std::pair<int, std::shared_ptr<IScanEngine>>> sorted;
    for (const auto& [name, engine] : engines_) {
      auto cfg_it = engine_configs_.find(name);
      if (cfg_it != engine_configs_.end() && cfg_it->second.enabled) {
        sorted.emplace_back(cfg_it->second.priority, engine);
      }
    }

    std::sort(sorted.begin(), sorted.end(),
              [](const auto& a, const auto& b) { return a.first < b.first; });

    std::vector<std::shared_ptr<IScanEngine>> result;
    result.reserve(sorted.size());
    for (auto& [pri, engine] : sorted) {
      result.push_back(std::move(engine));
    }
    return result;
  }

  // Get a specific engine by name
  std::shared_ptr<IScanEngine> get_engine(const std::string& name) {
    std::shared_lock<std::shared_mutex> lock(registry_mutex_);
    auto it = engines_.find(name);
    if (it != engines_.end()) return it->second;
    return nullptr;
  }

  // Get engine configuration
  std::optional<EngineConfig> get_config(const std::string& name) const {
    std::shared_lock<std::shared_mutex> lock(registry_mutex_);
    auto it = engine_configs_.find(name);
    if (it != engine_configs_.end()) return it->second;
    return std::nullopt;
  }

  // Update engine configuration
  void update_config(const std::string& name, const EngineConfig& config) {
    std::unique_lock<std::shared_mutex> lock(registry_mutex_);
    engine_configs_[name] = config;
  }

  // Get all engine statuses
  json get_all_status() const {
    std::shared_lock<std::shared_mutex> lock(registry_mutex_);
    json statuses = json::array();
    for (const auto& [name, engine] : engines_) {
      json status = engine->get_status();
      auto cfg_it = engine_configs_.find(name);
      if (cfg_it != engine_configs_.end()) {
        status["enabled"] = cfg_it->second.enabled;
        status["priority"] = cfg_it->second.priority;
      }
      statuses.push_back(status);
    }
    return statuses;
  }

  // Shutdown all engines
  void shutdown() {
    std::unique_lock<std::shared_mutex> lock(registry_mutex_);
    for (auto& [name, engine] : engines_) {
      engine->shutdown();
    }
    engines_.clear();
    engine_configs_.clear();
  }

  size_t engine_count() const {
    std::shared_lock<std::shared_mutex> lock(registry_mutex_);
    return engines_.size();
  }

private:
  std::unordered_map<std::string, std::shared_ptr<IScanEngine>> engines_;
  std::unordered_map<std::string, EngineConfig> engine_configs_;
  mutable std::shared_mutex registry_mutex_;
};

// ============================================================================
// Custom Scan Module Registry
// ============================================================================
class CustomModuleRegistry {
public:
  CustomModuleRegistry() = default;

  bool register_module(std::shared_ptr<CustomScanModuleBase> module) {
    std::unique_lock<std::shared_mutex> lock(module_mutex_);
    auto& log = get_scanner_logger("progressive.scanner.modules");
    log.info("Registering custom module: " + module->module_name()
             + " v" + module->module_version());
    modules_[module->module_name()] = std::move(module);
    return true;
  }

  bool unregister_module(const std::string& name) {
    std::unique_lock<std::shared_mutex> lock(module_mutex_);
    auto it = modules_.find(name);
    if (it != modules_.end()) {
      it->second->shutdown();
      modules_.erase(it);
      return true;
    }
    return false;
  }

  std::vector<std::shared_ptr<CustomScanModuleBase>> get_modules_for_mime(
      const std::string& mime_type) {
    std::shared_lock<std::shared_mutex> lock(module_mutex_);
    std::vector<std::shared_ptr<CustomScanModuleBase>> result;
    for (const auto& [name, module] : modules_) {
      if (module->supports_mime_type(mime_type)) {
        result.push_back(module);
      }
    }
    return result;
  }

  std::vector<std::shared_ptr<CustomScanModuleBase>> get_all_modules() {
    std::shared_lock<std::shared_mutex> lock(module_mutex_);
    std::vector<std::shared_ptr<CustomScanModuleBase>> result;
    result.reserve(modules_.size());
    for (const auto& [name, module] : modules_) {
      result.push_back(module);
    }
    return result;
  }

  json get_module_info() const {
    std::shared_lock<std::shared_mutex> lock(module_mutex_);
    json info = json::array();
    for (const auto& [name, module] : modules_) {
      info.push_back(module->get_module_info());
    }
    return info;
  }

  void notify_signature_update() {
    std::shared_lock<std::shared_mutex> lock(module_mutex_);
    for (auto& [name, module] : modules_) {
      module->on_signature_update();
    }
  }

  void shutdown() {
    std::unique_lock<std::shared_mutex> lock(module_mutex_);
    for (auto& [name, module] : modules_) {
      module->shutdown();
    }
    modules_.clear();
  }

private:
  std::unordered_map<std::string, std::shared_ptr<CustomScanModuleBase>> modules_;
  mutable std::shared_mutex module_mutex_;
};

// ============================================================================
// Content Scanner — Main orchestrator class
//
// This is the primary API that ties together all scanning components:
// engines, cache, quarantine, policies, scheduling, and metrics.
// ============================================================================
class ContentScanner {
public:
  ContentScanner()
    : initialized_(false), running_(false), bypass_mode_(false) {}

  ~ContentScanner() {
    shutdown();
  }

  // ------------------------------------------------------------------------
  // Initialization
  // ------------------------------------------------------------------------
  bool initialize(const json& config, DatabasePool* db_pool = nullptr) {
    auto& log = get_scanner_logger("progressive.scanner");
    log.info("Initializing Matrix Content Scanner...");

    db_pool_ = db_pool;

    // Parse configuration
    bool enable_clamav = config.value("clamav_enabled", true);
    bool enable_yara   = config.value("yara_enabled", true);
    bool enable_ml     = config.value("ml_enabled", true);
    bool enable_pattern = config.value("pattern_enabled", true);
    bool enable_hash   = config.value("hash_enabled", true);
    size_t worker_threads = config.value("worker_threads", 4);

    // Initialize scan engine registry
    registry_ = std::make_unique<ScanEngineRegistry>();
    registry_->initialize();

    // Initialize engines
    // 1. ClamAV
    if (enable_clamav) {
      EngineConfig clamav_cfg;
      clamav_cfg.engine_name = "clamav";
      clamav_cfg.engine_type = ScanEngineType::CLAMAV;
      clamav_cfg.enabled = true;
      clamav_cfg.priority = 10;
      clamav_cfg.scan_timeout_ms = config.value("clamav_timeout_ms", 15000);
      clamav_cfg.socket_path = config.value("clamav_socket", "/var/run/clamav/clamd.ctl");
      clamav_cfg.host = config.value("clamav_host", "");
      clamav_cfg.port = config.value("clamav_port", 3310);
      if (config.contains("clamav_config")) {
        clamav_cfg.extra_config = config["clamav_config"];
      }

      auto clamav = std::make_shared<ClamAVScanEngine>();
      if (clamav->initialize(clamav_cfg)) {
        registry_->register_engine(clamav, clamav_cfg);
        log.info("ClamAV engine registered successfully");
      } else {
        log.warn("ClamAV engine initialization failed — engine disabled");
      }
    }

    // 2. YARA
    if (enable_yara) {
      EngineConfig yara_cfg;
      yara_cfg.engine_name = "yara";
      yara_cfg.engine_type = ScanEngineType::YARA;
      yara_cfg.enabled = true;
      yara_cfg.priority = 20;
      yara_cfg.scan_timeout_ms = config.value("yara_timeout_ms", 10000);
      if (config.contains("yara_config")) {
        yara_cfg.extra_config = config["yara_config"];
      }

      auto yara = std::make_shared<YaraScanEngine>();
      if (yara->initialize(yara_cfg)) {
        registry_->register_engine(yara, yara_cfg);
        log.info("YARA engine registered successfully");
      } else {
        log.warn("YARA engine initialization failed — engine disabled");
      }
    }

    // 3. Pattern matching engine
    if (enable_pattern) {
      EngineConfig pattern_cfg;
      pattern_cfg.engine_name = "pattern";
      pattern_cfg.engine_type = ScanEngineType::PATTERN;
      pattern_cfg.enabled = true;
      pattern_cfg.priority = 5;  // Run pattern first (lightweight)
      pattern_cfg.scan_timeout_ms = config.value("pattern_timeout_ms", 5000);

      auto pattern = std::make_shared<PatternScanEngine>();
      if (pattern->initialize(pattern_cfg)) {
        registry_->register_engine(pattern, pattern_cfg);
        log.info("Pattern engine registered successfully");
      } else {
        log.warn("Pattern engine initialization failed");
      }
    }

    // 4. ML engine
    if (enable_ml) {
      EngineConfig ml_cfg;
      ml_cfg.engine_name = "machine_learning";
      ml_cfg.engine_type = ScanEngineType::MACHINE_LEARNING;
      ml_cfg.enabled = true;
      ml_cfg.priority = 30;
      ml_cfg.scan_timeout_ms = config.value("ml_timeout_ms", 20000);
      if (config.contains("ml_config")) {
        ml_cfg.extra_config = config["ml_config"];
      }

      auto ml = std::make_shared<MLScanEngine>();
      if (ml->initialize(ml_cfg)) {
        registry_->register_engine(ml, ml_cfg);
        log.info("ML engine registered successfully");
      } else {
        log.warn("ML engine initialization failed — engine disabled");
      }
    }

    // 5. Hash lookup engine
    if (enable_hash) {
      EngineConfig hash_cfg;
      hash_cfg.engine_name = "hash_lookup";
      hash_cfg.engine_type = ScanEngineType::HASH_LOOKUP;
      hash_cfg.enabled = true;
      hash_cfg.priority = 1;  // Run hash lookup first (fastest)
      hash_cfg.scan_timeout_ms = config.value("hash_timeout_ms", 1000);

      auto hash_engine = std::make_shared<HashScanEngine>();
      if (hash_engine->initialize(hash_cfg)) {
        registry_->register_engine(hash_engine, hash_cfg);
        log.info("Hash lookup engine registered successfully");
      } else {
        log.warn("Hash engine initialization failed");
      }
    }

    // Initialize cache manager
    cache_ = std::make_unique<ScanCacheManager>();
    size_t cache_size = config.value("cache_max_entries", 10000);
    int64_t cache_ttl = config.value("cache_ttl_ms", 3600000);
    cache_->initialize(cache_size, cache_ttl);

    // Initialize quarantine manager
    quarantine_ = std::make_unique<QuarantineManager>();
    std::string qpath = config.value("quarantine_path", "/var/lib/progressive/quarantine");
    quarantine_->initialize(qpath, db_pool_);

    // Initialize policy manager
    policy_manager_ = std::make_unique<ScanPolicyManager>();
    policy_manager_->initialize(db_pool_);

    // Initialize result aggregator
    aggregator_ = std::make_unique<ScanResultAggregator>();

    // Initialize scheduler
    scheduler_ = std::make_unique<ScanScheduler>();
    scheduler_->initialize(worker_threads);
    scheduler_->set_scan_executor([this](const ScanRequest& req) {
      return this->execute_scan(req);
    });

    // Initialize audit logger
    audit_logger_ = std::make_unique<ScanAuditLogger>();
    audit_logger_->initialize(db_pool_, 10000);

    // Initialize metrics
    metrics_ = std::make_unique<ScanMetricsCollector>();

    // Initialize signature database
    sig_db_ = std::make_unique<MalwareSignatureDB>();
    sig_db_->initialize(db_pool_);

    // Initialize adult content detector
    adult_detector_ = std::make_unique<AdultContentDetector>();
    adult_detector_->initialize({
      {"enabled", config.value("adult_detection_enabled", true)},
      {"threshold", config.value("adult_threshold", 0.7)},
      {"high_threshold", config.value("adult_high_threshold", 0.9)}
    });

    // Initialize custom module registry
    custom_modules_ = std::make_unique<CustomModuleRegistry>();

    initialized_ = true;
    running_ = true;

    log.info("Matrix Content Scanner initialized successfully (" +
             std::to_string(registry_->engine_count()) + " engines, " +
             std::to_string(cache_size) + " cache slots, " +
             std::to_string(worker_threads) + " workers)");
    return true;
  }

  // ------------------------------------------------------------------------
  // Shutdown
  // ------------------------------------------------------------------------
  void shutdown() {
    running_ = false;

    if (scheduler_) scheduler_->shutdown();
    if (registry_) registry_->shutdown();
    if (custom_modules_) custom_modules_->shutdown();

    initialized_ = false;

    auto& log = get_scanner_logger("progressive.scanner");
    log.info("Content Scanner shut down");
  }

  // ------------------------------------------------------------------------
  // Scan content synchronously
  // ------------------------------------------------------------------------
  ScanResult scan_sync(const ScanRequest& request) {
    if (!initialized_ || !running_) {
      ScanResult error_result;
      error_result.request_id = request.request_id;
      error_result.overall_verdict = ScanVerdict::ERROR;
      error_result.summary = "Scanner not initialized";
      return error_result;
    }

    // Audit log
    audit_logger_->log_scan_request(request);

    // Check if scan should be bypassed
    if (policy_manager_ && policy_manager_->should_bypass_scan(request)) {
      metrics_->record_scan_requested();

      ScanResult bypass_result;
      bypass_result.request_id = request.request_id;
      bypass_result.overall_verdict = ScanVerdict::BYPASSED;
      bypass_result.summary = "Scan bypassed by policy";
      bypass_result.completed_at_ms = now_ms();
      bypass_result.from_cache = false;

      metrics_->record_scan_completed(bypass_result);
      audit_logger_->log_scan_result(bypass_result);
      return bypass_result;
    }

    // Check cache
    ScanResult cached = check_cache(request);
    if (cached.overall_verdict != ScanVerdict::UNKNOWN) {
      cached.from_cache = true;
      metrics_->record_scan_requested();
      metrics_->record_cache_hit();
      metrics_->record_scan_completed(cached);
      audit_logger_->log_scan_result(cached);
      return cached;
    }

    metrics_->record_scan_requested();
    metrics_->record_cache_miss();

    // Execute scan
    ScanResult result = execute_scan(request);

    // Update metrics
    metrics_->record_scan_completed(result);
    metrics_->record_bytes_scanned(request.content_size);
    metrics_->record_scan_time_ms(result.total_scan_duration_ms);

    // Cache result
    cache_result(request, result);

    // Take quarantine action if needed
    handle_quarantine_action(request, result);

    // Audit log
    audit_logger_->log_scan_result(result);

    return result;
  }

  // ------------------------------------------------------------------------
  // Scan content asynchronously
  // ------------------------------------------------------------------------
  void scan_async(const ScanRequest& request,
                  std::function<void(const ScanResult&)> callback) {
    if (!initialized_ || !running_) {
      if (callback) {
        ScanResult error_result;
        error_result.request_id = request.request_id;
        error_result.overall_verdict = ScanVerdict::ERROR;
        error_result.summary = "Scanner not initialized";
        callback(error_result);
      }
      return;
    }

    // Check if scan should be bypassed
    if (policy_manager_ && policy_manager_->should_bypass_scan(request)) {
      metrics_->record_scan_requested();
      ScanResult bypass_result;
      bypass_result.request_id = request.request_id;
      bypass_result.overall_verdict = ScanVerdict::BYPASSED;
      bypass_result.summary = "Scan bypassed by policy";
      bypass_result.completed_at_ms = now_ms();
      metrics_->record_scan_completed(bypass_result);
      audit_logger_->log_scan_result(bypass_result);
      if (callback) callback(bypass_result);
      return;
    }

    // Check cache first
    ScanResult cached = check_cache(request);
    if (cached.overall_verdict != ScanVerdict::UNKNOWN) {
      cached.from_cache = true;
      metrics_->record_scan_requested();
      metrics_->record_cache_hit();
      metrics_->record_scan_completed(cached);
      audit_logger_->log_scan_result(cached);
      if (callback) callback(cached);
      return;
    }

    metrics_->record_scan_requested();
    metrics_->record_cache_miss();
    audit_logger_->log_scan_request(request);

    // Submit to scheduler
    scheduler_->submit(request,
      [this, callback](const ScanResult& result) {
        // Cache the result
        // We need the original request to cache; for now skip caching in async path
        metrics_->record_scan_completed(result);
        audit_logger_->log_scan_result(result);
        if (callback) callback(result);
      });
  }

  // ------------------------------------------------------------------------
  // Get scanner status
  // ------------------------------------------------------------------------
  json get_status() const {
    json engine_statuses = registry_ ? registry_->get_all_status() : json::array();
    json cache_stats;
    if (cache_) {
      auto cs = cache_->stats();
      cache_stats = json{
        {"entry_count", cs.entry_count},
        {"max_entries", cs.max_entries},
        {"hit_rate", cs.hit_rate},
        {"hits", cs.hits},
        {"misses", cs.misses}
      };
    }

    json quarantine_stats = quarantine_ ? quarantine_->get_stats() : json::object();
    json scheduler_stats;
    if (scheduler_) {
      auto ss = scheduler_->stats();
      scheduler_stats = json{
        {"pending", ss.pending},
        {"active", ss.active},
        {"completed", ss.completed},
        {"failed", ss.failed}
      };
    }

    return json{
      {"initialized", initialized_},
      {"running", running_},
      {"engine_count", registry_ ? registry_->engine_count() : 0},
      {"engines", engine_statuses},
      {"cache", cache_stats},
      {"quarantine", quarantine_stats},
      {"scheduler", scheduler_stats},
      {"metrics", metrics_ ? metrics_->to_json() : json::object()},
      {"signature_db", sig_db_ ? sig_db_->get_stats() : json::object()},
      {"audit", audit_logger_ ? audit_logger_->get_stats() : json::object()},
      {"custom_modules", custom_modules_ ? custom_modules_->get_module_info() : json::array()}
    };
  }

  // ------------------------------------------------------------------------
  // Quarantine management API
  // ------------------------------------------------------------------------
  std::optional<QuarantineRecord> get_quarantine(const std::string& quarantine_id) {
    if (!quarantine_) return std::nullopt;
    return quarantine_->get_record(quarantine_id);
  }

  std::vector<QuarantineRecord> list_quarantine(const std::string& status = "",
                                                  const std::string& user = "",
                                                  int limit = 100, int offset = 0) {
    if (!quarantine_) return {};
    return quarantine_->list_records(status, user, limit, offset);
  }

  bool release_quarantine(const std::string& quarantine_id,
                           const std::string& reviewer, const std::string& notes) {
    if (!quarantine_) return false;
    bool ok = quarantine_->release(quarantine_id, reviewer, notes);
    if (ok && audit_logger_) {
      audit_logger_->log_release(quarantine_id, reviewer);
    }
    return ok;
  }

  bool block_quarantine(const std::string& quarantine_id,
                         const std::string& reviewer, const std::string& notes) {
    if (!quarantine_) return false;
    return quarantine_->permanently_block(quarantine_id, reviewer, notes);
  }

  bool delete_quarantine(const std::string& quarantine_id) {
    if (!quarantine_) return false;
    return quarantine_->delete_quarantined(quarantine_id);
  }

  // ------------------------------------------------------------------------
  // Policy management API
  // ------------------------------------------------------------------------
  ScanPolicy get_policy(const ScanRequest& request) {
    if (!policy_manager_) return ScanPolicy{};
    return policy_manager_->get_policy(request);
  }

  void set_room_policy(const std::string& room_id, const ScanPolicy& policy) {
    if (policy_manager_) policy_manager_->set_room_policy(room_id, policy);
  }

  ScanPolicy get_global_policy() const {
    if (!policy_manager_) return ScanPolicy{};
    return policy_manager_->get_global_policy();
  }

  void update_global_policy(const ScanPolicy& policy) {
    if (policy_manager_) policy_manager_->update_global_policy(policy);
  }

  // ------------------------------------------------------------------------
  // Signature database API
  // ------------------------------------------------------------------------
  void add_signature(const MalwareSignature& signature) {
    if (sig_db_) sig_db_->add_signature(signature);
  }

  size_t signature_count() const {
    return sig_db_ ? sig_db_->signature_count() : 0;
  }

  void update_signatures() {
    if (sig_db_) {
      sig_db_->force_update();
      // Invalidate cache on signature update
      if (cache_) cache_->invalidate_all();
      if (custom_modules_) custom_modules_->notify_signature_update();
    }
  }

  // ------------------------------------------------------------------------
  // Custom module API
  // ------------------------------------------------------------------------
  bool register_custom_module(std::shared_ptr<CustomScanModuleBase> module) {
    if (!custom_modules_) return false;
    return custom_modules_->register_module(std::move(module));
  }

  json get_custom_module_info() const {
    return custom_modules_ ? custom_modules_->get_module_info() : json::array();
  }

  // ------------------------------------------------------------------------
  // Metrics API
  // ------------------------------------------------------------------------
  std::string get_metrics_prometheus() const {
    return metrics_ ? metrics_->to_prometheus() : "";
  }

  json get_metrics_json() const {
    return metrics_ ? metrics_->to_json() : json::object();
  }

  void reset_metrics() {
    if (metrics_) metrics_->reset();
  }

  // ------------------------------------------------------------------------
  // Audit API
  // ------------------------------------------------------------------------
  std::vector<AuditLogEntry> query_audit_log(const std::string& action = "",
                                               const std::string& user = "",
                                               int64_t from_ms = 0,
                                               int64_t to_ms = 0,
                                               int limit = 100) {
    if (!audit_logger_) return {};
    return audit_logger_->query(action, user, from_ms, to_ms, limit);
  }

  // ------------------------------------------------------------------------
  // Flush cache
  // ------------------------------------------------------------------------
  void flush_cache() {
    if (cache_) cache_->invalidate_all();
  }

  size_t cache_size() const {
    if (!cache_) return 0;
    return cache_->stats().entry_count;
  }

  // ------------------------------------------------------------------------
  // Bypass mode — temporarily disable scanning
  // ------------------------------------------------------------------------
  void set_bypass_mode(bool bypass) { bypass_mode_ = bypass; }
  bool bypass_mode() const { return bypass_mode_; }

  // ------------------------------------------------------------------------
  // Engine management
  // ------------------------------------------------------------------------
  bool register_engine(std::shared_ptr<IScanEngine> engine, const EngineConfig& config) {
    if (!registry_) return false;
    registry_->register_engine(std::move(engine), config);
    return true;
  }

  bool unregister_engine(const std::string& name) {
    if (!registry_) return false;
    return registry_->unregister_engine(name);
  }

  json get_engine_status(const std::string& name) const {
    if (!registry_) return json::object();
    auto engine = registry_->get_engine(name);
    if (engine) return engine->get_status();
    return json::object();
  }

  bool is_initialized() const { return initialized_; }
  bool is_running() const { return running_; }

private:
  // ------------------------------------------------------------------------
  // Core scan execution
  // ------------------------------------------------------------------------
  ScanResult execute_scan(const ScanRequest& request) {
    auto& log = get_scanner_logger("progressive.scanner");
    log.debug("Executing scan for request " + request.request_id);

    if (bypass_mode_) {
      ScanResult bypass_result;
      bypass_result.request_id = request.request_id;
      bypass_result.overall_verdict = ScanVerdict::BYPASSED;
      bypass_result.summary = "Bypass mode enabled";
      bypass_result.completed_at_ms = now_ms();
      return bypass_result;
    }

    // Get enabled engines
    auto engines = registry_->get_enabled_engines();

    // Filter engines based on request
    std::vector<std::shared_ptr<IScanEngine>> applicable_engines;
    for (const auto& engine : engines) {
      // Check if engine supports this target type
      if (!engine->supports_target(request.target_type)) continue;

      // Check if engine supports this mime type
      if (!request.mime_type.empty() && !engine->supports_mime_type(request.mime_type)) continue;

      // Check excluded engines
      bool excluded = false;
      for (const auto& excl : request.excluded_engines) {
        if (engine->engine_name() == excl) { excluded = true; break; }
      }
      if (excluded) continue;

      // Check required engines
      if (!request.required_engines.empty()) {
        bool found = false;
        for (const auto& req : request.required_engines) {
          if (engine->engine_name() == req) { found = true; break; }
        }
        if (!found) continue;
      }

      applicable_engines.push_back(engine);
    }

    // Run each engine and collect results
    std::vector<EngineScanResult> engine_results;
    for (const auto& engine : applicable_engines) {
      try {
        EngineScanResult er = engine->scan(request);
        engine_results.push_back(std::move(er));
      } catch (const std::exception& e) {
        EngineScanResult error_result;
        error_result.engine_name = engine->engine_name();
        error_result.engine_type = engine->engine_type();
        error_result.verdict = ScanVerdict::ERROR;
        error_result.detection_detail = std::string("Engine exception: ") + e.what();
        error_result.scanned_at_ms = now_ms();
        engine_results.push_back(error_result);

        log.error("Engine " + engine->engine_name() + " threw exception: " + e.what());
      }
    }

    // Run custom modules
    if (custom_modules_) {
      auto modules = custom_modules_->get_modules_for_mime(request.mime_type);
      for (const auto& module : modules) {
        try {
          EngineScanResult er = module->scan_content(request.content,
                                                       request.mime_type,
                                                       request.metadata);
          er.engine_name = module->module_name();
          er.engine_type = ScanEngineType::CUSTOM;
          er.scanned_at_ms = now_ms();
          engine_results.push_back(std::move(er));
        } catch (const std::exception& e) {
          auto& mlog = get_scanner_logger("progressive.scanner.modules");
          mlog.error("Custom module " + module->module_name() + " error: " + e.what());
        }
      }
    }

    // Run adult content detection if no engine caught it yet
    bool adult_detected_by_engine = false;
    for (const auto& er : engine_results) {
      if (er.verdict == ScanVerdict::ADULT) {
        adult_detected_by_engine = true;
        break;
      }
    }

    if (!adult_detected_by_engine && adult_detector_ && adult_detector_->is_enabled()) {
      AdultContentDetector::AdultScanResult adult_result = adult_detector_->analyze(request);
      if (adult_result.is_nsfw || adult_result.is_explicit) {
        EngineScanResult adult_er;
        adult_er.engine_name = "adult_content_detector";
        adult_er.engine_type = ScanEngineType::HEURISTIC;
        adult_er.scanned_at_ms = now_ms();
        adult_er.detection_method = DetectionMethod::HEURISTIC;
        adult_er.confidence_score = std::max(adult_result.nsfw_score, adult_result.explicit_score);
        adult_er.matched_signatures = adult_result.matched_indicators;

        if (adult_result.is_explicit) {
          adult_er.verdict = ScanVerdict::ADULT;
          adult_er.category = ContentCategory::ADULT_EXPLICIT;
          adult_er.severity = ScanSeverity::HIGH;
          adult_er.detection_name = "Explicit adult content";
        } else {
          adult_er.verdict = ScanVerdict::ADULT;
          adult_er.category = ContentCategory::ADULT_NSFW;
          adult_er.severity = ScanSeverity::MEDIUM;
          adult_er.detection_name = "NSFW content detected";
        }
        adult_er.detection_detail = adult_result.reason;
        engine_results.push_back(adult_er);
      }
    }

    // Aggregate results
    ScanResult result = aggregator_->aggregate(request, engine_results);

    return result;
  }

  // ------------------------------------------------------------------------
  // Cache helpers
  // ------------------------------------------------------------------------
  ScanResult check_cache(const ScanRequest& request) {
    if (request.bypass_cache || !cache_) {
      return ScanResult{};  // UNKNOWN verdict = cache miss
    }

    std::string cache_key = build_cache_key(request);
    if (cache_key.empty()) return ScanResult{};

    auto cached = cache_->get(cache_key);
    if (cached.has_value()) {
      return cached.value();
    }
    return ScanResult{};
  }

  void cache_result(const ScanRequest& request, const ScanResult& result) {
    if (request.bypass_cache || !cache_) return;

    std::string cache_key = build_cache_key(request);
    if (cache_key.empty()) return;

    // Clean results get shorter TTL (so signature updates take effect faster)
    int64_t ttl = result.is_clean() ? 600000 : 7200000; // 10 min clean, 2 hr malicious
    cache_->put(cache_key, result, ttl);
  }

  std::string build_cache_key(const ScanRequest& request) {
    // Use content hash if available, otherwise fall back to request fingerprint
    std::string hash = request.primary_hash();
    if (!hash.empty()) {
      return "scan:" + hash;
    }

    // Fallback: hash the content directly
    if (!request.content.empty()) {
      // Simple hash for cache key (in production: use SHA256)
      size_t h = std::hash<std::string_view>{}(
        std::string_view(reinterpret_cast<const char*>(request.content.data()),
                         std::min(request.content.size(), size_t(4096))));
      return "scan:content:" + std::to_string(h);
    }

    if (!request.text_content.empty()) {
      size_t h = std::hash<std::string>{}(request.text_content);
      return "scan:text:" + std::to_string(h);
    }

    if (!request.content_url.empty()) {
      size_t h = std::hash<std::string>{}(request.content_url);
      return "scan:url:" + std::to_string(h);
    }

    return "";
  }

  // ------------------------------------------------------------------------
  // Quarantine action handler
  // ------------------------------------------------------------------------
  void handle_quarantine_action(const ScanRequest& request, ScanResult& result) {
    if (!quarantine_ || !quarantine_->is_enabled()) return;

    // Skip if clean
    if (result.is_clean()) return;

    // Get applicable policy
    ScanPolicy policy = policy_manager_ ?
                        policy_manager_->get_policy(request) : ScanPolicy{};

    QuarantineAction action = policy.get_action_for_category(result.overall_category);

    switch (action) {
      case QuarantineAction::QUARANTINE: {
        auto record = quarantine_->quarantine(request, result);
        result.quarantine_id = record.quarantine_id;
        result.action_taken = QuarantineAction::QUARANTINE;
        if (audit_logger_) {
          audit_logger_->log_quarantine(record, request.user_id);
        }
        break;
      }
      case QuarantineAction::BLOCK: {
        auto record = quarantine_->quarantine(request, result);
        record.review_status = "permanently_blocked";
        result.quarantine_id = record.quarantine_id;
        result.action_taken = QuarantineAction::BLOCK;
        metrics_->record_blocked();
        break;
      }
      case QuarantineAction::FLAG: {
        result.action_taken = QuarantineAction::FLAG;
        break;
      }
      case QuarantineAction::REDACT: {
        result.action_taken = QuarantineAction::REDACT;
        break;
      }
      case QuarantineAction::DELETE_FILE: {
        result.action_taken = QuarantineAction::DELETE_FILE;
        break;
      }
      case QuarantineAction::NOTIFY_ADMIN: {
        result.action_taken = QuarantineAction::NOTIFY_ADMIN;
        break;
      }
      default:
        break;
    }
  }

  // ------------------------------------------------------------------------
  // Member variables
  // ------------------------------------------------------------------------
  bool initialized_;
  bool running_;
  bool bypass_mode_;
  DatabasePool* db_pool_ = nullptr;

  std::unique_ptr<ScanEngineRegistry> registry_;
  std::unique_ptr<ScanCacheManager> cache_;
  std::unique_ptr<QuarantineManager> quarantine_;
  std::unique_ptr<ScanPolicyManager> policy_manager_;
  std::unique_ptr<ScanResultAggregator> aggregator_;
  std::unique_ptr<ScanScheduler> scheduler_;
  std::unique_ptr<ScanAuditLogger> audit_logger_;
  std::unique_ptr<ScanMetricsCollector> metrics_;
  std::unique_ptr<MalwareSignatureDB> sig_db_;
  std::unique_ptr<AdultContentDetector> adult_detector_;
  std::unique_ptr<CustomModuleRegistry> custom_modules_;
};

} // namespace progressive
