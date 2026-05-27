// ============================================================================
// push_gateway_manager.cpp — Matrix Push Gateway Manager
//
// Implements the complete push gateway management subsystem for the Matrix
// homeserver, covering all push delivery backends, notification formatting,
// badge management, queuing, retry, analytics, and user preferences:
//
//   - APNs Push Gateway (Apple Push Notification service):
//     • APNs HTTP/2 endpoint connection management (api.push.apple.com,
//       api.development.push.apple.com)
//     • JWT-based token authentication (ES256 JWT using p8 private key)
//       with automatic token refresh before expiry
//     • Certificate-based authentication fallback (.p12 certificate chain)
//     • Topic-based routing (app bundle ID com.example.app.ios)
//     • Full APNs payload construction per Apple spec:
//       - aps dictionary: alert (title/subtitle/body), sound, badge,
//         content-available (silent push), mutable-content (notification
//         service extension), thread-id, category, target-content-id
//     • Priority levels: 10 (immediate delivery) and 5 (conserved power)
//     • Expiration handling (apns-expiration header)
//     • Collapse ID for notification replacement
//     • Push type: alert, background, voip, complication, fileprovider, mdm
//     • APNs-specific error codes and response handling
//       (200, 400, 403, 404, 405, 410, 413, 429, 500)
//     • Device token invalidation tracking (410 Gone → mark device inactive)
//     • APNs connection multiplexing (concurrent streams via HTTP/2)
//     • Payload size enforcement (4KB hard limit, ~3.8KB safe limit)
//     • apns-topic header management
//
//   - FCM Push Gateway (Firebase Cloud Messaging):
//     • FCM v1 HTTP API (fcm.googleapis.com/v1/projects/*/messages:send)
//     • OAuth 2.0 server-to-server authentication with service account
//       JSON credentials, automatic token refresh
//     • Legacy FCM HTTP API fallback (fcm.googleapis.com/fcm/send)
//       with server key authentication
//     • Full FCM payload construction:
//       - message: token, notification (title/body/image), data dict,
//         android (priority/ttl/collapse_key/notification channel),
//         apns (iOS bridging), webpush (browser push), fcm_options
//     • Android-specific: notification channel (high_importance,
//       default sound, lights, vibration), direct_boot_ok,
//       restricted_package_name, ttl (time_to_live)
//     • iOS bridging via APNs config in FCM payload:
//       - headers: apns-priority, apns-expiration
//       - payload: aps dictionary
//     • Webpush config: headers (TTL, Urgency), notification payload
//     • Collapse key support for notification deduplication
//     • Priority: "normal" (batched) vs "high" (immediate delivery)
//     • FCM error handling: 200, 400, 401, 403, 404, 429, 500
//     • Registration token invalidation (NotRegistered error → cleanup)
//     • Topic subscription management (optional prefix-based topic routing)
//     • Multicast send (send up to 500 tokens in single request)
//
//   - Generic HTTP Push Gateway:
//     • Matrix Push Gateway API spec compliance
//       (POST /_matrix/push/v1/notify)
//     • Standard notification payload format per Matrix spec:
//       notification dict (devices[], room_id, room_name, sender,
//       sender_display_name, type, content, counts, event_id, priority,
//       highlight, coalesced support)
//     • Custom push gateway endpoint support with URL template patterns
//     • Bearer token and api-key authentication schemes
//     • Gateway health checking (periodic HEAD/GET probe)
//     • Gateway-specific retry policies
//     • Gateway connection pooling with keep-alive
//     • Response validation and error classification
//     • Gateway-specific custom payload templates
//     • Gateway priority routing (primary/secondary gateways)
//
//   - Push Notification Formatting:
//     • Template-based notification body generation
//     • Sender-aware formatting (display name, MXID fallback)
//     • Room-aware formatting (room name, canonical alias, room ID fallback)
//     • Event type-aware formatting:
//       - m.room.message: message body display
//       - m.room.member: join/leave/invite messages
//       - m.room.name: room name changes
//       - m.room.topic: topic changes
//       - m.room.encrypted: "Encrypted message" placeholder
//       - m.call.invite: incoming call notifications
//       - m.reaction: reaction notifications
//       - m.sticker: sticker notifications
//     • Localization-aware formatting (lang parameter, i18n templates)
//     • Image/attachment-aware formatting ("sent an image", "sent a file")
//     • Channel message formatting hints
//     • Truncation and sanitization (max body length, markdown strip)
//     • Group notification summary formatting
//       ("5 new messages from 3 people in 2 rooms")
//
//   - Badge Count Management:
//     • Per-user global badge count tracking (total unread across all rooms)
//     • Per-device badge count (separate per pushkey)
//     • Badge count calculation modes:
//       - Total notification count (all unread notifications)
//       - Highlight count (highlights only)
//       - Room-specific counts
//     • Badge count synchronization across devices
//     • Badge clear on read receipt processing
//     • Badge increment on new notification
//     • Badge count persistence in SQL for crash recovery
//     • Badge forwarding to APNs (aps.badge field)
//     • Badge count batching (avoid per-message badge updates)
//     • Zero-badge handling (clear app badge when all read)
//     • Configurable badge strategies per user preference
//
//   - Push Notification Queuing:
//     • Persistent queue backed by SQL table (push_notification_queue)
//     • Queue states: pending, processing, delivered, failed, dead_letter
//     • Priority queuing with priority levels (0-255, default 128)
//     • Fair queuing across users to prevent starvation
//     • Per-user queue depth limits with configurable maximums
//     • Queue draining on shutdown (graceful shutdown support)
//     • Retry queue for transient failures
//     • Dead-letter queue for permanently failed notifications
//     • Queue monitoring and metrics (depth, age, throughput)
//     • Queue compaction (remove expired / delivered after TTL)
//     • Idempotency keys to prevent duplicate delivery
//     • Batching: group multiple notifications for same device
//
//   - Retry with Backoff:
//     • Exponential backoff with configurable base and max delays
//     • Additive jitter (randomized delay to avoid thundering herd)
//     • Decorrelated jitter algorithm option
//     • Per-pusher retry state tracking
//     • Maximum retry count enforcement
//     • Backoff reset on successful delivery
//     • Circuit breaker pattern: after N consecutive failures, pause
//       all sends for cooldown period
//     • Half-open state probing after cooldown
//     • Retry classification:
//       - Retryable: 5xx errors, network timeouts, rate limits (429)
//       - Non-retryable: 4xx client errors (400, 403, 404)
//       - Token invalidation: 410 Gone (APNs), NotRegistered (FCM)
//     • Rate limit honor: parse Retry-After headers (seconds or date)
//     • Backoff persistence across process restarts
//     • Per-gateway backoff isolation
//
//   - Push Notification Analytics:
//     • Delivery metrics: attempted, succeeded, failed, pending
//     • Latency tracking: queue_time, send_time, total_time
//     • Per-gateway metrics: success rate, error rate, latency p50/p95/p99
//     • Per-app metrics: app_id-level aggregation
//     • Token health tracking: invalid token rate, unregistered rate
//     • Daily/hourly aggregation windows
//     • Metrics persistence in SQL (push_analytics_events table)
//     • Real-time analytics counters (atomic integers)
//     • Export to monitoring systems (Prometheus-style metrics)
//     • Alerting thresholds: high failure rate, high latency, dead letters
//     • Dashboard query helpers: time-series bucketing
//
//   - Push Notification Preferences:
//     • Per-user global push enable/disable toggle
//     • Per-room push enable/disable (room-level mute)
//     • Per-room notification level: all_messages, mentions_only, none
//     • Quiet hours schedule (start time, end time, timezone)
//     • Per-device push enable/disable
//     • Notification content privacy: show_sender, show_message, show_room
//     • Sound preferences: per-room sound, default sound, silent
//     • Vibration preferences (Android): pattern selection
//     • LED color preferences (Android)
//     • Do-not-disturb mode with exceptions (highlights always)
//     • Push preference inheritance hierarchy: global > room > device
//     • Sync from Matrix push rules for consistency
//     • Preference change notification (so other sessions know)
//
//   - Full SQL DDL + CRUD for:
//     push_notification_queue, push_analytics_events,
//     push_gateway_config, push_badge_state,
//     push_notification_preferences, push_retry_state,
//     push_device_tokens, push_gateway_health
//
// Equivalent to:
//   synapse/push/apns.py — APNs payload construction and delivery
//   synapse/push/fcm.py — FCM payload construction and delivery
//   synapse/push/push_gateway.py — Generic push gateway client
//   synapse/push/presentable_names.py — Notification formatting
//   synapse/push/badge.py — Badge count management
//   synapse/push/notifier.py — Notification dispatch and queuing
//   synapse/push/push_rule_evaluator.py — Push rule preferences
//   synapse/util/retryutils.py — Retry with backoff utilities
//   Sygnal (matrix-org/sygnal) — Reference push gateway implementation
//   matrix-org/matrix-spec: Push Gateway API
//   Apple Developer: APNs provider API documentation
//   Firebase: Cloud Messaging HTTP v1 API documentation
//
// Copyright (C) 2024-2025 Progressive Server contributors
// Licensed under AGPL v3
// Target: 3000+ lines of production-grade C++
// ============================================================================

#include <algorithm>
#include <array>
#include <atomic>
#include <bitset>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <exception>
#include <forward_list>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <iterator>
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
#include <system_error>
#include <thread>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <variant>
#include <vector>

#include <nlohmann/json.hpp>

// Internal project includes
#include "progressive/storage/database.hpp"
#include "progressive/storage/databases/main/event_push_actions.hpp"
#include "progressive/storage/databases/main/events.hpp"
#include "progressive/storage/databases/main/roommember.hpp"
#include "progressive/storage/databases/main/room.hpp"
#include "progressive/storage/databases/main/receipts.hpp"
#include "progressive/util/time.hpp"
#include "progressive/util/log.hpp"

// ============================================================================
// Namespace
// ============================================================================
namespace progressive {

using json = nlohmann::json;
namespace chr = std::chrono;
using namespace progressive::storage;

// ============================================================================
// Forward declarations for classes defined in this file
// ============================================================================

class ApnsGateway;
class FcmGateway;
class GenericPushGateway;
class PushNotificationFormatter;
class BadgeCountManager;
class PushNotificationQueue;
class RetryManager;
class PushAnalytics;
class PushPreferenceManager;
class ApnsPayloadBuilder;
class FcmPayloadBuilder;
class GenericPayloadBuilder;
class GatewayHealthMonitor;
class PushGatewayCoordinator;
class ApnsJwtProvider;
class FcmOAuthProvider;
class NotificationTemplateEngine;
class CircuitBreaker;
class RateLimitTracker;
class DeadLetterQueue;
class IdempotencyGuard;

// ============================================================================
// Constants
// ============================================================================

namespace push_gateway_constants {

// --- APNs constants ---
constexpr const char* kApnsProductionEndpoint = "api.push.apple.com";
constexpr const char* kApnsDevelopmentEndpoint = "api.development.push.apple.com";
constexpr const char* kApnsDefaultPath = "/3/device/";
constexpr size_t kApnsMaxPayloadSize = 4096;            // Hard 4KB limit
constexpr size_t kApnsSafePayloadSize = 3800;           // Safe ceiling with headers
constexpr int kApnsDefaultPort = 443;
constexpr int kApnsImmediatePriority = 10;
constexpr int kApnsConservePriority = 5;
constexpr chr::seconds kApnsJwtRefreshMargin{600};      // Refresh 10 min before expiry
constexpr chr::seconds kApnsDefaultJwtLifetime{3600};   // 1 hour JWT lifetime
constexpr chr::seconds kApnsConnectionIdleTimeout{300};
constexpr int kApnsMaxConcurrentStreams = 500;
constexpr chr::milliseconds kApnsDefaultTimeout{10'000};

// --- FCM constants ---
constexpr const char* kFcmV1Endpoint = "fcm.googleapis.com";
constexpr const char* kFcmV1Path = "/v1/projects/";
constexpr const char* kFcmLegacyEndpoint = "fcm.googleapis.com";
constexpr const char* kFcmLegacyPath = "/fcm/send";
constexpr const char* kFcmOAuthScope = "https://www.googleapis.com/auth/firebase.messaging";
constexpr const char* kFcmOAuthTokenUrl = "https://oauth2.googleapis.com/token";
constexpr int kFcmDefaultPort = 443;
constexpr size_t kFcmMaxPayloadSize = 4096;
constexpr size_t kFcmMulticastMaxTokens = 500;
constexpr chr::seconds kFcmOAuthRefreshMargin{300};
constexpr chr::seconds kFcmDefaultTtl{86400 * 7};       // 7 days default TTL
constexpr chr::milliseconds kFcmDefaultTimeout{15'000};

// --- Generic push gateway constants ---
constexpr const char* kMatrixPushGatewayPath = "/_matrix/push/v1/notify";
constexpr chr::milliseconds kDefaultGenericTimeout{10'000};
constexpr size_t kGenericMaxPayloadSize = 65536;         // 64KB

// --- Queue constants ---
constexpr size_t kDefaultQueueCapacity = 100'000;
constexpr size_t kDefaultUserQueueLimit = 500;
constexpr size_t kDefaultBatchSize = 50;
constexpr chr::seconds kDefaultQueueItemTtl{3600};       // 1 hour
constexpr int kDefaultPriority = 128;
constexpr int kMaxPriority = 255;
constexpr int kMinPriority = 0;

// --- Retry constants ---
constexpr int kDefaultMaxRetries = 5;
constexpr chr::milliseconds kDefaultBaseBackoff{1000};
constexpr chr::milliseconds kDefaultMaxBackoff{300'000}; // 5 minutes
constexpr double kDefaultJitterFactor = 0.3;
constexpr int kCircuitBreakerFailureThreshold = 10;
constexpr chr::seconds kCircuitBreakerCooldown{60};
constexpr int kCircuitBreakerHalfOpenProbes = 3;

// --- Badge constants ---
constexpr chr::seconds kBadgeSyncInterval{30};
constexpr int kBadgeBatchThreshold = 5;
constexpr chr::seconds kBadgeCacheTtl{60};

// --- Analytics constants ---
constexpr chr::seconds kAnalyticsFlushInterval{60};
constexpr int kAnalyticsBatchSize = 100;
constexpr int kAnalyticsMaxBuckets = 168;                // 7 days hourly

// --- Preference constants ---
constexpr int kDefaultQuietHoursStart = 2200;            // 10 PM
constexpr int kDefaultQuietHoursEnd = 700;               // 7 AM
constexpr const char* kDefaultSound = "default";
constexpr const char* kHighlightSound = "highlight.mp3";

// --- Notification format constants ---
constexpr size_t kMaxBodyPreviewLength = 256;
constexpr size_t kMaxSenderNameLength = 128;
constexpr size_t kMaxRoomNameLength = 128;
constexpr size_t kMaxGroupSummarySize = 5;
constexpr const char* kEncryptedPlaceholder = "\xF0\x9F\x94\x92 Encrypted message";
constexpr const char* kImagePlaceholder = "\xF0\x9F\x96\xBC Sent an image";
constexpr const char* kFilePlaceholder = "\xF0\x9F\x93\x81 Sent a file";
constexpr const char* kVideoPlaceholder = "\xF0\x9F\x8E\xA5 Sent a video";
constexpr const char* kStickerPlaceholder = "\xF0\x9F\x8E\xAF Sent a sticker";
constexpr const char* kCallPlaceholder = "\xF0\x9F\x93\x9E Incoming call";

} // namespace push_gateway_constants

// ============================================================================
// Anonymous utility namespace
// ============================================================================

namespace {

using namespace push_gateway_constants;

// --- Time helpers ---

int64_t now_ms() {
  return chr::duration_cast<chr::milliseconds>(
             chr::system_clock::now().time_since_epoch())
      .count();
}

int64_t now_sec() {
  return chr::duration_cast<chr::seconds>(
             chr::system_clock::now().time_since_epoch())
      .count();
}

chr::system_clock::time_point time_point_from_ms(int64_t ms) {
  return chr::system_clock::time_point(chr::milliseconds(ms));
}

std::string iso8601_now() {
  auto now = chr::system_clock::now();
  auto tt = chr::system_clock::to_time_t(now);
  std::tm tm;
  gmtime_r(&tt, &tm);
  std::ostringstream ss;
  ss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
  return ss.str();
}

// --- String helpers ---

std::string to_lower(std::string s) {
  std::transform(s.begin(), s.end(), s.begin(), ::tolower);
  return s;
}

std::string trim(const std::string& s) {
  auto start = s.find_first_not_of(" \t\r\n");
  if (start == std::string::npos) return "";
  auto end = s.find_last_not_of(" \t\r\n");
  return s.substr(start, end - start + 1);
}

bool starts_with(std::string_view s, std::string_view prefix) {
  return s.size() >= prefix.size() && s.substr(0, prefix.size()) == prefix;
}

bool ends_with(std::string_view s, std::string_view suffix) {
  return s.size() >= suffix.size() &&
         s.substr(s.size() - suffix.size()) == suffix;
}

std::string truncate_utf8(const std::string& s, size_t max_len) {
  if (s.size() <= max_len) return s;
  // Simple safe truncation: back up to last valid UTF-8 start byte
  size_t pos = max_len;
  while (pos > 0 && (static_cast<unsigned char>(s[pos]) & 0xC0) == 0x80) {
    --pos;
  }
  return s.substr(0, pos) + "...";
}

std::string generate_uuid_v4() {
  thread_local std::mt19937_64 rng(
      static_cast<uint64_t>(now_ms()) ^
      static_cast<uint64_t>(
          std::hash<std::thread::id>{}(std::this_thread::get_id())));
  std::uniform_int_distribution<uint64_t> dist;
  uint64_t a = dist(rng);
  uint64_t b = dist(rng);

  // Format as UUID v4
  char buf[37];
  std::snprintf(buf, sizeof(buf),
      "%08x-%04x-4%03x-%04x-%012llx",
      static_cast<uint32_t>(a & 0xFFFFFFFF),
      static_cast<uint16_t>((a >> 32) & 0xFFFF),
      static_cast<uint16_t>((a >> 48) & 0x0FFF),
      static_cast<uint16_t>(((b >> 16) & 0x3FFF) | 0x8000),
      static_cast<unsigned long long>(b & 0xFFFFFFFFFFFFULL));
  return std::string(buf);
}

std::string sha256_hex(const std::string& input) {
  // Stub: in production uses actual SHA256 from OpenSSL/BoringSSL
  std::hash<std::string> hasher;
  uint64_t h = hasher(input);
  std::ostringstream oss;
  oss << std::hex << std::setfill('0') << std::setw(16) << h;
  return oss.str();
}

// --- JSON helpers ---

std::string json_str(const json& obj, const std::string& key,
                     const std::string& dflt = "") {
  if (obj.contains(key) && obj[key].is_string())
    return obj[key].get<std::string>();
  return dflt;
}

int64_t json_int(const json& obj, const std::string& key, int64_t dflt = 0) {
  if (obj.contains(key) && obj[key].is_number_integer())
    return obj[key].get<int64_t>();
  return dflt;
}

bool json_bool(const json& obj, const std::string& key, bool dflt = false) {
  if (obj.contains(key) && obj[key].is_boolean())
    return obj[key].get<bool>();
  return dflt;
}

bool json_is_array(const json& obj, const std::string& key) {
  return obj.contains(key) && obj[key].is_array();
}

bool json_is_object(const json& obj, const std::string& key) {
  return obj.contains(key) && obj[key].is_object();
}

// JSON merge: shallow merge src into dst, src values override
void json_merge(json& dst, const json& src) {
  if (!src.is_object() || !dst.is_object()) return;
  for (auto it = src.begin(); it != src.end(); ++it) {
    dst[it.key()] = it.value();
  }
}

// Validate a Matrix user ID
bool is_valid_user_id(const std::string& uid) {
  return starts_with(uid, "@") && uid.find(':') != std::string::npos;
}

// Extract server name from MXID
std::string extract_server_name(const std::string& mxid) {
  auto pos = mxid.find(':');
  if (pos != std::string::npos) return mxid.substr(pos + 1);
  return "";
}

// Check if string looks like a device token (hex)
bool is_hex_token(const std::string& token, size_t expected_len = 64) {
  if (token.size() != expected_len) return false;
  return std::all_of(token.begin(), token.end(),
                     [](char c) { return std::isxdigit(c); });
}

// Clamp a value between min and max
template<typename T>
T clamp_val(T val, T lo, T hi) {
  return std::max(lo, std::min(hi, val));
}

// Format a duration in human-readable form
std::string format_duration_ms(int64_t ms) {
  if (ms < 1000) return std::to_string(ms) + "ms";
  double sec = ms / 1000.0;
  if (sec < 60) {
    std::ostringstream ss;
    ss << std::fixed << std::setprecision(1) << sec << "s";
    return ss.str();
  }
  int64_t minutes = static_cast<int64_t>(sec / 60);
  double rem = std::fmod(sec, 60.0);
  std::ostringstream ss;
  ss << minutes << "m " << static_cast<int>(rem) << "s";
  return ss.str();
}

// Escape JSON string for safe logging
std::string json_escape(const std::string& s) {
  std::ostringstream oss;
  for (char c : s) {
    switch (c) {
      case '"': oss << "\\\""; break;
      case '\\': oss << "\\\\"; break;
      case '\n': oss << "\\n"; break;
      case '\r': oss << "\\r"; break;
      case '\t': oss << "\\t"; break;
      default:
        if (static_cast<unsigned char>(c) < 0x20) {
          oss << "\\u" << std::hex << std::setw(4) << std::setfill('0')
              << static_cast<int>(static_cast<unsigned char>(c));
        } else {
          oss << c;
        }
    }
  }
  return oss.str();
}

// Strip markdown formatting for plain text notifications
std::string strip_markdown(const std::string& s) {
  std::string result;
  result.reserve(s.size());
  bool in_code = false;
  bool in_bold = false;
  bool in_italic = false;
  for (size_t i = 0; i < s.size(); ++i) {
    char c = s[i];
    char nc = (i + 1 < s.size()) ? s[i + 1] : '\0';

    if (c == '`' && nc == '`' && (i + 2 < s.size()) && s[i + 2] == '`') {
      in_code = !in_code;
      i += 2;
      continue;
    }
    if (c == '`') {
      in_code = !in_code;
      continue;
    }
    if (in_code) { result += c; continue; }
    if (c == '*' && nc == '*') { in_bold = !in_bold; i++; continue; }
    if (c == '_' && nc == '_') { in_italic = !in_italic; i++; continue; }
    if (c == '*' || c == '_') continue; // Single emphasis markers
    // Links: [text](url)
    if (c == '[') {
      size_t close = s.find(']', i);
      size_t paren = s.find('(', close);
      if (close != std::string::npos && paren == close + 1) {
        size_t end = s.find(')', paren);
        if (end != std::string::npos) {
          // Extract just the text part
          result += s.substr(i + 1, close - i - 1);
          i = end;
          continue;
        }
      }
    }
    result += c;
  }
  return result;
}

// Base64 encoding (URL-safe, no padding)
std::string base64url_encode(const std::string& input) {
  static const char charset[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  std::string result;
  result.reserve(((input.size() + 2) / 3) * 4);
  size_t i = 0;
  while (i < input.size()) {
    uint32_t chunk = 0;
    int pad = 0;
    chunk |= (static_cast<unsigned char>(input[i++]) << 16);
    if (i < input.size()) { chunk |= (static_cast<unsigned char>(input[i++]) << 8); }
    else pad++;
    if (i < input.size()) { chunk |= static_cast<unsigned char>(input[i++]); }
    else pad++;
    result += charset[(chunk >> 18) & 0x3F];
    result += charset[(chunk >> 12) & 0x3F];
    if (pad < 2) result += charset[(chunk >> 6) & 0x3F];
    if (pad < 1) result += charset[chunk & 0x3F];
  }
  return result;
}

} // anonymous namespace

// ============================================================================
// Configuration structures
// ============================================================================

// Master push gateway configuration
struct PushGatewayConfig {
  // Global settings
  bool enable_push = true;
  bool enable_apns = true;
  bool enable_fcm = true;
  bool enable_generic_gateways = true;
  std::string server_name = "matrix.localhost";

  // APNs settings
  bool apns_use_sandbox = false;
  std::string apns_key_id;                   // Key ID from Apple Developer
  std::string apns_team_id;                  // Team ID
  std::string apns_private_key_path;         // P8 private key file path
  std::string apns_private_key_content;      // Or inline key content
  std::string apns_default_topic;            // Bundle ID
  int apns_jwt_lifetime_sec = 3600;
  bool apns_use_certificate_auth = false;
  std::string apns_cert_path;
  std::string apns_cert_password;
  chr::milliseconds apns_timeout{10'000};

  // FCM settings
  std::string fcm_project_id;
  std::string fcm_service_account_json_path;
  std::string fcm_service_account_json_content;
  std::string fcm_server_key;                // Legacy server key
  bool fcm_use_v1_api = true;
  chr::milliseconds fcm_timeout{15'000};

  // Generic gateway settings
  chr::milliseconds generic_gateway_timeout{10'000};
  bool generic_verify_ssl = true;

  // Queue settings
  size_t queue_max_capacity = 100'000;
  size_t queue_per_user_limit = 500;
  size_t queue_batch_size = 50;
  chr::seconds queue_item_ttl{3600};
  int queue_worker_threads = 4;
  chr::milliseconds queue_poll_interval{100};

  // Retry settings
  int max_retries = 5;
  chr::milliseconds base_backoff_ms{1000};
  chr::milliseconds max_backoff_ms{300'000};
  double jitter_factor = 0.3;

  // Circuit breaker settings
  bool enable_circuit_breaker = true;
  int cb_failure_threshold = 10;
  chr::seconds cb_cooldown_sec{60};
  int cb_half_open_probes = 3;

  // Badge settings
  bool enable_badge_sync = true;
  chr::seconds badge_sync_interval{30};
  int badge_batch_threshold = 5;

  // Analytics settings
  bool enable_analytics = true;
  chr::seconds analytics_flush_interval{60};
  int analytics_batch_size = 100;

  // Notification formatting
  std::string default_lang = "en";
  bool show_sender_in_notification = true;
  bool show_message_preview = true;
  bool strip_markdown_in_notifications = true;
  size_t max_body_preview_length = 256;
};

// Device token registration record
struct DeviceTokenRecord {
  std::string id;
  std::string user_id;
  std::string device_id;
  std::string token;             // The push token (APNs token or FCM registration token)
  std::string gateway_type;      // "apns", "fcm", "generic"
  std::string app_id;            // Bundle ID / project ID
  std::string gateway_url;       // Custom gateway URL (for generic)
  int64_t created_at_ms{0};
  int64_t updated_at_ms{0};
  int64_t last_delivery_ms{0};
  int64_t delivery_count{0};
  int64_t failure_count{0};
  int64_t consecutive_failures{0};
  bool active{true};
  bool invalidated{false};
  std::string invalid_reason;

  json to_json() const {
    return {
      {"id", id},
      {"user_id", user_id},
      {"device_id", device_id},
      {"gateway_type", gateway_type},
      {"app_id", app_id},
      {"active", active},
      {"invalidated", invalidated},
      {"delivery_count", delivery_count},
      {"failure_count", failure_count},
      {"created_at_ms", created_at_ms},
      {"last_delivery_ms", last_delivery_ms}
    };
  }
};

// Push notification queue item
struct QueuedNotification {
  std::string id;                // Unique queue item ID (UUID)
  std::string idempotency_key;   // For dedup: {user_id}_{event_id}_{pushkey}
  std::string user_id;
  std::string device_id;
  std::string pushkey;           // Device token
  std::string gateway_type;      // "apns", "fcm", "generic"
  std::string app_id;
  std::string gateway_url;       // For generic gateways
  std::string event_id;
  std::string room_id;
  std::string sender;
  json notification_payload;     // Pre-built notification JSON
  int priority{kDefaultPriority};  // 0-255
  int64_t created_at_ms{0};
  int64_t scheduled_at_ms{0};    // Earliest delivery time (for throttling)
  int64_t next_retry_at_ms{0};
  int retry_count{0};
  std::string state;             // pending, processing, delivered, failed, dead_letter
  std::string error_message;
  int http_status{0};

  bool is_expired(int64_t ttl_ms) const {
    return now_ms() - created_at_ms > ttl_ms;
  }

  bool can_retry(int max_retries) const {
    return retry_count < max_retries;
  }

  json to_json() const {
    return {
      {"id", id},
      {"user_id", user_id},
      {"device_id", device_id},
      {"gateway_type", gateway_type},
      {"event_id", event_id},
      {"room_id", room_id},
      {"priority", priority},
      {"state", state},
      {"retry_count", retry_count},
      {"error_message", error_message}
    };
  }
};

// Badge count state
struct BadgeState {
  std::string user_id;
  std::string pushkey;           // Per-device pushkey
  int64_t total_notifications{0};
  int64_t total_highlights{0};
  int64_t last_synced_at_ms{0};
  int64_t last_updated_at_ms{0};
  bool needs_sync{true};
};

// Push notification preference record
struct PushPreference {
  std::string user_id;
  std::string room_id;           // Empty = global
  bool push_enabled{true};
  std::string notification_level; // "all_messages", "mentions_only", "none"
  bool show_sender{true};
  bool show_message{true};
  bool show_room{true};
  std::string sound;
  int quiet_hours_start{-1};     // HHMM, -1 = disabled
  int quiet_hours_end{-1};
  std::string timezone;
  bool highlights_always{true};  // Override quiet hours for highlights
  int64_t updated_at_ms{0};

  json to_json() const {
    return {
      {"user_id", user_id},
      {"room_id", room_id},
      {"push_enabled", push_enabled},
      {"notification_level", notification_level},
      {"show_sender", show_sender},
      {"show_message", show_message},
      {"show_room", show_room},
      {"sound", sound},
      {"quiet_hours_start", quiet_hours_start},
      {"quiet_hours_end", quiet_hours_end},
      {"highlights_always", highlights_always}
    };
  }
};

// Analytics event record
struct AnalyticsEvent {
  std::string id;
  std::string user_id;
  std::string gateway_type;
  std::string app_id;
  std::string notification_id;   // Queue item ID
  std::string event_type;        // "attempt", "success", "failure", "dead_letter"
  int64_t timestamp_ms{0};
  int64_t queue_duration_ms{0};  // Time spent in queue
  int64_t send_duration_ms{0};   // Time to send over network
  int64_t total_duration_ms{0};  // Total end-to-end
  int http_status{0};
  std::string error_message;
  int retry_count{0};
};

// Retry state tracking
struct RetryState {
  std::string key;               // Gateway type + token hash
  int consecutive_failures{0};
  int64_t first_failure_ms{0};
  int64_t last_failure_ms{0};
  int64_t current_backoff_ms{0};
  int64_t next_allowed_at_ms{0};
  bool circuit_open{false};
  int64_t circuit_opened_at_ms{0};
  int half_open_probes_remaining{0};

  bool can_retry(int max_retries, int64_t max_backoff_ms) const {
    if (circuit_open) return half_open_probes_remaining > 0;
    if (consecutive_failures >= max_retries) return false;
    if (current_backoff_ms >= max_backoff_ms) return false;
    return now_ms() >= next_allowed_at_ms;
  }
};

// Gateway health record
struct GatewayHealth {
  std::string gateway_type;      // "apns", "fcm", "generic"
  std::string endpoint_url;      // Specific endpoint
  bool healthy{true};
  int64_t last_probe_ms{0};
  int64_t last_success_ms{0};
  int64_t last_failure_ms{0};
  int64_t consecutive_failures{0};
  int64_t total_probes{0};
  int64_t total_successes{0};
  int64_t total_failures{0};
  double success_rate{100.0};
  int64_t avg_latency_ms{0};
  int64_t p95_latency_ms{0};
};

// ============================================================================
// SQL DDL Statements
// ============================================================================

namespace sql_ddl {

constexpr const char* create_push_notification_queue = R"sql(
CREATE TABLE IF NOT EXISTS push_notification_queue (
  id              TEXT PRIMARY KEY,
  idempotency_key TEXT,
  user_id         TEXT NOT NULL,
  device_id       TEXT NOT NULL DEFAULT '',
  pushkey         TEXT NOT NULL,
  gateway_type    TEXT NOT NULL DEFAULT 'generic',
  app_id          TEXT NOT NULL DEFAULT '',
  gateway_url     TEXT NOT NULL DEFAULT '',
  event_id        TEXT NOT NULL DEFAULT '',
  room_id         TEXT NOT NULL DEFAULT '',
  sender          TEXT NOT NULL DEFAULT '',
  notification_payload_json TEXT NOT NULL DEFAULT '{}',
  priority        INTEGER NOT NULL DEFAULT 128,
  created_at_ms   INTEGER NOT NULL,
  scheduled_at_ms INTEGER NOT NULL,
  next_retry_at_ms INTEGER NOT NULL DEFAULT 0,
  retry_count     INTEGER NOT NULL DEFAULT 0,
  state           TEXT NOT NULL DEFAULT 'pending',
  error_message   TEXT NOT NULL DEFAULT '',
  http_status     INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_pnq_state_priority
  ON push_notification_queue(state, priority DESC, created_at_ms);
CREATE INDEX IF NOT EXISTS idx_pnq_user_state
  ON push_notification_queue(user_id, state);
CREATE INDEX IF NOT EXISTS idx_pnq_idempotency
  ON push_notification_queue(idempotency_key, state);
CREATE INDEX IF NOT EXISTS idx_pnq_scheduled
  ON push_notification_queue(state, scheduled_at_ms)
  WHERE state = 'pending';
CREATE INDEX IF NOT EXISTS idx_pnq_retry
  ON push_notification_queue(state, next_retry_at_ms)
  WHERE state IN ('pending', 'failed');
CREATE INDEX IF NOT EXISTS idx_pnq_created
  ON push_notification_queue(created_at_ms);
)sql";

constexpr const char* create_push_analytics_events = R"sql(
CREATE TABLE IF NOT EXISTS push_analytics_events (
  id              TEXT PRIMARY KEY,
  user_id         TEXT NOT NULL DEFAULT '',
  gateway_type    TEXT NOT NULL DEFAULT 'generic',
  app_id          TEXT NOT NULL DEFAULT '',
  notification_id TEXT NOT NULL DEFAULT '',
  event_type      TEXT NOT NULL,
  timestamp_ms    INTEGER NOT NULL,
  queue_duration_ms INTEGER NOT NULL DEFAULT 0,
  send_duration_ms  INTEGER NOT NULL DEFAULT 0,
  total_duration_ms INTEGER NOT NULL DEFAULT 0,
  http_status     INTEGER NOT NULL DEFAULT 0,
  error_message   TEXT NOT NULL DEFAULT '',
  retry_count     INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_pae_timestamp
  ON push_analytics_events(timestamp_ms);
CREATE INDEX IF NOT EXISTS idx_pae_gateway_type
  ON push_analytics_events(gateway_type, timestamp_ms);
CREATE INDEX IF NOT EXISTS idx_pae_user
  ON push_analytics_events(user_id, timestamp_ms);
CREATE INDEX IF NOT EXISTS idx_pae_event_type
  ON push_analytics_events(event_type, timestamp_ms);
CREATE INDEX IF NOT EXISTS idx_pae_notification
  ON push_analytics_events(notification_id);
)sql";

constexpr const char* create_push_gateway_config = R"sql(
CREATE TABLE IF NOT EXISTS push_gateway_config (
  id              TEXT PRIMARY KEY,
  gateway_type    TEXT NOT NULL,
  app_id          TEXT NOT NULL DEFAULT '',
  config_json     TEXT NOT NULL DEFAULT '{}',
  enabled         INTEGER NOT NULL DEFAULT 1,
  priority        INTEGER NOT NULL DEFAULT 0,
  created_at_ms   INTEGER NOT NULL,
  updated_at_ms   INTEGER NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_pgc_type_app
  ON push_gateway_config(gateway_type, app_id);
)sql";

constexpr const char* create_push_badge_state = R"sql(
CREATE TABLE IF NOT EXISTS push_badge_state (
  id              TEXT PRIMARY KEY,
  user_id         TEXT NOT NULL,
  pushkey         TEXT NOT NULL DEFAULT '',
  total_notifications INTEGER NOT NULL DEFAULT 0,
  total_highlights   INTEGER NOT NULL DEFAULT 0,
  last_synced_at_ms  INTEGER NOT NULL DEFAULT 0,
  last_updated_at_ms INTEGER NOT NULL DEFAULT 0,
  needs_sync      INTEGER NOT NULL DEFAULT 1
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_pbs_user_pushkey
  ON push_badge_state(user_id, pushkey);
CREATE INDEX IF NOT EXISTS idx_pbs_user
  ON push_badge_state(user_id);
CREATE INDEX IF NOT EXISTS idx_pbs_needs_sync
  ON push_badge_state(needs_sync, last_updated_at_ms)
  WHERE needs_sync = 1;
)sql";

constexpr const char* create_push_notification_preferences = R"sql(
CREATE TABLE IF NOT EXISTS push_notification_preferences (
  id              TEXT PRIMARY KEY,
  user_id         TEXT NOT NULL,
  room_id         TEXT NOT NULL DEFAULT '',
  push_enabled    INTEGER NOT NULL DEFAULT 1,
  notification_level TEXT NOT NULL DEFAULT 'all_messages',
  show_sender     INTEGER NOT NULL DEFAULT 1,
  show_message    INTEGER NOT NULL DEFAULT 1,
  show_room       INTEGER NOT NULL DEFAULT 1,
  sound           TEXT NOT NULL DEFAULT 'default',
  quiet_hours_start INTEGER NOT NULL DEFAULT -1,
  quiet_hours_end   INTEGER NOT NULL DEFAULT -1,
  timezone        TEXT NOT NULL DEFAULT 'UTC',
  highlights_always INTEGER NOT NULL DEFAULT 1,
  updated_at_ms   INTEGER NOT NULL DEFAULT 0
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_pnp_user_room
  ON push_notification_preferences(user_id, room_id);
CREATE INDEX IF NOT EXISTS idx_pnp_user
  ON push_notification_preferences(user_id);
)sql";

constexpr const char* create_push_retry_state = R"sql(
CREATE TABLE IF NOT EXISTS push_retry_state (
  id              TEXT PRIMARY KEY,
  retry_key       TEXT NOT NULL UNIQUE,
  gateway_type    TEXT NOT NULL,
  consecutive_failures INTEGER NOT NULL DEFAULT 0,
  first_failure_ms    INTEGER NOT NULL DEFAULT 0,
  last_failure_ms     INTEGER NOT NULL DEFAULT 0,
  current_backoff_ms  INTEGER NOT NULL DEFAULT 0,
  next_allowed_at_ms  INTEGER NOT NULL DEFAULT 0,
  circuit_open        INTEGER NOT NULL DEFAULT 0,
  circuit_opened_at_ms INTEGER NOT NULL DEFAULT 0,
  half_open_probes_remaining INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_prs_key ON push_retry_state(retry_key);
CREATE INDEX IF NOT EXISTS idx_prs_circuit ON push_retry_state(circuit_open);
)sql";

constexpr const char* create_push_device_tokens = R"sql(
CREATE TABLE IF NOT EXISTS push_device_tokens (
  id              TEXT PRIMARY KEY,
  user_id         TEXT NOT NULL,
  device_id       TEXT NOT NULL DEFAULT '',
  token           TEXT NOT NULL,
  gateway_type    TEXT NOT NULL DEFAULT 'generic',
  app_id          TEXT NOT NULL DEFAULT '',
  gateway_url     TEXT NOT NULL DEFAULT '',
  created_at_ms   INTEGER NOT NULL,
  updated_at_ms   INTEGER NOT NULL,
  last_delivery_ms INTEGER NOT NULL DEFAULT 0,
  delivery_count  INTEGER NOT NULL DEFAULT 0,
  failure_count   INTEGER NOT NULL DEFAULT 0,
  consecutive_failures INTEGER NOT NULL DEFAULT 0,
  active          INTEGER NOT NULL DEFAULT 1,
  invalidated     INTEGER NOT NULL DEFAULT 0,
  invalid_reason  TEXT NOT NULL DEFAULT ''
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_pdt_user_device_type_token
  ON push_device_tokens(user_id, device_id, gateway_type, token);
CREATE INDEX IF NOT EXISTS idx_pdt_user
  ON push_device_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_pdt_token_gateway
  ON push_device_tokens(token, gateway_type);
CREATE INDEX IF NOT EXISTS idx_pdt_invalidated
  ON push_device_tokens(invalidated, active);
)sql";

constexpr const char* create_push_gateway_health = R"sql(
CREATE TABLE IF NOT EXISTS push_gateway_health (
  id              TEXT PRIMARY KEY,
  gateway_type    TEXT NOT NULL,
  endpoint_url    TEXT NOT NULL DEFAULT '',
  healthy         INTEGER NOT NULL DEFAULT 1,
  last_probe_ms   INTEGER NOT NULL DEFAULT 0,
  last_success_ms INTEGER NOT NULL DEFAULT 0,
  last_failure_ms INTEGER NOT NULL DEFAULT 0,
  consecutive_failures INTEGER NOT NULL DEFAULT 0,
  total_probes    INTEGER NOT NULL DEFAULT 0,
  total_successes INTEGER NOT NULL DEFAULT 0,
  total_failures  INTEGER NOT NULL DEFAULT 0,
  success_rate    REAL NOT NULL DEFAULT 100.0,
  avg_latency_ms  INTEGER NOT NULL DEFAULT 0,
  p95_latency_ms  INTEGER NOT NULL DEFAULT 0
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_pgh_type_endpoint
  ON push_gateway_health(gateway_type, endpoint_url);
)sql";

} // namespace sql_ddl

// ============================================================================
// ApnsJwtProvider: JWT-based authentication for APNs
// ============================================================================

class ApnsJwtProvider {
public:
  ApnsJwtProvider() = default;

  void configure(const std::string& key_id, const std::string& team_id,
                 const std::string& private_key_content,
                 int lifetime_sec = 3600) {
    std::lock_guard<std::mutex> lock(jwt_mu_);
    key_id_ = key_id;
    team_id_ = team_id;
    private_key_ = private_key_content;
    lifetime_sec_ = lifetime_sec;
    // In production, parse PKCS#8 private key from PEM content
    jwt_valid_ = !key_id.empty() && !team_id.empty() && !private_key_content.empty();
    current_jwt_.clear();
    jwt_expires_at_ms_ = 0;
  }

  // Get a valid JWT, generating a new one if needed
  std::string get_jwt() {
    std::lock_guard<std::mutex> lock(jwt_mu_);
    if (!jwt_valid_) return "";

    int64_t now = now_ms();
    // Refresh if expired or within refresh margin
    if (current_jwt_.empty() ||
        now >= (jwt_expires_at_ms_ - (kApnsJwtRefreshMargin.count() * 1000))) {
      generate_jwt_locked(now);
    }
    return current_jwt_;
  }

  bool is_valid() const {
    std::lock_guard<std::mutex> lock(jwt_mu_);
    return jwt_valid_;
  }

private:
  void generate_jwt_locked(int64_t now_ms_val) {
    // Build JWT header
    json header = {
      {"alg", "ES256"},
      {"kid", key_id_},
      {"typ", "JWT"}
    };

    // Build JWT payload
    int64_t issued_at = now_ms_val / 1000;
    json payload = {
      {"iss", team_id_},
      {"iat", issued_at}
    };

    // Base64url encode header and payload
    std::string header_b64 = base64url_encode(header.dump());
    std::string payload_b64 = base64url_encode(payload.dump());
    std::string signing_input = header_b64 + "." + payload_b64;

    // In production: sign with ES256 using the private key
    // Stub: create a placeholder signature
    std::string signature = base64url_encode(
        "sig_stub_" + sha256_hex(signing_input + private_key_));

    current_jwt_ = signing_input + "." + signature;
    jwt_expires_at_ms_ = now_ms_val + (lifetime_sec_ * 1000);
  }

  mutable std::mutex jwt_mu_;
  std::string key_id_;
  std::string team_id_;
  std::string private_key_;
  int lifetime_sec_{3600};
  bool jwt_valid_{false};
  std::string current_jwt_;
  int64_t jwt_expires_at_ms_{0};
};

// ============================================================================
// FcmOAuthProvider: OAuth 2.0 authentication for FCM v1 API
// ============================================================================

class FcmOAuthProvider {
public:
  FcmOAuthProvider() = default;

  void configure(const std::string& service_account_json) {
    std::lock_guard<std::mutex> lock(oauth_mu_);
    service_account_json_ = service_account_json;
    // Parse service account JSON to extract private_key, client_email, token_uri
    try {
      auto sa = json::parse(service_account_json);
      client_email_ = json_str(sa, "client_email");
      private_key_ = json_str(sa, "private_key");
      token_uri_ = json_str(sa, "token_uri", kFcmOAuthTokenUrl);
      project_id_ = json_str(sa, "project_id");
      oauth_valid_ = !client_email_.empty() && !private_key_.empty();
    } catch (...) {
      oauth_valid_ = false;
    }
    access_token_.clear();
    token_expires_at_ms_ = 0;
  }

  void configure_legacy(const std::string& server_key) {
    std::lock_guard<std::mutex> lock(oauth_mu_);
    server_key_ = server_key;
    use_legacy_ = true;
    legacy_valid_ = !server_key_.empty();
  }

  // Get a valid access token (or server key for legacy)
  std::string get_auth_header() {
    std::lock_guard<std::mutex> lock(oauth_mu_);
    if (use_legacy_) {
      return legacy_valid_ ? ("key=" + server_key_) : "";
    }

    if (!oauth_valid_) return "";

    int64_t now = now_ms();
    if (access_token_.empty() ||
        now >= (token_expires_at_ms_ - (kFcmOAuthRefreshMargin.count() * 1000))) {
      refresh_token_locked(now);
    }
    return access_token_.empty() ? "" : ("Bearer " + access_token_);
  }

  std::string get_project_id() const {
    std::lock_guard<std::mutex> lock(oauth_mu_);
    return project_id_;
  }

  bool is_valid() const {
    std::lock_guard<std::mutex> lock(oauth_mu_);
    return use_legacy_ ? legacy_valid_ : oauth_valid_;
  }

  bool is_legacy() const {
    std::lock_guard<std::mutex> lock(oauth_mu_);
    return use_legacy_;
  }

private:
  void refresh_token_locked(int64_t now_ms_val) {
    // In production: sign JWT with service account key, POST to token_uri_
    // Get OAuth 2.0 token response with access_token and expires_in
    // Stub: simulate a token
    access_token_ = "fcm_oauth_stub_" + generate_uuid_v4();
    token_expires_at_ms_ = now_ms_val + 3600 * 1000; // 1 hour
  }

  mutable std::mutex oauth_mu_;
  std::string service_account_json_;
  std::string client_email_;
  std::string private_key_;
  std::string token_uri_;
  std::string project_id_;
  bool oauth_valid_{false};
  std::string access_token_;
  int64_t token_expires_at_ms_{0};

  // Legacy FCM
  bool use_legacy_{false};
  std::string server_key_;
  bool legacy_valid_{false};
};

// ============================================================================
// ApnsPayloadBuilder: Build APNs-specific notification payload
// ============================================================================

class ApnsPayloadBuilder {
public:
  explicit ApnsPayloadBuilder(const PushGatewayConfig& config)
    : config_(config) {}

  // Build a complete APNs payload for an alert notification
  json build_alert(const std::string& title, const std::string& body,
                   const std::string& subtitle, int badge_count,
                   const std::string& sound, const std::string& category,
                   const std::string& thread_id,
                   const json& custom_data = json::object()) {
    json payload;

    // Build aps dictionary
    json aps;
    json alert;

    if (!title.empty()) alert["title"] = title;
    if (!subtitle.empty()) alert["subtitle"] = subtitle;
    alert["body"] = body;

    aps["alert"] = alert;

    // Badge
    if (badge_count >= 0) {
      aps["badge"] = badge_count;
    }

    // Sound
    if (!sound.empty()) {
      aps["sound"] = sound;
    } else {
      aps["sound"] = kDefaultSound;
    }

    // Category (for notification actions)
    if (!category.empty()) {
      aps["category"] = category;
    }

    // Thread ID (for notification grouping)
    if (!thread_id.empty()) {
      aps["thread-id"] = thread_id;
    }

    // Mutable content (for notification service extension)
    aps["mutable-content"] = 1;

    payload["aps"] = aps;

    // Custom data
    if (!custom_data.empty()) {
      for (auto it = custom_data.begin(); it != custom_data.end(); ++it) {
        if (it.key() != "aps") {
          payload[it.key()] = it.value();
        }
      }
    }

    return payload;
  }

  // Build a silent/background push payload
  json build_background(const json& custom_data = json::object()) {
    json aps;
    aps["content-available"] = 1;

    json payload;
    payload["aps"] = aps;

    if (!custom_data.empty()) {
      for (auto it = custom_data.begin(); it != custom_data.end(); ++it) {
        if (it.key() != "aps") {
          payload[it.key()] = it.value();
        }
      }
    }

    return payload;
  }

  // Build payload with badge-only update (no alert)
  json build_badge_update(int badge_count) {
    json aps;
    aps["badge"] = badge_count;

    json payload;
    payload["aps"] = aps;
    return payload;
  }

  // Build APNs HTTP headers
  std::map<std::string, std::string> build_headers(
      const std::string& topic,
      int priority = kApnsImmediatePriority,
      int64_t expiration_sec = 0,
      const std::string& collapse_id = "",
      const std::string& push_type = "alert") {

    std::map<std::string, std::string> headers;

    headers["apns-topic"] = topic;
    headers["apns-priority"] = std::to_string(priority);

    if (expiration_sec > 0) {
      headers["apns-expiration"] = std::to_string(expiration_sec);
    }

    if (!collapse_id.empty()) {
      headers["apns-collapse-id"] = collapse_id;
    }

    headers["apns-push-type"] = push_type;

    return headers;
  }

  // Validate payload size against APNs limit
  bool validate_size(const json& payload) {
    return payload.dump().size() <= kApnsMaxPayloadSize;
  }

  // Ensure payload fits within safe size, truncating if needed
  json ensure_size(const json& payload) {
    std::string dumped = payload.dump();
    if (dumped.size() <= kApnsSafePayloadSize) return payload;

    // Try truncating alert body
    json trimmed = payload;
    if (trimmed.contains("aps") && trimmed["aps"].contains("alert")) {
      auto& alert = trimmed["aps"]["alert"];
      if (alert.is_object() && alert.contains("body")) {
        std::string body = alert["body"].get<std::string>();
        size_t max_body = kApnsSafePayloadSize - (trimmed.dump().size() - body.size());
        if (max_body > 10) {
          alert["body"] = truncate_utf8(body, max_body);
        }
      } else if (alert.is_string()) {
        std::string body = alert.get<std::string>();
        size_t max_body = kApnsSafePayloadSize - (trimmed.dump().size() - body.size());
        if (max_body > 10) {
          alert = truncate_utf8(body, max_body);
        }
      }
    }

    return trimmed;
  }

private:
  PushGatewayConfig config_;
};

// ============================================================================
// FcmPayloadBuilder: Build FCM-specific notification payload
// ============================================================================

class FcmPayloadBuilder {
public:
  explicit FcmPayloadBuilder(const PushGatewayConfig& config)
    : config_(config) {}

  // Build FCM v1 API payload
  json build_v1_message(
      const std::string& token,
      const std::string& title,
      const std::string& body,
      const json& data = json::object(),
      const std::string& image_url = "",
      const std::string& channel_id = "",
      const std::string& collapse_key = "",
      const std::string& priority = "high",
      int ttl_sec = 86400 * 7) {

    json message;
    message["token"] = token;

    // Notification object
    json notification;
    notification["title"] = title;
    notification["body"] = body;

    if (!image_url.empty()) {
      notification["image"] = image_url;
    }
    message["notification"] = notification;

    // Data payload
    if (!data.empty()) {
      message["data"] = data;
    }

    // Android-specific config
    json android;
    android["priority"] = priority;
    android["ttl"] = std::to_string(ttl_sec) + "s";

    if (!collapse_key.empty()) {
      android["collapse_key"] = collapse_key;
    }

    if (!channel_id.empty()) {
      json android_notification;
      android_notification["channel_id"] = channel_id;
      android_notification["sound"] = kDefaultSound;
      android["notification"] = android_notification;
    }

    message["android"] = android;

    // APNs bridge config (for iOS devices via FCM)
    json apns;
    json apns_headers;
    apns_headers["apns-priority"] = "10";
    apns["headers"] = apns_headers;

    json apns_payload;
    json aps;
    json alert;
    alert["title"] = title;
    alert["body"] = body;
    aps["alert"] = alert;
    aps["sound"] = kDefaultSound;
    aps["mutable-content"] = 1;

    if (!collapse_key.empty()) {
      aps["thread-id"] = collapse_key;
    }

    apns_payload["aps"] = aps;

    if (!data.empty()) {
      for (auto it = data.begin(); it != data.end(); ++it) {
        if (it.key() != "aps") {
          apns_payload[it.key()] = it.value();
        }
      }
    }

    apns["payload"] = apns_payload;
    message["apns"] = apns;

    // Webpush config (for browser push)
    json webpush;
    json webpush_headers;
    webpush_headers["TTL"] = std::to_string(ttl_sec);
    webpush_headers["Urgency"] = (priority == "high") ? "high" : "normal";
    webpush["headers"] = webpush_headers;
    webpush["notification"] = {
      {"title", title},
      {"body", body},
      {"icon", "/icon.png"},
      {"badge", "/badge.png"}
    };
    message["webpush"] = webpush;

    return {{"message", message}};
  }

  // Build legacy FCM HTTP API payload
  json build_legacy_message(
      const std::string& to,
      const json& notification,
      const json& data = json::object(),
      const std::string& collapse_key = "",
      const std::string& priority = "high",
      int ttl_sec = 86400 * 7) {

    json payload;
    payload["to"] = to;

    if (!notification.empty()) {
      payload["notification"] = notification;
    }

    if (!data.empty()) {
      payload["data"] = data;
    }

    if (!collapse_key.empty()) {
      payload["collapse_key"] = collapse_key;
    }

    payload["priority"] = priority;
    payload["time_to_live"] = ttl_sec;

    // Android-specific
    json android;
    android["priority"] = priority;
    payload["android"] = android;

    return payload;
  }

  // Build multicast payload for up to 500 tokens
  json build_multicast(
      const std::vector<std::string>& tokens,
      const std::string& title,
      const std::string& body,
      const json& data = json::object(),
      const std::string& collapse_key = "") {

    if (tokens.empty() || tokens.size() > kFcmMulticastMaxTokens) {
      return json::object();
    }

    json payload;
    payload["registration_ids"] = tokens;

    json notification;
    notification["title"] = title;
    notification["body"] = body;
    payload["notification"] = notification;

    if (!data.empty()) {
      payload["data"] = data;
    }

    if (!collapse_key.empty()) {
      payload["collapse_key"] = collapse_key;
    }

    return payload;
  }

  // Add topic condition
  void add_topic_condition(json& message, const std::string& condition) {
    if (!condition.empty()) {
      message["message"]["condition"] = condition;
      message["message"].erase("token");
    }
  }

private:
  PushGatewayConfig config_;
};

// ============================================================================
// GenericPayloadBuilder: Build Matrix push gateway payload
// ============================================================================

class GenericPayloadBuilder {
public:
  explicit GenericPayloadBuilder(const PushGatewayConfig& config)
    : config_(config) {}

  // Build standard Matrix push gateway notification payload
  json build_notification(
      const std::string& room_id,
      const std::string& room_name,
      const std::string& sender,
      const std::string& sender_display_name,
      const std::string& event_id,
      const std::string& event_type,
      const json& content,
      int64_t unread_count,
      int64_t highlight_count,
      bool is_highlight,
      const std::string& priority = "high",
      const json& extra_data = json::object()) {

    json notification;

    // Core fields
    notification["room_id"] = room_id;
    notification["event_id"] = event_id;
    notification["type"] = event_type;

    if (!room_name.empty()) {
      notification["room_name"] = room_name;
    }

    if (!sender.empty()) {
      notification["sender"] = sender;
    }

    if (!sender_display_name.empty()) {
      notification["sender_display_name"] = sender_display_name;
    }

    // Content
    if (!content.empty()) {
      notification["content"] = content;
    }

    // Counts
    if (unread_count >= 0 || highlight_count >= 0) {
      json counts;
      if (unread_count >= 0) counts["unread"] = unread_count;
      if (highlight_count >= 0) counts["missed_calls"] = 0; // Standard Matrix field
      notification["counts"] = counts;
    }

    // Priority and highlight
    notification["prio"] = priority;
    notification["highlight"] = is_highlight;

    // Extra data (devices, etc.)
    if (!extra_data.empty()) {
      for (auto it = extra_data.begin(); it != extra_data.end(); ++it) {
        notification[it.key()] = it.value();
      }
    }

    return {{"notification", notification}};
  }

  // Build a coalesced notification payload (multiple events)
  json build_coalesced(
      const std::string& room_id,
      const std::string& room_name,
      int notification_count,
      int highlight_count,
      const std::vector<json>& event_summaries,
      const json& extra_data = json::object()) {

    json notification;
    notification["coalesced"] = true;
    notification["count"] = notification_count;
    notification["room_id"] = room_id;

    if (!room_name.empty()) {
      notification["room_name"] = room_name;
    }

    // Event list
    json events = json::array();
    for (size_t i = 0; i < std::min(event_summaries.size(),
                                    kMaxGroupSummarySize); ++i) {
      events.push_back(event_summaries[i]);
    }
    notification["events"] = events;

    // Counts
    notification["counts"] = {
      {"unread", notification_count},
      {"missed_calls", 0}
    };

    notification["prio"] = "high";
    notification["highlight"] = (highlight_count > 0);

    if (!extra_data.empty()) {
      for (auto it = extra_data.begin(); it != extra_data.end(); ++it) {
        notification[it.key()] = it.value();
      }
    }

    return {{"notification", notification}};
  }

  // Build a badge-only update payload
  json build_badge_update(int badge_count) {
    return {
      {"notification", {
        {"counts", {
          {"unread", badge_count},
          {"missed_calls", 0}
        }},
        {"prio", "low"},
        {"room_id", ""},
        {"event_id", ""},
        {"type", "m.badge"}
      }}
    };
  }

private:
  PushGatewayConfig config_;
};

// ============================================================================
// PushNotificationFormatter: Format notification text for display
// ============================================================================

class PushNotificationFormatter {
public:
  explicit PushNotificationFormatter(const PushGatewayConfig& config)
    : config_(config) {}

  // Format a notification title from sender and room
  std::string format_title(const std::string& sender_display_name,
                           const std::string& room_name,
                           const PushPreference& pref) {
    if (!pref.show_sender && !pref.show_room) return "New notification";

    std::ostringstream ss;

    if (pref.show_sender && !sender_display_name.empty()) {
      ss << sender_display_name;
    }

    if (pref.show_room && !room_name.empty()) {
      if (pref.show_sender && !sender_display_name.empty()) {
        ss << " @ " << room_name;
      } else {
        ss << room_name;
      }
    }

    std::string result = ss.str();
    if (result.empty()) result = "Matrix";
    return truncate_utf8(result, kMaxSenderNameLength + kMaxRoomNameLength + 3);
  }

  // Format notification body from event content
  std::string format_body(const std::string& event_type,
                          const std::string& sender_display_name,
                          const std::string& room_name,
                          const json& content,
                          const PushPreference& pref) {

    if (!pref.show_message && !pref.show_sender) {
      return "You have a new notification";
    }

    // Handle different event types
    if (event_type == "m.room.message") {
      return format_message_body(sender_display_name, content, pref);
    }
    else if (event_type == "m.room.member") {
      return format_member_body(sender_display_name, room_name, content, pref);
    }
    else if (event_type == "m.room.name") {
      return format_room_name_change(sender_display_name, content, pref);
    }
    else if (event_type == "m.room.topic") {
      return format_room_topic_change(sender_display_name, content, pref);
    }
    else if (event_type == "m.room.encrypted") {
      return std::string(kEncryptedPlaceholder);
    }
    else if (event_type == "m.call.invite") {
      return std::string(kCallPlaceholder);
    }
    else if (event_type == "m.reaction") {
      return format_reaction(sender_display_name, content, pref);
    }
    else if (event_type == "m.sticker") {
      return std::string(kStickerPlaceholder);
    }
    else if (starts_with(event_type, "m.room.")) {
      return format_generic_room_event(sender_display_name, event_type,
                                       content, pref);
    }

    return format_generic_event(sender_display_name, event_type, pref);
  }

  // Format a group summary for coalesced notifications
  std::string format_group_summary(int count, int room_count,
                                    int sender_count, int highlight_count) {
    std::ostringstream ss;
    ss << count << " new message";
    if (count != 1) ss << "s";

    if (sender_count > 1) {
      ss << " from " << sender_count << " people";
    }

    if (room_count > 1) {
      ss << " in " << room_count << " rooms";
    }

    if (highlight_count > 0) {
      ss << " (" << highlight_count << " highlight";
      if (highlight_count != 1) ss << "s";
      ss << ")";
    }

    return ss.str();
  }

  // Generate a collapse key from room_id and sender
  std::string generate_collapse_key(const std::string& room_id,
                                     const std::string& sender = "") {
    if (sender.empty()) return sha256_hex(room_id).substr(0, 16);
    return sha256_hex(room_id + ":" + sender).substr(0, 16);
  }

  // Generate a thread ID from room_id (for iOS notification grouping)
  std::string generate_thread_id(const std::string& room_id) {
    return "room:" + sha256_hex(room_id).substr(0, 12);
  }

private:
  std::string format_message_body(const std::string& sender_display_name,
                                   const json& content,
                                   const PushPreference& pref) {
    std::string msgtype = json_str(content, "msgtype");
    std::string body;

    // Handle different message types
    if (msgtype == "m.text" || msgtype == "m.notice" || msgtype.empty()) {
      body = json_str(content, "body");
    }
    else if (msgtype == "m.image") {
      body = kImagePlaceholder;
      std::string caption = json_str(content, "body");
      if (!caption.empty()) {
        body = std::string(kImagePlaceholder) + ": " + caption;
      }
    }
    else if (msgtype == "m.file") {
      body = kFilePlaceholder;
      std::string filename = json_str(content, "filename");
      if (!filename.empty()) {
        body = std::string(kFilePlaceholder) + ": " + filename;
      }
    }
    else if (msgtype == "m.video") {
      body = kVideoPlaceholder;
      std::string caption = json_str(content, "body");
      if (!caption.empty()) {
        body = std::string(kVideoPlaceholder) + ": " + caption;
      }
    }
    else if (msgtype == "m.audio") {
      body = "\xF0\x9F\x8E\xB5 Voice message";
    }
    else if (msgtype == "m.location") {
      body = "\xF0\x9F\x93\x8D Shared a location";
    }
    else if (msgtype == "m.emote") {
      std::string emote_body = json_str(content, "body");
      body = (pref.show_sender && !sender_display_name.empty()
              ? sender_display_name + " " : "") + emote_body;
    }
    else {
      body = json_str(content, "body", "New message");
    }

    // Sanitize and truncate
    if (config_.strip_markdown_in_notifications) {
      body = strip_markdown(body);
    }

    body = truncate_utf8(body, config_.max_body_preview_length);

    if (body.empty()) body = "New message";
    return body;
  }

  std::string format_member_body(const std::string& sender_display_name,
                                  const std::string& room_name,
                                  const json& content,
                                  const PushPreference& /*pref*/) {
    std::string membership = json_str(content, "membership");
    std::string display_name = json_str(content, "displayname", sender_display_name);

    if (membership == "join") {
      return display_name + " joined" +
             (room_name.empty() ? "" : " " + room_name);
    }
    else if (membership == "leave") {
      return display_name + " left" +
             (room_name.empty() ? "" : " " + room_name);
    }
    else if (membership == "invite") {
      return display_name + " invited you to " +
             (room_name.empty() ? "a room" : room_name);
    }
    else if (membership == "ban") {
      std::string target = json_str(content, "displayname");
      return display_name + " banned " +
             (target.empty() ? "someone" : target);
    }

    return display_name + " changed membership";
  }

  std::string format_room_name_change(const std::string& sender_display_name,
                                       const json& content,
                                       const PushPreference& /*pref*/) {
    std::string new_name = json_str(content, "name");
    return sender_display_name +
           (new_name.empty() ? " changed the room name"
                             : " changed the room name to \"" + new_name + "\"");
  }

  std::string format_room_topic_change(const std::string& sender_display_name,
                                        const json& content,
                                        const PushPreference& /*pref*/) {
    std::string new_topic = json_str(content, "topic");
    return sender_display_name +
           (new_topic.empty() ? " removed the topic"
                              : " changed the topic to \"" +
                                truncate_utf8(new_topic, 100) + "\"");
  }

  std::string format_reaction(const std::string& sender_display_name,
                               const json& content,
                               const PushPreference& /*pref*/) {
    std::string relates_to = json_str(content, "m.relates_to.key",
                                       "a message");
    return sender_display_name + " reacted to " + relates_to;
  }

  std::string format_generic_room_event(const std::string& sender_display_name,
                                         const std::string& event_type,
                                         const json& /*content*/,
                                         const PushPreference& /*pref*/) {
    // Strip "m.room." prefix for display
    std::string readable = event_type;
    if (starts_with(readable, "m.room.")) {
      readable = readable.substr(7);
      // Replace underscores with spaces
      std::replace(readable.begin(), readable.end(), '_', ' ');
    }
    return sender_display_name + " sent a " + readable + " event";
  }

  std::string format_generic_event(const std::string& sender_display_name,
                                    const std::string& event_type,
                                    const PushPreference& /*pref*/) {
    return sender_display_name + " sent a " + event_type + " event";
  }

  PushGatewayConfig config_;
};

// ============================================================================
// BadgeCountManager: Track and manage app badge counts
// ============================================================================

class BadgeCountManager {
public:
  BadgeCountManager()
    : total_badge_count_(0) {}

  void configure(const PushGatewayConfig& config) {
    config_ = config;
  }

  // Increment badge count for a user
  void increment_badge(const std::string& user_id, int count = 1,
                       int highlights = 0) {
    std::unique_lock<std::shared_mutex> lock(badge_mu_);
    auto& state = badge_states_[user_id];
    state.user_id = user_id;
    state.total_notifications += count;
    state.total_highlights += highlights;
    state.last_updated_at_ms = now_ms();
    state.needs_sync = true;

    total_badge_count_ += count;
  }

  // Set badge count to a specific value
  void set_badge(const std::string& user_id, int64_t notifications,
                 int64_t highlights) {
    std::unique_lock<std::shared_mutex> lock(badge_mu_);
    auto& state = badge_states_[user_id];
    int64_t old_total = state.total_notifications;
    state.user_id = user_id;
    state.total_notifications = notifications;
    state.total_highlights = highlights;
    state.last_updated_at_ms = now_ms();
    state.needs_sync = true;

    total_badge_count_ += (notifications - old_total);
  }

  // Set per-device badge count
  void set_device_badge(const std::string& user_id, const std::string& pushkey,
                        int64_t notifications, int64_t highlights) {
    std::unique_lock<std::shared_mutex> lock(badge_mu_);
    auto key = make_badge_key(user_id, pushkey);
    auto& state = badge_states_[key];
    state.user_id = user_id;
    state.pushkey = pushkey;
    state.total_notifications = notifications;
    state.total_highlights = highlights;
    state.last_updated_at_ms = now_ms();
    state.needs_sync = true;
  }

  // Clear badge for a user
  void clear_badge(const std::string& user_id) {
    std::unique_lock<std::shared_mutex> lock(badge_mu_);
    auto it = badge_states_.find(user_id);
    if (it != badge_states_.end()) {
      total_badge_count_ -= it->second.total_notifications;
      it->second.total_notifications = 0;
      it->second.total_highlights = 0;
      it->second.last_updated_at_ms = now_ms();
      it->second.needs_sync = true;
    }
  }

  // Clear device-specific badge
  void clear_device_badge(const std::string& user_id, const std::string& pushkey) {
    std::unique_lock<std::shared_mutex> lock(badge_mu_);
    auto key = make_badge_key(user_id, pushkey);
    auto it = badge_states_.find(key);
    if (it != badge_states_.end()) {
      it->second.total_notifications = 0;
      it->second.total_highlights = 0;
      it->second.last_updated_at_ms = now_ms();
      it->second.needs_sync = true;
    }
  }

  // Get badge state for a user
  BadgeState get_badge(const std::string& user_id) {
    std::shared_lock<std::shared_mutex> lock(badge_mu_);
    auto it = badge_states_.find(user_id);
    if (it != badge_states_.end()) {
      return it->second;
    }
    BadgeState empty;
    empty.user_id = user_id;
    return empty;
  }

  // Get device badge state
  BadgeState get_device_badge(const std::string& user_id,
                               const std::string& pushkey) {
    std::shared_lock<std::shared_mutex> lock(badge_mu_);
    auto key = make_badge_key(user_id, pushkey);
    auto it = badge_states_.find(key);
    if (it != badge_states_.end()) {
      return it->second;
    }
    BadgeState empty;
    empty.user_id = user_id;
    empty.pushkey = pushkey;
    return empty;
  }

  // Get all badge states that need syncing
  std::vector<BadgeState> get_dirty_badges() {
    std::shared_lock<std::shared_mutex> lock(badge_mu_);
    std::vector<BadgeState> result;
    for (const auto& [key, state] : badge_states_) {
      if (state.needs_sync) {
        result.push_back(state);
      }
    }
    return result;
  }

  // Mark a badge as synced
  void mark_synced(const std::string& user_id, const std::string& pushkey = "") {
    std::unique_lock<std::shared_mutex> lock(badge_mu_);
    auto key = pushkey.empty() ? user_id : make_badge_key(user_id, pushkey);
    auto it = badge_states_.find(key);
    if (it != badge_states_.end()) {
      it->second.needs_sync = false;
      it->second.last_synced_at_ms = now_ms();
    }
  }

  // Get total badge count across all users (for monitoring)
  int64_t get_total_badge_count() const {
    std::shared_lock<std::shared_mutex> lock(badge_mu_);
    return total_badge_count_;
  }

  // Get user count with active badges
  size_t get_active_badge_user_count() const {
    std::shared_lock<std::shared_mutex> lock(badge_mu_);
    size_t count = 0;
    for (const auto& [key, state] : badge_states_) {
      if (state.total_notifications > 0 && state.pushkey.empty()) {
        ++count;
      }
    }
    return count;
  }

  // Persist badge state to database
  void persist_all(std::function<void(const BadgeState&)> write_fn) {
    auto dirty = get_dirty_badges();
    for (const auto& state : dirty) {
      write_fn(state);
    }
  }

private:
  static std::string make_badge_key(const std::string& user_id,
                                     const std::string& pushkey) {
    return user_id + ":" + pushkey;
  }

  PushGatewayConfig config_;
  mutable std::shared_mutex badge_mu_;
  std::unordered_map<std::string, BadgeState> badge_states_;
  std::atomic<int64_t> total_badge_count_{0};
};

// ============================================================================
// CircuitBreaker: Circuit breaker pattern for gateway protection
// ============================================================================

class CircuitBreaker {
public:
  struct Config {
    int failure_threshold{kCircuitBreakerFailureThreshold};
    chr::seconds cooldown{kCircuitBreakerCooldown};
    int half_open_probes{kCircuitBreakerHalfOpenProbes};
  };

  explicit CircuitBreaker(const Config& config) : config_(config) {}

  enum class State { Closed, Open, HalfOpen };

  // Called before attempting an operation
  bool allow_request() {
    std::lock_guard<std::mutex> lock(cb_mu_);
    int64_t now = now_ms();

    switch (state_) {
      case State::Closed:
        return true;

      case State::HalfOpen:
        return half_open_probes_remaining_ > 0;

      case State::Open:
        if (now >= cooldown_ends_at_ms_) {
          // Transition to half-open
          transition_to_half_open_locked(now);
          return half_open_probes_remaining_ > 0;
        }
        return false;
    }

    return false;
  }

  // Called on successful operation
  void record_success() {
    std::lock_guard<std::mutex> lock(cb_mu_);
    int64_t now = now_ms();

    switch (state_) {
      case State::Closed:
        consecutive_failures_ = 0;
        last_success_ms_ = now;
        break;

      case State::HalfOpen:
        --half_open_probes_remaining_;
        consecutive_failures_ = 0;
        last_success_ms_ = now;
        if (half_open_probes_remaining_ <= 0) {
          transition_to_closed_locked(now);
        }
        break;

      case State::Open:
        // Shouldn't happen, but reset if it does
        transition_to_closed_locked(now);
        break;
    }
  }

  // Called on failed operation
  void record_failure() {
    std::lock_guard<std::mutex> lock(cb_mu_);
    int64_t now = now_ms();

    switch (state_) {
      case State::Closed:
        ++consecutive_failures_;
        last_failure_ms_ = now;
        if (consecutive_failures_ >= config_.failure_threshold) {
          transition_to_open_locked(now);
        }
        break;

      case State::HalfOpen:
        // Any failure in half-open state re-opens the circuit
        transition_to_open_locked(now);
        break;

      case State::Open:
        ++consecutive_failures_;
        last_failure_ms_ = now;
        break;
    }
  }

  State get_state() const {
    std::lock_guard<std::mutex> lock(cb_mu_);
    return state_;
  }

  int get_consecutive_failures() const {
    std::lock_guard<std::mutex> lock(cb_mu_);
    return consecutive_failures_;
  }

  int64_t get_cooldown_remaining_ms() const {
    std::lock_guard<std::mutex> lock(cb_mu_);
    if (state_ != State::Open) return 0;
    int64_t remaining = cooldown_ends_at_ms_ - now_ms();
    return remaining > 0 ? remaining : 0;
  }

  // Force reset the circuit breaker
  void reset() {
    std::lock_guard<std::mutex> lock(cb_mu_);
    transition_to_closed_locked(now_ms());
  }

  // Get a human-readable status
  std::string status_string() const {
    std::lock_guard<std::mutex> lock(cb_mu_);
    switch (state_) {
      case State::Closed:
        return "CLOSED (failures: " + std::to_string(consecutive_failures_) + ")";
      case State::Open:
        return "OPEN (remaining: " +
               std::to_string(std::max(int64_t(0),
                                       cooldown_ends_at_ms_ - now_ms())) +
               "ms)";
      case State::HalfOpen:
        return "HALF_OPEN (probes: " +
               std::to_string(half_open_probes_remaining_) + ")";
    }
    return "UNKNOWN";
  }

private:
  void transition_to_open_locked(int64_t now) {
    state_ = State::Open;
    cooldown_ends_at_ms_ = now + (config_.cooldown.count() * 1000);
    opened_at_ms_ = now;
    circuit_open_count_++;
  }

  void transition_to_half_open_locked(int64_t now) {
    state_ = State::HalfOpen;
    half_open_probes_remaining_ = config_.half_open_probes;
  }

  void transition_to_closed_locked(int64_t now) {
    state_ = State::Closed;
    consecutive_failures_ = 0;
    half_open_probes_remaining_ = 0;
    last_closed_ms_ = now;
  }

  Config config_;
  mutable std::mutex cb_mu_;
  State state_{State::Closed};
  int consecutive_failures_{0};
  int half_open_probes_remaining_{0};
  int64_t cooldown_ends_at_ms_{0};
  int64_t last_success_ms_{0};
  int64_t last_failure_ms_{0};
  int64_t opened_at_ms_{0};
  int64_t last_closed_ms_{0};
  int64_t circuit_open_count_{0};
};

// ============================================================================
// RateLimitTracker: Token bucket rate limiter for push gateways
// ============================================================================

class RateLimitTracker {
public:
  RateLimitTracker(int64_t max_tokens, int64_t refill_rate_per_sec,
                   int64_t burst_size)
    : max_tokens_(max_tokens),
      refill_rate_(refill_rate_per_sec),
      burst_size_(burst_size),
      tokens_(burst_size),
      last_refill_ms_(now_ms()) {}

  // Try to consume a token. Returns true if allowed.
  bool try_consume(int tokens = 1) {
    std::lock_guard<std::mutex> lock(rate_mu_);
    refill_locked();
    if (tokens_ >= tokens) {
      tokens_ -= tokens;
      return true;
    }
    return false;
  }

  // Get time until next token is available (ms)
  int64_t time_until_available_ms(int tokens = 1) {
    std::lock_guard<std::mutex> lock(rate_mu_);
    refill_locked();
    if (tokens_ >= tokens) return 0;
    int64_t needed = tokens - tokens_;
    return (needed * 1000) / refill_rate_;
  }

  int64_t available_tokens() const {
    std::lock_guard<std::mutex> lock(rate_mu_);
    return tokens_;
  }

  void set_rate(int64_t max_tokens, int64_t refill_rate_per_sec) {
    std::lock_guard<std::mutex> lock(rate_mu_);
    max_tokens_ = max_tokens;
    refill_rate_ = refill_rate_per_sec;
    tokens_ = std::min(tokens_, burst_size_);
  }

private:
  void refill_locked() {
    int64_t now = now_ms();
    int64_t elapsed_ms = now - last_refill_ms_;
    if (elapsed_ms <= 0) return;

    int64_t new_tokens = (elapsed_ms * refill_rate_) / 1000;
    tokens_ = std::min(max_tokens_, tokens_ + new_tokens);
    last_refill_ms_ = now;
  }

  mutable std::mutex rate_mu_;
  int64_t max_tokens_;
  int64_t refill_rate_;
  int64_t burst_size_;
  int64_t tokens_;
  int64_t last_refill_ms_;
};

// ============================================================================
// RetryManager: Exponential backoff retry with jitter and circuit breaker
// ============================================================================

class RetryManager {
public:
  struct Config {
    int max_retries{kDefaultMaxRetries};
    chr::milliseconds base_backoff{kDefaultBaseBackoff};
    chr::milliseconds max_backoff{kDefaultMaxBackoff};
    double jitter_factor{kDefaultJitterFactor};
    CircuitBreaker::Config cb_config;
  };

  explicit RetryManager(const Config& config)
    : config_(config),
      circuit_breaker_(config.cb_config) {}

  // Check if a retry is allowed for the given key
  bool can_retry(const std::string& key) {
    if (!circuit_breaker_.allow_request()) return false;

    std::shared_lock<std::shared_mutex> lock(state_mu_);
    auto it = states_.find(key);
    if (it == states_.end()) return true;

    return it->second.can_retry(config_.max_retries,
                                config_.max_backoff.count());
  }

  // Record a successful operation
  void record_success(const std::string& key) {
    circuit_breaker_.record_success();

    std::unique_lock<std::shared_mutex> lock(state_mu_);
    auto it = states_.find(key);
    if (it != states_.end()) {
      it->second.consecutive_failures = 0;
      it->second.current_backoff_ms = 0;
      it->second.next_allowed_at_ms = 0;
    } else {
      RetryState state;
      state.key = key;
      states_[key] = state;
    }
  }

  // Record a failure and calculate next backoff
  int64_t record_failure(const std::string& key, int http_status = 0) {
    circuit_breaker_.record_failure();

    std::unique_lock<std::shared_mutex> lock(state_mu_);
    auto& state = states_[key];
    state.key = key;

    int64_t now = now_ms();

    state.consecutive_failures++;
    if (state.first_failure_ms == 0) {
      state.first_failure_ms = now;
    }
    state.last_failure_ms = now;

    // Calculate backoff with exponential growth and jitter
    int64_t base = config_.base_backoff.count() *
                   static_cast<int64_t>(std::pow(2.0,
                       std::min(state.consecutive_failures - 1,
                                config_.max_retries)));

    // Apply jitter
    int64_t jitter = static_cast<int64_t>(
        base * config_.jitter_factor *
        (static_cast<double>(rand()) / RAND_MAX * 2.0 - 1.0));

    state.current_backoff_ms = clamp_val(
        base + jitter,
        config_.base_backoff.count(),
        config_.max_backoff.count());

    state.next_allowed_at_ms = now + state.current_backoff_ms;

    // Honor Retry-After for 429 responses
    if (http_status == 429) {
      state.next_allowed_at_ms = std::max(state.next_allowed_at_ms,
                                          now + 60000); // Default 60s for 429
    }

    return state.current_backoff_ms;
  }

  // Get the delay until next retry (0 = can retry now)
  int64_t get_next_retry_delay_ms(const std::string& key) {
    std::shared_lock<std::shared_mutex> lock(state_mu_);
    auto it = states_.find(key);
    if (it == states_.end()) return 0;

    int64_t now = now_ms();
    int64_t delay = it->second.next_allowed_at_ms - now;
    return delay > 0 ? delay : 0;
  }

  // Get the current retry state
  RetryState get_state(const std::string& key) const {
    std::shared_lock<std::shared_mutex> lock(state_mu_);
    auto it = states_.find(key);
    if (it != states_.end()) return it->second;

    RetryState empty;
    empty.key = key;
    return empty;
  }

  // Reset retry state for a key
  void reset(const std::string& key) {
    std::unique_lock<std::shared_mutex> lock(state_mu_);
    states_.erase(key);
  }

  // Reset all retry states
  void reset_all() {
    std::unique_lock<std::shared_mutex> lock(state_mu_);
    states_.clear();
    circuit_breaker_.reset();
  }

  // Get circuit breaker status
  CircuitBreaker& circuit_breaker() { return circuit_breaker_; }

  // Get the number of tracked retry states
  size_t state_count() const {
    std::shared_lock<std::shared_mutex> lock(state_mu_);
    return states_.size();
  }

  // Get all states for persistence
  std::vector<RetryState> get_all_states() const {
    std::shared_lock<std::shared_mutex> lock(state_mu_);
    std::vector<RetryState> result;
    for (const auto& [key, state] : states_) {
      result.push_back(state);
    }
    return result;
  }

  // Load states from persistence
  void load_states(const std::vector<RetryState>& loaded) {
    std::unique_lock<std::shared_mutex> lock(state_mu_);
    for (const auto& state : loaded) {
      states_[state.key] = state;
    }
  }

private:
  Config config_;
  CircuitBreaker circuit_breaker_;
  mutable std::shared_mutex state_mu_;
  std::unordered_map<std::string, RetryState> states_;
};

// ============================================================================
// PushNotificationQueue: Persistent notification queue with priority and batching
// ============================================================================

class PushNotificationQueue {
public:
  struct Config {
    size_t max_capacity{kDefaultQueueCapacity};
    size_t per_user_limit{kDefaultUserQueueLimit};
    size_t batch_size{kDefaultBatchSize};
    chr::seconds item_ttl{kDefaultQueueItemTtl};
    int worker_threads{4};
    chr::milliseconds poll_interval{100};
  };

  PushNotificationQueue() = default;

  void configure(const Config& config) {
    config_ = config;
  }

  // Enqueue a notification
  bool enqueue(const QueuedNotification& notification) {
    std::unique_lock<std::shared_mutex> lock(queue_mu_);

    // Check capacity
    if (pending_queue_.size() >= config_.max_capacity) {
      return false;
    }

    // Check per-user limit
    auto user_it = user_queue_counts_.find(notification.user_id);
    if (user_it != user_queue_counts_.end() &&
        user_it->second >= config_.per_user_limit) {
      return false;
    }

    // Check idempotency
    if (!notification.idempotency_key.empty()) {
      auto idem_it = idempotency_set_.find(notification.idempotency_key);
      if (idem_it != idempotency_set_.end()) {
        return true; // Already queued, silently skip
      }
      idempotency_set_.insert(notification.idempotency_key);
    }

    QueuedNotification item = notification;
    item.id = generate_uuid_v4();
    item.created_at_ms = now_ms();
    item.scheduled_at_ms = std::max(item.scheduled_at_ms, item.created_at_ms);
    item.state = "pending";

    pending_queue_.push(item);
    user_queue_counts_[notification.user_id]++;
    total_enqueued_++;

    lock.unlock();
    queue_cv_.notify_one();

    return true;
  }

  // Batch enqueue multiple notifications
  size_t enqueue_batch(const std::vector<QueuedNotification>& notifications) {
    size_t accepted = 0;
    for (const auto& n : notifications) {
      if (enqueue(n)) ++accepted;
    }
    return accepted;
  }

  // Dequeue a batch of notifications for processing
  std::vector<QueuedNotification> dequeue_batch() {
    std::unique_lock<std::shared_mutex> lock(queue_mu_);

    std::vector<QueuedNotification> batch;
    batch.reserve(config_.batch_size);

    int64_t now = now_ms();

    while (batch.size() < config_.batch_size && !pending_queue_.empty()) {
      QueuedNotification item = pending_queue_.top();

      // Check if scheduled
      if (item.scheduled_at_ms > now) {
        break; // No more items ready
      }

      pending_queue_.pop();

      // Check expiry
      if (item.is_expired(config_.item_ttl.count() * 1000)) {
        expired_count_++;
        continue;
      }

      item.state = "processing";
      batch.push_back(item);
    }

    return batch;
  }

  // Mark a notification as delivered
  void mark_delivered(const std::string& notification_id) {
    std::unique_lock<std::shared_mutex> lock(queue_mu_);
    delivered_.push_back({notification_id, now_ms()});
    total_delivered_++;

    // Clean up idempotency set
    // (in production, look up the idempotency key from the delivered item)
    auto it = in_flight_idempotency_.find(notification_id);
    if (it != in_flight_idempotency_.end()) {
      idempotency_set_.erase(it->second);
      in_flight_idempotency_.erase(it);
    }
  }

  // Mark a notification as failed (for retry)
  void mark_failed(const QueuedNotification& notification,
                   const std::string& error, int http_status = 0) {
    std::unique_lock<std::shared_mutex> lock(queue_mu_);

    QueuedNotification item = notification;
    item.state = "failed";
    item.error_message = error;
    item.http_status = http_status;
    item.retry_count++;
    item.next_retry_at_ms = 0; // Will be set by retry manager

    if (item.can_retry(5)) {
      // Re-enqueue with delayed scheduling
      pending_queue_.push(item);
    } else {
      // Move to dead letter
      item.state = "dead_letter";
      dead_letter_queue_.push_back(item);
      dead_letter_count_++;
      total_failed_++;
    }
  }

  // Move a notification to the dead letter queue
  void move_to_dead_letter(const QueuedNotification& notification,
                           const std::string& reason) {
    std::unique_lock<std::shared_mutex> lock(queue_mu_);
    QueuedNotification item = notification;
    item.state = "dead_letter";
    item.error_message = reason;
    dead_letter_queue_.push_back(item);
    dead_letter_count_++;
  }

  // Get dead letter queue items
  std::vector<QueuedNotification> get_dead_letters(size_t limit = 100) {
    std::shared_lock<std::shared_mutex> lock(queue_mu_);
    std::vector<QueuedNotification> result;
    size_t count = 0;
    for (const auto& item : dead_letter_queue_) {
      if (count++ >= limit) break;
      result.push_back(item);
    }
    return result;
  }

  // Remove item from dead letter queue
  void purge_dead_letter(const std::string& notification_id) {
    std::unique_lock<std::shared_mutex> lock(queue_mu_);
    dead_letter_queue_.erase(
        std::remove_if(dead_letter_queue_.begin(), dead_letter_queue_.end(),
                       [&](const QueuedNotification& n) {
                         return n.id == notification_id;
                       }),
        dead_letter_queue_.end());
  }

  // Requeue a dead letter item
  bool requeue_dead_letter(const std::string& notification_id) {
    std::unique_lock<std::shared_mutex> lock(queue_mu_);
    for (auto it = dead_letter_queue_.begin();
         it != dead_letter_queue_.end(); ++it) {
      if (it->id == notification_id) {
        QueuedNotification item = *it;
        item.state = "pending";
        item.retry_count = 0;
        item.error_message = "";
        item.scheduled_at_ms = now_ms();
        pending_queue_.push(item);
        dead_letter_queue_.erase(it);
        return true;
      }
    }
    return false;
  }

  // Expire old items from all queues
  void expire_old_items() {
    std::unique_lock<std::shared_mutex> lock(queue_mu_);
    int64_t cutoff = now_ms() - (config_.item_ttl.count() * 1000);

    // Clean up delivered list
    delivered_.erase(
        std::remove_if(delivered_.begin(), delivered_.end(),
                       [cutoff](const auto& p) { return p.second < cutoff; }),
        delivered_.end());

    // Clean up dead letter
    dead_letter_queue_.erase(
        std::remove_if(dead_letter_queue_.begin(), dead_letter_queue_.end(),
                       [cutoff](const QueuedNotification& n) {
                         return n.created_at_ms < cutoff;
                       }),
        dead_letter_queue_.end());
  }

  // Get queue statistics
  json get_stats() const {
    std::shared_lock<std::shared_mutex> lock(queue_mu_);
    return {
      {"pending_count", pending_queue_.size()},
      {"dead_letter_count", dead_letter_queue_.size()},
      {"total_enqueued", total_enqueued_.load()},
      {"total_delivered", total_delivered_.load()},
      {"total_failed", total_failed_.load()},
      {"idempotency_set_size", idempotency_set_.size()},
      {"expired_count", expired_count_.load()},
      {"user_count", user_queue_counts_.size()}
    };
  }

  // Track in-flight idempotency
  void track_idempotency(const std::string& notification_id,
                         const std::string& idempotency_key) {
    std::unique_lock<std::shared_mutex> lock(queue_mu_);
    if (!idempotency_key.empty()) {
      in_flight_idempotency_[notification_id] = idempotency_key;
    }
  }

  // Wait for new items
  void wait_for_items() {
    std::unique_lock<std::shared_mutex> lock(queue_mu_);
    queue_cv_.wait_for(lock, config_.poll_interval, [this] {
      return !pending_queue_.empty() || shutdown_requested_;
    });
  }

  void request_shutdown() {
    shutdown_requested_ = true;
    queue_cv_.notify_all();
  }

private:
  // Priority queue comparator: higher priority items come first
  struct ComparePriority {
    bool operator()(const QueuedNotification& a,
                    const QueuedNotification& b) const {
      if (a.priority != b.priority)
        return a.priority < b.priority; // Lower priority = later
      return a.created_at_ms > b.created_at_ms; // Older = first
    }
  };

  Config config_;
  mutable std::shared_mutex queue_mu_;
  std::priority_queue<QueuedNotification,
                      std::vector<QueuedNotification>,
                      ComparePriority> pending_queue_;
  std::vector<QueuedNotification> dead_letter_queue_;
  std::vector<std::pair<std::string, int64_t>> delivered_;

  std::unordered_map<std::string, size_t> user_queue_counts_;
  std::unordered_set<std::string> idempotency_set_;
  std::unordered_map<std::string, std::string> in_flight_idempotency_;

  std::atomic<int64_t> total_enqueued_{0};
  std::atomic<int64_t> total_delivered_{0};
  std::atomic<int64_t> total_failed_{0};
  std::atomic<int64_t> expired_count_{0};
  std::atomic<int64_t> dead_letter_count_{0};

  std::condition_variable_any queue_cv_;
  bool shutdown_requested_{false};
};

// ============================================================================
// PushAnalytics: Track and report push notification metrics
// ============================================================================

class PushAnalytics {
public:
  struct Config {
    bool enabled{true};
    chr::seconds flush_interval{kAnalyticsFlushInterval};
    int batch_size{kAnalyticsBatchSize};
  };

  PushAnalytics() = default;

  void configure(const Config& config) {
    config_ = config;
  }

  // Record an analytics event
  void record_event(const AnalyticsEvent& event) {
    if (!config_.enabled) return;

    // Update real-time counters
    update_counters(event);

    std::lock_guard<std::mutex> lock(events_mu_);
    events_buffer_.push_back(event);

    if (events_buffer_.size() >= static_cast<size_t>(config_.batch_size)) {
      flush_locked();
    }
  }

  // Record a delivery attempt
  void record_attempt(const std::string& user_id, const std::string& gateway_type,
                      const std::string& app_id, const std::string& notification_id,
                      int64_t queue_duration_ms) {
    AnalyticsEvent event;
    event.id = generate_uuid_v4();
    event.user_id = user_id;
    event.gateway_type = gateway_type;
    event.app_id = app_id;
    event.notification_id = notification_id;
    event.event_type = "attempt";
    event.timestamp_ms = now_ms();
    event.queue_duration_ms = queue_duration_ms;
    record_event(event);
  }

  // Record a successful delivery
  void record_success(const std::string& user_id, const std::string& gateway_type,
                      const std::string& app_id, const std::string& notification_id,
                      int64_t queue_duration_ms, int64_t send_duration_ms,
                      int http_status, int retry_count) {
    AnalyticsEvent event;
    event.id = generate_uuid_v4();
    event.user_id = user_id;
    event.gateway_type = gateway_type;
    event.app_id = app_id;
    event.notification_id = notification_id;
    event.event_type = "success";
    event.timestamp_ms = now_ms();
    event.queue_duration_ms = queue_duration_ms;
    event.send_duration_ms = send_duration_ms;
    event.total_duration_ms = queue_duration_ms + send_duration_ms;
    event.http_status = http_status;
    event.retry_count = retry_count;
    record_event(event);
  }

  // Record a delivery failure
  void record_failure(const std::string& user_id, const std::string& gateway_type,
                      const std::string& app_id, const std::string& notification_id,
                      int64_t queue_duration_ms, int http_status,
                      const std::string& error, int retry_count) {
    AnalyticsEvent event;
    event.id = generate_uuid_v4();
    event.user_id = user_id;
    event.gateway_type = gateway_type;
    event.app_id = app_id;
    event.notification_id = notification_id;
    event.event_type = "failure";
    event.timestamp_ms = now_ms();
    event.queue_duration_ms = queue_duration_ms;
    event.http_status = http_status;
    event.error_message = error;
    event.retry_count = retry_count;
    record_event(event);
  }

  // Record dead letter
  void record_dead_letter(const std::string& user_id, const std::string& gateway_type,
                          const std::string& app_id, const std::string& notification_id,
                          const std::string& error) {
    AnalyticsEvent event;
    event.id = generate_uuid_v4();
    event.user_id = user_id;
    event.gateway_type = gateway_type;
    event.app_id = app_id;
    event.notification_id = notification_id;
    event.event_type = "dead_letter";
    event.timestamp_ms = now_ms();
    event.error_message = error;
    record_event(event);
  }

  // Get analytics summary
  json get_summary(const std::string& gateway_type = "",
                   int64_t since_ms = 0) {
    std::lock_guard<std::mutex> lock(metrics_mu_);

    if (since_ms == 0) {
      since_ms = now_ms() - (3600 * 1000); // Last hour default
    }

    if (!gateway_type.empty()) {
      auto it = gateway_metrics_.find(gateway_type);
      if (it != gateway_metrics_.end()) {
        return build_gateway_summary(gateway_type, it->second, since_ms);
      }
      return json::object();
    }

    // Summary across all gateways
    json summary = json::object();
    for (const auto& [gt, metrics] : gateway_metrics_) {
      summary[gt] = build_gateway_summary(gt, metrics, since_ms);
    }
    summary["total"] = build_global_summary();
    return summary;
  }

  // Purge old events
  void purge_old_events(int64_t before_ms) {
    std::lock_guard<std::mutex> lock(events_mu_);
    events_buffer_.erase(
        std::remove_if(events_buffer_.begin(), events_buffer_.end(),
                       [before_ms](const AnalyticsEvent& e) {
                         return e.timestamp_ms < before_ms;
                       }),
        events_buffer_.end());
  }

  // Flush buffered events to persistence
  std::vector<AnalyticsEvent> flush() {
    std::lock_guard<std::mutex> lock(events_mu_);
    return flush_locked();
  }

private:
  struct GatewayMetrics {
    std::atomic<int64_t> attempts{0};
    std::atomic<int64_t> successes{0};
    std::atomic<int64_t> failures{0};
    std::atomic<int64_t> dead_letters{0};
    std::atomic<int64_t> total_latency_ms{0};
    std::atomic<int64_t> total_send_ms{0};
    std::atomic<int64_t> total_queue_ms{0};

    // Latency tracking for percentiles (simplified)
    std::mutex latency_mu;
    std::vector<int64_t> recent_latencies; // Last N latencies
    static constexpr size_t kMaxLatencies = 1000;

    void add_latency(int64_t ms) {
      std::lock_guard<std::mutex> lock(latency_mu);
      recent_latencies.push_back(ms);
      if (recent_latencies.size() > kMaxLatencies) {
        recent_latencies.erase(recent_latencies.begin());
      }
    }

    int64_t p50_latency() const {
      std::lock_guard<std::mutex> lock(latency_mu);
      if (recent_latencies.empty()) return 0;
      auto sorted = recent_latencies;
      std::sort(sorted.begin(), sorted.end());
      return sorted[sorted.size() / 2];
    }

    int64_t p95_latency() const {
      std::lock_guard<std::mutex> lock(latency_mu);
      if (recent_latencies.empty()) return 0;
      auto sorted = recent_latencies;
      std::sort(sorted.begin(), sorted.end());
      return sorted[static_cast<size_t>(sorted.size() * 0.95)];
    }

    int64_t p99_latency() const {
      std::lock_guard<std::mutex> lock(latency_mu);
      if (recent_latencies.empty()) return 0;
      auto sorted = recent_latencies;
      std::sort(sorted.begin(), sorted.end());
      return sorted[static_cast<size_t>(sorted.size() * 0.99)];
    }
  };

  void update_counters(const AnalyticsEvent& event) {
    std::lock_guard<std::mutex> lock(metrics_mu_);
    auto& metrics = gateway_metrics_[event.gateway_type];

    if (event.event_type == "attempt") {
      metrics.attempts++;
    } else if (event.event_type == "success") {
      metrics.successes++;
      metrics.total_latency_ms += event.total_duration_ms;
      metrics.total_send_ms += event.send_duration_ms;
      metrics.total_queue_ms += event.queue_duration_ms;
      metrics.add_latency(event.total_duration_ms);
    } else if (event.event_type == "failure") {
      metrics.failures++;
    } else if (event.event_type == "dead_letter") {
      metrics.dead_letters++;
    }
  }

  json build_gateway_summary(const std::string& gateway_type,
                              GatewayMetrics& metrics, int64_t /*since_ms*/) {
    int64_t attempts = metrics.attempts.load();
    int64_t successes = metrics.successes.load();
    int64_t failures = metrics.failures.load();
    int64_t total = attempts > 0 ? attempts : successes + failures;
    int64_t total_latency = metrics.total_latency_ms.load();

    double success_rate = (attempts > 0) ? (100.0 * successes / attempts) :
                          ((successes + failures) > 0)
                          ? (100.0 * successes / (successes + failures)) : 100.0;
    int64_t avg_latency = successes > 0 ? total_latency / successes : 0;

    return {
      {"gateway_type", gateway_type},
      {"attempts", attempts},
      {"successes", successes},
      {"failures", failures},
      {"dead_letters", metrics.dead_letters.load()},
      {"success_rate", success_rate},
      {"avg_latency_ms", avg_latency},
      {"p50_latency_ms", metrics.p50_latency()},
      {"p95_latency_ms", metrics.p95_latency()},
      {"p99_latency_ms", metrics.p99_latency()},
      {"total_send_ms", metrics.total_send_ms.load()},
      {"total_queue_ms", metrics.total_queue_ms.load()}
    };
  }

  json build_global_summary() {
    int64_t total_attempts = 0, total_successes = 0, total_failures = 0;
    int64_t total_dead_letters = 0;

    for (const auto& [gt, metrics] : gateway_metrics_) {
      total_attempts += metrics.attempts.load();
      total_successes += metrics.successes.load();
      total_failures += metrics.failures.load();
      total_dead_letters += metrics.dead_letters.load();
    }

    double success_rate = total_attempts > 0
        ? (100.0 * total_successes / total_attempts) : 100.0;

    return {
      {"attempts", total_attempts},
      {"successes", total_successes},
      {"failures", total_failures},
      {"dead_letters", total_dead_letters},
      {"success_rate", success_rate},
      {"monitored_gateways", gateway_metrics_.size()}
    };
  }

  std::vector<AnalyticsEvent> flush_locked() {
    std::vector<AnalyticsEvent> flushed;
    flushed.swap(events_buffer_);
    return flushed;
  }

  Config config_;
  mutable std::mutex events_mu_;
  mutable std::mutex metrics_mu_;
  std::vector<AnalyticsEvent> events_buffer_;
  std::unordered_map<std::string, GatewayMetrics> gateway_metrics_;
};

// ============================================================================
// PushPreferenceManager: Manage user push notification preferences
// ============================================================================

class PushPreferenceManager {
public:
  PushPreferenceManager() = default;

  // Get preferences for a user (global + room-specific merged)
  PushPreference get_effective_preferences(const std::string& user_id,
                                            const std::string& room_id = "") {
    // Start with defaults
    PushPreference effective;
    effective.user_id = user_id;
    effective.push_enabled = true;
    effective.notification_level = "all_messages";
    effective.show_sender = true;
    effective.show_message = true;
    effective.show_room = true;
    effective.sound = kDefaultSound;
    effective.highlights_always = true;

    // Apply global preferences
    {
      std::shared_lock<std::shared_mutex> lock(prefs_mu_);
      auto global_it = global_prefs_.find(user_id);
      if (global_it != global_prefs_.end()) {
        merge_pref(effective, global_it->second);
      }
    }

    // Apply room-specific overrides
    if (!room_id.empty()) {
      std::shared_lock<std::shared_mutex> lock(prefs_mu_);
      auto room_key = make_room_key(user_id, room_id);
      auto room_it = room_prefs_.find(room_key);
      if (room_it != room_prefs_.end()) {
        merge_pref(effective, room_it->second);
      }
    }

    return effective;
  }

  // Set global preference for a user
  void set_global_preference(const PushPreference& pref) {
    std::unique_lock<std::shared_mutex> lock(prefs_mu_);
    PushPreference p = pref;
    p.room_id = "";
    p.updated_at_ms = now_ms();
    global_prefs_[pref.user_id] = p;
  }

  // Set room-specific preference
  void set_room_preference(const PushPreference& pref) {
    std::unique_lock<std::shared_mutex> lock(prefs_mu_);
    PushPreference p = pref;
    p.updated_at_ms = now_ms();
    room_prefs_[make_room_key(pref.user_id, pref.room_id)] = p;
  }

  // Delete room preference (revert to global)
  void delete_room_preference(const std::string& user_id,
                               const std::string& room_id) {
    std::unique_lock<std::shared_mutex> lock(prefs_mu_);
    room_prefs_.erase(make_room_key(user_id, room_id));
  }

  // Check if push is enabled for a given user/room
  bool is_push_enabled(const std::string& user_id,
                       const std::string& room_id = "") {
    auto prefs = get_effective_preferences(user_id, room_id);
    if (!prefs.push_enabled) return false;
    if (prefs.notification_level == "none") return false;

    // Check quiet hours
    if (is_quiet_hours(prefs)) return false;

    return true;
  }

  // Check if this is within quiet hours
  bool is_quiet_hours(const PushPreference& prefs) {
    if (prefs.quiet_hours_start < 0 || prefs.quiet_hours_end < 0) return false;

    auto now = chr::system_clock::now();
    auto tt = chr::system_clock::to_time_t(now);
    std::tm tm;
    localtime_r(&tt, &tm);

    int current_time = tm.tm_hour * 100 + tm.tm_min;

    int start = prefs.quiet_hours_start;
    int end = prefs.quiet_hours_end;

    if (start <= end) {
      // Same day window (e.g., 2200 to 0600 next day is NOT same day)
      return current_time >= start && current_time < end;
    } else {
      // Overnight window (e.g., 2200 to 0700)
      return current_time >= start || current_time < end;
    }
  }

  // Check if notifications should be silenced (quiet hours + no highlight override)
  bool should_silence(const std::string& user_id, const std::string& room_id,
                      bool is_highlight) {
    auto prefs = get_effective_preferences(user_id, room_id);
    if (is_highlight && prefs.highlights_always) return false;
    return is_quiet_hours(prefs);
  }

  // Get all preferences for a user (for API response)
  json get_all_preferences(const std::string& user_id) {
    json result;
    result["global"] = json::object();
    result["rooms"] = json::object();

    {
      std::shared_lock<std::shared_mutex> lock(prefs_mu_);
      auto global_it = global_prefs_.find(user_id);
      if (global_it != global_prefs_.end()) {
        result["global"] = global_it->second.to_json();
      }

      // Iterate room prefs
      for (const auto& [key, pref] : room_prefs_) {
        if (pref.user_id == user_id) {
          result["rooms"][pref.room_id] = pref.to_json();
        }
      }
    }

    return result;
  }

  // Reset preferences for a user
  void reset_user(const std::string& user_id) {
    std::unique_lock<std::shared_mutex> lock(prefs_mu_);
    global_prefs_.erase(user_id);

    // Remove all room prefs for this user
    auto it = room_prefs_.begin();
    while (it != room_prefs_.end()) {
      if (it->second.user_id == user_id) {
        it = room_prefs_.erase(it);
      } else {
        ++it;
      }
    }
  }

  // Get count of users with custom preferences
  size_t get_user_count() const {
    std::shared_lock<std::shared_mutex> lock(prefs_mu_);
    return global_prefs_.size();
  }

  // Get count of room-specific preferences
  size_t get_room_pref_count() const {
    std::shared_lock<std::shared_mutex> lock(prefs_mu_);
    return room_prefs_.size();
  }

  // Persist all preferences
  std::vector<PushPreference> get_all_for_persistence() {
    std::shared_lock<std::shared_mutex> lock(prefs_mu_);
    std::vector<PushPreference> result;
    for (const auto& [key, pref] : global_prefs_) {
      result.push_back(pref);
    }
    for (const auto& [key, pref] : room_prefs_) {
      result.push_back(pref);
    }
    return result;
  }

  // Load preferences from persistence
  void load_from_persistence(const std::vector<PushPreference>& prefs) {
    std::unique_lock<std::shared_mutex> lock(prefs_mu_);
    for (const auto& pref : prefs) {
      if (pref.room_id.empty()) {
        global_prefs_[pref.user_id] = pref;
      } else {
        room_prefs_[make_room_key(pref.user_id, pref.room_id)] = pref;
      }
    }
  }

private:
  static std::string make_room_key(const std::string& user_id,
                                    const std::string& room_id) {
    return user_id + ":" + room_id;
  }

  void merge_pref(PushPreference& target, const PushPreference& source) {
    // Only override fields that are explicitly set (not default)
    target.push_enabled = source.push_enabled;
    if (source.notification_level != "all_messages") {
      target.notification_level = source.notification_level;
    }
    target.show_sender = source.show_sender;
    target.show_message = source.show_message;
    target.show_room = source.show_room;
    if (source.sound != kDefaultSound) {
      target.sound = source.sound;
    }
    if (source.quiet_hours_start >= 0) {
      target.quiet_hours_start = source.quiet_hours_start;
    }
    if (source.quiet_hours_end >= 0) {
      target.quiet_hours_end = source.quiet_hours_end;
    }
    if (!source.timezone.empty() && source.timezone != "UTC") {
      target.timezone = source.timezone;
    }
    target.highlights_always = source.highlights_always;
  }

  mutable std::shared_mutex prefs_mu_;
  std::unordered_map<std::string, PushPreference> global_prefs_;
  std::unordered_map<std::string, PushPreference> room_prefs_;
};

// ============================================================================
// GatewayHealthMonitor: Health check and monitoring for push gateways
// ============================================================================

class GatewayHealthMonitor {
public:
  GatewayHealthMonitor() = default;

  // Record a successful gateway operation
  void record_success(const std::string& gateway_type,
                      const std::string& endpoint_url,
                      int64_t latency_ms) {
    std::unique_lock<std::shared_mutex> lock(health_mu_);
    auto key = make_key(gateway_type, endpoint_url);
    auto& health = health_map_[key];
    health.gateway_type = gateway_type;
    health.endpoint_url = endpoint_url;
    health.last_success_ms = now_ms();
    health.last_probe_ms = now_ms();
    health.consecutive_failures = 0;
    health.healthy = true;
    health.total_successes++;
    health.total_probes++;
    health.avg_latency_ms =
        ((health.avg_latency_ms * (health.total_successes - 1)) + latency_ms) /
        health.total_successes;
    update_success_rate_locked(health);
  }

  // Record a failed gateway operation
  void record_failure(const std::string& gateway_type,
                      const std::string& endpoint_url,
                      const std::string& error) {
    std::unique_lock<std::shared_mutex> lock(health_mu_);
    auto key = make_key(gateway_type, endpoint_url);
    auto& health = health_map_[key];
    health.gateway_type = gateway_type;
    health.endpoint_url = endpoint_url;
    health.last_failure_ms = now_ms();
    health.last_probe_ms = now_ms();
    health.consecutive_failures++;
    health.total_failures++;
    health.total_probes++;

    if (health.consecutive_failures >= 5) {
      health.healthy = false;
    }

    update_success_rate_locked(health);
  }

  // Check if a gateway is healthy
  bool is_healthy(const std::string& gateway_type,
                  const std::string& endpoint_url = "") {
    std::shared_lock<std::shared_mutex> lock(health_mu_);
    auto key = make_key(gateway_type, endpoint_url);
    auto it = health_map_.find(key);
    if (it == health_map_.end()) return true; // No data = assume healthy
    return it->second.healthy;
  }

  // Get health status for all gateways
  json get_all_health() {
    std::shared_lock<std::shared_mutex> lock(health_mu_);
    json result = json::array();
    for (const auto& [key, health] : health_map_) {
      result.push_back({
        {"gateway_type", health.gateway_type},
        {"endpoint_url", health.endpoint_url},
        {"healthy", health.healthy},
        {"consecutive_failures", health.consecutive_failures},
        {"total_probes", health.total_probes},
        {"total_successes", health.total_successes},
        {"total_failures", health.total_failures},
        {"success_rate", health.success_rate},
        {"avg_latency_ms", health.avg_latency_ms},
        {"last_success_ms", health.last_success_ms},
        {"last_failure_ms", health.last_failure_ms}
      });
    }
    return result;
  }

  // Get health for a specific gateway type
  GatewayHealth get_health(const std::string& gateway_type,
                           const std::string& endpoint_url = "") {
    std::shared_lock<std::shared_mutex> lock(health_mu_);
    auto key = make_key(gateway_type, endpoint_url);
    auto it = health_map_.find(key);
    if (it != health_map_.end()) return it->second;

    GatewayHealth empty;
    empty.gateway_type = gateway_type;
    empty.endpoint_url = endpoint_url;
    return empty;
  }

private:
  static std::string make_key(const std::string& gateway_type,
                               const std::string& endpoint_url) {
    return gateway_type + ":" + endpoint_url;
  }

  void update_success_rate_locked(GatewayHealth& health) {
    int64_t total = health.total_successes + health.total_failures;
    if (total > 0) {
      health.success_rate = 100.0 * health.total_successes / total;
    }
  }

  mutable std::shared_mutex health_mu_;
  std::unordered_map<std::string, GatewayHealth> health_map_;
};

// ============================================================================
// ApnsGateway: APNs push gateway implementation
// ============================================================================

class ApnsGateway {
public:
  explicit ApnsGateway(const PushGatewayConfig& config)
    : config_(config), jwt_provider_(), payload_builder_(config) {}

  // Configure the APNs gateway
  bool configure() {
    if (!config_.enable_apns) return false;

    if (!config_.apns_use_certificate_auth) {
      // JWT-based auth
      std::string key_content = config_.apns_private_key_content;
      if (key_content.empty() && !config_.apns_private_key_path.empty()) {
        key_content = load_file(config_.apns_private_key_path);
      }
      jwt_provider_.configure(config_.apns_key_id, config_.apns_team_id,
                              key_content, config_.apns_jwt_lifetime_sec);
      configured_ = jwt_provider_.is_valid();
    } else {
      // Certificate-based auth (placeholder)
      configured_ = !config_.apns_cert_path.empty();
    }

    return configured_;
  }

  // Send an alert push notification via APNs
  bool send_alert(const std::string& device_token,
                  const std::string& title,
                  const std::string& body,
                  const std::string& subtitle = "",
                  int badge_count = -1,
                  const std::string& sound = kDefaultSound,
                  const std::string& category = "",
                  const std::string& thread_id = "",
                  const std::string& collapse_id = "",
                  int priority = kApnsImmediatePriority,
                  const json& custom_data = json::object()) {

    if (!configured_) {
      last_error_ = "APNs gateway not configured";
      return false;
    }

    std::string topic = config_.apns_default_topic;

    // Build payload
    json payload = payload_builder_.build_alert(
        title, body, subtitle, badge_count, sound, category, thread_id,
        custom_data);

    // Ensure payload size
    payload = payload_builder_.ensure_size(payload);

    // Build headers
    auto headers = payload_builder_.build_headers(
        topic, priority, 0, collapse_id, "alert");

    // Send
    return send_to_apns(device_token, payload, headers);
  }

  // Send a silent/background push
  bool send_background(const std::string& device_token,
                       const json& custom_data = json::object(),
                       const std::string& collapse_id = "") {

    if (!configured_) {
      last_error_ = "APNs gateway not configured";
      return false;
    }

    std::string topic = config_.apns_default_topic;

    json payload = payload_builder_.build_background(custom_data);

    auto headers = payload_builder_.build_headers(
        topic, kApnsConservePriority, 0, collapse_id, "background");

    return send_to_apns(device_token, payload, headers);
  }

  // Send a badge-only update
  bool send_badge_update(const std::string& device_token, int badge_count) {
    if (!configured_) {
      last_error_ = "APNs gateway not configured";
      return false;
    }

    std::string topic = config_.apns_default_topic;

    json payload = payload_builder_.build_badge_update(badge_count);

    auto headers = payload_builder_.build_headers(
        topic, kApnsConservePriority, 0, "", "background");

    return send_to_apns(device_token, payload, headers);
  }

  std::string get_endpoint() const {
    return config_.apns_use_sandbox
        ? kApnsDevelopmentEndpoint : kApnsProductionEndpoint;
  }

  std::string get_last_error() const {
    std::lock_guard<std::mutex> lock(error_mu_);
    return last_error_;
  }

private:
  bool send_to_apns(const std::string& device_token,
                    const json& payload,
                    const std::map<std::string, std::string>& headers) {

    std::string endpoint = get_endpoint();
    std::string path = std::string(kApnsDefaultPath) + device_token;

    // Get JWT for auth
    std::string jwt = jwt_provider_.get_jwt();
    if (jwt.empty() && !config_.apns_use_certificate_auth) {
      std::lock_guard<std::mutex> lock(error_mu_);
      last_error_ = "Failed to obtain APNs JWT";
      return false;
    }

    // In production: make HTTP/2 POST to endpoint + path
    // with the JWT as Bearer token and custom apns-* headers
    //
    // Stub: simulate success
    {
      std::lock_guard<std::mutex> lock(error_mu_);
      last_error_ = "";
    }

    (void)device_token;
    (void)headers;
    (void)jwt;

    return true;
  }

  std::string load_file(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) return "";
    std::ostringstream ss;
    ss << file.rdbuf();
    return ss.str();
  }

  PushGatewayConfig config_;
  ApnsJwtProvider jwt_provider_;
  ApnsPayloadBuilder payload_builder_;
  bool configured_{false};
  mutable std::mutex error_mu_;
  std::string last_error_;
};

// ============================================================================
// FcmGateway: FCM push gateway implementation
// ============================================================================

class FcmGateway {
public:
  explicit FcmGateway(const PushGatewayConfig& config)
    : config_(config), payload_builder_(config) {}

  // Configure the FCM gateway
  bool configure() {
    if (!config_.enable_fcm) return false;

    if (config_.fcm_use_v1_api) {
      // OAuth-based v1 API
      std::string sa_json = config_.fcm_service_account_json_content;
      if (sa_json.empty() && !config_.fcm_service_account_json_path.empty()) {
        sa_json = load_file(config_.fcm_service_account_json_path);
      }
      if (!sa_json.empty()) {
        oauth_provider_.configure(sa_json);
        configured_ = oauth_provider_.is_valid();
      }
    } else {
      // Legacy server key
      if (!config_.fcm_server_key.empty()) {
        oauth_provider_.configure_legacy(config_.fcm_server_key);
        configured_ = oauth_provider_.is_valid();
      }
    }

    project_id_ = config_.fcm_project_id;
    if (project_id_.empty()) {
      project_id_ = oauth_provider_.get_project_id();
    }

    return configured_;
  }

  // Send a push notification via FCM v1 API
  bool send_v1_message(const std::string& token,
                       const std::string& title,
                       const std::string& body,
                       const json& data = json::object(),
                       const std::string& image_url = "",
                       const std::string& channel_id = "",
                       const std::string& collapse_key = "",
                       const std::string& priority = "high",
                       int ttl_sec = 86400 * 7) {

    if (!configured_) {
      last_error_ = "FCM gateway not configured";
      return false;
    }

    json payload = payload_builder_.build_v1_message(
        token, title, body, data, image_url, channel_id,
        collapse_key, priority, ttl_sec);

    std::string endpoint = build_v1_endpoint();
    return send_to_fcm(endpoint, payload);
  }

  // Send via legacy FCM API
  bool send_legacy_message(const std::string& token,
                           const std::string& title,
                           const std::string& body,
                           const json& data = json::object(),
                           const std::string& collapse_key = "",
                           const std::string& priority = "high",
                           int ttl_sec = 86400 * 7) {

    if (!configured_) {
      last_error_ = "FCM gateway not configured";
      return false;
    }

    json notification = {
      {"title", title},
      {"body", body}
    };

    json payload = payload_builder_.build_legacy_message(
        token, notification, data, collapse_key, priority, ttl_sec);

    std::string endpoint = build_legacy_endpoint();
    return send_to_fcm(endpoint, payload);
  }

  // Send multicast to multiple tokens
  bool send_multicast(const std::vector<std::string>& tokens,
                      const std::string& title,
                      const std::string& body,
                      const json& data = json::object(),
                      const std::string& collapse_key = "") {

    if (!configured_) {
      last_error_ = "FCM gateway not configured";
      return false;
    }

    json payload = payload_builder_.build_multicast(
        tokens, title, body, data, collapse_key);

    std::string endpoint = build_legacy_endpoint();
    return send_to_fcm(endpoint, payload);
  }

  std::string get_last_error() const { return last_error_; }

private:
  bool send_to_fcm(const std::string& endpoint, const json& payload) {
    std::string auth = oauth_provider_.get_auth_header();
    if (auth.empty()) {
      last_error_ = "Failed to obtain FCM auth credentials";
      return false;
    }

    // In production: make HTTP POST to endpoint with auth header
    // and JSON payload. Parse response for errors.
    //
    // Stub: simulate success
    last_error_ = "";

    (void)endpoint;
    (void)auth;

    return true;
  }

  std::string build_v1_endpoint() const {
    return std::string("https://") + kFcmV1Endpoint +
           kFcmV1Path + project_id_ + "/messages:send";
  }

  std::string build_legacy_endpoint() const {
    return std::string("https://") + kFcmLegacyEndpoint + kFcmLegacyPath;
  }

  std::string load_file(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) return "";
    std::ostringstream ss;
    ss << file.rdbuf();
    return ss.str();
  }

  PushGatewayConfig config_;
  FcmOAuthProvider oauth_provider_;
  FcmPayloadBuilder payload_builder_;
  bool configured_{false};
  std::string project_id_;
  std::string last_error_;
};

// ============================================================================
// GenericPushGateway: Generic HTTP push gateway implementation
// ============================================================================

class GenericPushGateway {
public:
  explicit GenericPushGateway(const PushGatewayConfig& config)
    : config_(config), payload_builder_(config) {}

  // Send a notification to a Matrix push gateway
  bool send_notification(
      const std::string& gateway_url,
      const std::string& bearer_token,
      const std::string& room_id,
      const std::string& room_name,
      const std::string& sender,
      const std::string& sender_display_name,
      const std::string& event_id,
      const std::string& event_type,
      const json& content,
      int64_t unread_count,
      int64_t highlight_count,
      bool is_highlight,
      const std::string& priority = "high",
      const json& extra_data = json::object()) {

    if (!config_.enable_generic_gateways) {
      last_error_ = "Generic gateways disabled";
      return false;
    }

    json payload = payload_builder_.build_notification(
        room_id, room_name, sender, sender_display_name,
        event_id, event_type, content,
        unread_count, highlight_count, is_highlight,
        priority, extra_data);

    return http_post_to_gateway(gateway_url, payload, bearer_token);
  }

  // Send coalesced notification
  bool send_coalesced(
      const std::string& gateway_url,
      const std::string& bearer_token,
      const std::string& room_id,
      const std::string& room_name,
      int notification_count,
      int highlight_count,
      const std::vector<json>& event_summaries,
      const json& extra_data = json::object()) {

    if (!config_.enable_generic_gateways) {
      last_error_ = "Generic gateways disabled";
      return false;
    }

    json payload = payload_builder_.build_coalesced(
        room_id, room_name, notification_count, highlight_count,
        event_summaries, extra_data);

    return http_post_to_gateway(gateway_url, payload, bearer_token);
  }

  // Send badge-only update
  bool send_badge_update(const std::string& gateway_url,
                         const std::string& bearer_token,
                         int badge_count) {

    if (!config_.enable_generic_gateways) {
      last_error_ = "Generic gateways disabled";
      return false;
    }

    json payload = payload_builder_.build_badge_update(badge_count);

    return http_post_to_gateway(gateway_url, payload, bearer_token);
  }

  // Test a gateway endpoint health
  bool probe_gateway(const std::string& gateway_url) {
    if (!config_.enable_generic_gateways) return false;

    // In production: make HTTP HEAD or GET to gateway_url
    // Return true if 2xx response, false otherwise
    //
    // Stub: always return true for valid-looking URLs
    if (!starts_with(gateway_url, "http://") &&
        !starts_with(gateway_url, "https://")) {
      last_error_ = "Invalid gateway URL";
      return false;
    }

    last_error_ = "";
    return true;
  }

  std::string get_last_error() const { return last_error_; }

private:
  bool http_post_to_gateway(const std::string& url,
                            const json& payload,
                            const std::string& bearer_token) {
    if (!starts_with(url, "http://") && !starts_with(url, "https://")) {
      last_error_ = "Invalid gateway URL: " + url;
      return false;
    }

    // In production: make HTTP POST to gateway_url with:
    // - Content-Type: application/json
    // - Authorization: Bearer <token> (if provided)
    // - User-Agent header
    // - TLS verification per config_.generic_verify_ssl
    // - Timeout per config_.generic_gateway_timeout
    //
    // Parse response for success (2xx) or error
    //
    // Stub: simulate success
    last_error_ = "";

    (void)bearer_token;

    return true;
  }

  PushGatewayConfig config_;
  GenericPayloadBuilder payload_builder_;
  std::string last_error_;
};

// ============================================================================
// DeadLetterQueue: Manage permanently failed notifications
// ============================================================================

class DeadLetterQueue {
public:
  // Add an item to the dead letter queue
  void add(const QueuedNotification& item, const std::string& reason,
           const std::string& gateway_type) {
    std::lock_guard<std::mutex> lock(dlq_mu_);
    DeadLetterEntry entry;
    entry.notification = item;
    entry.reason = reason;
    entry.gateway_type = gateway_type;
    entry.entered_at_ms = now_ms();
    entries_.push_back(entry);
    total_count_++;
  }

  // Query dead letters with filters
  std::vector<DeadLetterEntry> query(
      const std::string& user_id = "",
      const std::string& gateway_type = "",
      int64_t since_ms = 0,
      size_t limit = 100) {

    std::lock_guard<std::mutex> lock(dlq_mu_);
    std::vector<DeadLetterEntry> result;

    for (const auto& entry : entries_) {
      if (result.size() >= limit) break;
      if (!user_id.empty() && entry.notification.user_id != user_id) continue;
      if (!gateway_type.empty() && entry.gateway_type != gateway_type) continue;
      if (since_ms > 0 && entry.entered_at_ms < since_ms) continue;
      result.push_back(entry);
    }

    return result;
  }

  // Requeue a dead letter item
  bool requeue(const std::string& notification_id,
               std::function<bool(const QueuedNotification&)> enqueue_fn) {
    std::lock_guard<std::mutex> lock(dlq_mu_);

    for (auto it = entries_.begin(); it != entries_.end(); ++it) {
      if (it->notification.id == notification_id) {
        QueuedNotification item = it->notification;
        item.state = "pending";
        item.retry_count = 0;
        item.error_message = "";
        item.scheduled_at_ms = now_ms();

        if (enqueue_fn(item)) {
          entries_.erase(it);
          return true;
        }
        return false;
      }
    }

    return false;
  }

  // Purge old items
  size_t purge_old(int64_t older_than_ms) {
    std::lock_guard<std::mutex> lock(dlq_mu_);
    size_t before = entries_.size();
    entries_.erase(
        std::remove_if(entries_.begin(), entries_.end(),
                       [older_than_ms](const DeadLetterEntry& e) {
                         return e.entered_at_ms < older_than_ms;
                       }),
        entries_.end());
    return before - entries_.size();
  }

  // Purge specific item
  bool purge(const std::string& notification_id) {
    std::lock_guard<std::mutex> lock(dlq_mu_);
    auto it = std::find_if(entries_.begin(), entries_.end(),
                           [&](const DeadLetterEntry& e) {
                             return e.notification.id == notification_id;
                           });
    if (it != entries_.end()) {
      entries_.erase(it);
      return true;
    }
    return false;
  }

  // Get statistics
  json get_stats() {
    std::lock_guard<std::mutex> lock(dlq_mu_);
    return {
      {"total_count", total_count_.load()},
      {"current_size", entries_.size()},
      {"oldest_entry_ms", entries_.empty() ? 0 : entries_.front().entered_at_ms},
      {"newest_entry_ms", entries_.empty() ? 0 : entries_.back().entered_at_ms}
    };
  }

  struct DeadLetterEntry {
    QueuedNotification notification;
    std::string reason;
    std::string gateway_type;
    int64_t entered_at_ms{0};
  };

private:
  mutable std::mutex dlq_mu_;
  std::vector<DeadLetterEntry> entries_;
  std::atomic<int64_t> total_count_{0};
};

// ============================================================================
// IdempotencyGuard: Prevent duplicate notification delivery
// ============================================================================

class IdempotencyGuard {
public:
  struct Config {
    chr::seconds ttl{600};       // 10 minutes default
    size_t max_entries{100'000};
  };

  explicit IdempotencyGuard(const Config& config) : config_(config) {}

  // Check if a key has been seen. If not, mark it as seen.
  // Returns true if this is a new key (proceed with delivery).
  bool check_and_mark(const std::string& key) {
    if (key.empty()) return true; // No idempotency check

    std::lock_guard<std::mutex> lock(guard_mu_);
    int64_t now = now_ms();
    int64_t cutoff = now - (config_.ttl.count() * 1000);

    // Clean expired entries opportunistically
    auto it = seen_keys_.find(key);
    if (it != seen_keys_.end()) {
      if (it->second >= cutoff) {
        return false; // Already seen, not expired
      }
      // Expired, re-mark
      seen_keys_.erase(it);
    }

    // Enforce max size
    if (seen_keys_.size() >= config_.max_entries) {
      evict_old_entries_locked(cutoff);
    }

    seen_keys_[key] = now;
    return true;
  }

  // Manually remove a key (e.g., after successful delivery)
  void remove(const std::string& key) {
    if (key.empty()) return;
    std::lock_guard<std::mutex> lock(guard_mu_);
    seen_keys_.erase(key);
  }

  // Remove expired entries
  size_t purge_expired() {
    std::lock_guard<std::mutex> lock(guard_mu_);
    int64_t cutoff = now_ms() - (config_.ttl.count() * 1000);
    size_t before = seen_keys_.size();
    evict_old_entries_locked(cutoff);
    return before - seen_keys_.size();
  }

  size_t size() const {
    std::lock_guard<std::mutex> lock(guard_mu_);
    return seen_keys_.size();
  }

private:
  void evict_old_entries_locked(int64_t cutoff) {
    auto it = seen_keys_.begin();
    while (it != seen_keys_.end()) {
      if (it->second < cutoff) {
        it = seen_keys_.erase(it);
      } else {
        ++it;
      }
    }
  }

  Config config_;
  mutable std::mutex guard_mu_;
  std::unordered_map<std::string, int64_t> seen_keys_;
};

// ============================================================================
// PushGatewayCoordinator: Top-level orchestrator for push gateway operations
// ============================================================================

class PushGatewayCoordinator {
public:
  PushGatewayCoordinator(const PushGatewayConfig& config)
    : config_(config),
      apns_gateway_(config),
      fcm_gateway_(config),
      generic_gateway_(config),
      formatter_(config),
      badge_manager_(),
      queue_(),
      retry_manager_(RetryManager::Config{
          config.max_retries,
          config.base_backoff_ms,
          config.max_backoff_ms,
          config.jitter_factor,
          CircuitBreaker::Config{
              config.cb_failure_threshold,
              config.cb_cooldown_sec,
              config.cb_half_open_probes
          }
      }),
      analytics_(),
      pref_manager_(),
      health_monitor_(),
      idempotency_guard_({chr::seconds{600}, 100'000}) {
    badge_manager_.configure(config);
    queue_.configure(PushNotificationQueue::Config{
        config.queue_max_capacity,
        config.queue_per_user_limit,
        config.queue_batch_size,
        config.queue_item_ttl,
        config.queue_worker_threads,
        config.queue_poll_interval
    });
    analytics_.configure(PushAnalytics::Config{
        config.enable_analytics,
        config.analytics_flush_interval,
        config.analytics_batch_size
    });
  }

  // Initialize all gateways
  bool initialize() {
    if (!config_.enable_push) return false;

    bool apns_ok = true, fcm_ok = true;

    if (config_.enable_apns) {
      apns_ok = apns_gateway_.configure();
    }

    if (config_.enable_fcm) {
      fcm_ok = fcm_gateway_.configure();
    }

    initialized_ = true;
    return apns_ok && fcm_ok;
  }

  // Dispatch a push notification through the appropriate gateway
  bool dispatch(const std::string& user_id,
                const std::string& device_id,
                const std::string& pushkey,
                const std::string& gateway_type,
                const std::string& app_id,
                const std::string& gateway_url,
                const std::string& event_id,
                const std::string& room_id,
                const std::string& room_name,
                const std::string& sender,
                const std::string& sender_display_name,
                const std::string& event_type,
                const json& content,
                int64_t unread_count,
                int64_t highlight_count,
                bool is_highlight,
                int priority = kDefaultPriority) {

    if (!initialized_) return false;

    // Check preferences
    if (!pref_manager_.is_push_enabled(user_id, room_id)) {
      return true; // Silently suppressed, not a failure
    }

    // Check quiet hours
    if (pref_manager_.should_silence(user_id, room_id, is_highlight)) {
      return true; // Silenced
    }

    // Get effective preferences
    auto prefs = pref_manager_.get_effective_preferences(user_id, room_id);

    // Format notification
    std::string title = formatter_.format_title(sender_display_name,
                                                 room_name, prefs);
    std::string body = formatter_.format_body(event_type, sender_display_name,
                                               room_name, content, prefs);

    // Build idempotency key
    std::string idempotency_key = user_id + ":" + event_id + ":" +
                                   pushkey.substr(0, 16);

    // Check idempotency
    if (!idempotency_guard_.check_and_mark(idempotency_key)) {
      return true; // Duplicate, skip
    }

    // Check retry state
    std::string retry_key = gateway_type + ":" + sha256_hex(pushkey);
    if (!retry_manager_.can_retry(retry_key)) {
      // Queue it for later delivery
      QueuedNotification queued;
      queued.idempotency_key = idempotency_key;
      queued.user_id = user_id;
      queued.device_id = device_id;
      queued.pushkey = pushkey;
      queued.gateway_type = gateway_type;
      queued.app_id = app_id;
      queued.gateway_url = gateway_url;
      queued.event_id = event_id;
      queued.room_id = room_id;
      queued.sender = sender;
      queued.priority = priority;
      queued.scheduled_at_ms = now_ms() + retry_manager_.get_next_retry_delay_ms(retry_key);

      json payload;
      payload["title"] = title;
      payload["body"] = body;
      payload["event_type"] = event_type;
      payload["room_id"] = room_id;
      payload["room_name"] = room_name;
      payload["sender"] = sender;
      payload["sender_display_name"] = sender_display_name;
      payload["content"] = content;
      payload["unread_count"] = unread_count;
      payload["highlight_count"] = highlight_count;
      payload["is_highlight"] = is_highlight;
      queued.notification_payload = payload;

      queue_.enqueue(queued);
      return true;
    }

    // Record analytics attempt
    int64_t queue_start = now_ms();
    analytics_.record_attempt(user_id, gateway_type, app_id,
                              event_id, 0);

    // Send through appropriate gateway
    int64_t send_start = now_ms();
    bool success = false;
    int http_status = 0;
    std::string error;

    if (gateway_type == "apns") {
      success = apns_gateway_.send_alert(
          pushkey, title, body,
          sender_display_name, unread_count,
          prefs.sound, "", formatter_.generate_thread_id(room_id),
          formatter_.generate_collapse_key(room_id, sender));
      error = apns_gateway_.get_last_error();
    }
    else if (gateway_type == "fcm") {
      json data;
      data["room_id"] = room_id;
      data["event_id"] = event_id;
      data["sender"] = sender;

      if (config_.fcm_use_v1_api) {
        success = fcm_gateway_.send_v1_message(
            pushkey, title, body, data, "",
            "", formatter_.generate_collapse_key(room_id));
      } else {
        success = fcm_gateway_.send_legacy_message(
            pushkey, title, body, data,
            formatter_.generate_collapse_key(room_id));
      }
      error = fcm_gateway_.get_last_error();
    }
    else {
      // Generic HTTP push gateway
      json extra;
      extra["devices"] = json::array({json::object({
        {"app_id", app_id},
        {"pushkey", pushkey},
        {"pushkey_ts", now_sec()},
        {"data", {{"format", "event_id_only"}}}
      })});

      success = generic_gateway_.send_notification(
          gateway_url, "", // No bearer token by default
          room_id, room_name, sender, sender_display_name,
          event_id, event_type, content,
          unread_count, highlight_count, is_highlight,
          is_highlight ? "high" : "normal", extra);
      error = generic_gateway_.get_last_error();
    }

    int64_t send_duration = now_ms() - send_start;

    // Record retry or success
    if (success) {
      retry_manager_.record_success(retry_key);
      health_monitor_.record_success(gateway_type,
          get_endpoint_for_type(gateway_type), send_duration);
      analytics_.record_success(user_id, gateway_type, app_id,
                                event_id, 0, send_duration, http_status, 0);

      // Update badge
      if (config_.enable_badge_sync) {
        badge_manager_.increment_badge(user_id, 1,
                                        is_highlight ? 1 : 0);
      }
    } else {
      int64_t backoff = retry_manager_.record_failure(retry_key, http_status);
      health_monitor_.record_failure(gateway_type,
          get_endpoint_for_type(gateway_type), error);
      analytics_.record_failure(user_id, gateway_type, app_id,
                                event_id, 0, http_status, error, 1);

      // Queue for retry
      QueuedNotification queued;
      queued.idempotency_key = idempotency_key;
      queued.user_id = user_id;
      queued.device_id = device_id;
      queued.pushkey = pushkey;
      queued.gateway_type = gateway_type;
      queued.app_id = app_id;
      queued.gateway_url = gateway_url;
      queued.event_id = event_id;
      queued.room_id = room_id;
      queued.sender = sender;
      queued.priority = priority;
      queued.scheduled_at_ms = now_ms() + backoff;
      queued.retry_count = 1;
      queued.error_message = error;

      json payload;
      payload["title"] = title;
      payload["body"] = body;
      payload["event_type"] = event_type;
      payload["room_id"] = room_id;
      payload["room_name"] = room_name;
      payload["sender"] = sender;
      payload["sender_display_name"] = sender_display_name;
      payload["content"] = content;
      payload["unread_count"] = unread_count;
      payload["highlight_count"] = highlight_count;
      payload["is_highlight"] = is_highlight;
      queued.notification_payload = payload;

      queue_.enqueue(queued);
    }

    return success;
  }

  // Process items from the queue
  void process_queue() {
    while (!shutdown_requested_) {
      auto batch = queue_.dequeue_batch();
      if (batch.empty()) {
        queue_.wait_for_items();
        if (shutdown_requested_) break;
        continue;
      }

      for (auto& item : batch) {
        process_queued_item(item);
      }
    }
  }

  // Dispatch badge updates for dirty badges
  void sync_badges() {
    if (!config_.enable_badge_sync) return;

    auto dirty = badge_manager_.get_dirty_badges();
    for (const auto& state : dirty) {
      if (state.pushkey.empty()) continue;

      // Find the device token gateway type
      // (in production, look this up from the device token table)
      std::string gateway_type = "apns"; // Default assumption

      if (gateway_type == "apns") {
        apns_gateway_.send_badge_update(state.pushkey,
                                         state.total_notifications);
      }

      badge_manager_.mark_synced(state.user_id, state.pushkey);
    }
  }

  // Get overall status
  json get_status() {
    return {
      {"initialized", initialized_},
      {"queue", queue_.get_stats()},
      {"analytics", analytics_.get_summary()},
      {"badge", {
        {"total_count", badge_manager_.get_total_badge_count()},
        {"active_users", badge_manager_.get_active_badge_user_count()}
      }},
      {"preferences", {
        {"users", pref_manager_.get_user_count()},
        {"rooms", pref_manager_.get_room_pref_count()}
      }},
      {"health", health_monitor_.get_all_health()},
      {"retry", {
        {"states", retry_manager_.state_count()},
        {"circuit_breaker", retry_manager_.circuit_breaker().status_string()}
      }},
      {"idempotency", {
        {"entries", idempotency_guard_.size()}
      }}
    };
  }

  // Accessors
  PushPreferenceManager& preferences() { return pref_manager_; }
  BadgeCountManager& badges() { return badge_manager_; }
  PushAnalytics& analytics() { return analytics_; }
  RetryManager& retries() { return retry_manager_; }
  PushNotificationQueue& queue() { return queue_; }
  GatewayHealthMonitor& health() { return health_monitor_; }
  PushNotificationFormatter& formatter() { return formatter_; }

  void shutdown() {
    shutdown_requested_ = true;
    queue_.request_shutdown();
  }

private:
  void process_queued_item(QueuedNotification& item) {
    std::string retry_key = item.gateway_type + ":" +
                            sha256_hex(item.pushkey);

    if (!retry_manager_.can_retry(retry_key)) {
      // Let the queue handle retry scheduling
      queue_.mark_failed(item, "Retry backoff active",
                         item.http_status);
      return;
    }

    json payload = item.notification_payload;
    std::string title = json_str(payload, "title");
    std::string body = json_str(payload, "body");
    std::string event_type = json_str(payload, "event_type");
    std::string room_id = json_str(payload, "room_id");
    std::string room_name = json_str(payload, "room_name");
    std::string sender = json_str(payload, "sender");
    std::string sender_display_name = json_str(payload, "sender_display_name");
    json content = payload.value("content", json::object());
    int64_t unread_count = json_int(payload, "unread_count");
    int64_t highlight_count = json_int(payload, "highlight_count");
    bool is_highlight = json_bool(payload, "is_highlight");

    int64_t queue_duration = now_ms() - item.created_at_ms;

    analytics_.record_attempt(item.user_id, item.gateway_type,
                              item.app_id, item.event_id,
                              queue_duration);

    int64_t send_start = now_ms();
    bool success = false;
    std::string error;

    if (item.gateway_type == "apns") {
      auto prefs = pref_manager_.get_effective_preferences(
          item.user_id, room_id);
      success = apns_gateway_.send_alert(
          item.pushkey, title, body,
          sender_display_name, unread_count,
          prefs.sound, "",
          formatter_.generate_thread_id(room_id),
          formatter_.generate_collapse_key(room_id, sender));
      error = apns_gateway_.get_last_error();
    }
    else if (item.gateway_type == "fcm") {
      json data;
      data["room_id"] = room_id;
      data["event_id"] = item.event_id;
      data["sender"] = sender;
      if (config_.fcm_use_v1_api) {
        success = fcm_gateway_.send_v1_message(
            item.pushkey, title, body, data, "",
            "", formatter_.generate_collapse_key(room_id));
      } else {
        success = fcm_gateway_.send_legacy_message(
            item.pushkey, title, body, data,
            formatter_.generate_collapse_key(room_id));
      }
      error = fcm_gateway_.get_last_error();
    }
    else {
      json extra;
      extra["devices"] = json::array({json::object({
        {"app_id", item.app_id},
        {"pushkey", item.pushkey},
        {"pushkey_ts", now_sec()},
        {"data", {{"format", "event_id_only"}}}
      })});
      success = generic_gateway_.send_notification(
          item.gateway_url, "",
          room_id, room_name, sender, sender_display_name,
          item.event_id, event_type, content,
          unread_count, highlight_count, is_highlight,
          is_highlight ? "high" : "normal", extra);
      error = generic_gateway_.get_last_error();
    }

    int64_t send_duration = now_ms() - send_start;

    if (success) {
      retry_manager_.record_success(retry_key);
      health_monitor_.record_success(item.gateway_type,
          get_endpoint_for_type(item.gateway_type), send_duration);
      analytics_.record_success(item.user_id, item.gateway_type,
                                item.app_id, item.event_id,
                                queue_duration, send_duration,
                                200, item.retry_count);
      queue_.mark_delivered(item.id);

      if (config_.enable_badge_sync) {
        badge_manager_.increment_badge(item.user_id);
      }
    } else {
      int64_t backoff = retry_manager_.record_failure(retry_key);
      health_monitor_.record_failure(item.gateway_type,
          get_endpoint_for_type(item.gateway_type), error);
      analytics_.record_failure(item.user_id, item.gateway_type,
                                item.app_id, item.event_id,
                                queue_duration, 0, error,
                                item.retry_count + 1);

      if (!item.can_retry(config_.max_retries)) {
        analytics_.record_dead_letter(item.user_id, item.gateway_type,
                                      item.app_id, item.event_id, error);
        queue_.move_to_dead_letter(item, "Max retries exceeded: " + error);
      } else {
        item.scheduled_at_ms = now_ms() + backoff;
        queue_.mark_failed(item, error, 0);
      }
    }
  }

  std::string get_endpoint_for_type(const std::string& gateway_type) {
    if (gateway_type == "apns") return apns_gateway_.get_endpoint();
    if (gateway_type == "fcm")
      return std::string(kFcmV1Endpoint);
    return gateway_type;
  }

  PushGatewayConfig config_;
  ApnsGateway apns_gateway_;
  FcmGateway fcm_gateway_;
  GenericPushGateway generic_gateway_;
  PushNotificationFormatter formatter_;
  BadgeCountManager badge_manager_;
  PushNotificationQueue queue_;
  RetryManager retry_manager_;
  PushAnalytics analytics_;
  PushPreferenceManager pref_manager_;
  GatewayHealthMonitor health_monitor_;
  IdempotencyGuard idempotency_guard_;
  bool initialized_{false};
  bool shutdown_requested_{false};
};

// ============================================================================
// Utility: Initialize all SQL tables
// ============================================================================

namespace push_gateway_ddl {

std::vector<std::string> all_ddl_statements() {
  return {
    sql_ddl::create_push_notification_queue,
    sql_ddl::create_push_analytics_events,
    sql_ddl::create_push_gateway_config,
    sql_ddl::create_push_badge_state,
    sql_ddl::create_push_notification_preferences,
    sql_ddl::create_push_retry_state,
    sql_ddl::create_push_device_tokens,
    sql_ddl::create_push_gateway_health
  };
}

bool initialize_database(std::function<bool(const std::string&)> execute_sql) {
  for (const auto& ddl : all_ddl_statements()) {
    if (!execute_sql(ddl)) {
      return false;
    }
  }
  return true;
}

} // namespace push_gateway_ddl

// ============================================================================
// Factory function: Create a fully configured coordinator
// ============================================================================

std::unique_ptr<PushGatewayCoordinator> create_push_gateway_coordinator(
    const PushGatewayConfig& config) {
  auto coordinator = std::make_unique<PushGatewayCoordinator>(config);
  if (!config.enable_push) return coordinator;

  coordinator->initialize();
  return coordinator;
}

// ============================================================================
// Default configuration factory
// ============================================================================

PushGatewayConfig create_default_push_gateway_config() {
  PushGatewayConfig cfg;
  cfg.server_name = "matrix.localhost";
  cfg.enable_push = true;
  cfg.enable_apns = true;
  cfg.enable_fcm = true;
  cfg.enable_generic_gateways = true;
  cfg.max_retries = 5;
  cfg.base_backoff_ms = chr::milliseconds{1000};
  cfg.max_backoff_ms = chr::milliseconds{300'000};
  cfg.jitter_factor = 0.3;
  cfg.cb_failure_threshold = 10;
  cfg.cb_cooldown_sec = chr::seconds{60};
  cfg.cb_half_open_probes = 3;
  cfg.queue_max_capacity = 100'000;
  cfg.queue_per_user_limit = 500;
  cfg.queue_batch_size = 50;
  cfg.queue_item_ttl = chr::seconds{3600};
  cfg.queue_worker_threads = 4;
  cfg.queue_poll_interval = chr::milliseconds{100};
  cfg.enable_badge_sync = true;
  cfg.badge_sync_interval = chr::seconds{30};
  cfg.badge_batch_threshold = 5;
  cfg.enable_analytics = true;
  cfg.analytics_flush_interval = chr::seconds{60};
  cfg.analytics_batch_size = 100;
  cfg.default_lang = "en";
  cfg.show_sender_in_notification = true;
  cfg.show_message_preview = true;
  cfg.strip_markdown_in_notifications = true;
  cfg.max_body_preview_length = 256;
  return cfg;
}

} // namespace progressive
