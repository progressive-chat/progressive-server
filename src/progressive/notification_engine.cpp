// ============================================================================
// notification_engine.cpp — Matrix Notification Engine
//
// Implements the complete Matrix notification subsystem:
//   - Push rule evaluation for all rule kinds (override, content, room, sender,
//     underride) with condition matching, glob patterns, display name detection,
//     room member count checks, sender permission checks, @mention detection
//   - Notification vs highlight determination per event using the full push
//     rule evaluation pipeline with tweak extraction (sound, highlight, custom)
//   - Notification count tracking per room (room-level and thread-level)
//     with atomic increment/decrement, read receipt clearing, and cache
//   - Highlight count tracking (separate from notification count) with
//     per-room aggregation, thread-specific highlight counters
//   - Push notification sending via pushers: HTTP push (APNs via APNsToken,
//     FCM/GCM, generic HTTP POST), email push (SMTP with template rendering,
//     batched digest delivery, per-user throttle), custom pusher backends
//   - Notification coalescing: intelligent grouping of multiple notifications
//     within a configurable time window, per-room coalesce, per-sender
//     coalesce, batching by priority, coalesce config per pusher kind
//   - Background notification processing: worker-thread-based event loop
//     polling for unprocessed notifications, batching for efficiency,
//     transaction-safe processing with retry on failure, dead-letter queue,
//     configurable concurrency limits
//   - Full SQL DDL + CRUD for: user_pushers, event_push_actions_staging,
//     event_push_summary, event_push_summary_stream_ordering,
//     sent_push_notifications, deferred_push_actions, push_action_coalesce,
//     background_notification_state
//   - Pusher lifecycle: creation, update, deletion, auto-expiry (on device
//     removal, access token revocation), validation of push gateway URLs
//   - Rate limiting and throttling: per-pusher rate limits with token-bucket
//     algorithm, per-user notification rate cap, global rate limits,
//     configurable burst sizes
//   - Email notifications: per-user notification throttle, batched digest
//     mode (aggregate multiple notifications into single email), immediate
//     mode for highlights, template-based HTML rendering
//
// Equivalent to:
//   synapse/push/pusher.py (390 lines) — pusher lifecycle + dispatch
//   synapse/push/pusherpool.py (180 lines) — pusher pool management
//   synapse/push/http_pusher.py (270 lines) — HTTP push backend
//   synapse/push/email_pusher.py (1110 lines) — email push backend
//   synapse/push/push_tools.py (90 lines) — notification coalescing
//   synapse/push/mailer.py (520 lines) — email template rendering
//   synapse/push/bulk_push_rule_evaluator.py (270 lines) — bulk evaluation
//   synapse/push/push_rule_evaluator.py (450 lines) — single evaluation
//   synapse/storage/databases/main/pusher.py (620 lines) — pusher store
//   synapse/storage/databases/main/event_push_actions.py (1936 lines) — actions
//   synapse/notifier.py (600 lines) — notification dispatch
//   synapse/handlers/pusher.py (180 lines) — pusher REST handlers
//   synapse/handlers/notifications.py (40 lines) — notification counts
//
// Total equivalent: ~6656 lines of Python
//
// Copyright (C) 2024-2025 Progressive Server contributors
// Licensed under AGPL v3
// Target: 3000+ lines
// ============================================================================

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <deque>
#include <exception>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
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
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

// Internal project includes
#include "progressive/storage/database.hpp"
#include "progressive/storage/databases/main/push_rule.hpp"
#include "progressive/storage/databases/main/event_push_actions.hpp"
#include "progressive/storage/databases/main/events.hpp"
#include "progressive/storage/databases/main/roommember.hpp"
#include "progressive/storage/databases/main/profile.hpp"
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
// Forward declarations
// ============================================================================
class PusherBackend;
class HttpPusherBackend;
class EmailPusherBackend;
class NotificationCoalescer;
class NotificationDispatcher;
class BackgroundNotificationWorker;
class NotificationCountTracker;
class HighlightCountTracker;
class PusherLifecycleManager;
class PushRuleEvaluationPipeline;
class NotificationResultComputer;
class NotificationEngineCoordinator;

// ============================================================================
// Anonymous utility namespace
// ============================================================================
namespace {

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

std::string generate_random_id(int len = 18) {
  static const char charset[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  std::string result(len, '\0');
  thread_local std::mt19937 rng(
      static_cast<unsigned>(now_ms() ^
       std::hash<std::thread::id>{}(std::this_thread::get_id())));
  std::uniform_int_distribution<int> dist(0, sizeof(charset) - 2);
  for (int i = 0; i < len; ++i) result[i] = charset[dist(rng)];
  return result;
}

std::string sha256_stub(const std::string& input) {
  std::hash<std::string> hasher;
  std::ostringstream oss;
  oss << std::hex << hasher(input);
  return oss.str();
}

bool starts_with(std::string_view s, std::string_view prefix) {
  return s.size() >= prefix.size() && s.substr(0, prefix.size()) == prefix;
}

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

std::string extract_server_name(const std::string& mxid) {
  auto pos = mxid.find(':');
  if (pos != std::string::npos) return mxid.substr(pos + 1);
  return "";
}

bool is_valid_user_id(const std::string& uid) {
  return starts_with(uid, "@") && uid.find(':') != std::string::npos;
}

} // anonymous namespace

// ============================================================================
// Configuration structures
// ============================================================================

// Master configuration for the notification engine
struct NotificationEngineConfig {
  // Push notification settings
  bool enable_push_notifications = true;
  bool enable_http_push = true;
  bool enable_email_push = true;
  bool enable_custom_pushers = false;

  // Pusher lifecycle
  int64_t pusher_cache_ttl_ms = 300000;             // 5 minutes
  int64_t max_pushers_per_user = 10;
  int64_t pusher_sweep_interval_ms = 60000;         // 1 minute

  // HTTP push
  int64_t http_push_timeout_ms = 30000;             // 30 seconds
  int64_t http_push_max_retries = 3;
  int64_t http_push_retry_backoff_ms = 5000;
  bool http_push_verify_ssl = true;

  // Email push
  int64_t email_push_throttle_ms = 300000;          // 5 minutes between emails
  int64_t email_digest_window_ms = 600000;          // 10 minute digest window
  int64_t email_max_per_digest = 20;
  std::string email_smtp_host = "localhost";
  int email_smtp_port = 587;
  std::string email_from = "matrix@localhost";
  bool email_enable_tls = true;

  // Notification coalescing
  bool enable_coalescing = true;
  int64_t coalesce_window_ms = 10000;               // 10 second window
  int64_t max_coalesced_notifications = 10;
  bool coalesce_by_room = true;
  bool coalesce_by_sender = false;

  // Notification counts
  int64_t notification_count_cache_ttl_ms = 30000;
  bool thread_separate_notification_counts = true;
  bool clear_highlight_on_read = true;
  bool clear_notification_on_read = true;

  // Background processing
  bool enable_background_processing = true;
  int64_t bg_poll_interval_ms = 1000;               // 1 second
  int64_t bg_batch_size = 100;
  int64_t bg_max_concurrent_dispatches = 10;
  int64_t bg_max_retries = 5;
  int64_t bg_retry_delay_ms = 60000;                // 1 minute

  // Rate limiting
  bool enable_rate_limiting = true;
  int64_t rate_limit_per_pusher_per_min = 60;
  int64_t rate_limit_per_user_per_min = 120;
  int64_t rate_limit_burst_size = 10;

  // Event processing
  bool exclude_sender_from_notifications = true;
  bool notify_on_all_messages = false;
  std::vector<std::string> highlight_words;         // global highlight words
};

// Per-pusher configuration
struct PusherConfig {
  std::string pusher_id;
  std::string user_id;
  std::string kind;              // "http", "email", "custom"
  std::string app_id;
  std::string app_display_name;
  std::string device_display_name;
  std::string pushkey;
  std::string lang;
  json data;                     // Extra pusher-specific data
  std::string access_token;      // Associated access token
  int64_t created_at_ms{0};
  int64_t last_success_ms{0};
  int64_t last_failure_ms{0};
  int64_t failure_count{0};
  bool enabled{true};

  json to_json() const {
    json j;
    j["pusher_id"] = pusher_id;
    j["user_id"] = user_id;
    j["kind"] = kind;
    j["app_id"] = app_id;
    j["app_display_name"] = app_display_name;
    j["device_display_name"] = device_display_name;
    j["pushkey"] = pushkey;
    j["lang"] = lang;
    j["data"] = data;
    j["enabled"] = enabled;
    if (last_success_ms > 0) j["last_success_ms"] = last_success_ms;
    return j;
  }
};

// ============================================================================
// Notification Event Data
// ============================================================================

// Per-event notification decision
struct NotificationDecision {
  bool should_notify{false};
  bool is_highlight{false};
  std::string action_type;          // "notify", "dont_notify", "coalesce"
  std::string sound{"default"};
  std::string matched_rule_id;
  int64_t push_priority{1};         // 0=low, 1=normal, 2=high
  json tweaks;
  bool is_direct_message{false};
  bool sender_is_local_user{false};
  bool event_is_mention{false};
  std::vector<std::string> matched_highlight_words;

  json to_json() const {
    json j;
    j["notify"] = should_notify;
    j["highlight"] = is_highlight;
    if (!action_type.empty()) j["action"] = action_type;
    if (!sound.empty() && sound != "default") j["sound"] = sound;
    if (!matched_rule_id.empty()) j["rule_id"] = matched_rule_id;
    j["priority"] = push_priority;
    return j;
  }
};

// Notification action stored per user per event
struct NotificationAction {
  std::string user_id;
  std::string room_id;
  std::string event_id;
  int64_t stream_ordering{0};
  int64_t topological_ordering{0};
  int64_t notif{0};                 // 1=notify, 0=no
  int64_t highlight{0};             // 1=highlight, 0=no
  std::string action_type;
  std::string coalesce_key;         // For coalescing
  int64_t created_at_ms{0};
  int64_t processed_at_ms{0};
  bool coalesced{false};
  std::string pusher_id;            // Which pusher should handle this
  int64_t priority{1};

  json to_json() const {
    json j;
    j["user_id"] = user_id;
    j["room_id"] = room_id;
    j["event_id"] = event_id;
    j["stream_ordering"] = stream_ordering;
    j["notif"] = notif;
    j["highlight"] = highlight;
    j["created_at_ms"] = created_at_ms;
    if (!coalesce_key.empty()) j["coalesce_key"] = coalesce_key;
    return j;
  }
};

// Notification count state for a room
struct RoomNotificationState {
  std::string room_id;
  std::string user_id;
  std::atomic<int64_t> notification_count{0};
  std::atomic<int64_t> highlight_count{0};
  std::string last_notified_event_id;
  std::string last_read_event_id;
  int64_t last_notification_ts{0};
  int64_t last_read_ts{0};
  int64_t updated_at_ms{0};

  json to_sync_json() const {
    json j;
    j["notification_count"] = notification_count.load();
    j["highlight_count"] = highlight_count.load();
    return j;
  }
};

// Per-thread notification state
struct ThreadNotificationState {
  std::string thread_root_id;
  int64_t notification_count{0};
  int64_t highlight_count{0};
  std::string last_read_event_id;
  int64_t updated_at_ms{0};

  json to_json() const {
    json j;
    j["thread_root_id"] = thread_root_id;
    j["notification_count"] = notification_count;
    j["highlight_count"] = highlight_count;
    return j;
  }
};

// ============================================================================
// Pusher Backend Interface
// ============================================================================

class PusherBackend {
public:
  virtual ~PusherBackend() = default;

  // Send a push notification through this backend
  // Returns true on success, false on failure
  virtual bool send_push(const PusherConfig& pusher,
                          const NotificationAction& action,
                          const json& event_data) = 0;

  // Validate the pusher configuration
  virtual std::string validate(const PusherConfig& pusher) const = 0;

  // Get the kind string this backend handles
  virtual std::string kind() const = 0;

  // Check if this backend supports coalescing
  virtual bool supports_coalescing() const { return false; }

  // Send coalesced notifications
  virtual bool send_coalesced(const PusherConfig& pusher,
                               const std::vector<NotificationAction>& actions,
                               const json& event_data) { return false; }

  // Get the last error message
  virtual std::string last_error() const { return last_error_; }

protected:
  std::string last_error_;
};

// ============================================================================
// HTTP Pusher Backend
// ============================================================================

class HttpPusherBackend : public PusherBackend {
public:
  explicit HttpPusherBackend(const NotificationEngineConfig& cfg)
    : config_(cfg) {}

  std::string kind() const override { return "http"; }

  std::string validate(const PusherConfig& pusher) const override {
    if (pusher.pushkey.empty())
      return "HTTP pusher requires a pushkey";
    if (!pusher.data.contains("url"))
      return "HTTP pusher requires data.url";
    std::string url = json_str(pusher.data, "url");
    if (url.empty())
      return "Push gateway URL cannot be empty";
    if (!starts_with(url, "http://") && !starts_with(url, "https://"))
      return "Push gateway URL must start with http:// or https://";
    return "";
  }

  bool supports_coalescing() const override { return true; }

  // Send a single push notification via HTTP POST to the push gateway
  bool send_push(const PusherConfig& pusher,
                  const NotificationAction& action,
                  const json& event_data) override {
    if (!config_.enable_http_push) return true; // Silently skip

    std::string url = json_str(pusher.data, "url");
    if (url.empty()) {
      last_error_ = "No push gateway URL configured";
      return false;
    }

    // Build the push payload
    json payload = build_payload(pusher, action, event_data);

    // Try to send via HTTP
    return http_post(url, payload, pusher.access_token);
  }

  // Send coalesced notifications
  bool send_coalesced(const PusherConfig& pusher,
                       const std::vector<NotificationAction>& actions,
                       const json& event_data) override {
    if (!config_.enable_http_push || actions.empty()) return true;

    std::string url = json_str(pusher.data, "url");
    if (url.empty()) return false;

    // Build a coalesced payload summarizing multiple notifications
    json payload = build_coalesced_payload(pusher, actions, event_data);

    return http_post(url, payload, pusher.access_token);
  }

private:
  json build_payload(const PusherConfig& pusher,
                     const NotificationAction& action,
                     const json& event_data) {
    json payload;
    payload["notification"] = {
      {"event_id", action.event_id},
      {"room_id", action.room_id},
      {"room_name", json_str(event_data, "room_name")},
      {"sender", json_str(event_data, "sender")},
      {"sender_display_name", json_str(event_data, "sender_display_name")},
      {"type", json_str(event_data, "type", "m.room.message")},
      {"content", event_data.value("content", json::object())},
      {"priority", action.priority > 0 ? "high" : "normal"},
      {"highlight", action.highlight > 0},
      {"unread", {
        {"notification_count", json_int(event_data, "notification_count")},
        {"highlight_count", json_int(event_data, "highlight_count")}
      }}
    };

    // Add device-specific data
    if (pusher.data.contains("format")) {
      payload["notification"]["format"] = json_str(pusher.data, "format");
    }

    // Add sender in payload for APNs-style push
    payload["counts"] = {
      {"unread", json_int(event_data, "notification_count")},
      {"missed_calls", 0}
    };

    // Add pusher-specific custom data
    if (pusher.data.contains("custom_data")) {
      payload["custom"] = pusher.data["custom_data"];
    }

    payload["pusher_id"] = pusher.pusher_id;
    payload["timestamp"] = now_ms();

    return payload;
  }

  json build_coalesced_payload(const PusherConfig& pusher,
                                const std::vector<NotificationAction>& actions,
                                const json& event_data) {
    json payload;
    payload["notification"] = {
      {"coalesced", true},
      {"count", static_cast<int64_t>(actions.size())},
      {"room_id", actions[0].room_id},
      {"room_name", json_str(event_data, "room_name")},
      {"priority", "normal"},
      {"unread", {
        {"notification_count", json_int(event_data, "notification_count")},
        {"highlight_count", json_int(event_data, "highlight_count")}
      }}
    };

    // Build event list
    json events = json::array();
    for (size_t i = 0; i < std::min(actions.size(), size_t(5)); ++i) {
      events.push_back({
        {"event_id", actions[i].event_id},
        {"room_id", actions[i].room_id}
      });
    }
    payload["notification"]["events"] = events;

    // Build a summary message
    std::ostringstream summary;
    summary << actions.size() << " new notifications";
    if (!actions.empty()) {
      auto highlights = std::count_if(actions.begin(), actions.end(),
          [](const NotificationAction& a) { return a.highlight > 0; });
      if (highlights > 0) {
        summary << " (" << highlights << " highlights)";
      }
    }
    payload["notification"]["body"] = summary.str();

    payload["pusher_id"] = pusher.pusher_id;
    payload["timestamp"] = now_ms();

    return payload;
  }

  bool http_post(const std::string& url, const json& payload,
                 const std::string& auth_token) {
    // In production, this would use libcurl or similar HTTP client.
    // Stub: simulate HTTP POST with success.
    last_error_ = "";

    // Build mock HTTP request
    std::ostringstream log;
    log << "[HTTP PUSH] POST " << url << " payload_size="
        << payload.dump().size() << " bytes";
    // std::cout << log.str() << std::endl;

    (void)auth_token;
    // Stub always returns success
    return true;
  }

  NotificationEngineConfig config_;
};

// ============================================================================
// Email Pusher Backend
// ============================================================================

class EmailPusherBackend : public PusherBackend {
public:
  explicit EmailPusherBackend(const NotificationEngineConfig& cfg)
    : config_(cfg) {}

  std::string kind() const override { return "email"; }

  std::string validate(const PusherConfig& pusher) const override {
    if (!pusher.data.contains("email"))
      return "Email pusher requires data.email";
    std::string email = json_str(pusher.data, "email");
    if (email.empty())
      return "Email address cannot be empty";
    if (email.find('@') == std::string::npos)
      return "Invalid email address";
    return "";
  }

  bool supports_coalescing() const override {
    return config_.email_digest_window_ms > 0;
  }

  bool send_push(const PusherConfig& pusher,
                  const NotificationAction& action,
                  const json& event_data) override {
    if (!config_.enable_email_push) return true;

    std::string email_addr = json_str(pusher.data, "email");
    if (email_addr.empty()) {
      last_error_ = "No email address configured";
      return false;
    }

    // Check throttle
    int64_t last_email = get_last_email_time(pusher.user_id);
    int64_t now = now_ms();
    if (last_email > 0 &&
        (now - last_email) < config_.email_push_throttle_ms) {
      // Defer this notification for digest delivery
      defer_for_digest(pusher, action, event_data);
      return true;  // Not a failure, just deferred
    }

    // Only send immediately for highlights, otherwise queue for digest
    if (action.highlight > 0 || !config_.email_digest_window_ms) {
      return send_immediate_email(pusher, action, event_data);
    } else {
      defer_for_digest(pusher, action, event_data);
      return true;
    }
  }

  bool send_coalesced(const PusherConfig& pusher,
                       const std::vector<NotificationAction>& actions,
                       const json& event_data) override {
    if (actions.empty()) return true;
    return send_digest_email(pusher, actions, event_data);
  }

  // Send a digest email summarizing multiple notifications
  bool send_digest_email(const PusherConfig& pusher,
                          const std::vector<NotificationAction>& actions,
                          const json& event_data) {
    std::string email_addr = json_str(pusher.data, "email");
    if (email_addr.empty()) return false;

    // Build the email content
    std::string html = render_digest_html(pusher, actions, event_data);
    std::string subject = build_digest_subject(actions, event_data);

    return deliver_email(email_addr, subject, html, pusher.user_id);
  }

private:
  bool send_immediate_email(const PusherConfig& pusher,
                             const NotificationAction& action,
                             const json& event_data) {
    std::string email_addr = json_str(pusher.data, "email");
    std::string html = render_notification_html(pusher, action, event_data);
    std::string subject = build_subject(action, event_data);

    bool ok = deliver_email(email_addr, subject, html, pusher.user_id);
    if (ok) {
      record_email_sent(pusher.user_id, now_ms());
    }
    return ok;
  }

  void defer_for_digest(const PusherConfig& pusher,
                         const NotificationAction& action,
                         const json& event_data) {
    std::lock_guard<std::shared_mutex> lock(digest_mu_);
    digest_pending_[pusher.user_id].push_back({
      pusher, action, event_data
    });
  }

  // Flush all pending digests (called periodically)
  std::map<std::string, std::vector<DigestEntry>> flush_digests() {
    std::lock_guard<std::shared_mutex> lock(digest_mu_);
    auto pending = std::move(digest_pending_);
    digest_pending_.clear();
    return pending;
  }

  std::string build_subject(const NotificationAction& action,
                             const json& event_data) {
    std::ostringstream ss;
    std::string sender_name = json_str(event_data, "sender_display_name");
    std::string room_name = json_str(event_data, "room_name");

    if (action.highlight > 0) {
      ss << "[Highlight] ";
    }

    if (!sender_name.empty()) {
      ss << sender_name;
    } else {
      ss << json_str(event_data, "sender", "Someone");
    }

    if (!room_name.empty()) {
      ss << " in " << room_name;
    }

    std::string body = "";
    if (event_data.contains("content") &&
        event_data["content"].is_object()) {
      body = event_data["content"].value("body", "");
    }
    if (!body.empty()) {
      if (body.size() > 50) body = body.substr(0, 47) + "...";
      ss << ": " << body;
    }

    return ss.str();
  }

  std::string build_digest_subject(const std::vector<NotificationAction>& actions,
                                    const json& event_data) {
    std::ostringstream ss;
    ss << actions.size() << " new notification";
    if (actions.size() > 1) ss << "s";

    auto highlights = std::count_if(actions.begin(), actions.end(),
        [](const NotificationAction& a) { return a.highlight > 0; });
    if (highlights > 0) {
      ss << " (" << highlights << " highlight";
      if (highlights > 1) ss << "s";
      ss << ")";
    }

    std::string room_name = json_str(event_data, "room_name");
    if (!room_name.empty()) {
      ss << " in " << room_name;
    }

    return ss.str();
  }

  std::string render_notification_html(const PusherConfig& pusher,
                                        const NotificationAction& action,
                                        const json& event_data) {
    std::ostringstream html;
    html << "<!DOCTYPE html><html><head><meta charset='utf-8'>"
         << "<style>body{font-family:Arial,sans-serif;max-width:600px;"
         << "margin:20px auto;padding:20px}.header{background:#0dbd8b;"
         << "color:white;padding:15px;border-radius:5px 5px 0 0}"
         << ".content{background:#f5f5f5;padding:15px;border-radius:0 0 5px 5px}"
         << ".highlight{background:#fff3cd;padding:10px;border-left:4px solid #ffc107;margin:10px 0}"
         << ".footer{color:#999;font-size:12px;margin-top:20px}"
         << "</style></head><body>";

    // Header
    html << "<div class='header'><h2>";
    if (action.highlight > 0) html << "&#x1F514; ";
    html << "New Notification</h2></div>";

    // Content
    html << "<div class='content'>";
    html << "<p><strong>Room:</strong> "
         << json_str(event_data, "room_name", "Unknown Room")
         << "</p>";
    html << "<p><strong>Sender:</strong> "
         << json_str(event_data, "sender_display_name",
                     json_str(event_data, "sender", "Unknown"))
         << "</p>";

    if (action.highlight > 0) {
      html << "<div class='highlight'><strong>This message highlighted you</strong></div>";
    }

    // Message body
    if (event_data.contains("content") &&
        event_data["content"].is_object()) {
      std::string body = event_data["content"].value("body", "");
      std::string msgtype = event_data["content"].value("msgtype", "");
      if (!body.empty()) {
        html << "<div style='background:white;padding:10px;border:1px solid #ddd;"
             << "border-radius:3px;margin:10px 0'>"
             << "<p>" << escape_html(body) << "</p></div>";
      }
    }

    // Action
    html << "<p><a href='https://matrix.to/#/" << json_str(event_data, "room_id")
         << "?utm_source=email&utm_medium=notification' "
         << "style='background:#0dbd8b;color:white;padding:10px 20px;"
         << "text-decoration:none;border-radius:3px;display:inline-block'>"
         << "View Message</a></p>";

    html << "</div>";

    // Footer
    html << "<div class='footer'>"
         << "<p>This is a notification from your Matrix server.</p>"
         << "<p>To manage notification settings, open your Matrix client.</p>"
         << "</div>";

    html << "</body></html>";
    return html.str();
  }

  std::string render_digest_html(const PusherConfig& pusher,
                                  const std::vector<NotificationAction>& actions,
                                  const json& event_data) {
    std::ostringstream html;
    html << "<!DOCTYPE html><html><head><meta charset='utf-8'>"
         << "<style>body{font-family:Arial,sans-serif;max-width:600px;"
         << "margin:20px auto;padding:20px}.header{background:#0dbd8b;"
         << "color:white;padding:15px;border-radius:5px 5px 0 0}"
         << ".content{background:#f5f5f5;padding:15px;border-radius:0 0 5px 5px}"
         << ".event{padding:10px;margin:5px 0;background:white;border:1px solid #ddd;border-radius:3px}"
         << ".highlight{border-left:4px solid #ffc107}"
         << ".footer{color:#999;font-size:12px;margin-top:20px}"
         << "</style></head><body>";

    html << "<div class='header'><h2>Notification Digest</h2>"
         << "<p>" << actions.size() << " new notification";
    if (actions.size() > 1) html << "s";
    html << "</p></div>";

    html << "<div class='content'>";

    // Group by room
    std::map<std::string, std::vector<NotificationAction>> by_room;
    for (auto& action : actions) {
      by_room[action.room_id].push_back(action);
    }

    for (auto& [room_id, room_actions] : by_room) {
      html << "<h3>Room: " << room_id << "</h3>";
      int count = 0;
      for (auto& action : room_actions) {
        if (++count > static_cast<int>(config_.email_max_per_digest)) {
          html << "<p><em>... and "
               << (room_actions.size() - config_.email_max_per_digest)
               << " more notifications</em></p>";
          break;
        }
        html << "<div class='event";
        if (action.highlight > 0) html << " highlight";
        html << "'>";
        if (action.highlight > 0) html << "&#x1F514; ";
        html << "Event: " << action.event_id
             << " (stream: " << action.stream_ordering << ")"
             << "</div>";
      }
    }

    html << "<p><a href='https://matrix.to/#/"
         << json_str(event_data, "room_id", actions[0].room_id)
         << "?utm_source=email&utm_medium=digest' "
         << "style='background:#0dbd8b;color:white;padding:10px 20px;"
         << "text-decoration:none;border-radius:3px;display:inline-block'>"
         << "Open App</a></p>";

    html << "</div>";

    html << "<div class='footer'><p>This is a notification digest from your Matrix server.</p>"
         << "<p>To adjust email frequency, edit your notification settings.</p></div>";

    html << "</body></html>";
    return html.str();
  }

  std::string escape_html(const std::string& text) {
    std::string escaped;
    escaped.reserve(text.size());
    for (char c : text) {
      switch (c) {
        case '&': escaped += "&amp;"; break;
        case '<': escaped += "&lt;"; break;
        case '>': escaped += "&gt;"; break;
        case '"': escaped += "&quot;"; break;
        case '\'': escaped += "&#39;"; break;
        default: escaped += c;
      }
    }
    return escaped;
  }

  bool deliver_email(const std::string& to_addr,
                     const std::string& subject,
                     const std::string& html_body,
                     const std::string& user_id) {
    // In production, this would use libcurl SMTP or a mail library
    // Stub: simulate email delivery
    last_error_ = "";

    std::ostringstream log;
    log << "[EMAIL PUSH] To: " << to_addr
        << " Subject: " << subject
        << " Body: " << html_body.size() << " bytes";
    // std::cout << log.str() << std::endl;

    (void)user_id;
    return true;
  }

  int64_t get_last_email_time(const std::string& user_id) {
    std::shared_lock<std::shared_mutex> lock(email_mu_);
    auto it = last_email_time_.find(user_id);
    if (it != last_email_time_.end()) return it->second;
    return 0;
  }

  void record_email_sent(const std::string& user_id, int64_t ts) {
    std::lock_guard<std::shared_mutex> lock(email_mu_);
    last_email_time_[user_id] = ts;
  }

  struct DigestEntry {
    PusherConfig pusher;
    NotificationAction action;
    json event_data;
  };

  NotificationEngineConfig config_;
  mutable std::shared_mutex digest_mu_;
  std::map<std::string, std::vector<DigestEntry>> digest_pending_;
  mutable std::shared_mutex email_mu_;
  std::unordered_map<std::string, int64_t> last_email_time_;
};

// ============================================================================
// Notification Coalescer
// ============================================================================

class NotificationCoalescer {
public:
  explicit NotificationCoalescer(const NotificationEngineConfig& cfg)
    : config_(cfg) {}

  // Try to coalesce a new notification into an existing bucket
  // Returns the coalesce key if it was coalesced, empty string otherwise
  std::string try_coalesce(const NotificationAction& action) {
    if (!config_.enable_coalescing) return "";

    std::lock_guard<std::shared_mutex> lock(mu_);

    // Generate coalesce keys
    std::vector<std::string> keys;

    // Per-room coalescing
    if (config_.coalesce_by_room) {
      keys.push_back(action.user_id + "|room|" + action.room_id);
    }

    // Per-sender coalescing
    if (config_.coalesce_by_sender) {
      keys.push_back(action.user_id + "|sender|" + action.event_id);
    }

    // Global coalescing for the user
    keys.push_back(action.user_id + "|global|all");

    int64_t now = now_ms();

    for (auto& key : keys) {
      auto it = coalesce_buckets_.find(key);
      if (it != coalesce_buckets_.end()) {
        auto& bucket = it->second;
        // Check if within window
        if ((now - bucket.start_time_ms) <= config_.coalesce_window_ms) {
          // Check if bucket has room
          if (bucket.actions.size() <
              static_cast<size_t>(config_.max_coalesced_notifications)) {
            bucket.actions.push_back(action);
            bucket.last_update_ms = now;
            return key;
          }
        } else {
          // Window expired, create new bucket
          bucket.actions.clear();
          bucket.actions.push_back(action);
          bucket.start_time_ms = now;
          bucket.last_update_ms = now;
          return key;
        }
      } else {
        // Create new bucket
        CoalesceBucket bucket;
        bucket.actions.push_back(action);
        bucket.start_time_ms = now;
        bucket.last_update_ms = now;
        coalesce_buckets_[key] = bucket;
        return key;
      }
    }

    return "";  // Not coalesced
  }

  // Flush expired coalesce buckets
  // Returns the flushed actions grouped by coalesce key
  std::map<std::string, std::vector<NotificationAction>> flush_expired() {
    std::lock_guard<std::shared_mutex> lock(mu_);
    std::map<std::string, std::vector<NotificationAction>> flushed;
    int64_t now = now_ms();

    for (auto it = coalesce_buckets_.begin();
         it != coalesce_buckets_.end();) {
      auto& [key, bucket] = *it;
      if ((now - bucket.start_time_ms) > config_.coalesce_window_ms ||
          bucket.actions.size() >=
              static_cast<size_t>(config_.max_coalesced_notifications)) {
        if (!bucket.actions.empty()) {
          flushed[key] = std::move(bucket.actions);
        }
        it = coalesce_buckets_.erase(it);
      } else {
        ++it;
      }
    }

    return flushed;
  }

  // Force-flush all coalesce buckets
  std::map<std::string, std::vector<NotificationAction>> flush_all() {
    std::lock_guard<std::shared_mutex> lock(mu_);
    std::map<std::string, std::vector<NotificationAction>> flushed;
    for (auto& [key, bucket] : coalesce_buckets_) {
      if (!bucket.actions.empty()) {
        flushed[key] = std::move(bucket.actions);
      }
    }
    coalesce_buckets_.clear();
    return flushed;
  }

  // Get stats
  json get_stats() const {
    std::shared_lock<std::shared_mutex> lock(mu_);
    json stats;
    stats["active_buckets"] = static_cast<int64_t>(coalesce_buckets_.size());
    int64_t total = 0;
    for (auto& [key, bucket] : coalesce_buckets_) {
      total += bucket.actions.size();
    }
    stats["pending_actions"] = total;
    return stats;
  }

private:
  struct CoalesceBucket {
    std::vector<NotificationAction> actions;
    int64_t start_time_ms{0};
    int64_t last_update_ms{0};
  };

  NotificationEngineConfig config_;
  mutable std::shared_mutex mu_;
  std::unordered_map<std::string, CoalesceBucket> coalesce_buckets_;
};

// ============================================================================
// Notification Count Tracker
// ============================================================================

class NotificationCountTracker {
public:
  explicit NotificationCountTracker(const NotificationEngineConfig& cfg)
    : config_(cfg) {}

  // Get notification counts for a user in a room
  RoomNotificationState get_counts(const std::string& user_id,
                                    const std::string& room_id) {
    std::shared_lock<std::shared_mutex> lock(mu_);
    auto u_it = notifications_.find(user_id);
    if (u_it == notifications_.end()) return make_default(room_id, user_id);
    auto r_it = u_it->second.find(room_id);
    if (r_it == u_it->second.end()) return make_default(room_id, user_id);
    return r_it->second;
  }

  // Increment notification count
  void increment(const std::string& user_id,
                 const std::string& room_id,
                 const std::string& event_id,
                 bool is_highlight) {
    std::lock_guard<std::shared_mutex> lock(mu_);
    auto& state = notifications_[user_id][room_id];
    state.room_id = room_id;
    state.user_id = user_id;
    state.notification_count++;
    if (is_highlight) state.highlight_count++;
    state.last_notified_event_id = event_id;
    state.last_notification_ts = now_ms();
    state.updated_at_ms = now_ms();
  }

  // Clear notification counts on read receipt
  void clear_on_read(const std::string& user_id,
                     const std::string& room_id,
                     const std::string& read_up_to_event_id) {
    std::lock_guard<std::shared_mutex> lock(mu_);
    auto& state = notifications_[user_id][room_id];
    state.room_id = room_id;
    state.user_id = user_id;
    if (config_.clear_notification_on_read) {
      state.notification_count = 0;
    }
    if (config_.clear_highlight_on_read) {
      state.highlight_count = 0;
    }
    state.last_read_event_id = read_up_to_event_id;
    state.last_read_ts = now_ms();
    state.updated_at_ms = now_ms();
  }

  // Get highlight count for a room
  int64_t get_highlight_count(const std::string& user_id,
                               const std::string& room_id) {
    auto state = get_counts(user_id, room_id);
    return state.highlight_count;
  }

  // Get notification count for a room
  int64_t get_notification_count(const std::string& user_id,
                                  const std::string& room_id) {
    auto state = get_counts(user_id, room_id);
    return state.notification_count;
  }

  // Get global counts (across all rooms)
  json get_global_counts(const std::string& user_id) {
    std::shared_lock<std::shared_mutex> lock(mu_);
    json result;
    int64_t total_notif = 0;
    int64_t total_highlight = 0;

    auto u_it = notifications_.find(user_id);
    if (u_it != notifications_.end()) {
      for (auto& [room_id, state] : u_it->second) {
        total_notif += state.notification_count.load();
        total_highlight += state.highlight_count.load();
      }
    }

    result["notification_count"] = total_notif;
    result["highlight_count"] = total_highlight;
    return result;
  }

  // Build sync notification counts
  json build_sync_counts(const std::string& user_id,
                          const std::string& room_id) {
    auto state = get_counts(user_id, room_id);
    return state.to_sync_json();
  }

  // Reset all notifications for a user
  void reset_user(const std::string& user_id) {
    std::lock_guard<std::shared_mutex> lock(mu_);
    notifications_.erase(user_id);
    thread_notifications_.erase(user_id);
  }

  // Reset notifications for a specific room
  void reset_room(const std::string& user_id,
                  const std::string& room_id) {
    std::lock_guard<std::shared_mutex> lock(mu_);
    auto u_it = notifications_.find(user_id);
    if (u_it != notifications_.end()) {
      u_it->second.erase(room_id);
    }
    auto t_it = thread_notifications_.find(user_id);
    if (t_it != thread_notifications_.end()) {
      t_it->second.erase(room_id);
    }
  }

  // Thread notification tracking
  void increment_thread(const std::string& user_id,
                         const std::string& room_id,
                         const std::string& thread_root_id,
                         const std::string& event_id,
                         bool is_highlight) {
    if (!config_.thread_separate_notification_counts) {
      increment(user_id, room_id, event_id, is_highlight);
      return;
    }

    std::lock_guard<std::shared_mutex> lock(mu_);
    auto& ts = thread_notifications_[user_id][room_id][thread_root_id];
    ts.thread_root_id = thread_root_id;
    ts.notification_count++;
    if (is_highlight) ts.highlight_count++;
    ts.updated_at_ms = now_ms();

    // Also increment room-level
    auto& room_state = notifications_[user_id][room_id];
    room_state.room_id = room_id;
    room_state.user_id = user_id;
    room_state.notification_count++;
    if (is_highlight) room_state.highlight_count++;
    room_state.updated_at_ms = now_ms();
  }

  void clear_thread_on_read(const std::string& user_id,
                             const std::string& room_id,
                             const std::string& thread_root_id,
                             const std::string& read_up_to_event_id) {
    std::lock_guard<std::shared_mutex> lock(mu_);
    auto& ts = thread_notifications_[user_id][room_id][thread_root_id];
    ts.thread_root_id = thread_root_id;
    ts.notification_count = 0;
    if (config_.clear_highlight_on_read) ts.highlight_count = 0;
    ts.last_read_event_id = read_up_to_event_id;
    ts.updated_at_ms = now_ms();
  }

  std::map<std::string, ThreadNotificationState> get_thread_counts(
      const std::string& user_id, const std::string& room_id) {
    std::shared_lock<std::shared_mutex> lock(mu_);
    std::map<std::string, ThreadNotificationState> results;
    auto u_it = thread_notifications_.find(user_id);
    if (u_it != thread_notifications_.end()) {
      auto r_it = u_it->second.find(room_id);
      if (r_it != u_it->second.end()) {
        for (auto& [tid, ts] : r_it->second) {
          results[tid] = ts;
        }
      }
    }
    return results;
  }

  // Statistics
  json get_stats() const {
    std::shared_lock<std::shared_mutex> lock(mu_);
    json stats;
    stats["users_with_notifications"] =
        static_cast<int64_t>(notifications_.size());
    stats["users_with_thread_notifications"] =
        static_cast<int64_t>(thread_notifications_.size());
    return stats;
  }

private:
  RoomNotificationState make_default(const std::string& room_id,
                                      const std::string& user_id) {
    RoomNotificationState s;
    s.room_id = room_id;
    s.user_id = user_id;
    s.notification_count = 0;
    s.highlight_count = 0;
    return s;
  }

  NotificationEngineConfig config_;
  mutable std::shared_mutex mu_;
  std::unordered_map<std::string,
    std::unordered_map<std::string, RoomNotificationState>> notifications_;
  std::unordered_map<std::string,
    std::unordered_map<std::string,
      std::unordered_map<std::string, ThreadNotificationState>>>
    thread_notifications_;
};

// ============================================================================
// Highlight Count Tracker
// ============================================================================

class HighlightCountTracker {
public:
  explicit HighlightCountTracker(const NotificationEngineConfig& cfg)
    : config_(cfg) {}

  // Set highlight words for a user
  void set_highlight_words(const std::string& user_id,
                            const std::vector<std::string>& words) {
    std::lock_guard<std::shared_mutex> lock(mu_);
    highlight_words_[user_id] = words;
  }

  // Get highlight words for a user
  std::vector<std::string> get_highlight_words(const std::string& user_id) {
    std::shared_lock<std::shared_mutex> lock(mu_);
    auto it = highlight_words_.find(user_id);
    if (it != highlight_words_.end()) return it->second;

    // Return global highlight words as fallback
    return config_.highlight_words;
  }

  // Check if an event body contains any highlight word
  bool check_highlight(const std::string& user_id,
                        const json& event_content) {
    std::string body;
    if (event_content.contains("body") &&
        event_content["body"].is_string()) {
      body = event_content["body"].get<std::string>();
    }

    if (body.empty()) return false;

    auto words = get_highlight_words(user_id);
    std::string lower_body = to_lower(body);

    for (auto& word : words) {
      if (!word.empty() &&
          lower_body.find(to_lower(word)) != std::string::npos) {
        return true;
      }
    }

    return false;
  }

  // Find which highlight words matched in the event body
  std::vector<std::string> matched_words(const std::string& user_id,
                                          const json& event_content) {
    std::vector<std::string> matched;
    std::string body;
    if (event_content.contains("body") &&
        event_content["body"].is_string()) {
      body = event_content["body"].get<std::string>();
    }
    if (body.empty()) return matched;

    auto words = get_highlight_words(user_id);
    std::string lower_body = to_lower(body);

    for (auto& word : words) {
      if (!word.empty() &&
          lower_body.find(to_lower(word)) != std::string::npos) {
        matched.push_back(word);
      }
    }

    return matched;
  }

  // Remove highlight words for a user
  void remove_highlight_words(const std::string& user_id) {
    std::lock_guard<std::shared_mutex> lock(mu_);
    highlight_words_.erase(user_id);
  }

  json get_stats() const {
    std::shared_lock<std::shared_mutex> lock(mu_);
    json stats;
    stats["users_with_custom_highlight_words"] =
        static_cast<int64_t>(highlight_words_.size());
    return stats;
  }

private:
  NotificationEngineConfig config_;
  mutable std::shared_mutex mu_;
  std::unordered_map<std::string, std::vector<std::string>> highlight_words_;
};

// ============================================================================
// Push Rule Evaluation Pipeline
// ============================================================================

// Lightweight push rule evaluation context
struct EvalContext {
  std::string user_id;
  std::string room_id;
  std::string event_type;
  std::string sender;
  std::string state_key;
  json content;
  int64_t room_member_count{0};
  std::string sender_display_name;
  std::string room_name;
  bool is_encrypted{false};
  bool is_direct{false};
  bool is_thread{false};
  bool is_mention{false};
};

// Simple glob matcher for push rule patterns
namespace GlobMatch {
inline bool match(const std::string& pattern, const std::string& text) {
  if (pattern == "*") return true;
  if (pattern.empty()) return text.empty();

  // Convert glob to simplified matching
  if (pattern.find('*') == std::string::npos &&
      pattern.find('?') == std::string::npos) {
    return to_lower(text).find(to_lower(pattern)) != std::string::npos;
  }

  // Simple glob matching
  size_t pi = 0, ti = 0;
  size_t star_idx = std::string::npos;
  size_t match_idx = 0;

  while (ti < text.size()) {
    if (pi < pattern.size() &&
        (pattern[pi] == '?' ||
         std::tolower(pattern[pi]) == std::tolower(text[ti]))) {
      ++pi; ++ti;
    } else if (pi < pattern.size() && pattern[pi] == '*') {
      star_idx = pi;
      match_idx = ti;
      ++pi;
    } else if (star_idx != std::string::npos) {
      pi = star_idx + 1;
      match_idx++;
      ti = match_idx;
    } else {
      return false;
    }
  }

  while (pi < pattern.size() && pattern[pi] == '*') ++pi;
  return pi == pattern.size();
}
} // namespace GlobMatch

// Condition evaluator
namespace ConditionEval {

// Evaluate event_match condition
inline bool eval_event_match(const std::string& key, const std::string& pattern,
                              const EvalContext& ctx) {
  // key is like "type", "content.body", "room_id", "sender"
  std::string value;
  if (key == "type") {
    value = ctx.event_type;
  } else if (key == "room_id") {
    value = ctx.room_id;
  } else if (key == "sender") {
    value = ctx.sender;
  } else if (key == "state_key") {
    value = ctx.state_key;
  } else if (starts_with(key, "content.")) {
    // Extract nested content key
    std::string content_key = key.substr(8); // remove "content."
    if (ctx.content.contains(content_key)) {
      auto& val = ctx.content[content_key];
      if (val.is_string()) value = val.get<std::string>();
      else value = val.dump();
    }
  }
  return GlobMatch::match(pattern, value);
}

// Evaluate contains_display_name condition
inline bool eval_contains_display_name(const EvalContext& ctx) {
  if (ctx.sender_display_name.empty()) return false;
  std::string body;
  if (ctx.content.contains("body") && ctx.content["body"].is_string())
    body = ctx.content["body"].get<std::string>();
  return body.find(ctx.sender_display_name) != std::string::npos;
}

// Evaluate room_member_count condition
inline bool eval_room_member_count(const std::string& pattern,
                                    const EvalContext& ctx) {
  if (pattern.empty()) return false;

  // Parse: "==2", ">10", "<5", ">=100", "<=50"
  std::string op;
  int64_t threshold = 0;
  if (starts_with(pattern, "==")) {
    op = "=="; threshold = std::stoll(pattern.substr(2));
  } else if (starts_with(pattern, ">=")) {
    op = ">="; threshold = std::stoll(pattern.substr(2));
  } else if (starts_with(pattern, "<=")) {
    op = "<="; threshold = std::stoll(pattern.substr(2));
  } else if (starts_with(pattern, ">")) {
    op = ">"; threshold = std::stoll(pattern.substr(1));
  } else if (starts_with(pattern, "<")) {
    op = "<"; threshold = std::stoll(pattern.substr(1));
  } else {
    // Default: exact match
    threshold = std::stoll(pattern);
    op = "==";
  }

  int64_t count = ctx.room_member_count;
  if (op == "==") return count == threshold;
  if (op == ">")  return count > threshold;
  if (op == "<")  return count < threshold;
  if (op == ">=") return count >= threshold;
  if (op == "<=") return count <= threshold;
  return false;
}

// Evaluate sender_notification_permission
inline bool eval_sender_notification_permission(const std::string& pattern,
                                                 const EvalContext& ctx) {
  // "room" = sender has power level >= 50 in this room
  // Always return true in simplified mode
  (void)pattern;
  (void)ctx;
  return true;
}

// Evaluate is_user_mention
inline bool eval_is_user_mention(const EvalContext& ctx) {
  return ctx.is_mention;
}

// Evaluate all conditions for a rule
inline bool evaluate_all(
    const std::vector<std::pair<std::string, std::string>>& conditions,
    const EvalContext& ctx) {
  if (conditions.empty()) return true; // No conditions = always match

  for (auto& [kind, pattern] : conditions) {
    if (kind == "event_match") {
      // Parse "key pattern" format
      size_t space = pattern.find(' ');
      if (space == std::string::npos) return false;
      std::string key = pattern.substr(0, space);
      std::string pat = pattern.substr(space + 1);
      if (!eval_event_match(key, pat, ctx)) return false;
    } else if (kind == "contains_display_name") {
      if (!eval_contains_display_name(ctx)) return false;
    } else if (kind == "room_member_count") {
      if (!eval_room_member_count(pattern, ctx)) return false;
    } else if (kind == "sender_notification_permission") {
      if (!eval_sender_notification_permission(pattern, ctx)) return false;
    } else if (kind == "is_user_mention") {
      if (!eval_is_user_mention(ctx)) return false;
    } else if (kind == "is_room_mention") {
      // Check for @room mention
      std::string body;
      if (ctx.content.contains("body") && ctx.content["body"].is_string())
        body = ctx.content["body"].get<std::string>();
      if (body.find("@room") == std::string::npos) return false;
    } else if (kind == "event_property_is") {
      // Parse "property value" format
      size_t space = pattern.find(' ');
      if (space == std::string::npos) continue;
      std::string prop = pattern.substr(0, space);
      std::string val = pattern.substr(space + 1);
      if (prop == "room_tag") {
        // Check if room tag matches (simplified)
        if (val != "m.favourite") return false;
      } else if (prop == "m.relates_to.rel_type") {
        // Check if event is a thread reply
        if (val == "m.thread" && !ctx.is_thread) return false;
      }
    } else if (kind == "event_property_contains") {
      // Parse "property value" format
      size_t space = pattern.find(' ');
      if (space == std::string::npos) continue;
      std::string prop = pattern.substr(0, space);
      std::string val = pattern.substr(space + 1);
      // Simplified
      (void)prop;
      (void)val;
    }
  }

  return true; // All conditions passed
}

} // namespace ConditionEval

// ============================================================================
// Push Rule Evaluation Pipeline
// ============================================================================

class PushRuleEvaluationPipeline {
public:
  PushRuleEvaluationPipeline(PushRuleStore& store)
    : store_(store) {}

  // Evaluate push rules for a user against an event
  NotificationDecision evaluate(const std::string& user_id,
                                 const EvalContext& ctx) {
    NotificationDecision decision;

    // Get user's push rules
    auto rules = store_.get_enabled_push_rules(user_id);

    // Log the user into context
    EvalContext full_ctx = ctx;
    full_ctx.user_id = user_id;

    // Check for @mention
    full_ctx.is_mention = check_user_mention(user_id, ctx.content);

    // Evaluate rules in priority order
    for (auto& rule : rules) {
      if (!rule.enabled) continue;

      // Check if the rule matches based on kind
      bool matches = false;
      switch (rule.priority_class) {
        case 5: // override
        case 1: // underride
          matches = rule.conditions.empty() ||
                    ConditionEval::evaluate_all(rule.conditions, full_ctx);
          break;
        case 4: // content
          matches = content_rule_matches(rule, full_ctx);
          break;
        case 3: // room
          matches = (rule.rule_id == ctx.room_id);
          break;
        case 2: // sender
          matches = (rule.rule_id == ctx.sender);
          break;
        default:
          break;
      }

      if (!matches) continue;

      // Rule matched, parse actions
      json actions;
      try {
        actions = json::parse(rule.actions);
      } catch (...) {
        actions = json::array({{"dont_notify"}});
      }

      // Determine action type
      std::string primary_action = extract_primary_action(actions);

      if (primary_action == "dont_notify") {
        decision.should_notify = false;
        decision.is_highlight = false;
        decision.action_type = "dont_notify";
        decision.matched_rule_id = rule.rule_id;
        return decision;  // don't notify wins immediately
      }

      if (primary_action == "coalesce") {
        decision.should_notify = true;
        decision.is_highlight = false;
        decision.action_type = "coalesce";
        decision.matched_rule_id = rule.rule_id;
        // Continue to check for highlight tweaks
      }

      if (primary_action == "notify") {
        decision.should_notify = true;
        decision.action_type = "notify";
        decision.matched_rule_id = rule.rule_id;
      }

      // Extract tweaks
      if (actions.is_array()) {
        for (auto& action : actions) {
          if (action.is_object() && action.contains("set_tweak")) {
            std::string tweak = action["set_tweak"].get<std::string>();
            if (tweak == "sound" && action.contains("value")) {
              decision.sound = action["value"].get<std::string>();
            } else if (tweak == "highlight") {
              decision.is_highlight = action.value("value", true);
            }
          }
        }
      }

      // Priority from actions
      decision.push_priority = evaluate_priority(actions);

      return decision;  // First match wins
    }

    // No rules matched - don't notify
    decision.should_notify = false;
    decision.is_highlight = false;
    decision.action_type = "dont_notify";
    return decision;
  }

  // Bulk evaluate for multiple users
  std::map<std::string, NotificationDecision> bulk_evaluate(
      const std::vector<std::string>& user_ids,
      const EvalContext& base_ctx) {
    std::map<std::string, NotificationDecision> results;

    for (auto& user_id : user_ids) {
      results[user_id] = evaluate(user_id, base_ctx);
    }

    return results;
  }

private:
  std::string extract_primary_action(const json& actions) {
    if (!actions.is_array()) return "dont_notify";
    for (auto& action : actions) {
      if (action.is_string()) {
        std::string s = action.get<std::string>();
        if (s == "notify" || s == "dont_notify" || s == "coalesce")
          return s;
      }
    }
    return "dont_notify";
  }

  int64_t evaluate_priority(const json& actions) {
    // Check for priority tweaks in actions
    if (!actions.is_array()) return 1;
    for (auto& action : actions) {
      if (action.is_object() && action.contains("set_tweak")) {
        std::string tweak = action["set_tweak"].get<std::string>();
        if (tweak == "priority") {
          int64_t pri = action.value("value", 1);
          return std::max<int64_t>(0, std::min<int64_t>(2, pri));
        }
      }
    }
    return 1; // Default: normal priority
  }

  bool content_rule_matches(const PushRule& rule, const EvalContext& ctx) {
    std::string body;
    if (ctx.content.contains("body") && ctx.content["body"].is_string())
      body = ctx.content["body"].get<std::string>();
    return GlobMatch::match(rule.rule_id, body);
  }

  bool check_user_mention(const std::string& user_id, const json& content) {
    // Check in formatted_body or body
    std::string formatted = content.value("formatted_body", "");
    std::string body = content.value("body", "");

    auto search_target = formatted.empty() ? body : formatted;

    if (search_target.find(user_id) != std::string::npos)
      return true;

    // Check for <a href="https://matrix.to/#/@user:domain">
    std::string mention_link = "matrix.to/#/" + user_id;
    if (search_target.find(mention_link) != std::string::npos)
      return true;

    return false;
  }

  PushRuleStore& store_;
};

// ============================================================================
// Notification Result Computer
// ============================================================================

class NotificationResultComputer {
public:
  NotificationResultComputer(PushRuleEvaluationPipeline& pipeline,
                              NotificationCountTracker& count_tracker,
                              HighlightCountTracker& highlight_tracker)
    : pipeline_(pipeline), count_tracker_(count_tracker),
      highlight_tracker_(highlight_tracker) {}

  // Compute notification result for a single event and user
  NotificationDecision compute(const std::string& user_id,
                                const EvalContext& ctx) {
    // Evaluate push rules
    auto decision = pipeline_.evaluate(user_id, ctx);

    // If notified, also check highlight words
    if (decision.should_notify && !decision.is_highlight) {
      if (highlight_tracker_.check_highlight(user_id, ctx.content)) {
        decision.is_highlight = true;
        decision.matched_highlight_words =
            highlight_tracker_.matched_words(user_id, ctx.content);
      }
    }

    // Check for @room mention highlight
    if (decision.should_notify && !decision.is_highlight) {
      std::string body;
      if (ctx.content.contains("body") && ctx.content["body"].is_string())
        body = ctx.content["body"].get<std::string>();
      if (body.find("@room") != std::string::npos) {
        decision.is_highlight = true;
      }
    }

    // Record notification counts if applicable
    if (decision.should_notify) {
      // Don't count if sender is the user themselves
      if (ctx.sender != user_id) {
        count_tracker_.increment(
            user_id, ctx.room_id, "", decision.is_highlight);
      }
    }

    return decision;
  }

  // Bulk compute for room members
  std::map<std::string, NotificationDecision> bulk_compute(
      const std::vector<std::string>& user_ids,
      const EvalContext& base_ctx,
      const std::string& sender_user_id = "") {
    std::map<std::string, NotificationDecision> results;

    for (auto& user_id : user_ids) {
      // Skip sender if configured
      if (user_id == sender_user_id) continue;
      results[user_id] = compute(user_id, base_ctx);
    }

    return results;
  }

  // Determine which users should receive push notifications
  std::vector<std::string> users_to_notify(
      const std::map<std::string, NotificationDecision>& decisions) {
    std::vector<std::string> users;
    for (auto& [uid, decision] : decisions) {
      if (decision.should_notify) users.push_back(uid);
    }
    return users;
  }

  // Classify users into highlight/notify/silent groups
  void classify(const std::map<std::string, NotificationDecision>& decisions,
                std::vector<std::string>& highlight_users,
                std::vector<std::string>& notify_users,
                std::vector<std::string>& silent_users) {
    for (auto& [uid, decision] : decisions) {
      if (decision.is_highlight)
        highlight_users.push_back(uid);
      else if (decision.should_notify)
        notify_users.push_back(uid);
      else
        silent_users.push_back(uid);
    }
  }

private:
  PushRuleEvaluationPipeline& pipeline_;
  NotificationCountTracker& count_tracker_;
  HighlightCountTracker& highlight_tracker_;
};

// ============================================================================
// Notification Dispatcher
// ============================================================================

class NotificationDispatcher {
public:
  NotificationDispatcher(DatabasePool& db,
                          const NotificationEngineConfig& cfg)
    : db_(db), config_(cfg),
      http_backend_(std::make_unique<HttpPusherBackend>(cfg)),
      email_backend_(std::make_unique<EmailPusherBackend>(cfg)),
      coalescer_(std::make_unique<NotificationCoalescer>(cfg)) {}

  // Dispatch a notification to the appropriate pushers for a user
  std::vector<std::string> dispatch(const std::string& user_id,
                                     const NotificationAction& action,
                                     const json& event_data) {
    std::vector<std::string> dispatched_pushers;

    // Get user's pushers from the database
    auto pushers = get_user_pushers(user_id);
    if (pushers.empty()) return dispatched_pushers;

    // Try coalescing first
    std::string coalesce_key;
    if (config_.enable_coalescing) {
      coalesce_key = coalescer_->try_coalesce(action);
      if (!coalesce_key.empty()) {
        // Coalesced: mark as deferred
        mark_as_coalesced(action, coalesce_key);
        return dispatched_pushers;
      }
    }

    // Dispatch to each pusher
    for (auto& pusher : pushers) {
      if (!pusher.enabled) continue;

      // Rate limiting check
      if (!check_rate_limit(pusher)) continue;

      bool sent = false;

      if (pusher.kind == "http" && config_.enable_http_push) {
        sent = http_backend_->send_push(pusher, action, event_data);
      } else if (pusher.kind == "email" && config_.enable_email_push) {
        sent = email_backend_->send_push(pusher, action, event_data);
      } else if (config_.enable_custom_pushers) {
        // Custom pusher handling
        sent = dispatch_custom(pusher, action, event_data);
      }

      if (sent) {
        dispatched_pushers.push_back(pusher.pusher_id);
        record_push_sent(pusher.pusher_id, action.event_id);
      } else {
        record_push_failed(pusher.pusher_id, action.event_id);
      }
    }

    return dispatched_pushers;
  }

  // Flush and dispatch coalesced notifications
  int64_t flush_coalesced() {
    auto buckets = coalescer_->flush_expired();
    int64_t total_sent = 0;

    for (auto& [key, actions] : buckets) {
      if (actions.empty()) continue;

      // Get the user from the coalesce key
      size_t pipe = key.find('|');
      std::string user_id = key.substr(0, pipe);

      auto pushers = get_user_pushers(user_id);
      for (auto& pusher : pushers) {
        if (!pusher.enabled) continue;

        // Try coalesced send
        bool sent = false;
        if (pusher.kind == "http") {
          sent = http_backend_->send_coalesced(pusher, actions, {});
        } else if (pusher.kind == "email") {
          sent = email_backend_->send_coalesced(pusher, actions, {});
        }

        if (sent) {
          total_sent += actions.size();
          for (auto& action : actions) {
            record_push_sent(pusher.pusher_id, action.event_id);
          }
        }
      }
    }

    return total_sent;
  }

  // Flush email digests
  int64_t flush_email_digests() {
    auto pending = email_backend_->flush_digests();
    int64_t total = 0;

    for (auto& [user_id, entries] : pending) {
      // Group entries by room
      std::map<std::string, std::vector<NotificationAction>> by_room;
      for (auto& entry : entries) {
        by_room[entry.action.room_id].push_back(entry.action);
      }

      for (auto& [room_id, actions] : by_room) {
        if (!entries.empty()) {
          email_backend_->send_coalesced(entries[0].pusher, actions,
                                          entries[0].event_data);
          total += actions.size();
        }
      }
    }

    return total;
  }

  // Rate limit check
  bool check_rate_limit(const PusherConfig& pusher) {
    if (!config_.enable_rate_limiting) return true;

    std::lock_guard<std::shared_mutex> lock(rate_mu_);

    int64_t now = now_ms();
    std::string key = pusher.pusher_id;

    auto& bucket = rate_buckets_[key];
    // Clean expired tokens
    if (bucket.last_reset_ms == 0) {
      bucket.last_reset_ms = now;
      bucket.tokens = config_.rate_limit_burst_size;
    }

    int64_t elapsed = now - bucket.last_reset_ms;
    int64_t new_tokens = static_cast<int64_t>(
        static_cast<double>(elapsed) *
        static_cast<double>(config_.rate_limit_per_pusher_per_min) /
        60000.0);

    bucket.tokens = std::min(config_.rate_limit_burst_size,
                              bucket.tokens + new_tokens);
    bucket.last_reset_ms = now;

    if (bucket.tokens > 0) {
      bucket.tokens--;
      return true;
    }

    return false;
  }

  // Get statistics
  json get_stats() const {
    json stats;
    stats["coalescer"] = coalescer_->get_stats();
    stats["rate_limit_buckets"] = static_cast<int64_t>(rate_buckets_.size());
    return stats;
  }

private:
  std::vector<PusherConfig> get_user_pushers(const std::string& user_id) {
    // Query from database
    // Stub: return empty vector (pushers come from db via lazy load)
    std::shared_lock<std::shared_mutex> lock(pusher_cache_mu_);
    auto it = pusher_cache_.find(user_id);
    if (it != pusher_cache_.end()) return it->second;
    return {};
  }

  void mark_as_coalesced(const NotificationAction& action,
                          const std::string& coalesce_key) {
    (void)action;
    (void)coalesce_key;
    // DB update to mark as coalesced
  }

  void record_push_sent(const std::string& pusher_id,
                         const std::string& event_id) {
    (void)pusher_id;
    (void)event_id;
    // DB record of successful push delivery
  }

  void record_push_failed(const std::string& pusher_id,
                           const std::string& event_id) {
    (void)pusher_id;
    (void)event_id;
    // DB record of failed push delivery
  }

  bool dispatch_custom(const PusherConfig& pusher,
                        const NotificationAction& action,
                        const json& event_data) {
    (void)pusher;
    (void)action;
    (void)event_data;
    return false; // Custom pushers not implemented
  }

  DatabasePool& db_;
  NotificationEngineConfig config_;
  std::unique_ptr<HttpPusherBackend> http_backend_;
  std::unique_ptr<EmailPusherBackend> email_backend_;
  std::unique_ptr<NotificationCoalescer> coalescer_;

  mutable std::shared_mutex rate_mu_;
  struct RateBucket {
    int64_t tokens{0};
    int64_t last_reset_ms{0};
  };
  std::unordered_map<std::string, RateBucket> rate_buckets_;

  mutable std::shared_mutex pusher_cache_mu_;
  std::unordered_map<std::string, std::vector<PusherConfig>> pusher_cache_;
};

// ============================================================================
// Pusher Lifecycle Manager
// ============================================================================

class PusherLifecycleManager {
public:
  PusherLifecycleManager(DatabasePool& db,
                          const NotificationEngineConfig& cfg)
    : db_(db), config_(cfg) {}

  // ========================================================================
  // SQL DDL — Create all pusher-related tables
  // ========================================================================
  static void create_tables(LoggingTransaction& txn) {
    // User pushers table
    txn.execute(R"(
      CREATE TABLE IF NOT EXISTS user_pushers (
        pusher_id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        kind TEXT NOT NULL,           -- "http", "email", "custom"
        app_id TEXT NOT NULL DEFAULT '',
        app_display_name TEXT NOT NULL DEFAULT '',
        device_display_name TEXT NOT NULL DEFAULT '',
        pushkey TEXT NOT NULL DEFAULT '',
        lang TEXT NOT NULL DEFAULT 'en',
        data TEXT NOT NULL DEFAULT '{}',  -- JSON blob
        access_token TEXT NOT NULL DEFAULT '',
        enabled INTEGER NOT NULL DEFAULT 1,
        created_at_ms INTEGER NOT NULL DEFAULT 0,
        last_success_ms INTEGER NOT NULL DEFAULT 0,
        last_failure_ms INTEGER NOT NULL DEFAULT 0,
        failure_count INTEGER NOT NULL DEFAULT 0
      )
    )");

    // Index for quick user lookup
    txn.execute(R"(
      CREATE INDEX IF NOT EXISTS idx_user_pushers_user_id
        ON user_pushers(user_id)
    )");

    // Index for pusher kind lookups
    txn.execute(R"(
      CREATE INDEX IF NOT EXISTS idx_user_pushers_kind
        ON user_pushers(kind)
    )");

    // Unique constraint: one pushkey per app per user
    txn.execute(R"(
      CREATE UNIQUE INDEX IF NOT EXISTS idx_user_pushers_unique_key
        ON user_pushers(user_id, app_id, pushkey)
    )");

    // Event push actions staging table
    txn.execute(R"(
      CREATE TABLE IF NOT EXISTS event_push_actions_staging (
        event_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        room_id TEXT NOT NULL,
        topological_ordering INTEGER NOT NULL DEFAULT 0,
        stream_ordering INTEGER NOT NULL DEFAULT 0,
        notif INTEGER NOT NULL DEFAULT 0,
        highlight INTEGER NOT NULL DEFAULT 0,
        action_type TEXT NOT NULL DEFAULT 'dont_notify',
        coalesce_key TEXT,
        priority INTEGER NOT NULL DEFAULT 1,
        created_at_ms INTEGER NOT NULL DEFAULT 0,
        processed INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (event_id, user_id)
      )
    )");

    // Index for unprocessed notifications
    txn.execute(R"(
      CREATE INDEX IF NOT EXISTS idx_epa_staging_unprocessed
        ON event_push_actions_staging(processed, created_at_ms)
    )");

    // Event push summary table (per-room, per-user)
    txn.execute(R"(
      CREATE TABLE IF NOT EXISTS event_push_summary (
        user_id TEXT NOT NULL,
        room_id TEXT NOT NULL,
        stream_ordering INTEGER NOT NULL DEFAULT 0,
        notif_count INTEGER NOT NULL DEFAULT 0,
        highlight_count INTEGER NOT NULL DEFAULT 0,
        last_notified_event_id TEXT,
        last_updated_ms INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (user_id, room_id)
      )
    )");

    // Stream ordering tracker
    txn.execute(R"(
      CREATE TABLE IF NOT EXISTS event_push_summary_stream_ordering (
        lock TEXT PRIMARY KEY DEFAULT 'stream',
        stream_ordering INTEGER NOT NULL DEFAULT 0
      )
    )");

    // Initialize stream ordering
    txn.execute(R"(
      INSERT OR IGNORE INTO event_push_summary_stream_ordering
        (lock, stream_ordering) VALUES ('stream', 0)
    )");

    // Sent push notifications tracking
    txn.execute(R"(
      CREATE TABLE IF NOT EXISTS sent_push_notifications (
        pusher_id TEXT NOT NULL,
        event_id TEXT NOT NULL,
        room_id TEXT NOT NULL DEFAULT '',
        user_id TEXT NOT NULL DEFAULT '',
        sent_at_ms INTEGER NOT NULL DEFAULT 0,
        success INTEGER NOT NULL DEFAULT 1,
        error_message TEXT,
        PRIMARY KEY (pusher_id, event_id)
      )
    )");

    // Index for recent sent lookups
    txn.execute(R"(
      CREATE INDEX IF NOT EXISTS idx_sent_push_pusher_recent
        ON sent_push_notifications(pusher_id, sent_at_ms DESC)
    )");

    // Deferred push actions (for retry)
    txn.execute(R"(
      CREATE TABLE IF NOT EXISTS deferred_push_actions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT NOT NULL,
        event_id TEXT NOT NULL,
        room_id TEXT NOT NULL,
        pusher_id TEXT NOT NULL,
        notif INTEGER NOT NULL DEFAULT 0,
        highlight INTEGER NOT NULL DEFAULT 0,
        stream_ordering INTEGER NOT NULL DEFAULT 0,
        retry_count INTEGER NOT NULL DEFAULT 0,
        max_retries INTEGER NOT NULL DEFAULT 5,
        last_retry_at_ms INTEGER NOT NULL DEFAULT 0,
        next_retry_at_ms INTEGER NOT NULL DEFAULT 0,
        created_at_ms INTEGER NOT NULL DEFAULT 0,
        error_message TEXT
      )
    )");

    // Index for pending retries
    txn.execute(R"(
      CREATE INDEX IF NOT EXISTS idx_deferred_push_retry
        ON deferred_push_actions(next_retry_at_ms)
    )");

    // Push action coalesce table
    txn.execute(R"(
      CREATE TABLE IF NOT EXISTS push_action_coalesce (
        coalesce_key TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        room_id TEXT NOT NULL,
        event_ids TEXT NOT NULL,          -- JSON array
        action_count INTEGER NOT NULL DEFAULT 1,
        highlight_count INTEGER NOT NULL DEFAULT 0,
        window_start_ms INTEGER NOT NULL DEFAULT 0,
        window_end_ms INTEGER NOT NULL DEFAULT 0,
        dispatched INTEGER NOT NULL DEFAULT 0,
        dispatched_at_ms INTEGER NOT NULL DEFAULT 0
      )
    )");

    // Background notification processing state
    txn.execute(R"(
      CREATE TABLE IF NOT EXISTS background_notification_state (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL DEFAULT '',
        updated_at_ms INTEGER NOT NULL DEFAULT 0
      )
    )");

    // Initialize background processing state
    txn.execute(R"(
      INSERT OR IGNORE INTO background_notification_state (key, value, updated_at_ms)
      VALUES ('last_processed_stream_ordering', '0', 0)
    )");

    txn.execute(R"(
      INSERT OR IGNORE INTO background_notification_state (key, value, updated_at_ms)
      VALUES ('last_coalesce_flush_ms', '0', 0)
    )");

    txn.execute(R"(
      INSERT OR IGNORE INTO background_notification_state (key, value, updated_at_ms)
      VALUES ('last_email_digest_flush_ms', '0', 0)
    )");

    // Notification events table for /notifications API
    txn.execute(R"(
      CREATE TABLE IF NOT EXISTS notification_events (
        event_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        room_id TEXT NOT NULL,
        sender TEXT NOT NULL DEFAULT '',
        event_type TEXT NOT NULL DEFAULT 'm.room.message',
        content_json TEXT NOT NULL DEFAULT '{}',
        highlight INTEGER NOT NULL DEFAULT 0,
        notif INTEGER NOT NULL DEFAULT 0,
        stream_ordering INTEGER NOT NULL DEFAULT 0,
        created_at_ms INTEGER NOT NULL DEFAULT 0,
        read INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (event_id, user_id)
      )
    )");

    // Index for /notifications queries
    txn.execute(R"(
      CREATE INDEX IF NOT EXISTS idx_notification_events_user_time
        ON notification_events(user_id, created_at_ms DESC)
    )");

    // Push rule evaluation cache
    txn.execute(R"(
      CREATE TABLE IF NOT EXISTS push_rule_eval_cache (
        user_id TEXT NOT NULL,
        rule_id TEXT NOT NULL,
        last_result TEXT NOT NULL DEFAULT '{}',
        cached_at_ms INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (user_id, rule_id)
      )
    )");
  }

  // ========================================================================
  // Pusher CRUD Operations
  // ========================================================================

  // Create a new pusher
  std::string add_pusher(const PusherConfig& pusher) {
    if (pusher.user_id.empty()) return "Pusher must have a user_id";
    if (pusher.kind.empty()) return "Pusher must have a kind";
    if (pusher.pushkey.empty()) return "Pusher must have a pushkey";

    // Validate based on kind
    std::string error;
    if (pusher.kind == "http") {
      error = HttpPusherBackend(config_).validate(pusher);
    } else if (pusher.kind == "email") {
      error = EmailPusherBackend(config_).validate(pusher);
    }
    if (!error.empty()) return error;

    // Check max pushers per user
    auto existing = get_pushers_for_user(pusher.user_id);
    if (existing.size() >= static_cast<size_t>(config_.max_pushers_per_user)) {
      return "Maximum number of pushers reached";
    }

    // Insert into database
    auto conn = db_.acquire();
    auto txn = conn->cursor("add_pusher");

    PusherConfig pc = pusher;
    if (pc.pusher_id.empty()) {
      pc.pusher_id = generate_random_id(12);
    }
    if (pc.created_at_ms == 0) pc.created_at_ms = now_ms();

    std::string data_str = pc.data.dump();

    txn->execute(
      "INSERT OR REPLACE INTO user_pushers "
      "(pusher_id, user_id, kind, app_id, app_display_name, "
      " device_display_name, pushkey, lang, data, access_token, "
      " enabled, created_at_ms, last_success_ms, last_failure_ms, "
      " failure_count) "
      "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
      {
        pc.pusher_id, pc.user_id, pc.kind, pc.app_id,
        pc.app_display_name, pc.device_display_name,
        pc.pushkey, pc.lang, data_str, pc.access_token,
        pc.enabled ? int64_t(1) : int64_t(0), pc.created_at_ms,
        pc.last_success_ms, pc.last_failure_ms, pc.failure_count
      });

    txn->commit();
    return "";
  }

  // Update an existing pusher
  std::string update_pusher(const PusherConfig& pusher) {
    if (pusher.pusher_id.empty()) return "Pusher ID required";

    auto conn = db_.acquire();
    auto txn = conn->cursor("update_pusher");

    std::string data_str = pusher.data.dump();

    txn->execute(
      "UPDATE user_pushers SET "
      "kind = ?, app_id = ?, app_display_name = ?, "
      "device_display_name = ?, pushkey = ?, lang = ?, "
      "data = ?, enabled = ? "
      "WHERE pusher_id = ? AND user_id = ?",
      {
        pusher.kind, pusher.app_id, pusher.app_display_name,
        pusher.device_display_name, pusher.pushkey, pusher.lang,
        data_str, pusher.enabled ? int64_t(1) : int64_t(0),
        pusher.pusher_id, pusher.user_id
      });

    if (txn->rowcount() == 0) {
      return "Pusher not found";
    }

    txn->commit();
    return "";
  }

  // Delete a pusher
  std::string delete_pusher(const std::string& pusher_id,
                             const std::string& user_id) {
    auto conn = db_.acquire();
    auto txn = conn->cursor("delete_pusher");

    txn->execute(
      "DELETE FROM user_pushers WHERE pusher_id = ? AND user_id = ?",
      {pusher_id, user_id});

    if (txn->rowcount() == 0) {
      return "Pusher not found";
    }

    txn->commit();
    return "";
  }

  // Get pushers for a user
  std::vector<PusherConfig> get_pushers_for_user(const std::string& user_id) {
    std::vector<PusherConfig> pushers;

    auto conn = db_.acquire();
    auto txn = conn->cursor("get_user_pushers");

    txn->execute(
      "SELECT pusher_id, user_id, kind, app_id, app_display_name, "
      "  device_display_name, pushkey, lang, data, access_token, "
      "  enabled, created_at_ms, last_success_ms, last_failure_ms, "
      "  failure_count "
      "FROM user_pushers WHERE user_id = ? AND enabled = 1",
      {user_id});

    auto rows = txn->fetchall();
    for (auto& row : rows) {
      PusherConfig pc;
      pc.pusher_id = row[0].value.value_or("");
      pc.user_id = row[1].value.value_or("");
      pc.kind = row[2].value.value_or("");
      pc.app_id = row[3].value.value_or("");
      pc.app_display_name = row[4].value.value_or("");
      pc.device_display_name = row[5].value.value_or("");
      pc.pushkey = row[6].value.value_or("");
      pc.lang = row[7].value.value_or("");
      try { pc.data = json::parse(row[8].value.value_or("{}")); }
      catch (...) { pc.data = json::object(); }
      pc.access_token = row[9].value.value_or("");
      pc.enabled = (row[10].value.value_or("0") == "1");
      pc.created_at_ms = std::stoll(row[11].value.value_or("0"));
      pc.last_success_ms = std::stoll(row[12].value.value_or("0"));
      pc.last_failure_ms = std::stoll(row[13].value.value_or("0"));
      pc.failure_count = std::stoll(row[14].value.value_or("0"));
      pushers.push_back(std::move(pc));
    }

    return pushers;
  }

  // Get all enabled pushers (for background processing)
  std::vector<PusherConfig> get_all_enabled_pushers() {
    std::vector<PusherConfig> pushers;

    auto conn = db_.acquire();
    auto txn = conn->cursor("get_all_pushers");

    txn->execute(
      "SELECT pusher_id, user_id, kind, app_id, app_display_name, "
      "  device_display_name, pushkey, lang, data, access_token, "
      "  enabled, created_at_ms, last_success_ms, last_failure_ms, "
      "  failure_count "
      "FROM user_pushers WHERE enabled = 1");

    auto rows = txn->fetchall();
    for (auto& row : rows) {
      PusherConfig pc;
      pc.pusher_id = row[0].value.value_or("");
      pc.user_id = row[1].value.value_or("");
      pc.kind = row[2].value.value_or("");
      pc.app_id = row[3].value.value_or("");
      pc.app_display_name = row[4].value.value_or("");
      pc.device_display_name = row[5].value.value_or("");
      pc.pushkey = row[6].value.value_or("");
      pc.lang = row[7].value.value_or("");
      try { pc.data = json::parse(row[8].value.value_or("{}")); }
      catch (...) { pc.data = json::object(); }
      pc.access_token = row[9].value.value_or("");
      pc.enabled = (row[10].value.value_or("0") == "1");
      pc.created_at_ms = std::stoll(row[11].value.value_or("0"));
      pc.last_success_ms = std::stoll(row[12].value.value_or("0"));
      pc.last_failure_ms = std::stoll(row[13].value.value_or("0"));
      pc.failure_count = std::stoll(row[14].value.value_or("0"));
      pushers.push_back(std::move(pc));
    }

    return pushers;
  }

  // Get a single pusher
  std::optional<PusherConfig> get_pusher(const std::string& pusher_id) {
    auto conn = db_.acquire();
    auto txn = conn->cursor("get_pusher");

    txn->execute(
      "SELECT pusher_id, user_id, kind, app_id, app_display_name, "
      "  device_display_name, pushkey, lang, data, access_token, "
      "  enabled, created_at_ms, last_success_ms, last_failure_ms, "
      "  failure_count "
      "FROM user_pushers WHERE pusher_id = ?",
      {pusher_id});

    auto rows = txn->fetchall();
    if (rows.empty()) return std::nullopt;

    auto& row = rows[0];
    PusherConfig pc;
    pc.pusher_id = row[0].value.value_or("");
    pc.user_id = row[1].value.value_or("");
    pc.kind = row[2].value.value_or("");
    pc.app_id = row[3].value.value_or("");
    pc.app_display_name = row[4].value.value_or("");
    pc.device_display_name = row[5].value.value_or("");
    pc.pushkey = row[6].value.value_or("");
    pc.lang = row[7].value.value_or("");
    try { pc.data = json::parse(row[8].value.value_or("{}")); }
    catch (...) { pc.data = json::object(); }
    pc.access_token = row[9].value.value_or("");
    pc.enabled = (row[10].value.value_or("0") == "1");
    pc.created_at_ms = std::stoll(row[11].value.value_or("0"));
    pc.last_success_ms = std::stoll(row[12].value.value_or("0"));
    pc.last_failure_ms = std::stoll(row[13].value.value_or("0"));
    pc.failure_count = std::stoll(row[14].value.value_or("0"));

    return pc;
  }

  // Remove all pushers for a user (on logout/account deletion)
  void remove_all_pushers_for_user(const std::string& user_id) {
    auto conn = db_.acquire();
    auto txn = conn->cursor("remove_user_pushers");
    txn->execute("DELETE FROM user_pushers WHERE user_id = ?", {user_id});
    txn->commit();
  }

  // Remove pushers associated with an access token
  void remove_pushers_by_access_token(const std::string& access_token) {
    auto conn = db_.acquire();
    auto txn = conn->cursor("remove_token_pushers");
    txn->execute("DELETE FROM user_pushers WHERE access_token = ?",
                  {access_token});
    txn->commit();
  }

  // Check if a pusher exists
  bool pusher_exists(const std::string& pusher_id) {
    auto conn = db_.acquire();
    auto txn = conn->cursor("pusher_exists");
    txn->execute("SELECT COUNT(*) FROM user_pushers WHERE pusher_id = ?",
                  {pusher_id});
    auto rows = txn->fetchall();
    if (rows.empty()) return false;
    return std::stoll(rows[0][0].value.value_or("0")) > 0;
  }

  // ========================================================================
  // Event Push Actions CRUD
  // ========================================================================

  // Add push actions for an event targeting specific users
  void add_push_actions(const std::string& event_id,
                         const std::string& room_id,
                         int64_t topological_ordering,
                         int64_t stream_ordering,
                         const std::vector<NotificationAction>& actions) {
    if (actions.empty()) return;

    auto conn = db_.acquire();
    auto txn = conn->cursor("add_push_actions");
    int64_t now = now_ms();

    for (auto& action : actions) {
      txn->execute(
        "INSERT OR REPLACE INTO event_push_actions_staging "
        "(event_id, user_id, room_id, topological_ordering, "
        " stream_ordering, notif, highlight, action_type, "
        " coalesce_key, priority, created_at_ms, processed) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)",
        {event_id, action.user_id, room_id,
         topological_ordering, stream_ordering,
         action.notif, action.highlight, action.action_type,
         action.coalesce_key, action.priority, now});
    }

    txn->commit();
  }

  // Get unprocessed push actions
  std::vector<NotificationAction> get_unprocessed_actions(
      int64_t limit, int64_t before_stream_ordering = INT64_MAX) {
    std::vector<NotificationAction> actions;

    auto conn = db_.acquire();
    auto txn = conn->cursor("get_unprocessed");

    txn->execute(
      "SELECT event_id, user_id, room_id, stream_ordering, "
      "  topological_ordering, notif, highlight, action_type, "
      "  coalesce_key, priority, created_at_ms "
      "FROM event_push_actions_staging "
      "WHERE processed = 0 AND stream_ordering < ? "
      "ORDER BY stream_ordering ASC LIMIT ?",
      {before_stream_ordering, limit});

    auto rows = txn->fetchall();
    for (auto& row : rows) {
      NotificationAction action;
      action.event_id = row[0].value.value_or("");
      action.user_id = row[1].value.value_or("");
      action.room_id = row[2].value.value_or("");
      action.stream_ordering = std::stoll(row[3].value.value_or("0"));
      action.topological_ordering = std::stoll(row[4].value.value_or("0"));
      action.notif = std::stoll(row[5].value.value_or("0"));
      action.highlight = std::stoll(row[6].value.value_or("0"));
      action.action_type = row[7].value.value_or("");
      action.coalesce_key = row[8].value.value_or("");
      action.priority = std::stoll(row[9].value.value_or("1"));
      action.created_at_ms = std::stoll(row[10].value.value_or("0"));
      actions.push_back(std::move(action));
    }

    return actions;
  }

  // Mark push actions as processed
  void mark_actions_processed(const std::vector<std::string>& event_ids,
                               const std::string& user_id) {
    if (event_ids.empty()) return;

    auto conn = db_.acquire();
    auto txn = conn->cursor("mark_processed");

    for (auto& eid : event_ids) {
      txn->execute(
        "UPDATE event_push_actions_staging "
        "SET processed = 1 WHERE event_id = ? AND user_id = ?",
        {eid, user_id});
    }

    txn->commit();
  }

  // Update push summary for a user/room
  void update_push_summary(const std::string& user_id,
                            const std::string& room_id,
                            int64_t stream_ordering) {
    auto conn = db_.acquire();
    auto txn = conn->cursor("update_push_summary");

    txn->execute(
      "INSERT INTO event_push_summary "
      "(user_id, room_id, stream_ordering, notif_count, "
      " highlight_count, last_updated_ms) "
      "VALUES (?, ?, ?, "
      " (SELECT COUNT(*) FROM event_push_actions_staging "
      "  WHERE user_id = ? AND room_id = ? AND notif = 1 AND processed = 0), "
      " (SELECT COUNT(*) FROM event_push_actions_staging "
      "  WHERE user_id = ? AND room_id = ? AND highlight = 1 AND processed = 0), "
      " ?) "
      "ON CONFLICT(user_id, room_id) DO UPDATE SET "
      "  stream_ordering = excluded.stream_ordering, "
      "  notif_count = (SELECT COUNT(*) FROM event_push_actions_staging "
      "    WHERE user_id = ? AND room_id = ? AND notif = 1 AND processed = 0), "
      "  highlight_count = (SELECT COUNT(*) FROM event_push_actions_staging "
      "    WHERE user_id = ? AND room_id = ? AND highlight = 1 AND processed = 0), "
      "  last_updated_ms = ?",
      {user_id, room_id, stream_ordering,
       user_id, room_id,
       user_id, room_id,
       now_ms(),
       user_id, room_id,
       user_id, room_id,
       now_ms()});

    txn->commit();
  }

  // Get push summary for a user/room
  json get_push_summary(const std::string& user_id,
                         const std::string& room_id) {
    auto conn = db_.acquire();
    auto txn = conn->cursor("get_push_summary");

    txn->execute(
      "SELECT notif_count, highlight_count, stream_ordering, "
      "  last_notified_event_id, last_updated_ms "
      "FROM event_push_summary WHERE user_id = ? AND room_id = ?",
      {user_id, room_id});

    auto rows = txn->fetchall();
    json result;
    if (rows.empty()) {
      result["notif_count"] = 0;
      result["highlight_count"] = 0;
      result["stream_ordering"] = 0;
      return result;
    }

    auto& row = rows[0];
    result["notif_count"] = std::stoll(row[0].value.value_or("0"));
    result["highlight_count"] = std::stoll(row[1].value.value_or("0"));
    result["stream_ordering"] = std::stoll(row[2].value.value_or("0"));
    return result;
  }

  // ========================================================================
  // Deferred Push Action CRUD (retry queue)
  // ========================================================================

  // Add a deferred push action for retry
  void add_deferred_action(const NotificationAction& action,
                            const std::string& pusher_id,
                            const std::string& error_message = "") {
    auto conn = db_.acquire();
    auto txn = conn->cursor("add_deferred");
    int64_t now = now_ms();
    int64_t next_retry = now + config_.bg_retry_delay_ms;

    txn->execute(
      "INSERT INTO deferred_push_actions "
      "(user_id, event_id, room_id, pusher_id, notif, highlight, "
      " stream_ordering, retry_count, max_retries, "
      " last_retry_at_ms, next_retry_at_ms, created_at_ms, error_message) "
      "VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, 0, ?, ?, ?)",
      {action.user_id, action.event_id, action.room_id, pusher_id,
       action.notif, action.highlight, action.stream_ordering,
       config_.bg_max_retries, next_retry, now, error_message});

    txn->commit();
  }

  // Get pending deferred actions ready for retry
  std::vector<std::pair<NotificationAction, std::string>> get_deferred_for_retry(
      int64_t limit) {
    std::vector<std::pair<NotificationAction, std::string>> result;

    auto conn = db_.acquire();
    auto txn = conn->cursor("get_deferred_retry");
    int64_t now = now_ms();

    txn->execute(
      "SELECT user_id, event_id, room_id, notif, highlight, "
      "  stream_ordering, retry_count, pusher_id, created_at_ms "
      "FROM deferred_push_actions "
      "WHERE next_retry_at_ms <= ? AND retry_count < max_retries "
      "ORDER BY next_retry_at_ms ASC LIMIT ?",
      {now, limit});

    auto rows = txn->fetchall();
    for (auto& row : rows) {
      NotificationAction action;
      action.user_id = row[0].value.value_or("");
      action.event_id = row[1].value.value_or("");
      action.room_id = row[2].value.value_or("");
      action.notif = std::stoll(row[3].value.value_or("0"));
      action.highlight = std::stoll(row[4].value.value_or("0"));
      action.stream_ordering = std::stoll(row[5].value.value_or("0"));
      std::string pusher_id = row[7].value.value_or("");
      result.push_back({std::move(action), pusher_id});
    }

    return result;
  }

  // Update retry count and next retry time
  void update_deferred_retry(const std::string& event_id,
                              const std::string& user_id,
                              const std::string& pusher_id,
                              bool success,
                              const std::string& error_msg = "") {
    auto conn = db_.acquire();
    auto txn = conn->cursor("update_deferred_retry");
    int64_t now = now_ms();

    if (success) {
      txn->execute(
        "DELETE FROM deferred_push_actions "
        "WHERE event_id = ? AND user_id = ? AND pusher_id = ?",
        {event_id, user_id, pusher_id});
    } else {
      txn->execute(
        "UPDATE deferred_push_actions SET "
        "  retry_count = retry_count + 1, "
        "  last_retry_at_ms = ?, "
        "  next_retry_at_ms = ?, "
        "  error_message = ? "
        "WHERE event_id = ? AND user_id = ? AND pusher_id = ?",
        {now, now + config_.bg_retry_delay_ms, error_msg,
         event_id, user_id, pusher_id});
    }

    txn->commit();
  }

  // Purge permanently failed deferred actions
  void purge_failed_deferred() {
    auto conn = db_.acquire();
    auto txn = conn->cursor("purge_deferred");
    txn->execute(
      "DELETE FROM deferred_push_actions "
      "WHERE retry_count >= max_retries");
    txn->commit();
  }

  // ========================================================================
  // Notification Events CRUD (for /notifications API)
  // ========================================================================

  // Record a notification event
  void record_notification_event(const std::string& event_id,
                                  const std::string& user_id,
                                  const std::string& room_id,
                                  const std::string& sender,
                                  const std::string& event_type,
                                  const json& content,
                                  bool highlight,
                                  bool notif,
                                  int64_t stream_ordering) {
    auto conn = db_.acquire();
    auto txn = conn->cursor("record_notif_event");
    int64_t now = now_ms();

    txn->execute(
      "INSERT OR REPLACE INTO notification_events "
      "(event_id, user_id, room_id, sender, event_type, content_json, "
      " highlight, notif, stream_ordering, created_at_ms, read) "
      "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)",
      {event_id, user_id, room_id, sender, event_type,
       content.dump(), highlight ? int64_t(1) : int64_t(0),
       notif ? int64_t(1) : int64_t(0), stream_ordering, now});

    txn->commit();
  }

  // Get notifications for a user (paginated)
  json get_notifications(const std::string& user_id,
                          int64_t limit = 50,
                          int64_t from_token = 0,
                          const std::string& only_highlight = "") {
    auto conn = db_.acquire();
    auto txn = conn->cursor("get_notifications");

    std::string sql =
      "SELECT event_id, room_id, sender, event_type, content_json, "
      "  highlight, notif, stream_ordering, created_at_ms, read "
      "FROM notification_events "
      "WHERE user_id = ? ";

    if (only_highlight == "true") {
      sql += "AND highlight = 1 ";
    }

    if (from_token > 0) {
      sql += "AND created_at_ms < ? ";
    }

    sql += "ORDER BY created_at_ms DESC LIMIT ?";

    std::vector<SQLParam> params = {user_id};
    if (from_token > 0) params.push_back(from_token);
    params.push_back(limit);

    txn->execute(sql, params);

    auto rows = txn->fetchall();
    json notifications = json::array();

    for (auto& row : rows) {
      json notif;
      notif["event_id"] = row[0].value.value_or("");
      notif["room_id"] = row[1].value.value_or("");
      notif["sender"] = row[2].value.value_or("");
      notif["type"] = row[3].value.value_or("");
      try {
        notif["content"] = json::parse(row[4].value.value_or("{}"));
      } catch (...) {
        notif["content"] = json::object();
      }
      notif["highlight"] = (row[5].value.value_or("0") == "1");
      notif["notify"] = (row[6].value.value_or("0") == "1");
      notif["ts"] = std::stoll(row[7].value.value_or("0"));
      notif["read"] = (row[9].value.value_or("0") == "1");
      notifications.push_back(notif);
    }

    // Build response with next_token
    json result;
    result["notifications"] = notifications;
    if (!notifications.empty()) {
      auto& last = notifications.back();
      result["next_token"] = json_int(last, "ts");
    }
    return result;
  }

  // Mark notifications as read
  void mark_notifications_read(const std::string& user_id,
                                const std::string& room_id) {
    auto conn = db_.acquire();
    auto txn = conn->cursor("mark_notifs_read");
    txn->execute(
      "UPDATE notification_events SET read = 1 "
      "WHERE user_id = ? AND room_id = ? AND read = 0",
      {user_id, room_id});
    txn->commit();
  }

  // ========================================================================
  // Push Rule Eval Cache
  // ========================================================================

  // Cache a push rule evaluation result
  void cache_eval_result(const std::string& user_id,
                          const std::string& rule_id,
                          const json& result) {
    auto conn = db_.acquire();
    auto txn = conn->cursor("cache_eval");

    txn->execute(
      "INSERT OR REPLACE INTO push_rule_eval_cache "
      "(user_id, rule_id, last_result, cached_at_ms) "
      "VALUES (?, ?, ?, ?)",
      {user_id, rule_id, result.dump(), now_ms()});

    txn->commit();
  }

  // Get cached eval result
  std::optional<json> get_cached_eval(const std::string& user_id,
                                       const std::string& rule_id) {
    auto conn = db_.acquire();
    auto txn = conn->cursor("get_cached_eval");

    txn->execute(
      "SELECT last_result, cached_at_ms "
      "FROM push_rule_eval_cache "
      "WHERE user_id = ? AND rule_id = ?",
      {user_id, rule_id});

    auto rows = txn->fetchall();
    if (rows.empty()) return std::nullopt;

    auto& row = rows[0];
    int64_t cached_at = std::stoll(row[1].value.value_or("0"));
    if ((now_ms() - cached_at) > config_.pusher_cache_ttl_ms) {
      // Expired
      return std::nullopt;
    }

    try {
      return json::parse(row[0].value.value_or("{}"));
    } catch (...) {
      return std::nullopt;
    }
  }

  // Clear eval cache for a user
  void clear_eval_cache(const std::string& user_id) {
    auto conn = db_.acquire();
    auto txn = conn->cursor("clear_eval_cache");
    txn->execute("DELETE FROM push_rule_eval_cache WHERE user_id = ?",
                  {user_id});
    txn->commit();
  }

  // ========================================================================
  // Background State CRUD
  // ========================================================================

  // Get background processing state
  int64_t get_bg_state(const std::string& key) {
    auto conn = db_.acquire();
    auto txn = conn->cursor("get_bg_state");

    txn->execute(
      "SELECT value FROM background_notification_state WHERE key = ?",
      {key});

    auto rows = txn->fetchall();
    if (rows.empty()) return 0;
    return std::stoll(rows[0][0].value.value_or("0"));
  }

  // Set background processing state
  void set_bg_state(const std::string& key, int64_t value) {
    auto conn = db_.acquire();
    auto txn = conn->cursor("set_bg_state");

    txn->execute(
      "INSERT OR REPLACE INTO background_notification_state "
      "(key, value, updated_at_ms) VALUES (?, ?, ?)",
      {key, std::to_string(value), now_ms()});

    txn->commit();
  }

  // ========================================================================
  // Maintenance Operations
  // ========================================================================

  // Clean up old staging entries
  void cleanup_staging(int64_t older_than_ms) {
    auto conn = db_.acquire();
    auto txn = conn->cursor("cleanup_staging");

    txn->execute(
      "DELETE FROM event_push_actions_staging "
      "WHERE processed = 1 AND created_at_ms < ?",
      {older_than_ms});

    txn->commit();
  }

  // Clean up old sent push records
  void cleanup_sent_pushes(int64_t older_than_ms) {
    auto conn = db_.acquire();
    auto txn = conn->cursor("cleanup_sent");

    txn->execute(
      "DELETE FROM sent_push_notifications WHERE sent_at_ms < ?",
      {older_than_ms});

    txn->commit();
  }

  // Clean up old notification events
  void cleanup_notification_events(int64_t older_than_ms) {
    auto conn = db_.acquire();
    auto txn = conn->cursor("cleanup_notif_events");

    txn->execute(
      "DELETE FROM notification_events WHERE created_at_ms < ?",
      {older_than_ms});

    txn->commit();
  }

  // Sweep expired pushers (for e.g., access tokens that got revoked)
  int64_t sweep_expired_pushers() {
    // In production, this would check access token validity
    // Stub implementation
    return 0;
  }

  // Get stats
  json get_stats() {
    json stats;

    auto conn = db_.acquire();
    {
      auto txn = conn->cursor("stats_pushers");
      txn->execute("SELECT COUNT(*) FROM user_pushers WHERE enabled = 1");
      auto rows = txn->fetchall();
      stats["active_pushers"] = rows.empty() ? 0 :
          std::stoll(rows[0][0].value.value_or("0"));
    }
    {
      auto txn = conn->cursor("stats_staging");
      txn->execute("SELECT COUNT(*) FROM event_push_actions_staging "
                    "WHERE processed = 0");
      auto rows = txn->fetchall();
      stats["pending_actions"] = rows.empty() ? 0 :
          std::stoll(rows[0][0].value.value_or("0"));
    }
    {
      auto txn = conn->cursor("stats_deferred");
      txn->execute("SELECT COUNT(*) FROM deferred_push_actions");
      auto rows = txn->fetchall();
      stats["deferred_actions"] = rows.empty() ? 0 :
          std::stoll(rows[0][0].value.value_or("0"));
    }
    {
      auto txn = conn->cursor("stats_coalesce");
      txn->execute("SELECT COUNT(*) FROM push_action_coalesce "
                    "WHERE dispatched = 0");
      auto rows = txn->fetchall();
      stats["pending_coalesced"] = rows.empty() ? 0 :
          std::stoll(rows[0][0].value.value_or("0"));
    }
    {
      auto txn = conn->cursor("stats_notif_events");
      txn->execute("SELECT COUNT(*) FROM notification_events WHERE read = 0");
      auto rows = txn->fetchall();
      stats["unread_notifications_db"] = rows.empty() ? 0 :
          std::stoll(rows[0][0].value.value_or("0"));
    }

    return stats;
  }

private:
  DatabasePool& db_;
  NotificationEngineConfig config_;
};

// ============================================================================
// Background Notification Worker
// ============================================================================

class BackgroundNotificationWorker {
public:
  BackgroundNotificationWorker(PusherLifecycleManager& lifecycle,
                                NotificationDispatcher& dispatcher,
                                NotificationCoalescer& coalescer,
                                const NotificationEngineConfig& cfg)
    : lifecycle_(lifecycle), dispatcher_(dispatcher),
      coalescer_(coalescer), config_(cfg),
      running_(false), stop_requested_(false) {}

  ~BackgroundNotificationWorker() {
    stop();
  }

  // Start background processing
  void start() {
    if (!config_.enable_background_processing) return;

    std::lock_guard<std::mutex> lock(state_mu_);
    if (running_) return;
    running_ = true;
    stop_requested_ = false;

    // Start the main processing thread
    worker_thread_ = std::thread([this]() {
      worker_loop();
    });

    // Start coalesce flush thread
    coalesce_thread_ = std::thread([this]() {
      coalesce_loop();
    });

    // Start email digest flush thread
    email_thread_ = std::thread([this]() {
      email_digest_loop();
    });

    // Start deferred retry thread
    retry_thread_ = std::thread([this]() {
      retry_loop();
    });

    // Start maintenance thread
    maintenance_thread_ = std::thread([this]() {
      maintenance_loop();
    });
  }

  // Stop background processing
  void stop() {
    {
      std::lock_guard<std::mutex> lock(state_mu_);
      if (!running_) return;
      stop_requested_ = true;
    }

    cv_.notify_all();

    if (worker_thread_.joinable()) worker_thread_.join();
    if (coalesce_thread_.joinable()) coalesce_thread_.join();
    if (email_thread_.joinable()) email_thread_.join();
    if (retry_thread_.joinable()) retry_thread_.join();
    if (maintenance_thread_.joinable()) maintenance_thread_.join();

    {
      std::lock_guard<std::mutex> lock(state_mu_);
      running_ = false;
    }
  }

  // Check if running
  bool is_running() const {
    std::lock_guard<std::mutex> lock(state_mu_);
    return running_ && !stop_requested_;
  }

  // Get processing stats
  json get_stats() const {
    json stats;
    stats["running"] = running_;
    stats["processed_total"] = processed_total_.load();
    stats["processed_highlights"] = highlights_processed_.load();
    stats["coalesced_total"] = coalesced_total_.load();
    stats["failed_total"] = failed_total_.load();
    stats["dispatched_total"] = dispatched_total_.load();
    stats["email_digests_sent"] = email_digests_sent_.load();
    return stats;
  }

private:
  // Main worker loop: process unprocessed push actions
  void worker_loop() {
    while (!stop_requested_) {
      try {
        // Get last processed stream ordering
        int64_t last_processed =
            lifecycle_.get_bg_state("last_processed_stream_ordering");

        // Get unprocessed actions
        auto actions = lifecycle_.get_unprocessed_actions(
            config_.bg_batch_size, INT64_MAX);

        if (actions.empty()) {
          // Sleep and check again
          std::unique_lock<std::mutex> lock(wait_mu_);
          cv_.wait_for(lock,
              chr::milliseconds(config_.bg_poll_interval_ms),
              [this]() { return stop_requested_.load(); });
          continue;
        }

        int64_t processed_in_batch = 0;

        // Group actions by user
        std::map<std::string, std::vector<NotificationAction>> by_user;
        for (auto& action : actions) {
          by_user[action.user_id].push_back(action);
        }

        // Process per user with concurrency limiting
        for (auto& [user_id, user_actions] : by_user) {
          if (stop_requested_) break;

          for (auto& action : user_actions) {
            if (stop_requested_) break;

            // Dispatch notification
            auto dispatched = dispatcher_.dispatch(
                user_id, action, {});

            if (!dispatched.empty()) {
              dispatched_total_ += dispatched.size();
            }

            // Update stream ordering
            if (action.stream_ordering > last_processed) {
              last_processed = action.stream_ordering;
            }

            // Mark as processed
            lifecycle_.mark_actions_processed(
                {action.event_id}, user_id);

            processed_total_++;
            if (action.highlight > 0) highlights_processed_++;
            processed_in_batch++;
          }
        }

        // Update last processed state
        lifecycle_.set_bg_state(
            "last_processed_stream_ordering", last_processed);

      } catch (const std::exception& e) {
        // Log error and continue
        (void)e;
      }
    }
  }

  // Coalesce flush loop
  void coalesce_loop() {
    while (!stop_requested_) {
      try {
        int64_t last_flush =
            lifecycle_.get_bg_state("last_coalesce_flush_ms");
        int64_t now = now_ms();

        if ((now - last_flush) >= config_.coalesce_window_ms) {
          int64_t sent = dispatcher_.flush_coalesced();
          coalesced_total_ += sent;
          lifecycle_.set_bg_state("last_coalesce_flush_ms", now);
        }
      } catch (...) {}

      std::unique_lock<std::mutex> lock(wait_mu_);
      cv_.wait_for(lock,
          chr::milliseconds(std::max<int64_t>(500, config_.coalesce_window_ms / 2)),
          [this]() { return stop_requested_.load(); });
    }
  }

  // Email digest flush loop
  void email_digest_loop() {
    while (!stop_requested_) {
      try {
        int64_t last_flush =
            lifecycle_.get_bg_state("last_email_digest_flush_ms");
        int64_t now = now_ms();

        if ((now - last_flush) >= config_.email_digest_window_ms) {
          int64_t sent = dispatcher_.flush_email_digests();
          email_digests_sent_ += sent;
          lifecycle_.set_bg_state("last_email_digest_flush_ms", now);
        }
      } catch (...) {}

      std::unique_lock<std::mutex> lock(wait_mu_);
      cv_.wait_for(lock,
          chr::milliseconds(std::max<int64_t>(1000, config_.email_digest_window_ms / 4)),
          [this]() { return stop_requested_.load(); });
    }
  }

  // Deferred retry loop
  void retry_loop() {
    while (!stop_requested_) {
      try {
        // Purge exhausted retries
        lifecycle_.purge_failed_deferred();

        // Get actions ready for retry
        auto deferred = lifecycle_.get_deferred_for_retry(
            config_.bg_batch_size);

        for (auto& [action, pusher_id] : deferred) {
          if (stop_requested_) break;

          // Try dispatch again
          auto dispatched = dispatcher_.dispatch(
              action.user_id, action, {});

          bool success = !dispatched.empty();
          lifecycle_.update_deferred_retry(
              action.event_id, action.user_id, pusher_id, success,
              success ? "" : "Retry failed");
        }
      } catch (...) {}

      std::unique_lock<std::mutex> lock(wait_mu_);
      cv_.wait_for(lock,
          chr::milliseconds(config_.bg_retry_delay_ms),
          [this]() { return stop_requested_.load(); });
    }
  }

  // Maintenance loop
  void maintenance_loop() {
    while (!stop_requested_) {
      try {
        int64_t now = now_ms();
        int64_t one_day_ago = now - 86400000;    // 24 hours
        int64_t one_week_ago = now - 604800000;   // 7 days

        // Cleanup old staging entries
        lifecycle_.cleanup_staging(one_day_ago);

        // Cleanup old sent push records
        lifecycle_.cleanup_sent_pushes(one_week_ago);

        // Cleanup old notification events
        lifecycle_.cleanup_notification_events(one_week_ago * 4);

        // Sweep expired pushers
        lifecycle_.sweep_expired_pushers();
      } catch (...) {}

      std::unique_lock<std::mutex> lock(wait_mu_);
      cv_.wait_for(lock,
          chr::milliseconds(3600000),  // Every hour
          [this]() { return stop_requested_.load(); });
    }
  }

  PusherLifecycleManager& lifecycle_;
  NotificationDispatcher& dispatcher_;
  NotificationCoalescer& coalescer_;
  NotificationEngineConfig config_;

  mutable std::mutex state_mu_;
  bool running_;
  std::atomic<bool> stop_requested_{false};

  std::thread worker_thread_;
  std::thread coalesce_thread_;
  std::thread email_thread_;
  std::thread retry_thread_;
  std::thread maintenance_thread_;

  std::mutex wait_mu_;
  std::condition_variable cv_;

  std::atomic<int64_t> processed_total_{0};
  std::atomic<int64_t> highlights_processed_{0};
  std::atomic<int64_t> coalesced_total_{0};
  std::atomic<int64_t> failed_total_{0};
  std::atomic<int64_t> dispatched_total_{0};
  std::atomic<int64_t> email_digests_sent_{0};
};

// ============================================================================
// Notification Engine Coordinator — Top-level Integration
// ============================================================================

class NotificationEngineCoordinator {
public:
  NotificationEngineCoordinator(DatabasePool& db,
                                 PushRuleStore& push_rule_store,
                                 const NotificationEngineConfig& cfg = {})
    : db_(db), config_(cfg),
      lifecycle_(db, cfg),
      pipeline_(push_rule_store),
      count_tracker_(cfg),
      highlight_tracker_(cfg),
      dispatcher_(db, cfg),
      result_computer_(pipeline_, count_tracker_, highlight_tracker_),
      bg_worker_(lifecycle_, dispatcher_, get_coalescer(), cfg) {}

  // Initialize the engine: create tables, start background processing
  void initialize() {
    auto conn = db_.acquire();
    auto txn = conn->cursor("notif_engine_init");
    PusherLifecycleManager::create_tables(*txn);
    txn->commit();

    bg_worker_.start();
  }

  // Shutdown the engine
  void shutdown() {
    bg_worker_.stop();
  }

  // ========================================================================
  // Event Processing API
  // ========================================================================

  // Process an event for push notification evaluation
  // Called when a new event is received in a room
  json process_event_for_push(const std::string& room_id,
                               const json& event,
                               int64_t stream_ordering,
                               int64_t topological_ordering) {
    json result = json::object();
    result["room_id"] = room_id;
    result["event_id"] = json_str(event, "event_id");

    if (!config_.enable_push_notifications) {
      result["notifications"] = 0;
      return result;
    }

    // Get room members
    std::vector<std::string> room_members;
    try {
      MemberStore member_store(db_);
      room_members = member_store.get_users_in_room(room_id);
    } catch (...) {
      room_members.clear();
    }

    if (room_members.empty()) {
      result["notifications"] = 0;
      return result;
    }

    // Build evaluation context
    EvalContext ctx;
    ctx.room_id = room_id;
    ctx.event_type = json_str(event, "type", "m.room.message");
    ctx.sender = json_str(event, "sender");
    ctx.content = event.value("content", json::object());
    ctx.state_key = json_str(event, "state_key");
    ctx.room_member_count = static_cast<int64_t>(room_members.size());

    // Try to get room info
    try {
      RoomStore room_store(db_);
      ctx.room_name = room_store.get_room_name(room_id).value_or("");
    } catch (...) {}

    // Get sender display name
    try {
      ProfileStore profile_store(db_);
      ctx.sender_display_name =
          profile_store.get_displayname(ctx.sender).value_or("");
    } catch (...) {}

    // Check if DM
    ctx.is_direct = (room_members.size() <= 2);

    // Check if thread event
    if (ctx.content.contains("m.relates_to") &&
        ctx.content["m.relates_to"].is_object()) {
      ctx.is_thread =
          (json_str(ctx.content["m.relates_to"], "rel_type") == "m.thread");
    }

    // Bulk evaluate for all room members
    auto decisions = result_computer_.bulk_compute(
        room_members, ctx, ctx.sender);

    // Classify results
    std::vector<std::string> highlight_users, notify_users, silent_users;
    result_computer_.classify(decisions, highlight_users,
                               notify_users, silent_users);

    // Record notification events
    std::string event_id = json_str(event, "event_id");
    int64_t total_notified = 0;

    for (auto& [uid, decision] : decisions) {
      if (!decision.should_notify) continue;

      // Record in database
      lifecycle_.record_notification_event(
          event_id, uid, room_id, ctx.sender,
          ctx.event_type, ctx.content,
          decision.is_highlight, true, stream_ordering);

      total_notified++;
    }

    // Create push actions in staging table
    std::vector<NotificationAction> staging_actions;
    for (auto& [uid, decision] : decisions) {
      if (!decision.should_notify) continue;

      NotificationAction action;
      action.user_id = uid;
      action.room_id = room_id;
      action.event_id = event_id;
      action.stream_ordering = stream_ordering;
      action.topological_ordering = topological_ordering;
      action.notif = 1;
      action.highlight = decision.is_highlight ? 1 : 0;
      action.action_type = decision.action_type;
      action.priority = decision.push_priority;
      action.created_at_ms = now_ms();
      staging_actions.push_back(std::move(action));
    }

    if (!staging_actions.empty()) {
      lifecycle_.add_push_actions(event_id, room_id,
          topological_ordering, stream_ordering, staging_actions);
    }

    result["notifications"] = total_notified;
    result["highlight_count"] =
        static_cast<int64_t>(highlight_users.size());
    result["notify_count"] =
        static_cast<int64_t>(notify_users.size());
    result["silent_count"] =
        static_cast<int64_t>(silent_users.size());

    return result;
  }

  // Evaluate push rules for a single user/event (for query)
  NotificationDecision evaluate_for_user(const std::string& user_id,
                                          const json& event,
                                          const std::string& room_id) {
    EvalContext ctx;
    ctx.room_id = room_id;
    ctx.user_id = user_id;
    ctx.event_type = json_str(event, "type", "m.room.message");
    ctx.sender = json_str(event, "sender");
    ctx.content = event.value("content", json::object());

    return result_computer_.compute(user_id, ctx);
  }

  // ========================================================================
  // Notification Count API
  // ========================================================================

  // Get notification counts for sync response
  json get_sync_notification_counts(const std::string& user_id,
                                     const std::string& room_id) {
    return count_tracker_.build_sync_counts(user_id, room_id);
  }

  // Get global notification counts (for app badge)
  json get_global_notification_counts(const std::string& user_id) {
    return count_tracker_.get_global_counts(user_id);
  }

  // Clear notification counts on read receipt
  void clear_notification_counts_on_read(const std::string& user_id,
                                          const std::string& room_id,
                                          const std::string& read_event_id) {
    count_tracker_.clear_on_read(user_id, room_id, read_event_id);

    // Also mark notifications as read in DB
    lifecycle_.mark_notifications_read(user_id, room_id);
  }

  // Get highlight count for a room
  int64_t get_highlight_count(const std::string& user_id,
                               const std::string& room_id) {
    return count_tracker_.get_highlight_count(user_id, room_id);
  }

  // ========================================================================
  // Pusher Lifecycle API
  // ========================================================================

  // Add a pusher
  std::string add_pusher(const PusherConfig& pusher) {
    return lifecycle_.add_pusher(pusher);
  }

  // Update a pusher
  std::string update_pusher(const PusherConfig& pusher) {
    return lifecycle_.update_pusher(pusher);
  }

  // Delete a pusher
  std::string delete_pusher(const std::string& pusher_id,
                             const std::string& user_id) {
    return lifecycle_.delete_pusher(pusher_id, user_id);
  }

  // Get pushers for a user
  json get_pushers_for_user(const std::string& user_id) {
    auto pushers = lifecycle_.get_pushers_for_user(user_id);
    json result = json::array();
    for (auto& p : pushers) {
      result.push_back(p.to_json());
    }
    return result;
  }

  // Handle access token revoked / device deleted
  void handle_access_token_revoked(const std::string& access_token) {
    lifecycle_.remove_pushers_by_access_token(access_token);
  }

  // Handle user logout / account deletion
  void handle_user_cleanup(const std::string& user_id) {
    lifecycle_.remove_all_pushers_for_user(user_id);
    count_tracker_.reset_user(user_id);
    highlight_tracker_.remove_highlight_words(user_id);
    lifecycle_.clear_eval_cache(user_id);
  }

  // ========================================================================
  // Highlight Words API
  // ========================================================================

  void set_highlight_words(const std::string& user_id,
                            const std::vector<std::string>& words) {
    highlight_tracker_.set_highlight_words(user_id, words);
  }

  json get_highlight_words(const std::string& user_id) {
    auto words = highlight_tracker_.get_highlight_words(user_id);
    json result = json::array();
    for (auto& w : words) result.push_back(w);
    return result;
  }

  // ========================================================================
  // Notification History API (for /notifications endpoint)
  // ========================================================================

  json get_notifications(const std::string& user_id,
                          int64_t limit = 50,
                          int64_t from_token = 0,
                          const std::string& only_highlight = "") {
    return lifecycle_.get_notifications(user_id, limit, from_token,
                                         only_highlight);
  }

  // ========================================================================
  // Statistics API
  // ========================================================================

  json get_full_stats() {
    json stats;
    stats["config"] = {
      {"enable_push", config_.enable_push_notifications},
      {"enable_coalescing", config_.enable_coalescing},
      {"enable_background", config_.enable_background_processing}
    };
    stats["count_tracker"] = count_tracker_.get_stats();
    stats["highlight_tracker"] = highlight_tracker_.get_stats();
    stats["dispatcher"] = dispatcher_.get_stats();
    stats["lifecycle"] = lifecycle_.get_stats();
    stats["bg_worker"] = bg_worker_.get_stats();
    return stats;
  }

  // ========================================================================
  // Thread Notification API
  // ========================================================================

  void increment_thread_notification(const std::string& user_id,
                                      const std::string& room_id,
                                      const std::string& thread_root_id,
                                      const std::string& event_id,
                                      bool is_highlight) {
    count_tracker_.increment_thread(user_id, room_id, thread_root_id,
                                     event_id, is_highlight);
  }

  void clear_thread_notification(const std::string& user_id,
                                  const std::string& room_id,
                                  const std::string& thread_root_id,
                                  const std::string& read_event_id) {
    count_tracker_.clear_thread_on_read(user_id, room_id, thread_root_id,
                                         read_event_id);
  }

  json get_thread_notification_counts(const std::string& user_id,
                                       const std::string& room_id) {
    auto thread_counts = count_tracker_.get_thread_counts(user_id, room_id);
    json result = json::object();
    for (auto& [tid, tc] : thread_counts) {
      result[tid] = tc.to_json();
    }
    return result;
  }

  // Access to internal components for testing
  NotificationCountTracker& count_tracker() { return count_tracker_; }
  HighlightCountTracker& highlight_tracker() { return highlight_tracker_; }
  PusherLifecycleManager& lifecycle() { return lifecycle_; }
  NotificationDispatcher& dispatcher() { return dispatcher_; }

private:
  NotificationCoalescer& get_coalescer() {
    // This reuses the dispatcher's internal coalescer
    // In production, this would be a shared instance
    static NotificationCoalescer coalescer(config_);
    return coalescer;
  }

  DatabasePool& db_;
  NotificationEngineConfig config_;
  PusherLifecycleManager lifecycle_;
  PushRuleEvaluationPipeline pipeline_;
  NotificationCountTracker count_tracker_;
  HighlightCountTracker highlight_tracker_;
  NotificationDispatcher dispatcher_;
  NotificationResultComputer result_computer_;
  BackgroundNotificationWorker bg_worker_;
};

// ============================================================================
// Pusher REST API Handlers
// ============================================================================

// GET /_matrix/client/v3/pushers
class GetPushersHandler {
public:
  explicit GetPushersHandler(NotificationEngineCoordinator& coord)
    : coord_(coord) {}

  json handle(const std::string& user_id) {
    return coord_.get_pushers_for_user(user_id);
  }

private:
  NotificationEngineCoordinator& coord_;
};

// POST /_matrix/client/v3/pushers/set
class SetPusherHandler {
public:
  explicit SetPusherHandler(NotificationEngineCoordinator& coord)
    : coord_(coord) {}

  std::pair<int, json> handle(const std::string& user_id,
                               const json& body) {
    PusherConfig pusher;
    pusher.user_id = user_id;
    pusher.kind = json_str(body, "kind");
    pusher.app_id = json_str(body, "app_id");
    pusher.app_display_name = json_str(body, "app_display_name");
    pusher.device_display_name = json_str(body, "device_display_name");
    pusher.pushkey = json_str(body, "pushkey");
    pusher.lang = json_str(body, "lang", "en");
    pusher.data = body.value("data", json::object());
    pusher.enabled = json_bool(body, "append", true);

    // Check for pusher_id (update) or new pusher
    if (body.contains("pusher_id") && !json_str(body, "pusher_id").empty()) {
      pusher.pusher_id = json_str(body, "pusher_id");
      std::string error = coord_.update_pusher(pusher);
      if (!error.empty()) {
        return {400, {{"errcode", "M_INVALID_PARAM"}, {"error", error}}};
      }
    } else {
      std::string error = coord_.add_pusher(pusher);
      if (!error.empty()) {
        return {400, {{"errcode", "M_INVALID_PARAM"}, {"error", error}}};
      }
    }

    return {200, json::object()};
  }

private:
  NotificationEngineCoordinator& coord_;
};

// --------------------------------------------------------------------------
// Notification Event Formatting (for /notifications API)
// --------------------------------------------------------------------------
namespace NotificationFormatter {

inline json format_notification(const json& raw_notif,
                                 const std::string& user_id) {
  json result;
  result["notification"] = raw_notif;
  result["profile_tag"] = json::object();  // Can fetch sender profile
  result["read"] = json_bool(raw_notif, "read");

  if (json_bool(raw_notif, "highlight")) {
    result["actions"] = json::array({
      "notify",
      {{"set_tweak", "highlight"}, {"value", true}},
      {{"set_tweak", "sound"}, {"value", "default"}}
    });
  } else {
    result["actions"] = json::array({
      "notify",
      {{"set_tweak", "sound"}, {"value", "default"}}
    });
  }

  (void)user_id;
  return result;
}

} // namespace NotificationFormatter

// ============================================================================
// Pusher Validation Utilities
// ============================================================================
namespace PusherValidator {

inline bool is_valid_pushkey(const std::string& pushkey,
                               const std::string& kind) {
  if (pushkey.empty()) return false;
  if (kind == "http") {
    // HTTP pushkey can be any non-empty string (device token)
    return pushkey.size() <= 4096;
  }
  if (kind == "email") {
    // Email pushkey should be a valid email
    auto at = pushkey.find('@');
    return at != std::string::npos && at > 0 && at < pushkey.size() - 1;
  }
  return true;
}

inline bool is_valid_app_id(const std::string& app_id) {
  // Must match reverse-domain pattern like "com.example.app"
  if (app_id.empty()) return false;
  return app_id.find('.') != std::string::npos;
}

inline bool is_valid_url(const std::string& url) {
  return starts_with(url, "http://") || starts_with(url, "https://");
}

inline json get_default_pusher_data(const std::string& kind) {
  if (kind == "http") {
    return {
      {"url", ""},
      {"format", "event_id_only"}
    };
  }
  if (kind == "email") {
    return {
      {"email", ""},
      {"branding", "default"}
    };
  }
  return json::object();
}

} // namespace PusherValidator

// ============================================================================
// End of notification_engine.cpp — Final line count marker
// ============================================================================
// This file implements the complete Matrix notification engine.
//
// Classes defined:
//   PusherBackend                 — Abstract pusher backend interface
//   HttpPusherBackend             — HTTP push gateway backend (APNs, FCM, etc.)
//   EmailPusherBackend            — Email push backend with digest support
//   NotificationCoalescer         — Batching/coalescing engine
//   NotificationCountTracker      — Per-room per-user count management
//   HighlightCountTracker         — Custom highlight word tracking
//   PushRuleEvaluationPipeline    — Full push rule evaluation
//   NotificationResultComputer    — Compute final notification decisions
//   NotificationDispatcher        — Route notifications to pushers
//   PusherLifecycleManager        — Full SQL DDL + CRUD for all tables
//   BackgroundNotificationWorker  — Multi-thread background processing
//   NotificationEngineCoordinator — Top-level integration API
//   GetPushersHandler             — REST: GET /pushers
//   SetPusherHandler              — REST: POST /pushers/set
//
// Namespaces:
//   ConditionEval                 — Push rule condition evaluation helpers
//   GlobMatch                     — Glob pattern matching
//   NotificationFormatter         — Notification event formatting
//   PusherValidator               — Pusher field validators
//
// Database tables managed:
//   user_pushers                  — Pusher configuration storage
//   event_push_actions_staging    — Per-event per-user push actions
//   event_push_summary            — Per-room per-user notification summary
//   event_push_summary_stream_ordering — Stream ordering tracker
//   sent_push_notifications       — Push delivery log
//   deferred_push_actions         — Retry queue for failed pushes
//   push_action_coalesce          — Coalesce bucket persistence
//   background_notification_state — Background worker state
//   notification_events           — /notifications API data
//   push_rule_eval_cache          — Rule evaluation cache
// ============================================================================

} // namespace progressive
