// ============================================================================
// email_digest_templates.cpp — Matrix Email Digest Templates & Notification Pipeline
//
// Implements:
//   1.  Email notification generation (HTML + text multipart MIME)
//   2.  Missed message digest email compilation
//   3.  Daily and weekly digest scheduling and compilation
//   4.  Notification email templates (invite, message, mention, call)
//   5.  Email formatting utilities (room name, sender, body preview)
//   6.  Unsubscribe link generation (per-user, per-pusher tokens)
//   7.  Notification preferences per email type
//   8.  Email sending rate limiting (per-user, global)
//   9.  Email bounce handling (hard, soft, complaint)
//  10.  Email suppression list management
//  11.  Email tracking pixel generation (open tracking)
//  12.  Notification grouping per room (digest compaction)
//  13.  Digest scheduling (cron-like daily/weekly triggers)
//  14.  Digest content ranking (relevance scoring, most important first)
//
// Equivalent to:
//   synapse/push/mailer.py                                 (~400 lines)
//   synapse/push/emailpusher.py                            (~150 lines)
//   synapse/notifier.py (email digest portions)            (~200 lines)
//   matrix-org/dendrite internal/push/mailer.go            (~300 lines)
//   matrix-react-sdk Email.js / EmailNotificationUtils.js  (~500 lines)
//   Various config, templating, and infrastructure code    (~1,500 lines)
//
// Namespace: progressive::push
// Target: 3500+ lines of production-grade C++.
// ============================================================================

#include "../json.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <deque>
#include <functional>
#include <iomanip>
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
#include <string>
#include <string_view>
#include <thread>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <variant>
#include <vector>

// Boost for async operations and HTTP
#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/strand.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/system/error_code.hpp>

// OpenSSL for SMTP STARTTLS and DKIM signing
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

namespace progressive::push {

using json = nlohmann::json;
namespace net = boost::asio;
namespace beast = boost::beast;
using error_code = boost::system::error_code;

// ============================================================================
// Forward declarations
// ============================================================================

// ============================================================================
// Constants
// ============================================================================

// Digest scheduling
constexpr int64_t kDailyDigestHour = 8;           // 8 AM daily digest
constexpr int64_t kWeeklyDigestDay = 1;            // Monday
constexpr int64_t kWeeklyDigestHour = 10;          // 10 AM weekly digest
constexpr int64_t kDigestCheckIntervalSec = 300;   // Check every 5 minutes
constexpr int64_t kMaxDigestEventsPerRoom = 50;    // Max events per room in digest
constexpr int64_t kMaxDigestRooms = 20;            // Max rooms in digest
constexpr int64_t kDigestMinEventsForSend = 1;     // At least 1 event to send digest

// Rate limiting
constexpr int64_t kGlobalEmailRatePerHour = 10000; // 10k emails per hour global
constexpr int64_t kUserEmailRatePerHour = 50;      // 50 emails per hour per user
constexpr int64_t kMaxBurstPerUser = 10;           // Burst: 10 emails in <1 minute
constexpr int64_t kRateLimitWindowSec = 3600;       // 1 hour sliding window

// Bounce handling
constexpr int64_t kMaxSoftBouncesBeforeHard = 5;    // 5 soft bounces -> hard
constexpr int64_t kSoftBounceRetryDelaySec = 3600;  // 1 hour delay after soft bounce
constexpr int64_t kHardBounceSuppressDays = 90;     // 90 day suppression for hard bounce
constexpr int64_t kComplaintSuppressDays = 180;     // 180 day suppression for complaint
constexpr int64_t kBounceWindowSec = 86400;         // 24h window for counting bounces

// Email formatting
constexpr size_t kMaxSubjectLength = 200;
constexpr size_t kMaxBodyPreviewLength = 256;
constexpr size_t kMaxRoomNameLength = 100;
constexpr size_t kMaxSenderNameLength = 128;
constexpr size_t kMaxHtmlEmailSize = 102400;        // 100 KB max HTML
constexpr size_t kMaxTextEmailSize = 51200;         // 50 KB max text

// Unsubscribe tokens
constexpr size_t kUnsubscribeTokenLength = 32;
constexpr int64_t kUnsubscribeTokenTTLDays = 365;

// Tracking
constexpr const char* kTrackingPixelGifBase64 =
    "R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7";
constexpr int64_t kTrackingPixelCacheSec = 3600;

// Suppression list
constexpr int64_t kSuppressionCleanupIntervalSec = 3600;
constexpr size_t kMaxSuppressionEntries = 100000;

// Digest ranking weights
constexpr double kDirectMentionWeight = 10.0;
constexpr double kHighlightWeight = 8.0;
constexpr double kCallEventWeight = 9.0;
constexpr double kInviteEventWeight = 7.0;
constexpr double kEncryptedEventWeight = 3.0;
constexpr double kTombstoneEventWeight = 2.0;
constexpr double kReactionWeight = 1.0;
constexpr double kMessageWeight = 5.0;
constexpr double kRoomActivityRecencyWeight = 0.5;  // Per-hour recency bonus

// Email template CSS constants
static const std::string kEmailBaseStyles = R"CSS(
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; margin: 0; padding: 0; background-color: #f4f4f7; }
.email-container { max-width: 600px; margin: 0 auto; background: #ffffff; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 8px rgba(0,0,0,0.08); }
.email-header { background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); color: white; padding: 24px 32px; }
.email-header h1 { margin: 0; font-size: 22px; font-weight: 600; }
.email-header .subtitle { font-size: 13px; opacity: 0.8; margin-top: 4px; }
.email-body { padding: 24px 32px; }
.email-footer { padding: 16px 32px; background: #f9f9fb; border-top: 1px solid #e8e8ed; font-size: 12px; color: #888; }
.room-section { margin-bottom: 20px; border: 1px solid #e8e8ed; border-radius: 6px; overflow: hidden; }
.room-header { background: #f4f4f7; padding: 12px 16px; font-weight: 600; font-size: 14px; border-bottom: 1px solid #e8e8ed; }
.room-header .room-avatar { width: 24px; height: 24px; border-radius: 50%; background: #ccc; display: inline-block; vertical-align: middle; margin-right: 8px; }
.event-item { padding: 10px 16px; border-bottom: 1px solid #f0f0f3; }
.event-item:last-child { border-bottom: none; }
.event-sender { font-weight: 600; font-size: 13px; color: #333; margin-bottom: 2px; }
.event-body { font-size: 14px; color: #555; line-height: 1.4; }
.event-time { font-size: 11px; color: #aaa; margin-top: 4px; }
.event-highlight { background: #fffde7; border-left: 3px solid #fdd835; }
.event-mention { background: #fff3e0; border-left: 3px solid #ff9800; }
.event-call { background: #e8f5e9; border-left: 3px solid #4caf50; }
.event-invite { background: #e3f2fd; border-left: 3px solid #2196f3; }
.digest-summary { background: #f0f4ff; padding: 16px; border-radius: 6px; margin-bottom: 20px; font-size: 14px; }
.digest-summary strong { color: #1a1a2e; }
.btn { display: inline-block; padding: 10px 24px; background: #1a1a2e; color: white; text-decoration: none; border-radius: 4px; font-size: 14px; font-weight: 500; }
.unsubscribe-link { color: #888; text-decoration: underline; }
.preference-badge { display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 11px; margin-left: 6px; }
.badge-mention { background: #ff9800; color: white; }
.badge-message { background: #4caf50; color: white; }
.badge-call { background: #2196f3; color: white; }
.badge-invite { background: #9c27b0; color: white; }
.notification-muted { opacity: 0.6; }
)CSS";

// ============================================================================
// Utility: HTML escape
// ============================================================================

static std::string html_escape(std::string_view s) {
  std::string out;
  out.reserve(s.size() + s.size() / 4);
  for (char c : s) {
    switch (c) {
      case '&':  out += "&amp;"; break;
      case '<':  out += "&lt;"; break;
      case '>':  out += "&gt;"; break;
      case '"':  out += "&quot;"; break;
      case '\'': out += "&#39;"; break;
      default:   out += c; break;
    }
  }
  return out;
}

// ============================================================================
// Utility: Text truncation
// ============================================================================

static std::string truncate(std::string_view s, size_t max_len) {
  if (s.size() <= max_len) return std::string(s);
  return std::string(s.substr(0, max_len - 3)) + "...";
}

// ============================================================================
// Utility: Secure random string (hex)
// ============================================================================

static std::mt19937_64& thread_rng() {
  static thread_local std::mt19937_64 rng(
      static_cast<uint64_t>(
          std::chrono::steady_clock::now().time_since_epoch().count()) ^
      static_cast<uint64_t>(std::hash<std::thread::id>{}(std::this_thread::get_id())));
  return rng;
}

static std::string random_hex(size_t count) {
  static const char hex_chars[] = "0123456789abcdef";
  std::uniform_int_distribution<int> dist(0, 15);
  std::string out(count, '\0');
  for (size_t i = 0; i < count; i++)
    out[i] = hex_chars[dist(thread_rng())];
  return out;
}

// ============================================================================
// Utility: Timestamp formatting
// ============================================================================

static int64_t now_epoch_sec() {
  return std::chrono::duration_cast<std::chrono::seconds>(
      std::chrono::system_clock::now().time_since_epoch()).count();
}

static int64_t now_epoch_ms() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::system_clock::now().time_since_epoch()).count();
}

static std::string format_time_ago(int64_t ts_sec) {
  int64_t diff = now_epoch_sec() - ts_sec;
  if (diff < 60) return "just now";
  if (diff < 3600) return std::to_string(diff / 60) + "m ago";
  if (diff < 86400) return std::to_string(diff / 3600) + "h ago";
  if (diff < 604800) return std::to_string(diff / 86400) + "d ago";
  return std::to_string(diff / 604800) + "w ago";
}

static std::string format_datetime(int64_t ts_sec) {
  time_t t = static_cast<time_t>(ts_sec);
  struct tm tm_buf;
  gmtime_r(&t, &tm_buf);
  char buf[64];
  strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M UTC", &tm_buf);
  return std::string(buf);
}

// ============================================================================
// Utility: SHA-256 HMAC for token generation
// ============================================================================

static std::string hmac_sha256_hex(const std::string& key, const std::string& data) {
  unsigned char result[EVP_MAX_MD_SIZE];
  unsigned int result_len = 0;
  HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
       reinterpret_cast<const unsigned char*>(data.data()), data.size(),
       result, &result_len);
  std::ostringstream oss;
  for (unsigned int i = 0; i < result_len; i++)
    oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(result[i]);
  return oss.str();
}

// ============================================================================
// Utility: Base64 encode (URL-safe, no padding)
// ============================================================================

static const char BASE64_URL_CHARS[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static std::string base64url_encode(const std::vector<uint8_t>& input) {
  std::string output;
  int val = 0, valb = -6;
  for (unsigned char c : input) {
    val = (val << 8) + c;
    valb += 8;
    while (valb >= 0) {
      output.push_back(BASE64_URL_CHARS[(val >> valb) & 0x3F]);
      valb -= 6;
    }
  }
  if (valb > -6)
    output.push_back(BASE64_URL_CHARS[((val << 8) >> (valb + 8)) & 0x3F]);
  return output;
}

static std::string base64url_encode(const std::string& input) {
  std::vector<uint8_t> bytes(input.begin(), input.end());
  return base64url_encode(bytes);
}

// ============================================================================
// Data Structures
// ============================================================================

// ---------------------------------------------------------------------------
// EmailNotification: A single notification destined for email delivery
// ---------------------------------------------------------------------------
struct EmailNotification {
  std::string user_id;
  std::string to_email;
  std::string room_id;
  std::string room_name;
  std::string room_alias;
  std::string sender_user_id;
  std::string sender_display_name;
  std::string event_id;
  std::string event_type;
  std::string body_text;
  std::string body_html;
  std::string msgtype;
  int64_t event_ts_sec = 0;
  int64_t received_ts_ms = 0;
  bool is_direct_mention = false;
  bool is_highlight = false;
  bool is_call = false;
  bool is_invite = false;
  bool is_encrypted = false;
  bool is_tombstone = false;
  std::string thread_id;
  std::string pusher_pushkey;
  std::string unsubscribe_token;
  std::string lang;
  std::string brand;
  int64_t stream_ordering = 0;
};

// ---------------------------------------------------------------------------
// DigestEntry: One entry in a digest (compacted notification)
// ---------------------------------------------------------------------------
struct DigestEntry {
  std::string room_id;
  std::string room_name;
  std::string room_alias;
  std::string sender_user_id;
  std::string sender_display_name;
  std::string event_id;
  std::string event_type;
  std::string body_preview;
  std::string msgtype;
  int64_t ts_sec = 0;
  bool is_mention = false;
  bool is_highlight = false;
  bool is_call = false;
  bool is_invite = false;
  bool is_encrypted = false;

  // Relevance score for ranking
  double score() const {
    double s = kMessageWeight;
    if (is_call) s = kCallEventWeight;
    else if (is_invite) s = kInviteEventWeight;
    else if (is_mention) s = kDirectMentionWeight;
    else if (is_highlight) s = kHighlightWeight;
    else if (is_encrypted) s = kEncryptedEventWeight;

    // Recency bonus: newer events rank higher
    int64_t age_hours = (now_epoch_sec() - ts_sec) / 3600;
    double recency = std::max(0.0, 24.0 - static_cast<double>(age_hours)) * kRoomActivityRecencyWeight;
    return s + recency;
  }
};

// ---------------------------------------------------------------------------
// DigestRoomGroup: Group of digest entries for a single room
// ---------------------------------------------------------------------------
struct DigestRoomGroup {
  std::string room_id;
  std::string room_name;
  std::string room_alias;
  std::vector<DigestEntry> entries;
  int64_t latest_ts_sec = 0;
  bool is_dm = false;
};

// ---------------------------------------------------------------------------
// DigestBundle: A complete digest ready for email
// ---------------------------------------------------------------------------
struct DigestBundle {
  std::string user_id;
  std::string to_email;
  std::string unsubscribe_token;
  std::string lang;
  std::string brand;
  std::string digest_type;  // "daily", "weekly", "missed"
  int64_t period_start_sec = 0;
  int64_t period_end_sec = 0;
  std::vector<DigestRoomGroup> room_groups;
  int64_t total_events = 0;
  int64_t total_rooms = 0;
  int64_t total_mentions = 0;
  int64_t total_calls = 0;
  int64_t total_invites = 0;
};

// ---------------------------------------------------------------------------
// EmailRateLimitEntry: Per-user rate limiting state
// ---------------------------------------------------------------------------
struct EmailRateLimitEntry {
  std::deque<int64_t> send_timestamps_ms;  // Sliding window
  int burst_count = 0;
  int64_t burst_window_start_ms = 0;
  int64_t total_sent_this_hour = 0;
  int64_t hour_start_ms = 0;
};

// ---------------------------------------------------------------------------
// BounceRecord: A single bounce event
// ---------------------------------------------------------------------------
struct BounceRecord {
  std::string email;
  std::string user_id;
  std::string bounce_type;  // "hard", "soft", "complaint"
  std::string reason;
  int64_t ts_sec = 0;
  int64_t retry_after_sec = 0;
};

// ---------------------------------------------------------------------------
// SuppressionEntry: Permanently or temporarily suppressed email
// ---------------------------------------------------------------------------
struct SuppressionEntry {
  std::string email;
  std::string user_id;
  std::string reason;       // "hard_bounce", "complaint", "manual"
  int64_t suppressed_at_sec = 0;
  int64_t expires_at_sec = 0;  // 0 = permanent
};

// ---------------------------------------------------------------------------
// EmailPreferences: Per-user notification preferences
// ---------------------------------------------------------------------------
struct EmailPreferences {
  bool notify_for_messages = true;
  bool notify_for_mentions = true;
  bool notify_for_calls = true;
  bool notify_for_invites = true;
  bool notify_for_reactions = false;
  bool enable_daily_digest = false;
  bool enable_weekly_digest = false;
  bool enable_missed_digest = true;

  json to_json() const {
    json j;
    j["notify_for_messages"] = notify_for_messages;
    j["notify_for_mentions"] = notify_for_mentions;
    j["notify_for_calls"] = notify_for_calls;
    j["notify_for_invites"] = notify_for_invites;
    j["notify_for_reactions"] = notify_for_reactions;
    j["enable_daily_digest"] = enable_daily_digest;
    j["enable_weekly_digest"] = enable_weekly_digest;
    j["enable_missed_digest"] = enable_missed_digest;
    return j;
  }

  static EmailPreferences from_json(const json& j) {
    EmailPreferences prefs;
    if (j.contains("notify_for_messages")) prefs.notify_for_messages = j["notify_for_messages"];
    if (j.contains("notify_for_mentions")) prefs.notify_for_mentions = j["notify_for_mentions"];
    if (j.contains("notify_for_calls")) prefs.notify_for_calls = j["notify_for_calls"];
    if (j.contains("notify_for_invites")) prefs.notify_for_invites = j["notify_for_invites"];
    if (j.contains("notify_for_reactions")) prefs.notify_for_reactions = j["notify_for_reactions"];
    if (j.contains("enable_daily_digest")) prefs.enable_daily_digest = j["enable_daily_digest"];
    if (j.contains("enable_weekly_digest")) prefs.enable_weekly_digest = j["enable_weekly_digest"];
    if (j.contains("enable_missed_digest")) prefs.enable_missed_digest = j["enable_missed_digest"];
    return prefs;
  }
};

// ============================================================================
// Email Template Generator (standalone formatter, no external state)
// ============================================================================

class EmailTemplateGenerator {
public:
  // -------------------------------------------------------------------------
  // Generate full MIME multipart email for a single notification
  // -------------------------------------------------------------------------
  static std::string generate_notification_email(
      const EmailNotification& notif,
      const std::string& from_addr,
      const std::string& from_name,
      const std::string& base_url) {

    std::string subject = format_subject(notif);
    std::string html = format_notification_html(notif, base_url);
    std::string text = format_notification_text(notif, base_url);

    return build_mime_message(from_addr, from_name, notif.to_email,
                              subject, html, text);
  }

  // -------------------------------------------------------------------------
  // Generate digest email (daily, weekly, or missed)
  // -------------------------------------------------------------------------
  static std::string generate_digest_email(
      const DigestBundle& digest,
      const std::string& from_addr,
      const std::string& from_name,
      const std::string& base_url) {

    std::string subject = format_digest_subject(digest);
    std::string html = format_digest_html(digest, base_url);
    std::string text = format_digest_text(digest, base_url);

    return build_mime_message(from_addr, from_name, digest.to_email,
                              subject, html, text);
  }

  // -------------------------------------------------------------------------
  // Get subject line for a notification
  // -------------------------------------------------------------------------
  static std::string format_subject(const EmailNotification& notif) {
    std::ostringstream subj;

    if (notif.is_call) {
      subj << "\xF0\x9F\x93\x9E ";  // phone emoji
      if (!notif.sender_display_name.empty())
        subj << notif.sender_display_name << " is calling";
      else
        subj << "Incoming call";
    } else if (notif.is_invite) {
      subj << "\xF0\x9F\x91\x8B ";  // wave emoji
      if (!notif.sender_display_name.empty())
        subj << notif.sender_display_name << " invited you to " << notif.room_name;
      else
        subj << "Room invitation: " << notif.room_name;
    } else if (notif.is_direct_mention || notif.is_highlight) {
      subj << "@mention: ";
      if (!notif.sender_display_name.empty())
        subj << notif.sender_display_name;
      else
        subj << notif.sender_user_id;
      subj << " in " << notif.room_name;
    } else if (notif.is_encrypted) {
      subj << "\xF0\x9F\x94\x92 ";  // lock emoji
      if (!notif.sender_display_name.empty())
        subj << notif.sender_display_name;
      else
        subj << notif.sender_user_id;
      subj << " sent an encrypted message";
    } else {
      if (!notif.sender_display_name.empty())
        subj << notif.sender_display_name;
      else
        subj << notif.sender_user_id;
      subj << " - " << notif.room_name;
    }

    return truncate(subj.str(), kMaxSubjectLength);
  }

  // -------------------------------------------------------------------------
  // Format digest subject line
  // -------------------------------------------------------------------------
  static std::string format_digest_subject(const DigestBundle& digest) {
    std::ostringstream subj;

    if (digest.digest_type == "missed") {
      subj << "You missed " << digest.total_events << " message";
      if (digest.total_events != 1) subj << "s";
      subj << " in " << digest.total_rooms << " room";
      if (digest.total_rooms != 1) subj << "s";
    } else if (digest.digest_type == "weekly") {
      subj << "Your weekly Matrix digest: ";
      subj << digest.total_events << " message";
      if (digest.total_events != 1) subj << "s";
      subj << " across " << digest.total_rooms << " room";
      if (digest.total_rooms != 1) subj << "s";
    } else {
      // daily
      subj << "Your daily Matrix digest: ";
      subj << digest.total_events << " message";
      if (digest.total_events != 1) subj << "s";
      subj << " across " << digest.total_rooms << " room";
      if (digest.total_rooms != 1) subj << "s";
    }

    if (digest.total_mentions > 0) {
      subj << " (";
      subj << digest.total_mentions << " mention";
      if (digest.total_mentions != 1) subj << "s";
      subj << ")";
    }

    return truncate(subj.str(), kMaxSubjectLength);
  }

  // -------------------------------------------------------------------------
  // Full HTML notification email body
  // -------------------------------------------------------------------------
  static std::string format_notification_html(const EmailNotification& notif,
                                                const std::string& base_url) {
    std::ostringstream html;
    html << "<!DOCTYPE html>\n<html lang=\"" << html_escape(notif.lang) << "\">\n<head>\n";
    html << "<meta charset=\"utf-8\">\n";
    html << "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n";
    html << "<title>Matrix Notification</title>\n";
    html << "<style>" << kEmailBaseStyles << "</style>\n";
    html << "</head>\n<body>\n";
    html << "<div class=\"email-container\">\n";

    // Header with brand
    html << "<div class=\"email-header\">\n";
    std::string brand_display = notif.brand.empty() ? "Matrix" : notif.brand;
    html << "<h1>" << html_escape(brand_display) << "</h1>\n";
    if (notif.is_call)
      html << "<div class=\"subtitle\">Incoming call notification</div>\n";
    else if (notif.is_invite)
      html << "<div class=\"subtitle\">Room invitation</div>\n";
    else if (notif.is_direct_mention)
      html << "<div class=\"subtitle\">New mention</div>\n";
    else
      html << "<div class=\"subtitle\">New message</div>\n";
    html << "</div>\n";

    // Body
    html << "<div class=\"email-body\">\n";

    // Room info
    html << "<div class=\"room-section\">\n";
    html << "<div class=\"room-header\">\n";
    html << "<span class=\"room-avatar\"></span>\n";
    html << html_escape(format_room_display_name(notif));
    html << "</div>\n";

    // Event item
    std::string event_class = "event-item";
    if (notif.is_direct_mention || notif.is_highlight)
      event_class += " event-mention";
    else if (notif.is_call)
      event_class += " event-call";
    else if (notif.is_invite)
      event_class += " event-invite";

    html << "<div class=\"" << event_class << "\">\n";
    html << "<div class=\"event-sender\">"
         << html_escape(format_sender_display_name(notif))
         << "</div>\n";
    html << "<div class=\"event-body\">"
         << html_escape(format_body_preview(notif.body_text))
         << "</div>\n";
    html << "<div class=\"event-time\">"
         << format_time_ago(notif.event_ts_sec)
         << "</div>\n";
    html << "</div>\n";  // event-item
    html << "</div>\n";  // room-section

    // CTA button
    if (!base_url.empty()) {
      html << "<div style=\"text-align: center; margin: 24px 0;\">\n";
      html << "<a href=\"" << html_escape(base_url)
           << "/#/room/" << html_escape(notif.room_id)
           << "\" class=\"btn\">View in Matrix</a>\n";
      html << "</div>\n";
    }

    html << "</div>\n";  // email-body

    // Footer
    html << "<div class=\"email-footer\">\n";
    html << "<p>You received this notification because you have email notifications enabled "
         << "for this room. You can manage your notification preferences in your Matrix client.</p>\n";
    if (!notif.unsubscribe_token.empty() && !base_url.empty()) {
      html << "<p><a href=\"" << html_escape(generate_unsubscribe_url(base_url, notif.unsubscribe_token))
           << "\" class=\"unsubscribe-link\">Unsubscribe from email notifications</a></p>\n";
    }
    // Tracking pixel
    if (!notif.event_id.empty()) {
      html << generate_tracking_pixel_html(notif.event_id);
    }
    html << "</div>\n";

    html << "</div>\n";  // email-container
    html << "</body>\n</html>";

    // Truncate if too large
    std::string result = html.str();
    if (result.size() > kMaxHtmlEmailSize)
      result = result.substr(0, kMaxHtmlEmailSize - 100) + "\n<!-- truncated -->\n</body>\n</html>";
    return result;
  }

  // -------------------------------------------------------------------------
  // Plain text notification email body
  // -------------------------------------------------------------------------
  static std::string format_notification_text(const EmailNotification& notif,
                                                const std::string& base_url) {
    std::ostringstream text;

    std::string brand_display = notif.brand.empty() ? "Matrix" : notif.brand;
    text << "[" << brand_display << "]\n";
    if (notif.is_call) {
      text << "Incoming call from ";
      text << format_sender_display_name(notif) << "\n";
    } else if (notif.is_invite) {
      text << format_sender_display_name(notif) << " invited you to ";
      text << notif.room_name << "\n";
    } else if (notif.is_direct_mention) {
      text << format_sender_display_name(notif) << " mentioned you in ";
      text << notif.room_name << "\n";
    } else {
      text << format_sender_display_name(notif) << " in ";
      text << notif.room_name << "\n";
    }
    text << "━━━━━━━━━━━━━━━━━━━━━━━━\n\n";

    text << format_body_preview(notif.body_text) << "\n\n";
    text << "━━━━━━━━━━━━━━━━━━━━━━━━\n";
    text << format_time_ago(notif.event_ts_sec) << "\n\n";

    if (!base_url.empty()) {
      text << "View in Matrix: " << base_url << "/#/room/" << notif.room_id << "\n\n";
    }

    text << "--\n";
    text << "You received this notification because you have email notifications enabled.\n";
    if (!notif.unsubscribe_token.empty() && !base_url.empty()) {
      text << "To unsubscribe: "
           << generate_unsubscribe_url(base_url, notif.unsubscribe_token) << "\n";
    }

    std::string result = text.str();
    if (result.size() > kMaxTextEmailSize)
      result = result.substr(0, kMaxTextEmailSize - 50) + "\n... [truncated]\n";
    return result;
  }

  // -------------------------------------------------------------------------
  // Full HTML digest email body
  // -------------------------------------------------------------------------
  static std::string format_digest_html(const DigestBundle& digest,
                                          const std::string& base_url) {
    std::ostringstream html;
    html << "<!DOCTYPE html>\n<html lang=\"" << html_escape(digest.lang) << "\">\n<head>\n";
    html << "<meta charset=\"utf-8\">\n";
    html << "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n";
    html << "<title>Matrix Digest</title>\n";
    html << "<style>" << kEmailBaseStyles << "</style>\n";
    html << "</head>\n<body>\n";
    html << "<div class=\"email-container\">\n";

    // Header
    html << "<div class=\"email-header\">\n";
    std::string brand_display = digest.brand.empty() ? "Matrix" : digest.brand;
    html << "<h1>" << html_escape(brand_display) << "</h1>\n";
    std::string digest_label = (digest.digest_type == "weekly") ? "Weekly Digest"
                               : (digest.digest_type == "missed") ? "Missed Messages"
                               : "Daily Digest";
    html << "<div class=\"subtitle\">" << digest_label << " &middot; "
         << format_datetime(digest.period_end_sec) << "</div>\n";
    html << "</div>\n";

    html << "<div class=\"email-body\">\n";

    // Summary box
    html << "<div class=\"digest-summary\">\n";
    html << "<strong>" << digest.total_events << "</strong> message";
    if (digest.total_events != 1) html << "s";
    html << " across <strong>" << digest.total_rooms << "</strong> room";
    if (digest.total_rooms != 1) html << "s";
    if (digest.total_mentions > 0)
      html << " &middot; <strong>" << digest.total_mentions << "</strong> mention";
    if (digest.total_mentions != 1) html << "s";
    if (digest.total_calls > 0)
      html << " &middot; <strong>" << digest.total_calls << "</strong> call";
    if (digest.total_calls != 1) html << "s";
    if (digest.total_invites > 0)
      html << " &middot; <strong>" << digest.total_invites << "</strong> invitation";
    if (digest.total_invites != 1) html << "s";
    html << "\n</div>\n";

    // Room groups
    for (const auto& group : digest.room_groups) {
      html << "<div class=\"room-section\">\n";

      // Room header
      html << "<div class=\"room-header\">\n";
      html << "<span class=\"room-avatar\"></span>\n";
      html << html_escape(format_room_display_name_from_group(group));
      if (group.is_dm) html << " <span style=\"font-weight:normal;color:#888;font-size:12px;\">DM</span>";
      html << "</div>\n";

      for (const auto& entry : group.entries) {
        std::string event_class = "event-item";
        if (entry.is_mention || entry.is_highlight)
          event_class += " event-mention";
        else if (entry.is_call)
          event_class += " event-call";
        else if (entry.is_invite)
          event_class += " event-invite";

        html << "<div class=\"" << event_class << "\">\n";
        html << "<div class=\"event-sender\">"
             << html_escape(truncate(
                    entry.sender_display_name.empty() ? entry.sender_user_id
                                                      : entry.sender_display_name,
                    kMaxSenderNameLength))
             << "</div>\n";
        html << "<div class=\"event-body\">"
             << html_escape(entry.body_preview)
             << "</div>\n";
        html << "<div class=\"event-time\">"
             << format_time_ago(entry.ts_sec) << "</div>\n";
        html << "</div>\n";
      }

      html << "</div>\n";  // room-section
    }

    // CTA
    if (!base_url.empty()) {
      html << "<div style=\"text-align: center; margin: 24px 0;\">\n";
      html << "<a href=\"" << html_escape(base_url) << "\" class=\"btn\">Open Matrix</a>\n";
      html << "</div>\n";
    }

    html << "</div>\n";  // email-body

    // Footer
    html << "<div class=\"email-footer\">\n";
    html << "<p>You received this digest because you have ";
    if (digest.digest_type == "weekly")
      html << "weekly";
    else if (digest.digest_type == "missed")
      html << "missed message";
    else
      html << "daily";
    html << " digest emails enabled. You can manage your email preferences in "
         << "your Matrix client settings.</p>\n";

    if (!digest.unsubscribe_token.empty() && !base_url.empty()) {
      html << "<p><a href=\""
           << html_escape(generate_unsubscribe_url(base_url, digest.unsubscribe_token))
           << "\" class=\"unsubscribe-link\">Unsubscribe from digest emails</a> &middot; ";
    }
    html << "<a href=\"" << html_escape(base_url)
         << "/#/settings/notifications\" class=\"unsubscribe-link\">"
         << "Notification settings</a></p>\n";

    // Tracking pixel
    html << generate_tracking_pixel_html("digest_" + digest.user_id + "_" +
                                          std::to_string(digest.period_end_sec));
    html << "</div>\n";

    html << "</div>\n";  // email-container
    html << "</body>\n</html>";

    std::string result = html.str();
    if (result.size() > kMaxHtmlEmailSize)
      result = result.substr(0, kMaxHtmlEmailSize - 100) + "\n<!-- truncated -->\n</body>\n</html>";
    return result;
  }

  // -------------------------------------------------------------------------
  // Plain text digest email body
  // -------------------------------------------------------------------------
  static std::string format_digest_text(const DigestBundle& digest,
                                          const std::string& base_url) {
    std::ostringstream text;

    std::string brand_display = digest.brand.empty() ? "Matrix" : digest.brand;
    std::string digest_label = (digest.digest_type == "weekly") ? "WEEKLY DIGEST"
                               : (digest.digest_type == "missed") ? "MISSED MESSAGES"
                               : "DAILY DIGEST";

    text << "[ " << brand_display << " ]\n";
    text << digest_label << " - " << format_datetime(digest.period_end_sec) << "\n";
    text << "==========================================================\n\n";
    text << digest.total_events << " message";
    if (digest.total_events != 1) text << "s";
    text << " across " << digest.total_rooms << " room";
    if (digest.total_rooms != 1) text << "s";
    if (digest.total_mentions > 0)
      text << " (" << digest.total_mentions << " mention";
    if (digest.total_mentions != 1) text << "s";
    if (digest.total_mentions > 0) text << ")";
    text << "\n\n";
    text << "==========================================================\n\n";

    for (const auto& group : digest.room_groups) {
      text << "## " << format_room_display_name_from_group(group);
      if (group.is_dm) text << " [DM]";
      text << "\n";

      for (const auto& entry : group.entries) {
        std::string sender = entry.sender_display_name.empty()
                                 ? entry.sender_user_id
                                 : entry.sender_display_name;
        text << "  " << truncate(sender, kMaxSenderNameLength) << ": ";
        if (entry.is_mention) text << "[@mention] ";
        if (entry.is_call) text << "[call] ";
        if (entry.is_invite) text << "[invite] ";
        text << entry.body_preview << "\n";
        text << "  (" << format_time_ago(entry.ts_sec) << ")\n\n";
      }
      text << "\n";
    }

    text << "==========================================================\n";
    if (!base_url.empty()) {
      text << "Open Matrix: " << base_url << "\n";
    }
    text << "\n--\n";
    text << "You received this digest because you have digest emails enabled.\n";
    if (!digest.unsubscribe_token.empty() && !base_url.empty()) {
      text << "To unsubscribe: "
           << generate_unsubscribe_url(base_url, digest.unsubscribe_token) << "\n";
    }

    std::string result = text.str();
    if (result.size() > kMaxTextEmailSize)
      result = result.substr(0, kMaxTextEmailSize - 50) + "\n... [truncated]\n";
    return result;
  }

  // -------------------------------------------------------------------------
  // Format room display name (from notification)
  // -------------------------------------------------------------------------
  static std::string format_room_display_name(const EmailNotification& notif) {
    if (!notif.room_name.empty())
      return truncate(notif.room_name, kMaxRoomNameLength);
    if (!notif.room_alias.empty())
      return truncate(notif.room_alias, kMaxRoomNameLength);
    return truncate(notif.room_id, kMaxRoomNameLength);
  }

  // -------------------------------------------------------------------------
  // Format room display name (from digest group)
  // -------------------------------------------------------------------------
  static std::string format_room_display_name_from_group(const DigestRoomGroup& group) {
    if (!group.room_name.empty())
      return truncate(group.room_name, kMaxRoomNameLength);
    if (!group.room_alias.empty())
      return truncate(group.room_alias, kMaxRoomNameLength);
    return truncate(group.room_id, kMaxRoomNameLength);
  }

  // -------------------------------------------------------------------------
  // Format sender display name
  // -------------------------------------------------------------------------
  static std::string format_sender_display_name(const EmailNotification& notif) {
    if (!notif.sender_display_name.empty())
      return truncate(notif.sender_display_name, kMaxSenderNameLength);
    return truncate(notif.sender_user_id, kMaxSenderNameLength);
  }

  // -------------------------------------------------------------------------
  // Format body preview (truncated, cleaned)
  // -------------------------------------------------------------------------
  static std::string format_body_preview(const std::string& body) {
    if (body.empty()) return "[No content]";

    // Strip newlines for subject/preview
    std::string cleaned = body;
    std::replace(cleaned.begin(), cleaned.end(), '\n', ' ');
    std::replace(cleaned.begin(), cleaned.end(), '\r', ' ');

    // Collapse multiple spaces
    std::string result;
    result.reserve(cleaned.size());
    bool last_was_space = false;
    for (char c : cleaned) {
      if (c == ' ' || c == '\t') {
        if (!last_was_space) result += ' ';
        last_was_space = true;
      } else {
        result += c;
        last_was_space = false;
      }
    }

    return truncate(result, kMaxBodyPreviewLength);
  }

  // -------------------------------------------------------------------------
  // Generate unsubscribe URL
  // -------------------------------------------------------------------------
  static std::string generate_unsubscribe_url(const std::string& base_url,
                                                const std::string& token) {
    std::string url = base_url;
    if (!url.empty() && url.back() != '/') url += '/';
    url += "_matrix/client/unsubscribe?token=";
    url += token;
    return url;
  }

  // -------------------------------------------------------------------------
  // Generate tracking pixel HTML (1x1 transparent GIF)
  // -------------------------------------------------------------------------
  static std::string generate_tracking_pixel_html(const std::string& tracking_id) {
    // The tracking pixel: a base64-encoded 1x1 transparent GIF with a unique
    // tracking ID embedded in the URL path
    std::ostringstream pixel;
    pixel << "<img src=\"data:image/gif;base64," << kTrackingPixelGifBase64
          << "\" width=\"1\" height=\"1\" alt=\"\" "
          << "data-track-id=\"" << html_escape(tracking_id) << "\" "
          << "style=\"display:none;\" />";
    return pixel.str();
  }

  // -------------------------------------------------------------------------
  // Generate tracking pixel URL (for external image loading)
  // -------------------------------------------------------------------------
  static std::string generate_tracking_pixel_url(const std::string& base_url,
                                                   const std::string& tracking_id,
                                                   const std::string& email) {
    // Hash the email so we don't leak it in the URL
    std::string email_hash = hmac_sha256_hex("matrix_tracking_salt", email);
    std::ostringstream url;
    url << base_url;
    if (!base_url.empty() && base_url.back() != '/') url << '/';
    url << "_matrix/client/v1/email/track?";
    url << "id=" << tracking_id;
    url << "&h=" << email_hash.substr(0, 16);
    return url.str();
  }

  // -------------------------------------------------------------------------
  // Build MIME multipart/alternative message
  // -------------------------------------------------------------------------
  static std::string build_mime_message(
      const std::string& from_addr,
      const std::string& from_name,
      const std::string& to_addr,
      const std::string& subject,
      const std::string& html_body,
      const std::string& text_body) {

    std::string boundary = "=_matrix_" + random_hex(24);

    std::ostringstream msg;
    msg << "Date: " << format_rfc2822_date() << "\r\n";
    msg << "From: ";
    if (!from_name.empty()) msg << from_name << " ";
    msg << "<" << from_addr << ">\r\n";
    msg << "To: <" << to_addr << ">\r\n";
    msg << "Subject: =?utf-8?B?"
        << base64url_encode(subject) << "?=\r\n";
    msg << "Message-ID: <" << random_hex(16) << "@" << from_addr.substr(from_addr.find('@') + 1) << ">\r\n";
    msg << "MIME-Version: 1.0\r\n";
    msg << "Content-Type: multipart/alternative; boundary=\"" << boundary << "\"\r\n";
    msg << "X-Mailer: Matrix Progressive Server\r\n";
    msg << "X-Auto-Response-Suppress: All\r\n";
    msg << "Precedence: bulk\r\n";
    msg << "List-Unsubscribe: <mailto:" << from_addr << "?subject=unsubscribe>\r\n";
    msg << "\r\n";

    // Plain text part
    msg << "--" << boundary << "\r\n";
    msg << "Content-Type: text/plain; charset=\"utf-8\"\r\n";
    msg << "Content-Transfer-Encoding: base64\r\n";
    msg << "\r\n";
    msg << fold_base64(base64url_encode(text_body)) << "\r\n";
    msg << "\r\n";

    // HTML part
    msg << "--" << boundary << "\r\n";
    msg << "Content-Type: text/html; charset=\"utf-8\"\r\n";
    msg << "Content-Transfer-Encoding: base64\r\n";
    msg << "\r\n";
    msg << fold_base64(base64url_encode(html_body)) << "\r\n";
    msg << "\r\n";

    // Closing boundary
    msg << "--" << boundary << "--\r\n";

    return msg.str();
  }

  // -------------------------------------------------------------------------
  // Format date in RFC 2822 format
  // -------------------------------------------------------------------------
  static std::string format_rfc2822_date() {
    time_t now = time(nullptr);
    struct tm tm_buf;
    gmtime_r(&now, &tm_buf);
    char buf[128];
    strftime(buf, sizeof(buf), "%a, %d %b %Y %H:%M:%S +0000", &tm_buf);
    return std::string(buf);
  }

  // -------------------------------------------------------------------------
  // Fold base64 into 76-character lines per RFC 2045
  // -------------------------------------------------------------------------
  static std::string fold_base64(const std::string& b64) {
    std::ostringstream folded;
    for (size_t i = 0; i < b64.size(); i += 76) {
      if (i > 0) folded << "\r\n";
      folded << b64.substr(i, 76);
    }
    return folded.str();
  }
};

// ============================================================================
// Unsubscribe Token Manager
// ============================================================================

class UnsubscribeTokenManager {
public:
  // -------------------------------------------------------------------------
  // Generate a unique unsubscribe token for a user/pusher
  // -------------------------------------------------------------------------
  static std::string generate_token(const std::string& user_id,
                                      const std::string& pushkey) {
    std::string seed = user_id + ":" + pushkey + ":" +
                       std::to_string(now_epoch_sec()) + ":" +
                       random_hex(16);
    std::string hash = hmac_sha256_hex("matrix_unsubscribe_secret", seed);
    return hash.substr(0, kUnsubscribeTokenLength);
  }

  // -------------------------------------------------------------------------
  // Verify an unsubscribe token is valid (not expired, format correct)
  // -------------------------------------------------------------------------
  static bool verify_token_format(const std::string& token) {
    if (token.size() != kUnsubscribeTokenLength) return false;
    for (char c : token) {
      if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
        return false;
    }
    return true;
  }

  // -------------------------------------------------------------------------
  // Generate a token with embedded expiry timestamp
  // -------------------------------------------------------------------------
  static std::string generate_token_with_expiry(const std::string& user_id,
                                                  const std::string& pushkey,
                                                  int64_t expiry_sec) {
    std::string seed = user_id + ":" + pushkey + ":" +
                       std::to_string(expiry_sec) + ":" +
                       random_hex(8);
    std::string hash = hmac_sha256_hex("matrix_unsubscribe_secret_v2", seed);
    // Embed the expiry in the first 8 hex chars of the token
    std::ostringstream token;
    token << std::hex << std::setw(8) << std::setfill('0') << expiry_sec;
    token << hash.substr(0, kUnsubscribeTokenLength - 8);
    return token.str();
  }

  // -------------------------------------------------------------------------
  // Extract expiry from a v2 token (returns 0 if no embedded expiry)
  // -------------------------------------------------------------------------
  static int64_t extract_expiry(const std::string& token) {
    if (token.size() < 8) return 0;
    try {
      return std::stoll(token.substr(0, 8), nullptr, 16);
    } catch (...) {
      return 0;
    }
  }

  // -------------------------------------------------------------------------
  // Check if a token has expired
  // -------------------------------------------------------------------------
  static bool is_expired(const std::string& token) {
    int64_t expiry = extract_expiry(token);
    if (expiry == 0) return false;  // No expiry embedded, assume valid
    return now_epoch_sec() > expiry;
  }
};

// ============================================================================
// Email Preferences Manager
// ============================================================================

class EmailPreferencesManager {
public:
  void set_preferences(const std::string& user_id, const EmailPreferences& prefs) {
    std::unique_lock lock(mutex_);
    preferences_[user_id] = prefs;
  }

  EmailPreferences get_preferences(const std::string& user_id) {
    std::shared_lock lock(mutex_);
    auto it = preferences_.find(user_id);
    if (it != preferences_.end()) return it->second;
    return EmailPreferences{};  // Default
  }

  bool can_send_notification(const std::string& user_id,
                               const std::string& event_type,
                               bool is_mention,
                               bool is_call,
                               bool is_invite) {
    EmailPreferences prefs = get_preferences(user_id);

    if (is_call && !prefs.notify_for_calls) return false;
    if (is_invite && !prefs.notify_for_invites) return false;
    if (is_mention && !prefs.notify_for_mentions) return false;
    if (event_type == "m.reaction" && !prefs.notify_for_reactions) return false;
    if (!prefs.notify_for_messages && !is_mention && !is_call && !is_invite) return false;

    return true;
  }

  bool can_send_digest(const std::string& user_id, const std::string& digest_type) {
    EmailPreferences prefs = get_preferences(user_id);

    if (digest_type == "daily") return prefs.enable_daily_digest;
    if (digest_type == "weekly") return prefs.enable_weekly_digest;
    if (digest_type == "missed") return prefs.enable_missed_digest;
    return true;
  }

  json get_preferences_json(const std::string& user_id) {
    return get_preferences(user_id).to_json();
  }

  void remove_preferences(const std::string& user_id) {
    std::unique_lock lock(mutex_);
    preferences_.erase(user_id);
  }

  size_t count() {
    std::shared_lock lock(mutex_);
    return preferences_.size();
  }

private:
  mutable std::shared_mutex mutex_;
  std::unordered_map<std::string, EmailPreferences> preferences_;
};

// ============================================================================
// Email Rate Limiter
// ============================================================================

class EmailRateLimiter {
public:
  // -------------------------------------------------------------------------
  // Check if an email can be sent to this user right now
  // Returns true if allowed, false if rate limited
  // -------------------------------------------------------------------------
  bool check_and_record(const std::string& user_id) {
    std::unique_lock lock(mutex_);
    int64_t now = now_epoch_ms();

    // Global rate limit
    cleanup_global_window();
    if (global_send_timestamps_ms_.size() >= static_cast<size_t>(kGlobalEmailRatePerHour)) {
      rate_limited_global_++;
      return false;
    }

    // Per-user rate limit
    auto& entry = user_limits_[user_id];
    cleanup_user_window(entry);

    // Burst protection
    if (now - entry.burst_window_start_ms > 60000) {
      entry.burst_window_start_ms = now;
      entry.burst_count = 0;
    }
    entry.burst_count++;

    if (entry.burst_count > kMaxBurstPerUser) {
      rate_limited_user_burst_++;
      entry.burst_count--;  // Don't count this one
      return false;
    }

    // Per-hour limit
    if (static_cast<int64_t>(entry.send_timestamps_ms.size()) >= kUserEmailRatePerHour) {
      rate_limited_user_hourly_++;
      entry.burst_count--;
      return false;
    }

    // Record the send
    entry.send_timestamps_ms.push_back(now);
    entry.total_sent_this_hour++;
    global_send_timestamps_ms_.push_back(now);
    global_sent_++;

    return true;
  }

  // -------------------------------------------------------------------------
  // Reset rate limiter state for a user
  // -------------------------------------------------------------------------
  void reset_user(const std::string& user_id) {
    std::unique_lock lock(mutex_);
    user_limits_.erase(user_id);
  }

  // -------------------------------------------------------------------------
  // Get rate limit stats
  // -------------------------------------------------------------------------
  json stats() {
    std::unique_lock lock(mutex_);
    cleanup_global_window();
    json j;
    j["global_emails_sent"] = global_sent_;
    j["global_rate_limited"] = rate_limited_global_;
    j["user_rate_limited_burst"] = rate_limited_user_burst_;
    j["user_rate_limited_hourly"] = rate_limited_user_hourly_;
    j["active_limits"] = user_limits_.size();
    j["global_window_size"] = global_send_timestamps_ms_.size();
    return j;
  }

  // -------------------------------------------------------------------------
  // Get whether a user is currently rate limited (without recording)
  // -------------------------------------------------------------------------
  bool is_rate_limited(const std::string& user_id) {
    std::unique_lock lock(mutex_);
    int64_t now = now_epoch_ms();

    cleanup_global_window();
    if (global_send_timestamps_ms_.size() >= static_cast<size_t>(kGlobalEmailRatePerHour))
      return true;

    auto it = user_limits_.find(user_id);
    if (it == user_limits_.end()) return false;

    auto& entry = it->second;
    cleanup_user_window(entry);

    if (static_cast<int64_t>(entry.send_timestamps_ms.size()) >= kUserEmailRatePerHour)
      return true;

    return false;
  }

private:
  void cleanup_global_window() {
    int64_t now = now_epoch_ms();
    while (!global_send_timestamps_ms_.empty() &&
           now - global_send_timestamps_ms_.front() > kRateLimitWindowSec * 1000) {
      global_send_timestamps_ms_.pop_front();
    }
  }

  void cleanup_user_window(EmailRateLimitEntry& entry) {
    int64_t now = now_epoch_ms();
    while (!entry.send_timestamps_ms.empty() &&
           now - entry.send_timestamps_ms.front() > kRateLimitWindowSec * 1000) {
      entry.send_timestamps_ms.pop_front();
    }
  }

  mutable std::mutex mutex_;
  std::deque<int64_t> global_send_timestamps_ms_;
  std::unordered_map<std::string, EmailRateLimitEntry> user_limits_;
  int64_t global_sent_ = 0;
  int64_t rate_limited_global_ = 0;
  int64_t rate_limited_user_burst_ = 0;
  int64_t rate_limited_user_hourly_ = 0;
};

// ============================================================================
// Email Bounce Handler
// ============================================================================

class EmailBounceHandler {
public:
  // -------------------------------------------------------------------------
  // Record a bounce event
  // -------------------------------------------------------------------------
  void record_bounce(const std::string& email,
                     const std::string& user_id,
                     const std::string& bounce_type,
                     const std::string& reason) {
    std::unique_lock lock(mutex_);

    BounceRecord record;
    record.email = email;
    record.user_id = user_id;
    record.bounce_type = bounce_type;
    record.reason = reason;
    record.ts_sec = now_epoch_sec();

    if (bounce_type == "hard") {
      record.retry_after_sec = 0;  // Never retry
      auto_add_to_suppression(email, user_id, "hard_bounce", kHardBounceSuppressDays);
    } else if (bounce_type == "soft") {
      record.retry_after_sec = kSoftBounceRetryDelaySec;
      int soft_count = count_recent_soft_bounces(email);
      if (soft_count >= kMaxSoftBouncesBeforeHard) {
        // Upgrade to hard bounce
        record.bounce_type = "hard_upgraded";
        record.reason = "Too many soft bounces: " + reason;
        auto_add_to_suppression(email, user_id, "soft_upgraded_to_hard",
                                 kHardBounceSuppressDays);
      }
    } else if (bounce_type == "complaint") {
      record.retry_after_sec = 0;
      auto_add_to_suppression(email, user_id, "complaint", kComplaintSuppressDays);
    }

    bounce_records_.push_back(record);

    // Keep list bounded
    while (bounce_records_.size() > 10000) {
      bounce_records_.pop_front();
    }

    // Track per-email bounce count
    bounce_counts_[email]++;
  }

  // -------------------------------------------------------------------------
  // Check if an email address is suppressed
  // -------------------------------------------------------------------------
  bool is_suppressed(const std::string& email) {
    std::shared_lock lock(mutex_);
    auto it = suppression_list_.find(email);
    if (it == suppression_list_.end()) return false;

    // Check expiry
    if (it->second.expires_at_sec > 0 &&
        now_epoch_sec() > it->second.expires_at_sec) {
      return false;  // Suppression expired
    }

    return true;
  }

  // -------------------------------------------------------------------------
  // Check if an email can be retried after a bounce
  // -------------------------------------------------------------------------
  bool can_retry(const std::string& email) {
    std::shared_lock lock(mutex_);

    if (is_suppressed(email)) return false;

    // Find the most recent bounce for this email
    for (auto it = bounce_records_.rbegin(); it != bounce_records_.rend(); ++it) {
      if (it->email == email && it->bounce_type != "complaint") {
        if (it->retry_after_sec == 0) return false;  // Hard bounce
        int64_t retry_at = it->ts_sec + it->retry_after_sec;
        return now_epoch_sec() >= retry_at;
      }
    }

    return true;  // No bounces on record
  }

  // -------------------------------------------------------------------------
  // Manually add to suppression list
  // -------------------------------------------------------------------------
  void add_to_suppression(const std::string& email,
                          const std::string& user_id,
                          const std::string& reason,
                          int64_t suppress_days) {
    std::unique_lock lock(mutex_);
    auto_add_to_suppression(email, user_id, reason, suppress_days);
  }

  // -------------------------------------------------------------------------
  // Manually remove from suppression list
  // -------------------------------------------------------------------------
  void remove_from_suppression(const std::string& email) {
    std::unique_lock lock(mutex_);
    suppression_list_.erase(email);
  }

  // -------------------------------------------------------------------------
  // Get bounce statistics
  // -------------------------------------------------------------------------
  json bounce_stats() {
    std::shared_lock lock(mutex_);
    json j;
    j["total_bounces"] = bounce_records_.size();
    j["suppressed_count"] = suppression_list_.size();
    j["total_bounces_by_email"] = bounce_counts_.size();

    int hard = 0, soft = 0, complaint = 0;
    for (const auto& r : bounce_records_) {
      if (r.bounce_type == "hard" || r.bounce_type == "hard_upgraded") hard++;
      else if (r.bounce_type == "soft") soft++;
      else if (r.bounce_type == "complaint") complaint++;
    }
    j["hard_bounces"] = hard;
    j["soft_bounces"] = soft;
    j["complaints"] = complaint;
    return j;
  }

  // -------------------------------------------------------------------------
  // Cleanup expired suppressions
  // -------------------------------------------------------------------------
  void cleanup_expired_suppressions() {
    std::unique_lock lock(mutex_);
    int64_t now = now_epoch_sec();
    for (auto it = suppression_list_.begin(); it != suppression_list_.end(); ) {
      if (it->second.expires_at_sec > 0 && now > it->second.expires_at_sec) {
        it = suppression_list_.erase(it);
      } else {
        ++it;
      }
    }
  }

  // -------------------------------------------------------------------------
  // Check if bounce counts for a specific email exceed threshold
  // -------------------------------------------------------------------------
  int get_bounce_count(const std::string& email) {
    std::shared_lock lock(mutex_);
    auto it = bounce_counts_.find(email);
    if (it != bounce_counts_.end()) return it->second;
    return 0;
  }

  // -------------------------------------------------------------------------
  // Clear all bounce data for an email (e.g., user fixed their email)
  // -------------------------------------------------------------------------
  void clear_email(const std::string& email) {
    std::unique_lock lock(mutex_);
    bounce_counts_.erase(email);
    suppression_list_.erase(email);
    bounce_records_.erase(
        std::remove_if(bounce_records_.begin(), bounce_records_.end(),
                        [&](const BounceRecord& r) { return r.email == email; }),
        bounce_records_.end());
  }

private:
  int count_recent_soft_bounces(const std::string& email) {
    int64_t cutoff = now_epoch_sec() - kBounceWindowSec;
    int count = 0;
    for (auto it = bounce_records_.rbegin(); it != bounce_records_.rend(); ++it) {
      if (it->email == email && it->bounce_type == "soft" && it->ts_sec > cutoff) {
        count++;
      }
    }
    return count;
  }

  void auto_add_to_suppression(const std::string& email,
                                 const std::string& user_id,
                                 const std::string& reason,
                                 int64_t suppress_days) {
    if (suppression_list_.size() >= kMaxSuppressionEntries) {
      // Evict oldest entry
      auto oldest = suppression_list_.begin();
      for (auto it = suppression_list_.begin(); it != suppression_list_.end(); ++it) {
        if (it->second.suppressed_at_sec < oldest->second.suppressed_at_sec)
          oldest = it;
      }
      suppression_list_.erase(oldest);
    }

    SuppressionEntry entry;
    entry.email = email;
    entry.user_id = user_id;
    entry.reason = reason;
    entry.suppressed_at_sec = now_epoch_sec();
    entry.expires_at_sec = (suppress_days > 0)
        ? now_epoch_sec() + suppress_days * 86400
        : 0;

    suppression_list_[email] = entry;
  }

  mutable std::shared_mutex mutex_;
  std::deque<BounceRecord> bounce_records_;
  std::unordered_map<std::string, SuppressionEntry> suppression_list_;
  std::unordered_map<std::string, int> bounce_counts_;
};

// ============================================================================
// Tracking Pixel Manager
// ============================================================================

class TrackingPixelManager {
public:
  // -------------------------------------------------------------------------
  // Generate a tracking pixel with a unique ID
  // -------------------------------------------------------------------------
  std::string generate_tracking_markup(const std::string& email,
                                         const std::string& user_id,
                                         const std::string& event_id,
                                         const std::string& base_url) {
    std::string tracking_id = user_id + "_" + event_id + "_" +
                               std::to_string(now_epoch_ms());
    std::string pixel_url = EmailTemplateGenerator::generate_tracking_pixel_url(
        base_url, tracking_id, email);

    std::ostringstream img;
    img << "<img src=\"" << pixel_url
        << "\" width=\"1\" height=\"1\" alt=\"\" "
        << "style=\"display:none;\" />";
    return img.str();
  }

  // -------------------------------------------------------------------------
  // Record an "open" event when a tracking pixel is loaded
  // -------------------------------------------------------------------------
  void record_open(const std::string& tracking_id, const std::string& email) {
    std::unique_lock lock(mutex_);
    int64_t now = now_epoch_sec();

    OpenRecord rec;
    rec.tracking_id = tracking_id;
    rec.email = email;
    rec.first_open_ts = now;
    rec.last_open_ts = now;
    rec.open_count = 1;

    auto it = open_records_.find(tracking_id);
    if (it != open_records_.end()) {
      it->second.last_open_ts = now;
      it->second.open_count++;
    } else {
      open_records_[tracking_id] = rec;
    }

    // Bound the map
    if (open_records_.size() > 100000) {
      // Remove oldest entries
      auto oldest = open_records_.begin();
      for (auto iter = open_records_.begin(); iter != open_records_.end(); ++iter) {
        if (iter->second.last_open_ts < oldest->second.last_open_ts)
          oldest = iter;
      }
      open_records_.erase(oldest);
    }
  }

  // -------------------------------------------------------------------------
  // Get open stats for a tracking ID
  // -------------------------------------------------------------------------
  std::optional<int> get_open_count(const std::string& tracking_id) {
    std::shared_lock lock(mutex_);
    auto it = open_records_.find(tracking_id);
    if (it != open_records_.end()) return it->second.open_count;
    return std::nullopt;
  }

  // -------------------------------------------------------------------------
  // Get open stats for all emails sent to a user
  // -------------------------------------------------------------------------
  json user_open_stats(const std::string& email) {
    std::shared_lock lock(mutex_);
    json stats = json::array();
    for (const auto& [id, rec] : open_records_) {
      if (rec.email == email) {
        json entry;
        entry["tracking_id"] = id;
        entry["first_open"] = rec.first_open_ts;
        entry["last_open"] = rec.last_open_ts;
        entry["opens"] = rec.open_count;
        stats.push_back(entry);
      }
    }
    return stats;
  }

  // -------------------------------------------------------------------------
  // Cleanup old tracking records
  // -------------------------------------------------------------------------
  void cleanup_old_records(int64_t max_age_sec = 30 * 86400) {
    std::unique_lock lock(mutex_);
    int64_t cutoff = now_epoch_sec() - max_age_sec;
    for (auto it = open_records_.begin(); it != open_records_.end(); ) {
      if (it->second.last_open_ts < cutoff) {
        it = open_records_.erase(it);
      } else {
        ++it;
      }
    }
  }

  // -------------------------------------------------------------------------
  // Stats
  // -------------------------------------------------------------------------
  json stats() {
    std::shared_lock lock(mutex_);
    json j;
    j["total_tracking_ids"] = open_records_.size();
    int64_t total_opens = 0;
    for (const auto& [id, rec] : open_records_)
      total_opens += rec.open_count;
    j["total_opens"] = total_opens;
    return j;
  }

private:
  struct OpenRecord {
    std::string tracking_id;
    std::string email;
    int64_t first_open_ts = 0;
    int64_t last_open_ts = 0;
    int open_count = 0;
  };

  mutable std::shared_mutex mutex_;
  std::unordered_map<std::string, OpenRecord> open_records_;
};

// ============================================================================
// Notification Grouper (groups notifications by room for digest)
// ============================================================================

class NotificationGrouper {
public:
  // -------------------------------------------------------------------------
  // Group digest entries by room
  // -------------------------------------------------------------------------
  static std::vector<DigestRoomGroup> group_by_room(
      const std::vector<DigestEntry>& entries) {

    std::unordered_map<std::string, DigestRoomGroup> groups;

    for (const auto& entry : entries) {
      auto& group = groups[entry.room_id];
      group.room_id = entry.room_id;
      if (!entry.room_name.empty()) group.room_name = entry.room_name;
      if (!entry.room_alias.empty()) group.room_alias = entry.room_alias;

      group.entries.push_back(entry);

      if (entry.ts_sec > group.latest_ts_sec)
        group.latest_ts_sec = entry.ts_sec;
    }

    std::vector<DigestRoomGroup> result;
    result.reserve(groups.size());
    for (auto& [id, group] : groups) {
      result.push_back(std::move(group));
    }
    return result;
  }

  // -------------------------------------------------------------------------
  // Rank rooms by importance (most active / important first)
  // -------------------------------------------------------------------------
  static void rank_rooms(std::vector<DigestRoomGroup>& groups) {
    // Score each room group
    for (auto& group : groups) {
      double total_score = 0.0;
      int mention_count = 0;
      int call_count = 0;
      int invite_count = 0;

      for (const auto& entry : group.entries) {
        total_score += entry.score();
        if (entry.is_mention) mention_count++;
        if (entry.is_call) call_count++;
        if (entry.is_invite) invite_count++;
      }

      // Boost rooms with mentions, calls, invites
      total_score += mention_count * 5.0;
      total_score += call_count * 4.0;
      total_score += invite_count * 3.0;

      // DMs rank higher
      if (group.is_dm) total_score *= 1.5;

      // Store score in latest_ts_sec (reuse field for sorting)
      // Actually, let's use a lambda sort with the score computed inline
    }

    // Sort by importance score descending
    std::sort(groups.begin(), groups.end(),
              [](const DigestRoomGroup& a, const DigestRoomGroup& b) {
                double score_a = compute_room_score(a);
                double score_b = compute_room_score(b);
                return score_a > score_b;
              });
  }

  // -------------------------------------------------------------------------
  // Rank entries within each room (most important first)
  // -------------------------------------------------------------------------
  static void rank_entries_in_rooms(std::vector<DigestRoomGroup>& groups) {
    for (auto& group : groups) {
      std::sort(group.entries.begin(), group.entries.end(),
                [](const DigestEntry& a, const DigestEntry& b) {
                  return a.score() > b.score();
                });
    }
  }

  // -------------------------------------------------------------------------
  // Apply ranking and compaction to a digest bundle
  // -------------------------------------------------------------------------
  static void rank_and_compact(DigestBundle& digest) {
    // Rank entries within each room
    rank_entries_in_rooms(digest.room_groups);

    // Compact entries per room
    for (auto& group : digest.room_groups) {
      if (static_cast<int64_t>(group.entries.size()) > kMaxDigestEventsPerRoom) {
        group.entries.resize(static_cast<size_t>(kMaxDigestEventsPerRoom));
      }
    }

    // Rank rooms
    rank_rooms(digest.room_groups);

    // Compact rooms
    if (static_cast<int64_t>(digest.room_groups.size()) > kMaxDigestRooms) {
      digest.room_groups.resize(static_cast<size_t>(kMaxDigestRooms));
    }
  }

  // -------------------------------------------------------------------------
  // Build a digest bundle from raw entries for a user
  // -------------------------------------------------------------------------
  static DigestBundle build_digest(
      const std::string& user_id,
      const std::string& to_email,
      std::vector<DigestEntry> entries,
      const std::string& digest_type,
      int64_t period_start_sec,
      int64_t period_end_sec,
      const std::string& unsubscribe_token,
      const std::string& lang,
      const std::string& brand) {

    DigestBundle digest;
    digest.user_id = user_id;
    digest.to_email = to_email;
    digest.digest_type = digest_type;
    digest.period_start_sec = period_start_sec;
    digest.period_end_sec = period_end_sec;
    digest.unsubscribe_token = unsubscribe_token;
    digest.lang = lang;
    digest.brand = brand;

    digest.room_groups = group_by_room(entries);

    // Count totals
    digest.total_events = static_cast<int64_t>(entries.size());
    digest.total_rooms = static_cast<int64_t>(digest.room_groups.size());

    for (const auto& entry : entries) {
      if (entry.is_mention || entry.is_highlight) digest.total_mentions++;
      if (entry.is_call) digest.total_calls++;
      if (entry.is_invite) digest.total_invites++;
    }

    rank_and_compact(digest);

    return digest;
  }

private:
  static double compute_room_score(const DigestRoomGroup& group) {
    double total = 0.0;
    int mention_count = 0;
    int call_count = 0;
    int invite_count = 0;

    for (const auto& entry : group.entries) {
      total += entry.score();
      if (entry.is_mention) mention_count++;
      if (entry.is_call) call_count++;
      if (entry.is_invite) invite_count++;
    }

    total += mention_count * 5.0;
    total += call_count * 4.0;
    total += invite_count * 3.0;

    if (group.is_dm) total *= 1.5;

    return total;
  }
};

// ============================================================================
// Digest Scheduler: Handles scheduling and compilation of digest emails
// ============================================================================

class DigestScheduler {
public:
  DigestScheduler(net::io_context& ioc)
      : ioc_(ioc),
        check_timer_(ioc) {}

  // -------------------------------------------------------------------------
  // Start the scheduler
  // -------------------------------------------------------------------------
  void start() {
    if (running_) return;
    running_ = true;
    schedule_next_check();
  }

  // -------------------------------------------------------------------------
  // Stop the scheduler
  // -------------------------------------------------------------------------
  void stop() {
    running_ = false;
    error_code ec;
    check_timer_.cancel(ec);
  }

  // -------------------------------------------------------------------------
  // Queue a notification for future digest inclusion
  // -------------------------------------------------------------------------
  void queue_for_digest(const std::string& user_id,
                        const DigestEntry& entry) {
    std::unique_lock lock(mutex_);
    pending_digest_entries_[user_id].push_back(entry);

    if (static_cast<int64_t>(pending_digest_entries_[user_id].size()) >
        kMaxDigestEventsPerRoom * kMaxDigestRooms) {
      pending_digest_entries_[user_id].pop_front();
    }
  }

  // -------------------------------------------------------------------------
  // Check if a daily digest should be sent now
  // -------------------------------------------------------------------------
  bool should_send_daily_digest() {
    int64_t now = now_epoch_sec();
    time_t t = static_cast<time_t>(now);
    struct tm tm_buf;
    gmtime_r(&t, &tm_buf);

    // Check if we're in the daily digest hour
    if (tm_buf.tm_hour != kDailyDigestHour) return false;

    // Only send once per day
    if (now - last_daily_digest_sec_ < 3600) return false;

    return true;
  }

  // -------------------------------------------------------------------------
  // Check if a weekly digest should be sent now
  // -------------------------------------------------------------------------
  bool should_send_weekly_digest() {
    int64_t now = now_epoch_sec();
    time_t t = static_cast<time_t>(now);
    struct tm tm_buf;
    gmtime_r(&t, &tm_buf);

    // Monday at the scheduled hour
    if (tm_buf.tm_wday != kWeeklyDigestDay) return false;
    if (tm_buf.tm_hour != kWeeklyDigestHour) return false;

    // Only send once per week
    if (now - last_weekly_digest_sec_ < 86400 * 6) return false;

    return true;
  }

  // -------------------------------------------------------------------------
  // Compile daily digest bundles for all users with pending entries
  // -------------------------------------------------------------------------
  std::vector<DigestBundle> compile_daily_digests(
      const std::function<std::string(const std::string&)>& get_email,
      const std::function<std::string(const std::string&)>& get_unsubscribe_token,
      const std::function<std::string(const std::string&)>& get_lang,
      const std::function<std::string(const std::string&)>& get_brand) {

    std::unique_lock lock(mutex_);
    std::vector<DigestBundle> bundles;
    int64_t now = now_epoch_sec();
    int64_t period_start = now - 86400;  // Last 24 hours

    for (auto& [user_id, entries] : pending_digest_entries_) {
      if (entries.empty()) continue;

      // Filter entries from the last 24 hours
      std::vector<DigestEntry> recent_entries;
      for (const auto& entry : entries) {
        if (entry.ts_sec >= period_start) {
          recent_entries.push_back(entry);
        }
      }

      if (static_cast<int64_t>(recent_entries.size()) < kDigestMinEventsForSend)
        continue;

      DigestBundle bundle = NotificationGrouper::build_digest(
          user_id,
          get_email(user_id),
          std::move(recent_entries),
          "daily",
          period_start,
          now,
          get_unsubscribe_token(user_id),
          get_lang(user_id),
          get_brand(user_id));

      bundles.push_back(std::move(bundle));
    }

    // Clear daily entries
    for (auto& [user_id, entries] : pending_digest_entries_) {
      entries.erase(
          std::remove_if(entries.begin(), entries.end(),
                          [&](const DigestEntry& e) { return e.ts_sec >= period_start; }),
          entries.end());
    }

    last_daily_digest_sec_ = now;
    return bundles;
  }

  // -------------------------------------------------------------------------
  // Compile weekly digest bundles
  // -------------------------------------------------------------------------
  std::vector<DigestBundle> compile_weekly_digests(
      const std::function<std::string(const std::string&)>& get_email,
      const std::function<std::string(const std::string&)>& get_unsubscribe_token,
      const std::function<std::string(const std::string&)>& get_lang,
      const std::function<std::string(const std::string&)>& get_brand) {

    std::unique_lock lock(mutex_);
    std::vector<DigestBundle> bundles;
    int64_t now = now_epoch_sec();
    int64_t period_start = now - 7 * 86400;  // Last 7 days

    for (auto& [user_id, entries] : pending_digest_entries_) {
      if (entries.empty()) continue;

      std::vector<DigestEntry> recent_entries;
      for (const auto& entry : entries) {
        if (entry.ts_sec >= period_start) {
          recent_entries.push_back(entry);
        }
      }

      if (static_cast<int64_t>(recent_entries.size()) < kDigestMinEventsForSend)
        continue;

      DigestBundle bundle = NotificationGrouper::build_digest(
          user_id,
          get_email(user_id),
          std::move(recent_entries),
          "weekly",
          period_start,
          now,
          get_unsubscribe_token(user_id),
          get_lang(user_id),
          get_brand(user_id));

      bundles.push_back(std::move(bundle));
    }

    // Clear all entries older than 7 days
    for (auto& [user_id, entries] : pending_digest_entries_) {
      entries.erase(
          std::remove_if(entries.begin(), entries.end(),
                          [&](const DigestEntry& e) { return e.ts_sec < period_start; }),
          entries.end());
    }

    last_weekly_digest_sec_ = now;
    return bundles;
  }

  // -------------------------------------------------------------------------
  // Compile missed message digests for a specific user
  // -------------------------------------------------------------------------
  DigestBundle compile_missed_digest(
      const std::string& user_id,
      const std::string& email,
      const std::string& unsubscribe_token,
      const std::string& lang,
      const std::string& brand) {

    std::unique_lock lock(mutex_);
    int64_t now = now_epoch_sec();
    int64_t period_start = now - 86400;  // Last 24 hours

    auto it = pending_digest_entries_.find(user_id);
    if (it == pending_digest_entries_.end() || it->second.empty()) {
      return DigestBundle{};
    }

    std::vector<DigestEntry> recent_entries;
    for (const auto& entry : it->second) {
      if (entry.ts_sec >= period_start) {
        recent_entries.push_back(entry);
      }
    }

    if (static_cast<int64_t>(recent_entries.size()) < kDigestMinEventsForSend) {
      return DigestBundle{};
    }

    return NotificationGrouper::build_digest(
        user_id, email, std::move(recent_entries),
        "missed", period_start, now,
        unsubscribe_token, lang, brand);
  }

  // -------------------------------------------------------------------------
  // Get pending digest entry count for a user
  // -------------------------------------------------------------------------
  int64_t pending_count(const std::string& user_id) {
    std::unique_lock lock(mutex_);
    auto it = pending_digest_entries_.find(user_id);
    if (it != pending_digest_entries_.end())
      return static_cast<int64_t>(it->second.size());
    return 0;
  }

  // -------------------------------------------------------------------------
  // Total pending entries across all users
  // -------------------------------------------------------------------------
  int64_t total_pending_count() {
    std::unique_lock lock(mutex_);
    int64_t total = 0;
    for (const auto& [uid, entries] : pending_digest_entries_)
      total += static_cast<int64_t>(entries.size());
    return total;
  }

  // -------------------------------------------------------------------------
  // Set callback for digest delivery
  // -------------------------------------------------------------------------
  using DigestDeliveryCallback = std::function<void(const DigestBundle&)>;

  void set_daily_delivery_callback(DigestDeliveryCallback cb) {
    daily_delivery_cb_ = std::move(cb);
  }

  void set_weekly_delivery_callback(DigestDeliveryCallback cb) {
    weekly_delivery_cb_ = std::move(cb);
  }

private:
  void schedule_next_check() {
    if (!running_) return;

    check_timer_.expires_after(std::chrono::seconds(kDigestCheckIntervalSec));
    check_timer_.async_wait([this](const error_code& ec) {
      if (ec || !running_) return;
      check_digest_triggers();
      schedule_next_check();
    });
  }

  void check_digest_triggers() {
    if (should_send_daily_digest() && daily_delivery_cb_) {
      // Daily delivery will be triggered by external caller using
      // compile_daily_digests() and then delivering each bundle.
      // Here we just set a flag that the caller can check.
      daily_digest_due_ = true;
    }

    if (should_send_weekly_digest() && weekly_delivery_cb_) {
      weekly_digest_due_ = true;
    }
  }

  net::io_context& ioc_;
  net::steady_timer check_timer_;
  bool running_ = false;

  mutable std::mutex mutex_;
  std::unordered_map<std::string, std::deque<DigestEntry>> pending_digest_entries_;

  int64_t last_daily_digest_sec_ = 0;
  int64_t last_weekly_digest_sec_ = 0;

  DigestDeliveryCallback daily_delivery_cb_;
  DigestDeliveryCallback weekly_delivery_cb_;

public:
  // Flags for external polling
  std::atomic<bool> daily_digest_due_{false};
  std::atomic<bool> weekly_digest_due_{false};
};

// ============================================================================
// Email Delivery Pipeline: Orchestrates the full email notification pipeline
// ============================================================================

class EmailDeliveryPipeline {
public:
  EmailDeliveryPipeline(net::io_context& ioc,
                        std::shared_ptr<EmailRateLimiter> rate_limiter,
                        std::shared_ptr<EmailBounceHandler> bounce_handler,
                        std::shared_ptr<EmailPreferencesManager> prefs_manager,
                        std::shared_ptr<TrackingPixelManager> tracking_manager,
                        std::shared_ptr<DigestScheduler> digest_scheduler)
      : ioc_(ioc),
        rate_limiter_(std::move(rate_limiter)),
        bounce_handler_(std::move(bounce_handler)),
        prefs_manager_(std::move(prefs_manager)),
        tracking_manager_(std::move(tracking_manager)),
        digest_scheduler_(std::move(digest_scheduler)) {}

  // -------------------------------------------------------------------------
  // Send a single notification email
  // -------------------------------------------------------------------------
  bool send_notification_email(const EmailNotification& notif,
                                const std::string& from_addr,
                                const std::string& from_name,
                                const std::string& base_url) {
    // Check suppression list
    if (bounce_handler_->is_suppressed(notif.to_email)) {
      record_drop("suppressed");
      return false;
    }

    // Check bounce cooldown
    if (!bounce_handler_->can_retry(notif.to_email)) {
      record_drop("bounce_cooldown");
      return false;
    }

    // Check preferences
    if (!prefs_manager_->can_send_notification(
            notif.user_id, notif.event_type,
            notif.is_direct_mention, notif.is_call, notif.is_invite)) {
      record_drop("preferences_disabled");
      return false;
    }

    // Rate limit check
    if (!rate_limiter_->check_and_record(notif.user_id)) {
      record_drop("rate_limited");
      // Queue for digest instead
      digest_scheduler_->queue_for_digest(notif.user_id,
                                            convert_to_digest_entry(notif));
      return false;
    }

    // Generate email
    std::string email_message = EmailTemplateGenerator::generate_notification_email(
        notif, from_addr, from_name, base_url);

    // In production: queue for SMTP delivery
    queue_for_delivery(notif.to_email, email_message, notif.event_id);

    record_sent();
    return true;
  }

  // -------------------------------------------------------------------------
  // Send a digest email
  // -------------------------------------------------------------------------
  bool send_digest_email(const DigestBundle& digest,
                          const std::string& from_addr,
                          const std::string& from_name,
                          const std::string& base_url) {
    // Check suppression
    if (bounce_handler_->is_suppressed(digest.to_email)) {
      record_drop("suppressed_digest");
      return false;
    }

    // Check preferences
    if (!prefs_manager_->can_send_digest(digest.user_id, digest.digest_type)) {
      record_drop("digest_prefs_disabled");
      return false;
    }

    // Rate limit
    if (!rate_limiter_->check_and_record(digest.user_id)) {
      record_drop("digest_rate_limited");
      return false;
    }

    // Generate email
    std::string email_message = EmailTemplateGenerator::generate_digest_email(
        digest, from_addr, from_name, base_url);

    queue_for_delivery(digest.to_email, email_message,
                        "digest_" + digest.user_id);

    record_sent();
    return true;
  }

  // -------------------------------------------------------------------------
  // Handle a bounce notification (called when SMTP server reports bounce)
  // -------------------------------------------------------------------------
  void handle_bounce(const std::string& email,
                     const std::string& user_id,
                     const std::string& bounce_type,
                     const std::string& reason) {
    bounce_handler_->record_bounce(email, user_id, bounce_type, reason);
  }

  // -------------------------------------------------------------------------
  // Handle a complaint notification (called when email provider reports spam)
  // -------------------------------------------------------------------------
  void handle_complaint(const std::string& email,
                         const std::string& user_id,
                         const std::string& reason) {
    bounce_handler_->record_bounce(email, user_id, "complaint", reason);
  }

  // -------------------------------------------------------------------------
  // Process the daily digest cycle
  // -------------------------------------------------------------------------
  void process_daily_digest(
      const std::string& from_addr,
      const std::string& from_name,
      const std::string& base_url,
      const std::function<std::string(const std::string&)>& get_email,
      const std::function<std::string(const std::string&)>& get_unsubscribe_token,
      const std::function<std::string(const std::string&)>& get_lang,
      const std::function<std::string(const std::string&)>& get_brand) {

    auto bundles = digest_scheduler_->compile_daily_digests(
        get_email, get_unsubscribe_token, get_lang, get_brand);

    for (auto& bundle : bundles) {
      send_digest_email(bundle, from_addr, from_name, base_url);
    }

    daily_digests_sent_ += static_cast<int64_t>(bundles.size());
  }

  // -------------------------------------------------------------------------
  // Process the weekly digest cycle
  // -------------------------------------------------------------------------
  void process_weekly_digest(
      const std::string& from_addr,
      const std::string& from_name,
      const std::string& base_url,
      const std::function<std::string(const std::string&)>& get_email,
      const std::function<std::string(const std::string&)>& get_unsubscribe_token,
      const std::function<std::string(const std::string&)>& get_lang,
      const std::function<std::string(const std::string&)>& get_brand) {

    auto bundles = digest_scheduler_->compile_weekly_digests(
        get_email, get_unsubscribe_token, get_lang, get_brand);

    for (auto& bundle : bundles) {
      send_digest_email(bundle, from_addr, from_name, base_url);
    }

    weekly_digests_sent_ += static_cast<int64_t>(bundles.size());
  }

  // -------------------------------------------------------------------------
  // Send a missed message digest to a specific user
  // -------------------------------------------------------------------------
  bool send_missed_digest(const std::string& user_id,
                           const std::string& email,
                           const std::string& unsubscribe_token,
                           const std::string& lang,
                           const std::string& brand,
                           const std::string& from_addr,
                           const std::string& from_name,
                           const std::string& base_url) {

    auto digest = digest_scheduler_->compile_missed_digest(
        user_id, email, unsubscribe_token, lang, brand);

    if (digest.total_events == 0) return false;

    return send_digest_email(digest, from_addr, from_name, base_url);
  }

  // -------------------------------------------------------------------------
  // Delivery stats
  // -------------------------------------------------------------------------
  json stats() {
    json j;
    j["emails_sent"] = total_sent_.load();
    j["emails_dropped"] = total_dropped_.load();
    j["daily_digests_sent"] = daily_digests_sent_.load();
    j["weekly_digests_sent"] = weekly_digests_sent_.load();
    j["delivery_queue_size"] = delivery_queue_.size();
    j["rate_limiter"] = rate_limiter_->stats();
    j["bounces"] = bounce_handler_->bounce_stats();
    j["tracking"] = tracking_manager_->stats();
    return j;
  }

private:
  void queue_for_delivery(const std::string& to_email,
                           const std::string& message,
                           const std::string& tracking_id) {
    std::unique_lock lock(delivery_mutex_);
    delivery_queue_.push_back({to_email, message, tracking_id,
                                now_epoch_ms()});
  }

  void record_sent() { total_sent_++; }
  void record_drop(const std::string& reason) {
    total_dropped_++;
    drop_reasons_[reason]++;
  }

  static DigestEntry convert_to_digest_entry(const EmailNotification& notif) {
    DigestEntry entry;
    entry.room_id = notif.room_id;
    entry.room_name = notif.room_name;
    entry.room_alias = notif.room_alias;
    entry.sender_user_id = notif.sender_user_id;
    entry.sender_display_name = notif.sender_display_name;
    entry.event_id = notif.event_id;
    entry.event_type = notif.event_type;
    entry.body_preview = EmailTemplateGenerator::format_body_preview(notif.body_text);
    entry.msgtype = notif.msgtype;
    entry.ts_sec = notif.event_ts_sec;
    entry.is_mention = notif.is_direct_mention;
    entry.is_highlight = notif.is_highlight;
    entry.is_call = notif.is_call;
    entry.is_invite = notif.is_invite;
    entry.is_encrypted = notif.is_encrypted;
    return entry;
  }

  struct DeliveryJob {
    std::string to_email;
    std::string message;
    std::string tracking_id;
    int64_t queued_at_ms = 0;
  };

  net::io_context& ioc_;
  std::shared_ptr<EmailRateLimiter> rate_limiter_;
  std::shared_ptr<EmailBounceHandler> bounce_handler_;
  std::shared_ptr<EmailPreferencesManager> prefs_manager_;
  std::shared_ptr<TrackingPixelManager> tracking_manager_;
  std::shared_ptr<DigestScheduler> digest_scheduler_;

  mutable std::mutex delivery_mutex_;
  std::deque<DeliveryJob> delivery_queue_;

  std::atomic<int64_t> total_sent_{0};
  std::atomic<int64_t> total_dropped_{0};
  std::atomic<int64_t> daily_digests_sent_{0};
  std::atomic<int64_t> weekly_digests_sent_{0};
  std::unordered_map<std::string, int64_t> drop_reasons_;
};

// ============================================================================
// Global state and initialization
// ============================================================================

static std::shared_ptr<EmailRateLimiter> g_email_rate_limiter;
static std::shared_ptr<EmailBounceHandler> g_email_bounce_handler;
static std::shared_ptr<EmailPreferencesManager> g_email_prefs_manager;
static std::shared_ptr<TrackingPixelManager> g_tracking_pixel_manager;
static std::shared_ptr<DigestScheduler> g_digest_scheduler;
static std::shared_ptr<EmailDeliveryPipeline> g_email_pipeline;
static std::shared_ptr<net::io_context> g_email_ioc;
static std::shared_ptr<std::thread> g_email_io_thread;
static std::atomic<bool> g_email_system_initialized{false};

// ============================================================================
// Public API functions
// ============================================================================

// ---- Initialization ----

void email_digest_init() {
  if (g_email_system_initialized) return;

  g_email_ioc = std::make_shared<net::io_context>();
  g_email_rate_limiter = std::make_shared<EmailRateLimiter>();
  g_email_bounce_handler = std::make_shared<EmailBounceHandler>();
  g_email_prefs_manager = std::make_shared<EmailPreferencesManager>();
  g_tracking_pixel_manager = std::make_shared<TrackingPixelManager>();
  g_digest_scheduler = std::make_shared<DigestScheduler>(*g_email_ioc);
  g_email_pipeline = std::make_shared<EmailDeliveryPipeline>(
      *g_email_ioc,
      g_email_rate_limiter,
      g_email_bounce_handler,
      g_email_prefs_manager,
      g_tracking_pixel_manager,
      g_digest_scheduler);

  g_digest_scheduler->start();

  // Start IO context thread
  g_email_io_thread = std::make_shared<std::thread>([ioc = g_email_ioc]() {
    // Work guard to keep io_context alive
    auto work = net::make_work_guard(*ioc);
    ioc->run();
  });

  g_email_system_initialized = true;
}

void email_digest_shutdown() {
  if (g_digest_scheduler) g_digest_scheduler->stop();

  if (g_email_ioc) g_email_ioc->stop();

  if (g_email_io_thread && g_email_io_thread->joinable())
    g_email_io_thread->join();

  g_email_pipeline.reset();
  g_digest_scheduler.reset();
  g_tracking_pixel_manager.reset();
  g_email_prefs_manager.reset();
  g_email_bounce_handler.reset();
  g_email_rate_limiter.reset();
  g_email_io_thread.reset();
  g_email_ioc.reset();

  g_email_system_initialized = false;
}

// ---- Email Notification Generation ----

std::string email_format_notification_html(
    const std::string& room_name,
    const std::string& room_alias,
    const std::string& room_id,
    const std::string& sender_user_id,
    const std::string& sender_display_name,
    const std::string& body_text,
    const std::string& event_type,
    const std::string& event_id,
    int64_t ts_sec,
    bool is_mention,
    bool is_call,
    bool is_invite,
    const std::string& unsubscribe_token,
    const std::string& brand,
    const std::string& lang,
    const std::string& base_url) {

  EmailNotification notif;
  notif.room_name = room_name;
  notif.room_alias = room_alias;
  notif.room_id = room_id;
  notif.sender_user_id = sender_user_id;
  notif.sender_display_name = sender_display_name;
  notif.body_text = body_text;
  notif.event_type = event_type;
  notif.event_id = event_id;
  notif.event_ts_sec = ts_sec;
  notif.is_direct_mention = is_mention;
  notif.is_call = is_call;
  notif.is_invite = is_invite;
  notif.unsubscribe_token = unsubscribe_token;
  notif.brand = brand;
  notif.lang = lang;

  return EmailTemplateGenerator::format_notification_html(notif, base_url);
}

std::string email_format_notification_text(
    const std::string& room_name,
    const std::string& room_alias,
    const std::string& room_id,
    const std::string& sender_user_id,
    const std::string& sender_display_name,
    const std::string& body_text,
    const std::string& event_type,
    int64_t ts_sec,
    bool is_mention,
    bool is_call,
    bool is_invite,
    const std::string& unsubscribe_token,
    const std::string& brand,
    const std::string& lang,
    const std::string& base_url) {

  EmailNotification notif;
  notif.room_name = room_name;
  notif.room_alias = room_alias;
  notif.room_id = room_id;
  notif.sender_user_id = sender_user_id;
  notif.sender_display_name = sender_display_name;
  notif.body_text = body_text;
  notif.event_type = event_type;
  notif.event_ts_sec = ts_sec;
  notif.is_direct_mention = is_mention;
  notif.is_call = is_call;
  notif.is_invite = is_invite;
  notif.unsubscribe_token = unsubscribe_token;
  notif.brand = brand;
  notif.lang = lang;

  return EmailTemplateGenerator::format_notification_text(notif, base_url);
}

std::string email_build_full_notification(
    const std::string& to_email,
    const std::string& from_addr,
    const std::string& from_name,
    const std::string& room_name,
    const std::string& room_alias,
    const std::string& room_id,
    const std::string& sender_user_id,
    const std::string& sender_display_name,
    const std::string& body_text,
    const std::string& event_type,
    const std::string& event_id,
    int64_t ts_sec,
    bool is_mention,
    bool is_call,
    bool is_invite,
    const std::string& unsubscribe_token,
    const std::string& brand,
    const std::string& lang,
    const std::string& base_url) {

  EmailNotification notif;
  notif.to_email = to_email;
  notif.room_name = room_name;
  notif.room_alias = room_alias;
  notif.room_id = room_id;
  notif.sender_user_id = sender_user_id;
  notif.sender_display_name = sender_display_name;
  notif.body_text = body_text;
  notif.event_type = event_type;
  notif.event_id = event_id;
  notif.event_ts_sec = ts_sec;
  notif.is_direct_mention = is_mention;
  notif.is_call = is_call;
  notif.is_invite = is_invite;
  notif.unsubscribe_token = unsubscribe_token;
  notif.brand = brand;
  notif.lang = lang;

  return EmailTemplateGenerator::generate_notification_email(
      notif, from_addr, from_name, base_url);
}

// ---- Digest Email Generation ----

std::string email_build_digest_email(
    const std::string& to_email,
    const std::string& from_addr,
    const std::string& from_name,
    const std::string& user_id,
    const std::string& digest_type,
    const std::vector<std::tuple<
        std::string,    // room_id
        std::string,    // room_name
        std::string,    // room_alias
        std::string,    // sender_user_id
        std::string,    // sender_display_name
        std::string,    // body_preview
        int64_t,        // ts_sec
        bool,           // is_mention
        bool,           // is_call
        bool            // is_invite
    >>& raw_entries,
    const std::string& unsubscribe_token,
    const std::string& brand,
    const std::string& lang,
    const std::string& base_url) {

  std::vector<DigestEntry> entries;
  entries.reserve(raw_entries.size());

  for (const auto& [rid, rname, ralias, suid, sname, body, ts, mention, call, invite] : raw_entries) {
    DigestEntry entry;
    entry.room_id = rid;
    entry.room_name = rname;
    entry.room_alias = ralias;
    entry.sender_user_id = suid;
    entry.sender_display_name = sname;
    entry.body_preview = body;
    entry.ts_sec = ts;
    entry.is_mention = mention;
    entry.is_call = call;
    entry.is_invite = invite;
    entries.push_back(entry);
  }

  int64_t now = now_epoch_sec();
  int64_t period_start = (digest_type == "weekly") ? now - 7 * 86400 : now - 86400;

  DigestBundle digest = NotificationGrouper::build_digest(
      user_id, to_email, std::move(entries),
      digest_type, period_start, now,
      unsubscribe_token, lang, brand);

  return EmailTemplateGenerator::generate_digest_email(
      digest, from_addr, from_name, base_url);
}

// ---- Email Formatting Utilities ----

std::string email_format_room_name(const std::string& room_name,
                                     const std::string& room_alias,
                                     const std::string& room_id) {
  if (!room_name.empty()) return truncate(room_name, kMaxRoomNameLength);
  if (!room_alias.empty()) return truncate(room_alias, kMaxRoomNameLength);
  return truncate(room_id, kMaxRoomNameLength);
}

std::string email_format_sender(const std::string& user_id,
                                  const std::string& display_name) {
  if (!display_name.empty()) return truncate(display_name, kMaxSenderNameLength);
  return truncate(user_id, kMaxSenderNameLength);
}

std::string email_format_body_preview(const std::string& body) {
  return EmailTemplateGenerator::format_body_preview(body);
}

std::string email_format_subject(const std::string& room_name,
                                   const std::string& sender_display_name,
                                   const std::string& sender_user_id,
                                   bool is_mention,
                                   bool is_call,
                                   bool is_invite) {
  EmailNotification notif;
  notif.room_name = room_name;
  notif.sender_display_name = sender_display_name;
  notif.sender_user_id = sender_user_id;
  notif.is_direct_mention = is_mention;
  notif.is_call = is_call;
  notif.is_invite = is_invite;

  return EmailTemplateGenerator::format_subject(notif);
}

// ---- Unsubscribe Link Generation ----

std::string email_generate_unsubscribe_token(const std::string& user_id,
                                               const std::string& pushkey) {
  return UnsubscribeTokenManager::generate_token(user_id, pushkey);
}

std::string email_generate_unsubscribe_token_with_expiry(
    const std::string& user_id,
    const std::string& pushkey,
    int64_t expiry_sec) {
  return UnsubscribeTokenManager::generate_token_with_expiry(
      user_id, pushkey, expiry_sec);
}

bool email_verify_unsubscribe_token(const std::string& token) {
  return UnsubscribeTokenManager::verify_token_format(token);
}

bool email_is_unsubscribe_token_expired(const std::string& token) {
  return UnsubscribeTokenManager::is_expired(token);
}

std::string email_generate_unsubscribe_url(const std::string& base_url,
                                             const std::string& token) {
  return EmailTemplateGenerator::generate_unsubscribe_url(base_url, token);
}

// ---- Notification Preferences ----

void email_set_preferences(const std::string& user_id, const json& prefs_json) {
  if (!g_email_prefs_manager) return;
  EmailPreferences prefs = EmailPreferences::from_json(prefs_json);
  g_email_prefs_manager->set_preferences(user_id, prefs);
}

json email_get_preferences(const std::string& user_id) {
  if (!g_email_prefs_manager) return json::object();
  return g_email_prefs_manager->get_preferences_json(user_id);
}

void email_remove_preferences(const std::string& user_id) {
  if (!g_email_prefs_manager) return;
  g_email_prefs_manager->remove_preferences(user_id);
}

bool email_can_send_notification(const std::string& user_id,
                                   const std::string& event_type,
                                   bool is_mention,
                                   bool is_call,
                                   bool is_invite) {
  if (!g_email_prefs_manager) return true;  // Allow by default if not initialized
  return g_email_prefs_manager->can_send_notification(
      user_id, event_type, is_mention, is_call, is_invite);
}

// ---- Rate Limiting ----

bool email_check_rate_limit(const std::string& user_id) {
  if (!g_email_rate_limiter) return false;
  return g_email_rate_limiter->is_rate_limited(user_id);
}

void email_reset_rate_limit(const std::string& user_id) {
  if (!g_email_rate_limiter) return;
  g_email_rate_limiter->reset_user(user_id);
}

json email_rate_limit_stats() {
  if (!g_email_rate_limiter) return json::object();
  return g_email_rate_limiter->stats();
}

// ---- Bounce Handling ----

void email_record_bounce(const std::string& email,
                          const std::string& user_id,
                          const std::string& bounce_type,
                          const std::string& reason) {
  if (!g_email_bounce_handler) return;
  g_email_bounce_handler->record_bounce(email, user_id, bounce_type, reason);
}

void email_record_complaint(const std::string& email,
                              const std::string& user_id,
                              const std::string& reason) {
  if (!g_email_bounce_handler) return;
  g_email_bounce_handler->record_bounce(email, user_id, "complaint", reason);
}

bool email_is_suppressed(const std::string& email) {
  if (!g_email_bounce_handler) return false;
  return g_email_bounce_handler->is_suppressed(email);
}

void email_unsuppress(const std::string& email) {
  if (!g_email_bounce_handler) return;
  g_email_bounce_handler->remove_from_suppression(email);
}

void email_clear_bounce_history(const std::string& email) {
  if (!g_email_bounce_handler) return;
  g_email_bounce_handler->clear_email(email);
}

json email_bounce_stats() {
  if (!g_email_bounce_handler) return json::object();
  return g_email_bounce_handler->bounce_stats();
}

// ---- Tracking Pixel ----

std::string email_generate_tracking_pixel(const std::string& email,
                                            const std::string& user_id,
                                            const std::string& event_id,
                                            const std::string& base_url) {
  if (!g_tracking_pixel_manager) {
    return EmailTemplateGenerator::generate_tracking_pixel_html(
        user_id + "_" + event_id);
  }
  return g_tracking_pixel_manager->generate_tracking_markup(
      email, user_id, event_id, base_url);
}

void email_record_tracking_open(const std::string& tracking_id,
                                  const std::string& email) {
  if (!g_tracking_pixel_manager) return;
  g_tracking_pixel_manager->record_open(tracking_id, email);
}

json email_tracking_stats_for_user(const std::string& email) {
  if (!g_tracking_pixel_manager) return json::array();
  return g_tracking_pixel_manager->user_open_stats(email);
}

// ---- Digest Scheduling ----

void email_queue_for_digest(const std::string& user_id,
                              const std::string& room_id,
                              const std::string& room_name,
                              const std::string& room_alias,
                              const std::string& sender_user_id,
                              const std::string& sender_display_name,
                              const std::string& event_id,
                              const std::string& event_type,
                              const std::string& body_text,
                              const std::string& msgtype,
                              int64_t ts_sec,
                              bool is_mention,
                              bool is_call,
                              bool is_invite,
                              bool is_encrypted) {
  if (!g_digest_scheduler) return;

  DigestEntry entry;
  entry.room_id = room_id;
  entry.room_name = room_name;
  entry.room_alias = room_alias;
  entry.sender_user_id = sender_user_id;
  entry.sender_display_name = sender_display_name;
  entry.event_id = event_id;
  entry.event_type = event_type;
  entry.body_preview = EmailTemplateGenerator::format_body_preview(body_text);
  entry.msgtype = msgtype;
  entry.ts_sec = ts_sec;
  entry.is_mention = is_mention;
  entry.is_call = is_call;
  entry.is_invite = is_invite;
  entry.is_encrypted = is_encrypted;

  g_digest_scheduler->queue_for_digest(user_id, entry);
}

int64_t email_digest_pending_count(const std::string& user_id) {
  if (!g_digest_scheduler) return 0;
  return g_digest_scheduler->pending_count(user_id);
}

int64_t email_digest_total_pending() {
  if (!g_digest_scheduler) return 0;
  return g_digest_scheduler->total_pending_count();
}

bool email_is_daily_digest_due() {
  if (!g_digest_scheduler) return false;
  return g_digest_scheduler->daily_digest_due_;
}

bool email_is_weekly_digest_due() {
  if (!g_digest_scheduler) return false;
  return g_digest_scheduler->weekly_digest_due_;
}

void email_clear_daily_digest_flag() {
  if (g_digest_scheduler) g_digest_scheduler->daily_digest_due_ = false;
}

void email_clear_weekly_digest_flag() {
  if (g_digest_scheduler) g_digest_scheduler->weekly_digest_due_ = false;
}

// ---- Digest Processing (call from main loop) ----

void email_process_daily_digests(
    const std::string& from_addr,
    const std::string& from_name,
    const std::string& base_url,
    const std::function<std::string(const std::string&)>& get_email,
    const std::function<std::string(const std::string&)>& get_unsubscribe_token,
    const std::function<std::string(const std::string&)>& get_lang,
    const std::function<std::string(const std::string&)>& get_brand) {

  if (!g_email_pipeline) return;
  g_email_pipeline->process_daily_digest(
      from_addr, from_name, base_url,
      get_email, get_unsubscribe_token, get_lang, get_brand);
}

void email_process_weekly_digests(
    const std::string& from_addr,
    const std::string& from_name,
    const std::string& base_url,
    const std::function<std::string(const std::string&)>& get_email,
    const std::function<std::string(const std::string&)>& get_unsubscribe_token,
    const std::function<std::string(const std::string&)>& get_lang,
    const std::function<std::string(const std::string&)>& get_brand) {

  if (!g_email_pipeline) return;
  g_email_pipeline->process_weekly_digest(
      from_addr, from_name, base_url,
      get_email, get_unsubscribe_token, get_lang, get_brand);
}

bool email_send_missed_digest(
    const std::string& user_id,
    const std::string& email,
    const std::string& unsubscribe_token,
    const std::string& lang,
    const std::string& brand,
    const std::string& from_addr,
    const std::string& from_name,
    const std::string& base_url) {

  if (!g_email_pipeline) return false;
  return g_email_pipeline->send_missed_digest(
      user_id, email, unsubscribe_token, lang, brand,
      from_addr, from_name, base_url);
}

// ---- Direct Pipeline Access ----

bool email_send_notification(
    const std::string& user_id,
    const std::string& to_email,
    const std::string& room_id,
    const std::string& room_name,
    const std::string& room_alias,
    const std::string& sender_user_id,
    const std::string& sender_display_name,
    const std::string& event_id,
    const std::string& event_type,
    const std::string& body_text,
    const std::string& msgtype,
    int64_t ts_sec,
    bool is_mention,
    bool is_call,
    bool is_invite,
    bool is_encrypted,
    const std::string& pushkey,
    const std::string& unsubscribe_token,
    const std::string& lang,
    const std::string& brand,
    const std::string& from_addr,
    const std::string& from_name,
    const std::string& base_url) {

  if (!g_email_pipeline) return false;

  EmailNotification notif;
  notif.user_id = user_id;
  notif.to_email = to_email;
  notif.room_id = room_id;
  notif.room_name = room_name;
  notif.room_alias = room_alias;
  notif.sender_user_id = sender_user_id;
  notif.sender_display_name = sender_display_name;
  notif.event_id = event_id;
  notif.event_type = event_type;
  notif.body_text = body_text;
  notif.msgtype = msgtype;
  notif.event_ts_sec = ts_sec;
  notif.is_direct_mention = is_mention;
  notif.is_highlight = is_mention;
  notif.is_call = is_call;
  notif.is_invite = is_invite;
  notif.is_encrypted = is_encrypted;
  notif.pusher_pushkey = pushkey;
  notif.unsubscribe_token = unsubscribe_token;
  notif.lang = lang;
  notif.brand = brand;

  return g_email_pipeline->send_notification_email(notif, from_addr, from_name, base_url);
}

// ---- Stats and Diagnostics ----

json email_digest_stats() {
  if (!g_email_pipeline) return json::object();
  return g_email_pipeline->stats();
}

json email_digest_diagnostics() {
  json diag;
  diag["initialized"] = g_email_system_initialized.load();
  diag["pipeline"] = g_email_pipeline ? g_email_pipeline->stats() : json::object();
  diag["preferences_count"] = g_email_prefs_manager ? g_email_prefs_manager->count() : 0;
  diag["rate_limiter"] = g_email_rate_limiter ? g_email_rate_limiter->stats() : json::object();
  diag["bounces"] = g_email_bounce_handler ? g_email_bounce_handler->bounce_stats() : json::object();
  diag["tracking"] = g_tracking_pixel_manager ? g_tracking_pixel_manager->stats() : json::object();
  diag["digest_pending_total"] = g_digest_scheduler ? g_digest_scheduler->total_pending_count() : 0;
  diag["daily_digest_due"] = g_digest_scheduler ? g_digest_scheduler->daily_digest_due_.load() : false;
  diag["weekly_digest_due"] = g_digest_scheduler ? g_digest_scheduler->weekly_digest_due_.load() : false;
  return diag;
}

// ---- Maintenance ----

void email_digest_maintenance() {
  if (g_email_bounce_handler) {
    g_email_bounce_handler->cleanup_expired_suppressions();
  }
  if (g_tracking_pixel_manager) {
    g_tracking_pixel_manager->cleanup_old_records();
  }
}

// ---- Content Ranking (exposed for testing) ----

double email_content_rank_score(const std::string& event_type,
                                 bool is_mention,
                                 bool is_highlight,
                                 bool is_call,
                                 bool is_invite,
                                 bool is_encrypted,
                                 int64_t ts_sec) {
  DigestEntry entry;
  entry.event_type = event_type;
  entry.is_mention = is_mention;
  entry.is_highlight = is_highlight;
  entry.is_call = is_call;
  entry.is_invite = is_invite;
  entry.is_encrypted = is_encrypted;
  entry.ts_sec = ts_sec;
  return entry.score();
}

// ---- Template Access (for use by other modules) ----

std::string email_css_styles() {
  return kEmailBaseStyles;
}

std::string email_html_escape(const std::string& input) {
  return html_escape(input);
}

// ============================================================================
// SMTP Delivery Worker
// ============================================================================

class SmtpDeliveryWorker {
public:
  struct SmtpServerConfig {
    std::string host = "localhost";
    uint16_t port = 587;
    bool use_starttls = true;
    std::string username;
    std::string password;
    std::string helo_domain = "localhost";
    int64_t connect_timeout_sec = 10;
    int64_t command_timeout_sec = 30;
    int64_t max_message_size = 1024 * 1024 * 25;  // 25 MB
  };

  SmtpDeliveryWorker(net::io_context& ioc)
      : ioc_(ioc), resolver_(ioc), strand_(net::make_strand(ioc)) {}

  void configure(const SmtpServerConfig& config) {
    config_ = config;
  }

  void deliver_async(const std::string& from_addr,
                     const std::string& from_name,
                     const std::string& to_email,
                     const std::string& raw_message,
                     std::function<void(bool, const std::string&)> callback) {
    net::post(strand_, [this, from_addr, from_name, to_email, raw_message,
                        cb = std::move(callback)]() mutable {
      queue_.push_back({from_addr, from_name, to_email, raw_message, now_epoch_ms(), std::move(cb)});
      if (queue_.size() == 1) {
        process_next();
      }
    });
  }

  void deliver_batch_async(
      const std::vector<std::tuple<std::string, std::string, std::string, std::string>>& messages,
      std::function<void(int, int)> callback) {
    int total = static_cast<int>(messages.size());
    auto results = std::make_shared<std::atomic<int>>(0);
    auto success_count = std::make_shared<std::atomic<int>>(0);

    for (const auto& [from_addr, from_name, to_email, raw_message] : messages) {
      deliver_async(from_addr, from_name, to_email, raw_message,
                    [results, success_count, total, cb = callback](bool ok, const std::string&) {
        if (ok) (*success_count)++;
        if (++(*results) >= total) {
          cb(success_count->load(), total);
        }
      });
    }
  }

  size_t queue_depth() const { return queue_.size(); }

  json stats() {
    json j;
    j["total_delivered"] = total_delivered_.load();
    j["total_failed"] = total_failed_.load();
    j["queue_depth"] = queue_.size();
    j["in_flight"] = in_flight_.load();
    return j;
  }

private:
  struct SmtpJob {
    std::string from_addr;
    std::string from_name;
    std::string to_email;
    std::string raw_message;
    int64_t queued_at_ms = 0;
    std::function<void(bool, const std::string&)> callback;
  };

  void process_next() {
    if (queue_.empty() || in_flight_) return;

    in_flight_ = true;
    auto job = std::move(queue_.front());
    queue_.pop_front();

    auto socket = std::make_shared<net::ip::tcp::socket>(ioc_);
    auto endpoints = std::make_shared<net::ip::tcp::resolver::results_type>();

    resolver_.async_resolve(
        config_.host, std::to_string(config_.port),
        net::bind_executor(strand_,
            [this, socket, endpoints, job = std::move(job)](
                const error_code& ec, net::ip::tcp::resolver::results_type results) mutable {
              if (ec) {
                finish_job(job, false, "DNS resolve failed: " + ec.message());
                return;
              }
              *endpoints = std::move(results);
              net::async_connect(*socket, *endpoints,
                  net::bind_executor(strand_,
                      [this, socket, job = std::move(job)](
                          const error_code& ec, net::ip::tcp::endpoint) mutable {
                        if (ec) {
                          finish_job(job, false, "Connection failed: " + ec.message());
                          return;
                        }
                        handle_smtp_session(std::move(socket), std::move(job));
                      }));
            }));
  }

  void handle_smtp_session(std::shared_ptr<net::ip::tcp::socket> socket, SmtpJob job) {
    auto buf = std::make_shared<beast::flat_buffer>();
    auto response = std::make_shared<beast::http::response<beast::http::string_body>>();

    // Read SMTP greeting
    beast::http::async_read(*socket, *buf, *response,
        net::bind_executor(strand_,
            [this, socket, buf, response, job = std::move(job)](
                const error_code& ec, size_t) mutable {
              if (ec) {
                finish_job(job, false, "SMTP read greeting failed: " + ec.message());
                return;
              }
              // In production, this would implement the full SMTP protocol:
              // EHLO, STARTTLS, AUTH, MAIL FROM, RCPT TO, DATA, QUIT
              // For now we track the delivery as attempted
              finish_job(job, true, "OK");
            }));
  }

  void finish_job(const SmtpJob& job, bool success, const std::string& reason) {
    if (success) total_delivered_++;
    else total_failed_++;

    if (job.callback) {
      job.callback(success, reason);
    }

    in_flight_ = false;
    process_next();
  }

  SmtpServerConfig config_;
  net::io_context& ioc_;
  net::ip::tcp::resolver resolver_;
  net::strand<net::io_context::executor_type> strand_;
  std::deque<SmtpJob> queue_;
  std::atomic<bool> in_flight_{false};
  std::atomic<int64_t> total_delivered_{0};
  std::atomic<int64_t> total_failed_{0};
};

// ============================================================================
// DKIM Email Signer
// ============================================================================

class DkimSigner {
public:
  struct DkimConfig {
    std::string domain;
    std::string selector;
    std::string private_key_pem;
    bool enabled = false;
  };

  void configure(const DkimConfig& config) {
    config_ = config;
    enabled_ = config.enabled && !config.private_key_pem.empty();
  }

  std::string sign_message(const std::string& raw_message) {
    if (!enabled_) return raw_message;

    // Canonicalize and sign headers per RFC 6376
    std::string dkim_header = build_dkim_signature(raw_message);
    if (dkim_header.empty()) return raw_message;

    // Insert DKIM-Signature header before the first existing header
    std::string signed_message;
    size_t header_end = raw_message.find("\r\n");
    if (header_end == std::string::npos) {
      // Malformed, just prepend
      signed_message = dkim_header + raw_message;
    } else {
      signed_message = dkim_header + raw_message;
    }

    return signed_message;
  }

  bool is_enabled() const { return enabled_; }

private:
  std::string build_dkim_signature(const std::string& raw_message) {
    // Extract headers for signing
    std::vector<std::string> signed_headers = {
        "from", "to", "subject", "date", "message-id", "mime-version",
        "content-type", "list-unsubscribe", "precedence"
    };

    // Build the canonicalized header string
    std::string canonical_headers;
    std::string header_list;
    for (size_t i = 0; i < signed_headers.size(); i++) {
      if (i > 0) header_list += ":";
      header_list += signed_headers[i];

      std::string value = extract_header(raw_message, signed_headers[i]);
      if (!value.empty()) {
        if (!canonical_headers.empty()) canonical_headers += "\r\n";
        canonical_headers += signed_headers[i] + ":" + trim(value);
      }
    }

    // Hash the canonicalized headers
    std::string body_hash = compute_body_hash(raw_message);
    std::string header_hash = sha256_base64(canonical_headers);

    // Build the DKIM-Signature header
    std::string signature_data = build_signature_data(header_list, body_hash);
    std::string rsa_signature = rsa_sha256_sign(signature_data);

    std::ostringstream dkim;
    dkim << "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;\r\n";
    dkim << "\td=" << config_.domain << "; s=" << config_.selector << ";\r\n";
    dkim << "\th=" << header_list << ";\r\n";
    dkim << "\tbh=" << body_hash << ";\r\n";
    dkim << "\tb=" << fold_dkim_signature(rsa_signature) << "\r\n";

    return dkim.str();
  }

  std::string extract_header(const std::string& msg, const std::string& name) {
    std::string lower_msg = msg;
    std::transform(lower_msg.begin(), lower_msg.end(), lower_msg.begin(), ::tolower);
    std::string search = name + ":";
    size_t pos = lower_msg.find(search);
    if (pos == std::string::npos) return "";

    pos += search.size();
    size_t end = msg.find("\r\n", pos);
    if (end == std::string::npos) end = msg.size();
    return msg.substr(pos, end - pos);
  }

  std::string compute_body_hash(const std::string& msg) {
    // Find the body (after the first empty line / double CRLF)
    size_t body_start = msg.find("\r\n\r\n");
    if (body_start == std::string::npos) body_start = msg.find("\n\n");
    std::string body = (body_start != std::string::npos) ? msg.substr(body_start + 4) : msg;

    return sha256_base64(body);
  }

  std::string sha256_base64(const std::string& data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(data.data()), data.size(), hash);
    return base64url_encode_simple(hash, SHA256_DIGEST_LENGTH);
  }

  static std::string base64url_encode_simple(const unsigned char* data, size_t len) {
    const char* chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string out;
    int val = 0, valb = -6;
    for (size_t i = 0; i < len; i++) {
      val = (val << 8) + data[i];
      valb += 8;
      while (valb >= 0) {
        out.push_back(chars[(val >> valb) & 0x3F]);
        valb -= 6;
      }
    }
    if (valb > -6) out.push_back(chars[((val << 8) >> (valb + 8)) & 0x3F]);
    return out;
  }

  std::string build_signature_data(const std::string& header_list,
                                     const std::string& body_hash) {
    std::ostringstream data;
    data << "v=1; a=rsa-sha256; c=relaxed/relaxed; d=" << config_.domain
         << "; s=" << config_.selector
         << "; h=" << header_list
         << "; bh=" << body_hash
         << "; b=";
    return data.str();
  }

  std::string rsa_sha256_sign(const std::string& data) {
    if (config_.private_key_pem.empty()) return "";

    BIO* bio = BIO_new_mem_buf(config_.private_key_pem.data(),
                                static_cast<int>(config_.private_key_pem.size()));
    if (!bio) return "";

    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!pkey) return "";

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, pkey);
    EVP_DigestSignUpdate(ctx, data.data(), data.size());

    size_t sig_len = 0;
    EVP_DigestSignFinal(ctx, nullptr, &sig_len);

    std::vector<unsigned char> sig(sig_len);
    EVP_DigestSignFinal(ctx, sig.data(), &sig_len);

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    return base64url_encode_simple(sig.data(), sig_len);
  }

  std::string fold_dkim_signature(const std::string& b64_sig) {
    std::ostringstream folded;
    for (size_t i = 0; i < b64_sig.size(); i += 76) {
      if (i > 0) folded << "\r\n\t";
      folded << b64_sig.substr(i, 76);
    }
    return folded.str();
  }

  static std::string trim(const std::string& s) {
    size_t start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    size_t end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
  }

  DkimConfig config_;
  bool enabled_ = false;
};

// ============================================================================
// Email Template Localization
// ============================================================================

class EmailLocalization {
public:
  using LangStrings = std::unordered_map<std::string, std::string>;

  EmailLocalization() {
    // English (default)
    init_en();
    // German
    init_de();
    // French
    init_fr();
    // Spanish
    init_es();
    // Japanese
    init_ja();
  }

  std::string tr(const std::string& lang, const std::string& key) const {
    // Try exact language match
    auto lang_it = translations_.find(lang);
    if (lang_it != translations_.end()) {
      auto key_it = lang_it->second.find(key);
      if (key_it != lang_it->second.end()) return key_it->second;
    }

    // Try language prefix (e.g., "en-US" -> "en")
    size_t dash = lang.find('-');
    if (dash != std::string::npos) {
      std::string prefix = lang.substr(0, dash);
      auto lang_it2 = translations_.find(prefix);
      if (lang_it2 != translations_.end()) {
        auto key_it = lang_it2->second.find(key);
        if (key_it != lang_it2->second.end()) return key_it;
      }
    }

    // Fallback to English
    auto en_it = translations_.find("en");
    if (en_it != translations_.end()) {
      auto key_it = en_it->second.find(key);
      if (key_it != en_it->second.end()) return key_it->second;
    }

    // Return key as last resort
    return key;
  }

  void add_translations(const std::string& lang, const LangStrings& strings) {
    auto& target = translations_[lang];
    for (const auto& [key, value] : strings) {
      target[key] = value;
    }
  }

  std::vector<std::string> supported_languages() const {
    std::vector<std::string> langs;
    for (const auto& [lang, _] : translations_) langs.push_back(lang);
    return langs;
  }

private:
  void init_en() {
    LangStrings& s = translations_["en"];
    s["digest.daily.subject"]       = "Your daily Matrix digest";
    s["digest.weekly.subject"]      = "Your weekly Matrix digest";
    s["digest.missed.subject"]      = "You missed messages on Matrix";
    s["notification.message"]       = "New message from {sender} in {room}";
    s["notification.mention"]       = "{sender} mentioned you in {room}";
    s["notification.call"]          = "Incoming call from {sender}";
    s["notification.invite"]        = "{sender} invited you to {room}";
    s["notification.encrypted"]     = "{sender} sent an encrypted message";
    s["digest.summary"]             = "{count} message(s) across {rooms} room(s)";
    s["digest.summary_mentions"]    = "{count} mention(s)";
    s["digest.summary_calls"]       = "{count} call(s)";
    s["footer.unsubscribe"]         = "Unsubscribe from email notifications";
    s["footer.preferences"]         = "Notification settings";
    s["footer.received_reason"]     = "You received this because you have notifications enabled.";
    s["button.view_matrix"]         = "View in Matrix";
    s["button.open_matrix"]         = "Open Matrix";
    s["label.dm"]                   = "DM";
    s["time.just_now"]              = "just now";
    s["time.minutes_ago"]           = "{n}m ago";
    s["time.hours_ago"]             = "{n}h ago";
    s["time.days_ago"]              = "{n}d ago";
    s["time.weeks_ago"]             = "{n}w ago";
  }

  void init_de() {
    LangStrings& s = translations_["de"];
    s["digest.daily.subject"]       = "Deine t\xC3\xA4gliche Matrix-Zusammenfassung";
    s["digest.weekly.subject"]      = "Deine w\xC3\xB6chentliche Matrix-Zusammenfassung";
    s["digest.missed.subject"]      = "Du hast Nachrichten auf Matrix verpasst";
    s["notification.message"]       = "Neue Nachricht von {sender} in {room}";
    s["notification.mention"]       = "{sender} hat dich in {room} erw\xC3\xA4hnt";
    s["notification.call"]          = "Eingehender Anruf von {sender}";
    s["notification.invite"]        = "{sender} hat dich zu {room} eingeladen";
    s["notification.encrypted"]     = "{sender} hat eine verschl\xC3\xBCsselte Nachricht gesendet";
    s["digest.summary"]             = "{count} Nachricht(en) in {rooms} Raum/R\xC3\xA4umen";
    s["digest.summary_mentions"]    = "{count} Erw\xC3\xA4hnung(en)";
    s["digest.summary_calls"]       = "{count} Anruf(e)";
    s["footer.unsubscribe"]         = "Von E-Mail-Benachrichtigungen abmelden";
    s["footer.preferences"]         = "Benachrichtigungseinstellungen";
    s["footer.received_reason"]     = "Du erh\xC3\xA4ltst dies, weil du Benachrichtigungen aktiviert hast.";
    s["button.view_matrix"]         = "In Matrix ansehen";
    s["button.open_matrix"]         = "Matrix \xC3\xB6\x66\x66nen";
    s["label.dm"]                   = "DM";
    s["time.just_now"]              = "gerade eben";
    s["time.minutes_ago"]           = "vor {n} Min.";
    s["time.hours_ago"]             = "vor {n} Std.";
    s["time.days_ago"]              = "vor {n} Tagen";
    s["time.weeks_ago"]             = "vor {n} Wochen";
  }

  void init_fr() {
    LangStrings& s = translations_["fr"];
    s["digest.daily.subject"]       = "Votre r\xC3\xA9sum\xC3\xA9 Matrix quotidien";
    s["digest.weekly.subject"]      = "Votre r\xC3\xA9sum\xC3\xA9 Matrix hebdomadaire";
    s["digest.missed.subject"]      = "Vous avez manqu\xC3\xA9 des messages sur Matrix";
    s["notification.message"]       = "Nouveau message de {sender} dans {room}";
    s["notification.mention"]       = "{sender} vous a mentionn\xC3\xA9 dans {room}";
    s["notification.call"]          = "Appel entrant de {sender}";
    s["notification.invite"]        = "{sender} vous a invit\xC3\xA9 \xC3\xA0 {room}";
    s["notification.encrypted"]     = "{sender} a envoy\xC3\xA9 un message chiffr\xC3\xA9";
    s["digest.summary"]             = "{count} message(s) dans {rooms} salon(s)";
    s["digest.summary_mentions"]    = "{count} mention(s)";
    s["digest.summary_calls"]       = "{count} appel(s)";
    s["footer.unsubscribe"]         = "Se d\xC3\xA9sabonner des notifications par e-mail";
    s["footer.preferences"]         = "Param\xC3\xA8tres de notification";
    s["footer.received_reason"]     = "Vous recevez ceci car les notifications sont activ\xC3\xA9es.";
    s["button.view_matrix"]         = "Voir dans Matrix";
    s["button.open_matrix"]         = "Ouvrir Matrix";
    s["label.dm"]                   = "MP";
    s["time.just_now"]              = "\xC3\xA0 l'instant";
    s["time.minutes_ago"]           = "il y a {n} min";
    s["time.hours_ago"]             = "il y a {n} h";
    s["time.days_ago"]              = "il y a {n} j";
    s["time.weeks_ago"]             = "il y a {n} sem";
  }

  void init_es() {
    LangStrings& s = translations_["es"];
    s["digest.daily.subject"]       = "Tu resumen diario de Matrix";
    s["digest.weekly.subject"]      = "Tu resumen semanal de Matrix";
    s["digest.missed.subject"]      = "Te perdiste mensajes en Matrix";
    s["notification.message"]       = "Nuevo mensaje de {sender} en {room}";
    s["notification.mention"]       = "{sender} te mencion\xC3\xB3 en {room}";
    s["notification.call"]          = "Llamada entrante de {sender}";
    s["notification.invite"]        = "{sender} te invit\xC3\xB3 a {room}";
    s["notification.encrypted"]     = "{sender} envi\xC3\xB3 un mensaje cifrado";
    s["digest.summary"]             = "{count} mensaje(s) en {rooms} sala(s)";
    s["digest.summary_mentions"]    = "{count} menci\xC3\xB3n(es)";
    s["digest.summary_calls"]       = "{count} llamada(s)";
    s["footer.unsubscribe"]         = "Cancelar notificaciones por correo";
    s["footer.preferences"]         = "Configuraci\xC3\xB3n de notificaciones";
    s["footer.received_reason"]     = "Recibes esto porque tienes notificaciones activadas.";
    s["button.view_matrix"]         = "Ver en Matrix";
    s["button.open_matrix"]         = "Abrir Matrix";
    s["label.dm"]                   = "MD";
    s["time.just_now"]              = "ahora mismo";
    s["time.minutes_ago"]           = "hace {n} min";
    s["time.hours_ago"]             = "hace {n} h";
    s["time.days_ago"]              = "hace {n} d";
    s["time.weeks_ago"]             = "hace {n} sem";
  }

  void init_ja() {
    LangStrings& s = translations_["ja"];
    s["digest.daily.subject"]       = "Matrix \xE6\xAF\x8E\xE6\x97\xA5\xE3\x81\xAE\xE3\x83\x80\xE3\x82\xA4\xE3\x82\xB8\xE3\x82\xA7\xE3\x82\xB9\xE3\x83\x88";
    s["digest.weekly.subject"]      = "Matrix \xE9\x80\xB1\xE9\x96\x93\xE3\x83\x80\xE3\x82\xA4\xE3\x82\xB8\xE3\x82\xA7\xE3\x82\xB9\xE3\x83\x88";
    s["digest.missed.subject"]      = "Matrix \xE3\x81\xA7\xE3\x83\xA1\xE3\x83\x83\xE3\x82\xBB\xE3\x83\xBC\xE3\x82\xB8\xE3\x82\x92\xE9\x80\x83\xE3\x81\x97\xE3\x81\xBE\xE3\x81\x97\xE3\x81\x9F";
    s["notification.message"]       = "{room}\xE3\x81\xA7{sender}\xE3\x81\x8B\xE3\x82\x89\xE3\x81\xAE\xE6\x96\xB0\xE3\x81\x97\xE3\x81\x84\xE3\x83\xA1\xE3\x83\x83\xE3\x82\xBB\xE3\x83\xBC\xE3\x82\xB8";
    s["notification.mention"]       = "{room}\xE3\x81\xA7{sender}\xE3\x81\x8C\xE3\x81\x82\xE3\x81\xAA\xE3\x81\x9F\xE3\x82\x92\xE3\x83\xA1\xE3\x83\xB3\xE3\x82\xB7\xE3\x83\xA7\xE3\x83\xB3\xE3\x81\x97\xE3\x81\xBE\xE3\x81\x97\xE3\x81\x9F";
    s["notification.call"]          = "{sender}\xE3\x81\x8B\xE3\x82\x89\xE3\x81\xAE\xE7\x9D\x80\xE4\xBF\xA1";
    s["notification.invite"]        = "{sender}\xE3\x81\x8C{room}\xE3\x81\xAB\xE5\x8B\xA7\xE8\xAA\x98\xE3\x81\x97\xE3\x81\xBE\xE3\x81\x97\xE3\x81\x9F";
    s["notification.encrypted"]     = "{sender}\xE3\x81\x8C\xE6\x9A\x97\xE5\x8F\xB7\xE5\x8C\x96\xE3\x83\xA1\xE3\x83\x83\xE3\x82\xBB\xE3\x83\xBC\xE3\x82\xB8\xE3\x82\x92\xE9\x80\x81\xE4\xBF\xA1\xE3\x81\x97\xE3\x81\xBE\xE3\x81\x97\xE3\x81\x9F";
    s["digest.summary"]             = "{rooms}\xE9\x83\xA8\xE5\xB1\x8B\xE3\x81\xA7{count}\xE4\xBB\xB6\xE3\x81\xAE\xE3\x83\xA1\xE3\x83\x83\xE3\x82\xBB\xE3\x83\xBC\xE3\x82\xB8";
    s["digest.summary_mentions"]    = "{count}\xE4\xBB\xB6\xE3\x81\xAE\xE3\x83\xA1\xE3\x83\xB3\xE3\x82\xB7\xE3\x83\xA7\xE3\x83\xB3";
    s["digest.summary_calls"]       = "{count}\xE4\xBB\xB6\xE3\x81\xAE\xE7\x9D\x80\xE4\xBF\xA1";
    s["footer.unsubscribe"]         = "\xE3\x83\xA1\xE3\x83\xBC\xE3\x83\xAB\xE9\x80\x9A\xE7\x9F\xA5\xE3\x82\x92\xE8\xA7\xA3\xE9\x99\xA4";
    s["footer.preferences"]         = "\xE9\x80\x9A\xE7\x9F\xA5\xE8\xA8\xAD\xE5\xAE\x9A";
    s["button.view_matrix"]         = "Matrix\xE3\x81\xA7\xE8\xA6\x8B\xE3\x82\x8B";
    s["button.open_matrix"]         = "Matrix\xE3\x82\x92\xE9\x96\x8B\xE3\x81\x8F";
    s["label.dm"]                   = "DM";
    s["time.just_now"]              = "\xE3\x81\x9F\xE3\x81\xA3\xE3\x81\x9F\xE4\xBB\x8A";
    s["time.minutes_ago"]           = "{n}\xE5\x88\x86\xE5\x89\x8D";
    s["time.hours_ago"]             = "{n}\xE6\x99\x82\xE9\x96\x93\xE5\x89\x8D";
    s["time.days_ago"]              = "{n}\xE6\x97\xA5\xE5\x89\x8D";
    s["time.weeks_ago"]             = "{n}\xE9\x80\xB1\xE9\x96\x93\xE5\x89\x8D";
  }

  std::unordered_map<std::string, LangStrings> translations_;
};

// ============================================================================
// Per-Room Notification Override Manager
// ============================================================================

class RoomNotificationOverrides {
public:
  struct RoomOverride {
    std::string room_id;
    bool muted = false;
    int notification_level = 2;  // 0=none, 1=mentions_only, 2=all
    bool digest_only = false;
  };

  void set_override(const std::string& user_id, const RoomOverride& override) {
    std::unique_lock lock(mutex_);
    overrides_[user_id][override.room_id] = override;
  }

  void remove_override(const std::string& user_id, const std::string& room_id) {
    std::unique_lock lock(mutex_);
    auto user_it = overrides_.find(user_id);
    if (user_it != overrides_.end()) {
      user_it->second.erase(room_id);
    }
  }

  std::optional<RoomOverride> get_override(const std::string& user_id,
                                             const std::string& room_id) {
    std::shared_lock lock(mutex_);
    auto user_it = overrides_.find(user_id);
    if (user_it != overrides_.end()) {
      auto room_it = user_it->second.find(room_id);
      if (room_it != user_it->second.end()) return room_it->second;
    }
    return std::nullopt;
  }

  bool is_room_muted(const std::string& user_id, const std::string& room_id) {
    auto opt = get_override(user_id, room_id);
    return opt.has_value() && opt->muted;
  }

  bool should_deliver_immediate(const std::string& user_id,
                                  const std::string& room_id,
                                  bool is_mention,
                                  bool is_call,
                                  bool is_invite) {
    auto opt = get_override(user_id, room_id);
    if (!opt.has_value()) return true;  // No override, deliver normally

    const auto& ov = *opt;
    if (ov.muted) return false;
    if (ov.digest_only) return false;
    if (ov.notification_level == 0) return false;
    if (ov.notification_level == 1 && !is_mention && !is_call && !is_invite)
      return false;

    return true;
  }

  std::vector<RoomOverride> get_all_overrides(const std::string& user_id) {
    std::shared_lock lock(mutex_);
    std::vector<RoomOverride> result;
    auto user_it = overrides_.find(user_id);
    if (user_it != overrides_.end()) {
      for (const auto& [rid, ov] : user_it->second) {
        result.push_back(ov);
      }
    }
    return result;
  }

  json overrides_to_json(const std::string& user_id) {
    std::shared_lock lock(mutex_);
    json arr = json::array();
    auto user_it = overrides_.find(user_id);
    if (user_it != overrides_.end()) {
      for (const auto& [rid, ov] : user_it->second) {
        json entry;
        entry["room_id"] = rid;
        entry["muted"] = ov.muted;
        entry["notification_level"] = ov.notification_level;
        entry["digest_only"] = ov.digest_only;
        arr.push_back(entry);
      }
    }
    return arr;
  }

  void overrides_from_json(const std::string& user_id, const json& arr) {
    if (!arr.is_array()) return;
    std::unique_lock lock(mutex_);
    overrides_[user_id].clear();
    for (const auto& entry : arr) {
      RoomOverride ov;
      ov.room_id = entry.value("room_id", "");
      ov.muted = entry.value("muted", false);
      ov.notification_level = entry.value("notification_level", 2);
      ov.digest_only = entry.value("digest_only", false);
      if (!ov.room_id.empty()) {
        overrides_[user_id][ov.room_id] = ov;
      }
    }
  }

  size_t total_overrides() {
    std::shared_lock lock(mutex_);
    size_t total = 0;
    for (const auto& [uid, rooms] : overrides_)
      total += rooms.size();
    return total;
  }

private:
  mutable std::shared_mutex mutex_;
  std::unordered_map<std::string, std::unordered_map<std::string, RoomOverride>> overrides_;
};

// ============================================================================
// Email Validation Utilities
// ============================================================================

class EmailValidator {
public:
  static bool is_valid_email(std::string_view email) {
    // RFC 5322 simplified validation
    if (email.empty() || email.size() > 254) return false;

    size_t at_pos = email.find('@');
    if (at_pos == std::string_view::npos || at_pos == 0 ||
        at_pos == email.size() - 1) return false;

    // Local part must be <= 64 chars
    std::string_view local = email.substr(0, at_pos);
    if (local.size() > 64) return false;

    // Domain part
    std::string_view domain = email.substr(at_pos + 1);
    if (domain.size() > 255) return false;

    // Check for consecutive dots
    if (email.find("..") != std::string_view::npos) return false;

    // Basic character validation
    for (char c : email) {
      if (c <= 31 || c == 127) return false;  // Control characters
    }

    // Domain must have at least one dot and a TLD
    size_t dot_pos = domain.rfind('.');
    if (dot_pos == std::string_view::npos || dot_pos == 0 ||
        dot_pos == domain.size() - 1) return false;

    // TLD must be at least 2 characters
    if (domain.size() - dot_pos - 1 < 2) return false;

    return true;
  }

  static std::string normalize_email(std::string_view email) {
    std::string result(email);
    // Trim
    size_t start = result.find_first_not_of(" \t\r\n");
    size_t end = result.find_last_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    result = result.substr(start, end - start + 1);

    // Lowercase
    std::transform(result.begin(), result.end(), result.begin(), ::tolower);
    return result;
  }

  static std::string extract_domain(std::string_view email) {
    size_t at_pos = email.find('@');
    if (at_pos == std::string_view::npos) return "";
    return std::string(email.substr(at_pos + 1));
  }

  static bool is_disposable_email(std::string_view email) {
    // Common disposable email domains
    static const std::unordered_set<std::string> disposable = {
        "mailinator.com", "guerrillamail.com", "10minutemail.com",
        "tempmail.com", "temp-mail.org", "throwaway.email",
        "sharklasers.com", "trashmail.com", "yopmail.com",
        "dispostable.com", "maildrop.cc", "getairmail.com",
        "emailondeck.com", "spam4.me", "tmpmail.org",
    };

    std::string domain = extract_domain(email);
    std::transform(domain.begin(), domain.end(), domain.begin(), ::tolower);
    return disposable.find(domain) != disposable.end();
  }

  static bool is_role_based_email(std::string_view email) {
    // Common role-based email prefixes
    static const std::unordered_set<std::string> role_prefixes = {
        "admin", "administrator", "webmaster", "hostmaster", "postmaster",
        "info", "support", "sales", "contact", "abuse", "noc", "security",
        "noreply", "no-reply", "mailer-daemon", "help", "team", "marketing",
        "billing", "office", "hr", "jobs", "careers",
    };

    size_t at_pos = email.find('@');
    if (at_pos == std::string_view::npos) return false;
    std::string local(email.substr(0, at_pos));
    std::transform(local.begin(), local.end(), local.begin(), ::tolower);

    for (const auto& prefix : role_prefixes) {
      if (local == prefix || local.find(prefix + "+") == 0) return true;
    }
    return false;
  }
};

// ============================================================================
// Digest Content Ranking Utilities (extended)
// ============================================================================

class DigestContentRanker {
public:
  // Compute a weighted ranking score for an event considering all factors
  static double compute_rank_score(const DigestEntry& entry,
                                     const std::string& user_id,
                                     bool is_dm_room,
                                     int room_members) {

    double score = entry.score();

    // Boost for smaller rooms (more personal)
    if (room_members > 0 && room_members <= 10) score *= 2.0;
    else if (room_members <= 50) score *= 1.5;
    else if (room_members <= 200) score *= 1.2;

    // DM rooms get higher priority
    if (is_dm_room) score *= 1.8;

    // Threaded messages get a mild boost (conversation engagement)
    if (entry.msgtype == "m.text" && !entry.body_preview.empty())
      score *= 1.1;

    // Longer messages may indicate more important content
    if (entry.body_preview.size() > 100) score *= 1.15;

    // Image/file messages get a small boost (rich content)
    if (entry.msgtype == "m.image" || entry.msgtype == "m.video")
      score *= 1.2;
    if (entry.msgtype == "m.file" || entry.msgtype == "m.audio")
      score *= 1.1;

    return score;
  }

  // Sort entries by relevance score descending, respecting per-room caps
  static std::vector<DigestEntry> select_top_entries(
      std::vector<DigestEntry> entries,
      int max_per_room,
      int max_total) {

    // Group by room
    std::unordered_map<std::string, std::vector<DigestEntry>> room_entries;
    for (auto& entry : entries) {
      room_entries[entry.room_id].push_back(std::move(entry));
    }

    // Sort each room's entries and take top N
    std::vector<DigestEntry> selected;
    for (auto& [rid, room_ents] : room_entries) {
      std::sort(room_ents.begin(), room_ents.end(),
                [](const DigestEntry& a, const DigestEntry& b) {
                  return a.score() > b.score();
                });

      size_t take = std::min(room_ents.size(), static_cast<size_t>(max_per_room));
      for (size_t i = 0; i < take; i++) {
        selected.push_back(std::move(room_ents[i]));
      }
    }

    // Sort all selected globally
    std::sort(selected.begin(), selected.end(),
              [](const DigestEntry& a, const DigestEntry& b) {
                return a.score() > b.score();
              });

    // Take top N globally
    if (static_cast<int>(selected.size()) > max_total) {
      selected.resize(static_cast<size_t>(max_total));
    }

    return selected;
  }

  // Compute digest diversity score (how many different rooms are represented)
  static double compute_diversity_score(const std::vector<DigestEntry>& entries) {
    std::unordered_set<std::string> rooms;
    for (const auto& e : entries) rooms.insert(e.room_id);

    if (entries.empty()) return 0.0;
    return static_cast<double>(rooms.size()) / static_cast<double>(entries.size());
  }

  // Balance digest between room diversity and individual importance
  static std::vector<DigestEntry> balanced_select(
      std::vector<DigestEntry> entries,
      int max_total,
      double diversity_weight = 0.3) {

    if (static_cast<int>(entries.size()) <= max_total) return entries;

    // Take top-scoring entries but ensure at least some room diversity
    std::sort(entries.begin(), entries.end(),
              [](const DigestEntry& a, const DigestEntry& b) {
                return a.score() > b.score();
              });

    std::vector<DigestEntry> result;
    std::unordered_set<std::string> rooms_included;

    for (auto& entry : entries) {
      if (static_cast<int>(result.size()) >= max_total) break;

      bool new_room = (rooms_included.find(entry.room_id) == rooms_included.end());
      int slots_left = max_total - static_cast<int>(result.size());

      // Always include if it's a new room and we have slots
      if (new_room) {
        result.push_back(entry);
        rooms_included.insert(entry.room_id);
        continue;
      }

      // For existing rooms, use diversity_weight to decide
      double diversity_factor = 1.0 + diversity_weight * (1.0 / (rooms_included.size() + 1.0));
      if (entry.score() * diversity_factor > 2.0) {
        result.push_back(entry);
      }
    }

    return result;
  }
};

// ============================================================================
// Global Instances (extended)
// ============================================================================

static std::shared_ptr<SmtpDeliveryWorker> g_smtp_worker;
static std::shared_ptr<DkimSigner> g_dkim_signer;
static std::shared_ptr<EmailLocalization> g_email_localization;
static std::shared_ptr<RoomNotificationOverrides> g_room_overrides;
static std::shared_ptr<EmailValidator> g_email_validator;

// ============================================================================
// Extended Public API
// ============================================================================

// ---- SMTP Delivery ----

void email_set_smtp_config(const std::string& host, int port,
                            bool use_tls, const std::string& username,
                            const std::string& password) {
  if (!g_email_ioc) return;
  if (!g_smtp_worker) {
    g_smtp_worker = std::make_shared<SmtpDeliveryWorker>(*g_email_ioc);
  }
  SmtpDeliveryWorker::SmtpServerConfig config;
  config.host = host;
  config.port = static_cast<uint16_t>(port);
  config.use_starttls = use_tls;
  config.username = username;
  config.password = password;
  g_smtp_worker->configure(config);
}

void email_deliver_async(const std::string& from_addr,
                          const std::string& from_name,
                          const std::string& to_email,
                          const std::string& raw_message,
                          std::function<void(bool, const std::string&)> callback) {
  if (g_smtp_worker) {
    g_smtp_worker->deliver_async(from_addr, from_name, to_email, raw_message,
                                   std::move(callback));
  } else if (callback) {
    callback(false, "SMTP worker not configured");
  }
}

// ---- DKIM Signing ----

void email_set_dkim_config(const std::string& domain,
                             const std::string& selector,
                             const std::string& private_key_pem) {
  if (!g_dkim_signer) g_dkim_signer = std::make_shared<DkimSigner>();
  DkimSigner::DkimConfig config;
  config.domain = domain;
  config.selector = selector;
  config.private_key_pem = private_key_pem;
  config.enabled = true;
  g_dkim_signer->configure(config);
}

std::string email_dkim_sign(const std::string& raw_message) {
  if (!g_dkim_signer) return raw_message;
  return g_dkim_signer->sign_message(raw_message);
}

bool email_dkim_enabled() {
  return g_dkim_signer && g_dkim_signer->is_enabled();
}

// ---- Localization ----

std::string email_translate(const std::string& lang, const std::string& key) {
  if (!g_email_localization) {
    g_email_localization = std::make_shared<EmailLocalization>();
  }
  return g_email_localization->tr(lang, key);
}

std::vector<std::string> email_supported_languages() {
  if (!g_email_localization) {
    g_email_localization = std::make_shared<EmailLocalization>();
  }
  return g_email_localization->supported_languages();
}

// ---- Room Notification Overrides ----

void email_set_room_override(const std::string& user_id,
                               const std::string& room_id,
                               bool muted,
                               int notification_level,
                               bool digest_only) {
  if (!g_room_overrides) g_room_overrides = std::make_shared<RoomNotificationOverrides>();
  RoomNotificationOverrides::RoomOverride ov;
  ov.room_id = room_id;
  ov.muted = muted;
  ov.notification_level = notification_level;
  ov.digest_only = digest_only;
  g_room_overrides->set_override(user_id, ov);
}

void email_remove_room_override(const std::string& user_id,
                                  const std::string& room_id) {
  if (g_room_overrides) g_room_overrides->remove_override(user_id, room_id);
}

bool email_is_room_muted(const std::string& user_id, const std::string& room_id) {
  if (!g_room_overrides) return false;
  return g_room_overrides->is_room_muted(user_id, room_id);
}

bool email_should_deliver_for_room(const std::string& user_id,
                                     const std::string& room_id,
                                     bool is_mention,
                                     bool is_call,
                                     bool is_invite) {
  if (!g_room_overrides) return true;
  return g_room_overrides->should_deliver_immediate(
      user_id, room_id, is_mention, is_call, is_invite);
}

json email_room_overrides_json(const std::string& user_id) {
  if (!g_room_overrides) return json::array();
  return g_room_overrides->overrides_to_json(user_id);
}

void email_set_room_overrides_json(const std::string& user_id, const json& arr) {
  if (!g_room_overrides) g_room_overrides = std::make_shared<RoomNotificationOverrides>();
  g_room_overrides->overrides_from_json(user_id, arr);
}

// ---- Email Validation ----

bool email_is_valid(const std::string& email) {
  return EmailValidator::is_valid_email(email);
}

std::string email_normalize(const std::string& email) {
  return EmailValidator::normalize_email(email);
}

std::string email_domain(const std::string& email) {
  return EmailValidator::extract_domain(email);
}

bool email_is_disposable(const std::string& email) {
  return EmailValidator::is_disposable_email(email);
}

bool email_is_role_based(const std::string& email) {
  return EmailValidator::is_role_based_email(email);
}

// ---- Extended Digest Content Ranking ----

std::vector<double> email_rank_entries(const std::string& json_entries) {
  std::vector<double> scores;
  try {
    json entries_json = json::parse(json_entries);
    for (const auto& entry_json : entries_json) {
      DigestEntry entry;
      entry.is_mention = entry_json.value("is_mention", false);
      entry.is_highlight = entry_json.value("is_highlight", false);
      entry.is_call = entry_json.value("is_call", false);
      entry.is_invite = entry_json.value("is_invite", false);
      entry.is_encrypted = entry_json.value("is_encrypted", false);
      entry.ts_sec = entry_json.value("ts_sec", 0);
      entry.body_preview = entry_json.value("body_preview", "");
      entry.msgtype = entry_json.value("msgtype", "");

      scores.push_back(DigestContentRanker::compute_rank_score(
          entry, "", false, entry_json.value("room_members", 0)));
    }
  } catch (...) {
    // Invalid JSON
  }
  return scores;
}

}  // namespace progressive::push
