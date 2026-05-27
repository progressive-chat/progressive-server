// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Progressive Server Contributors
//
// DeltaChat Status Tracking — complete message status lifecycle, delivery
// reports, MDN receipts, error categorization, retry logic, read tracking,
// multi-device sync, and user-facing status formatting.
//
// Implements the full DeltaChat message state machine:
//   out_pending → out_delivered → out_mdn_rcvd  (success path)
//   out_pending → out_failed                    (error path)
//   in_fresh   → in_noticed  → in_seen          (inbound path)

#include <string>
#include <string_view>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <map>
#include <set>
#include <memory>
#include <optional>
#include <variant>
#include <ctime>
#include <cctype>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <algorithm>
#include <sstream>
#include <fstream>
#include <regex>
#include <deque>
#include <queue>
#include <functional>
#include <mutex>
#include <shared_mutex>
#include <atomic>
#include <chrono>
#include <thread>
#include <stdexcept>
#include <cmath>
#include <random>
#include <condition_variable>
#include <limits>

namespace progressive {
namespace deltachat {

// ============================================================================
// Forward declarations — types that live in sibling TUs
// ============================================================================
class DeltaChat;
struct DcMessage;

// ============================================================================
// Message State Constants (DeltaChat wire-compatible values)
// ============================================================================

constexpr int MSG_STATE_UNDEFINED       = 0;    // Unknown / uninitialised
constexpr int MSG_STATE_IN_FRESH        = 10;   // Inbound, not yet displayed
constexpr int MSG_STATE_IN_NOTICED      = 13;   // Inbound, displayed in list
constexpr int MSG_STATE_IN_SEEN         = 16;   // Inbound, opened by user
constexpr int MSG_STATE_OUT_PREPARING   = 18;   // Composing, not yet queued
constexpr int MSG_STATE_OUT_DRAFT       = 19;   // Saved as draft
constexpr int MSG_STATE_OUT_PENDING     = 24;   // Queued for SMTP delivery
constexpr int MSG_STATE_OUT_DELIVERED   = 26;   // Accepted by SMTP server
constexpr int MSG_STATE_OUT_MDN_RCVD    = 28;   // Read receipt received
constexpr int MSG_STATE_OUT_FAILED      = 29;   // Permanent send failure

// Display labels for each state
static const char* state_label(int state) {
    switch (state) {
        case MSG_STATE_UNDEFINED:     return "unknown";
        case MSG_STATE_IN_FRESH:      return "fresh";
        case MSG_STATE_IN_NOTICED:    return "noticed";
        case MSG_STATE_IN_SEEN:       return "seen";
        case MSG_STATE_OUT_PREPARING: return "preparing";
        case MSG_STATE_OUT_DRAFT:     return "draft";
        case MSG_STATE_OUT_PENDING:   return "pending";
        case MSG_STATE_OUT_DELIVERED: return "delivered";
        case MSG_STATE_OUT_MDN_RCVD:  return "read";
        case MSG_STATE_OUT_FAILED:    return "failed";
        default:                      return "???";
    }
}

// ============================================================================
// Retry / Backoff Constants
// ============================================================================

constexpr int   MAX_RETRY_COUNT              = 12;       // Max retries per msg
constexpr int   BASE_RETRY_BACKOFF_MS        = 1500;     // First backoff (ms)
constexpr int   MAX_RETRY_BACKOFF_MS         = 900000;   // 15 minutes cap
constexpr int   RETRY_BACKOFF_MULTIPLIER     = 2;        // Exponential factor
constexpr int   RETRY_JITTER_PCT             = 25;       // ±25 % jitter
constexpr int   SEND_TIMEOUT_MS              = 300000;   // 5 minute send timeout
constexpr int   MDN_TIMEOUT_MS               = 86400000; // 24h for MDN response
constexpr int   STATUS_PERSIST_INTERVAL_SECS = 120;      // Persist every 2 minutes
constexpr int   STATUS_SYNC_INTERVAL_MS      = 5000;     // Multi-device sync poll
constexpr int   MAX_RETRY_QUEUE_SIZE         = 5000;     // Hard cap on retry set
constexpr int   STALE_MESSAGE_AGE_SECS       = 2592000;  // 30 days — prune older

// ============================================================================
// Error Category Enumeration
// ============================================================================

enum class ErrorCategory : int {
    NONE                = 0,
    TEMPORARY_SMTP      = 1,    // e.g. 4xx, connection refused, DNS tempfail
    PERMANENT_SMTP      = 2,    // e.g. 5xx, auth failure, relay denied
    TEMPORARY_IMAP      = 3,    // e.g. IMAP BYE, timeouts, server busy
    PERMANENT_IMAP      = 4,    // e.g. NO [AUTHENTICATIONFAILED], folder gone
    ENCRYPTION_ERROR    = 5,    // PGP key missing, decrypt failure, bad armour
    NETWORK_ERROR       = 6,    // DNS failure, no route, TLS handshake fail
    CONFIGURATION_ERROR = 7,    // Missing SMTP/IMAP config, bad port, etc.
    DATABASE_ERROR      = 8,    // SQL write failure, corruption, disk full
    TIMEOUT_ERROR       = 9,    // Message send timed out
    UNKNOWN_ERROR       = 99
};

static const char* error_category_label(ErrorCategory cat) {
    switch (cat) {
        case ErrorCategory::NONE:                return "none";
        case ErrorCategory::TEMPORARY_SMTP:      return "temp_smtp";
        case ErrorCategory::PERMANENT_SMTP:      return "perm_smtp";
        case ErrorCategory::TEMPORARY_IMAP:      return "temp_imap";
        case ErrorCategory::PERMANENT_IMAP:      return "perm_imap";
        case ErrorCategory::ENCRYPTION_ERROR:    return "encryption";
        case ErrorCategory::NETWORK_ERROR:       return "network";
        case ErrorCategory::CONFIGURATION_ERROR: return "config";
        case ErrorCategory::DATABASE_ERROR:      return "database";
        case ErrorCategory::TIMEOUT_ERROR:       return "timeout";
        case ErrorCategory::UNKNOWN_ERROR:       return "unknown";
        default:                                 return "???";
    }
}

static bool is_error_temporary(ErrorCategory cat) {
    switch (cat) {
        case ErrorCategory::TEMPORARY_SMTP:
        case ErrorCategory::TEMPORARY_IMAP:
        case ErrorCategory::NETWORK_ERROR:
        case ErrorCategory::TIMEOUT_ERROR:
            return true;
        default:
            return false;
    }
}

// ============================================================================
// SMTP Error Code → Category mapping
// ============================================================================

struct SmtpErrorInfo {
    int         reply_code;       // e.g. 421, 450, 550
    std::string enhanced_code;    // e.g. "4.2.2", "5.1.1"
    std::string description;
    ErrorCategory category;
    bool         is_permanent;
};

// Canonical SMTP error catalogue used for classification
static const SmtpErrorInfo SMTP_ERROR_CATALOGUE[] = {
    // 4xx — temporary
    { 421, "4.3.0", "Service not available, closing transmission channel",
      ErrorCategory::TEMPORARY_SMTP, false },
    { 421, "4.4.1", "Connection timed out",
      ErrorCategory::TEMPORARY_SMTP, false },
    { 421, "4.7.0", "Temporary policy — try again later",
      ErrorCategory::TEMPORARY_SMTP, false },
    { 450, "4.2.0", "Requested mail action not taken: mailbox unavailable",
      ErrorCategory::TEMPORARY_SMTP, false },
    { 451, "4.3.0", "Requested action aborted: local error in processing",
      ErrorCategory::TEMPORARY_SMTP, false },
    { 451, "4.7.1", "Service unavailable — try again later",
      ErrorCategory::TEMPORARY_SMTP, false },
    { 452, "4.2.2", "Insufficient system storage",
      ErrorCategory::TEMPORARY_SMTP, false },
    { 452, "4.5.3", "Too many recipients",
      ErrorCategory::TEMPORARY_SMTP, false },
    { 454, "4.7.0", "TLS not available due to temporary reason",
      ErrorCategory::TEMPORARY_SMTP, false },

    // 5xx — permanent
    { 500, "5.5.1", "Syntax error, command unrecognized",
      ErrorCategory::PERMANENT_SMTP, true },
    { 501, "5.1.3", "Bad recipient address syntax",
      ErrorCategory::PERMANENT_SMTP, true },
    { 501, "5.5.2", "Syntax error in parameters or arguments",
      ErrorCategory::PERMANENT_SMTP, true },
    { 502, "5.5.1", "Command not implemented",
      ErrorCategory::PERMANENT_SMTP, true },
    { 503, "5.5.0", "Bad sequence of commands",
      ErrorCategory::PERMANENT_SMTP, true },
    { 504, "5.5.1", "Command parameter not implemented",
      ErrorCategory::PERMANENT_SMTP, true },
    { 510, "5.1.0", "Bad email address",
      ErrorCategory::PERMANENT_SMTP, true },
    { 530, "5.7.0", "Authentication required",
      ErrorCategory::PERMANENT_SMTP, true },
    { 535, "5.7.8", "Authentication credentials invalid",
      ErrorCategory::PERMANENT_SMTP, true },
    { 550, "5.1.1", "Mailbox not found / user unknown",
      ErrorCategory::PERMANENT_SMTP, true },
    { 550, "5.2.1", "Mailbox disabled / not accepting mail",
      ErrorCategory::PERMANENT_SMTP, true },
    { 550, "5.7.1", "Relay denied / not authorised",
      ErrorCategory::PERMANENT_SMTP, true },
    { 551, "5.1.6", "User not local — try alternate path",
      ErrorCategory::PERMANENT_SMTP, true },
    { 552, "5.2.2", "Mailbox full / storage allocation exceeded",
      ErrorCategory::PERMANENT_SMTP, true },
    { 553, "5.1.0", "Mailbox name not allowed — sender address rejected",
      ErrorCategory::PERMANENT_SMTP, true },
    { 554, "5.5.0", "Transaction failed — no valid recipients",
      ErrorCategory::PERMANENT_SMTP, true },
    { 554, "5.7.1", "Relay access denied",
      ErrorCategory::PERMANENT_SMTP, true },
    { 555, "5.5.2", "MAIL FROM/RCPT TO parameters not recognised",
      ErrorCategory::PERMANENT_SMTP, true },
};

// ============================================================================
// IMAP Error Info
// ============================================================================

struct ImapErrorInfo {
    std::string  response_tag;     // e.g. "NO", "BAD"
    std::string  response_text;    // Human-readable server text
    ErrorCategory category;
    bool         is_permanent;
};

static ErrorCategory classify_imap_error(const std::string& raw_line) {
    // Normalise to upper
    std::string upper = raw_line;
    std::transform(upper.begin(), upper.end(), upper.begin(),
                   [](unsigned char c) { return std::toupper(c); });

    // BAD → likely permanent (protocol error)
    if (upper.find("BAD") != std::string::npos) {
        if (upper.find("AUTHENTICATIONFAILED") != std::string::npos ||
            upper.find("AUTHORIZATIONFAILED")  != std::string::npos ||
            upper.find("NOT ALLOWED")          != std::string::npos) {
            return ErrorCategory::PERMANENT_IMAP;
        }
        // Some BAD responses are temporary (e.g. server overload)
        if (upper.find("TRYAGAIN")  != std::string::npos ||
            upper.find("OVERLOAD")  != std::string::npos ||
            upper.find("BUSY")      != std::string::npos) {
            return ErrorCategory::TEMPORARY_IMAP;
        }
        return ErrorCategory::PERMANENT_IMAP;
    }

    // NO → could be either
    if (upper.find("NO") != std::string::npos) {
        if (upper.find("UNAVAILABLE")    != std::string::npos ||
            upper.find("TEMPORARILY")    != std::string::npos ||
            upper.find("TRY LATER")      != std::string::npos ||
            upper.find("MAINTENANCE")    != std::string::npos ||
            upper.find("CLOSED")         != std::string::npos ||
            upper.find("TIMEOUT")        != std::string::npos) {
            return ErrorCategory::TEMPORARY_IMAP;
        }
        if (upper.find("AUTHENTICATIONFAILED") != std::string::npos ||
            upper.find("AUTHORIZATIONFAILED")  != std::string::npos ||
            upper.find("NOACCESS")             != std::string::npos ||
            upper.find("EXPUNGE FAILED")       != std::string::npos ||
            upper.find("NONEXISTENT")          != std::string::npos) {
            return ErrorCategory::PERMANENT_IMAP;
        }
        return ErrorCategory::TEMPORARY_IMAP; // Default NO → temporary
    }

    // BYE → connection lost (temporary)
    if (upper.find("BYE") != std::string::npos) {
        return ErrorCategory::TEMPORARY_IMAP;
    }

    return ErrorCategory::UNKNOWN_ERROR;
}

// ============================================================================
// Encryption error classification
// ============================================================================

struct EncryptionErrorInfo {
    std::string   description;
    ErrorCategory category;
    bool          retryable;
};

static EncryptionErrorInfo classify_encryption_error(const std::string& error_text) {
    std::string lower = error_text;
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return std::tolower(c); });

    if (lower.find("no key")       != std::string::npos ||
        lower.find("missing key")  != std::string::npos ||
        lower.find("key not found")!= std::string::npos ||
        lower.find("no public key")!= std::string::npos) {
        return { "Missing encryption key for recipient",
                 ErrorCategory::ENCRYPTION_ERROR, false };
    }
    if (lower.find("decrypt")      != std::string::npos ||
        lower.find("bad session")  != std::string::npos ||
        lower.find("decryption failed") != std::string::npos) {
        return { "Decryption failed — possibly wrong key",
                 ErrorCategory::ENCRYPTION_ERROR, false };
    }
    if (lower.find("signature")    != std::string::npos &&
        lower.find("verif")        != std::string::npos) {
        return { "Signature verification failed",
                 ErrorCategory::ENCRYPTION_ERROR, true }; // retryable
    }
    if (lower.find("armor")        != std::string::npos ||
        lower.find("garbled")      != std::string::npos ||
        lower.find("malformed")    != std::string::npos) {
        return { "Malformed encrypted data",
                 ErrorCategory::ENCRYPTION_ERROR, false };
    }
    if (lower.find("checksum")     != std::string::npos ||
        lower.find("integrity")    != std::string::npos) {
        return { "Encryption data integrity error",
                 ErrorCategory::ENCRYPTION_ERROR, true }; // retryable
    }
    if (lower.find("expired")      != std::string::npos ||
        lower.find("revoked")      != std::string::npos) {
        return { "Key expired or revoked",
                 ErrorCategory::ENCRYPTION_ERROR, false };
    }

    return { "Unknown encryption error",
             ErrorCategory::ENCRYPTION_ERROR, false };
}

// ============================================================================
// Deliverable report per recipient
// ============================================================================

struct RecipientDeliveryStatus {
    std::string   recipient_addr;
    std::string   original_rcpt_to;
    int           smtp_reply_code      = 0;
    std::string   smtp_enhanced_code;
    std::string   smtp_text;
    bool          delivered            = false;
    bool          delayed              = false;
    bool          relayed              = false;
    bool          expanded             = false;   // mailing list expansion
    ErrorCategory error_category       = ErrorCategory::NONE;
    std::string   diagnostic_message;
    std::string   remote_mta;                     // receiving server name
    time_t        last_attempt_time    = 0;
    time_t        delivery_time        = 0;
};

// ============================================================================
// Full delivery report (DSN — Delivery Status Notification)
// ============================================================================

struct DeliveryReport {
    // Envelope info
    std::string  original_envelope_id;
    std::string  original_message_id;             // RFC 5322 Message-ID
    std::string  reporting_mta;                   // Our server
    std::string  reporting_mta_type = "dns";

    // Arrival date of original message at our MTA
    time_t       arrival_date = 0;

    // Per-recipient results
    std::vector<RecipientDeliveryStatus> recipient_statuses;

    // Summary
    int          total_recipients     = 0;
    int          delivered_count      = 0;
    int          failed_count         = 0;
    int          delayed_count        = 0;
    int          relayed_count        = 0;
    int          expanded_count       = 0;
    time_t       report_generated_at  = 0;

    // Convenience
    bool all_delivered() const { return failed_count == 0 && delayed_count == 0; }
    bool has_failures()   const { return failed_count > 0; }
    bool has_delays()     const { return delayed_count > 0; }
};

// ============================================================================
// MDN (Message Disposition Notification) — Read Receipt
// ============================================================================

struct MdnReceipt {
    std::string  original_message_id;
    std::string  original_recipient;
    std::string  final_recipient;
    std::string  disposition;           // "displayed", "deleted", "dispatched", etc.
    std::string  disposition_mode;      // "manual", "automatic"
    std::string  disposition_type;      // "displayed"
    std::string  sending_mdn_agent;     // e.g. "DeltaChat/1.0"
    time_t       received_at = 0;
    time_t       displayed_at = 0;
    std::string  raw_mdn_body;          // Full original MDN body for auditing

    bool is_read_receipt() const {
        return disposition == "displayed" &&
               disposition_type == "displayed";
    }
};

// ============================================================================
// Message retry state
// ============================================================================

struct MessageRetryState {
    uint32_t      msg_id              = 0;
    int64_t       chat_id             = 0;
    int           current_state       = MSG_STATE_UNDEFINED;
    int           retry_count         = 0;
    int64_t       last_attempt_ms     = 0;        // absolute monotonic ms
    int64_t       next_attempt_ms     = 0;        // absolute monotonic ms
    int64_t       created_at_ms       = 0;        // enqueue time
    int64_t       send_deadline_ms    = 0;        // timeout absolute ms
    ErrorCategory last_error_category = ErrorCategory::NONE;
    std::string   last_error_text;
    bool          active              = false;
    bool          in_flight           = false;
    int64_t       in_flight_since_ms  = 0;
    std::string   smtp_message_id;                // For DSN / MDN correlation
    std::string   envelope_from;

    // For per-recipient tracking
    struct RecipientRetryInfo {
        std::string addr;
        int         local_retries  = 0;
        int         smtp_reply     = 0;
        std::string error_detail;
        ErrorCategory category = ErrorCategory::NONE;
        bool        permanently_failed = false;
    };
    std::vector<RecipientRetryInfo> recipients;
};

// ============================================================================
// Multi-device status sync payload
// ============================================================================

struct StatusSyncPayload {
    std::string  sync_type;                      // "msg_state", "read_state", "delivery_report"
    uint32_t     msg_id                 = 0;
    int          new_state              = MSG_STATE_UNDEFINED;
    int64_t       timestamp_ms          = 0;
    std::string  origin_device_id;
    std::string  rfc724_mid;
    int64_t       chat_id               = 0;
    std::string  extra_json;                     // Extensible payload
    int64_t       sync_serial           = 0;     // Monotonic serial for ordering
};

// ============================================================================
// User-facing status info
// ============================================================================

struct MessageStatusUI {
    uint32_t    msg_id        = 0;
    int         state         = MSG_STATE_UNDEFINED;
    std::string status_icon;                  // "✓", "✓✓", "✓✓✓", "✗", "🕐"
    std::string status_text;                  // "Sending…", "Delivered", "Read", "Failed"
    std::string error_text;                   // User-friendly error
    std::string error_detail;                 // Technical detail (expandable)
    std::string timestamp_text;               // "12:34" or "Yesterday"
    int64_t     timestamp_ms = 0;
    bool        is_encrypted   = false;
    bool        has_delivery_report = false;
    bool        has_read_receipt    = false;
    int         retry_count   = 0;
    int64_t     retry_eta_ms = 0;             // Next retry in ms (0 = none)
    int         padlock_state = 0;            // 0=none, 1=grey, 2=green
};

// ============================================================================
// Utility: timestamp helpers
// ============================================================================

static int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

static time_t now_unix() {
    return std::time(nullptr);
}

static std::string format_timestamp_hhmm(time_t t) {
    char buf[16];
    struct tm tmp;
    localtime_r(&t, &tmp);
    std::snprintf(buf, sizeof(buf), "%02d:%02d", tmp.tm_hour, tmp.tm_min);
    return buf;
}

static std::string format_timestamp_full(time_t t) {
    char buf[64];
    struct tm tmp;
    localtime_r(&t, &tmp);
    std::snprintf(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d:%02d",
                  tmp.tm_year + 1900, tmp.tm_mon + 1, tmp.tm_mday,
                  tmp.tm_hour, tmp.tm_min, tmp.tm_sec);
    return buf;
}

static std::string format_timestamp_relative(time_t t) {
    time_t now = std::time(nullptr);
    int64_t diff = static_cast<int64_t>(now) - static_cast<int64_t>(t);

    if (diff < 0)  return "just now";
    if (diff < 60) return "just now";
    if (diff < 120)return "1m ago";
    if (diff < 3600) return std::to_string(diff / 60) + "m ago";
    if (diff < 7200) return "1h ago";
    if (diff < 86400)return std::to_string(diff / 3600) + "h ago";
    if (diff < 172800)return "Yesterday";
    if (diff < 604800)return std::to_string(diff / 86400) + "d ago";
    if (diff < 2592000)return std::to_string(diff / 604800) + "w ago";
    return format_timestamp_full(t);
}

static int64_t steady_to_unix_ms(int64_t steady_ms) {
    // Approximate — good enough for UI display
    int64_t real_now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    int64_t steady_now = now_ms();
    return real_now + (steady_ms - steady_now);
}

// ============================================================================
// Utility: parse SMTP enhanced status code from reply text
// ============================================================================

static std::string extract_enhanced_code(const std::string& reply_text) {
    // RFC 3463 enhanced status codes look like "X.X.X"
    // They appear after the numeric reply code in SMTP responses
    // e.g. "550 5.1.1 User unknown"
    std::regex re(R"((\d\.\d{1,3}\.\d{1,3}))");
    std::smatch m;
    if (std::regex_search(reply_text, m, re)) {
        return m[1].str();
    }
    return "";
}

static int extract_smtp_reply_code(const std::string& reply_text) {
    if (reply_text.size() >= 3 && std::isdigit(reply_text[0])) {
        try {
            return std::stoi(reply_text.substr(0, 3));
        } catch (...) {
            return 0;
        }
    }
    return 0;
}

// ============================================================================
// Utility: classify an SMTP error from raw response text
// ============================================================================

static std::pair<ErrorCategory, std::string> classify_smtp_error(
    const std::string& raw_response) {

    int code = extract_smtp_reply_code(raw_response);
    std::string enhanced = extract_enhanced_code(raw_response);
    std::string upper = raw_response;
    std::transform(upper.begin(), upper.end(), upper.begin(),
                   [](unsigned char c) { return std::toupper(c); });

    // Walk the catalogue — find best match
    const SmtpErrorInfo* best = nullptr;
    int best_score = -1;

    for (const auto& entry : SMTP_ERROR_CATALOGUE) {
        int score = 0;
        if (code >= 400 && code < 500 && entry.reply_code / 100 == 4) score += 10;
        if (code >= 500 && code < 600 && entry.reply_code / 100 == 5) score += 10;
        if (code == entry.reply_code) score += 20;
        if (!enhanced.empty() && enhanced == entry.enhanced_code) score += 30;
        if (!enhanced.empty() && enhanced.substr(0, 3) == entry.enhanced_code.substr(0, 3)) score += 15;
        if (score > best_score) {
            best_score = score;
            best = &entry;
        }
    }

    if (best) {
        return { best->category, best->description };
    }

    // Fallback heuristics
    if (code >= 400 && code < 500) {
        // Check for auth-failure specific strings even in 4xx
        if (upper.find("AUTH") != std::string::npos ||
            upper.find("LOGIN") != std::string::npos ||
            upper.find("PASSWORD") != std::string::npos) {
            // Auth failures are permanent even with 4xx
            return { ErrorCategory::PERMANENT_SMTP, "Authentication failure" };
        }
        return { ErrorCategory::TEMPORARY_SMTP, "Temporary SMTP error " + std::to_string(code) };
    }
    if (code >= 500 && code < 600) {
        return { ErrorCategory::PERMANENT_SMTP, "Permanent SMTP error " + std::to_string(code) };
    }

    // No code found — try text heuristics
    if (upper.find("TIMEOUT")      != std::string::npos ||
        upper.find("TIME OUT")     != std::string::npos ||
        upper.find("CONNECTION REFUSED") != std::string::npos) {
        return { ErrorCategory::NETWORK_ERROR, "Network timeout or connection refused" };
    }
    if (upper.find("DNS")          != std::string::npos ||
        upper.find("HOST NOT FOUND")!= std::string::npos ||
        upper.find("NAME RESOLUTION")!= std::string::npos) {
        return { ErrorCategory::NETWORK_ERROR, "DNS resolution failure" };
    }
    if (upper.find("TLS")          != std::string::npos ||
        upper.find("SSL")          != std::string::npos ||
        upper.find("CERTIFICATE")  != std::string::npos) {
        return { ErrorCategory::NETWORK_ERROR, "TLS/SSL handshake failure" };
    }
    if (upper.find("AUTH")         != std::string::npos ||
        upper.find("CREDENTIAL")   != std::string::npos) {
        return { ErrorCategory::CONFIGURATION_ERROR, "Authentication configuration error" };
    }

    return { ErrorCategory::UNKNOWN_ERROR, raw_response };
}

// ============================================================================
// Exponential Backoff Calculator
// ============================================================================

static int64_t compute_backoff_ms(int retry_count) {
    if (retry_count <= 0) return 0;

    // Exponential: base * multiplier^(retry-1)
    double exponential = BASE_RETRY_BACKOFF_MS *
                         std::pow(static_cast<double>(RETRY_BACKOFF_MULTIPLIER),
                                  retry_count - 1);

    int64_t base_delay = static_cast<int64_t>(std::min(
        exponential, static_cast<double>(MAX_RETRY_BACKOFF_MS)));

    // Add jitter: ±jitter_pct% random
    static thread_local std::mt19937_64 rng(
        static_cast<uint64_t>(now_ms()) ^
        static_cast<uint64_t>(std::hash<std::thread::id>{}(std::this_thread::get_id())));
    double jitter_factor = 1.0 + ((static_cast<double>(rng() % (RETRY_JITTER_PCT * 2 + 1)) -
                                   RETRY_JITTER_PCT) / 100.0);
    int64_t jittered = static_cast<int64_t>(base_delay * jitter_factor);

    // Clamp to bounds
    if (jittered < BASE_RETRY_BACKOFF_MS) jittered = BASE_RETRY_BACKOFF_MS;
    if (jittered > MAX_RETRY_BACKOFF_MS)  jittered = MAX_RETRY_BACKOFF_MS;

    return jittered;
}

// ============================================================================
// MDN (Message Disposition Notification) Parser
// ============================================================================

static std::optional<MdnReceipt> parse_mdn_body(const std::string& mdn_text) {
    MdnReceipt receipt;
    receipt.received_at = now_unix();
    receipt.raw_mdn_body = mdn_text;

    // RFC 3798 MDN format: multipart/report with text/rfc822-headers part
    // The body has fields like:
    //   Original-Message-ID: <...>
    //   Final-Recipient: rfc822; addr
    //   Disposition: manual-action/MDN-sent-manually; displayed
    //   Original-Recipient: rfc822; addr

    std::istringstream stream(mdn_text);
    std::string line;

    while (std::getline(stream, line)) {
        // Trim CR
        if (!line.empty() && line.back() == '\r') line.pop_back();

        auto parse_field = [&](const std::string& prefix) -> std::string {
            if (line.size() > prefix.size() &&
                line.compare(0, prefix.size(), prefix) == 0) {
                std::string val = line.substr(prefix.size());
                // Unfold leading whitespace
                size_t nsp = val.find_first_not_of(" \t");
                if (nsp != std::string::npos) val = val.substr(nsp);
                return val;
            }
            return "";
        };

        std::string omid = parse_field("Original-Message-ID:");
        if (!omid.empty()) {
            // Strip angle brackets
            if (!omid.empty() && omid.front() == '<') omid = omid.substr(1);
            if (!omid.empty() && omid.back()  == '>') omid.pop_back();
            receipt.original_message_id = omid;
        }

        std::string fr = parse_field("Final-Recipient:");
        if (!fr.empty()) {
            // Format: "rfc822; addr" or just "addr"
            size_t semi = fr.find(';');
            if (semi != std::string::npos) {
                receipt.final_recipient = fr.substr(semi + 1);
                // Trim
                size_t ns = receipt.final_recipient.find_first_not_of(" \t");
                if (ns != std::string::npos) receipt.final_recipient = receipt.final_recipient.substr(ns);
                else receipt.final_recipient = "";
            } else {
                receipt.final_recipient = fr;
            }
        }

        std::string orec = parse_field("Original-Recipient:");
        if (!orec.empty()) {
            size_t semi = orec.find(';');
            if (semi != std::string::npos) {
                receipt.original_recipient = orec.substr(semi + 1);
                size_t ns = receipt.original_recipient.find_first_not_of(" \t");
                if (ns != std::string::npos) receipt.original_recipient = receipt.original_recipient.substr(ns);
                else receipt.original_recipient = "";
            } else {
                receipt.original_recipient = orec;
            }
        }

        std::string disp = parse_field("Disposition:");
        if (!disp.empty()) {
            // Format: "manual-action/MDN-sent-automatically; displayed"
            size_t semi = disp.find(';');
            if (semi != std::string::npos) {
                std::string dispmode = disp.substr(0, semi);
                receipt.disposition = disp.substr(semi + 1);
                // Trim disposition
                size_t ns = receipt.disposition.find_first_not_of(" \t");
                if (ns != std::string::npos) receipt.disposition = receipt.disposition.substr(ns);
                // Parse mode
                size_t slash = dispmode.find('/');
                if (slash != std::string::npos) {
                    receipt.disposition_mode = dispmode.substr(0, slash);
                    receipt.disposition_type = dispmode.substr(slash + 1);
                }
            } else {
                receipt.disposition = disp;
            }
        }

        std::string agent = parse_field("Reporting-UA:");
        if (!agent.empty()) {
            receipt.sending_mdn_agent = agent;
        }
    }

    if (receipt.original_message_id.empty()) {
        return std::nullopt; // Not a valid MDN
    }

    return receipt;
}

// ============================================================================
// DSN (Delivery Status Notification) Parser — parses DSN report body
// ============================================================================

static std::optional<DeliveryReport> parse_dsn_body(const std::string& dsn_text) {
    DeliveryReport report;
    report.report_generated_at = now_unix();

    std::istringstream stream(dsn_text);
    std::string line;
    RecipientDeliveryStatus* current_recipient = nullptr;

    enum Section { HEADER, PER_MESSAGE, PER_RECIPIENT };
    Section section = HEADER;

    while (std::getline(stream, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();

        // Section boundaries
        if (line.find("--") == 0) {
            // Determine next section by boundary
            if (section == HEADER)       section = PER_MESSAGE;
            else if (section == PER_MESSAGE) section = PER_RECIPIENT;
            continue;
        }

        if (line.empty()) continue;

        auto parse_field = [&](const std::string& prefix) -> std::string {
            if (line.size() > prefix.size() &&
                line.compare(0, prefix.size(), prefix) == 0) {
                std::string val = line.substr(prefix.size());
                size_t nsp = val.find_first_not_of(" \t");
                if (nsp != std::string::npos) val = val.substr(nsp);
                return val;
            }
            return "";
        };

        switch (section) {
        case HEADER:
            // Top-level fields
            break;
        case PER_MESSAGE: {
            std::string oid = parse_field("Original-Envelope-Id:");
            if (!oid.empty()) report.original_envelope_id = oid;
            std::string rmt = parse_field("Reporting-MTA:");
            if (!rmt.empty()) report.reporting_mta = rmt;
            break;
        }
        case PER_RECIPIENT: {
            std::string fr = parse_field("Final-Recipient:");
            if (!fr.empty()) {
                report.recipient_statuses.emplace_back();
                current_recipient = &report.recipient_statuses.back();
                report.total_recipients++;
                // Strip "rfc822;"
                size_t semi = fr.find(';');
                current_recipient->recipient_addr =
                    (semi != std::string::npos) ? fr.substr(semi + 1) : fr;
                // Trim
                size_t ns = current_recipient->recipient_addr.find_first_not_of(" \t");
                if (ns != std::string::npos)
                    current_recipient->recipient_addr =
                        current_recipient->recipient_addr.substr(ns);
            }

            std::string orec = parse_field("Original-Recipient:");
            if (!orec.empty() && current_recipient) {
                size_t semi = orec.find(';');
                current_recipient->original_rcpt_to =
                    (semi != std::string::npos) ? orec.substr(semi + 1) : orec;
                size_t ns = current_recipient->original_rcpt_to.find_first_not_of(" \t");
                if (ns != std::string::npos)
                    current_recipient->original_rcpt_to =
                        current_recipient->original_rcpt_to.substr(ns);
            }

            std::string action = parse_field("Action:");
            if (!action.empty() && current_recipient) {
                std::string la = action;
                std::transform(la.begin(), la.end(), la.begin(),
                               [](unsigned char c) { return std::tolower(c); });
                if (la == "delivered") {
                    current_recipient->delivered = true;
                    report.delivered_count++;
                } else if (la == "failed") {
                    report.failed_count++;
                    current_recipient->error_category = ErrorCategory::PERMANENT_SMTP;
                } else if (la == "delayed") {
                    current_recipient->delayed = true;
                    report.delayed_count++;
                } else if (la == "relayed") {
                    current_recipient->relayed = true;
                    report.relayed_count++;
                } else if (la == "expanded") {
                    current_recipient->expanded = true;
                    report.expanded_count++;
                }
            }

            std::string status = parse_field("Status:");
            if (!status.empty() && current_recipient) {
                try {
                    current_recipient->smtp_reply_code =
                        std::stoi(status.substr(0, status.find('.')));
                    current_recipient->smtp_enhanced_code = status;
                } catch (...) {}
            }

            std::string diag = parse_field("Diagnostic-Code:");
            if (!diag.empty() && current_recipient) {
                current_recipient->diagnostic_message = diag;
            }

            std::string rmta = parse_field("Remote-MTA:");
            if (!rmta.empty() && current_recipient) {
                current_recipient->remote_mta = rmta;
            }
            break;
        }
        }
    }

    if (report.total_recipients == 0) return std::nullopt;
    return report;
}

// ============================================================================
// User-friendly error message from ErrorCategory + raw error
// ============================================================================

static std::string user_friendly_error(ErrorCategory cat,
                                        const std::string& detail) {
    switch (cat) {
        case ErrorCategory::TEMPORARY_SMTP:
            return "Message couldn't be sent right now. We'll try again shortly.";
        case ErrorCategory::PERMANENT_SMTP:
            return "Message could not be delivered. " + detail;
        case ErrorCategory::TEMPORARY_IMAP:
            return "Temporarily unable to access your mailbox. We'll keep trying.";
        case ErrorCategory::PERMANENT_IMAP:
            return "Cannot access your mailbox. Please check your account settings.";
        case ErrorCategory::ENCRYPTION_ERROR:
            return "Encryption error — the message couldn't be encrypted.";
        case ErrorCategory::NETWORK_ERROR:
            return "Network error. Please check your internet connection.";
        case ErrorCategory::CONFIGURATION_ERROR:
            return "Email configuration error. Please check your account settings.";
        case ErrorCategory::DATABASE_ERROR:
            return "An internal database error occurred.";
        case ErrorCategory::TIMEOUT_ERROR:
            return "Sending timed out. We'll retry automatically.";
        case ErrorCategory::UNKNOWN_ERROR:
        default:
            if (detail.size() > 120) return detail.substr(0, 117) + "...";
            return detail.empty() ? "An unknown error occurred." : detail;
    }
}

// ============================================================================
// Status icon for UI display — returns single character / string
// ============================================================================

static const char* state_icon(int state, int retry_count, int padlock) {
    (void)retry_count;
    (void)padlock;
    switch (state) {
        case MSG_STATE_OUT_PREPARING:
        case MSG_STATE_OUT_DRAFT:     return "\xF0\x9F\x93\x9D";   // 📝 memo
        case MSG_STATE_OUT_PENDING:   return "\xF0\x9F\x95\x90";   // 🕐 clock
        case MSG_STATE_OUT_DELIVERED: return "\xE2\x9C\x93\xE2\x9C\x93"; // ✓✓
        case MSG_STATE_OUT_MDN_RCVD:  return "\xE2\x9C\x93\xE2\x9C\x93\xE2\x9C\x93"; // ✓✓✓
        case MSG_STATE_OUT_FAILED:    return "\xE2\x9C\x97";       // ✗
        case MSG_STATE_IN_FRESH:      return "\xF0\x9F\x94\xB5";   // 🔵 blue circle
        case MSG_STATE_IN_NOTICED:
        case MSG_STATE_IN_SEEN:
        default:                      return " ";
    }
}

static const char* state_icon_ascii(int state) {
    switch (state) {
        case MSG_STATE_OUT_PREPARING:
        case MSG_STATE_OUT_DRAFT:     return "[draft]";
        case MSG_STATE_OUT_PENDING:   return "[...]";
        case MSG_STATE_OUT_DELIVERED: return "[OK]";
        case MSG_STATE_OUT_MDN_RCVD:  return "[read]";
        case MSG_STATE_OUT_FAILED:    return "[FAIL]";
        case MSG_STATE_IN_FRESH:      return "[new]";
        case MSG_STATE_IN_NOTICED:
        case MSG_STATE_IN_SEEN:
        default:                      return "";
    }
}

// ============================================================================
// State transition validation — returns true if transition is valid
// ============================================================================

static bool is_valid_transition(int from_state, int to_state) {
    // Inbound progression
    if (from_state == MSG_STATE_IN_FRESH &&
        (to_state == MSG_STATE_IN_NOTICED || to_state == MSG_STATE_IN_SEEN))
        return true;
    if (from_state == MSG_STATE_IN_NOTICED &&
        to_state == MSG_STATE_IN_SEEN)
        return true;

    // Outbound progression — normal path
    if (from_state == MSG_STATE_OUT_PREPARING &&
        (to_state == MSG_STATE_OUT_DRAFT || to_state == MSG_STATE_OUT_PENDING))
        return true;
    if (from_state == MSG_STATE_OUT_DRAFT &&
        to_state == MSG_STATE_OUT_PENDING)
        return true;
    if (from_state == MSG_STATE_OUT_PENDING &&
        (to_state == MSG_STATE_OUT_DELIVERED || to_state == MSG_STATE_OUT_FAILED))
        return true;
    if (from_state == MSG_STATE_OUT_DELIVERED &&
        to_state == MSG_STATE_OUT_MDN_RCVD)
        return true;

    // Outbound — retry path (failed → pending on retry)
    if (from_state == MSG_STATE_OUT_FAILED &&
        to_state == MSG_STATE_OUT_PENDING)
        return true;

    // Allow re-delivery / re-send scenarios
    if (from_state == MSG_STATE_OUT_DELIVERED &&
        to_state == MSG_STATE_OUT_PENDING)
        return true;

    // Allow going back to preparing from draft/pending (editing)
    if (from_state == MSG_STATE_OUT_DRAFT &&
        to_state == MSG_STATE_OUT_PREPARING)
        return true;

    return false;
}

static const char* transition_error(int from_state, int to_state) {
    if (is_valid_transition(from_state, to_state)) return nullptr;
    // Build static message
    static thread_local char buf[128];
    std::snprintf(buf, sizeof(buf),
                  "Invalid state transition: %s → %s",
                  state_label(from_state), state_label(to_state));
    return buf;
}

// ============================================================================
// Read State Tracker — tracks which messages have been read across devices
// ============================================================================

struct ReadStateEntry {
    uint32_t msg_id;
    int64_t  chat_id;
    int64_t  read_at_unix;            // When the user saw this message
    bool     synced_to_server = false;// IMAP \\Seen flag set
    int64_t  synced_at_unix;
    std::string synced_by_device;
};

// ============================================================================
// Persistence record — for on-disk / SQL persistence of status
// ============================================================================

struct StatusPersistenceRecord {
    uint32_t    msg_id;
    int         state;
    int         retry_count;
    int64_t     last_attempt_ms;
    int64_t     next_attempt_ms;
    int64_t     created_at_ms;
    int64_t     send_deadline_ms;
    int         error_category_int;
    std::string error_text;
    std::string smtp_message_id;
    std::string envelope_from;
    int64_t     chat_id;
    int64_t     timestamp_ms;         // Last modification
};

// ============================================================================
// Status Manager — the main orchestrator
// ============================================================================

class MessageStatusManager {
public:
    MessageStatusManager() = default;
    ~MessageStatusManager() { shutdown(); }

    // Prevent copy/move
    MessageStatusManager(const MessageStatusManager&) = delete;
    MessageStatusManager& operator=(const MessageStatusManager&) = delete;

    // ------------------------------------------------------------------------
    // Initialisation / shutdown
    // ------------------------------------------------------------------------

    void init(const std::string& persistence_file = "") {
        std::unique_lock lock(mutex_);
        running_ = true;
        persistence_path_ = persistence_file;

        // Load persisted state if available
        if (!persistence_path_.empty()) {
            load_persistence();
        }

        // Start background workers
        retry_worker_ = std::thread(&MessageStatusManager::retry_loop, this);
        sync_worker_  = std::thread(&MessageStatusManager::sync_loop, this);
        persist_worker_ = std::thread(&MessageStatusManager::persist_loop, this);
    }

    void shutdown() {
        {
            std::unique_lock lock(mutex_);
            running_ = false;
        }
        retry_cv_.notify_all();
        sync_cv_.notify_all();
        persist_cv_.notify_all();

        if (retry_worker_.joinable())   retry_worker_.join();
        if (sync_worker_.joinable())    sync_worker_.join();
        if (persist_worker_.joinable()) persist_worker_.join();
    }

    // ------------------------------------------------------------------------
    // Core state tracking — get / set message state
    // ------------------------------------------------------------------------

    int get_state(uint32_t msg_id) const {
        std::shared_lock lock(mutex_);
        auto it = states_.find(msg_id);
        if (it != states_.end()) return it->second.current_state;
        return MSG_STATE_UNDEFINED;
    }

    // Set state with full transition validation.
    // Returns true if transition was accepted.
    bool set_state(uint32_t msg_id, int new_state,
                   const std::string& error = "",
                   ErrorCategory error_cat = ErrorCategory::NONE) {
        std::unique_lock lock(mutex_);

        auto it = states_.find(msg_id);
        if (it == states_.end()) {
            // Create new entry
            MessageRetryState entry;
            entry.msg_id        = msg_id;
            entry.current_state = MSG_STATE_UNDEFINED;
            entry.created_at_ms = now_ms();
            it = states_.emplace(msg_id, std::move(entry)).first;
        }

        MessageRetryState& s = it->second;
        int old_state = s.current_state;

        // Allow setting same state (no-op)
        if (old_state == new_state) return true;

        // Validate transition
        if (!is_valid_transition(old_state, new_state)) {
            // Log the invalid transition attempt
            last_transition_error_ = transition_error(old_state, new_state);
            return false;
        }

        // Perform transition
        s.current_state = new_state;
        s.last_attempt_ms = now_ms();

        if (!error.empty()) {
            s.last_error_text = error;
            s.last_error_category = error_cat;
        }

        // Update the state history map for quick lookups
        state_history_[msg_id].push_back({
            old_state, new_state, now_unix(), error
        });

        // Trim history to last 32 entries per message
        if (state_history_[msg_id].size() > 32) {
            state_history_[msg_id].erase(
                state_history_[msg_id].begin(),
                state_history_[msg_id].begin() +
                    (state_history_[msg_id].size() - 32));
        }

        // If transitioning to failed, update retry info
        if (new_state == MSG_STATE_OUT_FAILED) {
            s.last_error_text      = error;
            s.last_error_category  = error_cat;
            s.in_flight            = false;
        }

        // If transitioning to delivered, clear error
        if (new_state == MSG_STATE_OUT_DELIVERED) {
            s.last_error_text.clear();
            s.last_error_category = ErrorCategory::NONE;
            s.retry_count = 0;
            s.in_flight = false;
        }

        // If transitioning to pending (retry), set up next attempt
        if (new_state == MSG_STATE_OUT_PENDING && old_state == MSG_STATE_OUT_FAILED) {
            s.active = true;
            s.next_attempt_ms = now_ms() + compute_backoff_ms(s.retry_count + 1);
            retry_cv_.notify_one();
        }

        // If transitioning to pending from preparing, mark active
        if (new_state == MSG_STATE_OUT_PENDING &&
            (old_state == MSG_STATE_OUT_PREPARING || old_state == MSG_STATE_OUT_DRAFT)) {
            s.active = true;
            s.created_at_ms = now_ms();
            s.send_deadline_ms = s.created_at_ms + SEND_TIMEOUT_MS;
            s.next_attempt_ms = now_ms(); // Try immediately
            retry_cv_.notify_one();
        }

        // Fire callback for state change
        if (state_change_callback_) {
            state_change_callback_(msg_id, old_state, new_state);
        }

        return true;
    }

    // Convenience wrappers for specific transitions
    bool mark_pending(uint32_t msg_id, int64_t chat_id = 0) {
        std::unique_lock lock(mutex_);
        auto it = states_.find(msg_id);
        if (it == states_.end()) {
            MessageRetryState entry;
            entry.msg_id        = msg_id;
            entry.current_state = MSG_STATE_OUT_PENDING;
            entry.created_at_ms = now_ms();
            entry.send_deadline_ms = entry.created_at_ms + SEND_TIMEOUT_MS;
            entry.active        = true;
            entry.next_attempt_ms = now_ms();
            entry.chat_id       = chat_id;
            states_[msg_id] = std::move(entry);
            retry_cv_.notify_one();
            return true;
        }
        it->second.chat_id = chat_id;
        return set_state(msg_id, MSG_STATE_OUT_PENDING);
    }

    bool mark_delivered(uint32_t msg_id, const std::string& smtp_msg_id = "") {
        std::unique_lock lock(mutex_);
        auto it = states_.find(msg_id);
        if (it != states_.end() && !smtp_msg_id.empty()) {
            it->second.smtp_message_id = smtp_msg_id;
        }
        return set_state(msg_id, MSG_STATE_OUT_DELIVERED);
    }

    bool mark_mdn_received(uint32_t msg_id) {
        return set_state(msg_id, MSG_STATE_OUT_MDN_RCVD);
    }

    bool mark_failed(uint32_t msg_id, const std::string& error,
                     ErrorCategory cat = ErrorCategory::UNKNOWN_ERROR) {
        std::unique_lock lock(mutex_);
        auto it = states_.find(msg_id);
        if (it != states_.end()) {
            it->second.in_flight = false;
            if (is_error_temporary(cat)) {
                it->second.active = true;
                // Schedule retry
                it->second.retry_count++;
                if (it->second.retry_count <= MAX_RETRY_COUNT) {
                    it->second.next_attempt_ms = now_ms() +
                        compute_backoff_ms(it->second.retry_count);
                    retry_cv_.notify_one();
                } else {
                    it->second.active = false;
                }
            } else {
                it->second.active = false;
            }
        }
        return set_state(msg_id, MSG_STATE_OUT_FAILED, error, cat);
    }

    bool mark_fresh(uint32_t msg_id) {
        return set_state(msg_id, MSG_STATE_IN_FRESH);
    }

    bool mark_noticed(uint32_t msg_id) {
        return set_state(msg_id, MSG_STATE_IN_NOTICED);
    }

    bool mark_seen(uint32_t msg_id) {
        return set_state(msg_id, MSG_STATE_IN_SEEN);
    }

    // ------------------------------------------------------------------------
    // Read tracking
    // ------------------------------------------------------------------------

    void mark_message_read(uint32_t msg_id, int64_t chat_id,
                           const std::string& device_id = "local") {
        std::unique_lock lock(mutex_);

        ReadStateEntry entry;
        entry.msg_id         = msg_id;
        entry.chat_id        = chat_id;
        entry.read_at_unix   = now_unix();
        entry.synced_to_server = false;
        entry.synced_by_device = device_id;

        read_states_[msg_id] = entry;

        // Also transition state to seen if inbound
        auto it = states_.find(msg_id);
        if (it != states_.end()) {
            int st = it->second.current_state;
            if (st == MSG_STATE_IN_FRESH || st == MSG_STATE_IN_NOTICED) {
                set_state(msg_id, MSG_STATE_IN_SEEN);
            }
        }

        // Queue for multi-device sync
        sync_queue_.push_back({
            "read_state", msg_id, MSG_STATE_IN_SEEN,
            now_ms(), device_id, "", chat_id, "", ++sync_serial_
        });
    }

    bool is_message_read(uint32_t msg_id) const {
        std::shared_lock lock(mutex_);
        return read_states_.count(msg_id) > 0;
    }

    int64_t get_read_timestamp(uint32_t msg_id) const {
        std::shared_lock lock(mutex_);
        auto it = read_states_.find(msg_id);
        return (it != read_states_.end()) ? it->second.read_at_unix : 0;
    }

    std::vector<uint32_t> get_unread_messages(int64_t chat_id) const {
        std::shared_lock lock(mutex_);
        std::vector<uint32_t> result;
        for (const auto& [mid, state] : states_) {
            if (state.chat_id == chat_id) {
                int st = state.current_state;
                if (st == MSG_STATE_IN_FRESH || st == MSG_STATE_IN_NOTICED) {
                    if (read_states_.count(mid) == 0) {
                        result.push_back(mid);
                    }
                }
            }
        }
        return result;
    }

    int get_unread_count(int64_t chat_id) const {
        return static_cast<int>(get_unread_messages(chat_id).size());
    }

    // ------------------------------------------------------------------------
    // Delivery report generation
    // ------------------------------------------------------------------------

    DeliveryReport generate_delivery_report(uint32_t msg_id) {
        std::shared_lock lock(mutex_);
        DeliveryReport report;
        report.report_generated_at = now_unix();

        auto it = states_.find(msg_id);
        if (it == states_.end()) return report;

        const auto& s = it->second;
        report.original_message_id = s.smtp_message_id;
        report.reporting_mta = "progressive-server.local";
        report.arrival_date = static_cast<time_t>(s.created_at_ms / 1000);

        for (const auto& rec : s.recipients) {
            RecipientDeliveryStatus rds;
            rds.recipient_addr   = rec.addr;
            rds.smtp_reply_code  = rec.smtp_reply;
            rds.error_category   = rec.category;
            rds.diagnostic_message = rec.error_detail;
            rds.last_attempt_time  = static_cast<time_t>(s.last_attempt_ms / 1000);

            if (s.current_state == MSG_STATE_OUT_DELIVERED ||
                s.current_state == MSG_STATE_OUT_MDN_RCVD) {
                rds.delivered = true;
                rds.delivery_time = static_cast<time_t>(s.last_attempt_ms / 1000);
                report.delivered_count++;
            } else if (s.current_state == MSG_STATE_OUT_FAILED) {
                if (is_error_temporary(s.last_error_category)) {
                    rds.delayed = true;
                    report.delayed_count++;
                } else {
                    rds.delivered = false;
                    report.failed_count++;
                }
            } else {
                rds.delayed = true;
                report.delayed_count++;
            }

            report.recipient_statuses.push_back(rds);
        }

        report.total_recipients = static_cast<int>(s.recipients.size());
        return report;
    }

    // Generate a full RFC-format DSN text
    std::string generate_dsn_text(uint32_t msg_id) {
        DeliveryReport dr = generate_delivery_report(msg_id);
        std::stringstream dsn;

        dsn << "From: Mail Delivery System <mailer-daemon@progressive-server.local>\r\n";
        dsn << "To: <sender@local>\r\n";
        dsn << "Subject: Delivery Status Notification\r\n";
        dsn << "Date: " << format_timestamp_full(dr.report_generated_at) << "\r\n";
        dsn << "MIME-Version: 1.0\r\n";
        dsn << "Content-Type: multipart/report; report-type=delivery-status;\r\n";
        dsn << " boundary=\"===DSN" << dr.report_generated_at << "\"\r\n";
        dsn << "\r\n";
        dsn << "This is a MIME-encapsulated message.\r\n\r\n";
        dsn << "--===DSN" << dr.report_generated_at << "\r\n";
        dsn << "Content-Type: text/plain; charset=utf-8\r\n\r\n";

        if (dr.has_failures()) {
            dsn << "Your message could not be delivered to some recipients.\r\n";
        } else if (dr.all_delivered()) {
            dsn << "Your message was successfully delivered.\r\n";
        } else {
            dsn << "Delivery of your message is in progress.\r\n";
        }
        dsn << "\r\n";

        // Per-message DSN fields
        dsn << "--===DSN" << dr.report_generated_at << "\r\n";
        dsn << "Content-Type: message/delivery-status\r\n\r\n";
        dsn << "Reporting-MTA: dns; " << dr.reporting_mta << "\r\n";
        if (!dr.original_envelope_id.empty())
            dsn << "Original-Envelope-Id: " << dr.original_envelope_id << "\r\n";
        if (!dr.original_message_id.empty())
            dsn << "Original-Message-ID: <" << dr.original_message_id << ">\r\n";
        dsn << "Arrival-Date: " << format_timestamp_full(dr.arrival_date) << "\r\n";
        dsn << "\r\n";

        // Per-recipient blocks
        for (const auto& rec : dr.recipient_statuses) {
            dsn << "Final-Recipient: rfc822; " << rec.recipient_addr << "\r\n";
            if (!rec.original_rcpt_to.empty())
                dsn << "Original-Recipient: rfc822; " << rec.original_rcpt_to << "\r\n";

            if (rec.delivered) {
                dsn << "Action: delivered\r\n";
                dsn << "Status: 2.0.0\r\n";
            } else if (rec.delayed) {
                dsn << "Action: delayed\r\n";
                dsn << "Status: 4.0.0\r\n";
            } else {
                dsn << "Action: failed\r\n";
                dsn << "Status: " << rec.smtp_enhanced_code << "\r\n";
            }

            if (!rec.diagnostic_message.empty())
                dsn << "Diagnostic-Code: smtp; " << rec.smtp_reply_code
                    << " " << rec.diagnostic_message << "\r\n";
            if (!rec.remote_mta.empty())
                dsn << "Remote-MTA: dns; " << rec.remote_mta << "\r\n";
            if (rec.last_attempt_time > 0)
                dsn << "Last-Attempt-Date: "
                    << format_timestamp_full(rec.last_attempt_time) << "\r\n";
            dsn << "\r\n";
        }

        dsn << "--===DSN" << dr.report_generated_at << "--\r\n";
        return dsn.str();
    }

    // ------------------------------------------------------------------------
    // MDN receipt processing
    // ------------------------------------------------------------------------

    bool process_mdn_receipt(const std::string& mdn_raw_text) {
        std::unique_lock lock(mutex_);

        auto mdn_opt = parse_mdn_body(mdn_raw_text);
        if (!mdn_opt.has_value()) return false;

        const MdnReceipt& mdn = mdn_opt.value();

        // Store the MDN
        std::string mid = mdn.original_message_id;
        mdn_receipts_[mid] = mdn;

        // Find the message by its RFC 724 Message-ID and update state
        for (auto& [msg_id, state] : states_) {
            if (state.smtp_message_id == mid) {
                if (mdn.is_read_receipt()) {
                    set_state(msg_id, MSG_STATE_OUT_MDN_RCVD);
                    // Update read receipt info
                    state_read_receipts_[msg_id] = mdn;
                }
                return true;
            }
        }

        // Message not found in our state — store for later correlation
        orphan_mdns_[mid] = mdn;
        return true;
    }

    std::optional<MdnReceipt> get_mdn_receipt(uint32_t msg_id) const {
        std::shared_lock lock(mutex_);
        auto it = state_read_receipts_.find(msg_id);
        if (it != state_read_receipts_.end()) return it->second;
        return std::nullopt;
    }

    bool has_mdn_receipt(uint32_t msg_id) const {
        std::shared_lock lock(mutex_);
        return state_read_receipts_.count(msg_id) > 0;
    }

    // Correlate orphan MDNs after message IDs become known
    void correlate_orphan_mdns() {
        std::unique_lock lock(mutex_);
        std::vector<std::string> to_remove;

        for (const auto& [mid, mdn] : orphan_mdns_) {
            for (auto& [msg_id, state] : states_) {
                if (state.smtp_message_id == mid) {
                    if (mdn.is_read_receipt()) {
                        state_read_receipts_[msg_id] = mdn;
                        if (state.current_state == MSG_STATE_OUT_DELIVERED) {
                            state.current_state = MSG_STATE_OUT_MDN_RCVD;
                        }
                    }
                    to_remove.push_back(mid);
                    break;
                }
            }
        }

        for (const auto& mid : to_remove) {
            orphan_mdns_.erase(mid);
        }
    }

    // ------------------------------------------------------------------------
    // Error categorisation — static classification helpers
    // ------------------------------------------------------------------------

    static ErrorCategory categorize_error(const std::string& error_text) {
        // Try SMTP classification first
        auto [smtp_cat, smtp_desc] = classify_smtp_error(error_text);
        if (smtp_cat != ErrorCategory::UNKNOWN_ERROR) return smtp_cat;

        // Try IMAP classification
        ErrorCategory imap_cat = classify_imap_error(error_text);
        if (imap_cat != ErrorCategory::UNKNOWN_ERROR) return imap_cat;

        // Try encryption error classification
        EncryptionErrorInfo enc_info = classify_encryption_error(error_text);
        if (enc_info.category != ErrorCategory::UNKNOWN_ERROR) return enc_info.category;

        // Try network heuristics
        std::string upper = error_text;
        std::transform(upper.begin(), upper.end(), upper.begin(),
                       [](unsigned char c) { return std::toupper(c); });
        if (upper.find("TIMEOUT")      != std::string::npos ||
            upper.find("TIME OUT")     != std::string::npos) {
            return ErrorCategory::TIMEOUT_ERROR;
        }
        if (upper.find("DNS")          != std::string::npos ||
            upper.find("RESOLVE")      != std::string::npos ||
            upper.find("CONNECT")      != std::string::npos ||
            upper.find("REFUSED")      != std::string::npos ||
            upper.find("NETWORK")      != std::string::npos ||
            upper.find("UNREACHABLE")  != std::string::npos) {
            return ErrorCategory::NETWORK_ERROR;
        }
        if (upper.find("DATABASE")     != std::string::npos ||
            upper.find("SQL")          != std::string::npos ||
            upper.find("DISK FULL")    != std::string::npos ||
            upper.find("CORRUPT")      != std::string::npos) {
            return ErrorCategory::DATABASE_ERROR;
        }

        return ErrorCategory::UNKNOWN_ERROR;
    }

    static std::string user_error_message(const std::string& raw_error) {
        ErrorCategory cat = categorize_error(raw_error);
        return user_friendly_error(cat, raw_error);
    }

    // Set error for a specific message
    void set_message_error(uint32_t msg_id, const std::string& error_text) {
        std::unique_lock lock(mutex_);
        auto it = states_.find(msg_id);
        if (it == states_.end()) return;

        ErrorCategory cat = categorize_error(error_text);
        it->second.last_error_text     = error_text;
        it->second.last_error_category = cat;
    }

    // ------------------------------------------------------------------------
    // Retry logic
    // ------------------------------------------------------------------------

    // Explicitly schedule a retry
    bool schedule_retry(uint32_t msg_id) {
        std::unique_lock lock(mutex_);
        auto it = states_.find(msg_id);
        if (it == states_.end()) return false;

        MessageRetryState& s = it->second;
        if (s.retry_count >= MAX_RETRY_COUNT) return false;
        if (!is_error_temporary(s.last_error_category) &&
            s.last_error_category != ErrorCategory::NONE) return false;

        s.active = true;
        s.retry_count++;
        s.next_attempt_ms = now_ms() + compute_backoff_ms(s.retry_count);
        s.current_state = MSG_STATE_OUT_PENDING;
        retry_cv_.notify_one();
        return true;
    }

    // Cancel retries for a message
    void cancel_retries(uint32_t msg_id) {
        std::unique_lock lock(mutex_);
        auto it = states_.find(msg_id);
        if (it != states_.end()) {
            it->second.active = false;
            it->second.next_attempt_ms = 0;
        }
    }

    // Get the next message due for retry
    std::optional<uint32_t> get_next_retry_candidate() {
        std::unique_lock lock(mutex_);
        int64_t now = now_ms();
        uint32_t best_id = 0;
        int64_t  best_time = std::numeric_limits<int64_t>::max();

        for (auto& [msg_id, state] : states_) {
            if (!state.active) continue;
            if (state.in_flight) continue;
            if (state.current_state == MSG_STATE_OUT_FAILED &&
                !is_error_temporary(state.last_error_category)) continue;
            if (state.retry_count > MAX_RETRY_COUNT) continue;
            if (state.send_deadline_ms > 0 && now > state.send_deadline_ms) {
                // Timed out — mark as failed if not already
                if (state.current_state != MSG_STATE_OUT_FAILED) {
                    state.current_state = MSG_STATE_OUT_FAILED;
                    state.last_error_text = "Send timed out";
                    state.last_error_category = ErrorCategory::TIMEOUT_ERROR;
                    state.active = false;
                }
                continue;
            }

            if (state.next_attempt_ms <= now && state.next_attempt_ms < best_time) {
                best_time = state.next_attempt_ms;
                best_id   = msg_id;
            }
        }

        if (best_id != 0) {
            states_[best_id].in_flight = true;
            states_[best_id].in_flight_since_ms = now;
            return best_id;
        }
        return std::nullopt;
    }

    // Mark a retry attempt as finished
    void finish_retry_attempt(uint32_t msg_id, bool success,
                              const std::string& error = "") {
        std::unique_lock lock(mutex_);
        auto it = states_.find(msg_id);
        if (it == states_.end()) return;

        it->second.in_flight = false;
        it->second.last_attempt_ms = now_ms();

        if (success) {
            it->second.current_state = MSG_STATE_OUT_DELIVERED;
            it->second.active = false;
            it->second.last_error_text.clear();
            it->second.last_error_category = ErrorCategory::NONE;
            it->second.retry_count = 0;
        } else {
            ErrorCategory cat = categorize_error(error);
            it->second.last_error_text = error;
            it->second.last_error_category = cat;

            if (is_error_temporary(cat) && it->second.retry_count < MAX_RETRY_COUNT) {
                it->second.retry_count++;
                it->second.next_attempt_ms = now_ms() + compute_backoff_ms(it->second.retry_count);
                it->second.active = true;
            } else {
                it->second.current_state = MSG_STATE_OUT_FAILED;
                it->second.active = false;
            }
        }
    }

    // Get count of pending retries
    int get_pending_retry_count() const {
        std::shared_lock lock(mutex_);
        int count = 0;
        for (const auto& [_, state] : states_) {
            if (state.active && !state.in_flight) count++;
        }
        return count;
    }

    // ------------------------------------------------------------------------
    // Message sending timeout
    // ------------------------------------------------------------------------

    void check_send_timeouts() {
        std::unique_lock lock(mutex_);
        int64_t now = now_ms();
        std::vector<uint32_t> timed_out;

        for (auto& [msg_id, state] : states_) {
            if (state.current_state == MSG_STATE_OUT_PENDING &&
                state.send_deadline_ms > 0 &&
                now > state.send_deadline_ms) {
                // Check if there are still retries available
                if (state.retry_count < MAX_RETRY_COUNT &&
                    is_error_temporary(state.last_error_category)) {
                    // Extend deadline for one more retry
                    state.send_deadline_ms = now + SEND_TIMEOUT_MS;
                } else {
                    state.current_state = MSG_STATE_OUT_FAILED;
                    state.last_error_text = "Send timeout — message could not be delivered";
                    state.last_error_category = ErrorCategory::TIMEOUT_ERROR;
                    state.active = false;
                    state.in_flight = false;
                    timed_out.push_back(msg_id);
                }
            }
        }

        // Fire callbacks outside the lock to avoid deadlocks
        if (state_change_callback_) {
            for (uint32_t mid : timed_out) {
                state_change_callback_(mid, MSG_STATE_OUT_PENDING, MSG_STATE_OUT_FAILED);
            }
        }
    }

    // Set a custom send timeout per message
    void set_send_timeout(uint32_t msg_id, int64_t timeout_ms) {
        std::unique_lock lock(mutex_);
        auto it = states_.find(msg_id);
        if (it != states_.end()) {
            it->second.send_deadline_ms = now_ms() + timeout_ms;
        }
    }

    // ------------------------------------------------------------------------
    // Message status UI format
    // ------------------------------------------------------------------------

    MessageStatusUI get_status_ui(uint32_t msg_id, bool use_unicode = true) {
        std::shared_lock lock(mutex_);
        MessageStatusUI ui;
        ui.msg_id = msg_id;

        auto it = states_.find(msg_id);
        if (it == states_.end()) {
            ui.status_text = "";
            ui.status_icon = "";
            return ui;
        }

        const auto& s = it->second;
        ui.state         = s.current_state;
        ui.timestamp_ms = s.last_attempt_ms > 0 ? s.last_attempt_ms : s.created_at_ms;
        ui.error_text    = user_friendly_error(s.last_error_category, s.last_error_text);
        ui.error_detail  = s.last_error_text;
        ui.retry_count   = s.retry_count;

        if (s.active && s.current_state != MSG_STATE_OUT_FAILED) {
            ui.retry_eta_ms = s.next_attempt_ms - now_ms();
            if (ui.retry_eta_ms < 0) ui.retry_eta_ms = 0;
        }

        // Check if encryption is involved
        ui.is_encrypted = s.last_error_text.find("encrypt") != std::string::npos ||
                          s.last_error_text.find("pgp") != std::string::npos;

        // Check MDN / read receipt
        ui.has_read_receipt = state_read_receipts_.count(msg_id) > 0;
        ui.has_delivery_report = (s.current_state == MSG_STATE_OUT_DELIVERED ||
                                  s.current_state == MSG_STATE_OUT_MDN_RCVD ||
                                  s.current_state == MSG_STATE_OUT_FAILED);

        // Build status icon and text
        if (use_unicode) {
            ui.status_icon = state_icon(s.current_state, s.retry_count, 0);
        } else {
            ui.status_icon = state_icon_ascii(s.current_state);
        }

        switch (s.current_state) {
            case MSG_STATE_OUT_PREPARING:
                ui.status_text = "Composing…";
                break;
            case MSG_STATE_OUT_DRAFT:
                ui.status_text = "Draft";
                break;
            case MSG_STATE_OUT_PENDING:
                if (s.in_flight) {
                    ui.status_text = "Sending…";
                } else if (s.active && s.retry_count > 0) {
                    ui.status_text = "Retrying… (" +
                        std::to_string(s.retry_count) + "/" +
                        std::to_string(MAX_RETRY_COUNT) + ")";
                } else {
                    ui.status_text = "Queued";
                }
                break;
            case MSG_STATE_OUT_DELIVERED:
                ui.status_text = "Delivered";
                ui.padlock_state = ui.is_encrypted ? 2 : 0;
                break;
            case MSG_STATE_OUT_MDN_RCVD:
                ui.status_text = "Read";
                ui.padlock_state = ui.is_encrypted ? 2 : 0;
                break;
            case MSG_STATE_OUT_FAILED:
                if (s.retry_count >= MAX_RETRY_COUNT) {
                    ui.status_text = "Failed (max retries)";
                } else if (is_error_temporary(s.last_error_category)) {
                    ui.status_text = "Failed — will retry";
                } else {
                    ui.status_text = "Failed";
                }
                break;
            case MSG_STATE_IN_FRESH:
                ui.status_text = "";
                break;
            case MSG_STATE_IN_NOTICED:
                ui.status_text = "";
                break;
            case MSG_STATE_IN_SEEN:
                ui.status_text = "";
                break;
            default:
                ui.status_text = "Unknown";
                break;
        }

        // Format timestamp
        time_t ts = static_cast<time_t>(steady_to_unix_ms(ui.timestamp_ms) / 1000);
        ui.timestamp_text = format_timestamp_hhmm(ts);

        return ui;
    }

    std::string get_status_summary(uint32_t msg_id, bool verbose = false) {
        MessageStatusUI ui = get_status_ui(msg_id, false);
        std::stringstream ss;
        ss << ui.status_text;
        if (verbose && !ui.error_text.empty()) {
            ss << " — " << ui.error_text;
        }
        if (verbose && ui.retry_count > 0) {
            ss << " (retry " << ui.retry_count << "/" << MAX_RETRY_COUNT << ")";
        }
        return ss.str();
    }

    // ------------------------------------------------------------------------
    // Multi-device status sync
    // ------------------------------------------------------------------------

    // Generate a sync payload for the current status of a message
    StatusSyncPayload generate_sync_payload(uint32_t msg_id,
                                            const std::string& device_id) {
        std::shared_lock lock(mutex_);
        StatusSyncPayload payload;
        payload.sync_type   = "msg_state";
        payload.msg_id      = msg_id;
        payload.timestamp_ms = now_ms();
        payload.origin_device_id = device_id;
        payload.sync_serial = ++sync_serial_;

        auto it = states_.find(msg_id);
        if (it != states_.end()) {
            payload.new_state = it->second.current_state;
            payload.rfc724_mid = it->second.smtp_message_id;
            payload.chat_id    = it->second.chat_id;
        }

        return payload;
    }

    // Apply an incoming sync payload from another device
    bool apply_sync_payload(const StatusSyncPayload& payload) {
        std::unique_lock lock(mutex_);

        // Deduplicate — skip if we've already seen this serial
        if (payload.sync_serial > 0) {
            if (applied_sync_serials_.count(payload.sync_serial)) {
                return true; // Already applied
            }
            applied_sync_serials_.insert(payload.sync_serial);
            // Prune old serials to keep set bounded
            if (applied_sync_serials_.size() > 10000) {
                // Remove the smallest 5000 entries
                auto it = applied_sync_serials_.begin();
                std::advance(it, 5000);
                applied_sync_serials_.erase(applied_sync_serials_.begin(), it);
            }
        }

        if (payload.sync_type == "msg_state" || payload.sync_type == "read_state") {
            auto it = states_.find(payload.msg_id);
            if (it == states_.end()) {
                // Create entry if it doesn't exist locally
                MessageRetryState s;
                s.msg_id = payload.msg_id;
                s.chat_id = payload.chat_id;
                s.smtp_message_id = payload.rfc724_mid;
                s.current_state = payload.new_state;
                states_[payload.msg_id] = s;
            } else {
                // Only apply if the remote state is "more advanced"
                // (higher state value numbers are more advanced)
                if (payload.new_state > it->second.current_state) {
                    // Allow transition in any direction for sync
                    it->second.current_state = payload.new_state;
                }
            }

            // If this is a read_state sync, update read tracking
            if (payload.sync_type == "read_state" &&
                payload.new_state == MSG_STATE_IN_SEEN) {
                mark_message_read(payload.msg_id, payload.chat_id,
                                  payload.origin_device_id);
            }

            return true;
        }

        if (payload.sync_type == "delivery_report") {
            // For delivery reports, apply to the relevant message
            auto it = states_.find(payload.msg_id);
            if (it != states_.end() && payload.new_state > it->second.current_state) {
                it->second.current_state = payload.new_state;
            }
            return true;
        }

        return false;
    }

    // Get pending sync payloads to send to other devices
    std::vector<StatusSyncPayload> drain_sync_queue(int max_items = 100) {
        std::unique_lock lock(mutex_);
        std::vector<StatusSyncPayload> result;
        int count = std::min(max_items, static_cast<int>(sync_queue_.size()));
        for (int i = 0; i < count; i++) {
            result.push_back(sync_queue_.front());
            sync_queue_.pop_front();
        }
        return result;
    }

    // ------------------------------------------------------------------------
    // Persistence
    // ------------------------------------------------------------------------

    void set_persistence_path(const std::string& path) {
        std::unique_lock lock(mutex_);
        persistence_path_ = path;
    }

    // Force a persistence write now
    bool persist_now() {
        return write_persistence();
    }

    // ------------------------------------------------------------------------
    // Statistics / diagnostics
    // ------------------------------------------------------------------------

    struct StatusStats {
        int total_tracked;
        int out_pending;
        int out_delivered;
        int out_mdn_rcvd;
        int out_failed;
        int in_fresh;
        int in_noticed;
        int in_seen;
        int active_retries;
        int inactive;
    };

    StatusStats get_stats() const {
        std::shared_lock lock(mutex_);
        StatusStats s = {};
        s.total_tracked = static_cast<int>(states_.size());

        for (const auto& [_, st] : states_) {
            switch (st.current_state) {
                case MSG_STATE_OUT_PENDING:   s.out_pending++; break;
                case MSG_STATE_OUT_DELIVERED: s.out_delivered++; break;
                case MSG_STATE_OUT_MDN_RCVD:  s.out_mdn_rcvd++; break;
                case MSG_STATE_OUT_FAILED:    s.out_failed++; break;
                case MSG_STATE_IN_FRESH:      s.in_fresh++; break;
                case MSG_STATE_IN_NOTICED:    s.in_noticed++; break;
                case MSG_STATE_IN_SEEN:       s.in_seen++; break;
                default: break;
            }
            if (st.active && !st.in_flight) s.active_retries++;
            if (!st.active) s.inactive++;
        }

        return s;
    }

    std::string get_stats_text() const {
        StatusStats s = get_stats();
        std::stringstream ss;
        ss << "Status tracker: " << s.total_tracked << " messages\n";
        ss << "  Outgoing: pending=" << s.out_pending
           << " delivered=" << s.out_delivered
           << " read=" << s.out_mdn_rcvd
           << " failed=" << s.out_failed << "\n";
        ss << "  Incoming: fresh=" << s.in_fresh
           << " noticed=" << s.in_noticed
           << " seen=" << s.in_seen << "\n";
        ss << "  Active retries: " << s.active_retries << "\n";
        return ss.str();
    }

    // ------------------------------------------------------------------------
    // State change callback
    // ------------------------------------------------------------------------

    using StateChangeCallback = std::function<void(
        uint32_t msg_id, int old_state, int new_state)>;

    void set_state_change_callback(StateChangeCallback cb) {
        std::unique_lock lock(mutex_);
        state_change_callback_ = std::move(cb);
    }

    // ------------------------------------------------------------------------
    // Bulk operations
    // ------------------------------------------------------------------------

    // Mark all messages in a chat as seen
    void mark_chat_seen(int64_t chat_id) {
        std::unique_lock lock(mutex_);
        for (auto& [msg_id, state] : states_) {
            if (state.chat_id == chat_id) {
                if (state.current_state == MSG_STATE_IN_FRESH ||
                    state.current_state == MSG_STATE_IN_NOTICED) {
                    state.current_state = MSG_STATE_IN_SEEN;
                    // Also add read state
                    ReadStateEntry entry;
                    entry.msg_id       = msg_id;
                    entry.chat_id      = chat_id;
                    entry.read_at_unix = now_unix();
                    read_states_[msg_id] = entry;
                }
            }
        }
    }

    // Purge old / stale tracking entries
    void purge_stale_entries(int max_age_secs = STALE_MESSAGE_AGE_SECS) {
        std::unique_lock lock(mutex_);
        time_t cutoff = now_unix() - max_age_secs;
        std::vector<uint32_t> to_remove;

        for (const auto& [msg_id, state] : states_) {
            time_t msg_time = static_cast<time_t>(state.last_attempt_ms / 1000);
            if (msg_time < cutoff &&
                (state.current_state == MSG_STATE_OUT_DELIVERED ||
                 state.current_state == MSG_STATE_OUT_MDN_RCVD ||
                 state.current_state == MSG_STATE_IN_SEEN ||
                 (state.current_state == MSG_STATE_OUT_FAILED && !state.active))) {
                to_remove.push_back(msg_id);
            }
        }

        for (uint32_t mid : to_remove) {
            states_.erase(mid);
            state_history_.erase(mid);
            read_states_.erase(mid);
            state_read_receipts_.erase(mid);
        }
    }

    // ------------------------------------------------------------------------
    // Recipient-level tracking
    // ------------------------------------------------------------------------

    void set_recipients(uint32_t msg_id,
                        const std::vector<std::string>& recipient_addrs) {
        std::unique_lock lock(mutex_);
        auto it = states_.find(msg_id);
        if (it == states_.end()) {
            MessageRetryState s;
            s.msg_id = msg_id;
            states_[msg_id] = s;
            it = states_.find(msg_id);
        }

        it->second.recipients.clear();
        for (const auto& addr : recipient_addrs) {
            MessageRetryState::RecipientRetryInfo r;
            r.addr = addr;
            it->second.recipients.push_back(r);
        }
    }

    void update_recipient_error(uint32_t msg_id, const std::string& addr,
                                const std::string& error, int smtp_code) {
        std::unique_lock lock(mutex_);
        auto it = states_.find(msg_id);
        if (it == states_.end()) return;

        for (auto& rec : it->second.recipients) {
            if (rec.addr == addr) {
                rec.smtp_reply   = smtp_code;
                rec.error_detail = error;
                rec.category     = categorize_error(error);
                rec.local_retries++;
                if (!is_error_temporary(rec.category)) {
                    rec.permanently_failed = true;
                }
                break;
            }
        }
    }

    bool is_recipient_permanently_failed(uint32_t msg_id,
                                          const std::string& addr) const {
        std::shared_lock lock(mutex_);
        auto it = states_.find(msg_id);
        if (it == states_.end()) return false;
        for (const auto& rec : it->second.recipients) {
            if (rec.addr == addr) return rec.permanently_failed;
        }
        return false;
    }

    // ------------------------------------------------------------------------
    // Changelog / audit trail for a message
    // ------------------------------------------------------------------------

    struct StateTransition {
        int      from_state;
        int      to_state;
        time_t   timestamp;
        std::string error_info;
    };

    std::vector<StateTransition> get_state_history(uint32_t msg_id) const {
        std::shared_lock lock(mutex_);
        auto it = state_history_.find(msg_id);
        if (it != state_history_.end()) return it->second;
        return {};
    }

    // ------------------------------------------------------------------------
    // Access to underlying state for advanced users
    // ------------------------------------------------------------------------

    std::optional<MessageRetryState> get_retry_state(uint32_t msg_id) const {
        std::shared_lock lock(mutex_);
        auto it = states_.find(msg_id);
        if (it != states_.end()) return it->second;
        return std::nullopt;
    }

private:
    // ------------------------------------------------------------------------
    // Background worker — retry loop
    // ------------------------------------------------------------------------
    void retry_loop() {
        while (true) {
            std::unique_lock lock(mutex_);
            retry_cv_.wait_for(lock, std::chrono::milliseconds(1000), [this] {
                return !running_ || has_ready_retry();
            });

            if (!running_) break;
        }
    }

    bool has_ready_retry() {
        int64_t now = now_ms();
        for (const auto& [_, state] : states_) {
            if (state.active && !state.in_flight &&
                state.next_attempt_ms <= now) {
                return true;
            }
        }
        return false;
    }

    // ------------------------------------------------------------------------
    // Background worker — sync loop
    // ------------------------------------------------------------------------
    void sync_loop() {
        while (true) {
            {
                std::unique_lock lock(mutex_);
                sync_cv_.wait_for(lock,
                    std::chrono::milliseconds(STATUS_SYNC_INTERVAL_MS));
            }
            if (!running_) break;

            // Correlate orphan MDNs periodically
            correlate_orphan_mdns();

            // Check send timeouts
            check_send_timeouts();
        }
    }

    // ------------------------------------------------------------------------
    // Background worker — persistence loop
    // ------------------------------------------------------------------------
    void persist_loop() {
        while (true) {
            {
                std::unique_lock lock(mutex_);
                persist_cv_.wait_for(lock,
                    std::chrono::seconds(STATUS_PERSIST_INTERVAL_SECS));
            }
            if (!running_) break;

            if (!persistence_path_.empty()) {
                write_persistence();
            }
        }

        // Final flush on shutdown
        if (!persistence_path_.empty()) {
            write_persistence();
        }
    }

    // ------------------------------------------------------------------------
    // JSON persistence (simple JSON file)
    // ------------------------------------------------------------------------

    bool load_persistence() {
        if (persistence_path_.empty()) return false;

        std::ifstream file(persistence_path_);
        if (!file.good()) return false; // No file yet, not an error

        std::stringstream buffer;
        buffer << file.rdbuf();
        std::string content = buffer.str();
        if (content.empty()) return false;

        // Simple line-based CSV-like format for portability
        // Format: msg_id|state|retry_count|last_attempt|next_attempt|created|deadline|error_cat|error_text|smtp_msg_id|chat_id
        std::istringstream stream(content);
        std::string line;
        while (std::getline(stream, line)) {
            if (line.empty() || line[0] == '#') continue;

            std::vector<std::string> fields;
            std::stringstream ls(line);
            std::string field;
            while (std::getline(ls, field, '|')) {
                fields.push_back(field);
            }

            if (fields.size() < 8) continue;

            try {
                MessageRetryState s;
                s.msg_id            = static_cast<uint32_t>(std::stoul(fields[0]));
                s.current_state     = std::stoi(fields[1]);
                s.retry_count       = std::stoi(fields[2]);
                s.last_attempt_ms   = std::stoll(fields[3]);
                s.next_attempt_ms   = std::stoll(fields[4]);
                s.created_at_ms     = std::stoll(fields[5]);
                s.send_deadline_ms  = std::stoll(fields[6]);
                s.last_error_category = static_cast<ErrorCategory>(std::stoi(fields[7]));
                if (fields.size() > 8)  s.last_error_text  = fields[8];
                if (fields.size() > 9)  s.smtp_message_id   = fields[9];
                if (fields.size() > 10) s.chat_id           = std::stoll(fields[10]);
                s.active = (s.current_state == MSG_STATE_OUT_PENDING) ||
                           (s.current_state == MSG_STATE_OUT_FAILED &&
                            is_error_temporary(s.last_error_category));

                states_[s.msg_id] = s;
            } catch (...) {
                // Skip malformed lines
            }
        }

        return true;
    }

    bool write_persistence() {
        if (persistence_path_.empty()) return false;

        std::string tmp_path = persistence_path_ + ".tmp";
        std::ofstream file(tmp_path, std::ios::trunc);
        if (!file.good()) return false;

        file << "# DeltaChat Status Tracking — persistence file\n";
        file << "# Format: msg_id|state|retries|last_attempt|next_attempt|created|deadline|error_cat|error|msg_id|chat_id\n";
        file << "# Generated: " << format_timestamp_full(now_unix()) << "\n";

        for (const auto& [msg_id, s] : states_) {
            // Skip transient composes/drafts
            if (s.current_state == MSG_STATE_UNDEFINED ||
                s.current_state == MSG_STATE_OUT_PREPARING ||
                s.current_state == MSG_STATE_OUT_DRAFT) continue;

            // Simple CSV-like line with pipe separator
            auto escape_pipe = [](const std::string& input) -> std::string {
                std::string r;
                for (char c : input) {
                    if (c == '|') r += "\\|";
                    else if (c == '\\') r += "\\\\";
                    else if (c == '\n') r += "\\n";
                    else r += c;
                }
                return r;
            };

            file << msg_id << "|"
                 << s.current_state << "|"
                 << s.retry_count << "|"
                 << s.last_attempt_ms << "|"
                 << s.next_attempt_ms << "|"
                 << s.created_at_ms << "|"
                 << s.send_deadline_ms << "|"
                 << static_cast<int>(s.last_error_category) << "|"
                 << escape_pipe(s.last_error_text) << "|"
                 << escape_pipe(s.smtp_message_id) << "|"
                 << s.chat_id << "\n";
        }

        file.close();

        // Atomic rename
        std::rename(tmp_path.c_str(), persistence_path_.c_str());
        return true;
    }

    // ------------------------------------------------------------------------
    // Members
    // ------------------------------------------------------------------------

    mutable std::shared_mutex mutex_;

    // Primary state storage: msg_id → retry/status info
    std::unordered_map<uint32_t, MessageRetryState> states_;

    // State transition history: msg_id → ordered transitions
    std::unordered_map<uint32_t, std::vector<StateTransition>> state_history_;

    // Read tracking
    std::unordered_map<uint32_t, ReadStateEntry> read_states_;

    // MDN receipts correlated to messages
    std::unordered_map<uint32_t, MdnReceipt> state_read_receipts_;

    // MDN receipts by message-id (for lookup before correlation)
    std::unordered_map<std::string, MdnReceipt> mdn_receipts_;

    // Orphan MDNs — not yet correlated to a local message
    std::unordered_map<std::string, MdnReceipt> orphan_mdns_;

    // Sync queue — outgoing sync payloads
    std::deque<StatusSyncPayload> sync_queue_;
    std::set<int64_t> applied_sync_serials_;
    int64_t sync_serial_ = 0;

    // Persistence
    std::string persistence_path_;

    // Background workers
    std::thread retry_worker_;
    std::thread sync_worker_;
    std::thread persist_worker_;
    std::condition_variable_any retry_cv_;
    std::condition_variable_any sync_cv_;
    std::condition_variable_any persist_cv_;
    std::atomic<bool> running_{false};

    // Callbacks
    StateChangeCallback state_change_callback_;

    // Last transition error message
    std::string last_transition_error_;
};

// ============================================================================
// Singleton accessor — one status manager per process
// ============================================================================

static std::unique_ptr<MessageStatusManager> g_status_manager;
static std::mutex g_status_mutex;

MessageStatusManager& status_manager() {
    std::lock_guard<std::mutex> lock(g_status_mutex);
    if (!g_status_manager) {
        g_status_manager = std::make_unique<MessageStatusManager>();
    }
    return *g_status_manager;
}

// ============================================================================
// Public convenience functions — thin wrappers over the singleton
// ============================================================================

void status_init(const std::string& persistence_file) {
    status_manager().init(persistence_file);
}

void status_shutdown() {
    status_manager().shutdown();
}

int  status_get_state(uint32_t msg_id) {
    return status_manager().get_state(msg_id);
}

bool status_set_state(uint32_t msg_id, int new_state, const std::string& error) {
    return status_manager().set_state(msg_id, new_state, error);
}

bool status_mark_pending(uint32_t msg_id, int64_t chat_id) {
    return status_manager().mark_pending(msg_id, chat_id);
}

bool status_mark_delivered(uint32_t msg_id, const std::string& smtp_msg_id) {
    return status_manager().mark_delivered(msg_id, smtp_msg_id);
}

bool status_mark_mdn_received(uint32_t msg_id) {
    return status_manager().mark_mdn_received(msg_id);
}

bool status_mark_failed(uint32_t msg_id, const std::string& error,
                        ErrorCategory cat) {
    return status_manager().mark_failed(msg_id, error, cat);
}

bool status_mark_fresh(uint32_t msg_id) {
    return status_manager().mark_fresh(msg_id);
}

bool status_mark_noticed(uint32_t msg_id) {
    return status_manager().mark_noticed(msg_id);
}

bool status_mark_seen(uint32_t msg_id) {
    return status_manager().mark_seen(msg_id);
}

void status_mark_read(uint32_t msg_id, int64_t chat_id, const std::string& device) {
    status_manager().mark_message_read(msg_id, chat_id, device);
}

bool status_is_read(uint32_t msg_id) {
    return status_manager().is_message_read(msg_id);
}

int64_t status_read_timestamp(uint32_t msg_id) {
    return status_manager().get_read_timestamp(msg_id);
}

std::vector<uint32_t> status_get_unread(int64_t chat_id) {
    return status_manager().get_unread_messages(chat_id);
}

int status_unread_count(int64_t chat_id) {
    return status_manager().get_unread_count(chat_id);
}

void status_mark_chat_seen(int64_t chat_id) {
    status_manager().mark_chat_seen(chat_id);
}

DeliveryReport status_delivery_report(uint32_t msg_id) {
    return status_manager().generate_delivery_report(msg_id);
}

std::string status_dsn_text(uint32_t msg_id) {
    return status_manager().generate_dsn_text(msg_id);
}

bool status_process_mdn(const std::string& mdn_text) {
    return status_manager().process_mdn_receipt(mdn_text);
}

std::optional<MdnReceipt> status_get_mdn(uint32_t msg_id) {
    return status_manager().get_mdn_receipt(msg_id);
}

bool status_has_mdn(uint32_t msg_id) {
    return status_manager().has_mdn_receipt(msg_id);
}

ErrorCategory status_categorize_error(const std::string& error_text) {
    return MessageStatusManager::categorize_error(error_text);
}

std::string status_user_error(const std::string& raw_error) {
    return MessageStatusManager::user_error_message(raw_error);
}

void status_set_error(uint32_t msg_id, const std::string& error) {
    status_manager().set_message_error(msg_id, error);
}

bool status_schedule_retry(uint32_t msg_id) {
    return status_manager().schedule_retry(msg_id);
}

void status_cancel_retries(uint32_t msg_id) {
    status_manager().cancel_retries(msg_id);
}

std::optional<uint32_t> status_next_retry() {
    return status_manager().get_next_retry_candidate();
}

void status_finish_retry(uint32_t msg_id, bool success, const std::string& error) {
    status_manager().finish_retry_attempt(msg_id, success, error);
}

int status_pending_retry_count() {
    return status_manager().get_pending_retry_count();
}

void status_set_send_timeout(uint32_t msg_id, int64_t timeout_ms) {
    status_manager().set_send_timeout(msg_id, timeout_ms);
}

MessageStatusUI status_get_ui(uint32_t msg_id, bool unicode) {
    return status_manager().get_status_ui(msg_id, unicode);
}

std::string status_summary(uint32_t msg_id, bool verbose) {
    return status_manager().get_status_summary(msg_id, verbose);
}

StatusSyncPayload status_sync_payload(uint32_t msg_id, const std::string& device) {
    return status_manager().generate_sync_payload(msg_id, device);
}

bool status_apply_sync(const StatusSyncPayload& payload) {
    return status_manager().apply_sync_payload(payload);
}

std::vector<StatusSyncPayload> status_drain_sync(int max_items) {
    return status_manager().drain_sync_queue(max_items);
}

void status_set_persistence(const std::string& path) {
    status_manager().set_persistence_path(path);
}

bool status_persist_now() {
    return status_manager().persist_now();
}

void status_purge_stale(int max_age_secs) {
    status_manager().purge_stale_entries(max_age_secs);
}

void status_set_recipients(uint32_t msg_id, const std::vector<std::string>& addrs) {
    status_manager().set_recipients(msg_id, addrs);
}

void status_update_recipient_error(uint32_t msg_id, const std::string& addr,
                                    const std::string& error, int smtp_code) {
    status_manager().update_recipient_error(msg_id, addr, error, smtp_code);
}

bool status_recipient_permanently_failed(uint32_t msg_id, const std::string& addr) {
    return status_manager().is_recipient_permanently_failed(msg_id, addr);
}

std::vector<MessageStatusManager::StateTransition> status_get_history(uint32_t msg_id) {
    return status_manager().get_state_history(msg_id);
}

std::optional<MessageRetryState> status_get_retry_state(uint32_t msg_id) {
    return status_manager().get_retry_state(msg_id);
}

std::string status_stats_text() {
    return status_manager().get_stats_text();
}

void status_set_state_change_callback(
    std::function<void(uint32_t, int, int)> cb) {
    status_manager().set_state_change_callback(std::move(cb));
}

// ============================================================================
// Serialisation helpers for structured types
// ============================================================================

std::string delivery_report_to_string(const DeliveryReport& dr) {
    std::stringstream ss;
    ss << "Delivery Report:\n";
    ss << "  Message-ID: " << dr.original_message_id << "\n";
    ss << "  MTA: " << dr.reporting_mta << "\n";
    ss << "  Generated: " << format_timestamp_full(dr.report_generated_at) << "\n";
    ss << "  Recipients: total=" << dr.total_recipients
       << " delivered=" << dr.delivered_count
       << " failed=" << dr.failed_count
       << " delayed=" << dr.delayed_count << "\n";

    for (const auto& r : dr.recipient_statuses) {
        ss << "    " << r.recipient_addr << ": ";
        if (r.delivered) {
            ss << "DELIVERED";
        } else if (r.delayed) {
            ss << "DELAYED";
        } else {
            ss << "FAILED (" << r.smtp_reply_code << " " << r.diagnostic_message << ")";
        }
        ss << "\n";
    }

    return ss.str();
}

std::string mdn_receipt_to_string(const MdnReceipt& mdn) {
    std::stringstream ss;
    ss << "MDN Receipt:\n";
    ss << "  Original Message-ID: " << mdn.original_message_id << "\n";
    ss << "  Original Recipient: " << mdn.original_recipient << "\n";
    ss << "  Final Recipient: " << mdn.final_recipient << "\n";
    ss << "  Disposition: " << mdn.disposition
       << " (" << mdn.disposition_mode << ")\n";
    ss << "  Agent: " << mdn.sending_mdn_agent << "\n";
    if (mdn.displayed_at > 0) {
        ss << "  Displayed at: " << format_timestamp_full(mdn.displayed_at) << "\n";
    }
    ss << "  Received at: " << format_timestamp_full(mdn.received_at) << "\n";
    return ss.str();
}

std::string retry_state_to_string(const MessageRetryState& rs) {
    std::stringstream ss;
    ss << "RetryState(msg_id=" << rs.msg_id
       << " state=" << state_label(rs.current_state)
       << " retries=" << rs.retry_count << "/" << MAX_RETRY_COUNT;
    if (!rs.last_error_text.empty()) {
        ss << " error=[" << error_category_label(rs.last_error_category)
           << "] " << rs.last_error_text;
    }
    if (rs.active) {
        ss << " next_retry_in=" << (rs.next_attempt_ms - now_ms()) << "ms";
    }
    ss << ")";
    return ss.str();
}

// ============================================================================
// Periodic maintenance — call from the main I/O loop (e.g. every 30 s)
// ============================================================================

void status_periodic_maintenance() {
    status_manager().check_send_timeouts();
    status_manager().purge_stale_entries();
    status_manager().correlate_orphan_mdns();
}

// ============================================================================
// SQL-based persistence layer — optional, for production use
// ============================================================================

// SQL schema for status persistence (CREATE TABLE statements)
// Uses a minimal embedded SQL approach via simple file operations
// but the schema is documented here for real DB integration.

static const char* STATUS_TRACKING_SQL_SCHEMA = R"SQL(
-- DeltaChat Status Tracking — SQL schema
-- This is for reference; the actual persistence uses a pipe-delimited
-- flat file for zero-dependency operation.  Integrate with your
-- preferred SQL backend using these table definitions.

CREATE TABLE IF NOT EXISTS dc_message_status (
    msg_id              INTEGER PRIMARY KEY,
    chat_id             INTEGER NOT NULL DEFAULT 0,
    state               INTEGER NOT NULL DEFAULT 0,
    retry_count         INTEGER NOT NULL DEFAULT 0,
    last_attempt_ms     INTEGER NOT NULL DEFAULT 0,
    next_attempt_ms     INTEGER NOT NULL DEFAULT 0,
    created_at_ms       INTEGER NOT NULL DEFAULT 0,
    send_deadline_ms    INTEGER NOT NULL DEFAULT 0,
    error_category      INTEGER NOT NULL DEFAULT 0,
    error_text          TEXT,
    smtp_message_id     TEXT,
    envelope_from       TEXT,
    active              INTEGER NOT NULL DEFAULT 0,
    in_flight           INTEGER NOT NULL DEFAULT 0,
    in_flight_since_ms  INTEGER NOT NULL DEFAULT 0,
    updated_at_ms       INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS dc_message_recipients (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    msg_id              INTEGER NOT NULL,
    recipient_addr      TEXT NOT NULL,
    local_retries       INTEGER NOT NULL DEFAULT 0,
    smtp_reply_code     INTEGER NOT NULL DEFAULT 0,
    error_detail        TEXT,
    error_category      INTEGER NOT NULL DEFAULT 0,
    permanently_failed  INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (msg_id) REFERENCES dc_message_status(msg_id)
);

CREATE TABLE IF NOT EXISTS dc_read_states (
    msg_id              INTEGER PRIMARY KEY,
    chat_id             INTEGER NOT NULL,
    read_at_unix        INTEGER NOT NULL,
    synced_to_server    INTEGER NOT NULL DEFAULT 0,
    synced_at_unix      INTEGER NOT NULL DEFAULT 0,
    synced_by_device    TEXT
);

CREATE TABLE IF NOT EXISTS dc_mdn_receipts (
    original_message_id TEXT PRIMARY KEY,
    msg_id              INTEGER,
    original_recipient  TEXT,
    final_recipient     TEXT,
    disposition         TEXT,
    disposition_mode    TEXT,
    disposition_type    TEXT,
    sending_mdn_agent   TEXT,
    received_at         INTEGER NOT NULL DEFAULT 0,
    displayed_at        INTEGER NOT NULL DEFAULT 0,
    raw_mdn_body        TEXT
);

CREATE TABLE IF NOT EXISTS dc_state_history (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    msg_id              INTEGER NOT NULL,
    from_state          INTEGER NOT NULL,
    to_state            INTEGER NOT NULL,
    transition_at       INTEGER NOT NULL,
    error_info          TEXT,
    FOREIGN KEY (msg_id) REFERENCES dc_message_status(msg_id)
);

CREATE TABLE IF NOT EXISTS dc_sync_journal (
    sync_serial         INTEGER PRIMARY KEY,
    msg_id              INTEGER NOT NULL,
    sync_type           TEXT NOT NULL,
    new_state           INTEGER NOT NULL,
    timestamp_ms        INTEGER NOT NULL,
    origin_device_id    TEXT,
    rfc724_mid          TEXT,
    chat_id             INTEGER NOT NULL DEFAULT 0,
    extra_json          TEXT,
    applied_at_ms       INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_dc_msg_status_chat
    ON dc_message_status(chat_id, state);
CREATE INDEX IF NOT EXISTS idx_dc_msg_status_active
    ON dc_message_status(active, next_attempt_ms);
CREATE INDEX IF NOT EXISTS idx_dc_recipients_msg
    ON dc_message_recipients(msg_id);
CREATE INDEX IF NOT EXISTS idx_dc_state_history_msg
    ON dc_state_history(msg_id, transition_at);
)SQL";

// ============================================================================
// In-memory SQL simulator for testing / zero-dependency use
// ============================================================================

class InMemoryStatusStore {
public:
    InMemoryStatusStore() = default;

    // -----------------------------------------------------------------------
    // Insert / Update status
    // -----------------------------------------------------------------------
    void upsert_status(const StatusPersistenceRecord& rec) {
        std::unique_lock lock(mutex_);
        status_table_[rec.msg_id] = rec;
    }

    std::optional<StatusPersistenceRecord> get_status(uint32_t msg_id) const {
        std::shared_lock lock(mutex_);
        auto it = status_table_.find(msg_id);
        if (it != status_table_.end()) return it->second;
        return std::nullopt;
    }

    void delete_status(uint32_t msg_id) {
        std::unique_lock lock(mutex_);
        status_table_.erase(msg_id);
    }

    // Query all messages in a given state
    std::vector<StatusPersistenceRecord> query_by_state(int state) const {
        std::shared_lock lock(mutex_);
        std::vector<StatusPersistenceRecord> result;
        for (const auto& [_, rec] : status_table_) {
            if (rec.state == state) result.push_back(rec);
        }
        return result;
    }

    // Query active retries
    std::vector<StatusPersistenceRecord> query_active_retries() const {
        std::shared_lock lock(mutex_);
        std::vector<StatusPersistenceRecord> result;
        for (const auto& [_, rec] : status_table_) {
            if (rec.state == MSG_STATE_OUT_PENDING ||
                (rec.state == MSG_STATE_OUT_FAILED &&
                 rec.retry_count < MAX_RETRY_COUNT)) {
                result.push_back(rec);
            }
        }
        return result;
    }

    // Query by chat
    std::vector<StatusPersistenceRecord> query_by_chat(int64_t chat_id) const {
        std::shared_lock lock(mutex_);
        std::vector<StatusPersistenceRecord> result;
        for (const auto& [_, rec] : status_table_) {
            if (rec.chat_id == chat_id) result.push_back(rec);
        }
        return result;
    }

    // Bulk load from the pipe-delimited format (same as file persistence)
    void load_from_text(const std::string& content) {
        std::unique_lock lock(mutex_);
        std::istringstream stream(content);
        std::string line;
        while (std::getline(stream, line)) {
            if (line.empty() || line[0] == '#') continue;
            std::vector<std::string> fields;
            std::stringstream ls(line);
            std::string field;
            while (std::getline(ls, field, '|')) fields.push_back(field);
            if (fields.size() < 8) continue;

            try {
                StatusPersistenceRecord rec;
                rec.msg_id            = static_cast<uint32_t>(std::stoul(fields[0]));
                rec.state             = std::stoi(fields[1]);
                rec.retry_count       = std::stoi(fields[2]);
                rec.last_attempt_ms   = std::stoll(fields[3]);
                rec.next_attempt_ms   = std::stoll(fields[4]);
                rec.created_at_ms     = std::stoll(fields[5]);
                rec.send_deadline_ms  = std::stoll(fields[6]);
                rec.error_category_int = std::stoi(fields[7]);
                if (fields.size() > 8)  rec.error_text = fields[8];
                if (fields.size() > 9)  rec.smtp_message_id = fields[9];
                if (fields.size() > 10) rec.chat_id = std::stoll(fields[10]);
                status_table_[rec.msg_id] = rec;
            } catch (...) {}
        }
    }

    std::string export_to_text() const {
        std::shared_lock lock(mutex_);
        std::stringstream ss;
        ss << "# InMemoryStatusStore export\n";
        ss << "# msg_id|state|retries|last_attempt|next_attempt|created|deadline|error_cat|error|msg_id|chat_id\n";
        for (const auto& [_, rec] : status_table_) {
            ss << rec.msg_id << "|"
               << rec.state << "|"
               << rec.retry_count << "|"
               << rec.last_attempt_ms << "|"
               << rec.next_attempt_ms << "|"
               << rec.created_at_ms << "|"
               << rec.send_deadline_ms << "|"
               << rec.error_category_int << "|"
               << rec.error_text << "|"
               << rec.smtp_message_id << "|"
               << rec.chat_id << "\n";
        }
        return ss.str();
    }

    int count() const {
        std::shared_lock lock(mutex_);
        return static_cast<int>(status_table_.size());
    }

    void clear() {
        std::unique_lock lock(mutex_);
        status_table_.clear();
    }

private:
    mutable std::shared_mutex mutex_;
    std::unordered_map<uint32_t, StatusPersistenceRecord> status_table_;
};

// ============================================================================
// Message Status Batch Processor — efficient bulk operations
// ============================================================================

class StatusBatchProcessor {
public:
    StatusBatchProcessor(MessageStatusManager& mgr) : mgr_(mgr) {}

    // Batch transition many messages at once
    struct BatchTransitionOp {
        uint32_t      msg_id;
        int           new_state;
        std::string   error;
        ErrorCategory error_cat = ErrorCategory::NONE;
    };

    struct BatchResult {
        int total;
        int succeeded;
        int failed;
        std::vector<uint32_t> failed_ids;
        std::string first_error;
    };

    BatchResult apply_transitions(
        const std::vector<BatchTransitionOp>& ops) {

        BatchResult result;
        result.total = static_cast<int>(ops.size());

        for (const auto& op : ops) {
            if (mgr_.set_state(op.msg_id, op.new_state, op.error, op.error_cat)) {
                result.succeeded++;
            } else {
                result.failed++;
                result.failed_ids.push_back(op.msg_id);
                if (result.first_error.empty()) {
                    result.first_error = "Failed transition for msg " +
                                         std::to_string(op.msg_id);
                }
            }
        }
        return result;
    }

    // Batch mark messages as read
    void mark_all_read(const std::vector<uint32_t>& msg_ids,
                       int64_t chat_id,
                       const std::string& device = "batch") {
        for (uint32_t mid : msg_ids) {
            mgr_.mark_message_read(mid, chat_id, device);
        }
    }

    // Batch delete tracking entries
    void delete_tracking(const std::vector<uint32_t>& msg_ids) {
        for (uint32_t mid : msg_ids) {
            mgr_.cancel_retries(mid);
        }
    }

    // Retry all permanently-failed-but-retryable messages in a chat
    int retry_chat_failures(int64_t chat_id) {
        int scheduled = 0;
        // We need to iterate the manager's internal state; use stats + retry
        // This is a best-effort operation
        for (uint32_t mid = 1; mid < 1000000; ++mid) {
            auto st_opt = mgr_.get_retry_state(mid);
            if (!st_opt.has_value()) continue;
            const auto& st = st_opt.value();
            if (st.chat_id == chat_id &&
                st.current_state == MSG_STATE_OUT_FAILED &&
                is_error_temporary(st.last_error_category) &&
                st.retry_count < MAX_RETRY_COUNT) {
                if (mgr_.schedule_retry(mid)) scheduled++;
            }
        }
        return scheduled;
    }

private:
    MessageStatusManager& mgr_;
};

// ============================================================================
// Network Connectivity Integration — adapt retry behaviour to network state
// ============================================================================

enum class NetworkState {
    DISCONNECTED,
    CONNECTING,
    CONNECTED,
    WORKING,
    METERED,           // On cellular / metered connection
    UNKNOWN
};

class ConnectivityAwareRetryController {
public:
    ConnectivityAwareRetryController(MessageStatusManager& mgr)
        : mgr_(mgr) {}

    void set_network_state(NetworkState state) {
        std::unique_lock lock(mutex_);
        NetworkState old = network_state_;
        network_state_ = state;

        if (state == NetworkState::CONNECTED ||
            state == NetworkState::WORKING) {
            // Network returned — notify retry system
            if (old == NetworkState::DISCONNECTED) {
                on_network_restored();
            }
        } else if (state == NetworkState::DISCONNECTED) {
            on_network_lost();
        }
    }

    NetworkState get_network_state() const {
        std::shared_lock lock(mutex_);
        return network_state_;
    }

    bool should_allow_retries() const {
        std::shared_lock lock(mutex_);
        return network_state_ == NetworkState::CONNECTED ||
               network_state_ == NetworkState::WORKING;
    }

private:
    void on_network_restored() {
        // Reset next_attempt times for messages that were failing
        // due to network errors, so they retry immediately
        int64_t now = now_ms();
        auto candidate = mgr_.get_next_retry_candidate();
        if (candidate.has_value()) {
            // The retry loop will pick it up naturally
            (void)now;
        }
    }

    void on_network_lost() {
        // Don't cancel retries — just let them fail naturally
        // with network errors, which are temporary
    }

    mutable std::shared_mutex mutex_;
    NetworkState network_state_ = NetworkState::UNKNOWN;
    MessageStatusManager& mgr_;
};

// ============================================================================
// Ephemeral (Disappearing) Message Status Tracking
// ============================================================================

struct EphemeralStatusEntry {
    uint32_t    msg_id;
    int64_t     chat_id;
    int64_t     ephemeral_timer_secs;     // Seconds until deletion
    int64_t     started_at_unix;           // When timer started
    int64_t     expires_at_unix;           // Absolute deletion time
    bool        timer_started = false;     // Has the recipient seen it?
    bool        deleted       = false;
};

class EphemeralMessageTracker {
public:
    EphemeralMessageTracker() = default;

    void register_ephemeral(uint32_t msg_id, int64_t chat_id,
                            int64_t timer_secs) {
        std::unique_lock lock(mutex_);
        EphemeralStatusEntry entry;
        entry.msg_id              = msg_id;
        entry.chat_id             = chat_id;
        entry.ephemeral_timer_secs = timer_secs;
        entry.started_at_unix     = now_unix();
        entry.expires_at_unix     = entry.started_at_unix + timer_secs;
        entries_[msg_id] = entry;
    }

    void start_timer(uint32_t msg_id) {
        std::unique_lock lock(mutex_);
        auto it = entries_.find(msg_id);
        if (it != entries_.end() && !it->second.timer_started) {
            it->second.timer_started = true;
            it->second.started_at_unix = now_unix();
            it->second.expires_at_unix =
                it->second.started_at_unix + it->second.ephemeral_timer_secs;
        }
    }

    bool is_expired(uint32_t msg_id) const {
        std::shared_lock lock(mutex_);
        auto it = entries_.find(msg_id);
        if (it != entries_.end() && it->second.timer_started) {
            return now_unix() >= it->second.expires_at_unix;
        }
        return false;
    }

    int64_t seconds_until_expiry(uint32_t msg_id) const {
        std::shared_lock lock(mutex_);
        auto it = entries_.find(msg_id);
        if (it != entries_.end() && it->second.timer_started) {
            int64_t remaining = it->second.expires_at_unix - now_unix();
            return remaining > 0 ? remaining : 0;
        }
        return -1; // Not started or not ephemeral
    }

    std::vector<uint32_t> get_expired_messages() {
        std::unique_lock lock(mutex_);
        std::vector<uint32_t> expired;
        time_t now = now_unix();
        for (const auto& [mid, entry] : entries_) {
            if (entry.timer_started && !entry.deleted &&
                now >= entry.expires_at_unix) {
                expired.push_back(mid);
            }
        }
        return expired;
    }

    void mark_deleted(uint32_t msg_id) {
        std::unique_lock lock(mutex_);
        auto it = entries_.find(msg_id);
        if (it != entries_.end()) {
            it->second.deleted = true;
        }
    }

    void remove(uint32_t msg_id) {
        std::unique_lock lock(mutex_);
        entries_.erase(msg_id);
    }

    int get_chat_ephemeral_count(int64_t chat_id) const {
        std::shared_lock lock(mutex_);
        int count = 0;
        for (const auto& [_, entry] : entries_) {
            if (entry.chat_id == chat_id && !entry.deleted) count++;
        }
        return count;
    }

    std::string format_expiry_info(uint32_t msg_id) const {
        int64_t secs = seconds_until_expiry(msg_id);
        if (secs < 0) return "";
        if (secs == 0) return "Expired";
        if (secs < 60)  return std::to_string(secs) + "s";
        if (secs < 3600) return std::to_string(secs/60) + "m";
        if (secs < 86400) return std::to_string(secs/3600) + "h";
        return std::to_string(secs/86400) + "d";
    }

private:
    mutable std::shared_mutex mutex_;
    std::unordered_map<uint32_t, EphemeralStatusEntry> entries_;
};

// Singleton
static std::unique_ptr<EphemeralMessageTracker> g_ephemeral_tracker;
static std::mutex g_ephemeral_mutex;

EphemeralMessageTracker& ephemeral_tracker() {
    std::lock_guard<std::mutex> lock(g_ephemeral_mutex);
    if (!g_ephemeral_tracker) {
        g_ephemeral_tracker = std::make_unique<EphemeralMessageTracker>();
    }
    return *g_ephemeral_tracker;
}

// ============================================================================
// Delivery Confirmation Summary — for chat overview UI
// ============================================================================

struct DeliveryConfirmationSummary {
    int64_t     chat_id;
    int         total_outgoing;
    int         delivered;
    int         read;
    int         pending;
    int         failed;
    int         unread_incoming;
    time_t      last_activity;
    std::string summary_text;
};

DeliveryConfirmationSummary compute_delivery_summary(int64_t chat_id) {
    DeliveryConfirmationSummary sum;
    sum.chat_id = chat_id;

    // Gather stats from status manager
    auto stats = status_manager().get_stats();
    (void)stats; // Global stats; we need per-chat below

    // Iterate known msg IDs (simplified; in production you'd query by chat)
    for (uint32_t mid = 1; mid < 100000; ++mid) {
        auto st_opt = status_manager().get_retry_state(mid);
        if (!st_opt.has_value()) continue;
        const auto& st = st_opt.value();
        if (st.chat_id != chat_id) continue;

        sum.total_outgoing++;
        switch (st.current_state) {
            case MSG_STATE_OUT_PENDING:   sum.pending++; break;
            case MSG_STATE_OUT_DELIVERED: sum.delivered++; break;
            case MSG_STATE_OUT_MDN_RCVD:  sum.read++; break;
            case MSG_STATE_OUT_FAILED:    sum.failed++; break;
            default: break;
        }

        time_t msg_time = static_cast<time_t>(st.last_attempt_ms / 1000);
        if (msg_time > sum.last_activity) {
            sum.last_activity = msg_time;
        }
    }

    // Build summary text
    std::stringstream ss;
    ss << sum.delivered << " delivered";
    if (sum.read > 0) ss << ", " << sum.read << " read";
    if (sum.pending > 0) ss << ", " << sum.pending << " sending";
    if (sum.failed > 0) ss << ", " << sum.failed << " failed";
    if (sum.total_outgoing == 0) ss << "No outgoing messages";
    sum.summary_text = ss.str();

    return sum;
}

// ============================================================================
// Status Dashboard — full diagnostic view
// ============================================================================

struct StatusDashboard {
    // Per-state counts
    int total_tracked;
    int out_preparing;
    int out_draft;
    int out_pending;
    int out_delivered;
    int out_mdn;
    int out_failed;
    int in_fresh;
    int in_noticed;
    int in_seen;

    // Retry info
    int active_retries;
    int max_retries_exhausted;
    int64_t next_retry_in_ms;

    // Error breakdown
    int errors_temp_smtp;
    int errors_perm_smtp;
    int errors_temp_imap;
    int errors_perm_imap;
    int errors_encryption;
    int errors_network;
    int errors_config;
    int errors_timeout;
    int errors_unknown;

    // Persistence
    std::string persistence_path;
    bool persistence_ok;

    // Timestamps
    int64_t last_persist_ms;
    int64_t last_sync_ms;

    // UI rendering helpers
    std::string render_ascii() const {
        std::stringstream ss;
        ss << "═══════════════════════════════════════════\n";
        ss << "    DeltaChat Status Dashboard\n";
        ss << "═══════════════════════════════════════════\n\n";
        ss << "  OUTGOING MESSAGES\n";
        ss << "    Preparing : " << out_preparing << "\n";
        ss << "    Draft     : " << out_draft << "\n";
        ss << "    Pending   : " << out_pending << "\n";
        ss << "    Delivered : " << out_delivered << "\n";
        ss << "    Read      : " << out_mdn << "\n";
        ss << "    Failed    : " << out_failed << "\n\n";
        ss << "  INCOMING MESSAGES\n";
        ss << "    Fresh     : " << in_fresh << "\n";
        ss << "    Noticed   : " << in_noticed << "\n";
        ss << "    Seen      : " << in_seen << "\n\n";
        ss << "  RETRY STATUS\n";
        ss << "    Active    : " << active_retries << "\n";
        ss << "    Exhausted : " << max_retries_exhausted << "\n";
        if (next_retry_in_ms > 0) {
            ss << "    Next retry: " << (next_retry_in_ms / 1000) << "s\n";
        }
        ss << "\n  ERROR BREAKDOWN\n";
        ss << "    Temp SMTP  : " << errors_temp_smtp << "\n";
        ss << "    Perm SMTP  : " << errors_perm_smtp << "\n";
        ss << "    Temp IMAP  : " << errors_temp_imap << "\n";
        ss << "    Perm IMAP  : " << errors_perm_imap << "\n";
        ss << "    Encryption : " << errors_encryption << "\n";
        ss << "    Network    : " << errors_network << "\n";
        ss << "    Config     : " << errors_config << "\n";
        ss << "    Timeout    : " << errors_timeout << "\n";
        ss << "    Unknown    : " << errors_unknown << "\n";
        ss << "\n  PERSISTENCE\n";
        ss << "    Path       : " << persistence_path << "\n";
        ss << "    Status     : " << (persistence_ok ? "OK" : "FAIL") << "\n";
        ss << "═══════════════════════════════════════════\n";
        return ss.str();
    }
};

StatusDashboard compute_dashboard() {
    StatusDashboard db = {};

    auto stats = status_manager().get_stats();
    db.total_tracked   = stats.total_tracked;
    db.out_pending     = stats.out_pending;
    db.out_delivered   = stats.out_delivered;
    db.out_mdn         = stats.out_mdn_rcvd;
    db.out_failed      = stats.out_failed;
    db.in_fresh        = stats.in_fresh;
    db.in_noticed      = stats.in_noticed;
    db.in_seen         = stats.in_seen;
    db.active_retries  = stats.active_retries;

    // Walk all known states for detailed error breakdown
    for (uint32_t mid = 1; mid < 100000; ++mid) {
        auto st_opt = status_manager().get_retry_state(mid);
        if (!st_opt.has_value()) continue;
        const auto& st = st_opt.value();

        switch (st.last_error_category) {
            case ErrorCategory::TEMPORARY_SMTP:      db.errors_temp_smtp++; break;
            case ErrorCategory::PERMANENT_SMTP:      db.errors_perm_smtp++; break;
            case ErrorCategory::TEMPORARY_IMAP:      db.errors_temp_imap++; break;
            case ErrorCategory::PERMANENT_IMAP:      db.errors_perm_imap++; break;
            case ErrorCategory::ENCRYPTION_ERROR:    db.errors_encryption++; break;
            case ErrorCategory::NETWORK_ERROR:       db.errors_network++; break;
            case ErrorCategory::CONFIGURATION_ERROR: db.errors_config++; break;
            case ErrorCategory::TIMEOUT_ERROR:       db.errors_timeout++; break;
            case ErrorCategory::UNKNOWN_ERROR:       db.errors_unknown++; break;
            default: break;
        }

        if (st.retry_count >= MAX_RETRY_COUNT &&
            st.current_state == MSG_STATE_OUT_FAILED) {
            db.max_retries_exhausted++;
        }
    }

    return db;
}

// ============================================================================
// Message Status Event Bus — pub/sub for status changes
// ============================================================================

class StatusEventBus {
public:
    using StatusListener = std::function<void(uint32_t msg_id, int old_state,
                                               int new_state, const std::string& detail)>;

    // Register a listener; returns a handle for unregistration
    int subscribe(StatusListener listener) {
        std::unique_lock lock(mutex_);
        int id = next_listener_id_++;
        listeners_[id] = std::move(listener);
        return id;
    }

    void unsubscribe(int listener_id) {
        std::unique_lock lock(mutex_);
        listeners_.erase(listener_id);
    }

    void publish(uint32_t msg_id, int old_state, int new_state,
                 const std::string& detail = "") {
        std::shared_lock lock(mutex_);
        for (const auto& [id, listener] : listeners_) {
            if (listener) {
                listener(msg_id, old_state, new_state, detail);
            }
        }
    }

    int listener_count() const {
        std::shared_lock lock(mutex_);
        return static_cast<int>(listeners_.size());
    }

    void clear() {
        std::unique_lock lock(mutex_);
        listeners_.clear();
    }

private:
    mutable std::shared_mutex mutex_;
    std::unordered_map<int, StatusListener> listeners_;
    int next_listener_id_ = 1;
};

// Global event bus singleton
static std::unique_ptr<StatusEventBus> g_event_bus;
static std::mutex g_event_bus_mutex;

StatusEventBus& status_event_bus() {
    std::lock_guard<std::mutex> lock(g_event_bus_mutex);
    if (!g_event_bus) {
        g_event_bus = std::make_unique<StatusEventBus>();
    }
    return *g_event_bus;
}

// ============================================================================
// Status filtering and searching
// ============================================================================

struct StatusFilter {
    std::optional<int>           required_state;
    std::optional<ErrorCategory> required_error_category;
    std::optional<int64_t>       chat_id;
    std::optional<int64_t>       older_than_ms;
    std::optional<int64_t>       newer_than_ms;
    std::optional<int>           min_retry_count;
    std::optional<bool>          has_read_receipt;
    std::optional<bool>          is_encrypted;
    int                          max_results = 100;
};

std::vector<uint32_t> filter_messages_by_status(const StatusFilter& filter) {
    std::vector<uint32_t> results;
    int64_t now = now_ms();

    for (uint32_t mid = 1; mid < 100000 && static_cast<int>(results.size()) < filter.max_results; ++mid) {
        auto st_opt = status_manager().get_retry_state(mid);
        if (!st_opt.has_value()) continue;
        const auto& st = st_opt.value();

        if (filter.required_state.has_value() &&
            st.current_state != filter.required_state.value()) continue;

        if (filter.required_error_category.has_value() &&
            st.last_error_category != filter.required_error_category.value()) continue;

        if (filter.chat_id.has_value() &&
            st.chat_id != filter.chat_id.value()) continue;

        if (filter.older_than_ms.has_value()) {
            if (st.last_attempt_ms > now - filter.older_than_ms.value()) continue;
        }

        if (filter.newer_than_ms.has_value()) {
            if (st.last_attempt_ms < now - filter.newer_than_ms.value()) continue;
        }

        if (filter.min_retry_count.has_value() &&
            st.retry_count < filter.min_retry_count.value()) continue;

        if (filter.has_read_receipt.has_value()) {
            bool has_mdn = status_manager().has_mdn_receipt(mid);
            if (has_mdn != filter.has_read_receipt.value()) continue;
        }

        results.push_back(mid);
    }

    return results;
}

// ============================================================================
// Auto-retry scheduling integration — hooks into the send pipeline
// ============================================================================

struct AutoRetryConfig {
    bool     enabled              = true;
    int      max_auto_retries     = MAX_RETRY_COUNT;
    int      base_backoff_ms      = BASE_RETRY_BACKOFF_MS;
    int      max_backoff_ms       = MAX_RETRY_BACKOFF_MS;
    int      backoff_multiplier   = RETRY_BACKOFF_MULTIPLIER;
    int      jitter_pct           = RETRY_JITTER_PCT;
    int64_t  send_timeout_ms      = SEND_TIMEOUT_MS;
    bool     retry_on_network_error = true;
    bool     retry_on_timeout     = true;
    bool     retry_on_temp_smtp   = true;
    bool     retry_on_temp_imap   = true;
};

class AutoRetryScheduler {
public:
    AutoRetryScheduler() = default;

    void configure(const AutoRetryConfig& cfg) {
        std::unique_lock lock(mutex_);
        config_ = cfg;
    }

    AutoRetryConfig get_config() const {
        std::shared_lock lock(mutex_);
        return config_;
    }

    // Called by the send pipeline after a send attempt
    void on_send_result(uint32_t msg_id, bool success,
                        const std::string& error_text) {
        if (success) {
            status_manager().finish_retry_attempt(msg_id, true);
            return;
        }

        ErrorCategory cat = MessageStatusManager::categorize_error(error_text);
        AutoRetryConfig cfg = get_config();

        if (!cfg.enabled) {
            status_manager().finish_retry_attempt(msg_id, false, error_text);
            return;
        }

        bool should_retry = false;
        switch (cat) {
            case ErrorCategory::TEMPORARY_SMTP:
                should_retry = cfg.retry_on_temp_smtp;
                break;
            case ErrorCategory::TEMPORARY_IMAP:
                should_retry = cfg.retry_on_temp_imap;
                break;
            case ErrorCategory::NETWORK_ERROR:
                should_retry = cfg.retry_on_network_error;
                break;
            case ErrorCategory::TIMEOUT_ERROR:
                should_retry = cfg.retry_on_timeout;
                break;
            default:
                should_retry = false;
                break;
        }

        if (should_retry) {
            auto st_opt = status_manager().get_retry_state(msg_id);
            if (st_opt.has_value() && st_opt.value().retry_count < cfg.max_auto_retries) {
                status_manager().finish_retry_attempt(msg_id, false, error_text);
                return;
            }
        }

        // No more retries — final failure
        status_manager().finish_retry_attempt(msg_id, false, error_text);
    }

    // Process pending retries (call from send pipeline worker)
    std::optional<uint32_t> dequeue_next_retry() {
        return status_manager().get_next_retry_candidate();
    }

private:
    mutable std::shared_mutex mutex_;
    AutoRetryConfig config_;
};

// ============================================================================
// Status change audit log — for debugging / support
// ============================================================================

class StatusAuditLog {
public:
    static constexpr int MAX_ENTRIES = 5000;

    struct AuditEntry {
        int64_t   sequence;
        uint32_t  msg_id;
        int       from_state;
        int       to_state;
        int64_t   timestamp_ms;
        std::string error;
        std::string source;       // "user", "auto_retry", "sync", "mdn", "dsn"
    };

    void record(uint32_t msg_id, int from, int to, const std::string& error,
                const std::string& source = "system") {
        std::unique_lock lock(mutex_);
        AuditEntry entry;
        entry.sequence     = ++sequence_counter_;
        entry.msg_id       = msg_id;
        entry.from_state   = from;
        entry.to_state     = to;
        entry.timestamp_ms = now_ms();
        entry.error        = error;
        entry.source       = source;

        log_.push_back(entry);

        // Maintain circular buffer
        while (static_cast<int>(log_.size()) > MAX_ENTRIES) {
            log_.pop_front();
        }
    }

    std::vector<AuditEntry> get_recent(int limit = 100) const {
        std::shared_lock lock(mutex_);
        std::vector<AuditEntry> result;
        int start = std::max(0, static_cast<int>(log_.size()) - limit);
        for (int i = start; i < static_cast<int>(log_.size()); ++i) {
            result.push_back(log_[i]);
        }
        return result;
    }

    std::vector<AuditEntry> get_for_message(uint32_t msg_id) const {
        std::shared_lock lock(mutex_);
        std::vector<AuditEntry> result;
        for (const auto& entry : log_) {
            if (entry.msg_id == msg_id) {
                result.push_back(entry);
            }
        }
        return result;
    }

    std::string render_recent(int limit = 20) const {
        auto entries = get_recent(limit);
        std::stringstream ss;
        ss << "=== Status Change Audit Log (last " << entries.size() << ") ===\n";
        for (const auto& e : entries) {
            ss << "[" << e.sequence << "] msg=" << e.msg_id
               << " " << state_label(e.from_state)
               << " → " << state_label(e.to_state)
               << " src=" << e.source;
            if (!e.error.empty()) {
                std::string short_err = e.error.substr(0, 60);
                ss << " err=\"" << short_err;
                if (e.error.size() > 60) ss << "...";
                ss << "\"";
            }
            ss << "\n";
        }
        return ss.str();
    }

    void clear() {
        std::unique_lock lock(mutex_);
        log_.clear();
        sequence_counter_ = 0;
    }

private:
    mutable std::shared_mutex mutex_;
    std::deque<AuditEntry> log_;
    int64_t sequence_counter_ = 0;
};

// Global audit log
static std::unique_ptr<StatusAuditLog> g_audit_log;
static std::mutex g_audit_mutex;

StatusAuditLog& status_audit_log() {
    std::lock_guard<std::mutex> lock(g_audit_mutex);
    if (!g_audit_log) {
        g_audit_log = std::make_unique<StatusAuditLog>();
    }
    return *g_audit_log;
}

// ============================================================================
// Status Export / Import — for debugging and migration
// ============================================================================

struct StatusExportData {
    int64_t export_timestamp_ms;
    int version = 1;
    std::vector<StatusPersistenceRecord> records;
    std::unordered_map<uint32_t, ReadStateEntry> read_states;
    std::vector<StatusAuditLog::AuditEntry> audit_entries;
};

StatusExportData export_all_status() {
    StatusExportData data;
    data.export_timestamp_ms = now_ms();

    // Walk all known message IDs and export their persistence records
    for (uint32_t mid = 1; mid < 100000; ++mid) {
        auto st_opt = status_manager().get_retry_state(mid);
        if (!st_opt.has_value()) continue;
        const auto& st = st_opt.value();

        StatusPersistenceRecord rec;
        rec.msg_id = st.msg_id;
        rec.state = st.current_state;
        rec.retry_count = st.retry_count;
        rec.last_attempt_ms = st.last_attempt_ms;
        rec.next_attempt_ms = st.next_attempt_ms;
        rec.created_at_ms = st.created_at_ms;
        rec.send_deadline_ms = st.send_deadline_ms;
        rec.error_category_int = static_cast<int>(st.last_error_category);
        rec.error_text = st.last_error_text;
        rec.smtp_message_id = st.smtp_message_id;
        rec.chat_id = st.chat_id;
        data.records.push_back(rec);

        // Gather read state
        if (status_manager().is_message_read(mid)) {
            ReadStateEntry rse;
            rse.msg_id = mid;
            rse.chat_id = st.chat_id;
            rse.read_at_unix = status_manager().get_read_timestamp(mid);
            data.read_states[mid] = rse;
        }
    }

    // Gather audit log
    data.audit_entries = status_audit_log().get_recent(5000);

    return data;
}

std::string export_to_json(const StatusExportData& data) {
    std::stringstream ss;
    ss << "{\n";
    ss << "  \"version\": " << data.version << ",\n";
    ss << "  \"export_timestamp_ms\": " << data.export_timestamp_ms << ",\n";
    ss << "  \"status_records\": [\n";

    for (size_t i = 0; i < data.records.size(); ++i) {
        const auto& rec = data.records[i];
        ss << "    {"
           << "\"msg_id\": " << rec.msg_id
           << ", \"state\": " << rec.state
           << ", \"retry_count\": " << rec.retry_count
           << ", \"error_category\": " << rec.error_category_int;
        if (!rec.error_text.empty()) {
            ss << ", \"error\": \"" << rec.error_text << "\"";
        }
        ss << "}";
        if (i < data.records.size() - 1) ss << ",";
        ss << "\n";
    }

    ss << "  ],\n";
    ss << "  \"read_state_count\": " << data.read_states.size() << ",\n";
    ss << "  \"audit_entry_count\": " << data.audit_entries.size() << "\n";
    ss << "}\n";
    return ss.str();
}

// ============================================================================
// Status verification and integrity checks
// ============================================================================

struct StatusIntegrityReport {
    int total_checked;
    int inconsistencies;
    std::vector<std::string> issues;
};

StatusIntegrityReport verify_status_integrity() {
    StatusIntegrityReport report;

    for (uint32_t mid = 1; mid < 100000; ++mid) {
        auto st_opt = status_manager().get_retry_state(mid);
        if (!st_opt.has_value()) continue;

        report.total_checked++;
        const auto& st = st_opt.value();

        // Check 1: active messages should be pending or failed
        if (st.active) {
            if (st.current_state != MSG_STATE_OUT_PENDING &&
                st.current_state != MSG_STATE_OUT_FAILED) {
                report.inconsistencies++;
                report.issues.push_back(
                    "msg " + std::to_string(mid) +
                    ": active but state=" + std::string(state_label(st.current_state)));
            }
        }

        // Check 2: in_flight implies active
        if (st.in_flight && !st.active) {
            report.inconsistencies++;
            report.issues.push_back(
                "msg " + std::to_string(mid) + ": in_flight but not active");
        }

        // Check 3: retry count sanity
        if (st.retry_count < 0) {
            report.inconsistencies++;
            report.issues.push_back(
                "msg " + std::to_string(mid) + ": negative retry count");
        }

        // Check 4: MDN received but state not updated
        if (status_manager().has_mdn_receipt(mid) &&
            st.current_state != MSG_STATE_OUT_MDN_RCVD) {
            report.inconsistencies++;
            report.issues.push_back(
                "msg " + std::to_string(mid) +
                ": MDN received but state is " +
                std::string(state_label(st.current_state)));
        }
    }

    return report;
}

// ============================================================================
// Status recovery — attempt to repair inconsistent states
// ============================================================================

void repair_status_inconsistencies() {
    auto report = verify_status_integrity();
    if (report.inconsistencies == 0) return;

    for (uint32_t mid = 1; mid < 100000; ++mid) {
        auto st_opt = status_manager().get_retry_state(mid);
        if (!st_opt.has_value()) continue;
        const auto& st = st_opt.value();

        // Fix MDN state mismatch
        if (status_manager().has_mdn_receipt(mid) &&
            st.current_state == MSG_STATE_OUT_DELIVERED) {
            status_manager().mark_mdn_received(mid);
        }

        // Cancel in_flight that has been stuck too long
        if (st.in_flight) {
            int64_t stuck_ms = now_ms() - st.in_flight_since_ms;
            if (stuck_ms > SEND_TIMEOUT_MS * 3) {
                status_manager().cancel_retries(mid);
                status_manager().mark_failed(mid,
                    "Send stuck — automatically cancelled",
                    ErrorCategory::TIMEOUT_ERROR);
            }
        }

        // Reset negative retry counts
        if (st.retry_count < 0) {
            status_manager().cancel_retries(mid);
            status_manager().mark_failed(mid,
                "Invalid retry state — reset",
                ErrorCategory::UNKNOWN_ERROR);
        }
    }
}

// ============================================================================
// Public API wrappers for all new classes
// ============================================================================

void ephemeral_register(uint32_t msg_id, int64_t chat_id, int64_t timer_secs) {
    ephemeral_tracker().register_ephemeral(msg_id, chat_id, timer_secs);
}

void ephemeral_start_timer(uint32_t msg_id) {
    ephemeral_tracker().start_timer(msg_id);
}

bool ephemeral_is_expired(uint32_t msg_id) {
    return ephemeral_tracker().is_expired(msg_id);
}

int64_t ephemeral_seconds_until_expiry(uint32_t msg_id) {
    return ephemeral_tracker().seconds_until_expiry(msg_id);
}

std::vector<uint32_t> ephemeral_get_expired() {
    return ephemeral_tracker().get_expired_messages();
}

void ephemeral_mark_deleted(uint32_t msg_id) {
    ephemeral_tracker().mark_deleted(msg_id);
}

std::string ephemeral_format_expiry(uint32_t msg_id) {
    return ephemeral_tracker().format_expiry_info(msg_id);
}

DeliveryConfirmationSummary delivery_summary(int64_t chat_id) {
    return compute_delivery_summary(chat_id);
}

StatusDashboard status_dashboard() {
    return compute_dashboard();
}

std::string status_dashboard_render() {
    return compute_dashboard().render_ascii();
}

int status_event_subscribe(StatusEventBus::StatusListener listener) {
    return status_event_bus().subscribe(std::move(listener));
}

void status_event_unsubscribe(int listener_id) {
    status_event_bus().unsubscribe(listener_id);
}

void status_event_publish(uint32_t msg_id, int old_state, int new_state,
                          const std::string& detail) {
    status_event_bus().publish(msg_id, old_state, new_state, detail);
}

void audit_log_record(uint32_t msg_id, int from, int to,
                      const std::string& error, const std::string& source) {
    status_audit_log().record(msg_id, from, to, error, source);
}

std::string audit_log_render(int limit) {
    return status_audit_log().render_recent(limit);
}

std::vector<uint32_t> status_filter(const StatusFilter& filter) {
    return filter_messages_by_status(filter);
}

StatusExportData status_export_all() {
    return export_all_status();
}

std::string status_export_json() {
    return export_to_json(export_all_status());
}

StatusIntegrityReport status_verify() {
    return verify_status_integrity();
}

void status_repair() {
    repair_status_inconsistencies();
}

} // namespace deltachat
} // namespace progressive
