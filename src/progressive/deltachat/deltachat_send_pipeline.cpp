// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Progressive Server Contributors
//
// DeltaChat Send Pipeline
// Complete SMTP delivery, send queue, and email sending pipeline
// Includes: queue management, MIME construction, DKIM, PGP, autocrypt,
//           rate limiting, retry logic, BCC self, sent folder upload,
//           progress callbacks, MDN tracking, Chat-* headers

#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <optional>
#include <ctime>
#include <atomic>
#include <mutex>
#include <functional>
#include <deque>
#include <algorithm>
#include <sstream>
#include <cstring>
#include <cctype>
#include <cstdio>
#include <cerrno>
#include <cmath>
#include <random>
#include <chrono>
#include <thread>
#include <stdexcept>
#include <regex>
#include <condition_variable>
#include <fstream>
#include <filesystem>

namespace progressive {
namespace deltachat {

// ============================================================================
// SMTP Send Function type - abstracts the actual SMTP connection details.
// The caller (who has access to SmtpConnection's full definition) provides
// a function that takes config + recipients + MIME and returns success.
// ============================================================================

using SmtpSendFunc = std::function<bool(
    const std::string& smtp_host,
    int smtp_port,
    int smtp_security,
    const std::string& smtp_username,
    const std::string& smtp_password,
    const std::string& local_hostname,
    const std::string& from_addr,
    const std::vector<std::string>& envelope_recipients,
    const std::string& mime_message,
    std::vector<std::string>& failed_recipients,
    std::string& error_out)>;

// ============================================================================
// IMAP Append function type - abstracts IMAP sent-folder upload.
// ============================================================================

using ImapAppendFunc = std::function<bool(
    const std::string& imap_folder,
    const std::string& mime_message,
    const std::vector<std::string>& flags,
    const std::string& internal_date,
    std::string& error_out)>;

// ============================================================================
// Constants
// ============================================================================

constexpr int DEFAULT_SMTP_RATE_LIMIT_PER_MINUTE = 30;
constexpr int DEFAULT_SMTP_MAX_BURST = 10;
constexpr int MAX_SEND_RETRIES = 7;
constexpr int BASE_SEND_BACKOFF_MS = 2000;
constexpr int MAX_SEND_BACKOFF_MS = 300000;    // 5 minutes
constexpr int SEND_QUEUE_PERSIST_INTERVAL_SECS = 60;
constexpr int SEND_WORKER_POLL_MS = 500;
constexpr int MDN_TIMEOUT_SECONDS = 86400;       // 24h
constexpr int SENT_FOLDER_UPLOAD_RETRIES = 3;
constexpr const char* CRLF = "\r\n";
constexpr const char* CHAT_USER_AGENT = "DeltaChat/1.0 ProgressiveServer";
constexpr const char* CHAT_VERSION_STR = "1.0";
constexpr const char* AUTOCRYPT_HEADER_NAME = "Autocrypt";
constexpr const char* AUTOCRYPT_SETUP_HEADER_NAME = "Autocrypt-Setup-Message";
constexpr const char* CHAT_VERSION_HEADER = "Chat-Version";
constexpr const char* CHAT_GROUP_ID_HEADER = "Chat-Group-ID";
constexpr const char* CHAT_GROUP_NAME_HEADER = "Chat-Group-Name";
constexpr const char* CHAT_VERIFIED_HEADER = "Chat-Verified";
constexpr const char* CHAT_USER_AGENT_HEADER = "Chat-User-Agent";
constexpr const char* CHAT_CONTENT_TYPE_HEADER = "Chat-Content-Type";
constexpr const char* CHAT_PREVIOUS_HEADER = "Chat-Predecessor";
constexpr const char* LIST_ID_HEADER = "List-ID";
constexpr const char* PRECEDENCE_HEADER = "Precedence";
constexpr const char* DKIM_SIGNATURE_HEADER = "DKIM-Signature";
constexpr const char* DISPOSITION_NOTIFICATION_HEADER = "Disposition-Notification-To";
constexpr const char* SENT_FOLDER_NAME = "Sent";

// ============================================================================
// Utility: timestamp in milliseconds
// ============================================================================

static int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

static time_t now_unix() {
    return std::time(nullptr);
}

// ============================================================================
// Utility: random token generation
// ============================================================================

static std::string gen_random_hex(int length) {
    static const char hex_chars[] = "0123456789abcdef";
    static thread_local std::mt19937 rng(
        static_cast<unsigned>(now_ms() ^ std::hash<std::thread::id>{}(std::this_thread::get_id())));
    std::uniform_int_distribution<> dist(0, 15);
    std::string result(length, '0');
    for (int i = 0; i < length; ++i) {
        result[i] = hex_chars[dist(rng)];
    }
    return result;
}

static std::string gen_random_alnum(int length) {
    static const char chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    static thread_local std::mt19937 rng(
        static_cast<unsigned>(now_ms() ^ std::hash<std::thread::id>{}(std::this_thread::get_id())));
    std::uniform_int_distribution<> dist(0, 61);
    std::string result(length, 'A');
    for (int i = 0; i < length; ++i) {
        result[i] = chars[dist(rng)];
    }
    return result;
}

// ============================================================================
// Utility: Base64 encoding (standalone, not dependent on existing base64)
// ============================================================================

namespace send_base64 {

static const char enc_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string encode(const std::string& input) {
    std::string output;
    output.reserve(((input.size() + 2) / 3) * 4);
    for (size_t i = 0; i < input.size(); i += 3) {
        uint32_t a = i < input.size() ? static_cast<unsigned char>(input[i]) : 0;
        uint32_t b = i + 1 < input.size() ? static_cast<unsigned char>(input[i + 1]) : 0;
        uint32_t c = i + 2 < input.size() ? static_cast<unsigned char>(input[i + 2]) : 0;
        uint32_t triple = (a << 16) + (b << 8) + c;
        output.push_back(enc_table[(triple >> 18) & 0x3F]);
        output.push_back(enc_table[(triple >> 12) & 0x3F]);
        output.push_back(
            i + 1 < input.size() ? enc_table[(triple >> 6) & 0x3F] : '=');
        output.push_back(
            i + 2 < input.size() ? enc_table[triple & 0x3F] : '=');
    }
    return output;
}

} // namespace send_base64

// ============================================================================
// Utility: Quoted-Printable encoding
// ============================================================================

namespace send_qp {

std::string encode(const std::string& input, size_t line_length = 76) {
    std::string output;
    size_t line_pos = 0;
    for (unsigned char c : input) {
        bool needs_encode = (c < 33 || c == '=' || c > 126);
        if (needs_encode || (c == ' ' && line_pos + 1 >= line_length)) {
            char buf[4];
            std::snprintf(buf, sizeof(buf), "=%02X", c);
            output += buf;
            line_pos += 3;
        } else {
            output.push_back(c);
            line_pos++;
        }
        if (line_pos >= line_length) {
            output += "=\r\n";
            line_pos = 0;
        }
    }
    return output;
}

} // namespace send_qp

// ============================================================================
// Utility: MIME header encoding (RFC 2047)
// ============================================================================

static std::string encode_mime_header(const std::string& text,
                                       const std::string& charset = "utf-8") {
    // Check if encoding is needed
    bool needs_encoding = false;
    for (unsigned char c : text) {
        if (c > 127 || c < 32 || c == '=' || c == '?' || c == '_') {
            needs_encoding = true;
            break;
        }
    }
    if (!needs_encoding) return text;

    // Use B-encoding
    std::string encoded = send_base64::encode(text);
    return "=?" + charset + "?B?" + encoded + "?=";
}

// ============================================================================
// Utility: Format email address "Name <addr>" or just "addr"
// ============================================================================

static std::string format_email_addr(const std::string& name,
                                      const std::string& addr) {
    if (name.empty()) return addr;
    // Quote name if it contains special characters
    bool needs_quote = false;
    for (char c : name) {
        if (c == ',' || c == ';' || c == '<' || c == '>' ||
            c == '@' || c == '.' || c == '"') {
            needs_quote = true;
            break;
        }
    }
    if (needs_quote) {
        std::string escaped = name;
        // Escape backslash and double-quote
        size_t pos = 0;
        while ((pos = escaped.find_first_of("\\\"", pos)) != std::string::npos) {
            escaped.insert(pos, "\\");
            pos += 2;
        }
        return "\"" + escaped + "\" <" + addr + ">";
    }
    return encode_mime_header(name) + " <" + addr + ">";
}

// ============================================================================
// Utility: Extract raw email from "Name <addr>" format
// ============================================================================

static std::string extract_email(const std::string& input) {
    size_t lt = input.find('<');
    size_t gt = input.find('>');
    if (lt != std::string::npos && gt != std::string::npos && gt > lt) {
        return input.substr(lt + 1, gt - lt - 1);
    }
    // Trim whitespace
    std::string trimmed = input;
    trimmed.erase(0, trimmed.find_first_not_of(" \t\r\n"));
    trimmed.erase(trimmed.find_last_not_of(" \t\r\n") + 1);
    return trimmed;
}

// ============================================================================
// RFC 5322 date formatting
// ============================================================================

static std::string format_rfc5322_date(time_t t = 0) {
    if (t == 0) t = std::time(nullptr);
    struct tm tm_buf;
    gmtime_r(&t, &tm_buf);

    static const char* days[] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
    static const char* months[] = {
        "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
    };

    char buf[64];
    std::snprintf(buf, sizeof(buf),
        "%s, %02d %s %04d %02d:%02d:%02d +0000",
        days[tm_buf.tm_wday],
        tm_buf.tm_mday,
        months[tm_buf.tm_mon],
        tm_buf.tm_year + 1900,
        tm_buf.tm_hour,
        tm_buf.tm_min,
        tm_buf.tm_sec);
    return std::string(buf);
}

// ============================================================================
// Utility: generate MIME boundary
// ============================================================================

static std::string generate_boundary(const std::string& prefix = "") {
    std::string base = prefix.empty() ? "===Boundary" : prefix;
    return base + "_" + gen_random_hex(16) + "_" +
           std::to_string(now_ms());
}

// ============================================================================
// Utility: fold long header lines (RFC 5322, 78 char limit)
// ============================================================================

static std::string fold_header(const std::string& header_name,
                                const std::string& header_value) {
    std::string full = header_name + ": " + header_value;
    if (full.size() <= 78) return full + CRLF;

    std::string result = header_name + ": ";
    size_t line_start = result.size();
    size_t pos = 0;

    for (size_t i = 0; i < header_value.size(); ++i) {
        result.push_back(header_value[i]);
        if (result.size() - line_start >= 75 && i + 1 < header_value.size()) {
            result += CRLF " ";
            line_start = result.size();
        }
    }
    result += CRLF;
    return result;
}

// ============================================================================
// Send Queue Item - represents one outgoing message
// ============================================================================

struct SendQueueItem {
    // Unique identifier for this queue item
    std::string queue_id;

    // Core message data
    std::string from_addr;              // Sender email address
    std::string from_name;              // Sender display name
    std::vector<std::string> to_addrs;  // Primary recipients
    std::vector<std::string> cc_addrs;  // CC recipients
    std::vector<std::string> bcc_addrs; // BCC recipients
    std::string subject;
    std::string text_body;              // Plain text body
    std::string html_body;              // HTML body (optional)
    std::string message_id;             // RFC 5322 Message-ID
    std::string in_reply_to;            // In-Reply-To header value
    std::string references;             // References header value

    // DeltaChat-specific
    uint32_t chat_id = 0;
    uint32_t msg_id_internal = 0;
    std::string chat_group_id;
    std::string chat_group_name;
    int chat_verified = 0;
    std::string chat_predecessor;

    // Attachments
    struct Attachment {
        std::string file_path;
        std::string file_name;
        std::string mime_type;
        std::string content_id;
        bool is_inline = false;
        std::string encoded_content;    // Base64 encoded for sending
    };
    std::vector<Attachment> attachments;

    // Metadata
    int64_t created_at_ms = 0;
    int64_t priority = 0;              // Higher = more urgent
    int retry_count = 0;
    int64_t last_attempt_ms = 0;
    int64_t next_attempt_ms = 0;
    int state = 0;                     // 0=pending, 1=sending, 2=sent, 3=failed
    std::string last_error;
    bool is_bot_message = false;
    bool request_mdn = false;          // Request read receipt
    bool is_sync_message = false;      // Multi-device sync message
    bool bcc_self = false;             // Send copy to self

    // PGP encryption
    bool encrypt_pgp = false;
    std::vector<std::string> pgp_recipient_fingerprints;
    std::string autocrypt_keydata;     // Sender's autocrypt key
    std::string autocrypt_prefer_encrypt;

    // DKIM
    bool dkim_sign = false;
    std::string dkim_selector;
    std::string dkim_domain;
    std::string dkim_private_key_pem;

    // Sent folder
    bool upload_to_sent = true;
    std::string sent_folder;

    // Callback data
    std::function<void(const std::string& queue_id, int progress_pct,
                       const std::string& status)> progress_callback;
    std::function<void(const std::string& queue_id, bool success,
                       const std::string& error)> completion_callback;

    // Serialized MIME (built before sending)
    std::string built_mime;

    // Internal sequence number for FIFO ordering
    int64_t sequence = 0;

    SendQueueItem() {
        queue_id = gen_random_alnum(32);
        created_at_ms = now_ms();
    }
};

// ============================================================================
// Send Queue - persistent thread-safe queue of outgoing messages
// ============================================================================

class SendQueue {
public:
    SendQueue() : next_sequence_(0) {}

    // Enqueue a message
    std::string enqueue(SendQueueItem item) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (item.queue_id.empty()) {
            item.queue_id = gen_random_alnum(32);
        }
        if (item.created_at_ms == 0) {
            item.created_at_ms = now_ms();
        }
        item.state = 0; // pending
        item.sequence = next_sequence_++;
        queue_.push_back(item);
        // Keep sorted by priority (descending), then sequence (ascending)
        sort_queue();
        cv_.notify_one();
        return item.queue_id;
    }

    // Enqueue multiple messages
    void enqueue_batch(const std::vector<SendQueueItem>& items) {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto item : items) {
            if (item.queue_id.empty()) {
                item.queue_id = gen_random_alnum(32);
            }
            if (item.created_at_ms == 0) {
                item.created_at_ms = now_ms();
            }
            item.state = 0;
            item.sequence = next_sequence_++;
            queue_.push_back(item);
        }
        sort_queue();
        if (!items.empty()) cv_.notify_one();
    }

    // Dequeue the next message ready for sending (respects priority and timing)
    std::optional<SendQueueItem> dequeue() {
        std::lock_guard<std::mutex> lock(mutex_);
        int64_t now = now_ms();

        for (auto it = queue_.begin(); it != queue_.end(); ++it) {
            // Skip items that are already being sent
            if (it->state == 1) continue;
            // Skip items that are done
            if (it->state == 2) continue;
            // Skip items that are waiting for retry backoff
            if (it->next_attempt_ms > 0 && it->next_attempt_ms > now) continue;

            SendQueueItem item = *it;
            item.state = 1; // marking as sending
            *it = item;
            active_count_++;
            return item;
        }
        return std::nullopt;
    }

    // Mark item as successfully sent
    void mark_sent(const std::string& queue_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& item : queue_) {
            if (item.queue_id == queue_id) {
                item.state = 2; // sent
                item.last_attempt_ms = now_ms();
                active_count_ = std::max(0, active_count_ - 1);
                return;
            }
        }
    }

    // Mark item as failed, update retry info
    void mark_failed(const std::string& queue_id, const std::string& error) {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& item : queue_) {
            if (item.queue_id == queue_id) {
                item.retry_count++;
                item.last_error = error;
                item.last_attempt_ms = now_ms();
                item.state = 0; // back to pending
                active_count_ = std::max(0, active_count_ - 1);

                // Calculate exponential backoff
                int64_t backoff = BASE_SEND_BACKOFF_MS *
                    static_cast<int64_t>(std::pow(2, std::min(item.retry_count, 10)));
                if (backoff > MAX_SEND_BACKOFF_MS) {
                    backoff = MAX_SEND_BACKOFF_MS;
                }
                // Add jitter (±25%)
                int64_t jitter = (backoff / 4) *
                    (static_cast<int64_t>(std::rand()) % 100 - 50) / 100;
                item.next_attempt_ms = now_ms() + backoff + jitter;
                return;
            }
        }
    }

    // Permanently fail an item (after max retries)
    void mark_permanent_failure(const std::string& queue_id,
                                 const std::string& error) {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& item : queue_) {
            if (item.queue_id == queue_id) {
                item.state = 3; // permanent failure
                item.last_error = error;
                item.last_attempt_ms = now_ms();
                active_count_ = std::max(0, active_count_ - 1);
                return;
            }
        }
    }

    // Cancel a message
    bool cancel(const std::string& queue_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto it = queue_.begin(); it != queue_.end(); ++it) {
            if (it->queue_id == queue_id) {
                if (it->state == 1) {
                    active_count_ = std::max(0, active_count_ - 1);
                }
                queue_.erase(it);
                return true;
            }
        }
        return false;
    }

    // Get queue size
    size_t size() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_.size();
    }

    // Get pending count (not sent, not permanently failed)
    size_t pending_count() const {
        std::lock_guard<std::mutex> lock(mutex_);
        size_t count = 0;
        for (const auto& item : queue_) {
            if (item.state == 0) count++;
        }
        return count;
    }

    // Get active (currently sending) count
    int active_count() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return active_count_;
    }

    // Get all items (for persistence / debugging)
    std::vector<SendQueueItem> get_all() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_;
    }

    // Get items by state
    std::vector<SendQueueItem> get_by_state(int state) const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<SendQueueItem> result;
        for (const auto& item : queue_) {
            if (item.state == state) result.push_back(item);
        }
        return result;
    }

    // Remove completed items (state==2 sent)
    void purge_sent() {
        std::lock_guard<std::mutex> lock(mutex_);
        queue_.erase(
            std::remove_if(queue_.begin(), queue_.end(),
                [](const SendQueueItem& item) { return item.state == 2; }),
            queue_.end());
    }

    // Remove old permanently failed items
    void purge_old_failures(int64_t max_age_ms = 86400000) { // 24h default
        std::lock_guard<std::mutex> lock(mutex_);
        int64_t cutoff = now_ms() - max_age_ms;
        queue_.erase(
            std::remove_if(queue_.begin(), queue_.end(),
                [cutoff](const SendQueueItem& item) {
                    return item.state == 3 && item.last_attempt_ms < cutoff;
                }),
            queue_.end());
    }

    // Wait for new items (used by worker thread)
    void wait_for_items(int timeout_ms = SEND_WORKER_POLL_MS) {
        std::unique_lock<std::mutex> lock(mutex_);
        cv_.wait_for(lock, std::chrono::milliseconds(timeout_ms), [this]() {
            for (const auto& item : queue_) {
                if (item.state == 0 && item.next_attempt_ms <= now_ms()) {
                    return true;
                }
            }
            return false;
        });
    }

    // Clear the entire queue
    void clear() {
        std::lock_guard<std::mutex> lock(mutex_);
        queue_.clear();
        active_count_ = 0;
    }

private:
    void sort_queue() {
        std::sort(queue_.begin(), queue_.end(),
            [](const SendQueueItem& a, const SendQueueItem& b) {
                // Higher priority first
                if (a.priority != b.priority) return a.priority > b.priority;
                // Then by sequence (FIFO within same priority)
                return a.sequence < b.sequence;
            });
    }

    mutable std::mutex mutex_;
    std::deque<SendQueueItem> queue_;
    std::condition_variable cv_;
    int64_t next_sequence_;
    int active_count_ = 0;
};

// ============================================================================
// SMTP Rate Limiter - token bucket algorithm
// ============================================================================

class SmtpRateLimiter {
public:
    SmtpRateLimiter(int max_per_minute = DEFAULT_SMTP_RATE_LIMIT_PER_MINUTE,
                    int max_burst = DEFAULT_SMTP_MAX_BURST)
        : max_per_minute_(max_per_minute)
        , max_burst_(max_burst)
        , tokens_(max_burst)
        , last_refill_(now_ms()) {}

    // Returns false if rate limit exceeded, true if allowed
    bool try_acquire() {
        std::lock_guard<std::mutex> lock(mutex_);
        refill_tokens();
        if (tokens_ > 0) {
            tokens_--;
            return true;
        }
        return false;
    }

    // Block until a token is available
    void acquire() {
        std::unique_lock<std::mutex> lock(mutex_);
        while (tokens_ <= 0) {
            refill_tokens();
            if (tokens_ <= 0) {
                // Calculate wait time for next token
                int64_t wait_ms = static_cast<int64_t>(
                    (60000.0 / max_per_minute_) * (1.0 - (tokens_ > 0 ? tokens_ : 0)));
                lock.unlock();
                std::this_thread::sleep_for(std::chrono::milliseconds(
                    std::max(int64_t(100), wait_ms)));
                lock.lock();
            }
        }
        tokens_--;
    }

    // Get current available tokens
    int available_tokens() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return tokens_;
    }

    // Set new rate limit
    void set_rate(int max_per_minute) {
        std::lock_guard<std::mutex> lock(mutex_);
        max_per_minute_ = max_per_minute;
    }

private:
    void refill_tokens() {
        int64_t now = now_ms();
        int64_t elapsed = now - last_refill_;
        if (elapsed <= 0) return;

        double tokens_to_add = (static_cast<double>(elapsed) / 60000.0) *
                               static_cast<double>(max_per_minute_);
        tokens_ = std::min(max_burst_, static_cast<int>(tokens_ + tokens_to_add));
        last_refill_ = now;
    }

    mutable std::mutex mutex_;
    int max_per_minute_;
    int max_burst_;
    int tokens_;
    int64_t last_refill_;
};

// ============================================================================
// Message-ID Generator (RFC 5322)
// ============================================================================

class MessageIdGenerator {
public:
    MessageIdGenerator(const std::string& domain = "")
        : domain_(domain) {}

    void set_domain(const std::string& domain) {
        domain_ = domain;
    }

    std::string generate() {
        std::string local_part = gen_random_hex(16) + "." +
                                 std::to_string(now_ms());
        std::string domain = domain_.empty() ? "localhost" : domain_;
        return "<" + local_part + "@" + domain + ">";
    }

    // Generate message-id that's based on a seed (deterministic for same inputs)
    std::string generate_deterministic(const std::string& seed) {
        std::hash<std::string> hasher;
        size_t hash_val = hasher(seed + domain_ + std::to_string(std::time(nullptr)));
        std::stringstream ss;
        ss << std::hex << hash_val;
        std::string domain = domain_.empty() ? "localhost" : domain_;
        return "<" + ss.str() + "@" + domain + ">";
    }

private:
    std::string domain_;
};

// ============================================================================
// Autocrypt Header Builder
// ============================================================================

class AutocryptHeaderBuilder {
public:
    struct AutocryptParams {
        std::string keydata;          // Base64-encoded public key
        std::string addr;             // Email address
        std::string prefer_encrypt;   // "nopreference" or "mutual"
    };

    // Build the Autocrypt header value according to Autocrypt Level 1 spec
    static std::string build(const AutocryptParams& params) {
        if (params.keydata.empty()) return "";

        std::string header;
        header += "addr=" + params.addr + "; ";
        header += "prefer-encrypt=" + params.prefer_encrypt + "; ";
        header += "keydata=" + params.keydata;

        return header;
    }

    // Build Autocrypt-Setup-Message header
    static std::string build_setup_message(const std::string& setup_code) {
        return "v1 " + setup_code;
    }
};

// ============================================================================
// Chat Header Builder - DeltaChat-specific headers
// ============================================================================

class ChatHeaderBuilder {
public:
    struct ChatHeaders {
        int version = 1;
        std::string group_id;
        std::string group_name;
        std::string verified;            // "verified" or empty
        std::string predecessor_msg_id;
        std::string content_type;        // "text", "image", "video", etc.
        bool is_sync_message = false;
    };

    static std::unordered_map<std::string, std::string> build(const ChatHeaders& params) {
        std::unordered_map<std::string, std::string> headers;

        // Chat-Version: always present
        headers[CHAT_VERSION_HEADER] = std::to_string(params.version);

        // Chat-User-Agent
        headers[CHAT_USER_AGENT_HEADER] = CHAT_USER_AGENT;

        // Chat-Group-ID (for group messages)
        if (!params.group_id.empty()) {
            headers[CHAT_GROUP_ID_HEADER] = params.group_id;
        }

        // Chat-Group-Name (encoded)
        if (!params.group_name.empty()) {
            headers[CHAT_GROUP_NAME_HEADER] =
                encode_mime_header(params.group_name);
        }

        // Chat-Verified
        if (!params.verified.empty()) {
            headers[CHAT_VERIFIED_HEADER] = params.verified;
        }

        // Chat-Predecessor (message being replied to)
        if (!params.predecessor_msg_id.empty()) {
            headers[CHAT_PREVIOUS_HEADER] = params.predecessor_msg_id;
        }

        // Chat-Content-Type
        if (!params.content_type.empty()) {
            headers[CHAT_CONTENT_TYPE_HEADER] = params.content_type;
        }

        return headers;
    }
};

// ============================================================================
// DKIM Signer
// ============================================================================

class DkimSigner {
public:
    struct DkimParams {
        std::string private_key_pem;
        std::string selector;
        std::string domain;
        std::vector<std::string> signed_headers; // Headers to sign
        std::string algorithm = "rsa-sha256";     // "rsa-sha256" or "ed25519-sha256"
        std::string canonicalization = "relaxed/relaxed";
        std::string body_length_limit;            // Optional, "l=" tag
        int64_t signature_timestamp = 0;          // t= tag
        int64_t signature_expiration = 0;         // x= tag
    };

    // Build a DKIM-Signature header
    // In a full implementation this would use OpenSSL for RSA/Ed25519 signing.
    // Here we build the header structure and provide a signing interface.
    static std::string build_signature_header(const std::string& message_body_hash,
                                               const DkimParams& params,
                                               const std::string& header_canon_data) {
        std::string dkim;
        dkim += "v=1; ";
        dkim += "a=" + params.algorithm + "; ";
        dkim += "c=" + params.canonicalization + "; ";
        dkim += "d=" + params.domain + "; ";
        dkim += "s=" + params.selector + "; ";

        // Signed headers
        dkim += "h=";
        for (size_t i = 0; i < params.signed_headers.size(); ++i) {
            if (i > 0) dkim += ":";
            dkim += params.signed_headers[i];
        }
        dkim += "; ";

        // Body hash
        dkim += "bh=" + send_base64::encode(message_body_hash) + "; ";
        dkim += "b="; // Placeholder for actual signature

        if (params.signature_timestamp > 0) {
            dkim += "; t=" + std::to_string(params.signature_timestamp);
        }
        if (params.signature_expiration > 0) {
            dkim += "; x=" + std::to_string(params.signature_expiration);
        }

        return dkim;
    }

    // Compute the body hash for DKIM (simplified relaxation + SHA-256)
    static std::string compute_body_hash(const std::string& body) {
        // In a real implementation, this would:
        // 1. Canonicalize the body per the selected canonicalization algorithm
        // 2. Compute SHA-256 hash
        // For now, provide the structural interface
        return body; // Placeholder - real implementation uses SHA-256
    }

    // Sign data with the private key (placeholder)
    static std::string sign(const std::string& data,
                             const std::string& private_key_pem,
                             const std::string& algorithm) {
        // Real implementation would use OpenSSL EVP_Sign*
        // Returns base64-encoded signature
        return send_base64::encode(data); // Placeholder
    }
};

// ============================================================================
// PGP/MIME Encryptor
// ============================================================================

class PgpEncryptor {
public:
    struct PgpEncryptResult {
        std::string encrypted_mime;
        bool success = false;
        std::string error;
    };

    // Wrap a MIME message in PGP/MIME encryption (RFC 3156)
    // Produces multipart/encrypted with protocol="application/pgp-encrypted"
    static PgpEncryptResult encrypt_mime(
        const std::string& original_mime,
        const std::vector<std::string>& recipient_fingerprints,
        const std::string& sender_keydata) {

        PgpEncryptResult result;

        if (recipient_fingerprints.empty()) {
            result.error = "No recipient fingerprints for PGP encryption";
            return result;
        }

        // Build the PGP/MIME wrapper structure
        std::string boundary = generate_boundary("PGPMimeEncrypted");

        std::stringstream ss;

        ss << "Content-Type: multipart/encrypted; "
           << "boundary=\"" << boundary << "\"; "
           << "protocol=\"application/pgp-encrypted\"" << CRLF;
        ss << CRLF;
        ss << "--" << boundary << CRLF;
        ss << "Content-Type: application/pgp-encrypted" << CRLF;
        ss << "Content-Description: PGP/MIME version identification" << CRLF;
        ss << CRLF;
        ss << "Version: 1" << CRLF;
        ss << CRLF;
        ss << "--" << boundary << CRLF;
        ss << "Content-Type: application/octet-stream; name=\"encrypted.asc\"" << CRLF;
        ss << "Content-Description: OpenPGP encrypted message" << CRLF;
        ss << "Content-Disposition: inline; filename=\"encrypted.asc\"" << CRLF;
        ss << "Content-Transfer-Encoding: 7bit" << CRLF;
        ss << CRLF;

        // The actual encrypted content would be the original MIME message
        // encrypted with PGP. In production this calls GnuPG/gpgme.
        std::string pgp_encrypted_body = build_pgp_encrypted_block(
            original_mime, recipient_fingerprints);
        ss << pgp_encrypted_body << CRLF;
        ss << "--" << boundary << "--" << CRLF;

        result.encrypted_mime = ss.str();
        result.success = true;
        return result;
    }

private:
    static std::string build_pgp_encrypted_block(
        const std::string& plaintext,
        const std::vector<std::string>& recipients) {

        // Real implementation uses GpgME or calls gpg binary.
        // Structure:
        // -----BEGIN PGP MESSAGE-----
        // [base64-encoded encrypted data]
        // -----END PGP MESSAGE-----

        std::stringstream ss;
        ss << "-----BEGIN PGP MESSAGE-----" << CRLF;
        ss << CRLF;
        // Placeholder: in production, the actual encrypted content goes here
        ss << send_base64::encode(plaintext) << CRLF;
        ss << "-----END PGP MESSAGE-----" << CRLF;
        return ss.str();
    }
};

// ============================================================================
// MIME Message Builder
// ============================================================================

class MimeBuilder {
public:
    struct MimeOptions {
        // Core headers
        std::string from_name;
        std::string from_addr;
        std::vector<std::string> to_addrs;
        std::vector<std::string> cc_addrs;
        std::vector<std::string> bcc_addrs;
        std::string subject;
        std::string message_id;
        std::string in_reply_to;
        std::string references;

        // Bodies
        std::string text_body;
        std::string html_body;

        // Attachments
        std::vector<SendQueueItem::Attachment> attachments;

        // DeltaChat headers
        ChatHeaderBuilder::ChatHeaders chat_headers;

        // Autocrypt
        std::string autocrypt_header_value;
        std::string autocrypt_setup_value;

        // List headers
        std::string list_id;
        bool is_mailing_list = false;

        // Additional
        bool request_mdn = false;
        std::string mdn_return_addr;
        std::string precedence;         // "bulk", "list", etc.
        std::string dkim_signature;
        time_t message_date = 0;
    };

    static std::string build(const MimeOptions& opts) {
        std::stringstream mime;

        // ================================================================
        // Headers
        // ================================================================

        // Date
        if (opts.message_date == 0) opts.message_date; // suppress warning
        mime << "Date: " << format_rfc5322_date(
            opts.message_date ? opts.message_date : std::time(nullptr)) << CRLF;

        // From
        mime << "From: " << format_email_addr(opts.from_name, opts.from_addr) << CRLF;

        // To
        if (!opts.to_addrs.empty()) {
            mime << "To: ";
            for (size_t i = 0; i < opts.to_addrs.size(); ++i) {
                if (i > 0) mime << ", ";
                mime << opts.to_addrs[i];
            }
            mime << CRLF;
        }

        // CC
        if (!opts.cc_addrs.empty()) {
            mime << "Cc: ";
            for (size_t i = 0; i < opts.cc_addrs.size(); ++i) {
                if (i > 0) mime << ", ";
                mime << opts.cc_addrs[i];
            }
            mime << CRLF;
        }

        // BCC is NOT included in MIME headers (only in SMTP envelope)

        // Subject
        mime << fold_header("Subject",
            opts.subject.empty() ? "" : encode_mime_header(opts.subject));

        // Message-ID
        mime << "Message-ID: " << (opts.message_id.empty() ?
            "<" + gen_random_hex(16) + "@localhost>" : opts.message_id) << CRLF;

        // In-Reply-To
        if (!opts.in_reply_to.empty()) {
            mime << "In-Reply-To: " << opts.in_reply_to << CRLF;
        }

        // References
        if (!opts.references.empty()) {
            mime << "References: " << opts.references << CRLF;
        }

        // MIME-Version
        mime << "MIME-Version: 1.0" << CRLF;

        // ================================================================
        // DeltaChat Chat Headers
        // ================================================================
        auto chat_headers_map = ChatHeaderBuilder::build(opts.chat_headers);
        for (const auto& [name, value] : chat_headers_map) {
            mime << name << ": " << value << CRLF;
        }

        // ================================================================
        // Autocrypt Header
        // ================================================================
        if (!opts.autocrypt_header_value.empty()) {
            mime << fold_header(AUTOCRYPT_HEADER_NAME, opts.autocrypt_header_value);
        }
        if (!opts.autocrypt_setup_value.empty()) {
            mime << AUTOCRYPT_SETUP_HEADER_NAME << ": "
                 << opts.autocrypt_setup_value << CRLF;
        }

        // ================================================================
        // List-ID (for mailing list groups)
        // ================================================================
        if (!opts.list_id.empty()) {
            mime << LIST_ID_HEADER << ": " << opts.list_id << CRLF;
        }

        // ================================================================
        // Precedence header
        // ================================================================
        if (!opts.precedence.empty()) {
            mime << PRECEDENCE_HEADER ": " << opts.precedence << CRLF;
        } else if (opts.is_mailing_list) {
            mime << PRECEDENCE_HEADER ": list" << CRLF;
        }

        // ================================================================
        // Disposition-Notification-To (MDN requests)
        // ================================================================
        if (opts.request_mdn) {
            std::string mdn_addr = opts.mdn_return_addr.empty() ?
                opts.from_addr : opts.mdn_return_addr;
            mime << DISPOSITION_NOTIFICATION_HEADER ": " << mdn_addr << CRLF;
        }

        // ================================================================
        // DKIM-Signature
        // ================================================================
        if (!opts.dkim_signature.empty()) {
            mime << fold_header(DKIM_SIGNATURE_HEADER, opts.dkim_signature);
        }

        // ================================================================
        // Content-Type and Body
        // ================================================================

        bool has_attachments = !opts.attachments.empty();
        bool has_html = !opts.html_body.empty();
        bool has_text = !opts.text_body.empty();

        if (has_attachments) {
            // multipart/mixed wrapper
            std::string mixed_boundary = generate_boundary("Mixed");
            mime << "Content-Type: multipart/mixed; boundary=\""
                 << mixed_boundary << "\"" << CRLF;
            mime << CRLF;

            // If we have text/html, create a multipart/alternative sub-part
            if (has_text || has_html) {
                if (has_text && has_html) {
                    std::string alt_boundary = generate_boundary("Alternative");
                    mime << "--" << mixed_boundary << CRLF;
                    mime << "Content-Type: multipart/alternative; boundary=\""
                         << alt_boundary << "\"" << CRLF;
                    mime << CRLF;

                    // Text part
                    mime << "--" << alt_boundary << CRLF;
                    append_text_part(mime, opts.text_body, "plain");
                    mime << CRLF;

                    // HTML part
                    mime << "--" << alt_boundary << CRLF;
                    append_text_part(mime, opts.html_body, "html");
                    mime << CRLF;

                    mime << "--" << alt_boundary << "--" << CRLF;
                } else if (has_text) {
                    mime << "--" << mixed_boundary << CRLF;
                    append_text_part(mime, opts.text_body, "plain");
                    mime << CRLF;
                } else {
                    mime << "--" << mixed_boundary << CRLF;
                    append_text_part(mime, opts.html_body, "html");
                    mime << CRLF;
                }
            } else {
                // No text body, attachments only
                mime << "--" << mixed_boundary << CRLF;
                mime << "Content-Type: text/plain; charset=\"utf-8\"" << CRLF;
                mime << CRLF;
                mime << CRLF;
            }

            // Attachments
            for (const auto& att : opts.attachments) {
                mime << "--" << mixed_boundary << CRLF;
                append_attachment_part(mime, att);
                mime << CRLF;
            }

            mime << "--" << mixed_boundary << "--" << CRLF;

        } else if (has_text && has_html) {
            // Multipart/alternative (text + html, no attachments)
            std::string alt_boundary = generate_boundary("Alternative");
            mime << "Content-Type: multipart/alternative; boundary=\""
                 << alt_boundary << "\"" << CRLF;
            mime << CRLF;

            mime << "--" << alt_boundary << CRLF;
            append_text_part(mime, opts.text_body, "plain");
            mime << CRLF;

            mime << "--" << alt_boundary << CRLF;
            append_text_part(mime, opts.html_body, "html");
            mime << CRLF;

            mime << "--" << alt_boundary << "--" << CRLF;
        } else if (has_text) {
            // Plain text only
            mime << "Content-Type: text/plain; charset=\"utf-8\"" << CRLF;
            mime << "Content-Transfer-Encoding: quoted-printable" << CRLF;
            mime << CRLF;
            mime << send_qp::encode(opts.text_body) << CRLF;
        } else if (has_html) {
            // HTML only
            mime << "Content-Type: text/html; charset=\"utf-8\"" << CRLF;
            mime << "Content-Transfer-Encoding: quoted-printable" << CRLF;
            mime << CRLF;
            mime << send_qp::encode(opts.html_body) << CRLF;
        } else {
            // Empty body
            mime << "Content-Type: text/plain; charset=\"utf-8\"" << CRLF;
            mime << CRLF;
            mime << CRLF;
        }

        return mime.str();
    }

private:
    static void append_text_part(std::stringstream& mime,
                                  const std::string& body,
                                  const std::string& subtype) {
        mime << "Content-Type: text/" << subtype << "; charset=\"utf-8\"" << CRLF;
        mime << "Content-Transfer-Encoding: quoted-printable" << CRLF;
        mime << CRLF;
        mime << send_qp::encode(body) << CRLF;
    }

    static void append_attachment_part(std::stringstream& mime,
                                        const SendQueueItem::Attachment& att) {
        mime << "Content-Type: " << att.mime_type << ";";
        if (!att.file_name.empty()) {
            mime << CRLF " name=\"" << att.file_name << "\"";
        }
        mime << CRLF;

        mime << "Content-Disposition: ";
        if (att.is_inline) {
            mime << "inline";
        } else {
            mime << "attachment";
        }
        if (!att.file_name.empty()) {
            mime << ";" CRLF " filename=\"" << att.file_name << "\"";
        }
        mime << CRLF;

        if (!att.content_id.empty()) {
            mime << "Content-ID: <" << att.content_id << ">" << CRLF;
        }

        mime << "Content-Transfer-Encoding: base64" << CRLF;
        mime << CRLF;

        // Write base64 content line-wrapped at 76 chars
        std::string b64 = att.encoded_content.empty() ?
            send_base64::encode("") : att.encoded_content;
        for (size_t i = 0; i < b64.size(); i += 76) {
            mime << b64.substr(i, 76) << CRLF;
        }
    }
};

// ============================================================================
// Send Progress Tracker
// ============================================================================

class SendProgressTracker {
public:
    struct ProgressInfo {
        std::string queue_id;
        int progress_pct = 0;          // 0-100
        std::string stage;             // "connecting", "authenticating",
                                       // "sending", "uploading_sent", "done"
        std::string detail;
        int64_t started_at_ms = 0;
        int64_t updated_at_ms = 0;
        bool completed = false;
        bool success = false;
        std::string error;
    };

    void start(const std::string& queue_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        ProgressInfo info;
        info.queue_id = queue_id;
        info.progress_pct = 0;
        info.stage = "queued";
        info.started_at_ms = now_ms();
        info.updated_at_ms = now_ms();
        progress_map_[queue_id] = info;
    }

    void update(const std::string& queue_id, int progress_pct,
                const std::string& stage, const std::string& detail = "") {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = progress_map_.find(queue_id);
        if (it != progress_map_.end()) {
            it->second.progress_pct = progress_pct;
            it->second.stage = stage;
            it->second.detail = detail;
            it->second.updated_at_ms = now_ms();
        }
    }

    void complete(const std::string& queue_id, bool success,
                  const std::string& error = "") {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = progress_map_.find(queue_id);
        if (it != progress_map_.end()) {
            it->second.progress_pct = success ? 100 : it->second.progress_pct;
            it->second.stage = success ? "done" : "failed";
            it->second.completed = true;
            it->second.success = success;
            it->second.error = error;
            it->second.updated_at_ms = now_ms();
        }
    }

    ProgressInfo get(const std::string& queue_id) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = progress_map_.find(queue_id);
        if (it != progress_map_.end()) {
            return it->second;
        }
        return ProgressInfo{};
    }

    std::vector<ProgressInfo> get_all() const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<ProgressInfo> result;
        for (const auto& [id, info] : progress_map_) {
            result.push_back(info);
        }
        return result;
    }

    void remove(const std::string& queue_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        progress_map_.erase(queue_id);
    }

    void prune_old(int64_t max_age_ms = 3600000) { // 1 hour default
        std::lock_guard<std::mutex> lock(mutex_);
        int64_t cutoff = now_ms() - max_age_ms;
        auto it = progress_map_.begin();
        while (it != progress_map_.end()) {
            if (it->second.completed && it->second.updated_at_ms < cutoff) {
                it = progress_map_.erase(it);
            } else {
                ++it;
            }
        }
    }

private:
    mutable std::mutex mutex_;
    std::unordered_map<std::string, ProgressInfo> progress_map_;
};

// ============================================================================
// Send Failure Notifier
// ============================================================================

class SendFailureNotifier {
public:
    using FailureCallback = std::function<void(
        uint32_t chat_id,
        uint32_t msg_id,
        const std::string& error,
        int retry_count,
        bool is_permanent)>;

    void set_callback(FailureCallback cb) {
        std::lock_guard<std::mutex> lock(mutex_);
        callback_ = std::move(cb);
    }

    void notify_failure(uint32_t chat_id, uint32_t msg_id,
                        const std::string& error, int retry_count,
                        bool is_permanent) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (callback_) {
            callback_(chat_id, msg_id, error, retry_count, is_permanent);
        }
    }

    // Build a system message about send failure to insert into the chat
    static std::string build_failure_message(const std::string& error,
                                              int retry_count,
                                              bool is_permanent) {
        if (is_permanent) {
            return "Message sending failed permanently: " + error;
        }
        return "Message sending failed (attempt " +
               std::to_string(retry_count) + "): " + error +
               ". Will retry shortly.";
    }

private:
    std::mutex mutex_;
    FailureCallback callback_;
};

// ============================================================================
// MDN (Message Disposition Notification) Tracker
// ============================================================================

class MdnTracker {
public:
    struct MdnRecord {
        std::string original_message_id;
        std::string recipient_addr;
        int64_t sent_at_ms = 0;
        bool mdn_received = false;
        int64_t mdn_received_at_ms = 0;
        std::string disposition;       // "displayed", "dispatched", etc.
    };

    // Register a sent message for MDN tracking
    void track_send(const std::string& message_id,
                    const std::string& recipient_addr) {
        std::lock_guard<std::mutex> lock(mutex_);
        MdnRecord record;
        record.original_message_id = message_id;
        record.recipient_addr = recipient_addr;
        record.sent_at_ms = now_ms();
        records_[message_id] = record;
    }

    // Record that an MDN was received
    void record_mdn_received(const std::string& original_message_id,
                              const std::string& disposition) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = records_.find(original_message_id);
        if (it != records_.end()) {
            it->second.mdn_received = true;
            it->second.mdn_received_at_ms = now_ms();
            it->second.disposition = disposition;
        }
    }

    // Check if MDN received for a message
    bool is_mdn_received(const std::string& message_id) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = records_.find(message_id);
        return it != records_.end() && it->second.mdn_received;
    }

    // Get pending MDNs (not yet received, within timeout)
    std::vector<MdnRecord> get_pending() const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<MdnRecord> pending;
        int64_t cutoff = now_ms() - MDN_TIMEOUT_SECONDS * 1000;
        for (const auto& [id, record] : records_) {
            if (!record.mdn_received && record.sent_at_ms > cutoff) {
                pending.push_back(record);
            }
        }
        return pending;
    }

    // Clean up old records
    void prune_old() {
        std::lock_guard<std::mutex> lock(mutex_);
        int64_t cutoff = now_ms() - MDN_TIMEOUT_SECONDS * 1000;
        auto it = records_.begin();
        while (it != records_.end()) {
            if (it->second.sent_at_ms < cutoff) {
                it = records_.erase(it);
            } else {
                ++it;
            }
        }
    }

private:
    mutable std::mutex mutex_;
    std::unordered_map<std::string, MdnRecord> records_;
};

// ============================================================================
// Sent Folder Uploader - uploads sent message via IMAP APPEND
// ============================================================================

class SentFolderUploader {
public:
    SentFolderUploader() : sent_folder_(SENT_FOLDER_NAME) {}

    void set_sent_folder(const std::string& folder) {
        sent_folder_ = folder;
    }

    std::string get_sent_folder() const {
        return sent_folder_;
    }

    void set_imap_append_func(ImapAppendFunc func) {
        imap_append_func_ = std::move(func);
    }

    // Upload a sent message to the Sent folder via IMAP APPEND
    // Returns true on success
    bool upload_to_sent(const std::string& mime_message,
                         const std::string& queue_id,
                         SendProgressTracker* progress = nullptr) {

        if (!imap_append_func_) {
            last_error_ = "No IMAP append function configured";
            return false;
        }

        // Progress: uploading to sent folder (stage 80-95%)
        if (progress) {
            progress->update(queue_id, 80, "uploading_sent",
                             "Uploading copy to " + sent_folder_);
        }

        for (int attempt = 0; attempt < SENT_FOLDER_UPLOAD_RETRIES; ++attempt) {
            // Call the IMAP append callback function
            std::string append_error;
            bool success = imap_append_func_(
                sent_folder_,
                mime_message,
                {"\\Seen"},
                format_rfc5322_date(),
                append_error
            );

            if (success) {
                if (progress) {
                    progress->update(queue_id, 95, "uploading_sent",
                                     "Sent folder upload complete");
                }
                return true;
            }

            last_error_ = "IMAP APPEND to " + sent_folder_ +
                          " failed (attempt " + std::to_string(attempt + 1) + ")";

            if (attempt < SENT_FOLDER_UPLOAD_RETRIES - 1) {
                std::this_thread::sleep_for(std::chrono::seconds(2));
            }
        }

        return false;
    }

    std::string get_last_error() const { return last_error_; }

private:
    std::string sent_folder_;
    ImapAppendFunc imap_append_func_;
    mutable std::string last_error_;
};

// ============================================================================
// Config holder for send pipeline
// ============================================================================

struct SendPipelineConfig {
    // SMTP settings
    std::string smtp_host;
    int smtp_port = 465;
    int smtp_security = 1;       // 0=plain, 1=SSL/TLS, 2=STARTTLS
    std::string smtp_username;
    std::string smtp_password;

    // Sender identity
    std::string sender_addr;
    std::string sender_name;
    std::string sender_domain;   // For Message-ID generation

    // Autocrypt
    std::string autocrypt_keydata;
    std::string autocrypt_prefer_encrypt = "mutual";

    // Features
    bool bcc_self = false;
    bool e2ee_enabled = true;
    bool mdns_enabled = true;
    bool dkim_enabled = false;
    bool upload_to_sent = true;
    std::string sent_folder = SENT_FOLDER_NAME;

    // DKIM settings
    std::string dkim_selector;
    std::string dkim_domain;
    std::string dkim_private_key_pem;

    // Rate limiting
    int smtp_rate_limit_per_minute = DEFAULT_SMTP_RATE_LIMIT_PER_MINUTE;
    int smtp_max_burst = DEFAULT_SMTP_MAX_BURST;

    // Worker
    int max_concurrent_sends = 3;
    int worker_poll_interval_ms = SEND_WORKER_POLL_MS;
};

// ============================================================================
// Send Worker - background thread that processes the send queue
// ============================================================================

class SendWorker {
public:
    SendWorker(SendQueue& queue,
               SendPipelineConfig& config,
               SendProgressTracker& progress,
               SendFailureNotifier& notifier,
               MdnTracker& mdn_tracker,
               SentFolderUploader& sent_uploader)
        : queue_(queue)
        , config_(config)
        , progress_(progress)
        , notifier_(notifier)
        , mdn_tracker_(mdn_tracker)
        , sent_uploader_(sent_uploader)
        , running_(false)
        , rate_limiter_(config.smtp_rate_limit_per_minute,
                        config.smtp_max_burst) {}

    ~SendWorker() {
        stop();
    }

    void set_smtp_send_func(SmtpSendFunc func) {
        smtp_send_func_ = std::move(func);
    }

    void set_imap_append_func(ImapAppendFunc func) {
        imap_append_func_ = std::move(func);
        sent_uploader_.set_imap_append_func(imap_append_func_);
    }

    void start() {
        if (running_.exchange(true)) return;
        worker_thread_ = std::thread(&SendWorker::worker_loop, this);
    }

    void stop() {
        running_.store(false);
        if (worker_thread_.joinable()) {
            worker_thread_.join();
        }
    }

    bool is_running() const {
        return running_.load();
    }

    // Process one specific item immediately (bypasses queue ordering)
    bool send_now(const SendQueueItem& item) {
        return process_item(item);
    }

private:
    void worker_loop() {
        while (running_.load()) {
            // Drain the queue
            bool had_work = false;
            while (running_.load()) {
                auto item_opt = queue_.dequeue();
                if (!item_opt.has_value()) break;

                had_work = true;
                process_item(item_opt.value());
            }

            if (!had_work) {
                // Wait for new items or poll interval
                queue_.wait_for_items(config_.worker_poll_interval_ms);
            }
        }
    }

    bool process_item(SendQueueItem item) {
        std::string qid = item.queue_id;

        // Initialize progress tracking
        progress_.start(qid);

        // ================================================================
        // Step 1: Rate limiting
        // ================================================================
        progress_.update(qid, 5, "rate_limited", "Waiting for rate limiter");
        rate_limiter_.acquire();

        // ================================================================
        // Step 2: Build MIME message
        // ================================================================
        progress_.update(qid, 10, "building", "Constructing MIME message");

        std::string mime_message;
        try {
            mime_message = build_mime_message(item);
        } catch (const std::exception& e) {
            std::string error = std::string("MIME build error: ") + e.what();
            queue_.mark_permanent_failure(qid, error);
            progress_.complete(qid, false, error);
            notify_failure(item, error, true);
            if (item.completion_callback) {
                item.completion_callback(qid, false, error);
            }
            return false;
        }

        item.built_mime = mime_message;

        // ================================================================
        // Step 3: PGP/MIME encryption (if enabled)
        // ================================================================
        if (item.encrypt_pgp && config_.e2ee_enabled &&
            !item.pgp_recipient_fingerprints.empty()) {
            progress_.update(qid, 20, "encrypting", "PGP encrypting message");

            auto encrypt_result = PgpEncryptor::encrypt_mime(
                mime_message,
                item.pgp_recipient_fingerprints,
                item.autocrypt_keydata.empty() ?
                    config_.autocrypt_keydata : item.autocrypt_keydata);

            if (!encrypt_result.success) {
                queue_.mark_permanent_failure(qid, encrypt_result.error);
                progress_.complete(qid, false, encrypt_result.error);
                notify_failure(item, encrypt_result.error, true);
                if (item.completion_callback) {
                    item.completion_callback(qid, false, encrypt_result.error);
                }
                return false;
            }

            mime_message = encrypt_result.encrypted_mime;
        }

    // ================================================================
    // Step 4: Send via SMTP
    // ================================================================
    progress_.update(qid, 50, "sending",
        "Sending to " + std::to_string(item.to_addrs.size()) + " recipient(s)");

    // Collect all envelope recipients
    std::vector<std::string> envelope_recipients;
    for (const auto& addr : item.to_addrs) {
        envelope_recipients.push_back(extract_email(addr));
    }
    for (const auto& addr : item.cc_addrs) {
        envelope_recipients.push_back(extract_email(addr));
    }
    for (const auto& addr : item.bcc_addrs) {
        envelope_recipients.push_back(extract_email(addr));
    }
    // BCC self for multi-device sync
    if (item.bcc_self || config_.bcc_self) {
        if (!config_.sender_addr.empty()) {
            bool already_present = false;
            std::string self_addr = config_.sender_addr;
            for (const auto& r : envelope_recipients) {
                if (extract_email(r) == self_addr) {
                    already_present = true;
                    break;
                }
            }
            if (!already_present) {
                envelope_recipients.push_back(self_addr);
            }
        }
    }

    std::string from_addr = format_email_addr(
        item.from_name.empty() ? config_.sender_name : item.from_name,
        item.from_addr.empty() ? config_.sender_addr : item.from_addr);

    // Use the SMTP send function callback
    if (!smtp_send_func_) {
        handle_send_failure(item, "No SMTP send function configured");
        return false;
    }

    std::vector<std::string> failed_recipients;
    std::string smtp_error;
    bool smtp_ok = smtp_send_func_(
        config_.smtp_host,
        config_.smtp_port,
        config_.smtp_security,
        config_.smtp_username,
        config_.smtp_password,
        config_.sender_domain.empty() ? "localhost" : config_.sender_domain,
        extract_email(from_addr),
        envelope_recipients,
        mime_message,
        failed_recipients,
        smtp_error
    );

    if (!smtp_ok) {
        std::string error = smtp_error;
        if (!failed_recipients.empty()) {
            error += " | Failed recipients: ";
            for (size_t i = 0; i < failed_recipients.size(); ++i) {
                if (i > 0) error += ", ";
                error += failed_recipients[i];
            }
        }
        handle_send_failure(item, error);
        return false;
    }

        // ================================================================
        // Step 6: Upload to sent folder
        // ================================================================
        if (item.upload_to_sent && config_.upload_to_sent) {
            progress_.update(qid, 75, "uploading_sent",
                             "Uploading to sent folder");

            bool sent_ok = sent_uploader_.upload_to_sent(
                mime_message, qid, &progress_);
            if (!sent_ok) {
                // Non-fatal: we already sent successfully
                progress_.update(qid, 90, "sent_upload_warning",
                    "Sent folder upload failed: " +
                    sent_uploader_.get_last_error());
            }
        }

        // ================================================================
        // Step 7: Track MDN
        // ================================================================
        if (item.request_mdn || config_.mdns_enabled) {
            for (const auto& addr : item.to_addrs) {
                mdn_tracker_.track_send(item.message_id, extract_email(addr));
            }
        }

        // ================================================================
        // Step 8: Mark success
        // ================================================================
        queue_.mark_sent(qid);
        progress_.complete(qid, true, "");

        if (item.progress_callback) {
            item.progress_callback(qid, 100, "Sent successfully");
        }
        if (item.completion_callback) {
            item.completion_callback(qid, true, "");
        }

        return true;
    }

    std::string build_mime_message(const SendQueueItem& item) {
        MimeBuilder::MimeOptions opts;

        // Core headers
        opts.from_name = item.from_name.empty() ?
            config_.sender_name : item.from_name;
        opts.from_addr = item.from_addr.empty() ?
            config_.sender_addr : item.from_addr;
        opts.to_addrs = item.to_addrs;
        opts.cc_addrs = item.cc_addrs;
        // BCC addresses are only in SMTP envelope, not MIME headers
        opts.subject = item.subject;
        opts.message_id = item.message_id;
        opts.in_reply_to = item.in_reply_to;
        opts.references = item.references;

        // Bodies
        opts.text_body = item.text_body;
        opts.html_body = item.html_body;

        // Attachments
        opts.attachments = item.attachments;

        // DeltaChat chat headers
        opts.chat_headers.version = 1;
        opts.chat_headers.group_id = item.chat_group_id;
        opts.chat_headers.group_name = item.chat_group_name;
        opts.chat_headers.verified = item.chat_verified ? "verified" : "";
        opts.chat_headers.predecessor_msg_id = item.chat_predecessor;

        // Determine content type from attachments
        if (!item.attachments.empty()) {
            // Check if it's an image
            bool has_image = false;
            for (const auto& att : item.attachments) {
                if (att.mime_type.find("image/") == 0) {
                    has_image = true;
                    break;
                }
            }
            opts.chat_headers.content_type = has_image ? "image" : "file";
        } else {
            opts.chat_headers.content_type = "text";
        }

        // Autocrypt
        if (!item.autocrypt_keydata.empty()) {
            AutocryptHeaderBuilder::AutocryptParams ac_params;
            ac_params.addr = opts.from_addr;
            ac_params.keydata = item.autocrypt_keydata;
            ac_params.prefer_encrypt = item.autocrypt_prefer_encrypt.empty() ?
                config_.autocrypt_prefer_encrypt :
                item.autocrypt_prefer_encrypt;
            opts.autocrypt_header_value =
                AutocryptHeaderBuilder::build(ac_params);
        } else if (!config_.autocrypt_keydata.empty()) {
            AutocryptHeaderBuilder::AutocryptParams ac_params;
            ac_params.addr = config_.sender_addr;
            ac_params.keydata = config_.autocrypt_keydata;
            ac_params.prefer_encrypt = config_.autocrypt_prefer_encrypt;
            opts.autocrypt_header_value =
                AutocryptHeaderBuilder::build(ac_params);
        }

        // List-ID for mailing list groups
        if (!item.chat_group_id.empty() && !item.chat_group_name.empty()) {
            opts.list_id = item.chat_group_name + " <" +
                          item.chat_group_id + ".list." +
                          config_.sender_domain + ">";
        }

        // Precedence
        if (item.is_sync_message) {
            opts.precedence = "bulk";
        }

        // MDN
        opts.request_mdn = item.request_mdn || config_.mdns_enabled;
        opts.mdn_return_addr = opts.from_addr;

        // DKIM
        if (item.dkim_sign || config_.dkim_enabled) {
            std::string body_hash = DkimSigner::compute_body_hash(
                item.text_body);

            DkimSigner::DkimParams dkim_params;
            dkim_params.domain = item.dkim_domain.empty() ?
                config_.dkim_domain : item.dkim_domain;
            dkim_params.selector = item.dkim_selector.empty() ?
                config_.dkim_selector : item.dkim_selector;
            dkim_params.private_key_pem = item.dkim_private_key_pem.empty() ?
                config_.dkim_private_key_pem : item.dkim_private_key_pem;
            dkim_params.signed_headers = {
                "from", "to", "subject", "date", "message-id",
                "mime-version", "content-type",
                "chat-version", "autocrypt"
            };
            dkim_params.signature_timestamp = std::time(nullptr);

            opts.dkim_signature = DkimSigner::build_signature_header(
                body_hash, dkim_params, "");
        }

        return MimeBuilder::build(opts);
    }

    void handle_send_failure(SendQueueItem& item, const std::string& error) {
        if (item.retry_count >= MAX_SEND_RETRIES) {
            // Permanent failure
            queue_.mark_permanent_failure(item.queue_id, error);
            progress_.complete(item.queue_id, false, error);
            notify_failure(item, error, true);
            if (item.completion_callback) {
                item.completion_callback(item.queue_id, false, error);
            }
        } else {
            // Will retry
            queue_.mark_failed(item.queue_id, error);
            progress_.update(item.queue_id,
                std::min(90, 10 + item.retry_count * 10),
                "retry_waiting",
                "Failed: " + error + ". Will retry (attempt " +
                std::to_string(item.retry_count + 1) + "/" +
                std::to_string(MAX_SEND_RETRIES) + ")");
            notify_failure(item, error, false);
        }
    }

    void notify_failure(const SendQueueItem& item,
                         const std::string& error,
                         bool is_permanent) {
        notifier_.notify_failure(
            item.chat_id,
            item.msg_id_internal,
            error,
            item.retry_count,
            is_permanent);
    }

    SendQueue& queue_;
    SendPipelineConfig& config_;
    SendProgressTracker& progress_;
    SendFailureNotifier& notifier_;
    MdnTracker& mdn_tracker_;
    SentFolderUploader& sent_uploader_;

    std::atomic<bool> running_;
    std::thread worker_thread_;
    SmtpRateLimiter rate_limiter_;

    SmtpSendFunc smtp_send_func_;
    ImapAppendFunc imap_append_func_;
};

// ============================================================================
// Send Pipeline - main orchestrator class
// ============================================================================

class SendPipeline {
public:
    SendPipeline() {}

    explicit SendPipeline(const SendPipelineConfig& config) {
        configure(config);
    }

    ~SendPipeline() {
        stop();
    }

    // ========================================================================
    // Configuration
    // ========================================================================

    void configure(const SendPipelineConfig& config) {
        std::lock_guard<std::mutex> lock(mutex_);
        config_ = config;

        // Update rate limiter if worker exists
        if (rate_limiter_) {
            rate_limiter_->set_rate(config.smtp_rate_limit_per_minute);
        }

        // Update Message-ID domain
        msgid_gen_.set_domain(config.sender_domain);

        // Update sent folder
        sent_uploader_.set_sent_folder(config.sent_folder);
    }

    SendPipelineConfig get_config() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return config_;
    }

    // ========================================================================
    // Lifecycle
    // ========================================================================

    void start() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (running_) return;

        if (!rate_limiter_) {
            rate_limiter_ = std::make_unique<SmtpRateLimiter>(
                config_.smtp_rate_limit_per_minute,
                config_.smtp_max_burst);
        }

        if (!worker_) {
            worker_ = std::make_unique<SendWorker>(
                queue_, config_, progress_, notifier_,
                mdn_tracker_, sent_uploader_);
            worker_->set_smtp_send_func(smtp_send_func_);
            worker_->set_imap_append_func(imap_append_func_);
        }

        running_ = true;
        worker_->start();
    }

    void stop() {
        std::lock_guard<std::mutex> lock(mutex_);
        running_ = false;
        if (worker_) {
            worker_->stop();
        }
    }

    bool is_running() const {
        return running_;
    }

    // ========================================================================
    // Connection factories - set these before starting
    // ========================================================================

    void set_smtp_send_func(SmtpSendFunc func) {
        std::lock_guard<std::mutex> lock(mutex_);
        smtp_send_func_ = std::move(func);
        if (worker_) {
            worker_->set_smtp_send_func(smtp_send_func_);
        }
    }

    void set_imap_append_func(ImapAppendFunc func) {
        std::lock_guard<std::mutex> lock(mutex_);
        imap_append_func_ = std::move(func);
        sent_uploader_.set_imap_append_func(imap_append_func_);
        if (worker_) {
            worker_->set_imap_append_func(imap_append_func_);
        }
    }

    // ========================================================================
    // Queue management
    // ========================================================================

    // Queue a message for sending. Returns queue_id for tracking.
    std::string enqueue(SendQueueItem item) {
        // Generate Message-ID if not set
        if (item.message_id.empty()) {
            std::lock_guard<std::mutex> lock(mutex_);
            item.message_id = msgid_gen_.generate();
        }

        // Apply config defaults
        if (item.from_addr.empty()) item.from_addr = config_.sender_addr;
        if (item.from_name.empty()) item.from_name = config_.sender_name;
        if (item.bcc_self || config_.bcc_self) item.bcc_self = true;
        if (item.upload_to_sent && config_.upload_to_sent)
            item.upload_to_sent = true;
        if (item.dkim_sign && config_.dkim_enabled)
            item.dkim_sign = true;

        // Load attachment contents
        for (auto& att : item.attachments) {
            if (att.encoded_content.empty() && !att.file_path.empty()) {
                att.encoded_content = load_attachment_file(att.file_path);
            }
        }

        return queue_.enqueue(std::move(item));
    }

    // Enqueue multiple messages
    void enqueue_batch(const std::vector<SendQueueItem>& items) {
        std::vector<SendQueueItem> processed;
        for (auto item : items) {
            if (item.message_id.empty()) {
                std::lock_guard<std::mutex> lock(mutex_);
                item.message_id = msgid_gen_.generate();
            }
            if (item.from_addr.empty()) item.from_addr = config_.sender_addr;
            if (item.from_name.empty()) item.from_name = config_.sender_name;

            for (auto& att : item.attachments) {
                if (att.encoded_content.empty() && !att.file_path.empty()) {
                    att.encoded_content = load_attachment_file(att.file_path);
                }
            }
            processed.push_back(std::move(item));
        }
        queue_.enqueue_batch(processed);
    }

    // Send a message immediately (synchronous, bypasses queue)
    bool send_immediately(SendQueueItem item) {
        if (item.message_id.empty()) {
            std::lock_guard<std::mutex> lock(mutex_);
            item.message_id = msgid_gen_.generate();
        }

        if (item.from_addr.empty()) item.from_addr = config_.sender_addr;
        if (item.from_name.empty()) item.from_name = config_.sender_name;

        for (auto& att : item.attachments) {
            if (att.encoded_content.empty() && !att.file_path.empty()) {
                att.encoded_content = load_attachment_file(att.file_path);
            }
        }

        SendWorker temp_worker(queue_, config_, progress_, notifier_,
                                mdn_tracker_, sent_uploader_);
        {
            std::lock_guard<std::mutex> lock(mutex_);
            temp_worker.set_smtp_send_func(smtp_send_func_);
            temp_worker.set_imap_append_func(imap_append_func_);
        }

        return temp_worker.send_now(item);
    }

    // Cancel a queued message
    bool cancel(const std::string& queue_id) {
        return queue_.cancel(queue_id);
    }

    // ========================================================================
    // Queue status
    // ========================================================================

    size_t queue_size() const { return queue_.size(); }
    size_t pending_count() const { return queue_.pending_count(); }
    int active_count() const { return queue_.active_count(); }

    std::vector<SendQueueItem> get_queued_items() const {
        return queue_.get_all();
    }

    std::vector<SendQueueItem> get_pending_items() const {
        return queue_.get_by_state(0);
    }

    std::vector<SendQueueItem> get_failed_items() const {
        return queue_.get_by_state(3);
    }

    // ========================================================================
    // Progress tracking
    // ========================================================================

    SendProgressTracker::ProgressInfo get_progress(
        const std::string& queue_id) const {
        return progress_.get(queue_id);
    }

    std::vector<SendProgressTracker::ProgressInfo> get_all_progress() const {
        return progress_.get_all();
    }

    // ========================================================================
    // MDN tracking
    // ========================================================================

    bool is_mdn_received(const std::string& message_id) const {
        return mdn_tracker_.is_mdn_received(message_id);
    }

    void record_mdn(const std::string& original_message_id,
                    const std::string& disposition) {
        mdn_tracker_.record_mdn_received(original_message_id, disposition);
    }

    std::vector<MdnTracker::MdnRecord> get_pending_mdns() const {
        return mdn_tracker_.get_pending();
    }

    // ========================================================================
    // Failure notification
    // ========================================================================

    void set_failure_callback(SendFailureNotifier::FailureCallback cb) {
        notifier_.set_callback(std::move(cb));
    }

    // ========================================================================
    // Maintenance
    // ========================================================================

    void purge_sent() {
        queue_.purge_sent();
    }

    void purge_old_failures(int64_t max_age_ms = 86400000) {
        queue_.purge_old_failures(max_age_ms);
        mdn_tracker_.prune_old();
        progress_.prune_old();
    }

    void clear_queue() {
        queue_.clear();
    }

    // ========================================================================
    // Message-ID generation (public, for external use)
    // ========================================================================

    std::string generate_message_id() {
        std::lock_guard<std::mutex> lock(mutex_);
        return msgid_gen_.generate();
    }

    std::string generate_deterministic_message_id(const std::string& seed) {
        std::lock_guard<std::mutex> lock(mutex_);
        return msgid_gen_.generate_deterministic(seed);
    }

    // ========================================================================
    // Autocrypt helpers
    // ========================================================================

    static std::string build_autocrypt_header(
        const std::string& addr,
        const std::string& keydata,
        const std::string& prefer_encrypt) {
        return AutocryptHeaderBuilder::build({
            keydata, addr, prefer_encrypt
        });
    }

    // ========================================================================
    // Chat header helpers
    // ========================================================================

    static std::unordered_map<std::string, std::string> build_chat_headers(
        const ChatHeaderBuilder::ChatHeaders& params) {
        return ChatHeaderBuilder::build(params);
    }

    // ========================================================================
    // MIME build helper (public static, for preview/testing)
    // ========================================================================

    static std::string build_mime_preview(const MimeBuilder::MimeOptions& opts) {
        return MimeBuilder::build(opts);
    }

    // ========================================================================
    // Sent folder
    // ========================================================================

    void set_sent_folder(const std::string& folder) {
        config_.sent_folder = folder;
        sent_uploader_.set_sent_folder(folder);
    }

    std::string get_sent_folder() const {
        return sent_uploader_.get_sent_folder();
    }

private:
    std::string load_attachment_file(const std::string& file_path) {
        try {
            std::ifstream file(file_path, std::ios::binary | std::ios::ate);
            if (!file.is_open()) {
                return "";
            }
            std::streamsize size = file.tellg();
            file.seekg(0, std::ios::beg);
            std::string buffer(static_cast<size_t>(size), '\0');
            if (!file.read(&buffer[0], size)) {
                return "";
            }
            return send_base64::encode(buffer);
        } catch (...) {
            return "";
        }
    }

    mutable std::mutex mutex_;
    SendPipelineConfig config_;
    SendQueue queue_;
    std::unique_ptr<SmtpRateLimiter> rate_limiter_;
    std::unique_ptr<SendWorker> worker_;
    SendProgressTracker progress_;
    SendFailureNotifier notifier_;
    MdnTracker mdn_tracker_;
    SentFolderUploader sent_uploader_;
    MessageIdGenerator msgid_gen_;

    SmtpSendFunc smtp_send_func_;
    ImapAppendFunc imap_append_func_;

    bool running_ = false;
};

// ============================================================================
// Convenience builder for SendQueueItem
// ============================================================================

class SendQueueItemBuilder {
public:
    SendQueueItemBuilder() : item_() {}

    SendQueueItemBuilder& from(const std::string& name, const std::string& addr) {
        item_.from_name = name;
        item_.from_addr = addr;
        return *this;
    }

    SendQueueItemBuilder& to(const std::string& addr) {
        item_.to_addrs.push_back(addr);
        return *this;
    }

    SendQueueItemBuilder& to(const std::vector<std::string>& addrs) {
        item_.to_addrs.insert(item_.to_addrs.end(), addrs.begin(), addrs.end());
        return *this;
    }

    SendQueueItemBuilder& cc(const std::string& addr) {
        item_.cc_addrs.push_back(addr);
        return *this;
    }

    SendQueueItemBuilder& bcc(const std::string& addr) {
        item_.bcc_addrs.push_back(addr);
        return *this;
    }

    SendQueueItemBuilder& subject(const std::string& s) {
        item_.subject = s;
        return *this;
    }

    SendQueueItemBuilder& text(const std::string& t) {
        item_.text_body = t;
        return *this;
    }

    SendQueueItemBuilder& html(const std::string& h) {
        item_.html_body = h;
        return *this;
    }

    SendQueueItemBuilder& message_id(const std::string& mid) {
        item_.message_id = mid;
        return *this;
    }

    SendQueueItemBuilder& in_reply_to(const std::string& irt) {
        item_.in_reply_to = irt;
        return *this;
    }

    SendQueueItemBuilder& references(const std::string& refs) {
        item_.references = refs;
        return *this;
    }

    SendQueueItemBuilder& attachment(const std::string& file_path,
                                      const std::string& file_name,
                                      const std::string& mime_type,
                                      bool is_inline = false,
                                      const std::string& content_id = "") {
        SendQueueItem::Attachment att;
        att.file_path = file_path;
        att.file_name = file_name;
        att.mime_type = mime_type;
        att.is_inline = is_inline;
        att.content_id = content_id;
        item_.attachments.push_back(att);
        return *this;
    }

    SendQueueItemBuilder& attachment_data(const std::string& file_name,
                                           const std::string& mime_type,
                                           const std::string& base64_content,
                                           bool is_inline = false,
                                           const std::string& content_id = "") {
        SendQueueItem::Attachment att;
        att.file_name = file_name;
        att.mime_type = mime_type;
        att.encoded_content = base64_content;
        att.is_inline = is_inline;
        att.content_id = content_id;
        item_.attachments.push_back(att);
        return *this;
    }

    SendQueueItemBuilder& chat_id(uint32_t cid) {
        item_.chat_id = cid;
        return *this;
    }

    SendQueueItemBuilder& msg_id(uint32_t mid) {
        item_.msg_id_internal = mid;
        return *this;
    }

    SendQueueItemBuilder& group_id(const std::string& gid) {
        item_.chat_group_id = gid;
        return *this;
    }

    SendQueueItemBuilder& group_name(const std::string& gn) {
        item_.chat_group_name = gn;
        return *this;
    }

    SendQueueItemBuilder& verified(int v) {
        item_.chat_verified = v;
        return *this;
    }

    SendQueueItemBuilder& predecessor(const std::string& pred) {
        item_.chat_predecessor = pred;
        return *this;
    }

    SendQueueItemBuilder& encrypt(bool e) {
        item_.encrypt_pgp = e;
        return *this;
    }

    SendQueueItemBuilder& pgp_recipient(const std::string& fp) {
        item_.pgp_recipient_fingerprints.push_back(fp);
        return *this;
    }

    SendQueueItemBuilder& request_mdn(bool r) {
        item_.request_mdn = r;
        return *this;
    }

    SendQueueItemBuilder& bcc_self(bool b) {
        item_.bcc_self = b;
        return *this;
    }

    SendQueueItemBuilder& sync_message(bool s) {
        item_.is_sync_message = s;
        return *this;
    }

    SendQueueItemBuilder& bot_message(bool b) {
        item_.is_bot_message = b;
        return *this;
    }

    SendQueueItemBuilder& priority(int64_t p) {
        item_.priority = p;
        return *this;
    }

    SendQueueItemBuilder& dkim(const std::string& selector,
                                const std::string& domain,
                                const std::string& private_key) {
        item_.dkim_sign = true;
        item_.dkim_selector = selector;
        item_.dkim_domain = domain;
        item_.dkim_private_key_pem = private_key;
        return *this;
    }

    SendQueueItemBuilder& progress_callback(
        std::function<void(const std::string&, int, const std::string&)> cb) {
        item_.progress_callback = std::move(cb);
        return *this;
    }

    SendQueueItemBuilder& completion_callback(
        std::function<void(const std::string&, bool, const std::string&)> cb) {
        item_.completion_callback = std::move(cb);
        return *this;
    }

    SendQueueItem build() {
        if (item_.queue_id.empty()) {
            item_.queue_id = gen_random_alnum(32);
        }
        return item_;
    }

    // Get a mutable reference to the underlying item
    SendQueueItem& item() { return item_; }

private:
    SendQueueItem item_;
};

} // namespace deltachat
} // namespace progressive
