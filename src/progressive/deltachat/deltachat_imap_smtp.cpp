// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Progressive Server Contributors
//
// DeltaChat IMAP/SMTP Connection Management
// Complete implementation of IMAP and SMTP protocol handling for DeltaChat

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

namespace progressive {
namespace deltachat {

// ============================================================================
// Forward declarations
// ============================================================================

class TransportInterface;
class ImapConnection;
class SmtpConnection;
class IdleWatcher;
class FolderSync;
class MessageFetch;
class MimeParser;

// ============================================================================
// Constants
// ============================================================================

constexpr int DEFAULT_IMAP_PORT = 993;
constexpr int DEFAULT_SMTP_PORT = 465;
constexpr int IMAP_INSECURE_PORT = 143;
constexpr int SMTP_INSECURE_PORT = 587;
constexpr int DEFAULT_IDLE_TIMEOUT_SECONDS = 1740;  // 29 minutes, under 30-min server limit
constexpr int MAX_RETRY_COUNT = 5;
constexpr int BASE_BACKOFF_MS = 1000;
constexpr int MAX_BACKOFF_MS = 32000;
constexpr int CONNECTION_POOL_MAX_SIZE = 4;
constexpr int CONNECTION_POOL_MAX_IDLE_SECONDS = 60;
constexpr int READ_BUFFER_SIZE = 65536;
constexpr int LINE_BUFFER_SIZE = 8192;
constexpr int MAX_LITERAL_SIZE = 104857600;  // 100 MB max literal
constexpr int DEFAULT_FETCH_BATCH_SIZE = 50;
constexpr const char* CRLF = "\r\n";

// ============================================================================
// Transport Interface - abstraction over actual socket I/O
// ============================================================================

class TransportInterface {
public:
    virtual ~TransportInterface() = default;

    // Connection management
    virtual bool connect(const std::string& host, int port, int timeout_seconds) = 0;
    virtual void disconnect() = 0;
    virtual bool is_connected() const = 0;

    // I/O operations
    virtual int read(char* buffer, int max_bytes, int timeout_seconds) = 0;
    virtual int write(const char* data, int length, int timeout_seconds) = 0;

    // SSL/TLS
    virtual bool start_tls() = 0;
    virtual bool is_tls_active() const = 0;

    // Connection info
    virtual std::string get_peer_address() const = 0;
    virtual int get_peer_port() const = 0;
};

// ============================================================================
// Default transport using BSD sockets (for reference/future use)
// ============================================================================

class DefaultTransport : public TransportInterface {
private:
    int sockfd_;
    bool connected_;
    bool tls_active_;
    std::string host_;
    int port_;

public:
    DefaultTransport()
        : sockfd_(-1)
        , connected_(false)
        , tls_active_(false)
        , port_(0) {}

    ~DefaultTransport() override {
        disconnect();
    }

    bool connect(const std::string& host, int port, int timeout_seconds) override {
        host_ = host;
        port_ = port;
        // In a full implementation, this would:
        // 1. Resolve hostname via getaddrinfo
        // 2. Create socket with socket()
        // 3. Set SO_RCVTIMEO and SO_SNDTIMEO
        // 4. Connect with connect()
        // 5. Set TCP_NODELAY
        // For now, the actual socket logic is deferred to platform-specific code
        connected_ = false;
        return false;
    }

    void disconnect() override {
        if (sockfd_ >= 0) {
            // close(sockfd_);
            sockfd_ = -1;
        }
        connected_ = false;
        tls_active_ = false;
    }

    bool is_connected() const override {
        return connected_;
    }

    int read(char* buffer, int max_bytes, int timeout_seconds) override {
        if (!connected_) return -1;
        // return ::recv(sockfd_, buffer, max_bytes, 0);
        return -1;
    }

    int write(const char* data, int length, int timeout_seconds) override {
        if (!connected_) return -1;
        // return ::send(sockfd_, data, length, MSG_NOSIGNAL);
        return -1;
    }

    bool start_tls() override {
        // In a full implementation, wrap socket with OpenSSL/GnuTLS
        tls_active_ = true;
        return true;
    }

    bool is_tls_active() const override {
        return tls_active_;
    }

    std::string get_peer_address() const override {
        return host_;
    }

    int get_peer_port() const override {
        return port_;
    }
};

// ============================================================================
// Base64 encoding/decoding utilities
// ============================================================================

namespace base64 {

static const char encoding_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char decoding_table[256] = {
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  // 0-15
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  // 16-31
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,  // 32-47  + at 43, / at 47
    52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,  // 48-63  0-9 at 52-61
    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,  // 64-79  A-Z at 0-25
    15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,  // 80-95
    -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,  // 96-111 a-z at 26-51
    41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,  // 112-127
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
};

std::string encode(const std::string& input) {
    std::string output;
    output.reserve(((input.size() + 2) / 3) * 4);

    for (size_t i = 0; i < input.size(); i += 3) {
        uint32_t octet_a = i < input.size() ? static_cast<unsigned char>(input[i]) : 0;
        uint32_t octet_b = i + 1 < input.size() ? static_cast<unsigned char>(input[i + 1]) : 0;
        uint32_t octet_c = i + 2 < input.size() ? static_cast<unsigned char>(input[i + 2]) : 0;
        uint32_t triple = (octet_a << 16) + (octet_b << 8) + octet_c;

        output.push_back(encoding_table[(triple >> 18) & 0x3F]);
        output.push_back(encoding_table[(triple >> 12) & 0x3F]);
        output.push_back(i + 1 < input.size()
            ? encoding_table[(triple >> 6) & 0x3F] : '=');
        output.push_back(i + 2 < input.size()
            ? encoding_table[triple & 0x3F] : '=');
    }

    return output;
}

std::string decode(const std::string& input) {
    std::string output;
    output.reserve((input.size() / 4) * 3);

    int val = 0;
    int valb = -8;

    for (unsigned char c : input) {
        if (c == '=') break;
        if (decoding_table[c] == -1) continue;
        val = (val << 6) + decoding_table[c];
        valb += 6;
        if (valb >= 0) {
            output.push_back(static_cast<char>((val >> valb) & 0xFF));
            valb -= 8;
        }
    }

    return output;
}

} // namespace base64

// ============================================================================
// Quoted-Printable decoding
// ============================================================================

namespace quoted_printable {

std::string decode(const std::string& input) {
    std::string output;
    output.reserve(input.size());

    for (size_t i = 0; i < input.size(); ++i) {
        if (input[i] == '=' && i + 2 < input.size()) {
            // Check if it's a soft line break
            if (input[i + 1] == '\r' && i + 2 < input.size() && input[i + 2] == '\n') {
                i += 2;  // skip =CRLF
                continue;
            }
            if (input[i + 1] == '\n') {
                i += 1;  // skip =LF
                continue;
            }
            // Hex decode
            char hex[3] = {input[i + 1], input[i + 2], 0};
            char* endptr = nullptr;
            long value = strtol(hex, &endptr, 16);
            if (endptr == hex + 2) {
                output.push_back(static_cast<char>(value));
                i += 2;
                continue;
            }
        }
        output.push_back(input[i]);
    }

    return output;
}

std::string encode(const std::string& input, size_t line_length) {
    std::string output;
    size_t line_pos = 0;

    for (unsigned char c : input) {
        bool needs_encode = (c < 33 || c == '=' || c > 126);
        if (needs_encode || (c == ' ' && line_pos + 1 == line_length)) {
            char buf[4];
            snprintf(buf, sizeof(buf), "=%02X", c);
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

} // namespace quoted_printable

// ============================================================================
// MIME encoded-word decoder (RFC 2047)
// ============================================================================

namespace mime_words {

std::string decode_encoded_word(const std::string& input) {
    std::string result;
    result.reserve(input.size());

    size_t pos = 0;
    while (pos < input.size()) {
        // Look for =?charset?encoding?text?=
        size_t eq = input.find("=?", pos);
        if (eq == std::string::npos) {
            result += input.substr(pos);
            break;
        }

        // Copy everything before the encoded word
        result += input.substr(pos, eq - pos);

        size_t q1 = input.find('?', eq + 2);
        if (q1 == std::string::npos) {
            result += input.substr(eq);
            break;
        }

        std::string charset = input.substr(eq + 2, q1 - eq - 2);

        size_t q2 = input.find('?', q1 + 1);
        if (q2 == std::string::npos) {
            result += input.substr(eq);
            break;
        }

        char encoding = std::toupper(input[q1 + 1]);

        size_t qend = input.find("?=", q2 + 1);
        if (qend == std::string::npos) {
            result += input.substr(eq);
            break;
        }

        std::string encoded_text = input.substr(q2 + 1, qend - q2 - 1);
        std::string decoded;

        if (encoding == 'B' || encoding == 'b') {
            // Base64 encoded
            decoded = base64::decode(encoded_text);
        } else if (encoding == 'Q' || encoding == 'q') {
            // Q-encoded (like quoted-printable)
            for (size_t i = 0; i < encoded_text.size(); ++i) {
                if (encoded_text[i] == '_') {
                    decoded.push_back(' ');
                } else if (encoded_text[i] == '=' && i + 2 < encoded_text.size()) {
                    char hex[3] = {encoded_text[i + 1], encoded_text[i + 2], 0};
                    char* endptr = nullptr;
                    long val = strtol(hex, &endptr, 16);
                    if (endptr == hex + 2) {
                        decoded.push_back(static_cast<char>(val));
                        i += 2;
                    } else {
                        decoded.push_back(encoded_text[i]);
                    }
                } else {
                    decoded.push_back(encoded_text[i]);
                }
            }
        } else {
            // Unknown encoding, use as-is
            decoded = encoded_text;
        }

        // For simplicity, assume UTF-8 from most charsets commonly used in email
        // A full implementation would do charset conversion
        result += decoded;

        pos = qend + 2;
    }

    return result;
}

} // namespace mime_words

// ============================================================================
// IMAP protocol handler
// ============================================================================

// IMAP response structure
struct ImapResponse {
    std::string tag;           // Tag for command responses
    std::string status;        // OK, NO, BAD, PREAUTH, BYE
    std::string status_text;   // Text after status
    std::vector<std::string> lines;  // All response lines including untagged
    bool is_continuation;      // Response starts with '+'
    std::string continuation_text;
};

// Fetch result for a single message
struct FetchResult {
    uint32_t uid = 0;
    uint32_t sequence = 0;
    uint32_t flags = 0;
    uint32_t size = 0;
    std::string internal_date;
    std::string envelope;
    std::string body_structure;
    std::string header_data;
    std::string body_data;
    std::string full_mime;
    std::vector<uint32_t> body_parts;
    bool seen = false;
    bool answered = false;
    bool flagged = false;
    bool deleted = false;
    bool draft = false;
    bool recent = false;
};

// IMAP flag constants
namespace imap_flags {
    constexpr uint32_t SEEN      = 1 << 0;
    constexpr uint32_t ANSWERED  = 1 << 1;
    constexpr uint32_t FLAGGED   = 1 << 2;
    constexpr uint32_t DELETED   = 1 << 3;
    constexpr uint32_t DRAFT     = 1 << 4;
    constexpr uint32_t RECENT    = 1 << 5;
}

// UID mapping entry
struct UidMapping {
    uint32_t uid;
    uint32_t uidvalidity;
    uint32_t sequence;
    std::string message_id;
    std::string folder;
    time_t last_seen;
};

// Server capabilities
struct ServerCapabilities {
    bool imap4rev1 = false;
    bool idle = false;
    bool move = false;
    bool condstore = false;
    bool compress = false;
    bool starttls = false;
    bool auth_plain = false;
    bool auth_login = false;
    bool auth_xoauth2 = false;
    bool namespace_cap = false;
    bool uidplus = false;
    bool listextended = false;
    bool special_use = false;
    bool searchres = false;
    bool esearch = false;
    bool enable = false;
    bool unselect = false;
    bool children = false;
    bool multiappend = false;
    bool binary = false;
    bool literal_plus = false;
    bool sasl_ir = false;
    std::string id_response;
    std::vector<std::string> auth_mechanisms;
    std::vector<std::string> raw_capabilities;
};

// Folder info
struct FolderInfo {
    std::string name;
    std::string delimiter;
    std::vector<std::string> attributes;
    bool selectable = true;
    bool has_children = false;
    bool no_inferiors = false;
    bool inbox = false;
    bool sent = false;
    bool drafts = false;
    bool trash = false;
    bool junk = false;
    bool archive = false;
};

// Status info
struct FolderStatus {
    uint32_t messages = 0;
    uint32_t recent = 0;
    uint32_t unseen = 0;
    uint32_t uidnext = 0;
    uint32_t uidvalidity = 0;
    uint32_t highest_mod_seq = 0;
};

// Message header info
struct MessageHeader {
    std::string from;
    std::string to;
    std::string cc;
    std::string bcc;
    std::string subject;
    std::string date;
    std::string message_id;
    std::string in_reply_to;
    std::string references;
    std::string content_type;
    std::string autocrypt;
    std::string autocrypt_setup_message;
    int chat_version = 0;
    std::string chat_group_id;
    std::string chat_group_name;
    std::string chat_verified;
    std::string chat_user_agent;
    std::string chat_content_type;
    uint32_t size = 0;
};

// Message body part
struct BodyPart {
    std::string part_id;
    std::string mime_type;
    std::string mime_subtype;
    std::string charset;
    std::string content_transfer_encoding;
    std::string filename;
    std::string content_id;
    std::string content_description;
    uint32_t size = 0;
    bool is_attachment = false;
    bool is_inline = false;
    bool is_text = false;
    std::string decoded_content;
};

// Full message
struct ParsedMessage {
    uint32_t uid = 0;
    uint32_t uidvalidity = 0;
    std::string folder;
    MessageHeader header;
    std::string text_body;
    std::string html_body;
    std::vector<BodyPart> attachments;
    std::string raw_mime;
    time_t fetch_time = 0;
    bool is_delta_chat = false;
};

// ============================================================================
// Connection pool
// ============================================================================

class ConnectionPool {
public:
    struct PooledConnection {
        std::shared_ptr<TransportInterface> transport;
        time_t last_used;
        bool in_use;
        std::string tag;
        int id;
    };

private:
    std::mutex mutex_;
    std::vector<PooledConnection> connections_;
    int next_id_ = 0;
    int max_size_;
    int max_idle_seconds_;
    std::function<std::shared_ptr<TransportInterface>()> factory_;

public:
    ConnectionPool(int max_size, int max_idle_seconds,
                   std::function<std::shared_ptr<TransportInterface>()> factory)
        : max_size_(max_size)
        , max_idle_seconds_(max_idle_seconds)
        , factory_(std::move(factory)) {}

    std::shared_ptr<TransportInterface> acquire() {
        std::lock_guard<std::mutex> lock(mutex_);

        // Clean up expired idle connections
        time_t now = time(nullptr);
        auto it = connections_.begin();
        while (it != connections_.end()) {
            if (!it->in_use && (now - it->last_used) > max_idle_seconds_) {
                it->transport->disconnect();
                it = connections_.erase(it);
            } else {
                ++it;
            }
        }

        // Find an idle connection
        for (auto& conn : connections_) {
            if (!conn.in_use && conn.transport->is_connected()) {
                conn.in_use = true;
                conn.last_used = now;
                return conn.transport;
            }
        }

        // Create new connection if under limit
        if (static_cast<int>(connections_.size()) < max_size_) {
            auto transport = factory_();
            if (transport && transport->is_connected()) {
                PooledConnection pc;
                pc.transport = transport;
                pc.last_used = now;
                pc.in_use = true;
                pc.tag = "C" + std::to_string(next_id_);
                pc.id = next_id_++;
                connections_.push_back(pc);
                return transport;
            }
        }

        return nullptr;
    }

    void release(std::shared_ptr<TransportInterface> transport) {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& conn : connections_) {
            if (conn.transport == transport) {
                conn.in_use = false;
                conn.last_used = time(nullptr);
                return;
            }
        }
    }

    void remove(std::shared_ptr<TransportInterface> transport) {
        std::lock_guard<std::mutex> lock(mutex_);
        connections_.erase(
            std::remove_if(connections_.begin(), connections_.end(),
                [&](const PooledConnection& c) {
                    return c.transport == transport;
                }),
            connections_.end());
    }

    void disconnect_all() {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& conn : connections_) {
            conn.transport->disconnect();
            conn.in_use = false;
        }
        connections_.clear();
    }

    size_t size() const {
        return connections_.size();
    }

    size_t idle_count() const {
        size_t count = 0;
        for (const auto& conn : connections_) {
            if (!conn.in_use) count++;
        }
        return count;
    }

    size_t active_count() const {
        size_t count = 0;
        for (const auto& conn : connections_) {
            if (conn.in_use) count++;
        }
        return count;
    }
};

// ============================================================================
// Reconnection manager with exponential backoff
// ============================================================================

class ReconnectionManager {
private:
    int max_retries_;
    int base_backoff_ms_;
    int max_backoff_ms_;
    int current_retry_;
    int current_backoff_ms_;
    std::mt19937 rng_;
    std::uniform_real_distribution<double> jitter_dist_;
    time_t last_success_;
    std::chrono::steady_clock::time_point last_attempt_;

public:
    ReconnectionManager(int max_retries = MAX_RETRY_COUNT,
                        int base_backoff_ms = BASE_BACKOFF_MS,
                        int max_backoff_ms = MAX_BACKOFF_MS)
        : max_retries_(max_retries)
        , base_backoff_ms_(base_backoff_ms)
        , max_backoff_ms_(max_backoff_ms)
        , current_retry_(0)
        , current_backoff_ms_(0)
        , rng_(std::random_device{}())
        , jitter_dist_(0.0, 1.0)
        , last_success_(0)
        , last_attempt_(std::chrono::steady_clock::now()) {}

    void reset() {
        current_retry_ = 0;
        current_backoff_ms_ = 0;
    }

    void mark_success() {
        reset();
        last_success_ = time(nullptr);
    }

    void mark_failure() {
        current_retry_++;
        last_attempt_ = std::chrono::steady_clock::now();
    }

    bool should_retry() const {
        return current_retry_ < max_retries_;
    }

    int get_backoff_ms() {
        if (current_retry_ == 0) return 0;

        // Exponential backoff: base * 2^retry with jitter
        int backoff = base_backoff_ms_ * (1 << std::min(current_retry_ - 1, 5));
        if (backoff > max_backoff_ms_) backoff = max_backoff_ms_;

        // Add jitter: +/- 25%
        double jitter = 0.75 + jitter_dist_(rng_) * 0.5;
        current_backoff_ms_ = static_cast<int>(backoff * jitter);

        return current_backoff_ms_;
    }

    void wait_backoff() {
        int ms = get_backoff_ms();
        if (ms > 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(ms));
        }
    }

    int retry_count() const { return current_retry_; }
    int max_retries() const { return max_retries_; }
    time_t last_success_time() const { return last_success_; }

    bool is_rate_limited() const {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - last_attempt_);
        return elapsed.count() < 100;  // Don't retry more than 10 times/sec
    }
};

// ============================================================================
// IMAP Tag generator
// ============================================================================

class TagGenerator {
private:
    std::atomic<uint32_t> counter_{0};
    std::string prefix_;

public:
    explicit TagGenerator(const std::string& prefix = "A")
        : prefix_(prefix) {}

    std::string next() {
        uint32_t val = counter_.fetch_add(1, std::memory_order_relaxed);
        char buf[32];
        snprintf(buf, sizeof(buf), "%s%04u", prefix_.c_str(), val % 10000);
        return std::string(buf);
    }

    void reset() {
        counter_.store(0, std::memory_order_relaxed);
    }
};

// ============================================================================
// Base connection class
// ============================================================================

class BaseConnection {
protected:
    std::shared_ptr<TransportInterface> transport_;
    std::string host_;
    int port_;
    std::string username_;
    std::string password_;
    bool use_ssl_;
    bool authenticated_;
    ServerCapabilities capabilities_;
    TagGenerator tag_gen_;
    ReconnectionManager reconnect_mgr_;
    std::mutex io_mutex_;
    std::string last_error_;
    time_t last_activity_;
    int timeout_seconds_;

    // Line buffer for reading responses
    std::string line_buffer_;
    size_t line_buffer_pos_ = 0;

public:
    BaseConnection()
        : port_(0)
        , use_ssl_(true)
        , authenticated_(false)
        , last_activity_(0)
        , timeout_seconds_(30) {}

    virtual ~BaseConnection() {
        disconnect();
    }

    void configure(const std::string& host, int port,
                   const std::string& username, const std::string& password,
                   bool use_ssl) {
        host_ = host;
        port_ = port;
        username_ = username;
        password_ = password;
        use_ssl_ = use_ssl;
    }

    void set_transport(std::shared_ptr<TransportInterface> transport) {
        transport_ = std::move(transport);
    }

    bool is_connected() const {
        return transport_ && transport_->is_connected();
    }

    bool is_authenticated() const {
        return authenticated_;
    }

    std::string get_last_error() const {
        std::lock_guard<std::mutex> lock(io_mutex_);
        return last_error_;
    }

    const ServerCapabilities& get_capabilities() const {
        return capabilities_;
    }

    void setTimeout(int seconds) {
        timeout_seconds_ = seconds;
    }

    void set_last_activity(time_t t) {
        last_activity_ = t;
    }

    time_t get_last_activity() const {
        return last_activity_;
    }

    virtual bool connect() {
        if (!transport_) {
            last_error_ = "No transport configured";
            return false;
        }

        if (!transport_->connect(host_, port_, timeout_seconds_)) {
            last_error_ = "Failed to connect to " + host_ + ":" + std::to_string(port_);
            return false;
        }

        last_activity_ = time(nullptr);
        line_buffer_.clear();
        line_buffer_pos_ = 0;
        tag_gen_.reset();

        // Read greeting
        auto greeting = read_response_line(timeout_seconds_);
        if (greeting.empty()) {
            last_error_ = "No greeting from server";
            return false;
        }

        // Check if greeting is valid
        if (greeting.size() < 4 || greeting[0] != '*' ||
            (greeting.find("OK") == std::string::npos &&
             greeting.find("PREAUTH") == std::string::npos)) {
            last_error_ = "Invalid greeting: " + greeting;
            return false;
        }

        return true;
    }

    void disconnect() {
        authenticated_ = false;
        line_buffer_.clear();
        line_buffer_pos_ = 0;
        if (transport_) {
            transport_->disconnect();
        }
    }

protected:
    // Write a line to the transport
    bool write_line(const std::string& line) {
        if (!transport_ || !transport_->is_connected()) {
            last_error_ = "Not connected";
            return false;
        }

        std::string data = line + CRLF;
        int written = transport_->write(data.c_str(), static_cast<int>(data.size()),
                                         timeout_seconds_);
        if (written != static_cast<int>(data.size())) {
            last_error_ = "Write failed";
            return false;
        }

        last_activity_ = time(nullptr);
        return true;
    }

    // Read a single line from the transport
    std::string read_response_line(int timeout) {
        std::string line;
        char c;
        bool got_cr = false;

        while (true) {
            int n = transport_->read(&c, 1, timeout);
            if (n <= 0) {
                // If we got nothing and line is empty, return empty
                if (line.empty()) return "";
                // Otherwise, return what we have (partial line)
                break;
            }

            last_activity_ = time(nullptr);

            if (got_cr && c == '\n') {
                // Remove the trailing CR from the line
                if (!line.empty() && line.back() == '\r') {
                    line.pop_back();
                }
                break;
            }

            got_cr = (c == '\r');
            if (!got_cr) {
                line.push_back(c);
            }

            // Safety limit
            if (line.size() > static_cast<size_t>(LINE_BUFFER_SIZE)) {
                last_error_ = "Line too long (>" + std::to_string(LINE_BUFFER_SIZE) + " bytes)";
                return line;
            }
        }

        return line;
    }

    // Read all response lines for a command until the tagged response
    ImapResponse read_tagged_response(const std::string& tag, int timeout) {
        ImapResponse response;
        response.tag = tag;

        while (true) {
            std::string line = read_response_line(timeout);
            if (line.empty()) {
                response.status = "NO";
                response.status_text = "Connection closed or timeout";
                return response;
            }

            // Handle continuation requests
            if (!line.empty() && line[0] == '+') {
                response.is_continuation = true;
                response.continuation_text = line.substr(1);
                // Strip leading space
                if (!response.continuation_text.empty() &&
                    response.continuation_text[0] == ' ') {
                    response.continuation_text.erase(0, 1);
                }
                response.lines.push_back(line);
                continue;
            }

            response.lines.push_back(line);

            // Check if this is the tagged response
            if (line.size() >= tag.size() + 1 &&
                line.compare(0, tag.size(), tag) == 0 &&
                line[tag.size()] == ' ') {

                // Parse status
                size_t status_pos = tag.size() + 1;
                if (line.size() > status_pos + 2) {
                    std::string status_str = line.substr(status_pos, 2);
                    if (status_str == "OK") {
                        response.status = "OK";
                        response.status_text = line.substr(status_pos + 3);
                    } else if (status_str == "NO") {
                        response.status = "NO";
                        response.status_text = line.substr(status_pos + 3);
                    } else if (status_str == "BA" && line.size() > status_pos + 2 &&
                               line[status_pos + 2] == 'D') {
                        response.status = "BAD";
                        response.status_text = line.substr(status_pos + 4);
                    } else {
                        response.status = status_str;
                        response.status_text = line.substr(status_pos);
                    }
                }
                response.is_continuation = false;
                break;
            }

            // Check for BYE
            if (line.find("* BYE") != std::string::npos) {
                response.status = "BYE";
                response.status_text = line.substr(line.find("BYE") + 4);
                break;
            }
        }

        return response;
    }

    // Send a command and get the tagged response
    ImapResponse send_command(const std::string& command, int timeout) {
        std::lock_guard<std::mutex> lock(io_mutex_);

        std::string tag = tag_gen_.next();
        std::string full_command = tag + " " + command;

        if (!write_line(full_command)) {
            ImapResponse error_response;
            error_response.tag = tag;
            error_response.status = "NO";
            error_response.status_text = last_error_;
            return error_response;
        }

        return read_tagged_response(tag, timeout);
    }

    // Send a command with a literal
    ImapResponse send_command_with_literal(
        const std::string& command_prefix,
        const std::string& literal_data,
        int timeout) {

        std::lock_guard<std::mutex> lock(io_mutex_);

        std::string tag = tag_gen_.next();
        std::string full_command = tag + " " + command_prefix + " {" +
            std::to_string(literal_data.size()) + "}";

        if (!write_line(full_command)) {
            ImapResponse error_response;
            error_response.tag = tag;
            error_response.status = "NO";
            error_response.status_text = last_error_;
            return error_response;
        }

        // Wait for continuation request
        std::string cont = read_response_line(timeout);
        if (cont.empty() || cont[0] != '+') {
            ImapResponse error_response;
            error_response.tag = tag;
            error_response.status = "NO";
            error_response.status_text = "Expected continuation but got: " + cont;
            // Read remaining response lines
            if (!cont.empty()) error_response.lines.push_back(cont);
            return error_response;
        }

        // Send the literal data
        if (!write_line(literal_data)) {
            ImapResponse error_response;
            error_response.tag = tag;
            error_response.status = "NO";
            error_response.status_text = last_error_;
            return error_response;
        }

        return read_tagged_response(tag, timeout);
    }

    // Parse a single untagged FETCH response line
    FetchResult parse_fetch_line(const std::string& line) {
        FetchResult result;

        // Expected format: * SEQ FETCH (UID uid FLAGS (flags) ...)
        size_t fetch_pos = line.find(" FETCH ");
        if (fetch_pos == std::string::npos) return result;

        // Get sequence number
        std::string seq_str;
        size_t space_pos = line.find(' ');
        if (space_pos != std::string::npos && space_pos < fetch_pos) {
            seq_str = line.substr(space_pos + 1, fetch_pos - space_pos - 1);
            result.sequence = static_cast<uint32_t>(strtoul(seq_str.c_str(), nullptr, 10));
        }

        // Parse parenthesized fetch data
        size_t data_start = fetch_pos + 7;  // " FETCH "
        std::string fetch_data = line.substr(data_start);

        // Remove outer parentheses
        if (!fetch_data.empty() && fetch_data[0] == '(') {
            fetch_data = fetch_data.substr(1);
            if (!fetch_data.empty() && fetch_data.back() == ')') {
                fetch_data.pop_back();
            }
        }

        // Tokenize: split by space but respect parenthesized groups and quoted strings
        std::vector<std::string> tokens;
        size_t i = 0;
        while (i < fetch_data.size()) {
            // Skip whitespace
            while (i < fetch_data.size() && fetch_data[i] == ' ') i++;
            if (i >= fetch_data.size()) break;

            if (fetch_data[i] == '(') {
                // Parenthesized group
                int depth = 1;
                size_t start = i;
                i++;
                while (i < fetch_data.size() && depth > 0) {
                    if (fetch_data[i] == '(') depth++;
                    else if (fetch_data[i] == ')') depth--;
                    else if (fetch_data[i] == '"') {
                        // Skip quoted strings inside parens
                        i++;
                        while (i < fetch_data.size() && fetch_data[i] != '"') {
                            if (fetch_data[i] == '\\') i++;
                            i++;
                        }
                    }
                    i++;
                }
                tokens.push_back(fetch_data.substr(start, i - start));
            } else if (fetch_data[i] == '"') {
                // Quoted string
                size_t start = i;
                i++;
                while (i < fetch_data.size() && fetch_data[i] != '"') {
                    if (fetch_data[i] == '\\') i++;
                    i++;
                }
                if (i < fetch_data.size()) i++;  // skip closing quote
                tokens.push_back(fetch_data.substr(start, i - start));
            } else if (fetch_data[i] == '{') {
                // Literal size
                size_t start = i;
                i++;
                while (i < fetch_data.size() && fetch_data[i] != '}') i++;
                if (i < fetch_data.size()) i++;  // skip }
                tokens.push_back(fetch_data.substr(start, i - start));
            } else {
                // Regular token
                size_t start = i;
                while (i < fetch_data.size() && fetch_data[i] != ' ' &&
                       fetch_data[i] != '(' && fetch_data[i] != ')') {
                    i++;
                }
                tokens.push_back(fetch_data.substr(start, i - start));
            }
        }

        // Parse tokens as key-value pairs
        for (size_t j = 0; j < tokens.size(); j++) {
            std::string tk = tokens[j];
            // Normalize to uppercase for comparison
            std::string tk_upper;
            tk_upper.reserve(tk.size());
            for (char c : tk) tk_upper.push_back(static_cast<char>(std::toupper(c)));

            if (tk_upper == "UID" && j + 1 < tokens.size()) {
                result.uid = static_cast<uint32_t>(strtoul(tokens[++j].c_str(), nullptr, 10));
            } else if (tk_upper == "FLAGS" && j + 1 < tokens.size()) {
                std::string flags_str = tokens[++j];
                // Parse parenthesized flag list
                if (!flags_str.empty() && flags_str[0] == '(') {
                    flags_str = flags_str.substr(1);
                    if (!flags_str.empty() && flags_str.back() == ')') {
                        flags_str.pop_back();
                    }
                }
                // Split flags by space
                std::istringstream fiss(flags_str);
                std::string flag;
                while (fiss >> flag) {
                    // Convert to uppercase for comparison
                    for (char& c : flag) c = static_cast<char>(std::toupper(c));
                    if (flag == "\\SEEN") result.seen = true;
                    else if (flag == "\\ANSWERED") result.answered = true;
                    else if (flag == "\\FLAGGED") result.flagged = true;
                    else if (flag == "\\DELETED") result.deleted = true;
                    else if (flag == "\\DRAFT") result.draft = true;
                    else if (flag == "\\RECENT") result.recent = true;
                }

                // Build flags bitmask
                if (result.seen) result.flags |= imap_flags::SEEN;
                if (result.answered) result.flags |= imap_flags::ANSWERED;
                if (result.flagged) result.flags |= imap_flags::FLAGGED;
                if (result.deleted) result.flags |= imap_flags::DELETED;
                if (result.draft) result.flags |= imap_flags::DRAFT;
                if (result.recent) result.flags |= imap_flags::RECENT;
            } else if (tk_upper == "RFC822.SIZE" && j + 1 < tokens.size()) {
                result.size = static_cast<uint32_t>(strtoul(tokens[++j].c_str(), nullptr, 10));
            } else if (tk_upper == "INTERNALDATE" && j + 1 < tokens.size()) {
                result.internal_date = tokens[++j];
                // Remove surrounding quotes
                if (result.internal_date.size() >= 2 &&
                    result.internal_date.front() == '"' &&
                    result.internal_date.back() == '"') {
                    result.internal_date = result.internal_date.substr(
                        1, result.internal_date.size() - 2);
                }
            } else if (tk_upper == "BODY[]" && j + 1 < tokens.size()) {
                result.body_data = tokens[++j];
            } else if (tk_upper == "BODY[HEADER]" && j + 1 < tokens.size()) {
                result.header_data = tokens[++j];
            } else if (tk_upper == "BODY[TEXT]" && j + 1 < tokens.size()) {
                result.body_data = tokens[++j];
            }
        }

        return result;
    }

    // Parse EXIST/RECENT/EXPUNGE responses from untagged lines
    void parse_untagged_status(const std::string& line, FolderStatus& status,
                               int& exists_count, int& recent_count) {
        // * N EXISTS
        size_t exists_pos = line.find(" EXISTS");
        if (exists_pos != std::string::npos && line[0] == '*') {
            std::string num_str = line.substr(2, exists_pos - 2);
            exists_count = static_cast<int>(strtol(num_str.c_str(), nullptr, 10));
        }

        // * N RECENT
        size_t recent_pos = line.find(" RECENT");
        if (recent_pos != std::string::npos && line[0] == '*') {
            std::string num_str = line.substr(2, recent_pos - 2);
            recent_count = static_cast<int>(strtol(num_str.c_str(), nullptr, 10));
        }
    }

    // Parse STATUS response
    FolderStatus parse_status_response(const ImapResponse& response) {
        FolderStatus status;

        for (const auto& line : response.lines) {
            if (line.compare(0, 8, "* STATUS") != 0) continue;

            // * STATUS folder (MESSAGES N ...)
            std::string rest = line.substr(8);
            // Find first '('
            size_t paren = rest.find('(');
            if (paren == std::string::npos) continue;

            std::string status_data = rest.substr(paren);
            // Remove outer parens
            if (!status_data.empty() && status_data[0] == '(') {
                status_data = status_data.substr(1);
            }
            if (!status_data.empty() && status_data.back() == ')') {
                status_data.pop_back();
            }

            std::istringstream ss(status_data);
            std::string key;
            while (ss >> key) {
                std::string key_upper;
                for (char c : key) key_upper.push_back(static_cast<char>(std::toupper(c)));

                uint32_t value = 0;
                if (ss >> value) {
                    if (key_upper == "MESSAGES") status.messages = value;
                    else if (key_upper == "RECENT") status.recent = value;
                    else if (key_upper == "UNSEEN") status.unseen = value;
                    else if (key_upper == "UIDNEXT") status.uidnext = value;
                    else if (key_upper == "UIDVALIDITY") status.uidvalidity = value;
                    else if (key_upper == "HIGHESTMODSEQ") status.highest_mod_seq = value;
                }
            }
        }

        return status;
    }

    // NIL or quoted string parser
    std::string parse_nil_or_string(const std::string& token) {
        if (token == "NIL") return "";
        if (token.size() >= 2 && token.front() == '"' && token.back() == '"') {
            return token.substr(1, token.size() - 2);
        }
        return token;
    }
};

// ============================================================================
// IMAP Connection Manager
// ============================================================================

class ImapConnection : public BaseConnection {
private:
    std::string current_folder_;
    uint32_t current_uidvalidity_ = 0;
    FolderStatus current_status_;
    std::unordered_map<std::string, FolderInfo> folder_cache_;
    std::deque<UidMapping> uid_mappings_;
    bool idle_supported_ = false;
    bool idle_active_ = false;

public:
    ImapConnection() : BaseConnection() {
        tag_gen_ = TagGenerator("IM");
        timeout_seconds_ = 30;
    }

    // ========================================================================
    // Connection & Login
    // ========================================================================

    bool connect_and_login() {
        reconnect_mgr_.reset();
        bool success = false;

        while (reconnect_mgr_.should_retry()) {
            if (reconnect_mgr_.is_rate_limited()) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                continue;
            }

            // Connect
            if (!connect()) {
                reconnect_mgr_.mark_failure();
                reconnect_mgr_.wait_backoff();
                continue;
            }

            // If not using direct SSL, try STARTTLS
            if (!use_ssl_ && capabilities_.starttls) {
                if (!starttls()) {
                    disconnect();
                    reconnect_mgr_.mark_failure();
                    reconnect_mgr_.wait_backoff();
                    continue;
                }
            }

            // Get capabilities post-TLS
            if (!fetch_capabilities()) {
                disconnect();
                reconnect_mgr_.mark_failure();
                reconnect_mgr_.wait_backoff();
                continue;
            }

            // Login
            if (!login()) {
                disconnect();
                reconnect_mgr_.mark_failure();
                reconnect_mgr_.wait_backoff();
                continue;
            }

            // Fetch capabilities again post-login (some servers reveal more)
            fetch_capabilities();

            success = true;
            break;
        }

        if (success) {
            reconnect_mgr_.mark_success();
        }

        return success;
    }

    bool login() {
        if (capabilities_.auth_xoauth2) {
            // Try OAUTH2 first if available
            auto response = send_command(
                "AUTHENTICATE XOAUTH2 " + base64::encode(
                    "user=" + username_ + "\x01auth=Bearer " + password_ + "\x01\x01"),
                timeout_seconds_);
            if (response.status == "OK") {
                authenticated_ = true;
                return true;
            }
        }

        // Try LOGIN command (most common)
        std::string login_cmd = "LOGIN " + quote_string(username_) +
            " " + quote_string(password_);
        auto response = send_command(login_cmd, timeout_seconds_);

        if (response.status == "OK") {
            authenticated_ = true;
            return true;
        }

        last_error_ = response.status_text;
        return false;
    }

    bool logout() {
        if (!authenticated_) return true;

        auto response = send_command("LOGOUT", 5);
        authenticated_ = false;
        current_folder_.clear();
        return response.status == "OK" || response.status == "BYE";
    }

    // ========================================================================
    // Capabilities
    // ========================================================================

    bool fetch_capabilities() {
        auto response = send_command("CAPABILITY", timeout_seconds_);

        if (response.status != "OK") {
            last_error_ = "CAPABILITY failed: " + response.status_text;
            return false;
        }

        capabilities_ = ServerCapabilities{};

        for (const auto& line : response.lines) {
            if (line.find("* CAPABILITY") == std::string::npos) continue;

            std::string caps;
            size_t cap_pos = line.find("CAPABILITY");
            if (cap_pos != std::string::npos) {
                caps = line.substr(cap_pos + 10);
                // Trim leading space
                size_t start = 0;
                while (start < caps.size() && caps[start] == ' ') start++;
                caps = caps.substr(start);
            }

            std::istringstream ss(caps);
            std::string cap;
            while (ss >> cap) {
                std::string cap_upper;
                for (char c : cap) cap_upper.push_back(static_cast<char>(std::toupper(c)));
                capabilities_.raw_capabilities.push_back(cap);

                if (cap_upper == "IMAP4REV1") capabilities_.imap4rev1 = true;
                else if (cap_upper == "IDLE") capabilities_.idle = true;
                else if (cap_upper == "MOVE") capabilities_.move = true;
                else if (cap_upper == "CONDSTORE") capabilities_.condstore = true;
                else if (cap_upper == "COMPRESS" || cap_upper == "COMPRESS=DEFLATE")
                    capabilities_.compress = true;
                else if (cap_upper == "STARTTLS") capabilities_.starttls = true;
                else if (cap_upper.find("AUTH=") == 0) {
                    capabilities_.auth_mechanisms.push_back(cap.substr(5));
                    std::string mech_upper = cap_upper.substr(5);
                    if (mech_upper == "PLAIN") capabilities_.auth_plain = true;
                    else if (mech_upper == "LOGIN") capabilities_.auth_login = true;
                    else if (mech_upper == "XOAUTH2") capabilities_.auth_xoauth2 = true;
                } else if (cap_upper == "AUTH=PLAIN") capabilities_.auth_plain = true;
                else if (cap_upper == "AUTH=LOGIN") capabilities_.auth_login = true;
                else if (cap_upper == "NAMESPACE") capabilities_.namespace_cap = true;
                else if (cap_upper == "UIDPLUS") capabilities_.uidplus = true;
                else if (cap_upper == "LIST-EXTENDED") capabilities_.listextended = true;
                else if (cap_upper == "SPECIAL-USE") capabilities_.special_use = true;
                else if (cap_upper == "SEARCHRES") capabilities_.searchres = true;
                else if (cap_upper == "ESEARCH") capabilities_.esearch = true;
                else if (cap_upper == "ENABLE") capabilities_.enable = true;
                else if (cap_upper == "UNSELECT") capabilities_.unselect = true;
                else if (cap_upper == "CHILDREN") capabilities_.children = true;
                else if (cap_upper == "MULTIAPPEND") capabilities_.multiappend = true;
                else if (cap_upper == "BINARY") capabilities_.binary = true;
                else if (cap_upper == "LITERAL+") capabilities_.literal_plus = true;
                else if (cap_upper == "SASL-IR") capabilities_.sasl_ir = true;
            }
        }

        idle_supported_ = capabilities_.idle;

        // Enable useful extensions
        if (capabilities_.enable) {
            std::string enable_cmd = "ENABLE";
            if (capabilities_.condstore) enable_cmd += " CONDSTORE";
            if (capabilities_.uidplus) enable_cmd += " UIDPLUS";
            send_command(enable_cmd, timeout_seconds_);
        }

        return true;
    }

    // ========================================================================
    // STARTTLS
    // ========================================================================

    bool starttls() {
        auto response = send_command("STARTTLS", timeout_seconds_);
        if (response.status != "OK") {
            last_error_ = "STARTTLS rejected: " + response.status_text;
            return false;
        }

        if (!transport_->start_tls()) {
            last_error_ = "TLS handshake failed";
            return false;
        }

        return true;
    }

    // ========================================================================
    // ID
    // ========================================================================

    bool send_id(const std::string& name, const std::string& version) {
        std::string id_params = "(\"name\" \"" + name + "\" \"version\" \"" + version + "\")";
        auto response = send_command("ID " + id_params, timeout_seconds_);

        if (response.status == "OK") {
            // Parse server ID response
            for (const auto& line : response.lines) {
                if (line.find("* ID") != std::string::npos) {
                    capabilities_.id_response = line;
                }
            }
            return true;
        }

        return false;
    }

    // ========================================================================
    // Folder operations
    // ========================================================================

    bool select_folder(const std::string& folder_name, bool read_only = false) {
        std::string cmd = read_only ? "EXAMINE " : "SELECT ";
        cmd += quote_utf7_folder(folder_name);

        auto response = send_command(cmd, timeout_seconds_);
        if (response.status != "OK") {
            last_error_ = "Failed to select folder: " + response.status_text;
            return false;
        }

        current_folder_ = folder_name;

        // Parse untagged responses for UIDVALIDITY, etc.
        for (const auto& line : response.lines) {
            // UIDVALIDITY
            size_t uidv_pos = line.find("UIDVALIDITY");
            if (uidv_pos != std::string::npos) {
                std::string rest = line.substr(uidv_pos + 11);
                // Trim and parse
                size_t start = 0;
                while (start < rest.size() && rest[start] == ' ') start++;
                current_uidvalidity_ = static_cast<uint32_t>(
                    strtoul(rest.c_str() + start, nullptr, 10));
            }

            // EXISTS count
            size_t exists_pos = line.find(" EXISTS");
            if (exists_pos != std::string::npos) {
                std::string num_str;
                size_t space = line.rfind(' ', exists_pos - 1);
                if (space != std::string::npos) {
                    num_str = line.substr(space + 1, exists_pos - space - 1);
                    current_status_.messages = static_cast<uint32_t>(
                        strtoul(num_str.c_str(), nullptr, 10));
                }
            }

            // RECENT count
            size_t recent_pos = line.find(" RECENT");
            if (recent_pos != std::string::npos) {
                std::string num_str;
                size_t space = line.rfind(' ', recent_pos - 1);
                if (space != std::string::npos) {
                    num_str = line.substr(space + 1, recent_pos - space - 1);
                    current_status_.recent = static_cast<uint32_t>(
                        strtoul(num_str.c_str(), nullptr, 10));
                }
            }

            // UNSEEN
            size_t unseen_pos = line.find("UNSEEN");
            if (unseen_pos != std::string::npos) {
                std::string rest = line.substr(unseen_pos + 6);
                // Format: OK [UNSEEN N]
                size_t bracket = rest.find(']');
                if (bracket != std::string::npos) {
                    std::string inner = rest.substr(0, bracket);
                    size_t space = inner.rfind(' ');
                    if (space != std::string::npos) {
                        std::string num = inner.substr(space + 1);
                        current_status_.unseen = static_cast<uint32_t>(
                            strtoul(num.c_str(), nullptr, 10));
                    }
                }
            }

            // UIDNEXT
            size_t uidn_pos = line.find("UIDNEXT");
            if (uidn_pos != std::string::npos) {
                std::string rest = line.substr(uidn_pos + 7);
                size_t bracket = rest.find(']');
                if (bracket != std::string::npos) {
                    std::string inner = rest.substr(0, bracket);
                    size_t space = inner.rfind(' ');
                    if (space != std::string::npos) {
                        std::string num = inner.substr(space + 1);
                        current_status_.uidnext = static_cast<uint32_t>(
                            strtoul(num.c_str(), nullptr, 10));
                    }
                }
            }
        }

        return true;
    }

    bool unselect_folder() {
        if (current_folder_.empty()) return true;

        if (capabilities_.unselect) {
            auto response = send_command("UNSELECT", timeout_seconds_);
            current_folder_.clear();
            return response.status == "OK";
        }

        // Fallback: close by selecting a non-existent folder or using CLOSE
        auto response = send_command("CLOSE", timeout_seconds_);
        current_folder_.clear();
        return response.status == "OK";
    }

    bool create_folder(const std::string& folder_name) {
        auto response = send_command("CREATE " + quote_utf7_folder(folder_name),
                                      timeout_seconds_);
        return response.status == "OK";
    }

    bool delete_folder(const std::string& folder_name) {
        auto response = send_command("DELETE " + quote_utf7_folder(folder_name),
                                      timeout_seconds_);
        return response.status == "OK";
    }

    bool rename_folder(const std::string& old_name, const std::string& new_name) {
        auto response = send_command("RENAME " + quote_utf7_folder(old_name) +
                                      " " + quote_utf7_folder(new_name),
                                      timeout_seconds_);
        return response.status == "OK";
    }

    bool subscribe_folder(const std::string& folder_name) {
        auto response = send_command("SUBSCRIBE " + quote_utf7_folder(folder_name),
                                      timeout_seconds_);
        return response.status == "OK";
    }

    bool unsubscribe_folder(const std::string& folder_name) {
        auto response = send_command("UNSUBSCRIBE " + quote_utf7_folder(folder_name),
                                      timeout_seconds_);
        return response.status == "OK";
    }

    std::vector<FolderInfo> list_folders(const std::string& reference = "",
                                          const std::string& mailbox = "*") {
        std::vector<FolderInfo> folders;

        std::string cmd = "LIST";
        if (capabilities_.special_use) {
            cmd += " (SPECIAL-USE)";
        }
        cmd += " " + quote_string(reference) + " " + quote_string(mailbox);

        if (capabilities_.listextended) {
            cmd += " RETURN (SUBSCRIBED CHILDREN)";
        }

        auto response = send_command(cmd, timeout_seconds_);
        if (response.status != "OK") {
            last_error_ = "LIST failed: " + response.status_text;
            return folders;
        }

        for (const auto& line : response.lines) {
            if (line.compare(0, 6, "* LIST") != 0 && line.compare(0, 7, "* XLIST") != 0) {
                continue;
            }

            FolderInfo info;

            // Find attribute list in parentheses
            size_t attr_start = line.find('(');
            if (attr_start == std::string::npos) continue;
            size_t attr_end = line.find(')', attr_start);
            if (attr_end == std::string::npos) continue;

            std::string attr_str = line.substr(attr_start + 1, attr_end - attr_start - 1);
            std::istringstream ass(attr_str);
            std::string attr;
            while (ass >> attr) {
                // Remove backslash prefix
                if (!attr.empty() && attr[0] == '\\') {
                    attr = attr.substr(1);
                }
                std::string attr_upper;
                for (char c : attr) attr_upper.push_back(static_cast<char>(std::toupper(c)));

                info.attributes.push_back(attr_upper);

                if (attr_upper == "NOSELECT") info.selectable = false;
                else if (attr_upper == "HASNOCHILDREN") info.has_children = false;
                else if (attr_upper == "HASCHILDREN") info.has_children = true;
                else if (attr_upper == "NOINFERIORS") info.no_inferiors = true;
                else if (attr_upper == "INBOX") info.inbox = true;
                else if (attr_upper == "SENT") info.sent = true;
                else if (attr_upper == "DRAFTS") info.drafts = true;
                else if (attr_upper == "TRASH") info.trash = true;
                else if (attr_upper == "JUNK" || attr_upper == "SPAM") info.junk = true;
                else if (attr_upper == "ARCHIVE") info.archive = true;
            }

            // Find delimiter
            size_t delim_start = attr_end + 1;
            while (delim_start < line.size() && line[delim_start] == ' ') delim_start++;
            if (delim_start < line.size()) {
                if (line[delim_start] == '"') {
                    size_t qend = line.find('"', delim_start + 1);
                    if (qend != std::string::npos) {
                        info.delimiter = line.substr(delim_start + 1, qend - delim_start - 1);
                        delim_start = qend + 1;
                    }
                } else if (line.substr(delim_start, 3) == "NIL") {
                    info.delimiter = "";
                    delim_start += 3;
                }
            }

            // Find mailbox name
            while (delim_start < line.size() && line[delim_start] == ' ') delim_start++;
            if (delim_start < line.size()) {
                info.name = parse_nil_or_string(line.substr(delim_start));
            }

            if (!info.name.empty()) {
                // Detect special folders by name if not already detected
                std::string name_lower;
                for (char c : info.name) name_lower.push_back(static_cast<char>(std::tolower(c)));

                if (name_lower == "inbox") info.inbox = true;
                else if (name_lower.find("sent") != std::string::npos) info.sent = true;
                else if (name_lower.find("draft") != std::string::npos) info.drafts = true;
                else if (name_lower.find("trash") != std::string::npos ||
                         name_lower.find("deleted") != std::string::npos) info.trash = true;
                else if (name_lower.find("spam") != std::string::npos ||
                         name_lower.find("junk") != std::string::npos) info.junk = true;
                else if (name_lower.find("archive") != std::string::npos) info.archive = true;

                folders.push_back(info);
                folder_cache_[info.name] = info;
            }
        }

        return folders;
    }

    FolderStatus get_folder_status(const std::string& folder_name) {
        FolderStatus status;
        std::string items = "MESSAGES RECENT UNSEEN UIDNEXT UIDVALIDITY";
        if (capabilities_.condstore) {
            items += " HIGHESTMODSEQ";
        }

        auto response = send_command("STATUS " + quote_utf7_folder(folder_name) +
                                      " (" + items + ")", timeout_seconds_);

        if (response.status != "OK") {
            last_error_ = "STATUS failed: " + response.status_text;
            return status;
        }

        return parse_status_response(response);
    }

    // ========================================================================
    // Message search
    // ========================================================================

    std::vector<uint32_t> search_uids(const std::string& criteria) {
        std::vector<uint32_t> uids;

        auto response = send_command("UID SEARCH " + criteria, timeout_seconds_);
        if (response.status != "OK") {
            last_error_ = "SEARCH failed: " + response.status_text;
            return uids;
        }

        for (const auto& line : response.lines) {
            if (line.find("* SEARCH") == std::string::npos) continue;

            std::string rest = line.substr(line.find("SEARCH") + 7);
            std::istringstream ss(rest);
            uint32_t uid;
            while (ss >> uid) {
                uids.push_back(uid);
            }
        }

        return uids;
    }

    // Search all messages
    std::vector<uint32_t> search_all() {
        return search_uids("ALL");
    }

    // Search unseen messages
    std::vector<uint32_t> search_unseen() {
        return search_uids("UNSEEN");
    }

    // Search messages since a specific UID
    std::vector<uint32_t> search_since_uid(uint32_t uid) {
        return search_uids("UID " + std::to_string(uid) + ":*");
    }

    // Search messages newer than a date
    std::vector<uint32_t> search_since_date(const std::string& date) {
        return search_uids("SINCE " + date);
    }

    // Search for DeltaChat messages
    std::vector<uint32_t> search_delta_chat() {
        // DeltaChat messages have Chat-Version header
        return search_uids("HEADER Chat-Version \"\"");
    }

    // ========================================================================
    // Message fetch
    // ========================================================================

    // Fetch message headers by UID
    std::vector<FetchResult> fetch_headers(const std::vector<uint32_t>& uids) {
        return fetch_messages(uids, "(UID FLAGS RFC822.SIZE INTERNALDATE BODY.PEEK[HEADER.FIELDS (FROM TO CC BCC SUBJECT DATE MESSAGE-ID IN-REPLY-TO REFERENCES CONTENT-TYPE AUTOCRYPT AUTOCRYPT-SETUP-MESSAGE CHAT-VERSION CHAT-GROUP-ID CHAT-GROUP-NAME CHAT-VERIFIED CHAT-USER-AVATAR CHAT-CONTENT-TYPE)])");
    }

    // Fetch message bodies by UID
    std::vector<FetchResult> fetch_bodies(const std::vector<uint32_t>& uids) {
        return fetch_messages(uids, "(UID FLAGS BODY.PEEK[TEXT])");
    }

    // Fetch full messages by UID
    std::vector<FetchResult> fetch_full(const std::vector<uint32_t>& uids) {
        return fetch_messages(uids, "(UID FLAGS RFC822.SIZE INTERNALDATE BODY.PEEK[])");
    }

    // Generic fetch
    std::vector<FetchResult> fetch_messages(const std::vector<uint32_t>& uids,
                                              const std::string& fetch_items) {
        std::vector<FetchResult> results;

        if (uids.empty()) return results;

        // Build UID set - for efficiency, use ranges when possible
        std::string uid_set = build_uid_set(uids);

        std::string command = "UID FETCH " + uid_set + " " + fetch_items;

        auto response = send_command(command, timeout_seconds_ * 2);
        if (response.status != "OK") {
            last_error_ = "FETCH failed: " + response.status_text;
            return results;
        }

        for (const auto& line : response.lines) {
            if (line.find(" FETCH ") != std::string::npos) {
                results.push_back(parse_fetch_line(line));
            }
        }

        return results;
    }

    // Fetch message flags by UID
    std::vector<FetchResult> fetch_flags(const std::vector<uint32_t>& uids) {
        return fetch_messages(uids, "(UID FLAGS)");
    }

    // ========================================================================
    // Message flags manipulation
    // ========================================================================

    bool store_flags(const std::vector<uint32_t>& uids,
                     const std::string& flags_operation,
                     const std::string& flags) {
        if (uids.empty()) return true;

        std::string uid_set = build_uid_set(uids);
        std::string command = "UID STORE " + uid_set + " " + flags_operation + " (" + flags + ")";

        auto response = send_command(command, timeout_seconds_);
        return response.status == "OK";
    }

    bool mark_seen(const std::vector<uint32_t>& uids) {
        return store_flags(uids, "+FLAGS", "\\Seen");
    }

    bool mark_unseen(const std::vector<uint32_t>& uids) {
        return store_flags(uids, "-FLAGS", "\\Seen");
    }

    bool mark_deleted(const std::vector<uint32_t>& uids) {
        return store_flags(uids, "+FLAGS", "\\Deleted");
    }

    bool mark_flagged(const std::vector<uint32_t>& uids) {
        return store_flags(uids, "+FLAGS", "\\Flagged");
    }

    bool add_flags(const std::vector<uint32_t>& uids, const std::string& custom_flags) {
        return store_flags(uids, "+FLAGS", custom_flags);
    }

    bool remove_flags(const std::vector<uint32_t>& uids, const std::string& custom_flags) {
        return store_flags(uids, "-FLAGS", custom_flags);
    }

    // ========================================================================
    // Message copy and move
    // ========================================================================

    bool copy_messages(const std::vector<uint32_t>& uids,
                       const std::string& destination_folder) {
        if (uids.empty()) return true;

        std::string uid_set = build_uid_set(uids);
        std::string command = "UID COPY " + uid_set + " " +
            quote_utf7_folder(destination_folder);

        auto response = send_command(command, timeout_seconds_);
        return response.status == "OK";
    }

    bool move_messages(const std::vector<uint32_t>& uids,
                       const std::string& destination_folder) {
        if (uids.empty()) return true;

        if (capabilities_.move) {
            // Use native MOVE command
            std::string uid_set = build_uid_set(uids);
            std::string command = "UID MOVE " + uid_set + " " +
                quote_utf7_folder(destination_folder);

            auto response = send_command(command, timeout_seconds_);
            return response.status == "OK";
        }

        // Fallback: COPY + STORE + EXPUNGE
        if (!copy_messages(uids, destination_folder)) {
            return false;
        }

        if (!store_flags(uids, "+FLAGS", "\\Deleted")) {
            return false;
        }

        return expunge();
    }

    bool move_to_delta_chat_folder(const std::vector<uint32_t>& uids,
                                     const std::string& mvbox_folder) {
        // DeltaChat MVBOX handling: move messages to the DeltaChat folder
        if (mvbox_folder.empty()) {
            // No MVBOX configured, just mark as deleted
            return store_flags(uids, "+FLAGS", "\\Deleted \\Seen");
        }

        return move_messages(uids, mvbox_folder);
    }

    // ========================================================================
    // Message append
    // ========================================================================

    bool append_message(const std::string& folder, const std::string& mime_message,
                        const std::vector<std::string>& flags = {"\\Seen"},
                        const std::string& internal_date = "") {
        std::string command = "APPEND " + quote_utf7_folder(folder);

        // Add flags
        if (!flags.empty()) {
            command += " (";
            for (size_t i = 0; i < flags.size(); ++i) {
                if (i > 0) command += " ";
                command += flags[i];
            }
            command += ")";
        }

        // Add internal date
        if (!internal_date.empty()) {
            command += " " + quote_string(internal_date);
        }

        // Use literal+
        if (capabilities_.literal_plus) {
            command += " {" + std::to_string(mime_message.size()) + "+}";
            auto response = send_command(command, timeout_seconds_);
            if (response.status != "OK" && !response.is_continuation) {
                last_error_ = "APPEND failed: " + response.status_text;
                return false;
            }
        } else {
            command += " {" + std::to_string(mime_message.size()) + "}";
        }

        // Send the message data
        auto response = send_command_with_literal(
            "APPEND " + quote_utf7_folder(folder) +
                (flags.empty() ? "" : " (" + join_strings(flags, " ") + ")") +
                (internal_date.empty() ? "" : " " + quote_string(internal_date)),
            mime_message, timeout_seconds_ * 3);

        return response.status == "OK";
    }

    // ========================================================================
    // Expunge
    // ========================================================================

    bool expunge() {
        auto response = send_command("EXPUNGE", timeout_seconds_);
        return response.status == "OK";
    }

    bool uid_expunge(const std::vector<uint32_t>& uids) {
        if (!capabilities_.uidplus) {
            // Fallback: mark deleted and expunge
            store_flags(uids, "+FLAGS", "\\Deleted");
            return expunge();
        }

        std::string uid_set = build_uid_set(uids);
        auto response = send_command("UID EXPUNGE " + uid_set, timeout_seconds_);
        return response.status == "OK";
    }

    // ========================================================================
    // IDLE management
    // ========================================================================

    bool start_idle() {
        if (!idle_supported_) return false;
        if (idle_active_) return true;

        auto response = send_command("IDLE", timeout_seconds_);
        if (response.is_continuation) {
            idle_active_ = true;
            return true;
        }

        return false;
    }

    bool stop_idle() {
        if (!idle_active_) return false;

        // Send DONE to terminate IDLE
        bool result = write_line("DONE");
        idle_active_ = false;

        // Read the remaining response
        read_tagged_response("", 5);
        return result;
    }

    ImapResponse idle_check(int timeout_seconds = 1) {
        ImapResponse response;
        response.tag = "IDLE";

        if (!idle_active_) return response;

        while (true) {
            std::string line = read_response_line(timeout_seconds);
            if (line.empty()) {
                // Timeout or disconnect
                break;
            }

            response.lines.push_back(line);

            // Check for untagged responses
            if (line.find(" EXISTS") != std::string::npos ||
                line.find(" RECENT") != std::string::npos ||
                line.find(" EXPUNGE") != std::string::npos ||
                line.find(" FETCH") != std::string::npos) {
                break;
            }
        }

        return response;
    }

    bool is_idle_active() const {
        return idle_active_;
    }

    bool supports_idle() const {
        return idle_supported_;
    }

    // ========================================================================
    // Fetch existing messages (prefetch mode)
    // ========================================================================

    std::vector<FetchResult> fetch_existing_msgs(uint32_t last_known_uid,
                                                   uint32_t batch_size = DEFAULT_FETCH_BATCH_SIZE) {
        std::vector<FetchResult> all_results;

        if (last_known_uid == 0) {
            // Fetch all messages
            return fetch_all_batched(batch_size);
        }

        // Fetch messages with UID greater than last_known_uid
        std::string uid_range = std::to_string(last_known_uid + 1) + ":*";
        auto uids = search_uids("UID " + uid_range);

        // Batch fetch
        for (size_t i = 0; i < uids.size(); i += batch_size) {
            size_t end = std::min(i + batch_size, uids.size());
            std::vector<uint32_t> batch(uids.begin() + i, uids.begin() + end);

            auto results = fetch_messages(batch,
                "(UID FLAGS RFC822.SIZE INTERNALDATE BODY.PEEK[HEADER.FIELDS "
                "(FROM TO CC BCC SUBJECT DATE MESSAGE-ID IN-REPLY-TO REFERENCES "
                "CONTENT-TYPE AUTOCRYPT AUTOCRYPT-SETUP-MESSAGE "
                "CHAT-VERSION CHAT-GROUP-ID CHAT-GROUP-NAME CHAT-VERIFIED "
                "CHAT-USER-AVATAR CHAT-CONTENT-TYPE)])");

            all_results.insert(all_results.end(), results.begin(), results.end());
        }

        return all_results;
    }

    std::vector<FetchResult> fetch_all_batched(uint32_t batch_size = DEFAULT_FETCH_BATCH_SIZE) {
        std::vector<FetchResult> all_results;

        // Get total message count
        FolderStatus status = get_folder_status(current_folder_);
        if (status.messages == 0) return all_results;

        // Fetch in batches of sequence numbers
        uint32_t total = status.messages;
        for (uint32_t start = 1; start <= total; start += batch_size) {
            uint32_t end = std::min(start + batch_size - 1, total);
            std::string seq_range = std::to_string(start) + ":" + std::to_string(end);

            auto response = send_command(
                "FETCH " + seq_range +
                " (UID FLAGS RFC822.SIZE INTERNALDATE BODY.PEEK[HEADER.FIELDS "
                "(FROM TO CC BCC SUBJECT DATE MESSAGE-ID IN-REPLY-TO REFERENCES "
                "CONTENT-TYPE AUTOCRYPT AUTOCRYPT-SETUP-MESSAGE "
                "CHAT-VERSION CHAT-GROUP-ID CHAT-GROUP-NAME CHAT-VERIFIED "
                "CHAT-USER-AVATAR CHAT-CONTENT-TYPE)])",
                timeout_seconds_ * 2);

            if (response.status != "OK") {
                last_error_ = "Batch fetch failed: " + response.status_text;
                break;
            }

            for (const auto& line : response.lines) {
                if (line.find(" FETCH ") != std::string::npos) {
                    all_results.push_back(parse_fetch_line(line));
                }
            }
        }

        return all_results;
    }

    // ========================================================================
    // UIDVALIDITY handling
    // ========================================================================

    uint32_t get_uidvalidity() const {
        return current_uidvalidity_;
    }

    bool is_uidvalidity_changed(uint32_t expected_uidvalidity) const {
        return current_uidvalidity_ != expected_uidvalidity;
    }

    void add_uid_mapping(uint32_t uid, uint32_t uidvalidity,
                         const std::string& message_id, const std::string& folder) {
        UidMapping mapping;
        mapping.uid = uid;
        mapping.uidvalidity = uidvalidity;
        mapping.message_id = message_id;
        mapping.folder = folder;
        mapping.last_seen = time(nullptr);
        mapping.sequence = 0;

        // Deduplicate
        auto it = std::find_if(uid_mappings_.begin(), uid_mappings_.end(),
            [&](const UidMapping& m) {
                return m.message_id == message_id && m.folder == folder;
            });
        if (it != uid_mappings_.end()) {
            *it = mapping;
        } else {
            uid_mappings_.push_back(mapping);
        }

        // Limit cache size
        if (uid_mappings_.size() > 10000) {
            uid_mappings_.pop_front();
        }
    }

    std::optional<uint32_t> find_uid_by_message_id(const std::string& message_id,
                                                     const std::string& folder) {
        for (const auto& m : uid_mappings_) {
            if (m.message_id == message_id && m.folder == folder) {
                return m.uid;
            }
        }
        return std::nullopt;
    }

    void clear_uid_mappings() {
        uid_mappings_.clear();
    }

    // ========================================================================
    // NOOP (keep-alive)
    // ========================================================================

    bool noop() {
        auto response = send_command("NOOP", timeout_seconds_);
        return response.status == "OK";
    }

    // ========================================================================
    // COMPRESS
    // ========================================================================

    bool enable_compression() {
        if (!capabilities_.compress) return false;

        auto response = send_command("COMPRESS DEFLATE", timeout_seconds_);
        return response.status == "OK";
    }

    // ========================================================================
    // Utility
    // ========================================================================

    const std::string& get_current_folder() const {
        return current_folder_;
    }

    FolderStatus get_current_status() const {
        if (!current_folder_.empty()) {
            return get_folder_status(current_folder_);
        }
        return current_status_;
    }

    bool check_connection() {
        if (!is_connected()) return false;
        return noop();
    }

private:
    // Build a compact UID set from a vector of UIDs
    std::string build_uid_set(const std::vector<uint32_t>& uids) {
        if (uids.empty()) return "";

        std::string result;
        uint32_t range_start = uids[0];
        uint32_t range_end = uids[0];

        for (size_t i = 1; i < uids.size(); ++i) {
            if (uids[i] == range_end + 1) {
                range_end = uids[i];
            } else {
                if (!result.empty()) result += ",";
                if (range_start == range_end) {
                    result += std::to_string(range_start);
                } else {
                    result += std::to_string(range_start) + ":" +
                              std::to_string(range_end);
                }
                range_start = uids[i];
                range_end = uids[i];
            }
        }

        // Add final range
        if (!result.empty()) result += ",";
        if (range_start == range_end) {
            result += std::to_string(range_start);
        } else {
            result += std::to_string(range_start) + ":" +
                      std::to_string(range_end);
        }

        return result;
    }

    // Quote a string for IMAP (surround with double quotes, escape special chars)
    std::string quote_string(const std::string& str) {
        std::string result = "\"";
        for (char c : str) {
            if (c == '\\' || c == '"') {
                result.push_back('\\');
            }
            result.push_back(c);
        }
        result.push_back('"');
        return result;
    }

    // Quote a folder name using modified UTF-7 (simplified)
    std::string quote_utf7_folder(const std::string& folder) {
        // For now, use simple quoting; full UTF-7 encoding would go here
        // Check if folder has non-ASCII or special characters
        bool needs_utf7 = false;
        for (char c : folder) {
            unsigned char uc = static_cast<unsigned char>(c);
            if (uc > 127 || uc < 32 || uc == '"' || uc == '\\') {
                needs_utf7 = true;
                break;
            }
        }

        if (needs_utf7) {
            // Encode in modified UTF-7
            return quote_string(encode_modified_utf7(folder));
        }

        return quote_string(folder);
    }

    // Encode a string in modified UTF-7
    std::string encode_modified_utf7(const std::string& input) {
        std::string result;
        size_t i = 0;

        while (i < input.size()) {
            unsigned char c = static_cast<unsigned char>(input[i]);

            // Printable ASCII (except &) can be used literally
            if (c >= 0x20 && c <= 0x7E && c != '&') {
                result.push_back(static_cast<char>(c));
                i++;
                continue;
            }

            // Start UTF-7 encoded section
            result.push_back('&');

            // Collect non-ASCII characters
            std::string non_ascii;
            while (i < input.size()) {
                c = static_cast<unsigned char>(input[i]);
                if (c >= 0x20 && c <= 0x7E && c != '&') break;
                non_ascii.push_back(static_cast<char>(c));
                i++;
            }

            // Base64 encode the UTF-16 representation (simplified)
            result += base64::encode(non_ascii);
            result.push_back('-');
        }

        return result;
    }

    // Join strings with a delimiter
    static std::string join_strings(const std::vector<std::string>& strings,
                                     const std::string& delimiter) {
        std::string result;
        for (size_t i = 0; i < strings.size(); ++i) {
            if (i > 0) result += delimiter;
            result += strings[i];
        }
        return result;
    }
};

// ============================================================================
// IMAP IDLE Watcher for push notifications
// ============================================================================

class IdleWatcher {
private:
    std::shared_ptr<ImapConnection> connection_;
    std::string watch_folder_;
    std::atomic<bool> running_{false};
    std::atomic<bool> should_stop_{false};
    std::thread watcher_thread_;
    std::mutex callback_mutex_;
    std::function<void(const std::string& event_type, uint32_t count)> event_callback_;
    std::function<void(const std::string& error)> error_callback_;
    int idle_timeout_seconds_;
    time_t last_idle_restart_;
    std::atomic<time_t> last_event_time_{0};

public:
    IdleWatcher()
        : idle_timeout_seconds_(DEFAULT_IDLE_TIMEOUT_SECONDS)
        , last_idle_restart_(0) {}

    ~IdleWatcher() {
        stop();
    }

    void set_connection(std::shared_ptr<ImapConnection> conn) {
        connection_ = std::move(conn);
    }

    void set_watch_folder(const std::string& folder) {
        watch_folder_ = folder;
    }

    void set_idle_timeout(int seconds) {
        idle_timeout_seconds_ = seconds;
    }

    void set_event_callback(std::function<void(const std::string&, uint32_t)> callback) {
        std::lock_guard<std::mutex> lock(callback_mutex_);
        event_callback_ = std::move(callback);
    }

    void set_error_callback(std::function<void(const std::string&)> callback) {
        std::lock_guard<std::mutex> lock(callback_mutex_);
        error_callback_ = std::move(callback);
    }

    bool start() {
        if (running_.exchange(true)) {
            return true;  // Already running
        }

        if (!connection_ || !connection_->supports_idle()) {
            running_ = false;
            if (error_callback_) {
                error_callback_("IDLE not supported or no connection");
            }
            return false;
        }

        should_stop_ = false;

        watcher_thread_ = std::thread([this]() {
            idle_loop();
        });

        return true;
    }

    void stop() {
        should_stop_ = true;

        if (watcher_thread_.joinable()) {
            watcher_thread_.join();
        }

        running_ = false;
    }

    bool is_running() const {
        return running_;
    }

    time_t get_last_event_time() const {
        return last_event_time_.load();
    }

private:
    void idle_loop() {
        while (!should_stop_) {
            // Select the watch folder
            if (!connection_->select_folder(watch_folder_, false)) {
                if (error_callback_) {
                    error_callback_("Failed to select folder: " + watch_folder_);
                }
                std::this_thread::sleep_for(std::chrono::seconds(30));
                continue;
            }

            // Start IDLE
            if (!connection_->start_idle()) {
                if (error_callback_) {
                    error_callback_("Failed to start IDLE");
                }
                std::this_thread::sleep_for(std::chrono::seconds(30));
                continue;
            }

            last_idle_restart_ = time(nullptr);

            // Monitor for events with periodic re-IDLE
            while (!should_stop_ && connection_->is_idle_active()) {
                auto response = connection_->idle_check(5);

                if (!response.lines.empty()) {
                    last_event_time_ = time(nullptr);

                    // Process events
                    for (const auto& line : response.lines) {
                        process_idle_event(line);
                    }

                    // Restart IDLE after events
                    connection_->stop_idle();
                    break;
                }

                // Check if we need to restart IDLE (before server timeout)
                time_t now = time(nullptr);
                if (now - last_idle_restart_ > idle_timeout_seconds_ - 60) {
                    connection_->stop_idle();
                    break;
                }
            }
        }

        // Cleanup
        if (connection_->is_idle_active()) {
            connection_->stop_idle();
        }
    }

    void process_idle_event(const std::string& line) {
        uint32_t count = 0;
        std::string event_type;

        if (line.find(" EXISTS") != std::string::npos) {
            event_type = "exists";
            // Extract count
            size_t pos = line.find(" EXISTS");
            if (pos > 2) {
                count = static_cast<uint32_t>(
                    strtoul(line.substr(2, pos - 2).c_str(), nullptr, 10));
            }
        } else if (line.find(" RECENT") != std::string::npos) {
            event_type = "recent";
            size_t pos = line.find(" RECENT");
            if (pos > 2) {
                count = static_cast<uint32_t>(
                    strtoul(line.substr(2, pos - 2).c_str(), nullptr, 10));
            }
        } else if (line.find(" EXPUNGE") != std::string::npos) {
            event_type = "expunge";
            count = 1;
        } else if (line.find(" FETCH") != std::string::npos) {
            event_type = "fetch";
            count = 1;
        }

        if (!event_type.empty()) {
            std::lock_guard<std::mutex> lock(callback_mutex_);
            if (event_callback_) {
                event_callback_(event_type, count);
            }
        }
    }
};

// ============================================================================
// SMTP Connection Manager
// ============================================================================

class SmtpConnection : public BaseConnection {
private:
    std::string local_hostname_;
    bool esmtp_ = false;
    int max_message_size_ = 0;
    bool pipelining_ = false;
    bool eight_bit_mime_ = false;
    bool dsn_ = false;

public:
    SmtpConnection() : BaseConnection() {
        tag_gen_ = TagGenerator("SM");
        timeout_seconds_ = 60;
        local_hostname_ = "localhost";
    }

    void set_local_hostname(const std::string& hostname) {
        local_hostname_ = hostname;
    }

    // ========================================================================
    // Connection and EHLO
    // ========================================================================

    bool connect_and_setup() {
        reconnect_mgr_.reset();

        while (reconnect_mgr_.should_retry()) {
            if (!connect()) {
                reconnect_mgr_.mark_failure();
                reconnect_mgr_.wait_backoff();
                continue;
            }

            // Read greeting
            std::string greeting = read_response_line(timeout_seconds_);
            if (greeting.empty() || greeting.size() < 3) {
                disconnect();
                reconnect_mgr_.mark_failure();
                reconnect_mgr_.wait_backoff();
                continue;
            }

            // Check greeting code (2xx)
            int code = parse_smtp_code(greeting);
            if (code < 200 || code >= 300) {
                last_error_ = "SMTP greeting error: " + greeting;
                disconnect();
                reconnect_mgr_.mark_failure();
                reconnect_mgr_.wait_backoff();
                continue;
            }

            // Send EHLO
            if (!send_ehlo()) {
                // Try HELO fallback
                if (!send_helo()) {
                    disconnect();
                    reconnect_mgr_.mark_failure();
                    reconnect_mgr_.wait_backoff();
                    continue;
                }
            }

            // STARTTLS if not using direct SSL
            if (!use_ssl_ && capabilities_.starttls) {
                if (!starttls_smtp()) {
                    disconnect();
                    reconnect_mgr_.mark_failure();
                    reconnect_mgr_.wait_backoff();
                    continue;
                }
                // Re-send EHLO after TLS
                if (!send_ehlo()) {
                    disconnect();
                    reconnect_mgr_.mark_failure();
                    reconnect_mgr_.wait_backoff();
                    continue;
                }
            }

            // Authenticate
            if (!smtp_authenticate()) {
                disconnect();
                reconnect_mgr_.mark_failure();
                reconnect_mgr_.wait_backoff();
                continue;
            }

            reconnect_mgr_.mark_success();
            return true;
        }

        return false;
    }

    bool send_ehlo() {
        auto response = send_smtp_command("EHLO " + local_hostname_);
        int code = parse_smtp_code(response);

        if (code != 250) {
            last_error_ = "EHLO failed: " + response;
            return false;
        }

        esmtp_ = true;

        // Parse EHLO response to detect capabilities
        std::istringstream ss(response);
        std::string line;
        while (std::getline(ss, line)) {
            if (line.empty()) continue;

            std::string line_upper;
            for (char c : line) line_upper.push_back(static_cast<char>(std::toupper(c)));

            if (line_upper.find("STARTTLS") != std::string::npos) {
                capabilities_.starttls = true;
            } else if (line_upper.find("AUTH") != std::string::npos) {
                parse_smtp_auth_line(line);
            } else if (line_upper.find("PIPELINING") != std::string::npos) {
                pipelining_ = true;
            } else if (line_upper.find("8BITMIME") != std::string::npos) {
                eight_bit_mime_ = true;
            } else if (line_upper.find("DSN") != std::string::npos) {
                dsn_ = true;
            } else if (line_upper.find("SIZE") != std::string::npos) {
                size_t size_pos = line_upper.find("SIZE");
                std::string rest = line.substr(size_pos + 4);
                // Trim whitespace
                size_t start = 0;
                while (start < rest.size() && rest[start] == ' ') start++;
                max_message_size_ = static_cast<int>(
                    strtol(rest.c_str() + start, nullptr, 10));
            }
        }

        return true;
    }

    bool send_helo() {
        auto response = send_smtp_command("HELO " + local_hostname_);
        int code = parse_smtp_code(response);

        if (code != 250) {
            last_error_ = "HELO failed: " + response;
            return false;
        }

        esmtp_ = false;
        return true;
    }

    bool starttls_smtp() {
        auto response = send_smtp_command("STARTTLS");
        int code = parse_smtp_code(response);

        if (code != 220) {
            last_error_ = "STARTTLS rejected: " + response;
            return false;
        }

        if (!transport_->start_tls()) {
            last_error_ = "TLS handshake failed";
            return false;
        }

        return true;
    }

    // ========================================================================
    // Authentication
    // ========================================================================

    bool smtp_authenticate() {
        if (username_.empty()) return true;

        // Try XOAUTH2 first
        if (capabilities_.auth_xoauth2) {
            auto response = send_smtp_command(
                "AUTH XOAUTH2 " + base64::encode(
                    "user=" + username_ + "\x01auth=Bearer " + password_ + "\x01\x01"));
            if (parse_smtp_code(response) == 235) {
                authenticated_ = true;
                return true;
            }
            // If XOAUTH2 fails with 334 (challenge), handle challenge-response
            if (parse_smtp_code(response) == 334) {
                // Send empty response
                auto resp2 = send_smtp_command("");
                if (parse_smtp_code(resp2) == 235) {
                    authenticated_ = true;
                    return true;
                }
            }
        }

        // Try LOGIN auth
        if (capabilities_.auth_login) {
            auto response = send_smtp_command("AUTH LOGIN");
            if (parse_smtp_code(response) == 334) {
                // Send username
                auto user_resp = send_smtp_command(
                    base64::encode(username_));
                if (parse_smtp_code(user_resp) == 334) {
                    // Send password
                    auto pass_resp = send_smtp_command(
                        base64::encode(password_));
                    if (parse_smtp_code(pass_resp) == 235) {
                        authenticated_ = true;
                        return true;
                    }
                }
            }
        }

        // Try PLAIN auth
        if (capabilities_.auth_plain) {
            std::string auth_string = "\0" + username_ + "\0" + password_;
            auto response = send_smtp_command("AUTH PLAIN " +
                base64::encode(auth_string));
            if (parse_smtp_code(response) == 235) {
                authenticated_ = true;
                return true;
            }
        }

        last_error_ = "SMTP authentication failed";
        return false;
    }

    // ========================================================================
    // Message sending
    // ========================================================================

    bool send_message(const std::string& from,
                      const std::vector<std::string>& recipients,
                      const std::string& mime_message,
                      std::vector<std::string>& failed_recipients) {

        if (!transport_ || !transport_->is_connected()) {
            last_error_ = "Not connected";
            return false;
        }

        // MAIL FROM
        std::string mail_from_cmd = "MAIL FROM:<" + extract_email_address(from) + ">";
        if (eight_bit_mime_) {
            mail_from_cmd += " BODY=8BITMIME";
        }
        if (dsn_) {
            mail_from_cmd += " RET=HDRS";
        }

        auto response = send_smtp_command(mail_from_cmd);
        int code = parse_smtp_code(response);
        if (code != 250) {
            last_error_ = "MAIL FROM failed: " + response;
            return false;
        }

        // RCPT TO for each recipient
        std::vector<std::string> accepted_recipients;
        for (const auto& rcpt : recipients) {
            std::string rcpt_cmd = "RCPT TO:<" + extract_email_address(rcpt) + ">";
            if (dsn_) {
                rcpt_cmd += " NOTIFY=FAILURE";
            }

            auto rcpt_response = send_smtp_command(rcpt_cmd);
            int rcpt_code = parse_smtp_code(rcpt_response);

            if (rcpt_code == 250 || rcpt_code == 251) {
                accepted_recipients.push_back(rcpt);
            } else {
                failed_recipients.push_back(rcpt);
            }
        }

        if (accepted_recipients.empty()) {
            // All recipients failed, send RSET
            send_smtp_command("RSET");
            last_error_ = "No valid recipients";
            return false;
        }

        // DATA
        response = send_smtp_command("DATA");
        code = parse_smtp_code(response);
        if (code != 354) {
            last_error_ = "DATA command failed: " + response;
            send_smtp_command("RSET");
            return false;
        }

        // Send message data with dot-stuffing
        std::string dot_stuffed = dot_stuff_message(mime_message);

        // Write the message
        {
            std::lock_guard<std::mutex> lock(io_mutex_);
            int written = transport_->write(
                dot_stuffed.c_str(),
                static_cast<int>(dot_stuffed.size()),
                timeout_seconds_);
            if (written != static_cast<int>(dot_stuffed.size())) {
                last_error_ = "Failed to write message data";
                return false;
            }
            last_activity_ = time(nullptr);
        }

        // End of message
        std::string end_marker = CRLF "." CRLF;
        {
            std::lock_guard<std::mutex> lock(io_mutex_);
            int written = transport_->write(
                end_marker.c_str(),
                static_cast<int>(end_marker.size()),
                timeout_seconds_);
            if (written != static_cast<int>(end_marker.size())) {
                last_error_ = "Failed to write end marker";
                return false;
            }
            last_activity_ = time(nullptr);
        }

        // Read response
        std::string data_response = read_response_line(timeout_seconds_ * 2);
        int data_code = parse_smtp_code(data_response);

        if (data_code != 250) {
            last_error_ = "Message rejected: " + data_response;
            return false;
        }

        return true;
    }

    bool send_message_simple(const std::string& from,
                              const std::vector<std::string>& recipients,
                              const std::string& mime_message) {
        std::vector<std::string> failed;
        return send_message(from, recipients, mime_message, failed);
    }

    // ========================================================================
    // Reset and quit
    // ========================================================================

    bool reset() {
        auto response = send_smtp_command("RSET");
        return parse_smtp_code(response) == 250;
    }

    bool quit() {
        auto response = send_smtp_command("QUIT");
        authenticated_ = false;
        return parse_smtp_code(response) == 221;
    }

    // ========================================================================
    // Verify
    // ========================================================================

    bool verify_recipient(const std::string& address) {
        auto response = send_smtp_command("VRFY " + address);
        int code = parse_smtp_code(response);
        return code >= 200 && code < 300;
    }

    bool noop_smtp() {
        auto response = send_smtp_command("NOOP");
        return parse_smtp_code(response) == 250;
    }

    // ========================================================================
    // Capabilities
    // ========================================================================

    int get_max_message_size() const {
        return max_message_size_;
    }

    bool supports_pipelining() const {
        return pipelining_;
    }

    bool supports_eight_bit_mime() const {
        return eight_bit_mime_;
    }

private:
    std::string send_smtp_command(const std::string& command) {
        std::lock_guard<std::mutex> lock(io_mutex_);

        if (!transport_ || !transport_->is_connected()) {
            last_error_ = "Not connected";
            return "";
        }

        if (!command.empty()) {
            std::string data = command + CRLF;
            int written = transport_->write(data.c_str(), static_cast<int>(data.size()),
                                             timeout_seconds_);
            if (written != static_cast<int>(data.size())) {
                last_error_ = "Write failed";
                return "";
            }
            last_activity_ = time(nullptr);
        }

        return read_smtp_response();
    }

    std::string read_smtp_response() {
        std::string full_response;
        bool last_line = false;

        while (!last_line) {
            std::string line = read_response_line(timeout_seconds_);
            if (line.empty()) {
                last_error_ = "Empty response from server";
                return full_response;
            }

            if (!full_response.empty()) full_response += "\n";
            full_response += line;

            // Check if this is the last line (code followed by space, not dash)
            if (line.size() >= 4 && line[3] == ' ') {
                last_line = true;
            } else if (line.size() < 4 || line[3] != '-') {
                // Single-line response
                last_line = true;
            }
        }

        return full_response;
    }

    int parse_smtp_code(const std::string& response) {
        if (response.size() < 3) return 0;
        return static_cast<int>(strtol(response.c_str(), nullptr, 10));
    }

    void parse_smtp_auth_line(const std::string& line) {
        size_t auth_pos = line.find("AUTH");
        if (auth_pos == std::string::npos) return;

        std::string rest = line.substr(auth_pos + 4);
        // Trim leading space
        size_t start = 0;
        while (start < rest.size() && rest[start] == ' ') start++;

        std::istringstream ss(rest.substr(start));
        std::string mech;
        while (ss >> mech) {
            std::string mech_upper;
            for (char c : mech) mech_upper.push_back(static_cast<char>(std::toupper(c)));

            capabilities_.auth_mechanisms.push_back(mech);
            if (mech_upper == "PLAIN") capabilities_.auth_plain = true;
            else if (mech_upper == "LOGIN") capabilities_.auth_login = true;
            else if (mech_upper == "XOAUTH2") capabilities_.auth_xoauth2 = true;
        }
    }

    std::string extract_email_address(const std::string& input) {
        // Extract email from formats like "Name <email>" or just "email"
        size_t lt = input.find('<');
        size_t gt = input.find('>');
        if (lt != std::string::npos && gt != std::string::npos && gt > lt) {
            return input.substr(lt + 1, gt - lt - 1);
        }
        return input;
    }

    std::string dot_stuff_message(const std::string& message) {
        // Dot-stuffing: lines starting with '.' get an extra '.' prepended
        std::string result;
        result.reserve(message.size() + message.size() / 50);

        bool at_line_start = true;
        for (size_t i = 0; i < message.size(); ++i) {
            char c = message[i];
            if (at_line_start && c == '.') {
                result.push_back('.');
            }
            result.push_back(c);
            at_line_start = (c == '\n');
        }

        // Ensure message ends with CRLF
        if (result.size() < 2 || result.substr(result.size() - 2) != CRLF) {
            if (!result.empty() && result.back() == '\n') {
                result.insert(result.size() - 1, '\r');
            } else if (!result.empty() && result.back() == '\r') {
                result.push_back('\n');
            } else {
                result += CRLF;
            }
        }

        return result;
    }
};

// ============================================================================
// MIME Parser
// ============================================================================

class MimeParser {
public:
    // Parse a full MIME message into a ParsedMessage structure
    static ParsedMessage parse_message(const std::string& raw_mime,
                                        uint32_t uid,
                                        const std::string& folder) {
        ParsedMessage msg;
        msg.uid = uid;
        msg.folder = folder;
        msg.raw_mime = raw_mime;
        msg.fetch_time = time(nullptr);

        // Split headers from body
        size_t header_end = raw_mime.find("\r\n\r\n");
        if (header_end == std::string::npos) {
            header_end = raw_mime.find("\n\n");
            if (header_end == std::string::npos) return msg;
        }

        std::string header_block = raw_mime.substr(0, header_end);
        std::string body_block = raw_mime.substr(header_end + 4);

        // Parse headers
        parse_headers(header_block, msg.header);

        // Parse body
        parse_body(body_block, msg.header.content_type, msg);

        // Check if this is a DeltaChat message
        msg.is_delta_chat = (msg.header.chat_version > 0 ||
                             !msg.header.chat_group_id.empty());

        return msg;
    }

    // Parse headers from a header block
    static MessageHeader parse_header_block(const std::string& header_block) {
        MessageHeader header;
        parse_headers(header_block, header);
        return header;
    }

private:
    static void parse_headers(const std::string& header_block, MessageHeader& header) {
        std::string current_header;
        std::string current_value;
        bool in_header = false;

        std::istringstream ss(header_block);
        std::string line;

        while (std::getline(ss, line)) {
            // Remove trailing \r
            if (!line.empty() && line.back() == '\r') {
                line.pop_back();
            }

            if (line.empty()) continue;

            // Check for continuation (starts with whitespace)
            if (!line.empty() && (line[0] == ' ' || line[0] == '\t')) {
                if (in_header) {
                    // Unfold: replace newline with space
                    current_value += " ";
                    // Trim leading whitespace
                    size_t start = 0;
                    while (start < line.size() &&
                           (line[start] == ' ' || line[start] == '\t')) start++;
                    current_value += line.substr(start);
                    continue;
                }
            }

            // Save previous header
            if (in_header && !current_header.empty()) {
                assign_header(header, current_header, current_value);
            }

            // Parse new header
            size_t colon = line.find(':');
            if (colon != std::string::npos) {
                current_header = line.substr(0, colon);
                current_value = line.substr(colon + 1);
                // Trim leading whitespace from value
                size_t start = 0;
                while (start < current_value.size() &&
                       (current_value[start] == ' ' || current_value[start] == '\t')) start++;
                current_value = current_value.substr(start);
                in_header = true;
            } else {
                in_header = false;
            }
        }

        // Don't forget the last header
        if (in_header && !current_header.empty()) {
            assign_header(header, current_header, current_value);
        }
    }

    static void assign_header(MessageHeader& header,
                               const std::string& name,
                               const std::string& value) {
        // Decode MIME encoded words
        std::string decoded_value = mime_words::decode_encoded_word(value);

        std::string name_lower;
        for (char c : name) name_lower.push_back(static_cast<char>(std::tolower(c)));

        if (name_lower == "from") {
            header.from = decoded_value;
        } else if (name_lower == "to") {
            header.to = decoded_value;
        } else if (name_lower == "cc") {
            header.cc = decoded_value;
        } else if (name_lower == "bcc") {
            header.bcc = decoded_value;
        } else if (name_lower == "subject") {
            header.subject = decoded_value;
        } else if (name_lower == "date") {
            header.date = decoded_value;
        } else if (name_lower == "message-id") {
            header.message_id = trim_brackets(value);
        } else if (name_lower == "in-reply-to") {
            header.in_reply_to = trim_brackets(decoded_value);
        } else if (name_lower == "references") {
            header.references = decoded_value;
        } else if (name_lower == "content-type") {
            header.content_type = value;
        } else if (name_lower == "autocrypt") {
            header.autocrypt = value;
        } else if (name_lower == "autocrypt-setup-message") {
            header.autocrypt_setup_message = value;
        } else if (name_lower == "chat-version") {
            header.chat_version = static_cast<int>(strtol(value.c_str(), nullptr, 10));
        } else if (name_lower == "chat-group-id") {
            header.chat_group_id = value;
        } else if (name_lower == "chat-group-name") {
            header.chat_group_name = decoded_value;
        } else if (name_lower == "chat-verified") {
            header.chat_verified = value;
        } else if (name_lower == "chat-user-avatar") {
            header.chat_user_agent = value;
        } else if (name_lower == "chat-content-type") {
            header.chat_content_type = value;
        }
    }

    static void parse_body(const std::string& body_block,
                            const std::string& content_type_header,
                            ParsedMessage& msg) {
        // Parse content type
        std::string media_type = "text";
        std::string media_subtype = "plain";
        std::string boundary;
        std::string charset = "utf-8";
        std::string transfer_encoding;

        parse_content_type(content_type_header, media_type, media_subtype,
                           boundary, charset);

        if (media_type == "text" && media_subtype == "plain") {
            // Simple text body
            msg.text_body = decode_transfer_encoding(body_block, "");
        } else if (media_type == "text" && media_subtype == "html") {
            msg.html_body = decode_transfer_encoding(body_block, "");
        } else if (media_type == "multipart" && !boundary.empty()) {
            // Parse multipart message
            parse_multipart(body_block, boundary, msg);
        } else {
            // Treat as attachment
            BodyPart part;
            part.mime_type = media_type;
            part.mime_subtype = media_subtype;
            part.decoded_content = decode_transfer_encoding(body_block, "");
            part.size = static_cast<uint32_t>(body_block.size());
            part.is_attachment = true;
            msg.attachments.push_back(part);
        }
    }

    static void parse_multipart(const std::string& body,
                                 const std::string& boundary,
                                 ParsedMessage& msg) {
        std::string delimiter = "--" + boundary;
        std::string close_delimiter = "--" + boundary + "--";

        size_t pos = body.find(delimiter);
        if (pos == std::string::npos) return;

        // Skip past first delimiter
        pos += delimiter.size();
        // Skip to next line
        while (pos < body.size() && body[pos] != '\n') pos++;
        if (pos < body.size()) pos++;  // skip \n

        while (pos < body.size()) {
            // Check if we reached the end
            if (body.compare(pos, close_delimiter.size(), close_delimiter) == 0) {
                break;
            }

            // Find next delimiter
            size_t next_delim = body.find(delimiter, pos);
            if (next_delim == std::string::npos) break;

            // Extract part content
            std::string part_content = body.substr(pos, next_delim - pos);

            // Trim trailing CRLF
            while (!part_content.empty() &&
                   (part_content.back() == '\n' || part_content.back() == '\r')) {
                part_content.pop_back();
            }

            // Parse part headers and body
            parse_mime_part(part_content, msg);

            // Move past delimiter
            pos = next_delim + delimiter.size();
            while (pos < body.size() && body[pos] != '\n') pos++;
            if (pos < body.size()) pos++;
        }
    }

    static void parse_mime_part(const std::string& part_content, ParsedMessage& msg) {
        // Split headers from body
        size_t header_end = part_content.find("\r\n\r\n");
        if (header_end == std::string::npos) {
            header_end = part_content.find("\n\n");
            if (header_end == std::string::npos) return;
        }

        std::string part_headers = part_content.substr(0, header_end);
        std::string part_body = part_content.substr(
            header_end + (part_content[header_end] == '\r' ? 4 : 2));

        // Parse part headers
        std::string content_type = "text/plain";
        std::string content_disposition;
        std::string content_transfer_encoding;
        std::string content_id;
        std::string content_description;

        std::istringstream ss(part_headers);
        std::string line;
        while (std::getline(ss, line)) {
            if (!line.empty() && line.back() == '\r') line.pop_back();
            if (line.empty()) continue;

            size_t colon = line.find(':');
            if (colon == std::string::npos) continue;

            std::string header_name = line.substr(0, colon);
            std::string header_value = line.substr(colon + 1);
            // Trim leading whitespace
            size_t start = 0;
            while (start < header_value.size() &&
                   (header_value[start] == ' ' || header_value[start] == '\t')) start++;
            header_value = header_value.substr(start);

            std::string header_lower;
            for (char c : header_name) header_lower.push_back(static_cast<char>(std::tolower(c)));

            if (header_lower == "content-type") {
                content_type = header_value;
            } else if (header_lower == "content-disposition") {
                content_disposition = header_value;
            } else if (header_lower == "content-transfer-encoding") {
                content_transfer_encoding = header_value;
            } else if (header_lower == "content-id") {
                content_id = trim_brackets(header_value);
            } else if (header_lower == "content-description") {
                content_description = header_value;
            }
        }

        // Parse media type
        std::string media_type = "text";
        std::string media_subtype = "plain";
        std::string sub_boundary;
        std::string charset = "utf-8";
        std::string filename;

        parse_content_type(content_type, media_type, media_subtype, sub_boundary, charset);

        // Parse content disposition for filename
        parse_content_disposition(content_disposition, filename);

        bool is_attachment = false;
        if (!content_disposition.empty()) {
            std::string disp_lower;
            for (char c : content_disposition)
                disp_lower.push_back(static_cast<char>(std::tolower(c)));
            if (disp_lower.find("attachment") != std::string::npos) {
                is_attachment = true;
            }
        }

        // Determine if text body or attachment
        if (media_type == "text" && media_subtype == "plain" && !is_attachment) {
            msg.text_body = decode_transfer_encoding(part_body,
                                                       content_transfer_encoding);
        } else if (media_type == "text" && media_subtype == "html" && !is_attachment) {
            msg.html_body = decode_transfer_encoding(part_body,
                                                       content_transfer_encoding);
        } else if (media_type == "multipart" && !sub_boundary.empty()) {
            parse_multipart(part_body, sub_boundary, msg);
        } else {
            // This is an attachment or other part
            BodyPart bp;
            bp.mime_type = media_type;
            bp.mime_subtype = media_subtype;
            bp.charset = charset;
            bp.content_transfer_encoding = content_transfer_encoding;
            bp.filename = filename;
            bp.content_id = content_id;
            bp.content_description = content_description;
            bp.size = static_cast<uint32_t>(part_body.size());
            bp.is_attachment = is_attachment;
            bp.decoded_content = decode_transfer_encoding(part_body,
                                                            content_transfer_encoding);

            // Check if it's an inline image
            if (!is_attachment && !content_id.empty() &&
                media_type == "image") {
                bp.is_inline = true;
            }

            msg.attachments.push_back(bp);
        }
    }

    static void parse_content_type(const std::string& content_type,
                                    std::string& media_type,
                                    std::string& media_subtype,
                                    std::string& boundary,
                                    std::string& charset) {
        if (content_type.empty()) return;

        // Split type/subtype from parameters
        size_t semi = content_type.find(';');
        std::string type_part = semi != std::string::npos
            ? content_type.substr(0, semi)
            : content_type;

        // Parse type/subtype
        size_t slash = type_part.find('/');
        if (slash != std::string::npos) {
            media_type = type_part.substr(0, slash);
            media_subtype = type_part.substr(slash + 1);

            // Trim
            trim_string(media_type);
            trim_string(media_subtype);
        }

        // Lowercase
        for (char& c : media_type) c = static_cast<char>(std::tolower(c));
        for (char& c : media_subtype) c = static_cast<char>(std::tolower(c));

        // Parse parameters
        if (semi != std::string::npos) {
            std::string params = content_type.substr(semi + 1);
            parse_mime_parameters(params, boundary, charset);
        }
    }

    static void parse_content_disposition(const std::string& disposition,
                                            std::string& filename) {
        if (disposition.empty()) return;

        size_t semi = disposition.find(';');
        if (semi != std::string::npos) {
            std::string params = disposition.substr(semi + 1);

            // Look for filename= or filename*=
            size_t fn_pos = params.find("filename");
            if (fn_pos == std::string::npos) return;

            std::string rest = params.substr(fn_pos + 8);  // past "filename"
            // Skip optional * and =
            size_t eq = rest.find('=');
            if (eq == std::string::npos) return;

            rest = rest.substr(eq + 1);
            // Trim whitespace
            trim_string(rest);

            if (!rest.empty() && rest[0] == '"') {
                size_t endq = rest.find('"', 1);
                if (endq != std::string::npos) {
                    filename = rest.substr(1, endq - 1);
                }
            } else {
                // Unquoted value
                size_t semi_end = rest.find(';');
                if (semi_end != std::string::npos) {
                    filename = rest.substr(0, semi_end);
                } else {
                    filename = rest;
                }
                trim_string(filename);
            }
        }
    }

    static void parse_mime_parameters(const std::string& params,
                                       std::string& boundary,
                                       std::string& charset) {
        std::string current_param;
        std::string current_value;
        bool in_value = false;
        bool in_quotes = false;

        for (size_t i = 0; i <= params.size(); ++i) {
            char c = (i < params.size()) ? params[i] : ';';

            if (in_quotes) {
                current_value.push_back(c);
                if (c == '"' && (i + 1 >= params.size() || params[i + 1] == ';' ||
                    params[i + 1] == ' ')) {
                    in_quotes = false;
                }
                continue;
            }

            if (c == '"') {
                in_quotes = true;
                current_value.push_back(c);
                continue;
            }

            if (c == '=' && !in_value) {
                in_value = true;
                continue;
            }

            if (c == ';' || i >= params.size()) {
                // Save parameter
                if (!current_param.empty()) {
                    std::string param_lower;
                    for (char pc : current_param)
                        param_lower.push_back(static_cast<char>(std::tolower(pc)));
                    trim_string(param_lower);

                    // Unquote value
                    if (current_value.size() >= 2 &&
                        current_value.front() == '"' && current_value.back() == '"') {
                        current_value = current_value.substr(1, current_value.size() - 2);
                    }

                    if (param_lower == "boundary") {
                        boundary = current_value;
                    } else if (param_lower == "charset") {
                        charset = current_value;
                    }
                }

                current_param.clear();
                current_value.clear();
                in_value = false;
                continue;
            }

            if (!in_value) {
                if (c != ' ') current_param.push_back(c);
            } else {
                if (!(c == ' ' && current_value.empty())) {
                    current_value.push_back(c);
                }
            }
        }
    }

    static std::string decode_transfer_encoding(const std::string& data,
                                                  const std::string& encoding) {
        std::string encoding_lower;
        for (char c : encoding) encoding_lower.push_back(static_cast<char>(std::tolower(c)));
        // Trim
        trim_string(encoding_lower);

        if (encoding_lower == "base64") {
            return base64::decode(data);
        } else if (encoding_lower == "quoted-printable") {
            return quoted_printable::decode(data);
        } else if (encoding_lower == "7bit" || encoding_lower == "8bit" ||
                   encoding_lower == "binary" || encoding_lower.empty()) {
            return data;
        }

        // Unknown encoding, return as-is
        return data;
    }

    static std::string trim_brackets(const std::string& input) {
        std::string result = input;
        // Trim whitespace
        trim_string(result);
        // Remove surrounding < >
        if (result.size() >= 2 && result.front() == '<' && result.back() == '>') {
            result = result.substr(1, result.size() - 2);
        }
        return result;
    }

    static void trim_string(std::string& str) {
        size_t start = 0;
        while (start < str.size() && (str[start] == ' ' || str[start] == '\t' ||
               str[start] == '\r' || str[start] == '\n')) start++;

        size_t end = str.size();
        while (end > start && (str[end - 1] == ' ' || str[end - 1] == '\t' ||
               str[end - 1] == '\r' || str[end - 1] == '\n')) end--;

        if (start > 0 || end < str.size()) {
            str = str.substr(start, end - start);
        }
    }
};

// ============================================================================
// Folder Synchronization Manager
// ============================================================================

class FolderSync {
public:
    struct SyncConfig {
        std::string watch_folder;       // Folder to watch for new messages
        std::string sent_folder;        // Folder where sent messages are stored
        std::string mvbox_folder;       // DeltaChat folder for moved messages
        std::string drafts_folder;      // Drafts folder
        std::string trash_folder;       // Trash folder
        bool delete_from_server = false;
        bool delete_to_trash = true;
        bool sync_sent = true;
        bool only_fetch_mvbox = false;
        int max_age_days = 0;           // 0 = no limit
        uint32_t last_known_uid = 0;    // Last UID we've seen
    };

private:
    std::shared_ptr<ImapConnection> imap_;
    SyncConfig config_;
    std::atomic<bool> syncing_{false};
    std::mutex sync_mutex_;
    std::function<void(const ParsedMessage&)> message_callback_;
    std::function<void(const std::string&, int, int)> progress_callback_;
    std::function<void(const std::string&)> error_callback_;

public:
    FolderSync() = default;

    void set_connection(std::shared_ptr<ImapConnection> conn) {
        imap_ = std::move(conn);
    }

    void set_config(const SyncConfig& config) {
        config_ = config;
    }

    void set_message_callback(std::function<void(const ParsedMessage&)> callback) {
        message_callback_ = std::move(callback);
    }

    void set_progress_callback(std::function<void(const std::string&, int, int)> callback) {
        progress_callback_ = std::move(callback);
    }

    void set_error_callback(std::function<void(const std::string&)> callback) {
        error_callback_ = std::move(callback);
    }

    bool perform_full_sync() {
        if (!imap_ || !imap_->is_connected() || !imap_->is_authenticated()) {
            if (error_callback_) error_callback_("Not connected or not authenticated");
            return false;
        }

        std::lock_guard<std::mutex> lock(sync_mutex_);
        if (syncing_.exchange(true)) {
            if (error_callback_) error_callback_("Sync already in progress");
            return false;
        }

        bool success = false;

        try {
            success = sync_watch_folder();
        } catch (const std::exception& e) {
            if (error_callback_) error_callback_(std::string("Sync error: ") + e.what());
            success = false;
        }

        syncing_ = false;
        return success;
    }

    bool perform_quick_sync() {
        if (!imap_ || !imap_->is_connected()) return false;

        std::lock_guard<std::mutex> lock(sync_mutex_);
        if (syncing_.exchange(true)) return false;

        bool success = false;

        try {
            // Quick sync only fetches new messages since last known UID
            success = sync_new_messages();
        } catch (const std::exception& e) {
            if (error_callback_) error_callback_(std::string("Quick sync error: ") + e.what());
            success = false;
        }

        syncing_ = false;
        return success;
    }

    bool is_syncing() const { return syncing_; }

    void set_last_known_uid(uint32_t uid) {
        config_.last_known_uid = uid;
    }

    uint32_t get_last_known_uid() const {
        return config_.last_known_uid;
    }

private:
    bool sync_watch_folder() {
        // Select the watch folder
        if (!imap_->select_folder(config_.watch_folder)) {
            if (error_callback_) error_callback_("Failed to select folder: " +
                                                   config_.watch_folder);
            return false;
        }

        // Get folder status
        FolderStatus status = imap_->get_current_status();
        if (progress_callback_) {
            progress_callback_(config_.watch_folder, 0, static_cast<int>(status.messages));
        }

        // Fetch existing messages that are new
        std::vector<FetchResult> fetch_results;

        if (config_.only_fetch_mvbox) {
            // Only fetch from MVBOX if configured
            if (!config_.mvbox_folder.empty()) {
                imap_->select_folder(config_.mvbox_folder);
                fetch_results = imap_->fetch_existing_msgs(0);
                imap_->select_folder(config_.watch_folder);
            }
        } else {
            fetch_results = imap_->fetch_existing_msgs(config_.last_known_uid);
        }

        // Process fetched messages
        uint32_t highest_uid = config_.last_known_uid;
        int processed = 0;

        for (const auto& fetch : fetch_results) {
            // Skip already-processed messages
            if (fetch.uid <= config_.last_known_uid) continue;

            // Fetch full message if needed
            ParsedMessage parsed;
            if (!fetch.body_data.empty() || !fetch.full_mime.empty()) {
                std::string raw = fetch.full_mime.empty()
                    ? fetch.header_data + "\r\n\r\n" + fetch.body_data
                    : fetch.full_mime;
                parsed = MimeParser::parse_message(raw, fetch.uid,
                                                     config_.watch_folder);
            } else {
                // Need to fetch full body
                auto full_results = imap_->fetch_full({fetch.uid});
                if (!full_results.empty()) {
                    parsed = MimeParser::parse_message(
                        full_results[0].full_mime, fetch.uid, config_.watch_folder);
                }
            }

            // Mark as seen if needed
            if (!fetch.seen) {
                imap_->mark_seen({fetch.uid});
            }

            // Apply max age filter
            if (config_.max_age_days > 0) {
                time_t now = time(nullptr);
                time_t msg_age = now - parsed.fetch_time;
                if (msg_age > config_.max_age_days * 86400) {
                    continue;
                }
            }

            // Delete old messages if configured
            if (config_.delete_from_server && config_.delete_to_trash &&
                !config_.trash_folder.empty()) {
                imap_->move_messages({fetch.uid}, config_.trash_folder);
            } else if (config_.delete_from_server) {
                imap_->store_flags({fetch.uid}, "+FLAGS", "\\Deleted");
            }

            // Save UID mapping
            imap_->add_uid_mapping(fetch.uid,
                                     imap_->get_uidvalidity(),
                                     parsed.header.message_id,
                                     config_.watch_folder);

            // Notify callback
            if (message_callback_) {
                message_callback_(parsed);
            }

            if (fetch.uid > highest_uid) {
                highest_uid = fetch.uid;
            }

            processed++;
            if (progress_callback_ && processed % 10 == 0) {
                progress_callback_(config_.watch_folder, processed,
                                    static_cast<int>(status.messages));
            }
        }

        // Update last known UID
        config_.last_known_uid = highest_uid;

        // Expunge if messages were deleted
        if (config_.delete_from_server) {
            imap_->expunge();
        }

        if (progress_callback_) {
            progress_callback_(config_.watch_folder, processed,
                                static_cast<int>(status.messages));
        }

        return true;
    }

    bool sync_new_messages() {
        // Much faster: only fetch messages with UIDs > last_known_uid
        if (!imap_->select_folder(config_.watch_folder)) return false;

        // Search for new messages
        auto new_uids = imap_->search_since_uid(config_.last_known_uid);
        if (new_uids.empty()) return true;

        // Fetch headers only first
        auto fetch_results = imap_->fetch_headers(new_uids);

        uint32_t highest_uid = config_.last_known_uid;

        for (const auto& fetch : fetch_results) {
            if (fetch.uid > highest_uid) highest_uid = fetch.uid;

            // For DeltaChat messages, fetch full body
            std::string header_str = fetch.header_data;
            MessageHeader header = MimeParser::parse_header_block(header_str);

            ParsedMessage parsed;
            parsed.uid = fetch.uid;
            parsed.folder = config_.watch_folder;
            parsed.header = header;
            parsed.is_delta_chat = (header.chat_version > 0);

            if (message_callback_) {
                message_callback_(parsed);
            }
        }

        config_.last_known_uid = highest_uid;
        return true;
    }

public:
    // Sync sent folder
    bool sync_sent_folder() {
        if (!config_.sync_sent || config_.sent_folder.empty()) return true;
        if (!imap_ || !imap_->is_connected()) return false;

        // Select sent folder
        if (!imap_->select_folder(config_.sent_folder)) return false;

        // Get status
        FolderStatus status = imap_->get_current_status();
        if (status.messages == 0) return true;

        // Mark all sent messages as seen (they're ours)
        auto all_uids = imap_->search_all();

        // Batch mark as seen
        const size_t batch_size = 100;
        for (size_t i = 0; i < all_uids.size(); i += batch_size) {
            size_t end = std::min(i + batch_size, all_uids.size());
            std::vector<uint32_t> batch(all_uids.begin() + i, all_uids.begin() + end);
            imap_->mark_seen(batch);
        }

        return true;
    }

    // Clean up old messages
    bool cleanup_old_messages(int max_age_days) {
        if (!imap_ || !imap_->is_connected()) return false;
        if (max_age_days <= 0) return true;

        // Calculate date threshold
        time_t now = time(nullptr);
        time_t threshold = now - (max_age_days * 86400);
        struct tm* tm_threshold = gmtime(&threshold);
        char date_str[32];
        strftime(date_str, sizeof(date_str), "%d-%b-%Y", tm_threshold);

        // Search for old messages
        std::string criteria = "BEFORE " + std::string(date_str);
        auto old_uids = imap_->search_uids(criteria);

        if (old_uids.empty()) return true;

        // Move to trash or delete
        if (!config_.trash_folder.empty()) {
            return imap_->move_messages(old_uids, config_.trash_folder);
        } else {
            imap_->store_flags(old_uids, "+FLAGS", "\\Deleted");
            return imap_->expunge();
        }
    }

    // Initial scan of all folders
    std::vector<FolderInfo> scan_folders() {
        return imap_->list_folders();
    }

    // Detect special folders
    void detect_special_folders() {
        auto folders = imap_->list_folders();

        for (const auto& folder : folders) {
            if (folder.inbox && config_.watch_folder.empty()) {
                config_.watch_folder = folder.name;
            }
            if (folder.sent && config_.sent_folder.empty()) {
                config_.sent_folder = folder.name;
            }
            if (folder.drafts && config_.drafts_folder.empty()) {
                config_.drafts_folder = folder.name;
            }
            if (folder.trash && config_.trash_folder.empty()) {
                config_.trash_folder = folder.name;
            }
        }

        // Fallbacks
        if (config_.watch_folder.empty()) config_.watch_folder = "INBOX";
        if (config_.sent_folder.empty()) config_.sent_folder = "Sent";
        if (config_.drafts_folder.empty()) config_.drafts_folder = "Drafts";
        if (config_.trash_folder.empty()) config_.trash_folder = "Trash";
    }
};

// ============================================================================
// DeltaChat Account Manager (top-level API)
// ============================================================================

class DeltaChatAccount {
public:
    struct AccountConfig {
        std::string email;
        std::string password;
        std::string imap_server;
        int imap_port = DEFAULT_IMAP_PORT;
        bool imap_ssl = true;
        std::string smtp_server;
        int smtp_port = DEFAULT_SMTP_PORT;
        bool smtp_ssl = true;
        std::string mvbox_folder;
        std::string sent_folder = "Sent";
        std::string draft_folder = "Drafts";
        std::string trash_folder = "Trash";
        int fetch_existing_msgs_days = 30;
        bool delete_server_after = false;
        int timeout_seconds = 30;
    };

private:
    AccountConfig config_;
    std::shared_ptr<TransportInterface> imap_transport_;
    std::shared_ptr<TransportInterface> smtp_transport_;
    std::shared_ptr<ImapConnection> imap_;
    std::shared_ptr<SmtpConnection> smtp_;
    std::shared_ptr<ConnectionPool> pool_;
    std::shared_ptr<IdleWatcher> idle_watcher_;
    std::shared_ptr<FolderSync> folder_sync_;
    std::atomic<bool> initialized_{false};
    std::atomic<bool> connected_{false};
    std::mutex state_mutex_;

public:
    DeltaChatAccount() = default;

    ~DeltaChatAccount() {
        disconnect();
    }

    void configure(const AccountConfig& config) {
        std::lock_guard<std::mutex> lock(state_mutex_);
        config_ = config;
    }

    bool initialize(std::shared_ptr<TransportInterface> imap_transport,
                    std::shared_ptr<TransportInterface> smtp_transport) {
        std::lock_guard<std::mutex> lock(state_mutex_);

        imap_transport_ = std::move(imap_transport);
        smtp_transport_ = std::move(smtp_transport);

        // Create IMAP connection
        imap_ = std::make_shared<ImapConnection>();
        imap_->configure(config_.imap_server, config_.imap_port,
                         config_.email, config_.password, config_.imap_ssl);
        imap_->set_transport(imap_transport_);
        imap_->setTimeout(config_.timeout_seconds);

        // Create SMTP connection
        smtp_ = std::make_shared<SmtpConnection>();
        smtp_->configure(config_.smtp_server, config_.smtp_port,
                         config_.email, config_.password, config_.smtp_ssl);
        smtp_->set_transport(smtp_transport_);
        smtp_->setTimeout(config_.timeout_seconds);

        // Create pool
        auto pool_factory = [this]() -> std::shared_ptr<TransportInterface> {
            return imap_transport_;
        };
        pool_ = std::make_shared<ConnectionPool>(
            CONNECTION_POOL_MAX_SIZE, CONNECTION_POOL_MAX_IDLE_SECONDS, pool_factory);

        // Create idle watcher
        idle_watcher_ = std::make_shared<IdleWatcher>();
        idle_watcher_->set_connection(imap_);
        idle_watcher_->set_watch_folder("INBOX");

        // Create folder sync
        folder_sync_ = std::make_shared<FolderSync>();
        folder_sync_->set_connection(imap_);

        FolderSync::SyncConfig sync_config;
        sync_config.watch_folder = "INBOX";
        sync_config.sent_folder = config_.sent_folder;
        sync_config.mvbox_folder = config_.mvbox_folder;
        sync_config.drafts_folder = config_.draft_folder;
        sync_config.trash_folder = config_.trash_folder;
        sync_config.delete_from_server = config_.delete_server_after;
        sync_config.max_age_days = config_.fetch_existing_msgs_days;
        folder_sync_->set_config(sync_config);

        initialized_ = true;
        return true;
    }

    bool connect() {
        std::lock_guard<std::mutex> lock(state_mutex_);

        if (!initialized_) {
            last_error_ = "Not initialized";
            return false;
        }

        // Connect IMAP
        if (!imap_->connect_and_login()) {
            last_error_ = "IMAP connection failed: " + imap_->get_last_error();
            return false;
        }

        // Connect SMTP
        if (!smtp_->connect_and_setup()) {
            last_error_ = "SMTP connection failed: " + smtp_->get_last_error();
            imap_->logout();
            return false;
        }

        connected_ = true;

        // Detect special folders
        folder_sync_->detect_special_folders();

        return true;
    }

    void disconnect() {
        std::lock_guard<std::mutex> lock(state_mutex_);

        if (idle_watcher_) {
            idle_watcher_->stop();
        }

        if (smtp_) {
            smtp_->quit();
        }

        if (imap_) {
            imap_->logout();
        }

        if (pool_) {
            pool_->disconnect_all();
        }

        connected_ = false;
    }

    bool is_connected() const {
        return connected_ && imap_ && imap_->is_connected();
    }

    // ========================================================================
    // High-level operations
    // ========================================================================

    bool perform_initial_sync(
        std::function<void(const ParsedMessage&)> message_callback,
        std::function<void(const std::string&, int, int)> progress_callback) {

        if (!connected_) return false;

        folder_sync_->set_message_callback(std::move(message_callback));
        folder_sync_->set_progress_callback(std::move(progress_callback));

        return folder_sync_->perform_full_sync();
    }

    bool perform_quick_sync(
        std::function<void(const ParsedMessage&)> message_callback) {

        if (!connected_) return false;

        folder_sync_->set_message_callback(std::move(message_callback));
        return folder_sync_->perform_quick_sync();
    }

    bool send_delta_chat_message(const std::string& from,
                                   const std::vector<std::string>& recipients,
                                   const std::string& mime_message) {
        if (!connected_ || !smtp_) return false;

        // Send via SMTP
        std::vector<std::string> failed;
        bool success = smtp_->send_message(from, recipients, mime_message, failed);

        if (!success) {
            last_error_ = smtp_->get_last_error();
            return false;
        }

        // Append to sent folder
        if (imap_ && imap_->is_connected() && imap_->is_authenticated()) {
            std::string sent_folder = config_.sent_folder;
            if (!sent_folder.empty()) {
                imap_->append_message(sent_folder, mime_message, {"\\Seen"});
            }
        }

        return true;
    }

    bool fetch_message_body(uint32_t uid, std::string& body) {
        if (!connected_ || !imap_) return false;

        auto results = imap_->fetch_full({uid});
        if (results.empty()) return false;

        body = results[0].full_mime;
        return true;
    }

    bool fetch_message_headers(uint32_t uid, MessageHeader& header) {
        if (!connected_ || !imap_) return false;

        auto results = imap_->fetch_headers({uid});
        if (results.empty()) return false;

        header = MimeParser::parse_header_block(results[0].header_data);
        return true;
    }

    bool mark_message_seen(uint32_t uid) {
        if (!connected_ || !imap_) return false;
        return imap_->mark_seen({uid});
    }

    bool delete_message(uint32_t uid) {
        if (!connected_ || !imap_) return false;

        if (!config_.trash_folder.empty()) {
            return imap_->move_messages({uid}, config_.trash_folder);
        }

        imap_->store_flags({uid}, "+FLAGS", "\\Deleted");
        return imap_->expunge();
    }

    bool move_to_delta_chat_folder(uint32_t uid) {
        if (!connected_ || !imap_) return false;
        return imap_->move_to_delta_chat_folder({uid}, config_.mvbox_folder);
    }

    bool start_idle_watcher(
        std::function<void(const std::string&, uint32_t)> event_callback,
        std::function<void(const std::string&)> error_callback) {

        if (!connected_ || !idle_watcher_) return false;

        idle_watcher_->set_event_callback(std::move(event_callback));
        idle_watcher_->set_error_callback(std::move(error_callback));

        return idle_watcher_->start();
    }

    void stop_idle_watcher() {
        if (idle_watcher_) {
            idle_watcher_->stop();
        }
    }

    bool check_idle_health() {
        if (!idle_watcher_ || !idle_watcher_->is_running()) return false;

        time_t last_event = idle_watcher_->get_last_event_time();
        time_t now = time(nullptr);

        // If no events for 30 minutes, connection might be dead
        if (now - last_event > DEFAULT_IDLE_TIMEOUT_SECONDS) {
            return false;
        }

        return true;
    }

    // ========================================================================
    // Server capabilities
    // ========================================================================

    const ServerCapabilities& get_imap_capabilities() const {
        static ServerCapabilities empty;
        if (!imap_) return empty;
        return imap_->get_capabilities();
    }

    const ServerCapabilities& get_smtp_capabilities() const {
        static ServerCapabilities empty;
        if (!smtp_) return empty;
        return smtp_->get_capabilities();
    }

    // ========================================================================
    // Folder operations
    // ========================================================================

    std::vector<FolderInfo> list_folders() {
        if (!connected_ || !imap_) return {};
        return imap_->list_folders();
    }

    bool create_folder(const std::string& name) {
        if (!connected_ || !imap_) return false;
        return imap_->create_folder(name);
    }

    bool delete_folder(const std::string& name) {
        if (!connected_ || !imap_) return false;
        return imap_->delete_folder(name);
    }

    FolderStatus get_folder_status(const std::string& folder) {
        if (!connected_ || !imap_) return FolderStatus{};
        return imap_->get_folder_status(folder);
    }

    // ========================================================================
    // Error handling
    // ========================================================================

    std::string get_last_error() const {
        return last_error_;
    }

    void clear_error() {
        last_error_.clear();
    }

private:
    mutable std::string last_error_;
};

// ============================================================================
// Utility: Date formatting for IMAP
// ============================================================================

namespace date_utils {

std::string format_imap_date(time_t timestamp) {
    struct tm* tm_utc = gmtime(&timestamp);
    char buf[64];
    strftime(buf, sizeof(buf), "%d-%b-%Y %H:%M:%S +0000", tm_utc);
    return std::string(buf);
}

std::string format_rfc2822_date(time_t timestamp) {
    struct tm* tm_utc = gmtime(&timestamp);
    char buf[128];

    // Day name
    static const char* day_names[] = {
        "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"
    };
    static const char* month_names[] = {
        "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
    };

    snprintf(buf, sizeof(buf), "%s, %02d %s %04d %02d:%02d:%02d +0000",
             day_names[tm_utc->tm_wday],
             tm_utc->tm_mday,
             month_names[tm_utc->tm_mon],
             tm_utc->tm_year + 1900,
             tm_utc->tm_hour,
             tm_utc->tm_min,
             tm_utc->tm_sec);

    return std::string(buf);
}

time_t parse_imap_date(const std::string& date_str) {
    struct tm tm = {};
    // Format: "DD-Mon-YYYY HH:MM:SS +ZZZZ"
    char month_str[4] = {};

    int n = sscanf(date_str.c_str(), "%d-%3s-%d %d:%d:%d",
                   &tm.tm_mday, month_str, &tm.tm_year,
                   &tm.tm_hour, &tm.tm_min, &tm.tm_sec);

    if (n < 6) return 0;

    tm.tm_year -= 1900;

    // Parse month
    static const char* months[] = {
        "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
    };

    for (int i = 0; i < 12; i++) {
        if (strcasecmp(month_str, months[i]) == 0) {
            tm.tm_mon = i;
            break;
        }
    }

    tm.tm_isdst = -1;  // Let mktime determine DST

    return timegm(&tm);
}

} // namespace date_utils

// ============================================================================
// Utility: Autocrypt header parsing
// ============================================================================

namespace autocrypt {

struct AutocryptHeader {
    std::string addr;
    std::string prefer_encrypt;
    std::string keydata;
    std::string public_key;
    time_t effective_date = 0;
    bool valid = false;
};

AutocryptHeader parse_autocrypt_header(const std::string& header_value) {
    AutocryptHeader result;

    if (header_value.empty()) return result;

    // Autocrypt header format: addr=a@b.com; prefer-encrypt=mutual; keydata=...
    std::istringstream ss(header_value);
    std::string param;

    while (std::getline(ss, param, ';')) {
        // Trim whitespace
        size_t start = 0;
        while (start < param.size() && param[start] == ' ') start++;
        param = param.substr(start);

        size_t eq = param.find('=');
        if (eq == std::string::npos) continue;

        std::string key = param.substr(0, eq);
        std::string value = param.substr(eq + 1);

        // Trim key
        size_t key_end = key.size();
        while (key_end > 0 && key[key_end - 1] == ' ') key_end--;
        key = key.substr(0, key_end);

        // Unquote value
        if (value.size() >= 2 && value.front() == '"' && value.back() == '"') {
            value = value.substr(1, value.size() - 2);
        }

        std::string key_lower;
        for (char c : key) key_lower.push_back(static_cast<char>(std::tolower(c)));

        if (key_lower == "addr") {
            result.addr = value;
        } else if (key_lower == "prefer-encrypt") {
            result.prefer_encrypt = value;
        } else if (key_lower == "keydata") {
            result.keydata = value;
            // Decode base64 keydata to get the public key
            result.public_key = base64::decode(value);
        } else if (key_lower == "effective-date") {
            result.effective_date = date_utils::parse_imap_date(value);
        }
    }

    result.valid = !result.addr.empty() && !result.keydata.empty();
    return result;
}

std::string build_autocrypt_header(const std::string& addr,
                                     const std::string& prefer_encrypt,
                                     const std::string& public_key_base64,
                                     time_t effective_date) {
    std::string header = "addr=" + addr + "; prefer-encrypt=" + prefer_encrypt;

    if (!public_key_base64.empty()) {
        header += "; keydata=" + public_key_base64;
    }

    if (effective_date > 0) {
        header += "; effective-date=" + date_utils::format_rfc2822_date(effective_date);
    }

    return header;
}

} // namespace autocrypt

// ============================================================================
// Utility: Chat-* header handling
// ============================================================================

namespace chat_headers {

struct ChatHeaders {
    int version = 0;
    std::string group_id;
    std::string group_name;
    std::string verified;
    std::string user_avatar;
    std::string content_type;
    bool is_delta_chat = false;
};

ChatHeaders extract_chat_headers(const MessageHeader& header) {
    ChatHeaders result;
    result.version = header.chat_version;
    result.group_id = header.chat_group_id;
    result.group_name = header.chat_group_name;
    result.verified = header.chat_verified;
    result.user_avatar = header.chat_user_agent;
    result.content_type = header.chat_content_type;
    result.is_delta_chat = (result.version > 0 || !result.group_id.empty());
    return result;
}

bool is_delta_chat_message(const MessageHeader& header) {
    return header.chat_version > 0 || !header.chat_group_id.empty();
}

} // namespace chat_headers

// ============================================================================
// Thread-safe connection state manager
// ============================================================================

class ConnectionStateManager {
private:
    std::mutex mutex_;
    enum class State {
        DISCONNECTED,
        CONNECTING,
        CONNECTED,
        AUTHENTICATED,
        ERROR,
        SHUTTING_DOWN
    };
    std::atomic<State> state_{State::DISCONNECTED};
    std::atomic<time_t> last_state_change_{0};
    std::string state_details_;

public:
    ConnectionStateManager() {
        last_state_change_ = time(nullptr);
    }

    void set_disconnected(const std::string& reason = "") {
        transition(State::DISCONNECTED, reason);
    }

    void set_connecting() {
        transition(State::CONNECTING);
    }

    void set_connected() {
        transition(State::CONNECTED);
    }

    void set_authenticated() {
        transition(State::AUTHENTICATED);
    }

    void set_error(const std::string& error) {
        transition(State::ERROR, error);
    }

    void set_shutting_down() {
        transition(State::SHUTTING_DOWN);
    }

    bool is_connected() const {
        State s = state_;
        return s == State::CONNECTED || s == State::AUTHENTICATED;
    }

    bool is_authenticated() const {
        return state_ == State::AUTHENTICATED;
    }

    bool is_error() const {
        return state_ == State::ERROR;
    }

    std::string get_state_string() const {
        switch (state_) {
            case State::DISCONNECTED: return "DISCONNECTED";
            case State::CONNECTING: return "CONNECTING";
            case State::CONNECTED: return "CONNECTED";
            case State::AUTHENTICATED: return "AUTHENTICATED";
            case State::ERROR: return "ERROR";
            case State::SHUTTING_DOWN: return "SHUTTING_DOWN";
            default: return "UNKNOWN";
        }
    }

    time_t get_last_state_change() const {
        return last_state_change_;
    }

    std::string get_state_details() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return state_details_;
    }

private:
    void transition(State new_state, const std::string& details = "") {
        std::lock_guard<std::mutex> lock(mutex_);
        state_ = new_state;
        state_details_ = details;
        last_state_change_ = time(nullptr);
    }
};

// ============================================================================
// Error codes and exception
// ============================================================================

enum class ImapError {
    NONE = 0,
    CONNECTION_FAILED,
    TLS_FAILED,
    AUTH_FAILED,
    PROTOCOL_ERROR,
    TIMEOUT,
    COMMAND_FAILED,
    PARSE_ERROR,
    FOLDER_NOT_FOUND,
    NETWORK_ERROR,
    PERMISSION_DENIED,
    QUOTA_EXCEEDED,
    RATE_LIMITED,
    INTERNAL_ERROR,
    NOT_CONNECTED,
    NOT_AUTHENTICATED
};

class ImapException : public std::runtime_error {
private:
    ImapError error_code_;

public:
    ImapException(ImapError code, const std::string& message)
        : std::runtime_error(message)
        , error_code_(code) {}

    ImapError error_code() const { return error_code_; }

    static const char* error_code_string(ImapError code) {
        switch (code) {
            case ImapError::NONE: return "NONE";
            case ImapError::CONNECTION_FAILED: return "CONNECTION_FAILED";
            case ImapError::TLS_FAILED: return "TLS_FAILED";
            case ImapError::AUTH_FAILED: return "AUTH_FAILED";
            case ImapError::PROTOCOL_ERROR: return "PROTOCOL_ERROR";
            case ImapError::TIMEOUT: return "TIMEOUT";
            case ImapError::COMMAND_FAILED: return "COMMAND_FAILED";
            case ImapError::PARSE_ERROR: return "PARSE_ERROR";
            case ImapError::FOLDER_NOT_FOUND: return "FOLDER_NOT_FOUND";
            case ImapError::NETWORK_ERROR: return "NETWORK_ERROR";
            case ImapError::PERMISSION_DENIED: return "PERMISSION_DENIED";
            case ImapError::QUOTA_EXCEEDED: return "QUOTA_EXCEEDED";
            case ImapError::RATE_LIMITED: return "RATE_LIMITED";
            case ImapError::INTERNAL_ERROR: return "INTERNAL_ERROR";
            case ImapError::NOT_CONNECTED: return "NOT_CONNECTED";
            case ImapError::NOT_AUTHENTICATED: return "NOT_AUTHENTICATED";
            default: return "UNKNOWN";
        }
    }
};

// ============================================================================
// Health checker
// ============================================================================

class ConnectionHealthChecker {
private:
    std::shared_ptr<ImapConnection> imap_;
    std::shared_ptr<SmtpConnection> smtp_;
    std::shared_ptr<ConnectionPool> pool_;
    int check_interval_seconds_;
    int unhealthy_threshold_;
    int consecutive_failures_;
    time_t last_check_;
    std::function<void()> on_unhealthy_;
    std::function<void()> on_recovered_;

public:
    ConnectionHealthChecker()
        : check_interval_seconds_(30)
        , unhealthy_threshold_(3)
        , consecutive_failures_(0)
        , last_check_(0) {}

    void set_connections(std::shared_ptr<ImapConnection> imap,
                         std::shared_ptr<SmtpConnection> smtp,
                         std::shared_ptr<ConnectionPool> pool) {
        imap_ = std::move(imap);
        smtp_ = std::move(smtp);
        pool_ = std::move(pool);
    }

    void set_check_interval(int seconds) {
        check_interval_seconds_ = seconds;
    }

    void set_unhealthy_threshold(int threshold) {
        unhealthy_threshold_ = threshold;
    }

    void set_on_unhealthy(std::function<void()> callback) {
        on_unhealthy_ = std::move(callback);
    }

    void set_on_recovered(std::function<void()> callback) {
        on_recovered_ = std::move(callback);
    }

    bool check_health() {
        time_t now = time(nullptr);
        if (now - last_check_ < check_interval_seconds_) {
            return consecutive_failures_ < unhealthy_threshold_;
        }

        last_check_ = now;
        bool healthy = true;

        // Check IMAP
        if (imap_) {
            if (!imap_->is_connected()) {
                healthy = false;
            } else if (!imap_->check_connection()) {
                healthy = false;
            }
        }

        // Check SMTP
        if (healthy && smtp_) {
            if (!smtp_->is_connected()) {
                healthy = false;
            } else if (!smtp_->noop_smtp()) {
                healthy = false;
            }
        }

        // Check pool
        if (healthy && pool_) {
            size_t active = pool_->active_count();
            size_t idle = pool_->idle_count();
            if (active == 0 && idle == 0) {
                // Pool is empty but might be intentional
                healthy = true;
            }
        }

        // Update failure tracking
        if (healthy) {
            bool was_unhealthy = consecutive_failures_ >= unhealthy_threshold_;
            consecutive_failures_ = 0;
            if (was_unhealthy && on_recovered_) {
                on_recovered_();
            }
        } else {
            consecutive_failures_++;
            if (consecutive_failures_ == unhealthy_threshold_ && on_unhealthy_) {
                on_unhealthy_();
            }
        }

        return healthy;
    }

    bool is_healthy() const {
        return consecutive_failures_ < unhealthy_threshold_;
    }

    int get_consecutive_failures() const {
        return consecutive_failures_;
    }

    void reset() {
        consecutive_failures_ = 0;
        last_check_ = 0;
    }
};

// ============================================================================
// Rate limiter
// ============================================================================

class RateLimiter {
private:
    std::chrono::steady_clock::time_point window_start_;
    int max_operations_;
    int operation_count_;
    std::chrono::seconds window_duration_;
    std::mutex mutex_;

public:
    RateLimiter(int max_ops_per_window, int window_seconds)
        : max_operations_(max_ops_per_window)
        , operation_count_(0)
        , window_duration_(window_seconds)
        , window_start_(std::chrono::steady_clock::now()) {}

    bool try_acquire() {
        std::lock_guard<std::mutex> lock(mutex_);

        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            now - window_start_);

        if (elapsed >= window_duration_) {
            // New window
            window_start_ = now;
            operation_count_ = 0;
        }

        if (operation_count_ >= max_operations_) {
            return false;
        }

        operation_count_++;
        return true;
    }

    void wait_and_acquire() {
        while (!try_acquire()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }

    int remaining() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return std::max(0, max_operations_ - operation_count_);
    }

    void reset() {
        std::lock_guard<std::mutex> lock(mutex_);
        window_start_ = std::chrono::steady_clock::now();
        operation_count_ = 0;
    }
};

// ============================================================================
// Prefetch manager for FETCH_EXISTING_MSGS mode
// ============================================================================

class PrefetchManager {
public:
    struct PrefetchState {
        bool in_progress = false;
        uint32_t total_messages = 0;
        uint32_t fetched_count = 0;
        uint32_t last_uid = 0;
        time_t started_at = 0;
        time_t completed_at = 0;
    };

private:
    PrefetchState state_;
    std::mutex mutex_;
    std::function<void(const ParsedMessage&)> message_handler_;
    std::shared_ptr<FolderSync> folder_sync_;

public:
    void set_folder_sync(std::shared_ptr<FolderSync> sync) {
        folder_sync_ = std::move(sync);
    }

    void set_message_handler(std::function<void(const ParsedMessage&)> handler) {
        message_handler_ = std::move(handler);
    }

    bool start_prefetch(uint32_t last_known_uid = 0) {
        std::lock_guard<std::mutex> lock(mutex_);

        if (state_.in_progress) return false;

        state_.in_progress = true;
        state_.last_uid = last_known_uid;
        state_.fetched_count = 0;
        state_.started_at = time(nullptr);
        state_.completed_at = 0;

        return true;
    }

    void update_progress(uint32_t fetched_count, uint32_t total) {
        std::lock_guard<std::mutex> lock(mutex_);
        state_.fetched_count = fetched_count;
        state_.total_messages = total;
    }

    void complete_prefetch() {
        std::lock_guard<std::mutex> lock(mutex_);
        state_.in_progress = false;
        state_.completed_at = time(nullptr);
    }

    void abort_prefetch() {
        std::lock_guard<std::mutex> lock(mutex_);
        state_.in_progress = false;
    }

    PrefetchState get_state() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return state_;
    }

    bool is_in_progress() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return state_.in_progress;
    }

    double get_progress_percent() const {
        std::lock_guard<std::mutex> lock(mutex_);
        if (state_.total_messages == 0) return 0.0;
        return (static_cast<double>(state_.fetched_count) /
                static_cast<double>(state_.total_messages)) * 100.0;
    }
};

} // namespace deltachat
} // namespace progressive
