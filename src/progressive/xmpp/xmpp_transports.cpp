// =============================================================================
// xmpp_transports.cpp
// XMPP Transport Layer: BOSH (XEP-0124/XEP-0206), WebSocket (RFC 7395),
// HTTP Long Poll, Transport Negotiation, and Connection Management
// =============================================================================
// Implements:
//   - BOSH connection manager (XEP-0124): session management, request/response,
//     stanza wrapping/unwrapping, HTTP long polling
//   - WebSocket transport (RFC 7395): handshake, frame encoding/decoding,
//     XMPP subprotocol framing, stream management
//   - HTTP Poll transport (legacy): simple request/response polling
//   - Connection Manager Discovery (XEP-0156): DNS SRV + HTTP well-known
//   - Transport negotiation: select best transport, fallback chain
//   - Transport reconnection: session resumption, multi-host failover
//   - Transport metrics: connection counts, latency, throughput
//   - Transport rate limiting: token bucket per connection
//   - Transport compression: deflate/gzip for BOSH and WebSocket
//   - Cross-origin support: CORS headers, preflight handling
//   - Keep-alive management: heartbeat, ping/pong, timeout detection
//   - Transport error handling: retry, backoff, circuit breaker
// =============================================================================

#include <string>
#include <string_view>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <map>
#include <set>
#include <deque>
#include <memory>
#include <functional>
#include <optional>
#include <variant>
#include <ctime>
#include <cstdint>
#include <cstring>
#include <algorithm>
#include <sstream>
#include <chrono>
#include <random>
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <regex>
#include <cmath>
#include <iomanip>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#include <nlohmann/json.hpp>

namespace progressive {
namespace xmpp {

using json = nlohmann::json;

// =============================================================================
// Utility helpers
// =============================================================================

static int64_t nms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

static int64_t nus() {
    return std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

static std::string gen_id() {
    static std::atomic<int64_t> counter{1};
    return "xmpp-" + std::to_string(nms()) + "-" +
           std::to_string(counter.fetch_add(1, std::memory_order_relaxed));
}

static std::string gen_token(int length = 32) {
    static const char chars[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    static thread_local std::mt19937 rng(nms());
    std::uniform_int_distribution<> dist(0, 61);
    std::string token(length, 'A');
    for (auto& c : token) c = chars[dist(rng)];
    return token;
}

static std::string gen_sid() {
    return gen_token(16);
}

// =============================================================================
// Base64 encoding/decoding (for WebSocket key, SASL, etc.)
// =============================================================================

static const std::string B64_TABLE =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static std::string base64_encode(const std::string& input) {
    std::string out;
    out.reserve(((input.size() + 2) / 3) * 4);
    int val = 0, valb = -6;
    for (unsigned char c : input) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            out.push_back(B64_TABLE[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6)
        out.push_back(B64_TABLE[((val << 8) >> (valb + 8)) & 0x3F]);
    while (out.size() % 4)
        out.push_back('=');
    return out;
}

static std::string base64_decode(const std::string& input) {
    std::vector<int> T(256, -1);
    for (int i = 0; i < 64; i++) T[(unsigned char)B64_TABLE[i]] = i;
    std::string out;
    out.reserve(input.size() * 3 / 4);
    int val = 0, valb = -8;
    for (unsigned char c : input) {
        if (T[c] == -1) break;
        val = (val << 6) + T[c];
        valb += 6;
        if (valb >= 0) {
            out.push_back(static_cast<char>((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return out;
}

// =============================================================================
// SHA1 for WebSocket handshake
// =============================================================================

static std::string sha1(const std::string& input) {
    uint32_t h[5] = {
        0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0
    };
    uint64_t total_bits = 0;
    uint8_t block[64];
    int buf_index = 0;

    auto transform = [&](uint8_t* blk) {
        uint32_t w[80];
        for (int i = 0; i < 16; i++) {
            w[i] = (blk[i * 4] << 24) | (blk[i * 4 + 1] << 16) |
                   (blk[i * 4 + 2] << 8) | blk[i * 4 + 3];
        }
        for (int i = 16; i < 80; i++) {
            w[i] = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16];
            w[i] = (w[i] << 1) | (w[i] >> 31);
        }
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
        for (int i = 0; i < 80; i++) {
            uint32_t f, k;
            if (i < 20) { f = (b & c) | ((~b) & d); k = 0x5A827999; }
            else if (i < 40) { f = b ^ c ^ d; k = 0x6ED9EBA1; }
            else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
            else { f = b ^ c ^ d; k = 0xCA62C1D6; }
            uint32_t temp = ((a << 5) | (a >> 27)) + f + e + k + w[i];
            e = d; d = c; c = (b << 30) | (b >> 2); b = a; a = temp;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
    };

    for (size_t i = 0; i < input.size(); i++) {
        block[buf_index++] = input[i];
        total_bits += 8;
        if (buf_index == 64) { transform(block); buf_index = 0; }
    }

    block[buf_index++] = 0x80;
    if (buf_index > 56) {
        while (buf_index < 64) block[buf_index++] = 0;
        transform(block);
        buf_index = 0;
    }
    while (buf_index < 56) block[buf_index++] = 0;

    uint64_t bits = total_bits;
    for (int i = 7; i >= 0; i--) {
        block[56 + i] = static_cast<uint8_t>(bits & 0xFF);
        bits >>= 8;
    }
    transform(block);

    std::string digest(20, '\0');
    for (int i = 0; i < 5; i++) {
        digest[i * 4]     = (h[i] >> 24) & 0xFF;
        digest[i * 4 + 1] = (h[i] >> 16) & 0xFF;
        digest[i * 4 + 2] = (h[i] >> 8) & 0xFF;
        digest[i * 4 + 3] = h[i] & 0xFF;
    }
    return digest;
}

// =============================================================================
// URL encoding/decoding
// =============================================================================

static std::string url_decode(const std::string& str) {
    std::string result;
    result.reserve(str.size());
    for (size_t i = 0; i < str.size(); i++) {
        if (str[i] == '%' && i + 2 < str.size()) {
            int value = 0;
            auto hex = [](char c) -> int {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                return -1;
            };
            int h1 = hex(str[i + 1]), h2 = hex(str[i + 2]);
            if (h1 >= 0 && h2 >= 0) {
                result += static_cast<char>((h1 << 4) | h2);
                i += 2;
                continue;
            }
        } else if (str[i] == '+') {
            result += ' ';
            continue;
        }
        result += str[i];
    }
    return result;
}

static std::string url_encode(const std::string& str) {
    std::ostringstream oss;
    oss << std::hex;
    for (unsigned char c : str) {
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            oss << c;
        } else {
            oss << '%' << std::uppercase << std::setw(2) << std::setfill('0')
                << (int)c << std::nouppercase;
        }
    }
    return oss.str();
}

// =============================================================================
// XML escaping helpers
// =============================================================================

static std::string xml_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size() * 1.2);
    for (char c : s) {
        switch (c) {
            case '&':  out += "&amp;"; break;
            case '<':  out += "&lt;"; break;
            case '>':  out += "&gt;"; break;
            case '"':  out += "&quot;"; break;
            case '\'': out += "&apos;"; break;
            default:   out += c;
        }
    }
    return out;
}

static std::string xml_unescape(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size(); i++) {
        if (s[i] == '&') {
            if (s.compare(i, 5, "&amp;") == 0)  { out += '&'; i += 4; }
            else if (s.compare(i, 4, "&lt;") == 0)  { out += '<'; i += 3; }
            else if (s.compare(i, 4, "&gt;") == 0)  { out += '>'; i += 3; }
            else if (s.compare(i, 6, "&quot;") == 0) { out += '"'; i += 5; }
            else if (s.compare(i, 6, "&apos;") == 0) { out += '\''; i += 5; }
            else { out += s[i]; }
        } else {
            out += s[i];
        }
    }
    return out;
}

// =============================================================================
// Deflate/Zlib-style compression helpers
// =============================================================================

namespace compress {

// Minimal deflate compression for BOSH/WebSocket transport compression
// Uses fixed Huffman coding - a simplified, self-contained implementation
// that compresses XMPP XML reasonably well without external libraries.

struct DeflateState {
    std::string output;
    uint32_t bit_buf = 0;
    int bit_count = 0;

    void emit_bit(int bit) {
        bit_buf |= (bit & 1) << bit_count;
        bit_count++;
        if (bit_count >= 8) {
            output.push_back(static_cast<char>(bit_buf & 0xFF));
            bit_buf >>= 8;
            bit_count -= 8;
        }
    }

    void emit_bits(int value, int num_bits) {
        for (int i = 0; i < num_bits; i++) {
            emit_bit((value >> i) & 1);
        }
    }

    void emit_bits_rev(int value, int num_bits) {
        for (int i = 0; i < num_bits; i++) {
            emit_bit((value >> (num_bits - 1 - i)) & 1);
        }
    }

    void flush() {
        if (bit_count > 0) {
            output.push_back(static_cast<char>(bit_buf & 0xFF));
            bit_buf = 0;
            bit_count = 0;
        }
    }
};

// Fixed huffman codes for literal/length alphabet
static int fixed_lit_code(int literal) {
    if (literal <= 143) return 0x030 + literal;
    if (literal <= 255) return 0x190 + literal - 144;
    if (literal <= 279) return 0x000 + literal - 256;
    return 0x0C0 + literal - 280;
}

static int fixed_lit_bits(int literal) {
    if (literal <= 143) return 8;
    if (literal <= 255) return 9;
    if (literal <= 279) return 7;
    return 8;
}

static std::string deflate_compress(const std::string& data) {
    DeflateState s;
    // BFINAL=1, BTYPE=1 (fixed huffman)
    s.emit_bit(1); // BFINAL
    s.emit_bits(1, 2); // BTYPE = 01 (fixed)

    for (size_t i = 0; i < data.size(); i++) {
        unsigned char c = data[i];
        int code = fixed_lit_code(c);
        int bits = fixed_lit_bits(c);
        s.emit_bits_rev(code, bits);
    }

    // End of block: literal 256
    s.emit_bits_rev(0x000, 7);

    s.flush();
    return s.output;
}

static std::string deflate_decompress(const std::string& data) {
    // For our simplified scheme, we only decompress fixed-huffman blocks
    // that were compressed with the above method.
    std::string result;
    uint32_t bit_buf = 0;
    int bit_count = 0;
    size_t pos = 0;

    auto peek_bits = [&](int n) -> int {
        while (bit_count < n && pos < data.size()) {
            bit_buf |= static_cast<unsigned char>(data[pos++]) << bit_count;
            bit_count += 8;
        }
        return bit_buf & ((1 << n) - 1);
    };

    auto consume_bits = [&](int n) {
        bit_buf >>= n;
        bit_count -= n;
    };

    // Read header: BFINAL=1, BTYPE=01
    int bfinal = peek_bits(1); consume_bits(1);
    int btype = peek_bits(2); consume_bits(2);
    if (btype != 1) return data; // not fixed huffman, return raw

    while (true) {
        // Read fixed huffman code
        int next7 = peek_bits(7);
        if (next7 <= 0x017) { // 0-23: length codes 256-279
            // Literal 256 (end of block) is code 0
            int code = peek_bits(7);
            consume_bits(7);
            if (code == 0x000) break;
            // Not our simplified encoding; bail
            return data;
        } else if (next7 <= 0x02F) {
            // 7-bit codes: 0-47 maps to 256-279
            // Actually in fixed huffman, 7-bit codes are 256-279
            // Code 0x000 = 256 (end), 0x001 = 257, etc.
            // For literals 0-143, codes are 0x030-0x0BF (8 bits)
            // For 144-255, codes are 0x190-0x1FF (9 bits)
            // For 280-287, codes are 0x0C0-0x0C7 (8 bits)
            int code = peek_bits(7);
            consume_bits(7);
            int literal = code - 0x030 + 0;
            if (literal >= 0 && literal <= 143) {
                result += static_cast<char>(literal);
            }
        } else {
            // 8 or 9 bits
            int code8 = peek_bits(8);
            if (code8 >= 0x0C0 && code8 <= 0x0C7) {
                consume_bits(8);
                int literal = code8 - 0x0C0 + 280;
                result += static_cast<char>(literal);
            } else if (code8 >= 0x030 && code8 <= 0x0BF) {
                consume_bits(8);
                int literal = code8 - 0x030;
                result += static_cast<char>(literal);
            } else {
                int code9 = peek_bits(9);
                if (code9 >= 0x190 && code9 <= 0x1FF) {
                    consume_bits(9);
                    int literal = code9 - 0x190 + 144;
                    result += static_cast<char>(literal);
                } else {
                    return data; // unrecognized
                }
            }
        }
    }

    return result;
}

} // namespace compress

// =============================================================================
// Transport namespace constants
// =============================================================================

namespace transport_ns {
    constexpr const char* BOSH        = "http://jabber.org/protocol/httpbind";
    constexpr const char* BOSH_XMPP   = "urn:xmpp:bosh";
    constexpr const char* WEBSOCKET   = "urn:xmpp:websocket";
    constexpr const char* HTTP_POLL   = "urn:xmpp:httppoll:0";
    constexpr const char* CM_DISCO    = "urn:xmpp:connectionmanager:disco";
    constexpr const char* STREAM_MGMT = "urn:xmpp:sm:3";
    constexpr const char* COMPRESS    = "http://jabber.org/features/compress";
    constexpr const char* CORS        = "urn:xmpp:cors:0";
}

// =============================================================================
// Transport type enumeration
// =============================================================================

enum class TransportType : uint8_t {
    NONE       = 0,
    BOSH       = 1,
    WEBSOCKET  = 2,
    HTTP_POLL  = 3,
    RAW_TCP    = 4,  // standard XMPP C2S
    RAW_TLS    = 5,  // direct TLS
};

const char* transport_type_str(TransportType t) {
    switch (t) {
        case TransportType::BOSH:      return "bosh";
        case TransportType::WEBSOCKET: return "websocket";
        case TransportType::HTTP_POLL: return "http-poll";
        case TransportType::RAW_TCP:   return "tcp";
        case TransportType::RAW_TLS:   return "tls";
        default: return "unknown";
    }
}

// =============================================================================
// Transport metrics / statistics
// =============================================================================

struct TransportMetrics {
    // Connection counts
    std::atomic<int64_t> active_connections{0};
    std::atomic<int64_t> total_connections_created{0};
    std::atomic<int64_t> total_connections_closed{0};
    std::atomic<int64_t> failed_handshakes{0};

    // Traffic
    std::atomic<int64_t> bytes_sent{0};
    std::atomic<int64_t> bytes_received{0};
    std::atomic<int64_t> frames_sent{0};
    std::atomic<int64_t> frames_received{0};
    std::atomic<int64_t> stanzas_sent{0};
    std::atomic<int64_t> stanzas_received{0};

    // Latency (rolling average in microseconds)
    std::atomic<int64_t> avg_latency_us{0};
    std::atomic<int64_t> max_latency_us{0};
    std::atomic<int64_t> p99_latency_us{0};

    // Session
    std::atomic<int64_t> active_sessions{0};
    std::atomic<int64_t> resumed_sessions{0};
    std::atomic<int64_t> expired_sessions{0};

    // Errors
    std::atomic<int64_t> rate_limit_hits{0};
    std::atomic<int64_t> compression_errors{0};
    std::atomic<int64_t> frame_decode_errors{0};
    std::atomic<int64_t> timeout_errors{0};

    void record_connection() {
        active_connections.fetch_add(1);
        total_connections_created.fetch_add(1);
    }

    void record_disconnection() {
        active_connections.fetch_sub(1);
        total_connections_closed.fetch_add(1);
    }

    void record_bytes_sent(int64_t n) { bytes_sent.fetch_add(n); }
    void record_bytes_received(int64_t n) { bytes_received.fetch_add(n); }
    void record_frame_sent() { frames_sent.fetch_add(1); }
    void record_frame_received() { frames_received.fetch_add(1); }
    void record_stanza_sent() { stanzas_sent.fetch_add(1); }
    void record_stanza_received() { stanzas_received.fetch_add(1); }
    void record_latency(int64_t us) {
        int64_t cur = avg_latency_us.load();
        avg_latency_us.store(cur > 0 ? (cur * 15 + us) / 16 : us);
        int64_t cur_max = max_latency_us.load();
        if (us > cur_max) max_latency_us.store(us);
    }

    json to_json() const {
        return json{
            {"active_connections", active_connections.load()},
            {"total_connections_created", total_connections_created.load()},
            {"total_connections_closed", total_connections_closed.load()},
            {"failed_handshakes", failed_handshakes.load()},
            {"bytes_sent", bytes_sent.load()},
            {"bytes_received", bytes_received.load()},
            {"frames_sent", frames_sent.load()},
            {"frames_received", frames_received.load()},
            {"stanzas_sent", stanzas_sent.load()},
            {"stanzas_received", stanzas_received.load()},
            {"avg_latency_us", avg_latency_us.load()},
            {"max_latency_us", max_latency_us.load()},
            {"active_sessions", active_sessions.load()},
            {"resumed_sessions", resumed_sessions.load()},
            {"expired_sessions", expired_sessions.load()},
            {"rate_limit_hits", rate_limit_hits.load()},
            {"compression_errors", compression_errors.load()},
            {"frame_decode_errors", frame_decode_errors.load()},
            {"timeout_errors", timeout_errors.load()},
        };
    }
};

// =============================================================================
// Rate limiter (token bucket algorithm)
// =============================================================================

class TokenBucket {
public:
    TokenBucket(double rate_per_sec, double burst_size)
        : rate_(rate_per_sec), burst_(burst_size), tokens_(burst_size),
          last_refill_(nus()) {}

    void set_rate(double rate_per_sec) {
        rate_ = rate_per_sec;
        if (tokens_ > burst_) tokens_ = burst_;
    }

    void set_burst(double burst_size) {
        burst_ = burst_size;
        if (tokens_ > burst_) tokens_ = burst_size;
    }

    bool consume(int64_t tokens = 1) {
        refill();
        if (tokens_ >= tokens) {
            tokens_ -= tokens;
            return true;
        }
        return false;
    }

    int64_t available() {
        refill();
        return static_cast<int64_t>(tokens_);
    }

    double tokens_available() const { return tokens_; }

private:
    void refill() {
        int64_t now = nus();
        double elapsed = static_cast<double>(now - last_refill_) / 1000000.0;
        tokens_ = std::min(burst_, tokens_ + elapsed * rate_);
        last_refill_ = now;
    }

    double rate_;
    double burst_;
    double tokens_;
    int64_t last_refill_;
};

// =============================================================================
// BOSH Session (XEP-0124 §9)
// =============================================================================

struct BoshSession {
    std::string sid;                         // Session ID
    std::string from;                        // Client JID
    std::string to;                          // Server domain
    std::string route;                       // Routing hint
    std::string xml_lang;                    // xml:lang
    std::string accept;                      // Content-Types accepted
    std::string hold_str;                    // Original hold value

    int64_t created_at = 0;                  // Creation timestamp
    int64_t last_activity = 0;               // Last request timestamp
    int64_t expires = 0;                     // Expiration timestamp

    int wait = 30;                           // Max wait time (seconds)
    int hold = 1;                            // Max simultaneous requests
    int requests = 2;                        // Max requests between ack windows
    int64_t inactivity = 60;                 // Max inactivity (seconds)
    int64_t max_pause = 300;                 // Max pause (seconds)
    uint32_t rid = 0;                        // Last request ID
    uint32_t last_ack = 0;                   // Last acknowledged RID
    int version_minor = 6;                   // BOSH protocol version
    int version_major = 1;

    bool terminated = false;                 // Session ended
    bool paused = false;                     // Session paused
    bool restartable = true;                 // Can be resumed
    bool use_acks = true;                    // Use ack system
    bool authenticated = false;              // SASL authenticated
    bool compressed = false;                 // Body compression
    bool secure = false;                     // HTTPS
    bool xmpp_restart = false;               // XMPP stream restart needed

    // Queued stanzas waiting to be delivered to client
    std::deque<std::string> outbound_queue;
    mutable std::mutex queue_mutex;

    // Stream management (XEP-0198 over BOSH)
    int sm_h_in = 0;                         // Inbound stanza count (server->client)
    int sm_h_out = 0;                        // Outbound ack (client->server)
    bool sm_enabled = false;
    std::string sm_id;

    // Metrics
    int64_t total_requests = 0;
    int64_t total_stanzas_in = 0;
    int64_t total_stanzas_out = 0;
    int64_t bytes_in = 0;
    int64_t bytes_out = 0;
    int64_t poll_count = 0;

    // Transport routing
    std::string client_ip;
    TransportType transport = TransportType::BOSH;

    BoshSession() {
        sid = gen_sid();
        created_at = nms();
        last_activity = created_at;
    }

    bool is_expired() const {
        return nms() > expires;
    }

    void touch() {
        last_activity = nms();
        expires = last_activity + inactivity * 1000;
    }

    json to_json() const {
        json j;
        j["sid"] = sid;
        j["from"] = from;
        j["to"] = to;
        j["rid"] = rid;
        j["hold"] = hold;
        j["wait"] = wait;
        j["created_at"] = created_at;
        j["last_activity"] = last_activity;
        j["total_requests"] = total_requests;
        j["total_stanzas_in"] = total_stanzas_in;
        j["total_stanzas_out"] = total_stanzas_out;
        j["compressed"] = compressed;
        j["secure"] = secure;
        j["authenticated"] = authenticated;
        j["terminated"] = terminated;
        j["sm_enabled"] = sm_enabled;
        return j;
    }
};

// =============================================================================
// WebSocket connection state
// =============================================================================

enum class WebSocketOpcode : uint8_t {
    CONTINUATION = 0x0,
    TEXT         = 0x1,
    BINARY       = 0x2,
    CLOSE        = 0x8,
    PING         = 0x9,
    PONG         = 0xA,
};

enum class WebSocketCloseCode : uint16_t {
    NORMAL              = 1000,
    GOING_AWAY          = 1001,
    PROTOCOL_ERROR      = 1002,
    UNSUPPORTED_DATA    = 1003,
    RESERVED            = 1004,
    NO_STATUS           = 1005,
    ABNORMAL            = 1006,
    INVALID_PAYLOAD     = 1007,
    POLICY_VIOLATION    = 1008,
    MESSAGE_TOO_BIG     = 1009,
    EXTENSION_REQUIRED  = 1010,
    INTERNAL_ERROR      = 1011,
    SERVICE_RESTART     = 1012,
    TRY_AGAIN_LATER     = 1013,
};

enum class WebSocketState : uint8_t {
    CONNECTING    = 0,
    OPEN          = 1,
    CLOSING       = 2,
    CLOSED        = 3,
};

struct WebSocketFrame {
    bool fin = true;
    bool rsv1 = false;
    bool rsv2 = false;
    bool rsv3 = false;
    WebSocketOpcode opcode = WebSocketOpcode::TEXT;
    bool mask = false;
    uint32_t mask_key = 0;
    std::string payload;

    WebSocketFrame() = default;

    WebSocketFrame(WebSocketOpcode op, const std::string& data, bool f = true)
        : fin(f), opcode(op), payload(data) {}

    static std::optional<WebSocketFrame> parse(const uint8_t* data, size_t len,
                                                size_t& consumed) {
        if (len < 2) return std::nullopt;

        consumed = 2;
        WebSocketFrame frame;
        uint8_t byte0 = data[0];
        uint8_t byte1 = data[1];

        frame.fin  = (byte0 >> 7) & 1;
        frame.rsv1 = (byte0 >> 6) & 1;
        frame.rsv2 = (byte0 >> 5) & 1;
        frame.rsv3 = (byte0 >> 4) & 1;
        frame.opcode = static_cast<WebSocketOpcode>(byte0 & 0x0F);
        frame.mask = (byte1 >> 7) & 1;

        uint64_t payload_len = byte1 & 0x7F;

        if (payload_len == 126) {
            if (len < 4) return std::nullopt;
            payload_len = (data[2] << 8) | data[3];
            consumed += 2;
        } else if (payload_len == 127) {
            if (len < 10) return std::nullopt;
            payload_len = 0;
            for (int i = 0; i < 8; i++) {
                payload_len = (payload_len << 8) | data[2 + i];
            }
            consumed += 8;
        }

        if (frame.mask) {
            if (len < consumed + 4) return std::nullopt;
            frame.mask_key = (data[consumed] << 24) | (data[consumed + 1] << 16) |
                             (data[consumed + 2] << 8) | data[consumed + 3];
            consumed += 4;
        }

        if (payload_len > len - consumed) return std::nullopt;

        frame.payload.assign(
            reinterpret_cast<const char*>(data + consumed),
            static_cast<size_t>(payload_len));

        if (frame.mask) {
            uint8_t* mask_bytes = reinterpret_cast<uint8_t*>(&frame.mask_key);
            for (size_t i = 0; i < frame.payload.size(); i++) {
                frame.payload[i] ^= mask_bytes[i % 4];
            }
        }

        consumed += static_cast<size_t>(payload_len);
        return frame;
    }

    std::string encode(bool mask_output = false) const {
        std::string result;
        uint8_t byte0 = (fin ? 0x80 : 0x00) |
                        (rsv1 ? 0x40 : 0x00) |
                        (rsv2 ? 0x20 : 0x00) |
                        (rsv3 ? 0x10 : 0x00) |
                        (static_cast<uint8_t>(opcode) & 0x0F);
        result.push_back(static_cast<char>(byte0));

        uint8_t byte1 = mask_output ? 0x80 : 0x00;
        uint64_t len = payload.size();

        if (len <= 125) {
            byte1 |= static_cast<uint8_t>(len);
            result.push_back(static_cast<char>(byte1));
        } else if (len <= 65535) {
            byte1 |= 126;
            result.push_back(static_cast<char>(byte1));
            result.push_back(static_cast<char>((len >> 8) & 0xFF));
            result.push_back(static_cast<char>(len & 0xFF));
        } else {
            byte1 |= 127;
            result.push_back(static_cast<char>(byte1));
            for (int i = 7; i >= 0; i--) {
                result.push_back(static_cast<char>((len >> (i * 8)) & 0xFF));
            }
        }

        if (mask_output) {
            uint32_t mk = mask_key;
            result.push_back(static_cast<char>((mk >> 24) & 0xFF));
            result.push_back(static_cast<char>((mk >> 16) & 0xFF));
            result.push_back(static_cast<char>((mk >> 8) & 0xFF));
            result.push_back(static_cast<char>(mk & 0xFF));

            const uint8_t* mk_bytes = reinterpret_cast<const uint8_t*>(&mk);
            for (size_t i = 0; i < payload.size(); i++) {
                result.push_back(payload[i] ^ mk_bytes[i % 4]);
            }
        } else {
            result += payload;
        }

        return result;
    }
};

struct WebSocketConnection {
    int fd = -1;
    std::string id;                          // Connection ID
    std::string remote_addr;                 // Client IP
    std::string user_agent;
    std::string origin;
    std::string protocol;                    // Negotiated sub-protocol
    std::string resource;                    // URI path
    std::string host;
    std::string key;                         // Sec-WebSocket-Key

    WebSocketState state = WebSocketState::CONNECTING;
    TransportType transport = TransportType::WEBSOCKET;

    int64_t created_at = 0;
    int64_t last_activity = 0;
    int64_t last_ping = 0;
    int64_t last_pong = 0;
    int64_t ping_interval = 30;              // Seconds between pings

    bool authenticated = false;
    bool compressed = false;
    bool xmpp_subprotocol = false;
    bool secure = false;                     // WSS

    // Fragmented message reassembly
    std::string fragment_buffer;
    WebSocketOpcode fragment_opcode = WebSocketOpcode::TEXT;

    // Outbound queue with backpressure
    std::deque<std::string> send_queue;
    std::deque<std::string> send_queue_high; // High priority (control frames)
    mutable std::mutex send_mutex;
    int64_t max_send_queue = 1024 * 1024;    // 1MB max

    // Rate limiting
    TokenBucket rate_limiter{1000, 100};     // 1000 msgs/sec, burst 100

    // Stream management (XEP-0198)
    int sm_h_in = 0;
    int sm_h_out = 0;
    bool sm_enabled = false;
    std::string sm_id;

    // Metrics
    int64_t frames_sent = 0;
    int64_t frames_received = 0;
    int64_t bytes_sent = 0;
    int64_t bytes_received = 0;
    int64_t pings_sent = 0;
    int64_t pongs_received = 0;
    int64_t stanza_count = 0;
    int64_t connect_latency_us = 0;          // Time from connect to open

    WebSocketConnection() {
        id = gen_id();
        created_at = nms();
        last_activity = created_at;
    }

    void touch() {
        last_activity = nms();
    }

    bool is_stale(int64_t timeout_ms = 60000) const {
        return (nms() - last_activity) > timeout_ms;
    }

    bool needs_ping() const {
        if (ping_interval <= 0) return false;
        return (nms() - last_ping) > ping_interval * 1000;
    }

    json to_json() const {
        json j;
        j["id"] = id;
        j["fd"] = fd;
        j["remote_addr"] = remote_addr;
        j["state"] = static_cast<int>(state);
        j["protocol"] = protocol;
        j["secure"] = secure;
        j["compressed"] = compressed;
        j["authenticated"] = authenticated;
        j["created_at"] = created_at;
        j["last_activity"] = last_activity;
        j["frames_sent"] = frames_sent;
        j["frames_received"] = frames_received;
        j["bytes_sent"] = bytes_sent;
        j["bytes_received"] = bytes_received;
        j["stanza_count"] = stanza_count;
        j["sm_enabled"] = sm_enabled;
        return j;
    }
};

// =============================================================================
// HTTP Poll transport session
// =============================================================================

struct HttpPollSession {
    std::string sid;
    std::string jid;
    int64_t created_at = 0;
    int64_t last_poll = 0;
    int64_t expires = 0;
    bool authenticated = false;
    std::deque<std::string> pending_stanzas;
    mutable std::mutex mutex;

    HttpPollSession() {
        sid = gen_sid();
        created_at = nms();
        last_poll = created_at;
        expires = created_at + 300000; // 5 min
    }

    void touch() { last_poll = nms(); }
    bool is_expired() const { return nms() > expires; }

    void enqueue(const std::string& stanza) {
        std::lock_guard lock(mutex);
        pending_stanzas.push_back(stanza);
        if (pending_stanzas.size() > 100) {
            pending_stanzas.pop_front(); // Drop oldest if queue full
        }
    }

    std::vector<std::string> drain() {
        std::lock_guard lock(mutex);
        std::vector<std::string> result;
        result.reserve(pending_stanzas.size());
        while (!pending_stanzas.empty()) {
            result.push_back(pending_stanzas.front());
            pending_stanzas.pop_front();
        }
        return result;
    }
};

// =============================================================================
// Connection Manager Discovery (XEP-0156) - DNS SRV records
// =============================================================================

struct ConnectionManagerEndpoint {
    std::string host;
    int port = 5280;
    TransportType transport = TransportType::BOSH;
    std::string path = "/http-bind";
    int priority = 0;
    int weight = 0;
    bool secure = false;
};

// =============================================================================
// Transport negotiation result
// =============================================================================

struct TransportNegotiation {
    TransportType selected = TransportType::NONE;
    std::string endpoint_url;
    int priority = 0;
    std::string error;
    bool fallback_used = false;
    std::vector<TransportType> tried;
};

// =============================================================================
// CORS configuration
// =============================================================================

struct CorsConfig {
    bool enabled = true;
    std::string allow_origin = "*";
    std::string allow_methods = "GET, POST, OPTIONS";
    std::string allow_headers = "Content-Type, Authorization, X-Requested-With, Accept";
    std::string expose_headers = "X-BOSH-SID, X-BOSH-RID, X-BOSH-WAIT, X-BOSH-HOLD";
    std::string allow_credentials = "true";
    int64_t max_age = 86400; // 24 hours

    std::string get_headers() const {
        std::ostringstream oss;
        oss << "Access-Control-Allow-Origin: " << allow_origin << "\r\n"
            << "Access-Control-Allow-Methods: " << allow_methods << "\r\n"
            << "Access-Control-Allow-Headers: " << allow_headers << "\r\n"
            << "Access-Control-Allow-Credentials: " << allow_credentials << "\r\n"
            << "Access-Control-Max-Age: " << max_age << "\r\n"
            << "Access-Control-Expose-Headers: " << expose_headers << "\r\n";
        return oss.str();
    }

    bool is_origin_allowed(const std::string& origin) const {
        if (allow_origin == "*") return true;
        // Simple glob matching: *.example.com, example.com
        if (allow_origin == origin) return true;
        if (allow_origin.size() > 2 && allow_origin[0] == '*' && allow_origin[1] == '.') {
            std::string suffix = allow_origin.substr(1);
            return origin.size() >= suffix.size() &&
                   origin.compare(origin.size() - suffix.size(), suffix.size(), suffix) == 0;
        }
        return false;
    }
};

// =============================================================================
// Keep-alive manager
// =============================================================================

struct KeepAliveConfig {
    bool enabled = true;
    int64_t interval_ms = 30000;    // 30 seconds between keep-alives
    int64_t timeout_ms = 120000;    // 2 minutes before considering dead
    int max_missed = 3;             // Max missed pings before disconnect
    bool use_tcp_keepalive = true;  // Enable SO_KEEPALIVE
    int tcp_keepalive_idle = 60;    // seconds
    int tcp_keepalive_interval = 10;
    int tcp_keepalive_count = 5;
};

// =============================================================================
// Transport configuration
// =============================================================================

struct TransportConfig {
    // General
    bool enabled = true;
    int max_connections = 100000;
    int max_stanza_size = 65536;
    int64_t connection_timeout_ms = 300000; // 5 minutes

    // BOSH
    bool bosh_enabled = true;
    std::string bosh_path = "/http-bind";
    int bosh_max_wait = 120;         // seconds
    int bosh_min_wait = 5;
    int bosh_default_wait = 30;
    int bosh_max_hold = 10;
    int bosh_max_requests = 20;
    int64_t bosh_max_inactivity = 120;
    int64_t bosh_max_pause = 300;
    int bosh_polling_interval = 25;  // ms between polls
    bool bosh_compression = true;
    bool bosh_use_acks = true;

    // WebSocket
    bool websocket_enabled = true;
    std::string websocket_path = "/xmpp-websocket";
    int websocket_max_frame_size = 1048576;  // 1MB
    int websocket_max_message_size = 1048576;
    int64_t websocket_ping_interval = 30;    // seconds
    int64_t websocket_timeout = 120000;      // 2 minutes
    bool websocket_permessage_deflate = true;
    std::string websocket_protocols = "xmpp";

    // HTTP Poll
    bool httppoll_enabled = true;
    std::string httppoll_path = "/http-poll";
    int64_t httppoll_timeout = 60000;

    // Rate limiting
    bool rate_limit_enabled = true;
    double rate_limit_per_sec = 100.0;       // 100 stanzas/sec
    double rate_limit_burst = 200.0;

    // CORS
    CorsConfig cors;

    // Keep-alive
    KeepAliveConfig keepalive;

    // Transport fallback order
    std::vector<TransportType> fallback_order = {
        TransportType::WEBSOCKET,
        TransportType::BOSH,
        TransportType::HTTP_POLL,
    };
};

// =============================================================================
// Transport error types
// =============================================================================

enum class TransportError : uint8_t {
    NONE                    = 0,
    CONNECTION_FAILED       = 1,
    HANDSHAKE_FAILED        = 2,
    TIMEOUT                 = 3,
    RATE_LIMITED            = 4,
    INVALID_FRAME           = 5,
    FRAME_TOO_LARGE         = 6,
    SESSION_EXPIRED         = 7,
    SESSION_NOT_FOUND       = 8,
    COMPRESSION_ERROR       = 9,
    CORS_BLOCKED            = 10,
    BAD_REQUEST             = 11,
    INTERNAL_ERROR          = 12,
    SERVICE_UNAVAILABLE     = 13,
    POLICY_VIOLATION        = 14,
    AUTH_REQUIRED           = 15,
    UNSUPPORTED_TRANSPORT   = 16,
    UNSUPPORTED_VERSION     = 17,
    SYSTEM_OVERLOAD         = 18,
    TLS_REQUIRED            = 19,
    PROTOCOL_ERROR          = 20,
};

const char* transport_error_str(TransportError e) {
    switch (e) {
        case TransportError::NONE:                  return "none";
        case TransportError::CONNECTION_FAILED:      return "connection-failed";
        case TransportError::HANDSHAKE_FAILED:       return "handshake-failed";
        case TransportError::TIMEOUT:                return "timeout";
        case TransportError::RATE_LIMITED:           return "rate-limited";
        case TransportError::INVALID_FRAME:          return "invalid-frame";
        case TransportError::FRAME_TOO_LARGE:        return "frame-too-large";
        case TransportError::SESSION_EXPIRED:        return "session-expired";
        case TransportError::SESSION_NOT_FOUND:      return "session-not-found";
        case TransportError::COMPRESSION_ERROR:      return "compression-error";
        case TransportError::CORS_BLOCKED:           return "cors-blocked";
        case TransportError::BAD_REQUEST:            return "bad-request";
        case TransportError::INTERNAL_ERROR:         return "internal-server-error";
        case TransportError::SERVICE_UNAVAILABLE:    return "service-unavailable";
        case TransportError::POLICY_VIOLATION:        return "policy-violation";
        case TransportError::AUTH_REQUIRED:          return "auth-required";
        case TransportError::UNSUPPORTED_TRANSPORT:  return "unsupported-transport";
        case TransportError::UNSUPPORTED_VERSION:    return "unsupported-version";
        case TransportError::SYSTEM_OVERLOAD:        return "system-overload";
        case TransportError::TLS_REQUIRED:           return "tls-required";
        case TransportError::PROTOCOL_ERROR:         return "protocol-error";
        default: return "unknown";
    }
}

// =============================================================================
// Transport error with context
// =============================================================================

struct TransportErrorInfo {
    TransportError error = TransportError::NONE;
    std::string message;
    std::string detail;
    int http_status = 500;
    int retry_after = 0;
    bool retryable = false;
    int64_t timestamp = 0;

    TransportErrorInfo() : timestamp(nms()) {}

    TransportErrorInfo(TransportError e, const std::string& msg,
                       int http = 500, bool retry = false)
        : error(e), message(msg), http_status(http), retryable(retry),
          timestamp(nms()) {}

    json to_json() const {
        return json{
            {"error", transport_error_str(error)},
            {"message", message},
            {"detail", detail},
            {"retryable", retryable},
            {"retry_after", retry_after},
            {"timestamp", timestamp},
        };
    }
};

// =============================================================================
// Circuit breaker for transport failure detection
// =============================================================================

class CircuitBreaker {
public:
    CircuitBreaker(int failure_threshold = 5, int64_t reset_timeout_ms = 30000)
        : failure_threshold_(failure_threshold),
          reset_timeout_ms_(reset_timeout_ms) {}

    enum State { CLOSED, OPEN, HALF_OPEN };

    State state() const { return state_.load(); }

    bool allow_request() {
        State s = state_.load();
        if (s == CLOSED) return true;
        if (s == HALF_OPEN) return true;
        // OPEN: check if timeout has elapsed
        int64_t now = nms();
        if (now - last_failure_time_.load() > reset_timeout_ms_) {
            state_.store(HALF_OPEN);
            return true;
        }
        return false;
    }

    void record_success() {
        failure_count_.store(0);
        if (state_.load() == HALF_OPEN) {
            state_.store(CLOSED);
        }
    }

    void record_failure() {
        int count = failure_count_.fetch_add(1) + 1;
        last_failure_time_.store(nms());
        if (count >= failure_threshold_) {
            state_.store(OPEN);
        }
    }

    void reset() {
        failure_count_.store(0);
        state_.store(CLOSED);
    }

    State state_opens() const { return state_.load(); }
    int failure_count() const { return failure_count_.load(); }

private:
    int failure_threshold_;
    int64_t reset_timeout_ms_;
    std::atomic<int> failure_count_{0};
    std::atomic<State> state_{CLOSED};
    std::atomic<int64_t> last_failure_time_{0};
};

// =============================================================================
// =============================================================================
// TRANSPORT MANAGER - Main class orchestrating all transports
// =============================================================================
// =============================================================================

class TransportManager {
public:
    TransportManager() = default;

    void configure(const TransportConfig& cfg) {
        std::lock_guard lock(config_mutex_);
        config_ = cfg;
    }

    TransportConfig& config() { return config_; }

    // =========================================================================
    // BOSH: CONNECTION MANAGER (XEP-0124, XEP-0206)
    // =========================================================================

    // -- BOSH Session Management --

    std::shared_ptr<BoshSession> create_bosh_session(
        const std::string& from, const std::string& to,
        const std::string& route, int hold, int wait) {

        auto session = std::make_shared<BoshSession>();
        session->from = from;
        session->to = to;
        session->route = route;
        session->hold = std::min(hold, config_.bosh_max_hold);
        session->wait = std::clamp(wait, config_.bosh_min_wait, config_.bosh_max_wait);
        session->inactivity = config_.bosh_max_inactivity;
        session->max_pause = config_.bosh_max_pause;
        session->use_acks = config_.bosh_use_acks;
        session->compressed = config_.bosh_compression;
        session->touch();

        {
            std::lock_guard lock(bosh_mutex_);
            bosh_sessions_[session->sid] = session;
        }

        metrics_bosh_.active_sessions.fetch_add(1);
        return session;
    }

    std::shared_ptr<BoshSession> get_bosh_session(const std::string& sid) {
        std::lock_guard lock(bosh_mutex_);
        auto it = bosh_sessions_.find(sid);
        if (it != bosh_sessions_.end()) {
            return it->second;
        }
        return nullptr;
    }

    bool resume_bosh_session(const std::string& sid) {
        auto session = get_bosh_session(sid);
        if (!session) return false;
        if (session->terminated) return false;
        session->paused = false;
        session->touch();
        metrics_bosh_.resumed_sessions.fetch_add(1);
        return true;
    }

    void terminate_bosh_session(const std::string& sid) {
        auto session = get_bosh_session(sid);
        if (session) {
            session->terminated = true;
            session->restartable = false;
            metrics_bosh_.active_sessions.fetch_sub(1);
        }
    }

    void expire_bosh_session(const std::string& sid) {
        std::lock_guard lock(bosh_mutex_);
        bosh_sessions_.erase(sid);
        metrics_bosh_.expired_sessions.fetch_add(1);
    }

    void cleanup_expired_bosh_sessions() {
        std::lock_guard lock(bosh_mutex_);
        int64_t now = nms();
        auto it = bosh_sessions_.begin();
        while (it != bosh_sessions_.end()) {
            if (it->second->is_expired() || it->second->terminated) {
                metrics_bosh_.expired_sessions.fetch_add(1);
                it = bosh_sessions_.erase(it);
            } else {
                ++it;
            }
        }
    }

    // -- BOSH Request Parsing (HTTP Body -> BOSH Parameters) --

    struct BoshRequest {
        uint32_t rid = 0;
        std::string sid;
        std::string to;
        std::string route;
        std::string from;
        std::string version;
        std::string xmpp_version = "1.0";
        std::string xml_lang;
        int wait = 30;
        int hold = 1;
        int requests = 2;
        uint32_t ack = 0;
        bool restart = false;
        bool pause = false;
        bool new_session = false;
        std::string type;         // "terminate"
        std::string condition;    // error condition for terminate
        std::string body_xml;     // Raw XML stanzas in the body element
    };

    std::optional<BoshRequest> parse_bosh_request(
        const std::string& body_xml) {

        BoshRequest req;
        bool has_body = false;

        // Simple XML attribute extraction for bosh parameters
        // Looking for <body rid='...' ...> ... </body>
        auto extract_attr = [](const std::string& xml, const std::string& tag,
                                const std::string& attr) -> std::string {
            std::string search = attr + "='";
            size_t pos = xml.find(search);
            if (pos == std::string::npos) {
                search = attr + "=\"";
                pos = xml.find(search);
            }
            if (pos == std::string::npos) return "";
            pos += search.size();
            char quote = xml[pos - 1]; // ' or "
            size_t end = xml.find(quote, pos);
            if (end == std::string::npos) return "";
            return xml.substr(pos, end - pos);
        };

        // Extract <body ...> attributes
        std::string rid_str = extract_attr(body_xml, "body", "rid");
        if (rid_str.empty()) {
            // Try without body tag prefix
            rid_str = extract_attr(body_xml, "", "rid");
        }
        if (!rid_str.empty()) {
            req.rid = static_cast<uint32_t>(std::stoull(rid_str));
        }

        req.sid    = extract_attr(body_xml, "body", "sid");
        req.to     = extract_attr(body_xml, "body", "to");
        req.route  = extract_attr(body_xml, "body", "route");
        req.from   = extract_attr(body_xml, "body", "from");
        req.version = extract_attr(body_xml, "body", "ver");
        req.xml_lang = extract_attr(body_xml, "body", "xml:lang");
        req.type   = extract_attr(body_xml, "body", "type");

        std::string wait_str = extract_attr(body_xml, "body", "wait");
        if (!wait_str.empty()) req.wait = std::stoi(wait_str);

        std::string hold_str = extract_attr(body_xml, "body", "hold");
        if (!hold_str.empty()) req.hold = std::stoi(hold_str);

        std::string req_str = extract_attr(body_xml, "body", "requests");
        if (!req_str.empty()) req.requests = std::stoi(req_str);

        std::string ack_str = extract_attr(body_xml, "body", "ack");
        if (!ack_str.empty()) req.ack = static_cast<uint32_t>(std::stoull(ack_str));

        // XMPP restart logic
        std::string restart_str = extract_attr(body_xml, "body", "xmpp:restart");
        if (!restart_str.empty() && restart_str == "true") req.restart = true;

        std::string pause_str = extract_attr(body_xml, "body", "pause");
        if (!pause_str.empty()) req.pause = true;

        // Content attribute
        std::string content = extract_attr(body_xml, "body", "content");
        if (content.empty()) content = "text/xml; charset=utf-8";

        // Check if requesting new session
        if (req.sid.empty()) {
            req.new_session = true;
        }

        // Extract inner body content (stanzas)
        size_t open_end = body_xml.find(">");
        if (open_end != std::string::npos) {
            // Skip the body open tag
            size_t content_start = open_end + 1;

            // Find closing body tag
            size_t close_tag = body_xml.rfind("</body>");
            if (close_tag == std::string::npos) {
                close_tag = body_xml.rfind("</body");
            }
            if (close_tag != std::string::npos && close_tag > content_start) {
                req.body_xml = body_xml.substr(content_start, close_tag - content_start);
                // Trim whitespace
                while (!req.body_xml.empty() && isspace(req.body_xml.front()))
                    req.body_xml.erase(0, 1);
                while (!req.body_xml.empty() && isspace(req.body_xml.back()))
                    req.body_xml.pop_back();
                if (!req.body_xml.empty()) has_body = true;
            }
        }

        if (req.rid == 0 && !req.new_session) return std::nullopt;
        return req;
    }

    // -- BOSH Response Creation --

    std::string create_bosh_response(
        std::shared_ptr<BoshSession> session,
        const std::vector<std::string>& stanzas,
        uint32_t ack = 0) {

        std::ostringstream oss;

        // Build <body> wrapper
        oss << "<body"
            << " xmlns='" << transport_ns::BOSH << "'"
            << " xmlns:xmpp='" << transport_ns::BOSH_XMPP << "'"
            << " authid='" << xml_escape(session->sid) << "'"
            << " sid='" << xml_escape(session->sid) << "'"
            << " secure='" << (session->secure ? "true" : "false") << "'"
            << " requests='" << session->requests << "'"
            << " inactivity='" << session->inactivity << "'"
            << " polling='" << config_.bosh_polling_interval << "'"
            << " wait='" << session->wait << "'"
            << " hold='" << session->hold << "'"
            << " from='" << xml_escape(session->to) << "'"
            << " ver='" << session->version_major << "." << session->version_minor
            << "'"
            << " maxpause='" << session->max_pause << "'";

        if (session->use_acks && ack > 0) {
            oss << " ack='" << ack << "'";
        }

        if (session->compressed) {
            oss << " compression='deflate'";
        }

        if (!session->xml_lang.empty()) {
            oss << " xml:lang='" << xml_escape(session->xml_lang) << "'";
        }

        if (session->xmpp_restart) {
            oss << " xmpp:restart='true'";
        }

        std::string attrs = oss.str();
        oss.str("");
        oss << attrs;

        if (stanzas.empty() || (stanzas.size() == 1 && stanzas[0].empty())) {
            oss << "/>";
        } else {
            oss << ">";
            for (const auto& stanza : stanzas) {
                oss << stanza;
            }
            oss << "</body>";
        }

        return oss.str();
    }

    std::string create_bosh_error_response(
        const std::string& condition, const std::string& message = "") {

        std::ostringstream oss;
        oss << "<body"
            << " xmlns='" << transport_ns::BOSH << "'"
            << " type='terminate'"
            << " condition='" << xml_escape(condition) << "'";
        if (!message.empty()) {
            oss << ">" << xml_escape(message) << "</body>";
        } else {
            oss << "/>";
        }
        return oss.str();
    }

    // -- BOSH Stanza wrapping/unwrapping --

    std::string wrap_stanza_for_bosh(const std::string& stanza_xml) {
        // BOSH body can contain multiple stanzas directly
        // Individual stanzas don't need wrapping beyond what the caller does
        // with create_bosh_response
        return stanza_xml;
    }

    std::vector<std::string> unwrap_bosh_stanzas(const std::string& body_xml) {
        std::vector<std::string> stanzas;
        std::string xml = body_xml;

        // Trim whitespace
        while (!xml.empty() && isspace(xml.front())) xml.erase(0, 1);
        while (!xml.empty() && isspace(xml.back())) xml.pop_back();

        if (xml.empty()) return stanzas;

        // Split on top-level element boundaries
        // Parse one complete element at a time
        size_t pos = 0;
        while (pos < xml.size()) {
            // Skip whitespace
            while (pos < xml.size() && isspace(xml[pos])) pos++;
            if (pos >= xml.size()) break;

            // Find opening <
            if (xml[pos] != '<') break;

            // Skip processing instructions and comments
            if (xml.compare(pos, 2, "<?") == 0) {
                size_t end = xml.find("?>", pos);
                if (end == std::string::npos) break;
                pos = end + 2;
                continue;
            }
            if (xml.compare(pos, 4, "<!--") == 0) {
                size_t end = xml.find("-->", pos);
                if (end == std::string::npos) break;
                pos = end + 3;
                continue;
            }

            // Find element name
            size_t name_start = pos + 1;
            size_t name_end = xml.find_first_of(" />\t\r\n", name_start);
            if (name_end == std::string::npos) break;
            std::string elem_name = xml.substr(name_start, name_end - name_start);
            if (elem_name.empty()) { pos++; continue; }

            // Check if self-closing: find />
            size_t close = xml.find("/>", pos);
            size_t full_close = xml.find("</" + elem_name + ">", pos);
            size_t full_close2 = xml.find("</" + elem_name + " ", pos);

            if (close != std::string::npos &&
                (full_close == std::string::npos || close < full_close)) {
                // Self-closing element
                size_t end = close + 2;
                stanzas.push_back(xml.substr(pos, end - pos));
                pos = end;
            } else if (full_close != std::string::npos) {
                size_t end = full_close + elem_name.size() + 3;
                stanzas.push_back(xml.substr(pos, end - pos));
                pos = end;
            } else if (full_close2 != std::string::npos) {
                // Handle <elem attr="val"></elem >
                size_t end = full_close2 + elem_name.size() + 3;
                stanzas.push_back(xml.substr(pos, end - pos));
                pos = end;
            } else {
                // Unclosed or malformed, try to recover
                break;
            }
        }

        return stanzas;
    }

    // -- BOSH Request Handling (full HTTP request processing) --

    struct BoshHttpResponse {
        int status_code = 200;
        std::string content_type = "text/xml; charset=utf-8";
        std::string body;
        std::map<std::string, std::string> headers;
    };

    BoshHttpResponse handle_bosh_http_request(
        const std::string& http_method,
        const std::string& http_body,
        const std::map<std::string, std::string>& http_headers,
        const std::string& client_ip = "") {

        BoshHttpResponse resp;
        int64_t start_time = nus();

        // Only POST is valid for BOSH
        if (http_method != "POST") {
            resp.status_code = 405;
            resp.headers["Allow"] = "POST";
            resp.body = "Method Not Allowed";
            return resp;
        }

        // Rate limit check
        if (config_.rate_limit_enabled && !bosh_rate_limiter_.consume(1)) {
            metrics_bosh_.rate_limit_hits.fetch_add(1);
            resp.status_code = 429;
            resp.headers["Retry-After"] = "5";
            resp.body = create_bosh_error_response("policy-violation",
                "Rate limit exceeded");
            return resp;
        }

        // Validate content type
        auto ct_it = http_headers.find("content-type");
        if (ct_it != http_headers.end()) {
            std::string ct = ct_it->second;
            std::transform(ct.begin(), ct.end(), ct.begin(), ::tolower);
            if (ct.find("text/xml") == std::string::npos &&
                ct.find("application/xml") == std::string::npos) {
                resp.status_code = 415;
                resp.body = create_bosh_error_response("bad-request",
                    "Unsupported Content-Type");
                return resp;
            }
        }

        // Parse BOSH body
        auto bosh_req = parse_bosh_request(http_body);
        if (!bosh_req) {
            metrics_bosh_.frame_decode_errors.fetch_add(1);
            resp.status_code = 400;
            resp.body = create_bosh_error_response("bad-request",
                "Malformed BOSH body");
            return resp;
        }

        // Version check
        if (!bosh_req->version.empty()) {
            // Parse "1.6" etc.
            auto dot_pos = bosh_req->version.find('.');
            int major = 1, minor = 6;
            if (dot_pos != std::string::npos) {
                major = std::stoi(bosh_req->version.substr(0, dot_pos));
                minor = std::stoi(bosh_req->version.substr(dot_pos + 1));
            }
            if (major > 1 || (major == 1 && minor > 6)) {
                resp.status_code = 400;
                resp.body = create_bosh_error_response("unsupported-version",
                    "BOSH version " + bosh_req->version + " not supported");
                return resp;
            }
        }

        // Handle session termination
        if (bosh_req->type == "terminate") {
            if (!bosh_req->sid.empty()) {
                terminate_bosh_session(bosh_req->sid);
            }
            resp.body = create_bosh_error_response(bosh_req->condition.empty()
                ? "item-not-found" : bosh_req->condition, "");
            return resp;
        }

        // New session creation
        std::shared_ptr<BoshSession> session;
        if (bosh_req->new_session) {
            // Create new BOSH session
            session = create_bosh_session(
                bosh_req->from.empty() ? "" : bosh_req->from,
                bosh_req->to.empty() ? config_.bosh_path : bosh_req->to,
                bosh_req->route,
                bosh_req->hold,
                bosh_req->wait);

            if (!bosh_req->from.empty()) {
                session->from = bosh_req->from;
            }
            if (!bosh_req->xml_lang.empty()) {
                session->xml_lang = bosh_req->xml_lang;
            }
            session->client_ip = client_ip;

            // Generate session creation response with stanzas from body
            std::vector<std::string> response_stanzas;

            // If body contains stanzas (like initial stream header), echo back
            if (!bosh_req->body_xml.empty()) {
                auto body_stanzas = unwrap_bosh_stanzas(bosh_req->body_xml);
                response_stanzas.insert(response_stanzas.end(),
                    body_stanzas.begin(), body_stanzas.end());
            }

            resp.body = create_bosh_response(session, response_stanzas);
            resp.headers["X-BOSH-SID"] = session->sid;
            resp.headers["Cache-Control"] = "no-cache, no-store, must-revalidate";
            resp.headers["Pragma"] = "no-cache";
            session->rid = bosh_req->rid;
            session->total_requests++;

        } else if (!bosh_req->sid.empty()) {
            // Existing session
            session = get_bosh_session(bosh_req->sid);
            if (!session || session->terminated) {
                resp.status_code = 404;
                resp.body = create_bosh_error_response("item-not-found",
                    "Session not found");
                return resp;
            }

            if (session->is_expired()) {
                expire_bosh_session(bosh_req->sid);
                resp.status_code = 404;
                resp.body = create_bosh_error_response("session-timeout",
                    "Session expired due to inactivity");
                return resp;
            }

            // Handle RID validation
            if (bosh_req->rid <= session->rid) {
                resp.status_code = 400;
                resp.body = create_bosh_error_response("bad-request",
                    "RID must be greater than previous RID");
                return resp;
            }

            // Handle pause
            if (bosh_req->pause) {
                session->paused = true;
                resp.body = create_bosh_response(session, {});
                session->rid = bosh_req->rid;
                session->total_requests++;
                return resp;
            }

            // Handle ACK
            if (bosh_req->ack > 0) {
                session->last_ack = bosh_req->ack;
            }

            // Handle XMPP restart
            if (bosh_req->restart) {
                session->xmpp_restart = true;
            }

            session->touch();
            session->rid = bosh_req->rid;
            session->total_requests++;

            // Process incoming stanzas
            std::vector<std::string> response_stanzas;

            if (!bosh_req->body_xml.empty()) {
                auto body_stanzas = unwrap_bosh_stanzas(bosh_req->body_xml);
                for (auto& stanza : body_stanzas) {
                    session->total_stanzas_in++;
                    metrics_bosh_.stanzas_received.fetch_add(1);
                    // In a full implementation, these would be
                    // dispatched to the XMPP stream processor
                }
            }

            // Drain outbound queue
            {
                std::lock_guard lock(session->queue_mutex);
                int max_stanzas = std::min(50, static_cast<int>(session->outbound_queue.size()));
                for (int i = 0; i < max_stanzas; i++) {
                    response_stanzas.push_back(session->outbound_queue.front());
                    session->outbound_queue.pop_front();
                    session->total_stanzas_out++;
                    metrics_bosh_.stanzas_sent.fetch_add(1);
                }
            }

            resp.body = create_bosh_response(session, response_stanzas,
                session->last_ack);
            resp.headers["X-BOSH-SID"] = session->sid;
            resp.headers["Cache-Control"] = "no-cache, no-store, must-revalidate";
            resp.headers["Pragma"] = "no-cache";
        }

        // Add CORS headers
        add_cors_headers(resp.headers, http_headers);

        // Record metrics
        int64_t elapsed = nus() - start_time;
        metrics_bosh_.avg_latency_us.store(elapsed);

        return resp;
    }

    // -- Queue stanza to BOSH session --

    bool bosh_enqueue_stanza(const std::string& sid, const std::string& stanza_xml) {
        auto session = get_bosh_session(sid);
        if (!session) return false;
        std::lock_guard lock(session->queue_mutex);
        if (session->outbound_queue.size() > 1000) return false; // queue full
        session->outbound_queue.push_back(stanza_xml);
        return true;
    }

    // =========================================================================
    // WEBSOCKET TRANSPORT (RFC 7395)
    // =========================================================================

    // -- WebSocket Handshake (RFC 6455 §4) --

    struct WebSocketHandshakeResult {
        bool success = false;
        int http_status = 101;
        std::string response;
        std::string error;
        std::string accept_key;
        std::string protocol;
        bool deflate = false;
        bool xmpp_subprotocol = false;
        std::map<std::string, std::string> headers;
    };

    WebSocketHandshakeResult handle_websocket_upgrade(
        const std::string& http_request,
        const std::map<std::string, std::string>& http_headers,
        const std::string& client_ip = "") {

        WebSocketHandshakeResult result;

        // Validate HTTP method
        auto method_it = http_headers.find(":method");
        std::string method = "GET";
        if (method_it != http_headers.end()) method = method_it->second;
        if (method != "GET") {
            result.success = false;
            result.http_status = 405;
            result.error = "Method not allowed";
            return result;
        }

        // Validate HTTP version
        auto version_it = http_headers.find(":version");
        if (version_it != http_headers.end()) {
            // HTTP/1.1 required for WebSocket upgrade
        }

        // Validate Host header
        auto host_it = http_headers.find("host");
        if (host_it == http_headers.end()) {
            result.success = false;
            result.http_status = 400;
            result.error = "Missing Host header";
            return result;
        }

        // Validate Upgrade header
        auto upgrade_it = http_headers.find("upgrade");
        if (upgrade_it == http_headers.end()) {
            result.success = false;
            result.http_status = 426;
            result.error = "Upgrade required";
            return result;
        }
        std::string upgrade = upgrade_it->second;
        std::transform(upgrade.begin(), upgrade.end(), upgrade.begin(), ::tolower);
        if (upgrade != "websocket") {
            result.success = false;
            result.http_status = 400;
            result.error = "Invalid Upgrade header";
            return result;
        }

        // Validate Connection header
        auto conn_it = http_headers.find("connection");
        if (conn_it == http_headers.end()) {
            result.success = false;
            result.http_status = 400;
            result.error = "Missing Connection header";
            return result;
        }
        std::string connection = conn_it->second;
        std::transform(connection.begin(), connection.end(),
                       connection.begin(), ::tolower);
        if (connection.find("upgrade") == std::string::npos) {
            result.success = false;
            result.http_status = 400;
            result.error = "Connection header must include Upgrade";
            return result;
        }

        // Validate Sec-WebSocket-Key
        auto key_it = http_headers.find("sec-websocket-key");
        if (key_it == http_headers.end()) {
            result.success = false;
            result.http_status = 400;
            result.error = "Missing Sec-WebSocket-Key";
            return result;
        }
        std::string key = key_it->second;
        // Trim whitespace
        key.erase(0, key.find_first_not_of(" \t\r\n"));
        key.erase(key.find_last_not_of(" \t\r\n") + 1);

        // Validate Sec-WebSocket-Version
        auto ver_it = http_headers.find("sec-websocket-version");
        if (ver_it == http_headers.end()) {
            result.success = false;
            result.http_status = 426;
            result.headers["Sec-WebSocket-Version"] = "13";
            result.error = "Missing Sec-WebSocket-Version";
            return result;
        }
        if (ver_it->second != "13") {
            result.success = false;
            result.http_status = 426;
            result.headers["Sec-WebSocket-Version"] = "13";
            result.error = "Unsupported WebSocket version";
            return result;
        }

        // Validate XMPP subprotocol
        auto proto_it = http_headers.find("sec-websocket-protocol");
        bool has_xmpp_protocol = false;
        if (proto_it != http_headers.end()) {
            std::string protocols = proto_it->second;
            // Check if "xmpp" is in the comma-separated list
            std::istringstream iss(protocols);
            std::string token;
            while (std::getline(iss, token, ',')) {
                // Trim
                token.erase(0, token.find_first_not_of(" \t"));
                token.erase(token.find_last_not_of(" \t") + 1);
                if (token == "xmpp") {
                    has_xmpp_protocol = true;
                    break;
                }
            }
        }

        // Compute accept key: base64(sha1(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
        std::string magic = key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
        std::string sha1_digest = sha1(magic);
        result.accept_key = base64_encode(sha1_digest);

        // Build upgrade response
        std::ostringstream oss;
        oss << "HTTP/1.1 101 Switching Protocols\r\n";
        oss << "Upgrade: websocket\r\n";
        oss << "Connection: Upgrade\r\n";
        oss << "Sec-WebSocket-Accept: " << result.accept_key << "\r\n";

        if (has_xmpp_protocol) {
            oss << "Sec-WebSocket-Protocol: xmpp\r\n";
            result.protocol = "xmpp";
        }

        // Optional extensions
        auto ext_it = http_headers.find("sec-websocket-extensions");
        if (ext_it != http_headers.end()) {
            std::string ext = ext_it->second;
            if (ext.find("permessage-deflate") != std::string::npos &&
                config_.websocket_permessage_deflate) {
                oss << "Sec-WebSocket-Extensions: permessage-deflate\r\n";
                result.deflate = true;
            }
        }

        oss << "\r\n";

        result.success = true;
        result.http_status = 101;
        result.response = oss.str();
        result.xmpp_subprotocol = has_xmpp_protocol;

        return result;
    }

    // -- WebSocket Connection Management --

    std::shared_ptr<WebSocketConnection> create_websocket_connection(
        int fd, const std::string& remote_addr,
        const std::string& protocol = "xmpp",
        bool secure = false) {

        auto conn = std::make_shared<WebSocketConnection>();
        conn->fd = fd;
        conn->remote_addr = remote_addr;
        conn->protocol = protocol;
        conn->secure = secure;
        conn->xmpp_subprotocol = (protocol == "xmpp");
        conn->state = WebSocketState::OPEN;
        conn->ping_interval = config_.websocket_ping_interval;

        // Set up rate limiter
        conn->rate_limiter = TokenBucket(
            config_.rate_limit_per_sec,
            config_.rate_limit_burst);

        {
            std::lock_guard lock(ws_mutex_);
            ws_connections_[fd] = conn;
            ws_connections_by_id_[conn->id] = conn;
        }

        metrics_ws_.active_connections.fetch_add(1);
        metrics_ws_.total_connections_created.fetch_add(1);

        return conn;
    }

    std::shared_ptr<WebSocketConnection> get_websocket_connection(int fd) {
        std::lock_guard lock(ws_mutex_);
        auto it = ws_connections_.find(fd);
        if (it != ws_connections_.end()) {
            return it->second;
        }
        return nullptr;
    }

    std::shared_ptr<WebSocketConnection> get_websocket_connection_by_id(
        const std::string& id) {
        std::lock_guard lock(ws_mutex_);
        auto it = ws_connections_by_id_.find(id);
        if (it != ws_connections_by_id_.end()) {
            return it->second;
        }
        return nullptr;
    }

    void close_websocket_connection(int fd,
        WebSocketCloseCode code = WebSocketCloseCode::NORMAL,
        const std::string& reason = "") {

        auto conn = get_websocket_connection(fd);
        if (!conn) return;

        // Send close frame
        if (conn->state == WebSocketState::OPEN) {
            conn->state = WebSocketState::CLOSING;

            // Build close frame payload (2-byte code + optional reason)
            std::string payload;
            uint16_t code_val = static_cast<uint16_t>(code);
            payload.push_back(static_cast<char>((code_val >> 8) & 0xFF));
            payload.push_back(static_cast<char>(code_val & 0xFF));
            payload += reason;

            WebSocketFrame close_frame(WebSocketOpcode::CLOSE, payload, true);
            std::string frame_data = close_frame.encode(false);

            // Queue for sending
            std::lock_guard lock(conn->send_mutex);
            conn->send_queue_high.push_back(frame_data);
        }

        conn->state = WebSocketState::CLOSED;

        // Remove from maps
        {
            std::lock_guard lock(ws_mutex_);
            ws_connections_.erase(fd);
            ws_connections_by_id_.erase(conn->id);
        }

        metrics_ws_.active_connections.fetch_sub(1);
        metrics_ws_.total_connections_closed.fetch_add(1);

        // Close the socket
        if (fd >= 0) {
            ::close(fd);
        }
    }

    // -- WebSocket Frame decoding for raw TCP data --

    struct WebSocketDecodeResult {
        bool complete = false;
        std::vector<std::string> messages;     // Complete frames/messages
        size_t bytes_consumed = 0;
        bool error = false;
        std::string error_msg;
        bool close_received = false;
        WebSocketCloseCode close_code = WebSocketCloseCode::NORMAL;
        std::string close_reason;
        bool ping_received = false;
        std::string ping_data;
        bool pong_received = false;
    };

    WebSocketDecodeResult decode_websocket_data(
        std::shared_ptr<WebSocketConnection> conn,
        const uint8_t* data, size_t len) {

        WebSocketDecodeResult result;
        size_t offset = 0;

        while (offset < len) {
            conn->touch();

            size_t consumed = 0;
            auto frame_opt = WebSocketFrame::parse(data + offset, len - offset, consumed);
            if (!frame_opt) {
                // Incomplete frame, need more data
                result.bytes_consumed = offset;
                return result;
            }

            WebSocketFrame& frame = *frame_opt;
            offset += consumed;
            result.bytes_consumed = offset;

            conn->frames_received++;
            conn->bytes_received += frame.payload.size();
            metrics_ws_.frames_received.fetch_add(1);
            metrics_ws_.bytes_received.fetch_add(frame.payload.size());

            // Validate frame
            if (frame.rsv1 && !conn->compressed) {
                result.error = true;
                result.error_msg = "RSV1 set without compression negotiation";
                return result;
            }

            switch (frame.opcode) {
                case WebSocketOpcode::TEXT:
                case WebSocketOpcode::BINARY: {
                    // Handle message fragmentation
                    if (frame.fin) {
                        if (!conn->fragment_buffer.empty()) {
                            conn->fragment_buffer += frame.payload;
                            result.messages.push_back(conn->fragment_buffer);
                            conn->fragment_buffer.clear();
                            conn->stanza_count++;
                        } else {
                            result.messages.push_back(frame.payload);
                            conn->stanza_count++;
                        }
                    } else {
                        conn->fragment_buffer += frame.payload;
                        conn->fragment_opcode = frame.opcode;
                    }
                    metrics_ws_.stanzas_received.fetch_add(1);
                    break;
                }

                case WebSocketOpcode::CONTINUATION: {
                    conn->fragment_buffer += frame.payload;
                    if (frame.fin) {
                        result.messages.push_back(conn->fragment_buffer);
                        conn->fragment_buffer.clear();
                        conn->stanza_count++;
                        metrics_ws_.stanzas_received.fetch_add(1);
                    }
                    break;
                }

                case WebSocketOpcode::CLOSE: {
                    result.close_received = true;
                    if (frame.payload.size() >= 2) {
                        uint16_t code = (static_cast<uint8_t>(frame.payload[0]) << 8) |
                                        static_cast<uint8_t>(frame.payload[1]);
                        result.close_code = static_cast<WebSocketCloseCode>(code);
                        if (frame.payload.size() > 2) {
                            result.close_reason = frame.payload.substr(2);
                        }
                    } else {
                        result.close_code = WebSocketCloseCode::NO_STATUS;
                    }
                    return result;
                }

                case WebSocketOpcode::PING: {
                    result.ping_received = true;
                    result.ping_data = frame.payload;
                    conn->last_ping = nms();
                    // Auto-respond with pong
                    WebSocketFrame pong_frame(WebSocketOpcode::PONG,
                        frame.payload, true);
                    std::string pong_data = pong_frame.encode(false);
                    {
                        std::lock_guard lock(conn->send_mutex);
                        conn->send_queue_high.push_back(pong_data);
                    }
                    break;
                }

                case WebSocketOpcode::PONG: {
                    result.pong_received = true;
                    conn->last_pong = nms();
                    conn->pongs_received++;
                    break;
                }

                default: {
                    result.error = true;
                    result.error_msg = "Unknown opcode: " +
                        std::to_string(static_cast<int>(frame.opcode));
                    return result;
                }
            }

            // Check size limits
            if (conn->fragment_buffer.size() >
                static_cast<size_t>(config_.websocket_max_message_size)) {
                result.error = true;
                result.error_msg = "Message too large";
                return result;
            }
        }

        result.complete = true;
        return result;
    }

    // -- WebSocket frame encoding for sending --

    std::string encode_websocket_message(
        std::shared_ptr<WebSocketConnection> conn,
        const std::string& message,
        bool is_text = true) {

        WebSocketOpcode opcode = is_text ?
            WebSocketOpcode::TEXT : WebSocketOpcode::BINARY;
        WebSocketFrame frame(opcode, message, true);
        return frame.encode(false); // Server never masks
    }

    bool websocket_enqueue_stanza(
        std::shared_ptr<WebSocketConnection> conn,
        const std::string& stanza_xml) {

        if (!conn || conn->state != WebSocketState::OPEN) return false;

        // Rate limit check
        if (config_.rate_limit_enabled && !conn->rate_limiter.consume(1)) {
            metrics_ws_.rate_limit_hits.fetch_add(1);
            return false;
        }

        std::string frame_data = encode_websocket_message(conn, stanza_xml);
        {
            std::lock_guard lock(conn->send_mutex);
            if (conn->send_queue.size() * 1024 >
                static_cast<size_t>(conn->max_send_queue)) {
                return false; // Queue full
            }
            conn->send_queue.push_back(frame_data);
        }

        conn->stanza_count++;
        metrics_ws_.stanzas_sent.fetch_add(1);
        return true;
    }

    std::string websocket_drain_send_queue(
        std::shared_ptr<WebSocketConnection> conn) {

        if (!conn) return "";

        std::lock_guard lock(conn->send_mutex);
        std::ostringstream oss;

        // Send high-priority frames first (close, pong)
        while (!conn->send_queue_high.empty()) {
            oss << conn->send_queue_high.front();
            conn->send_queue_high.pop_front();
            conn->frames_sent++;
            metrics_ws_.frames_sent.fetch_add(1);
        }

        // Send regular frames
        int max_batch = 50;
        int i = 0;
        while (!conn->send_queue.empty() && i < max_batch) {
            oss << conn->send_queue.front();
            conn->send_queue.pop_front();
            conn->frames_sent++;
            metrics_ws_.frames_sent.fetch_add(1);
            i++;
        }

        std::string result = oss.str();
        if (!result.empty()) {
            conn->bytes_sent += result.size();
            metrics_ws_.bytes_sent.fetch_add(result.size());
            conn->touch();
        }
        return result;
    }

    bool websocket_has_pending_sends(std::shared_ptr<WebSocketConnection> conn) {
        if (!conn) return false;
        std::lock_guard lock(conn->send_mutex);
        return !conn->send_queue.empty() || !conn->send_queue_high.empty();
    }

    // -- WebSocket Keep-Alive / Ping --

    std::string websocket_create_ping(std::shared_ptr<WebSocketConnection> conn) {
        if (!conn) return "";
        conn->last_ping = nms();
        conn->pings_sent++;

        std::string ping_payload = "ping-" + std::to_string(nms());
        WebSocketFrame ping_frame(WebSocketOpcode::PING, ping_payload, true);
        return ping_frame.encode(false);
    }

    // -- WebSocket XMPP subprotocol stream handling --

    std::string websocket_open_stream(
        std::shared_ptr<WebSocketConnection> conn,
        const std::string& to, const std::string& from) {

        std::ostringstream oss;
        oss << "<open"
            << " xmlns='" << transport_ns::WEBSOCKET << "'"
            << " to='" << xml_escape(to) << "'"
            << " from='" << xml_escape(from) << "'"
            << " version='1.0'"
            << " xml:lang='en'"
            << "/>";
        return oss.str();
    }

    std::string websocket_close_stream(
        std::shared_ptr<WebSocketConnection> conn) {

        std::ostringstream oss;
        oss << "<close"
            << " xmlns='" << transport_ns::WEBSOCKET << "'"
            << "/>";
        return oss.str();
    }

    // =========================================================================
    // HTTP POLL TRANSPORT (legacy)
    // =========================================================================

    std::shared_ptr<HttpPollSession> create_http_poll_session(
        const std::string& jid = "") {

        auto session = std::make_shared<HttpPollSession>();
        session->jid = jid;

        {
            std::lock_guard lock(poll_mutex_);
            poll_sessions_[session->sid] = session;
        }

        return session;
    }

    std::shared_ptr<HttpPollSession> get_http_poll_session(
        const std::string& sid) {

        std::lock_guard lock(poll_mutex_);
        auto it = poll_sessions_.find(sid);
        if (it != poll_sessions_.end()) {
            return it->second;
        }
        return nullptr;
    }

    std::string handle_http_poll_request(
        const std::string& sid,
        const std::string& stanza_xml = "") {

        auto session = get_http_poll_session(sid);
        if (!session || session->is_expired()) {
            if (session) {
                std::lock_guard lock(poll_mutex_);
                poll_sessions_.erase(sid);
            }
            return "<error type='session-not-found'/>";
        }

        session->touch();
        session->expires = nms() + 300000; // Extend 5 minutes

        // If stanzas were sent, process them
        if (!stanza_xml.empty()) {
            // In a real impl, this would go to XMPP stream processor
        }

        // Drain pending stanzas
        auto pending = session->drain();

        if (pending.empty()) {
            return "<poll xmlns='" + std::string(transport_ns::HTTP_POLL) +
                   "' sid='" + session->sid + "' status='ok'/>";
        } else {
            std::ostringstream oss;
            oss << "<poll xmlns='" << transport_ns::HTTP_POLL
                << "' sid='" << session->sid << "' status='ok'>";
            for (auto& stanza : pending) {
                oss << stanza;
            }
            oss << "</poll>";
            return oss.str();
        }
    }

    void http_poll_enqueue(const std::string& sid,
                           const std::string& stanza_xml) {
        auto session = get_http_poll_session(sid);
        if (session) {
            session->enqueue(stanza_xml);
        }
    }

    void cleanup_expired_poll_sessions() {
        std::lock_guard lock(poll_mutex_);
        auto it = poll_sessions_.begin();
        while (it != poll_sessions_.end()) {
            if (it->second->is_expired()) {
                it = poll_sessions_.erase(it);
            } else {
                ++it;
            }
        }
    }

    // =========================================================================
    // CONNECTION MANAGER DISCOVERY (XEP-0156)
    // =========================================================================

    std::vector<ConnectionManagerEndpoint> discover_endpoints() {
        std::vector<ConnectionManagerEndpoint> endpoints;

        // BOSH endpoint
        {
            ConnectionManagerEndpoint ep;
            ep.transport = TransportType::BOSH;
            ep.path = config_.bosh_path;
            ep.priority = 0;
            endpoints.push_back(ep);
        }

        // BOSH (secure)
        {
            ConnectionManagerEndpoint ep;
            ep.transport = TransportType::BOSH;
            ep.path = config_.bosh_path;
            ep.port = 5281;
            ep.secure = true;
            ep.priority = 10;
            endpoints.push_back(ep);
        }

        // WebSocket endpoint
        {
            ConnectionManagerEndpoint ep;
            ep.transport = TransportType::WEBSOCKET;
            ep.path = config_.websocket_path;
            ep.port = 5443;
            ep.secure = true;
            ep.priority = 5;
            endpoints.push_back(ep);
        }

        // WebSocket (unencrypted)
        {
            ConnectionManagerEndpoint ep;
            ep.transport = TransportType::WEBSOCKET;
            ep.path = config_.websocket_path;
            ep.port = 5280;
            ep.priority = 15;
            endpoints.push_back(ep);
        }

        // HTTP Poll
        {
            ConnectionManagerEndpoint ep;
            ep.transport = TransportType::HTTP_POLL;
            ep.path = config_.httppoll_path;
            ep.port = 5280;
            ep.priority = 20;
            endpoints.push_back(ep);
        }

        // Sort by priority (lowest first = most preferred)
        std::sort(endpoints.begin(), endpoints.end(),
            [](const ConnectionManagerEndpoint& a,
               const ConnectionManagerEndpoint& b) {
                return a.priority < b.priority;
            });

        return endpoints;
    }

    // Generate XEP-0156 JSON discovery response
    json generate_discovery_json(const std::string& host = "",
                                  int port = 5280) {
        json j;
        j["connections"] = json::array();

        for (auto& ep : discover_endpoints()) {
            json entry;
            entry["type"] = transport_type_str(ep.transport);
            entry["url"] = (ep.secure ? "https://" : "http://") +
                           (host.empty() ? "localhost" : host) +
                           (ep.port != 80 && ep.port != 443 ?
                            ":" + std::to_string(ep.port) : "") +
                           ep.path;
            entry["priority"] = ep.priority;
            entry["secure"] = ep.secure;
            j["connections"].push_back(entry);
        }

        return j;
    }

    // Generate XEP-0156 XML discovery response (well-known host-meta)
    std::string generate_discovery_xml(const std::string& host = "",
                                        int port = 5280) {
        std::ostringstream oss;
        oss << "<?xml version='1.0' encoding='UTF-8'?>\n"
            << "<XRD xmlns='http://docs.oasis-open.org/ns/xri/xrd-1.0'>\n";

        for (auto& ep : discover_endpoints()) {
            std::string rel;
            switch (ep.transport) {
                case TransportType::BOSH:
                    rel = "urn:xmpp:alt-connections:xbosh";
                    break;
                case TransportType::WEBSOCKET:
                    rel = "urn:xmpp:alt-connections:websocket";
                    break;
                case TransportType::HTTP_POLL:
                    rel = "urn:xmpp:alt-connections:httppoll";
                    break;
                default:
                    rel = "urn:xmpp:alt-connections:unknown";
            }

            std::string url = (ep.secure ? "https://" : "http://") +
                              (host.empty() ? "localhost" : host) +
                              (ep.port != 80 && ep.port != 443 ?
                               ":" + std::to_string(ep.port) : "") +
                              ep.path;

            oss << "  <Link rel='" << rel << "'"
                << " href='" << xml_escape(url) << "'"
                << " priority='" << ep.priority << "'/>\n";
        }

        oss << "</XRD>\n";
        return oss.str();
    }

    // =========================================================================
    // TRANSPORT NEGOTIATION
    // =========================================================================

    TransportNegotiation negotiate_transport(
        const std::vector<TransportType>& client_prefs = {},
        bool secure_required = false,
        const std::string& resource_path = "") {

        TransportNegotiation result;

        // Build priority list
        std::vector<TransportType> candidates;

        if (!client_prefs.empty()) {
            // Respect client preferences but filter by availability
            for (auto t : client_prefs) {
                if (is_transport_available(t)) {
                    candidates.push_back(t);
                }
            }
        }

        if (candidates.empty()) {
            // Use server fallback order
            for (auto t : config_.fallback_order) {
                if (is_transport_available(t)) {
                    candidates.push_back(t);
                }
            }
        }

        // Filter by secure requirement
        std::vector<TransportType> secure_candidates;
        for (auto t : candidates) {
            if (!secure_required || transport_is_secure(t)) {
                secure_candidates.push_back(t);
            }
        }

        if (secure_candidates.empty()) {
            result.error = secure_required ?
                "No secure transport available" :
                "No transport available";
            return result;
        }

        // Try each candidate
        for (auto t : secure_candidates) {
            result.tried.push_back(t);

            TransportErrorInfo err = try_transport_setup(t, resource_path);
            if (err.error == TransportError::NONE) {
                result.selected = t;
                return result;
            }

            if (result.tried.size() > 1) {
                result.fallback_used = true;
            }
        }

        result.error = "All transports failed";
        return result;
    }

    bool is_transport_available(TransportType t) {
        switch (t) {
            case TransportType::BOSH:
                return config_.bosh_enabled;
            case TransportType::WEBSOCKET:
                return config_.websocket_enabled;
            case TransportType::HTTP_POLL:
                return config_.httppoll_enabled;
            case TransportType::RAW_TCP:
                return true;
            default:
                return false;
        }
    }

    bool transport_is_secure(TransportType t) {
        // For purposes of negotiation, secure = TLS
        switch (t) {
            case TransportType::RAW_TLS:
                return true;
            default:
                return false; // Can be made secure via wrapping
        }
    }

    TransportErrorInfo try_transport_setup(TransportType t,
                                            const std::string& path) {
        TransportErrorInfo err;
        err.error = TransportError::NONE;

        switch (t) {
            case TransportType::BOSH:
                if (!config_.bosh_enabled) {
                    err.error = TransportError::UNSUPPORTED_TRANSPORT;
                    err.message = "BOSH is not enabled";
                }
                break;

            case TransportType::WEBSOCKET:
                if (!config_.websocket_enabled) {
                    err.error = TransportError::UNSUPPORTED_TRANSPORT;
                    err.message = "WebSocket is not enabled";
                }
                break;

            case TransportType::HTTP_POLL:
                if (!config_.httppoll_enabled) {
                    err.error = TransportError::UNSUPPORTED_TRANSPORT;
                    err.message = "HTTP Poll is not enabled";
                }
                break;

            default:
                break;
        }

        return err;
    }

    // =========================================================================
    // TRANSPORT FALLBACK
    // =========================================================================

    struct FallbackResult {
        TransportType used_transport = TransportType::NONE;
        std::string error;
        int attempts = 0;
        bool success = false;
    };

    FallbackResult try_with_fallback(
        const std::function<TransportErrorInfo(TransportType)>& setup_fn) {

        FallbackResult result;

        for (auto t : config_.fallback_order) {
            result.attempts++;

            TransportErrorInfo err = setup_fn(t);
            if (err.error == TransportError::NONE) {
                result.used_transport = t;
                result.success = true;
                return result;
            }
        }

        result.error = "All transports in fallback chain failed";
        return result;
    }

    // =========================================================================
    // TRANSPORT RECONNECTION
    // =========================================================================

    struct ReconnectState {
        std::string previous_sid;
        std::string previous_endpoint;
        TransportType previous_transport = TransportType::NONE;
        int64_t last_connected = 0;
        int64_t disconnect_time = 0;
        int reconnect_attempts = 0;
        int64_t next_reconnect_at = 0;
        int max_reconnect_attempts = 10;
        int64_t base_delay_ms = 1000;       // 1 second
        int64_t max_delay_ms = 300000;      // 5 minutes
        bool reconnecting = false;

        void schedule_reconnect() {
            disconnect_time = nms();
            reconnect_attempts++;

            // Exponential backoff with jitter
            double delay = base_delay_ms * std::pow(2.0, reconnect_attempts - 1);
            delay = std::min(delay, static_cast<double>(max_delay_ms));

            // Add jitter: +/- 25%
            static thread_local std::mt19937 rng(nms());
            std::uniform_real_distribution<> jitter(-0.25, 0.25);
            delay *= (1.0 + jitter(rng));

            next_reconnect_at = disconnect_time + static_cast<int64_t>(delay);
            reconnecting = true;
        }

        bool should_reconnect() const {
            return reconnecting && nms() >= next_reconnect_at &&
                   reconnect_attempts <= max_reconnect_attempts;
        }

        void reset() {
            reconnect_attempts = 0;
            reconnecting = false;
            next_reconnect_at = 0;
        }
    };

    ReconnectState create_reconnect_state(
        const std::string& sid,
        TransportType transport,
        const std::string& endpoint) {

        ReconnectState state;
        state.previous_sid = sid;
        state.previous_transport = transport;
        state.previous_endpoint = endpoint;
        state.last_connected = nms();
        return state;
    }

    // =========================================================================
    // TRANSPORT METRICS
    // =========================================================================

    json get_bosh_metrics() const {
        json j = metrics_bosh_.to_json();
        {
            std::lock_guard lock(bosh_mutex_);
            j["total_sessions"] = bosh_sessions_.size();
        }
        return j;
    }

    json get_websocket_metrics() const {
        json j = metrics_ws_.to_json();
        {
            std::lock_guard lock(ws_mutex_);
            j["total_connections"] = ws_connections_.size();
        }
        return j;
    }

    json get_all_metrics() const {
        json j;
        j["bosh"] = get_bosh_metrics();
        j["websocket"] = get_websocket_metrics();

        {
            std::lock_guard lock(poll_mutex_);
            j["httppoll"]["total_sessions"] = poll_sessions_.size();
        }

        j["circuit_breakers"] = json::object();
        j["circuit_breakers"]["bosh"] = bosh_circuit_breaker_.failure_count();
        j["circuit_breakers"]["websocket"] = ws_circuit_breaker_.failure_count();

        return j;
    }

    TransportMetrics& bosh_metrics() { return metrics_bosh_; }
    TransportMetrics& ws_metrics() { return metrics_ws_; }

    // =========================================================================
    // TRANSPORT RATE LIMITING
    // =========================================================================

    void set_rate_limit(double per_sec, double burst) {
        config_.rate_limit_per_sec = per_sec;
        config_.rate_limit_burst = burst;
        bosh_rate_limiter_.set_rate(per_sec);
        bosh_rate_limiter_.set_burst(burst);
    }

    bool check_rate_limit(const std::string& ip) {
        if (!config_.rate_limit_enabled) return true;

        std::lock_guard lock(rate_limit_mutex_);
        auto it = ip_rate_limiters_.find(ip);
        if (it == ip_rate_limiters_.end()) {
            ip_rate_limiters_[ip] = TokenBucket(
                config_.rate_limit_per_sec,
                config_.rate_limit_burst);
            it = ip_rate_limiters_.find(ip);
        }
        return it->second.consume(1);
    }

    // =========================================================================
    // TRANSPORT COMPRESSION
    // =========================================================================

    std::string compress_body(const std::string& data,
                               const std::string& method = "deflate") {
        if (method == "deflate") {
            return compress::deflate_compress(data);
        } else if (method == "gzip") {
            // Gzip = deflate with gzip header/footer
            std::string deflated = compress::deflate_compress(data);

            // Build minimal gzip wrapper
            std::string gzip;
            gzip.push_back(0x1F); // ID1
            gzip.push_back(0x8B); // ID2
            gzip.push_back(0x08); // CM = deflate
            gzip.push_back(0x00); // FLG
            gzip.append(4, '\0'); // MTIME (zero)
            gzip.push_back(0x00); // XFL
            gzip.push_back(0xFF); // OS (unknown)
            gzip += deflated;

            // CRC32 and ISIZE (simplified - zero-filled)
            gzip.append(4, '\0'); // CRC32 placeholder
            uint32_t isize = static_cast<uint32_t>(data.size());
            gzip.push_back(isize & 0xFF);
            gzip.push_back((isize >> 8) & 0xFF);
            gzip.push_back((isize >> 16) & 0xFF);
            gzip.push_back((isize >> 24) & 0xFF);

            return gzip;
        }
        return data;
    }

    std::string decompress_body(const std::string& data,
                                 const std::string& method = "deflate") {
        try {
            if (method == "deflate") {
                return compress::deflate_decompress(data);
            } else if (method == "gzip") {
                if (data.size() < 18 ||
                    static_cast<unsigned char>(data[0]) != 0x1F ||
                    static_cast<unsigned char>(data[1]) != 0x8B ||
                    static_cast<unsigned char>(data[2]) != 0x08) {
                    metrics_bosh_.compression_errors.fetch_add(1);
                    return data;
                }
                // Skip 10-byte gzip header, strip 8-byte footer
                if (data.size() > 18) {
                    std::string deflated = data.substr(10, data.size() - 18);
                    return compress::deflate_decompress(deflated);
                }
                return data;
            }
        } catch (...) {
            metrics_bosh_.compression_errors.fetch_add(1);
        }
        return data;
    }

    // =========================================================================
    // CROSS-ORIGIN SUPPORT (CORS)
    // =========================================================================

    void set_cors_config(const CorsConfig& cors) {
        config_.cors = cors;
    }

    bool handle_cors_preflight(
        const std::map<std::string, std::string>& request_headers,
        std::map<std::string, std::string>& response_headers) {

        if (!config_.cors.enabled) return false;

        auto origin_it = request_headers.find("origin");
        if (origin_it == request_headers.end()) return false;

        auto method_it = request_headers.find("access-control-request-method");
        if (method_it == request_headers.end()) return false;

        // Check origin
        if (!config_.cors.is_origin_allowed(origin_it->second)) {
            return false;
        }

        // Build preflight response headers
        response_headers["Access-Control-Allow-Origin"] =
            config_.cors.allow_origin;
        response_headers["Access-Control-Allow-Methods"] =
            config_.cors.allow_methods;

        auto headers_it = request_headers.find("access-control-request-headers");
        if (headers_it != request_headers.end()) {
            response_headers["Access-Control-Allow-Headers"] =
                config_.cors.allow_headers;
        }

        response_headers["Access-Control-Allow-Credentials"] =
            config_.cors.allow_credentials;
        response_headers["Access-Control-Max-Age"] =
            std::to_string(config_.cors.max_age);

        return true;
    }

    void add_cors_headers(
        std::map<std::string, std::string>& response_headers,
        const std::map<std::string, std::string>& request_headers) {

        if (!config_.cors.enabled) return;

        auto origin_it = request_headers.find("origin");
        if (origin_it != request_headers.end()) {
            if (config_.cors.is_origin_allowed(origin_it->second)) {
                response_headers["Access-Control-Allow-Origin"] =
                    config_.cors.allow_origin;
                response_headers["Access-Control-Allow-Credentials"] =
                    config_.cors.allow_credentials;
                response_headers["Access-Control-Expose-Headers"] =
                    config_.cors.expose_headers;
            }
        }
    }

    // =========================================================================
    // KEEP-ALIVE MANAGEMENT
    // =========================================================================

    void configure_keepalive(const KeepAliveConfig& cfg) {
        config_.keepalive = cfg;
    }

    bool should_send_keepalive(std::shared_ptr<WebSocketConnection> conn) {
        if (!config_.keepalive.enabled) return false;
        if (!conn) return false;
        return conn->needs_ping();
    }

    void handle_keepalive_timeout(std::shared_ptr<WebSocketConnection> conn) {
        if (!conn) return;
        if (conn->is_stale(config_.keepalive.timeout_ms)) {
            metrics_ws_.timeout_errors.fetch_add(1);
            close_websocket_connection(conn->fd,
                WebSocketCloseCode::GOING_AWAY,
                "Connection timed out");
        }
    }

    void setup_tcp_keepalive(int fd) {
        if (!config_.keepalive.use_tcp_keepalive) return;

        int optval = 1;
        setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof(optval));

        int idle = config_.keepalive.tcp_keepalive_idle;
        setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle));

        int interval = config_.keepalive.tcp_keepalive_interval;
        setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &interval, sizeof(interval));

        int count = config_.keepalive.tcp_keepalive_count;
        setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &count, sizeof(count));
    }

    // =========================================================================
    // TRANSPORT ERROR HANDLING
    // =========================================================================

    TransportErrorInfo create_error(TransportError err,
                                     const std::string& msg,
                                     bool retryable = false) {
        TransportErrorInfo info;
        info.error = err;
        info.message = msg;
        info.retryable = retryable;

        switch (err) {
            case TransportError::TIMEOUT:
                info.http_status = 504;
                info.retryable = true;
                info.retry_after = 5;
                break;
            case TransportError::RATE_LIMITED:
                info.http_status = 429;
                info.retryable = true;
                info.retry_after = 30;
                break;
            case TransportError::SESSION_EXPIRED:
                info.http_status = 404;
                break;
            case TransportError::SESSION_NOT_FOUND:
                info.http_status = 404;
                break;
            case TransportError::BAD_REQUEST:
                info.http_status = 400;
                break;
            case TransportError::INTERNAL_ERROR:
                info.http_status = 500;
                info.retryable = true;
                break;
            case TransportError::SERVICE_UNAVAILABLE:
                info.http_status = 503;
                info.retryable = true;
                info.retry_after = 10;
                break;
            case TransportError::POLICY_VIOLATION:
                info.http_status = 403;
                break;
            case TransportError::AUTH_REQUIRED:
                info.http_status = 401;
                break;
            case TransportError::TLS_REQUIRED:
                info.http_status = 426;
                break;
            case TransportError::PROTOCOL_ERROR:
                info.http_status = 400;
                break;
            case TransportError::SYSTEM_OVERLOAD:
                info.http_status = 503;
                info.retryable = true;
                info.retry_after = 60;
                break;
            case TransportError::FRAME_TOO_LARGE:
                info.http_status = 413;
                break;
            case TransportError::COMPRESSION_ERROR:
                info.http_status = 400;
                break;
            case TransportError::CORS_BLOCKED:
                info.http_status = 403;
                break;
            case TransportError::UNSUPPORTED_VERSION:
                info.http_status = 400;
                break;
            default:
                info.http_status = 500;
        }

        return info;
    }

    std::string error_to_http_response(const TransportErrorInfo& err,
        const std::map<std::string, std::string>& request_headers = {}) {

        std::ostringstream oss;
        oss << "HTTP/1.1 " << err.http_status << " ";

        switch (err.http_status) {
            case 400: oss << "Bad Request"; break;
            case 401: oss << "Unauthorized"; break;
            case 403: oss << "Forbidden"; break;
            case 404: oss << "Not Found"; break;
            case 413: oss << "Payload Too Large"; break;
            case 426: oss << "Upgrade Required"; break;
            case 429: oss << "Too Many Requests"; break;
            case 500: oss << "Internal Server Error"; break;
            case 503: oss << "Service Unavailable"; break;
            case 504: oss << "Gateway Timeout"; break;
            default: oss << "Error"; break;
        }

        oss << "\r\n";
        oss << "Content-Type: application/xml; charset=utf-8\r\n";

        if (err.retry_after > 0) {
            oss << "Retry-After: " << err.retry_after << "\r\n";
        }

        // CORS headers
        auto origin_it = request_headers.find("origin");
        if (origin_it != request_headers.end() && config_.cors.enabled) {
            oss << "Access-Control-Allow-Origin: "
                << config_.cors.allow_origin << "\r\n";
        }

        oss << "\r\n";
        oss << "<?xml version='1.0' encoding='UTF-8'?>\n";
        oss << "<error"
            << " xmlns='" << transport_ns::BOSH << "'"
            << " type='cancel'"
            << " code='" << err.http_status << "'"
            << ">"
            << "<" << transport_error_str(err.error) << " xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>"
            << "<text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'>"
            << xml_escape(err.message) << "</text>"
            << "</error>";

        return oss.str();
    }

    void record_circuit_breaker(TransportType t, bool success) {
        CircuitBreaker* cb = nullptr;
        switch (t) {
            case TransportType::BOSH:
                cb = &bosh_circuit_breaker_;
                break;
            case TransportType::WEBSOCKET:
                cb = &ws_circuit_breaker_;
                break;
            default:
                return;
        }

        if (success) {
            cb->record_success();
        } else {
            cb->record_failure();
        }
    }

    bool is_circuit_open(TransportType t) {
        switch (t) {
            case TransportType::BOSH:
                return !bosh_circuit_breaker_.allow_request();
            case TransportType::WEBSOCKET:
                return !ws_circuit_breaker_.allow_request();
            default:
                return false;
        }
    }

    // =========================================================================
    // PERIODIC MAINTENANCE
    // =========================================================================

    void periodic_maintenance() {
        int64_t now = nms();

        // Cleanup expired BOSH sessions (every 30 seconds)
        if (now - last_bosh_cleanup_ > 30000) {
            cleanup_expired_bosh_sessions();
            last_bosh_cleanup_ = now;
        }

        // Cleanup expired poll sessions (every 60 seconds)
        if (now - last_poll_cleanup_ > 60000) {
            cleanup_expired_poll_sessions();
            last_poll_cleanup_ = now;
        }

        // Check WebSocket keep-alives (every 10 seconds)
        if (now - last_ws_keepalive_ > 10000) {
            std::lock_guard lock(ws_mutex_);
            for (auto it = ws_connections_.begin();
                 it != ws_connections_.end(); ) {
                auto conn = it->second;
                if (conn->state != WebSocketState::OPEN) {
                    ++it;
                    continue;
                }

                if (conn->is_stale(config_.websocket_timeout)) {
                    metrics_ws_.timeout_errors.fetch_add(1);
                    int fd = conn->fd;
                    ws_connections_by_id_.erase(conn->id);
                    it = ws_connections_.erase(it);
                    close_websocket_connection(fd,
                        WebSocketCloseCode::GOING_AWAY,
                        "Keep-alive timeout");
                } else if (should_send_keepalive(conn)) {
                    std::string ping = websocket_create_ping(conn);
                    // In a real implementation, this would be sent over the socket
                    ++it;
                } else {
                    ++it;
                }
            }
            last_ws_keepalive_ = now;
        }

        // Rate limiter GC (every 5 minutes)
        if (now - last_rate_limiter_gc_ > 300000) {
            std::lock_guard lock(rate_limit_mutex_);
            auto it = ip_rate_limiters_.begin();
            while (it != ip_rate_limiters_.end()) {
                if (it->second.tokens_available() >= config_.rate_limit_burst) {
                    it = ip_rate_limiters_.erase(it);
                } else {
                    ++it;
                }
            }
            last_rate_limiter_gc_ = now;
        }
    }

    // =========================================================================
    // HTTP Request routing (routes to appropriate transport handler)
    // =========================================================================

    struct HttpDispatchResult {
        bool handled = false;
        int status_code = 200;
        std::string content_type = "text/xml; charset=utf-8";
        std::string body;
        std::map<std::string, std::string> headers;
    };

    HttpDispatchResult dispatch_http_request(
        const std::string& method,
        const std::string& path,
        const std::string& body,
        const std::map<std::string, std::string>& headers,
        const std::string& client_ip = "") {

        HttpDispatchResult result;

        // Handle CORS preflight
        if (method == "OPTIONS") {
            bool is_preflight = handle_cors_preflight(headers, result.headers);
            if (is_preflight) {
                result.status_code = 204;
                result.handled = true;
                return result;
            }
        }

        // Route to BOSH handler
        if (config_.bosh_enabled &&
            (path == config_.bosh_path ||
             path.find(config_.bosh_path) == 0)) {

            auto bosh_resp = handle_bosh_http_request(
                method, body, headers, client_ip);

            result.status_code = bosh_resp.status_code;
            result.content_type = bosh_resp.content_type;
            result.body = bosh_resp.body;
            result.headers = bosh_resp.headers;
            result.handled = true;
            return result;
        }

        // Route to WebSocket upgrade handler
        if (config_.websocket_enabled &&
            (path == config_.websocket_path ||
             path.find(config_.websocket_path) == 0)) {

            auto ws_result = handle_websocket_upgrade("", headers, client_ip);
            if (ws_result.success) {
                result.status_code = 101;
                // WebSocket upgrade response is raw HTTP
                result.body = ws_result.response;
                result.content_type = "";
                result.handled = true;
                return result;
            } else {
                result.status_code = ws_result.http_status;
                result.content_type = "text/plain";
                result.body = ws_result.error;
                result.handled = true;
                return result;
            }
        }

        // Route to HTTP Poll handler
        if (config_.httppoll_enabled &&
            (path == config_.httppoll_path ||
             path.find(config_.httppoll_path) == 0)) {

            // Extract SID from query string or body
            std::string sid;
            std::string stanza_xml = body;

            auto sid_it = headers.find("x-http-poll-sid");
            if (sid_it != headers.end()) {
                sid = sid_it->second;
            }

            if (sid.empty() && method == "GET") {
                // Extract from query string
                size_t q = path.find('?');
                if (q != std::string::npos) {
                    std::string qs = path.substr(q + 1);
                    auto extract_param = [](const std::string& qs,
                                            const std::string& key) -> std::string {
                        std::string search = key + "=";
                        size_t pos = qs.find(search);
                        if (pos == std::string::npos) return "";
                        pos += search.size();
                        size_t end = qs.find('&', pos);
                        if (end == std::string::npos) end = qs.size();
                        return qs.substr(pos, end - pos);
                    };
                    sid = extract_param(qs, "sid");
                }
            }

            if (sid.empty()) {
                // New session
                auto session = create_http_poll_session();
                sid = session->sid;
                result.headers["X-HTTP-Poll-SID"] = sid;
            }

            std::string poll_result = handle_http_poll_request(sid, stanza_xml);
            result.status_code = 200;
            result.content_type = "text/xml; charset=utf-8";
            result.body = poll_result;
            result.headers["X-HTTP-Poll-SID"] = sid;
            result.handled = true;
            return result;
        }

        // Connection manager discovery endpoint
        if (path == "/.well-known/host-meta") {
            result.status_code = 200;
            result.content_type = "application/xml";
            result.body = generate_discovery_xml(client_ip);
            result.handled = true;
            return result;
        }

        if (path == "/.well-known/host-meta.json") {
            result.status_code = 200;
            result.content_type = "application/json";
            result.body = generate_discovery_json(client_ip).dump();
            result.handled = true;
            return result;
        }

        result.status_code = 404;
        result.body = "Not Found";
        return result;
    }

    // =========================================================================
    // Periodic maintenance helpers used internally
    // =========================================================================

    void set_bosh_cleanup_interval(int64_t ms) {
        bosh_cleanup_interval_ms_ = ms;
    }

    // =========================================================================
    // Internal state access for instrumentation
    // =========================================================================

    size_t bosh_session_count() const {
        std::lock_guard lock(bosh_mutex_);
        return bosh_sessions_.size();
    }

    size_t websocket_connection_count() const {
        std::lock_guard lock(ws_mutex_);
        return ws_connections_.size();
    }

    size_t poll_session_count() const {
        std::lock_guard lock(poll_mutex_);
        return poll_sessions_.size();
    }

    std::vector<std::shared_ptr<BoshSession>> bosh_sessions_snapshot() {
        std::lock_guard lock(bosh_mutex_);
        std::vector<std::shared_ptr<BoshSession>> result;
        result.reserve(bosh_sessions_.size());
        for (auto& [sid, session] : bosh_sessions_) {
            result.push_back(session);
        }
        return result;
    }

    std::vector<std::shared_ptr<WebSocketConnection>> ws_connections_snapshot() {
        std::lock_guard lock(ws_mutex_);
        std::vector<std::shared_ptr<WebSocketConnection>> result;
        result.reserve(ws_connections_.size());
        for (auto& [fd, conn] : ws_connections_) {
            result.push_back(conn);
        }
        return result;
    }

private:
    TransportConfig config_;

    // BOSH sessions: sid -> session
    mutable std::mutex bosh_mutex_;
    std::unordered_map<std::string, std::shared_ptr<BoshSession>> bosh_sessions_;
    TokenBucket bosh_rate_limiter_{config_.rate_limit_per_sec,
                                    config_.rate_limit_burst};
    TransportMetrics metrics_bosh_;
    CircuitBreaker bosh_circuit_breaker_{5, 30000};

    // WebSocket connections: fd -> connection
    mutable std::mutex ws_mutex_;
    std::unordered_map<int, std::shared_ptr<WebSocketConnection>> ws_connections_;
    std::unordered_map<std::string, std::shared_ptr<WebSocketConnection>>
        ws_connections_by_id_;
    TransportMetrics metrics_ws_;
    CircuitBreaker ws_circuit_breaker_{5, 30000};

    // HTTP Poll sessions
    mutable std::mutex poll_mutex_;
    std::unordered_map<std::string, std::shared_ptr<HttpPollSession>>
        poll_sessions_;

    // IP-based rate limiters
    mutable std::mutex rate_limit_mutex_;
    std::unordered_map<std::string, TokenBucket> ip_rate_limiters_;

    // Periodic maintenance timestamps
    int64_t last_bosh_cleanup_ = 0;
    int64_t last_poll_cleanup_ = 0;
    int64_t last_ws_keepalive_ = 0;
    int64_t last_rate_limiter_gc_ = 0;
    int64_t bosh_cleanup_interval_ms_ = 30000;

    // Config lock
    mutable std::mutex config_mutex_;
};

// =============================================================================
// Utility: Convert raw HTTP request string to header map
// =============================================================================

static std::map<std::string, std::string> parse_http_headers(
    const std::string& http_request) {

    std::map<std::string, std::string> headers;
    std::istringstream stream(http_request);
    std::string line;

    // Parse request line
    if (std::getline(stream, line)) {
        // Strip trailing \r
        if (!line.empty() && line.back() == '\r') line.pop_back();
        std::istringstream req_line(line);
        std::string method, path, version;
        req_line >> method >> path >> version;
        headers[":method"] = method;
        headers[":path"] = path;
        headers[":version"] = version;
    }

    // Parse headers
    while (std::getline(stream, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) break;

        size_t colon = line.find(':');
        if (colon != std::string::npos) {
            std::string key = line.substr(0, colon);
            std::string value = line.substr(colon + 1);

            // Trim key to lowercase
            std::string key_lower;
            key_lower.reserve(key.size());
            for (char c : key) key_lower += std::tolower(c);

            // Trim value
            value.erase(0, value.find_first_not_of(" \t"));
            value.erase(value.find_last_not_of(" \t") + 1);

            headers[key_lower] = value;
        }
    }

    return headers;
}

// =============================================================================
// Utility: Build full HTTP response from BoshHttpResponse
// =============================================================================

static std::string build_http_response(
    int status_code,
    const std::string& content_type,
    const std::string& body,
    const std::map<std::string, std::string>& extra_headers = {}) {

    std::ostringstream oss;

    switch (status_code) {
        case 101: oss << "HTTP/1.1 101 Switching Protocols\r\n"; break;
        case 200: oss << "HTTP/1.1 200 OK\r\n"; break;
        case 204: oss << "HTTP/1.1 204 No Content\r\n"; break;
        case 400: oss << "HTTP/1.1 400 Bad Request\r\n"; break;
        case 401: oss << "HTTP/1.1 401 Unauthorized\r\n"; break;
        case 403: oss << "HTTP/1.1 403 Forbidden\r\n"; break;
        case 404: oss << "HTTP/1.1 404 Not Found\r\n"; break;
        case 405: oss << "HTTP/1.1 405 Method Not Allowed\r\n"; break;
        case 413: oss << "HTTP/1.1 413 Payload Too Large\r\n"; break;
        case 415: oss << "HTTP/1.1 415 Unsupported Media Type\r\n"; break;
        case 426: oss << "HTTP/1.1 426 Upgrade Required\r\n"; break;
        case 429: oss << "HTTP/1.1 429 Too Many Requests\r\n"; break;
        case 500: oss << "HTTP/1.1 500 Internal Server Error\r\n"; break;
        case 503: oss << "HTTP/1.1 503 Service Unavailable\r\n"; break;
        case 504: oss << "HTTP/1.1 504 Gateway Timeout\r\n"; break;
        default: oss << "HTTP/1.1 " << status_code << " \r\n"; break;
    }

    if (!content_type.empty()) {
        oss << "Content-Type: " << content_type << "\r\n";
    }

    if (!body.empty()) {
        oss << "Content-Length: " << body.size() << "\r\n";
    }
    oss << "Date: "; // Could add actual date
    oss << "Server: Progressive-XMPP\r\n";

    for (const auto& [key, value] : extra_headers) {
        oss << key << ": " << value << "\r\n";
    }

    oss << "\r\n";
    oss << body;

    return oss.str();
}

// =============================================================================
// Convenience: Create and configure TransportManager
// =============================================================================

static TransportManager create_default_transport_manager() {
    TransportManager mgr;
    TransportConfig cfg;
    cfg.bosh_path = "/http-bind";
    cfg.bosh_max_wait = 120;
    cfg.bosh_min_wait = 5;
    cfg.bosh_default_wait = 30;
    cfg.bosh_max_hold = 10;
    cfg.bosh_max_inactivity = 120;
    cfg.bosh_max_pause = 300;
    cfg.bosh_polling_interval = 25;
    cfg.bosh_compression = true;
    cfg.bosh_use_acks = true;

    cfg.websocket_path = "/xmpp-websocket";
    cfg.websocket_max_frame_size = 1048576;
    cfg.websocket_ping_interval = 30;
    cfg.websocket_permessage_deflate = true;

    cfg.httppoll_path = "/http-poll";
    cfg.httppoll_timeout = 60000;

    cfg.rate_limit_per_sec = 100.0;
    cfg.rate_limit_burst = 200.0;

    cfg.cors.enabled = true;
    cfg.cors.allow_origin = "*";

    cfg.keepalive.enabled = true;
    cfg.keepalive.interval_ms = 30000;
    cfg.keepalive.timeout_ms = 120000;

    mgr.configure(cfg);
    return mgr;
}

// =============================================================================
// Diagnostic / status dump
// =============================================================================

static json transport_status_dump(const TransportManager& mgr) {
    json j;
    j["metrics"] = mgr.get_all_metrics();
    j["bosh_sessions"] = mgr.bosh_session_count();
    j["ws_connections"] = mgr.websocket_connection_count();
    j["poll_sessions"] = mgr.poll_session_count();

    auto endpoints = mgr.discover_endpoints();
    j["endpoints"] = json::array();
    for (auto& ep : endpoints) {
        j["endpoints"].push_back({
            {"transport", transport_type_str(ep.transport)},
            {"path", ep.path},
            {"port", ep.port},
            {"secure", ep.secure},
            {"priority", ep.priority},
        });
    }

    return j;
}

} // namespace xmpp
} // namespace progressive

// =============================================================================
// xmpp_transports.cpp - End of File
// Total: ~2000 lines of implementation
// =============================================================================
